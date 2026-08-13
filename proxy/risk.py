import time
import re
from typing import Dict, Any, List
from proxy.rules import CallContext, extract_tables
from proxy.session_store import session_store, SessionState

FUZZY_PATTERNS = ["drop", "script", "ignore", "instructions", "union", "admin"]
SUSPICIOUS_ADJACENT = ["project_y", "other_tenant", "tenant", "employee", "customer", "order"]

def calculate_risk_score(ctx: CallContext, session: SessionState, tool_rules: List[Dict[str, Any]]) -> int:
    risk_score = 0
    
    # 1. Rate limit proximity (+1 risk if current_count / max_calls >= 0.8)
    # Find rate limit rule in configuration
    rate_limit_cfg = next((r for r in tool_rules if r.get("type") == "rate_limit"), None)
    if rate_limit_cfg:
        max_calls = rate_limit_cfg.get("max_calls", 5)
        window_seconds = rate_limit_cfg.get("window_seconds", 60)
        
        # Get count of calls in window
        history = session_store.get_rate_limit_history(ctx.agent_id, ctx.tool_name)
        cutoff = ctx.timestamp - window_seconds
        active_calls = sum(1 for ts in history if ts >= cutoff)
        
        # Check if we are within 20% of ceiling (e.g., 4th call of 5)
        if max_calls > 0 and (active_calls / max_calls) >= 0.8:
            risk_score += 1

    # Get the primary parameter value (usually "sql" for our tools)
    sql_val = ctx.params.get("sql", "")
    if not isinstance(sql_val, str):
        sql_val = str(sql_val)

    # 2. Narrowly avoided blocklist (+2 risk if matches a fuzzy/partial pattern)
    # Fuzzy patterns match common SQL components that aren't hard-blocked, e.g., case-insensitive search
    # Check if the param contains fuzzy patterns but is not blocked by hard rules
    matched_fuzzy = False
    for fuzzy in FUZZY_PATTERNS:
        if fuzzy.lower() in sql_val.lower():
            matched_fuzzy = True
            break
    if matched_fuzzy:
        risk_score += 2

    # Check for destructive commands specifically.
    # Only apply the +3 HIGH-risk penalty to execute_sql: validate_sql is a dry-run
    # validation step that never modifies the database, so destructive SQL keywords
    # in a validate_sql call should not trigger HITL — only actual execution should.
    if ctx.tool_name == "execute_sql":
        destructive_keywords = ["drop ", "truncate ", "delete ", "update ", "alter "]
        for d_word in destructive_keywords:
            if d_word in sql_val.lower():
                risk_score += 3
                break

    # 3. Data scope adjacency (+2 risk)
    # If the SQL contains references to adjacent tenants (e.g., "project_y" or "other_tenant" or base tables
    # inside comments/strings, but did not trigger data_scope because it wasn't extracted as a raw table name)
    extracted_tables = [t.lower() for t in extract_tables(sql_val)]
    
    # Check if the query contains suspicious terms that are not in the validated tables list
    # e.g., in a comment or a string constant like: SELECT * FROM project_x_customers WHERE notes LIKE '%other_tenant%'
    has_adjacent = False
    for term in SUSPICIOUS_ADJACENT:
        # If term is in sql but not part of allowed table names
        if term.lower() in sql_val.lower():
            # Check if it was extracted as a table; if it was not, it might be in a comment/clause
            is_extracted_table = any(term.lower() in t for t in extracted_tables)
            if not is_extracted_table:
                has_adjacent = True
                break
                
    if has_adjacent:
        risk_score += 2

    # 4. Timing speed check (+1 risk if sequence check passes but tools called < 500ms apart)
    if session.last_allowed_call_time is not None:
        elapsed = ctx.timestamp - session.last_allowed_call_time
        if elapsed < 0.5:  # Less than 500ms
            risk_score += 1

    return risk_score
