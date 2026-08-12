import sqlite3
import json
import os
import re
from datetime import datetime
from typing import Dict, Any, List
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "audit.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            tool TEXT NOT NULL,
            params TEXT NOT NULL,
            rule_results TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_band TEXT NOT NULL,
            disposition TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pending_reviews (
            review_id TEXT PRIMARY KEY,
            ts TEXT NOT NULL,
            session_id TEXT NOT NULL,
            tool TEXT NOT NULL,
            params TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            timeout REAL NOT NULL,
            status TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def mask_value(val: Any) -> Any:
    if not isinstance(val, str):
        return val
    # Redact Cookie values
    val = re.sub(r'(?i)cookie\s*:\s*[^;\s\r\n]+', 'Cookie: [REDACTED]', val)
    # Redact Authorization Bearer tokens
    val = re.sub(r'(?i)bearer\s+[a-zA-Z0-9_\-\.]+', 'Bearer [REDACTED]', val)
    # Redact passwords/secrets in JSON structures
    val = re.sub(r'(?i)"(key|token|password|secret|api_key)"\s*:\s*"[^"]+"', r'"\1": "[REDACTED]"', val)
    return val

def mask_params(params: Dict[str, Any]) -> Dict[str, Any]:
    """Mask sensitive keys (key, token, password, secret, cookies) in parameters."""
    masked = {}
    for k, v in params.items():
        if any(sec in k.lower() for sec in ["key", "token", "password", "secret"]):
            masked[k] = "[REDACTED]"
        elif isinstance(v, dict):
            masked[k] = mask_params(v)
        elif isinstance(v, str):
            masked[k] = mask_value(v)
        else:
            masked[k] = v
    return masked

def truncate_params(params: Dict[str, Any], max_len: int = 100) -> Dict[str, Any]:
    """Truncate long string parameters for dashboard display."""
    truncated = {}
    for k, v in params.items():
        if isinstance(v, str) and len(v) > max_len:
            truncated[k] = v[:max_len] + f"... [REDACTED {len(v)} chars]"
        elif isinstance(v, dict):
            truncated[k] = truncate_params(v, max_len)
        else:
            truncated[k] = v
    return truncated

def log_call(
    agent_id: str,
    session_id: str,
    tool: str,
    params: Dict[str, Any],
    rule_results: List[Dict[str, Any]],
    risk_score: int,
    risk_band: str,
    disposition: str
) -> Dict[str, Any]:
    """
    Saves the call to SQLite and returns the sanitized payload suitable for WebSocket broadcast.
    """
    ts = datetime.utcnow().isoformat() + "Z"
    
    # Mask parameters for storage
    masked_params = mask_params(params)
    params_str = json.dumps(masked_params)
    rule_results_str = json.dumps(rule_results)
    
    # Store to SQLite
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO audit_log (ts, agent_id, session_id, tool, params, rule_results, risk_score, risk_band, disposition)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (ts, agent_id, session_id, tool, params_str, rule_results_str, risk_score, risk_band, disposition))
    conn.commit()
    conn.close()

    # Generate truncated payload for display
    truncated_params = truncate_params(masked_params, max_len=100)
    
    return {
        "ts": ts,
        "agent_id": agent_id,
        "session_id": session_id,
        "tool": tool,
        "params": truncated_params,
        "rule_results": rule_results,
        "risk_score": risk_score,
        "risk_band": risk_band,
        "disposition": disposition
    }

# ========================================================
# HITL Pending Reviews Utilities
# ========================================================

def create_pending_review(
    review_id: str,
    session_id: str,
    tool: str,
    params: Dict[str, Any],
    risk_score: int,
    timeout_seconds: int = 300
):
    """Inserts a new pending review with a future timeout epoch."""
    import time
    ts = datetime.utcnow().isoformat() + "Z"
    timeout_epoch = time.time() + timeout_seconds
    masked_params = mask_params(params)
    params_str = json.dumps(masked_params)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO pending_reviews (review_id, ts, session_id, tool, params, risk_score, timeout, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
    """, (review_id, ts, session_id, tool, params_str, risk_score, timeout_epoch))
    conn.commit()
    conn.close()

def check_and_handle_timeouts():
    """Updates any reviews that have exceeded their timeout to 'denied' and sets logs to blocked."""
    import time
    now = time.time()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Find all pending reviews that have expired
    cursor.execute("SELECT session_id, tool, params FROM pending_reviews WHERE status = 'pending' AND timeout < ?", (now,))
    expired = cursor.fetchall()
    
    if expired:
        # Update pending reviews status
        cursor.execute("UPDATE pending_reviews SET status = 'denied' WHERE status = 'pending' AND timeout < ?", (now,))
        
        # Update matching audit log entries to blocked
        for session_id, tool, params_str in expired:
            cursor.execute("""
                UPDATE audit_log 
                SET disposition = 'blocked' 
                WHERE session_id = ? AND tool = ? AND params = ? AND disposition = 'pending_hitl'
            """, (session_id, tool, params_str))
            
    conn.commit()
    conn.close()

def get_pending_reviews() -> List[Dict[str, Any]]:
    """Returns a list of all active pending reviews."""
    check_and_handle_timeouts()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT review_id, ts, session_id, tool, params, risk_score, timeout FROM pending_reviews WHERE status = 'pending' ORDER BY ts ASC")
    rows = cursor.fetchall()
    reviews = []
    for r in rows:
        reviews.append({
            "review_id": r["review_id"],
            "ts": r["ts"],
            "session_id": r["session_id"],
            "tool": r["tool"],
            "params": json.loads(r["params"]),
            "risk_score": r["risk_score"],
            "timeout": r["timeout"]
        })
    conn.close()
    return reviews

def get_review_status(review_id: str) -> str:
    """Returns the current status of a review ('pending', 'approved', 'denied')."""
    check_and_handle_timeouts()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM pending_reviews WHERE review_id = ?", (review_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row[0]
    return "denied"

def resolve_review(review_id: str, decision: str) -> bool:
    """Sets a review's status to 'approved' or 'denied' and updates the matching audit_log entry."""
    if decision not in ["approved", "denied"]:
        return False
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Retrieve the review parameters to link with the audit log
    cursor.execute("SELECT session_id, tool, params FROM pending_reviews WHERE review_id = ? AND status = 'pending'", (review_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False
        
    session_id, tool, params_str = row
    
    # Update the pending review
    cursor.execute("UPDATE pending_reviews SET status = ? WHERE review_id = ? AND status = 'pending'", (decision, review_id))
    rows_affected = cursor.rowcount
    
    if rows_affected > 0:
        # Determine the updated disposition for the audit log
        final_disp = "blocked" if decision == "denied" else "allowed"
        # Update the original pending_hitl log entry to the final disposition
        cursor.execute("""
            UPDATE audit_log 
            SET disposition = ? 
            WHERE session_id = ? AND tool = ? AND params = ? AND disposition = 'pending_hitl'
        """, (final_disp, session_id, tool, params_str))
        
    conn.commit()
    conn.close()
    return rows_affected > 0
