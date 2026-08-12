import re
import time
from typing import List, Dict, Any, Optional, Set
from proxy.session_store import session_store, SessionState

class CallContext:
    def __init__(self, agent_id: str, session_id: str, tool_name: str, params: Dict[str, Any], timestamp: float):
        self.agent_id: str = agent_id
        self.session_id: str = session_id
        self.tool_name: str = tool_name
        self.params: Dict[str, Any] = params
        self.timestamp: float = timestamp

class RuleResult:
    def __init__(self, rule_type: str, outcome: str, reason: str, enforce: bool = True):
        self.rule_type: str = rule_type
        self.outcome: str = outcome  # "allow" or "violation"
        self.reason: str = reason
        self.enforce: bool = enforce

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule_type,
            "outcome": self.outcome,
            "reason": self.reason if self.outcome == "violation" else ""
        }

class Rule:
    def __init__(self, rule_config: Dict[str, Any], global_enforce: bool = True):
        self.config: Dict[str, Any] = rule_config
        # rule-level enforce overrides global_enforce
        self.enforce: bool = rule_config.get("enforce", global_enforce)

    def evaluate(self, ctx: CallContext, session: SessionState) -> RuleResult:
        raise NotImplementedError("Subclasses must implement evaluate()")

class RateLimitRule(Rule):
    def evaluate(self, ctx: CallContext, session: SessionState) -> RuleResult:
        max_calls = self.config.get("max_calls", 1)
        window_seconds = self.config.get("window_seconds", 60)

        history = session_store.get_rate_limit_history(ctx.agent_id, ctx.tool_name)
        
        # Clean history of old timestamps
        cutoff = ctx.timestamp - window_seconds
        while history and history[0] < cutoff:
            history.popleft()

        if len(history) >= max_calls:
            return RuleResult(
                rule_type="rate_limit",
                outcome="violation",
                reason=f"Rate limit exceeded: max {max_calls} calls per {window_seconds}s. Current count: {len(history)}.",
                enforce=self.enforce
            )
        
        return RuleResult(rule_type="rate_limit", outcome="allow", reason="", enforce=self.enforce)

class ParamValidationRule(Rule):
    def evaluate(self, ctx: CallContext, session: SessionState) -> RuleResult:
        param_name = self.config.get("param", "sql")
        patterns = self.config.get("patterns", [])
        max_length = self.config.get("max_length", 4000)

        val = ctx.params.get(param_name, "")
        if not isinstance(val, str):
            val = str(val)

        # Check length
        if len(val) > max_length:
            return RuleResult(
                rule_type="param_blocklist",
                outcome="violation",
                reason=f"param_blocklist violation: Parameter '{param_name}' exceeds maximum length of {max_length} (length: {len(val)}).",
                enforce=self.enforce
            )

        # Check blocklist patterns
        for pattern in patterns:
            try:
                if re.search(pattern, val, re.IGNORECASE):
                    return RuleResult(
                        rule_type="param_blocklist",
                        outcome="violation",
                        reason=f"param_blocklist violation: Parameter '{param_name}' matched blocked pattern: '{pattern}'.",
                        enforce=self.enforce
                    )
            except re.error:
                # If invalid regex, fallback to exact substring case-insensitive match
                if pattern.lower() in val.lower():
                    return RuleResult(
                        rule_type="param_blocklist",
                        outcome="violation",
                        reason=f"param_blocklist violation: Parameter '{param_name}' matched blocked substring: '{pattern}'.",
                        enforce=self.enforce
                    )

        return RuleResult(rule_type="param_blocklist", outcome="allow", reason="", enforce=self.enforce)

def extract_tables(sql: str) -> List[str]:
    # Strip line comments and block comments
    sql_clean = re.sub(r'(--.*)|(\/\*[\s\S]*?\*\/)', '', sql)
    # Match FROM, JOIN, INTO, UPDATE, TABLE followed by table identifiers
    pattern = re.compile(
        r'\b(?:FROM|JOIN|INTO|UPDATE|TABLE|TRUNCATE)\s+([a-zA-Z0-9_\"`\.]+)',
        re.IGNORECASE
    )
    tables = []
    for match in pattern.finditer(sql_clean):
        table = match.group(1).strip('"` ')
        # Handle dot notations (e.g. database.table)
        if '.' in table:
            table = table.split('.')[-1]
        tables.append(table)
    return tables

class DataScopeRule(Rule):
    def evaluate(self, ctx: CallContext, session: SessionState) -> RuleResult:
        param_name = self.config.get("param", "sql")
        allowed_prefix = self.config.get("allowed_table_prefix", "project_x_")
        
        # Use session's declared scope if present, fallback to rule config
        prefix = session.declared_scope or allowed_prefix

        val = ctx.params.get(param_name, "")
        if not isinstance(val, str):
            val = str(val)

        if ctx.tool_name == "user_prompt":
            # For natural language prompts, check if they reference any known out-of-scope tables
            known_tables = ["other_tenant_orders", "employees", "customers", "orders"]
            for table in known_tables:
                if table.lower() in val.lower():
                    # Check if the reference is prefixed with the allowed prefix
                    full_prefixed_table = f"{prefix}{table}"
                    if full_prefixed_table.lower() not in val.lower():
                        return RuleResult(
                            rule_type="data_scope",
                            outcome="violation",
                            reason=f"data_scope violation: Prompt references unauthorized table '{table}' outside allowed prefix '{prefix}'.",
                            enforce=self.enforce
                        )
            return RuleResult(rule_type="data_scope", outcome="allow", reason="", enforce=self.enforce)

        tables = extract_tables(val)
        
        # If no tables are referenced (e.g. SELECT 1;), it's allowed
        if not tables:
            return RuleResult(rule_type="data_scope", outcome="allow", reason="", enforce=self.enforce)

        for table in tables:
            if not table.lower().startswith(prefix.lower()):
                return RuleResult(
                    rule_type="data_scope",
                    outcome="violation",
                    reason=f"data_scope violation: Table '{table}' is outside allowed prefix '{prefix}'.",
                    enforce=self.enforce
                )

        return RuleResult(rule_type="data_scope", outcome="allow", reason="", enforce=self.enforce)

class SequenceRule(Rule):
    def evaluate(self, ctx: CallContext, session: SessionState) -> RuleResult:
        requires = self.config.get("requires", [])

        missing = [req for req in requires if req not in session.allowed_tools]
        if missing:
            return RuleResult(
                rule_type="sequence",
                outcome="violation",
                reason=f"sequence violation: Tool '{ctx.tool_name}' requires [{', '.join(requires)}] to be run first. Missing: [{', '.join(missing)}].",
                enforce=self.enforce
            )

        return RuleResult(rule_type="sequence", outcome="allow", reason="", enforce=self.enforce)
