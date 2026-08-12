import pytest
import time
from proxy.rules import CallContext, RateLimitRule, ParamValidationRule, DataScopeRule, SequenceRule
from proxy.session_store import session_store, SessionState
from proxy.risk import calculate_risk_score

@pytest.fixture(autouse=True)
def clean_store():
    session_store.clear()
    yield

def test_rate_limit_rule():
    session_id = "test-session"
    agent_id = "test-agent"
    tool_name = "execute_sql"
    session = session_store.get_session(session_id)
    
    # Configure rule: 3 calls per 10 seconds
    rule_cfg = {"type": "rate_limit", "max_calls": 3, "window_seconds": 10}
    rule = RateLimitRule(rule_cfg)

    # 1. Under limit (0 calls recorded)
    ctx = CallContext(agent_id, session_id, tool_name, {}, time.time())
    res = rule.evaluate(ctx, session)
    assert res.outcome == "allow"

    # Record 2 calls
    t = time.time()
    session_store.record_call_timestamp(agent_id, tool_name, t - 5)
    session_store.record_call_timestamp(agent_id, tool_name, t - 2)

    # 2. Exactly at limit (2 calls in window, current call is 3rd)
    res = rule.evaluate(ctx, session)
    assert res.outcome == "allow"

    # Record 3rd call
    session_store.record_call_timestamp(agent_id, tool_name, t)

    # 3. Exceeded limit (3 calls in window, current call is 4th)
    res = rule.evaluate(ctx, session)
    assert res.outcome == "violation"
    assert "rate limit exceeded" in res.reason.lower()

def test_param_validation_rule():
    session = SessionState("test-session")
    
    # Configure rule: max length 20, block DROP and SELECT
    rule_cfg = {
        "type": "param_blocklist",
        "param": "sql",
        "patterns": ["DROP TABLE", "SELECT .* FROM secrets"],
        "max_length": 25
    }
    rule = ParamValidationRule(rule_cfg)

    # 1. Clean query
    ctx1 = CallContext("agent", "sess", "validate_sql", {"sql": "SELECT * FROM customers"}, time.time())
    assert rule.evaluate(ctx1, session).outcome == "allow"

    # 2. Max length violation
    ctx2 = CallContext("agent", "sess", "validate_sql", {"sql": "SELECT * FROM project_x_customers_and_orders"}, time.time())
    res_len = rule.evaluate(ctx2, session)
    assert res_len.outcome == "violation"
    assert "exceeds maximum length" in res_len.reason.lower()

    # 3. Exact pattern match (case-insensitive)
    ctx3 = CallContext("agent", "sess", "validate_sql", {"sql": "drop table x"}, time.time())
    res_pattern = rule.evaluate(ctx3, session)
    assert res_pattern.outcome == "violation"
    assert "matched blocked pattern" in res_pattern.reason.lower()

    # 4. Regex pattern match
    ctx4 = CallContext("agent", "sess", "validate_sql", {"sql": "SELECT id FROM secrets"}, time.time())
    res_regex = rule.evaluate(ctx4, session)
    assert res_regex.outcome == "violation"
    assert "matched blocked pattern" in res_regex.reason.lower()

def test_data_scope_rule():
    session = SessionState("test-session")
    session.declared_scope = "project_x_"
    
    rule_cfg = {
        "type": "data_scope",
        "param": "sql",
        "allowed_table_prefix": "project_x_"
    }
    rule = DataScopeRule(rule_cfg)

    # 1. In-scope query
    ctx1 = CallContext("agent", "sess", "execute_sql", {"sql": "SELECT * FROM project_x_customers JOIN project_x_orders ON id"}, time.time())
    assert rule.evaluate(ctx1, session).outcome == "allow"

    # 2. Out-of-scope query (wrong prefix)
    ctx2 = CallContext("agent", "sess", "execute_sql", {"sql": "SELECT * FROM other_tenant_orders"}, time.time())
    res_scope = rule.evaluate(ctx2, session)
    assert res_scope.outcome == "violation"
    assert "is outside allowed prefix" in res_scope.reason.lower()

    # 3. Out-of-scope query (no prefix)
    ctx3 = CallContext("agent", "sess", "execute_sql", {"sql": "SELECT * FROM employees"}, time.time())
    assert rule.evaluate(ctx3, session).outcome == "violation"

    # 4. Non-table reference query (e.g. constant selection)
    ctx4 = CallContext("agent", "sess", "execute_sql", {"sql": "SELECT datetime('now')"}, time.time())
    assert rule.evaluate(ctx4, session).outcome == "allow"

def test_sequence_rule():
    session_id = "test-session"
    session = session_store.get_session(session_id)
    
    rule_cfg = {
        "type": "sequence",
        "requires": ["get_schema", "validate_sql"]
    }
    rule = SequenceRule(rule_cfg)
    ctx = CallContext("agent", session_id, "execute_sql", {}, time.time())

    # 1. Missing both requirements
    res1 = rule.evaluate(ctx, session)
    assert res1.outcome == "violation"
    assert "get_schema" in res1.reason
    assert "validate_sql" in res1.reason

    # 2. Missing one requirement
    session_store.record_allowed_call(session_id, "get_schema", time.time())
    res2 = rule.evaluate(ctx, session)
    assert res2.outcome == "violation"
    assert "validate_sql" in res2.reason

    # 3. All satisfied
    session_store.record_allowed_call(session_id, "validate_sql", time.time())
    assert rule.evaluate(ctx, session).outcome == "allow"

def test_risk_score_calculation():
    session_id = "test-session"
    agent_id = "test-agent"
    session = session_store.get_session(session_id)
    
    tool_rules = [
        {"type": "rate_limit", "max_calls": 5, "window_seconds": 10},
        {"type": "param_blocklist", "patterns": ["DROP"]}
    ]

    # Baseline risk should be 0 for standard query under threshold
    ctx = CallContext(agent_id, session_id, "execute_sql", {"sql": "SELECT * FROM project_x_customers"}, time.time())
    assert calculate_risk_score(ctx, session, tool_rules) == 0

    # 1. Rate Limit Proximity check (+1 risk)
    # Add 4 calls (which is 80% of 5 limit)
    t = time.time()
    for _ in range(4):
        session_store.record_call_timestamp(agent_id, "execute_sql", t)
    
    # Risk should now be 1
    assert calculate_risk_score(ctx, session, tool_rules) == 1

    # Clear rate history
    session_store.clear()
    session = session_store.get_session(session_id)

    # 2. Fuzzy match check (+2 risk)
    # Query contains fuzzy word 'admin' and 'select'
    ctx_fuzzy = CallContext(agent_id, session_id, "execute_sql", {"sql": "SELECT * FROM project_x_admin_settings"}, time.time())
    assert calculate_risk_score(ctx_fuzzy, session, tool_rules) == 2

    # 3. Adjacent suspect check (+2 risk)
    # Contains 'project_y' inside comment block (stripped during table extraction, so no data scope violation)
    ctx_adj = CallContext(agent_id, session_id, "execute_sql", {"sql": "SELECT * FROM project_x_customers; -- check project_y data"}, time.time())
    assert calculate_risk_score(ctx_adj, session, tool_rules) == 2

    # 4. Timing speed check (+3 risk)
    # Set last allowed call to just 100ms ago
    session.last_allowed_call_time = t - 0.1
    ctx_time = CallContext(agent_id, session_id, "execute_sql", {"sql": "SELECT * FROM project_x_customers"}, t)
    assert calculate_risk_score(ctx_time, session, tool_rules) == 3
