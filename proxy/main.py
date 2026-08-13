import time
import os
import requests
from typing import Dict, Any, List, Set, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, BackgroundTasks, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from proxy.config import config
from proxy.session_store import session_store
from proxy.rules import CallContext, RateLimitRule, ParamValidationRule, DataScopeRule, SequenceRule
from proxy.risk import calculate_risk_score
from proxy.audit import log_call, init_db, create_pending_review
from mcp_server.server import init_app_db, get_schema, validate_sql, execute_sql

app = FastAPI(title="Agent WAF Policy Proxy")

# Enable CORS for the dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# WebSocket Connections Registry
class ConnectionManager:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                disconnected.append(connection)
        for conn in disconnected:
            self.disconnect(conn)

manager = ConnectionManager()

class InvokeRequest(BaseModel):
    agent_id: str
    session_id: str
    tool: str
    params: Dict[str, Any]

@app.on_event("startup")
async def startup_event():
    # Automatically initialize databases on startup
    init_app_db()
    init_db()

@app.websocket("/ws/events")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection open by listening for any text (e.g., pings)
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

async def handle_audit_and_broadcast(
    agent_id: str,
    session_id: str,
    tool: str,
    params: Dict[str, Any],
    rule_results: List[Dict[str, Any]],
    risk_score: int,
    risk_band: str,
    disposition: str
):
    try:
        # Perform SQLite write and return sanitized display/WebSocket payload
        log_payload = log_call(
            agent_id=agent_id,
            session_id=session_id,
            tool=tool,
            params=params,
            rule_results=rule_results,
            risk_score=risk_score,
            risk_band=risk_band,
            disposition=disposition
        )
        # Broadcast sanitized payload to dashboard
        await manager.broadcast(log_payload)
    except Exception as e:
        print(f"Error in audit/broadcast task: {e}")

def check_recent_approval(session_id: str, tool: str, params: Dict[str, Any]) -> bool:
    import sqlite3
    import json
    from proxy.audit import DB_PATH, mask_params
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    masked = mask_params(params)
    params_str = json.dumps(masked)
    try:
        cursor.execute("""
            SELECT 1 FROM pending_reviews 
            WHERE session_id = ? AND tool = ? AND params = ? AND status = 'approved'
            LIMIT 1
        """, (session_id, tool, params_str))
        row = cursor.fetchone()
        conn.close()
        return row is not None
    except Exception:
        conn.close()
        return False

def consume_review_approval(session_id: str, tool: str, params: Dict[str, Any]):
    import sqlite3
    import json
    from proxy.audit import DB_PATH, mask_params
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    masked = mask_params(params)
    params_str = json.dumps(masked)
    try:
        cursor.execute("""
            UPDATE pending_reviews 
            SET status = 'executed' 
            WHERE session_id = ? AND tool = ? AND params = ? AND status = 'approved'
        """, (session_id, tool, params_str))
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()

def create_security_report() -> str:
    import sqlite3
    import json
    import os
    from datetime import datetime
    from proxy.audit import DB_PATH
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT ts, tool, disposition, risk_score, rule_results FROM audit_log ORDER BY ts DESC")
    rows = cursor.fetchall()
    conn.close()
    
    total = len(rows)
    blocks = sum(1 for r in rows if r["disposition"] == "blocked")
    shadows = sum(1 for r in rows if r["disposition"] == "shadow_block")
    allows = sum(1 for r in rows if r["disposition"] == "allowed")
    
    violations = {"rate_limit": 0, "param_blocklist": 0, "data_scope": 0, "sequence": 0}
    for r in rows:
        try:
            rules = json.loads(r["rule_results"])
            for rule in rules:
                if rule.get("outcome") == "violation":
                    rule_type = rule.get("rule")
                    if rule_type in violations:
                        violations[rule_type] += 1
        except Exception:
            pass
            
    low_risk = sum(1 for r in rows if r["risk_score"] < 1)
    med_risk = sum(1 for r in rows if 1 <= r["risk_score"] < 3)
    high_risk = sum(1 for r in rows if r["risk_score"] >= 3)
    
    report_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>WAF Security Patrol Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #0b0f19;
            color: #e2e8f0;
            margin: 0;
            padding: 40px;
        }}
        .container {{
            max-width: 900px;
            margin: 0 auto;
            background: rgba(30, 41, 59, 0.4);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 12px;
            padding: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
        }}
        h1 {{
            color: #f1f5f9;
            margin-top: 0;
            border-bottom: 2px solid #3b82f6;
            padding-bottom: 10px;
        }}
        .meta {{
            font-size: 14px;
            color: #94a3b8;
            margin-bottom: 30px;
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 40px;
        }}
        .card {{
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.05);
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .card h3 {{
            margin: 0 0 10px 0;
            font-size: 14px;
            color: #94a3b8;
        }}
        .card p {{
            margin: 0;
            font-size: 28px;
            font-weight: bold;
            color: #3b82f6;
        }}
        .card.blocked p {{
            color: #ef4444;
        }}
        .card.shadow p {{
            color: #f59e0b;
        }}
        .section-title {{
            font-size: 18px;
            font-weight: bold;
            color: #f1f5f9;
            margin-bottom: 15px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            padding-bottom: 5px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
            margin-bottom: 30px;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }}
        th {{
            background: rgba(15, 23, 42, 0.8);
            color: #94a3b8;
            font-weight: 600;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Agent WAF Security Patrol Report</h1>
        <div class="meta">Generated at: {report_time} | Scope: Local SQLite WAF</div>
        
        <div class="grid">
            <div class="card">
                <h3>Total Intercepts</h3>
                <p>{total}</p>
            </div>
            <div class="card blocked">
                <h3>Hard Blocks</h3>
                <p>{blocks}</p>
            </div>
            <div class="card shadow">
                <h3>Shadow Blocks</h3>
                <p>{shadows}</p>
            </div>
            <div class="card">
                <h3>Allowed Calls</h3>
                <p>{allows}</p>
            </div>
        </div>
        
        <div class="section-title">📊 Rule Violations Summary</div>
        <table>
            <thead>
                <tr>
                    <th>Rule Type</th>
                    <th>Violations Count</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Rate Limit (rate_limit)</td><td>{violations['rate_limit']}</td></tr>
                <tr><td>Parameter Blocklist (param_blocklist)</td><td>{violations['param_blocklist']}</td></tr>
                <tr><td>Data Scope Prefix Constraint (data_scope)</td><td>{violations['data_scope']}</td></tr>
                <tr><td>Sequence Verification (sequence)</td><td>{violations['sequence']}</td></tr>
            </tbody>
        </table>
        
        <div class="section-title">⚠️ Risk Levels Distribution</div>
        <table>
            <thead>
                <tr>
                    <th>Risk Band</th>
                    <th>Count</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>🟢 Low Risk (Score 0)</td><td>{low_risk}</td></tr>
                <tr><td>🟡 Medium Risk (Score 1-2)</td><td>{med_risk}</td></tr>
                <tr><td>🔴 High Risk (Score &gt;= 3)</td><td>{high_risk}</td></tr>
            </tbody>
        </table>
    </div>
</body>
</html>
"""
    reports_dir = os.path.join(os.getcwd(), "reports")
    os.makedirs(reports_dir, exist_ok=True)
    filename = f"patrol_report_{int(datetime.utcnow().timestamp())}.html"
    filepath = os.path.join(reports_dir, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)
    return filepath

@app.post("/invoke")
async def invoke_tool(request: InvokeRequest, background_tasks: BackgroundTasks):
    current_time = time.time()
    session = session_store.get_session(request.session_id)
    tool_rules = config.get_tool_rules(request.tool)
    
    # Check if this exact tool call was recently approved by HITL
    already_approved = False
    if request.tool in ["execute_sql", "validate_sql"]:
        already_approved = check_recent_approval(request.session_id, request.tool, request.params)

    ctx = CallContext(
        agent_id=request.agent_id,
        session_id=request.session_id,
        tool_name=request.tool,
        params=request.params,
        timestamp=current_time
    )

    # 1. Evaluate rules in order: rate limit -> param -> scope -> sequence
    rule_results = []
    hard_violation = None
    shadow_violation = None

    if not already_approved:
        for rule_cfg in tool_rules:
            rule_type = rule_cfg.get("type")
            rule = None
            
            if rule_type == "rate_limit":
                rule = RateLimitRule(rule_cfg, config.global_enforce)
            elif rule_type == "param_blocklist":
                rule = ParamValidationRule(rule_cfg, config.global_enforce)
            elif rule_type == "data_scope":
                rule = DataScopeRule(rule_cfg, config.global_enforce)
            elif rule_type == "sequence":
                rule = SequenceRule(rule_cfg, config.global_enforce)

            if rule:
                res = rule.evaluate(ctx, session)
                rule_results.append(res)
                
                if res.outcome == "violation":
                    if res.enforce:
                        # Capture first hard violation (order is guaranteed by config listing)
                        if hard_violation is None:
                            hard_violation = res
                    else:
                        # Capture shadow violation
                        if shadow_violation is None:
                            shadow_violation = res

    # 2. Risk score calculation
    if already_approved:
        risk_score = 0
        risk_band = "LOW"
    else:
        risk_score = calculate_risk_score(ctx, session, tool_rules)
        if risk_score >= 3:
            risk_band = "HIGH"
        elif risk_score >= 1:
            risk_band = "MED"
        else:
            risk_band = "LOW"

    # 3. Determine final disposition
    disposition = "allowed"
    reason = ""
    review_id = None

    if already_approved:
        disposition = "allowed"
        reason = "approved_by_hitl"
    elif hard_violation:
        disposition = "blocked"
        reason = hard_violation.reason
    elif risk_band == "HIGH":
        # Suspend tool execution for high risk pending admin approval (HITL)
        disposition = "pending_hitl"
        import uuid
        review_id = f"rev-{str(uuid.uuid4())[:8]}"
        create_pending_review(review_id, request.session_id, request.tool, request.params, risk_score)
        reason = f"High risk action (score: {risk_score}) suspended pending administrator review."
    elif shadow_violation:
        disposition = "shadow_block"
        reason = shadow_violation.reason

    # Format rules results for logging
    logged_results = [res.to_dict() for res in rule_results]

    # 4. If allowed / shadow_blocked, record the successful call metadata and call the real tool
    tool_result = None
    if disposition in ["allowed", "shadow_block"]:
        # Record history
        session_store.record_call_timestamp(request.agent_id, request.tool, current_time)
        session_store.record_allowed_call(request.session_id, request.tool, current_time)
        
        # Execute the tool
        if request.tool == "get_schema":
            tool_result = get_schema()
        elif request.tool == "validate_sql":
            tool_result = validate_sql(request.params.get("sql", ""))
        elif request.tool == "execute_sql":
            tool_result = execute_sql(request.params.get("sql", ""))
        elif request.tool == "generate_security_report":
            try:
                filepath = create_security_report()
                filename = os.path.basename(filepath)
                tool_result = {
                    "status": "success",
                    "message": f"WAF Security Patrol Report successfully generated. Path: {filepath}",
                    "filename": filename
                }
            except Exception as e:
                tool_result = {"status": "error", "error": str(e)}
        else:
            tool_result = {"status": "error", "error": f"Unknown tool: {request.tool}"}

    # 5. Schedule database writing & WebSocket notification in background
    background_tasks.add_task(
        handle_audit_and_broadcast,
        agent_id=request.agent_id,
        session_id=request.session_id,
        tool=request.tool,
        params=request.params,
        rule_results=logged_results,
        risk_score=risk_score,
        risk_band=risk_band,
        disposition=disposition
    )

    if already_approved:
        consume_review_approval(request.session_id, request.tool, request.params)

    # 6. Return response
    if disposition == "blocked":
        return {
            "status": "blocked",
            "disposition": "blocked",
            "reason": reason,
            "risk_score": risk_score,
            "risk_band": risk_band
        }
    elif disposition == "pending_hitl":
        return {
            "status": "pending",
            "disposition": "pending_hitl",
            "review_id": review_id,
            "reason": reason,
            "risk_score": risk_score,
            "risk_band": risk_band
        }
    else:
        return {
            "status": "success",
            "disposition": disposition,
            "result": tool_result,
            "reason": reason,
            "risk_score": risk_score,
            "risk_band": risk_band
        }

@app.post("/clear")
async def clear_session():
    # Helper endpoint to clean states for test runs
    session_store.clear()
    return {"status": "cleared"}

class ChatRequest(BaseModel):
    query: str
    session_id: str
    api_key: Optional[str] = None
    model: Optional[str] = "openai/gpt-oss-120b"

@app.post("/chat")
async def chat_agent(request: ChatRequest, background_tasks: BackgroundTasks):
    api_key = request.api_key or os.environ.get("GROQ_API_KEY")
    if not api_key:
        return {
            "status": "error",
            "error": "Groq API Key is missing. Please enter it in the chat settings or set the GROQ_API_KEY environment variable."
        }

    agent_id = "chatbot-web"

    # Ingress/Prompt Auditing: Check if raw user query violates WAF policies
    val_rules = config.get_tool_rules("validate_sql")
    exec_rules = config.get_tool_rules("execute_sql")
    session = session_store.get_session(request.session_id)
    
    prompt_ctx = CallContext(
        agent_id=agent_id,
        session_id=request.session_id,
        tool_name="user_prompt",
        params={"sql": request.query},
        timestamp=time.time()
    )
    
    prompt_violation = None
    prompt_rule_results = []
    
    # Check blocklist rules on prompt
    param_cfg = next((r for r in val_rules if r.get("type") == "param_blocklist"), None)
    if param_cfg:
        rule = ParamValidationRule(param_cfg, config.global_enforce)
        res = rule.evaluate(prompt_ctx, session)
        prompt_rule_results.append(res.to_dict())
        if res.outcome == "violation" and res.enforce:
            prompt_violation = res
            
    # Check data scope rules on prompt
    scope_cfg = next((r for r in exec_rules if r.get("type") == "data_scope"), None)
    if scope_cfg:
        rule = DataScopeRule(scope_cfg, config.global_enforce)
        res = rule.evaluate(prompt_ctx, session)
        prompt_rule_results.append(res.to_dict())
        if res.outcome == "violation" and res.enforce and not prompt_violation:
            prompt_violation = res
            
    # Log prompt block event to audit log and stream it to the dashboard
    if prompt_violation:
        background_tasks.add_task(
            handle_audit_and_broadcast,
            agent_id=agent_id,
            session_id=request.session_id,
            tool="user_prompt",
            params={"query": request.query},
            rule_results=prompt_rule_results,
            risk_score=3,
            risk_band="HIGH",
            disposition="blocked"
        )
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    # SQLite tools schema for LLM function calling
    tools_schema = [
        {
            "type": "function",
            "function": {
                "name": "get_schema",
                "description": "Retrieves the database schema showing tables and column definitions."
            }
        },
        {
            "type": "function",
            "function": {
                "name": "validate_sql",
                "description": "Validates the structure of a SQL query prior to execution. Required step before executing SQL.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "sql": {"type": "string", "description": "The SQL query to check syntax."}
                    },
                    "required": ["sql"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "execute_sql",
                "description": "Runs a SQL query against the database and returns rows. Must only call after validating the SQL.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "sql": {"type": "string", "description": "The SQL query to run."}
                    },
                    "required": ["sql"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "generate_security_report",
                "description": "Generates a WAF security patrol report based on all intercepted WAF logs."
            }
        }
    ]

    messages = [
        {
            "role": "system",
            "content": (
                "You are an AI assistant that translates natural language questions into SQLite queries and answers them.\n"
                "You must use the provided database tools in order to complete your task.\n"
                "CRITICAL INSTRUCTIONS:\n"
                "1. First, always inspect the schema of the database using get_schema.\n"
                "2. When you build your query, you must first validate it using validate_sql.\n"
                "3. If validation succeeds, execute the query using execute_sql to obtain results.\n"
                "4. All tables you query must start with 'project_x_'. Any other table will fail security restrictions.\n"
                "5. Only call one tool at a time.\n"
                "6. If the user asks for a security report, weekly report, or security patrol report, invoke the generate_security_report tool."
            )
        },
        {"role": "user", "content": request.query}
    ]

    steps = []
    max_steps = 8
    step = 0
    final_response = "Unable to fetch complete response from agent."

    while step < max_steps:
        step += 1
        payload = {
            "model": request.model,
            "messages": messages,
            "tools": tools_schema,
            "tool_choice": "auto"
        }

        try:
            res = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                json=payload,
                headers=headers,
                timeout=20
            )
            
            if res.status_code != 200:
                final_response = f"Groq API returned error {res.status_code}: {res.text}"
                break

            res_json = res.json()
            choice = res_json["choices"][0]
            message = choice["message"]
            messages.append(message)

            # Check if model wants to call a tool
            if "tool_calls" in message and message["tool_calls"]:
                tool_call = message["tool_calls"][0]
                tool_name = tool_call["function"]["name"]
                
                try:
                    import json
                    tool_args = json.loads(tool_call["function"]["arguments"])
                except Exception:
                    tool_args = {}

                # Execute tool call directly in-memory as a Python coroutine
                # This avoids network deadlocks on single-worker Uvicorn servers!
                invoke_req = InvokeRequest(
                    agent_id=agent_id,
                    session_id=request.session_id,
                    tool=tool_name,
                    params=tool_args
                )
                
                try:
                    waf_res = await invoke_tool(invoke_req, background_tasks)
                except Exception as invoke_err:
                    steps.append({
                        "tool": tool_name,
                        "args": tool_args,
                        "disposition": "blocked",
                        "reason": f"Internal WAF Invoke Error: {str(invoke_err)}"
                    })
                    break
                
                disposition = waf_res.get("disposition")
                review_id = waf_res.get("review_id")
                
                steps.append({
                    "tool": tool_name,
                    "args": tool_args,
                    "disposition": disposition,
                    "risk_score": waf_res.get("risk_score", 0),
                    "risk_band": waf_res.get("risk_band", "LOW"),
                    "reason": waf_res.get("reason", "")
                })

                # Handle HITL (Human-in-the-Loop) suspension: return immediately to avoid blocking client
                if disposition == "pending_hitl" and review_id:
                    return {
                        "status": "pending",
                        "disposition": "pending_hitl",
                        "review_id": review_id,
                        "response": f"Action blocked: High risk action (score: {waf_res.get('risk_score', 3)}) suspended pending administrator review.",
                        "steps": steps
                    }

                if disposition == "blocked":
                    block_content = {"status": "blocked", "error": f"Security Policy Violation: {waf_res.get('reason')}"}
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call["id"],
                        "name": tool_name,
                        "content": json.dumps(block_content)
                    })
                else:
                    result_data = waf_res.get("result", {})
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call["id"],
                        "name": tool_name,
                        "content": json.dumps(result_data)
                    })
            else:
                final_response = message.get("content", "")
                break

        except Exception as e:
            final_response = f"Exception in agent loop: {str(e)}"
            break

    return {
        "status": "success",
        "response": final_response,
        "steps": steps
    }

@app.get("/logs")
async def get_logs():
    import sqlite3
    import json
    from proxy.audit import DB_PATH
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT ts, agent_id, session_id, tool, params, rule_results, risk_score, risk_band, disposition 
            FROM audit_log 
            ORDER BY ts DESC 
            LIMIT 100
        """)
        rows = cursor.fetchall()
        logs = []
        for row in rows:
            try:
                params_dict = json.loads(row["params"])
            except Exception:
                params_dict = {"raw": row["params"]}
                
            try:
                rules_list = json.loads(row["rule_results"])
            except Exception:
                rules_list = []

            logs.append({
                "ts": row["ts"],
                "agent_id": row["agent_id"],
                "session_id": row["session_id"],
                "tool": row["tool"],
                "params": params_dict,
                "rule_results": rules_list,
                "risk_score": row["risk_score"],
                "risk_band": row["risk_band"],
                "disposition": row["disposition"]
            })
        conn.close()
        return logs
    except Exception as e:
        conn.close()
        return {"status": "error", "error": str(e)}

class ResolveReviewRequest(BaseModel):
    decision: str

@app.get("/admin/reviews")
async def admin_get_reviews():
    from proxy.audit import get_pending_reviews
    return get_pending_reviews()

@app.post("/admin/reviews/{review_id}/resolve")
async def admin_resolve_review(review_id: str, payload: ResolveReviewRequest):
    from proxy.audit import resolve_review
    success = resolve_review(review_id, payload.decision)
    if success:
        return {"status": "success", "message": f"Review {review_id} resolved as {payload.decision}."}
    return {"status": "error", "error": "Review not found or already resolved."}

@app.get("/invoke/status/{review_id}")
async def get_invoke_status(review_id: str):
    from proxy.audit import get_review_status
    status = get_review_status(review_id)
    return {"status": "success", "review_id": review_id, "decision": status}
