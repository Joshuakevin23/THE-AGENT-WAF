import streamlit as st
import os
import time
import requests
import pandas as pd
from datetime import datetime
from dotenv import load_dotenv

# Load API credentials from .env file
load_dotenv()

# Set up page configurations
st.set_page_config(
    page_title="Agent WAF Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Backend FastAPI settings
BACKEND_URL = "http://127.0.0.1:8000"
CHAT_ENDPOINT = f"{BACKEND_URL}/chat"
LOGS_ENDPOINT = f"{BACKEND_URL}/logs"

# Styling improvements
st.markdown("""
<style>
    .reportview-container {
        background: #090d16;
    }
    .status-allowed {
        color: #10b981;
        font-weight: bold;
    }
    .status-blocked {
        color: #ef4444;
        font-weight: bold;
    }
    .status-shadow {
        color: #f59e0b;
        font-weight: bold;
    }
    .risk-badge {
        padding: 2px 6px;
        border-radius: 4px;
        font-size: 12px;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# Helper to format timestamps
def format_time(ts_str):
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.strftime("%H:%M:%S")
    except Exception:
        return ts_str

# Sidebar Configuration
st.sidebar.title("🛡️ Agent WAF Settings")

# Check API Key from .env
api_key = os.getenv("GROQ_API_KEY")
if api_key:
    st.sidebar.success("🔑 API Key loaded from `.env`")
else:
    st.sidebar.warning("⚠️ No API Key found in `.env`")
    # Fallback input field
    api_key = st.sidebar.text_input("Enter Groq API Key (Fallback)", type="password")

# Fetch active pending reviews count to show a badge in the sidebar
pending_count = 0
try:
    p_res = requests.get(f"{BACKEND_URL}/admin/reviews", timeout=2)
    if p_res.status_code == 200:
        pending_count = len(p_res.json())
except Exception:
    pass

nav_label = "📊 Admin Dashboard"
if pending_count > 0:
    nav_label += f" ({pending_count} pending)"

# Navigation Selector
page = st.sidebar.radio("Navigation", ["🤖 Chat Agent Console", "🧪 Demo Scenarios", nav_label])

# Model Selection
model = st.sidebar.selectbox(
    "Groq Model",
    ["openai/gpt-oss-120b", "llama-3.1-70b-versatile", "llama3-70b-8192", "mixtral-8x7b-32768"],
    index=0
)

# Active Session ID management
if "session_id" not in st.session_state:
    st.session_state.session_id = f"sess-st-{int(time.time())}"

st.sidebar.text_input("Active Session ID", value=st.session_state.session_id, disabled=True)

st.sidebar.divider()
if st.sidebar.button("🚀 Run Automated Demo Agent", use_container_width=True, help="Simulate a scripted agent to generate test traffic logs"):
    agent_id = "agent-scripted"
    demo_session_id = f"demo-{int(time.time())}"
    results = []
    with st.sidebar.status("Running Demo Agent...", expanded=True) as status:
        st.write("1️⃣ Calling `get_schema`...")
        r1 = requests.post(f"{BACKEND_URL}/invoke", json={"agent_id": agent_id, "session_id": demo_session_id, "tool": "get_schema", "params": {}}, timeout=5).json()
        results.append({"step": 1, "tool": "get_schema", "response": r1})
        time.sleep(0.5)
        
        st.write("2️⃣ Calling `validate_sql`...")
        sql = "SELECT * FROM project_x_customers;"
        r2 = requests.post(f"{BACKEND_URL}/invoke", json={"agent_id": agent_id, "session_id": demo_session_id, "tool": "validate_sql", "params": {"sql": sql}}, timeout=5).json()
        results.append({"step": 2, "tool": "validate_sql", "response": r2})
        time.sleep(0.5)
        
        st.write("3️⃣ Calling `execute_sql`...")
        r3 = requests.post(f"{BACKEND_URL}/invoke", json={"agent_id": agent_id, "session_id": demo_session_id, "tool": "execute_sql", "params": {"sql": sql}}, timeout=5).json()
        results.append({"step": 3, "tool": "execute_sql", "response": r3})
        time.sleep(0.5)
        
        status.update(label="Demo Complete! View Results in Main Panel.", state="complete", expanded=False)
    
    st.session_state.demo_results = results
st.sidebar.divider()

# Display DB Info in Sidebar
st.sidebar.info("""
### 📋 Seeded DB Info
**Allowed Tables:**
* `project_x_customers`
* `project_x_orders`
* `project_x_employees`

**Blocked Tables:**
* `other_tenant_orders` (wrong prefix)
* `employees` (no prefix)
""")

# WAF Pipeline Visualization in Sidebar
st.sidebar.markdown("""
<style>
.pipeline-container {
    display: flex;
    flex-direction: column;
    align-items: center;
    font-family: sans-serif;
    margin-top: 10px;
    margin-bottom: 20px;
    padding: 0 10px;
}
.pipeline-node {
    background: #0f172a;
    border: 2px solid #334155;
    border-radius: 8px;
    padding: 12px;
    width: 100%;
    text-align: center;
    position: relative;
    z-index: 2;
    transition: all 0.3s ease;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
}
.pipeline-node:hover {
    border-color: #3b82f6;
    transform: translateY(-2px);
    box-shadow: 0 6px 12px -2px rgba(59, 130, 246, 0.4);
}
.pipeline-pipe {
    width: 4px;
    height: 24px;
    background: linear-gradient(to bottom, #334155, #475569);
    margin: 0 auto;
    z-index: 1;
}
.node-title {
    font-weight: bold;
    font-size: 14px;
    color: #f8fafc;
    margin-bottom: 4px;
}
.node-desc {
    font-size: 11px;
    color: #94a3b8;
}
</style>
<hr/>
<div style="text-align: center; font-weight: bold; margin-bottom: 15px; color: #f8fafc; font-size: 16px;">
    🔄 Proxy Workflow Pipeline
</div>
<div class="pipeline-container">
    <div class="pipeline-node" style="border-color: #8b5cf6;">
        <div class="node-title">1️⃣ Intercept</div>
        <div class="node-desc">Agent Tool Call Captured</div>
    </div>
    <div class="pipeline-pipe"></div>
    <div class="pipeline-node" style="border-color: #0ea5e9;">
        <div class="node-title">2️⃣ Risk Analysis</div>
        <div class="node-desc">Policy, Scope & Rate Checks</div>
    </div>
    <div class="pipeline-pipe"></div>
    <div class="pipeline-node" style="border-color: #10b981;">
        <div class="node-title">3️⃣ Decision Engine</div>
        <div class="node-desc">Allow / Block / Shadow</div>
    </div>
    <div class="pipeline-pipe"></div>
    <div class="pipeline-node" style="border-color: #f59e0b;">
        <div class="node-title">4️⃣ HITL Review</div>
        <div class="node-desc">Admin Approval for High Risk</div>
    </div>
    <div class="pipeline-pipe"></div>
    <div class="pipeline-node" style="border-color: #ef4444;">
        <div class="node-title">5️⃣ Execution</div>
        <div class="node-desc">Action Runs on DB</div>
    </div>
</div>
<hr/>
""", unsafe_allow_html=True)

# Render rule validation traces
def render_traces(steps):
    if not steps:
        return
    with st.expander("🛡️ View WAF Interception Traces", expanded=True):
        for idx, step in enumerate(steps):
            col1, col2 = st.columns([1, 4])
            
            disposition = step.get("disposition", "unknown")
            if disposition == "blocked":
                disp_html = f"<span class='status-blocked'>Blocked</span>"
            elif disposition == "shadow_block":
                disp_html = f"<span class='status-shadow'>Shadow Blocked</span>"
            else:
                disp_html = f"<span class='status-allowed'>Allowed</span>"
                
            with col1:
                st.markdown(f"**Step {idx+1}:** {step.get('tool')}")
                st.markdown(disp_html, unsafe_allow_html=True)
            with col2:
                st.markdown(f"**Args:** `{step.get('args')}`")
                st.markdown(f"**Risk:** {step.get('risk_band')} (Score: {step.get('risk_score')})")
                if step.get("reason"):
                    st.error(f"Reason: {step.get('reason')}")
            st.divider()

# ========================================================
# Page 1: Chat Agent Console
# ========================================================
if page == "🤖 Chat Agent Console":
    st.title("🤖 Agent WAF Chat Console")
    st.caption("Interact with the tenant database. Your queries and intermediate tool actions are processed via WAF.")

    # Render Automated Demo Results if triggered
    if "demo_results" in st.session_state and st.session_state.demo_results:
        st.info("ℹ️ **Automated Demo Agent Results**")
        with st.expander("🚀 View Detailed Pipeline Execution for Demo Agent", expanded=True):
            for res in st.session_state.demo_results:
                step = res["step"]
                tool = res["tool"]
                data = res["response"]
                
                disposition = data.get("disposition", "unknown")
                if disposition == "blocked":
                    disp_html = "<span class='status-blocked'>Blocked</span>"
                elif disposition == "shadow_block":
                    disp_html = "<span class='status-shadow'>Shadow Blocked</span>"
                elif disposition == "pending_hitl":
                    disp_html = "<span style='color: orange; font-weight: bold;'>Pending HITL</span>"
                else:
                    disp_html = "<span class='status-allowed'>Allowed</span>"
                
                st.markdown(f"### Step {step}: `{tool}`")
                st.markdown(disp_html, unsafe_allow_html=True)
                
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("**Action Reason / Justification:**")
                    if data.get("reason"):
                        if disposition == "blocked":
                            st.error(data.get("reason"))
                        elif disposition == "shadow_block":
                            st.warning(data.get("reason"))
                        elif disposition == "pending_hitl":
                            st.warning(data.get("reason"))
                        else:
                            st.success(data.get("reason"))
                    else:
                        st.info("No explicit reason provided.")
                with col2:
                    st.markdown(f"**Risk Band:** {data.get('risk_band')} (Score: {data.get('risk_score')})")
                    st.markdown("**Raw Output / Response:**")
                    st.json(data.get("result", {}))
                
                st.divider()
        
        if st.button("Clear Demo Results"):
            st.session_state.demo_results = None
            st.rerun()

    # Check if there is a pending review that needs approval checking
    if "pending_review" in st.session_state and st.session_state.pending_review:
        p_info = st.session_state.pending_review
        review_id = p_info["review_id"]
        try:
            status_res = requests.get(f"{BACKEND_URL}/invoke/status/{review_id}", timeout=2)
            if status_res.status_code == 200:
                decision = status_res.json().get("decision", "pending")
                if decision == "approved":
                    st.success("✅ Action approved by administrator! Resubmitting original query...")
                    original_query = p_info["query"]
                    original_model = p_info["model"]
                    st.session_state.pending_review = None
                    
                    st.session_state.messages.append({
                        "role": "user",
                        "content": f"🔄 [Resubmitted Approved Action] {original_query}"
                    })
                    
                    # Submit query to /chat automatically
                    with st.chat_message("assistant"):
                        with st.spinner("Executing approved query..."):
                            payload = {
                                "query": original_query,
                                "session_id": st.session_state.session_id,
                                "api_key": api_key,
                                "model": original_model
                            }
                            res = requests.post(CHAT_ENDPOINT, json=payload, timeout=30)
                            if res.status_code == 200:
                                data = res.json()
                                if data.get("status") == "success":
                                    st.markdown(data.get("response", ""))
                                    render_traces(data.get("steps"))
                                    st.session_state.messages.append({
                                        "role": "assistant",
                                        "content": data.get("response", ""),
                                        "steps": data.get("steps")
                                    })
                                elif data.get("status") == "pending":
                                    st.session_state.pending_review = {
                                        "review_id": data.get("review_id"),
                                        "query": original_query,
                                        "model": original_model
                                    }
                                    st.warning(f"⏳ Action suspended. Requires administrator approval (Review ID: `{data.get('review_id')}`).")
                                else:
                                    st.error(f"Error: {data.get('error', 'Unknown error')}")
                            else:
                                st.error(f"HTTP Error: {res.text}")
                    st.rerun()
                elif decision == "denied":
                    st.error("❌ Action denied by administrator.")
                    st.session_state.messages.append({
                        "role": "assistant",
                        "content": "❌ Action denied by administrator."
                    })
                    st.session_state.pending_review = None
                    st.rerun()
                else:
                    st.info(f"⏳ **Action pending administrator approval** (Review ID: `{review_id}`).\n\nPlease switch to the **📊 Admin Dashboard** in the sidebar to review and approve it, then return here.")
        except Exception as e:
            st.error(f"Error checking review status: {e}")

    # Initialize chat log state
    if "messages" not in st.session_state:
        st.session_state.messages = []

    # Display chat logs
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
            if msg.get("steps"):
                render_traces(msg["steps"])

    # User Input
    if prompt := st.chat_input("Ask a question about customers, orders, or employees..."):
        # Append User query to screen
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        # Query the backend agent
        with st.chat_message("assistant"):
            if not api_key:
                st.error("Groq API Key is missing. Please set it in the `.env` file or sidebar fallback.")
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": "Groq API Key is missing. Please configure it."
                })
            else:
                with st.spinner("Agent planning and invoking database tools..."):
                    payload = {
                        "query": prompt,
                        "session_id": st.session_state.session_id,
                        "api_key": api_key,
                        "model": model
                    }
                    try:
                        res = requests.post(CHAT_ENDPOINT, json=payload, timeout=30)
                        if res.status_code == 200:
                            data = res.json()
                            if data.get("status") == "success":
                                st.markdown(data.get("response", ""))
                                render_traces(data.get("steps"))
                                
                                # Store to session state
                                st.session_state.messages.append({
                                    "role": "assistant",
                                    "content": data.get("response", ""),
                                    "steps": data.get("steps")
                                })
                            elif data.get("status") == "pending":
                                st.session_state.pending_review = {
                                    "review_id": data.get("review_id"),
                                    "query": prompt,
                                    "model": model
                                }
                                warning_text = f"⏳ **Action suspended.** A high risk action requires administrator approval (Review ID: `{data.get('review_id')}`).\n\nPlease select **📊 Admin Dashboard** in the sidebar to review and approve it."
                                st.warning(warning_text)
                                st.session_state.messages.append({
                                    "role": "assistant",
                                    "content": warning_text,
                                    "steps": data.get("steps")
                                })
                            else:
                                error_msg = f"Error: {data.get('error', 'Unknown agent error')}"
                                st.error(error_msg)
                                st.session_state.messages.append({
                                    "role": "assistant",
                                    "content": error_msg
                                })
                        else:
                            error_msg = f"HTTP Error {res.status_code}: {res.text}"
                            st.error(error_msg)
                            st.session_state.messages.append({
                                "role": "assistant",
                                "content": error_msg
                            })
                    except Exception as e:
                        error_msg = f"Connection Error: {str(e)}"
                        st.error(error_msg)
                        st.session_state.messages.append({
                            "role": "assistant",
                            "content": error_msg
                        })
        
        # Scroll to bottom
        st.rerun()

# ========================================================
# Page 2: Demo Scenarios
# ========================================================
elif page == "🧪 Demo Scenarios":
    st.title("🧪 Pre-configured Demo Scenarios")
    st.caption("Click a scenario below to run a scripted sequence of WAF tool calls and see how the proxy responds.")
    
    # Helper to run a sequence
    def run_scenario(name, steps, resume_data=None):
        agent_id = resume_data["agent_id"] if resume_data else f"demo-{name.lower().replace(' ', '-')}"
        session_id = resume_data["session_id"] if resume_data else f"{agent_id}-{int(time.time())}"
        results = resume_data["results"] if resume_data else []
        start_idx = resume_data["current_step_idx"] if resume_data else 1
        
        with st.status(f"Running Scenario: {name}...", expanded=True) as status:
            for i, step in enumerate(steps):
                step_idx = start_idx + i
                tool = step["tool"]
                params = step["params"]
                st.write(f"{step_idx}️⃣ Calling `{tool}`...")
                res = requests.post(f"{BACKEND_URL}/invoke", json={"agent_id": agent_id, "session_id": session_id, "tool": tool, "params": params}, timeout=5).json()
                
                # If HITL triggered, halt the scenario
                if res.get("disposition") == "pending_hitl":
                    status.update(label="Scenario paused for Admin Approval.", state="error", expanded=False)
                    st.session_state.demo_pending_review = {
                        "review_id": res.get("review_id"),
                        "name": name,
                        "agent_id": agent_id,
                        "session_id": session_id,
                        "current_step_idx": step_idx,
                        "remaining_steps": steps[i:], # Include the current step so it gets re-run when approved
                        "results": results
                    }
                    st.rerun()
                    return

                results.append({"step": step_idx, "tool": tool, "response": res})
                time.sleep(0.5)
            status.update(label=f"Scenario Complete!", state="complete", expanded=False)
        st.session_state.scenario_results = results
        st.rerun()

    # Check for pending HITL demo review
    if "demo_pending_review" in st.session_state and st.session_state.demo_pending_review:
        review = st.session_state.demo_pending_review
        review_id = review["review_id"]
        
        try:
            status_res = requests.get(f"{BACKEND_URL}/admin/reviews/{review_id}", timeout=3)
            if status_res.status_code == 200:
                rev_data = status_res.json()
                decision = rev_data.get("decision")
                if decision == "approved":
                    st.success("✅ Action approved by administrator! Resuming scenario...")
                    st.session_state.demo_pending_review = None
                    # Resume by re-running the remaining steps (which starts with the originally pending tool call)
                    run_scenario(review["name"], review["remaining_steps"], resume_data=review)
                elif decision == "denied":
                    st.error("❌ Action denied by administrator. Scenario halted.")
                    # Manually inject the blocked result for the pending step
                    review["results"].append({
                        "step": review["current_step_idx"],
                        "tool": review["remaining_steps"][0]["tool"],
                        "response": {"disposition": "blocked", "reason": "Action denied by administrator.", "risk_score": 3, "risk_band": "HIGH"}
                    })
                    st.session_state.scenario_results = review["results"]
                    st.session_state.demo_pending_review = None
                    st.rerun()
                else:
                    st.info(f"⏳ **Scenario paused.** Action pending administrator approval (Review ID: `{review_id}`).\n\nPlease switch to the **📊 Admin Dashboard** in the sidebar to review and approve it, then return here.")
        except Exception as e:
            st.error(f"Error checking review status: {e}")
            
    # Scenario Definitions
    scenarios = {
        "1. Happy Path (Allowed)": {
            "desc": "Simulates a standard allowed query where the agent checks the schema and queries a permitted table.",
            "steps": [
                {"tool": "get_schema", "params": {}},
                {"tool": "validate_sql", "params": {"sql": "SELECT * FROM project_x_customers;"}},
                {"tool": "execute_sql", "params": {"sql": "SELECT * FROM project_x_customers;"}}
            ]
        },
        "2. Data Scope Block (Blocked)": {
            "desc": "Simulates the agent attempting to access another tenant's table (other_tenant_orders), which is immediately blocked upon execution.",
            "steps": [
                {"tool": "get_schema", "params": {}},
                {"tool": "validate_sql", "params": {"sql": "SELECT * FROM other_tenant_orders;"}},
                {"tool": "execute_sql", "params": {"sql": "SELECT * FROM other_tenant_orders;"}}
            ]
        },
        "3. Shadow Mode (Shadowed)": {
            "desc": "Simulates the agent querying the schema multiple times in a row, which triggers the rate-limit rule but it is in 'shadow mode' (so it shadows instead of blocking).",
            "steps": [
                {"tool": "get_schema", "params": {}},
                {"tool": "get_schema", "params": {}},
                {"tool": "get_schema", "params": {}},
                {"tool": "get_schema", "params": {}},
                {"tool": "get_schema", "params": {}},
                {"tool": "get_schema", "params": {}},
                {"tool": "get_schema", "params": {}},
                {"tool": "get_schema", "params": {}},
                {"tool": "get_schema", "params": {}},
                {"tool": "get_schema", "params": {}},
                {"tool": "get_schema", "params": {}}
            ]
        },
        "4. High Risk (HITL)": {
            "desc": "Simulates the agent attempting a destructive action (TRUNCATE). This passes the initial validator but is flagged as High Risk (Score 3) and sent for administrator approval.",
            "steps": [
                {"tool": "get_schema", "params": {}},
                {"tool": "validate_sql", "params": {"sql": "TRUNCATE project_x_customers;"}},
                {"tool": "execute_sql", "params": {"sql": "TRUNCATE project_x_customers;"}}
            ]
        }
    }

    # Scenario Buttons
    col1, col2 = st.columns(2)
    for idx, (s_name, s_data) in enumerate(scenarios.items()):
        target_col = col1 if idx % 2 == 0 else col2
        with target_col:
            st.markdown(f"**{s_name}**")
            st.caption(s_data["desc"])
            if st.button(f"▶️ Run", key=s_name, use_container_width=True):
                run_scenario(s_name, s_data["steps"])
        if idx % 2 == 1:
            st.write("") # spacing

    st.divider()

    # Render Results
    if "scenario_results" in st.session_state and st.session_state.scenario_results:
        st.subheader("📊 Scenario Execution Results")
        for res in st.session_state.scenario_results:
            step = res["step"]
            tool = res["tool"]
            data = res["response"]
            
            disposition = data.get("disposition", "unknown")
            if disposition == "blocked":
                disp_html = "<span class='status-blocked'>Blocked</span>"
                status_emoji = "🛑"
            elif disposition == "shadow_block":
                disp_html = "<span class='status-shadow'>Shadow Blocked</span>"
                status_emoji = "👻"
            elif disposition == "pending_hitl":
                disp_html = "<span style='color: orange; font-weight: bold;'>Pending HITL</span>"
                status_emoji = "⏳"
            else:
                disp_html = "<span class='status-allowed'>Allowed</span>"
                status_emoji = "✅"
            
            st.markdown(f"### {status_emoji} Step {step}: `{tool}`")
            st.markdown(disp_html, unsafe_allow_html=True)
            
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("**Action Reason:**")
                if data.get("reason"):
                    if disposition == "blocked":
                        st.error(data.get("reason"))
                    elif disposition == "shadow_block":
                        st.warning(data.get("reason"))
                    elif disposition == "pending_hitl":
                        st.warning(data.get("reason"))
                    else:
                        st.success(data.get("reason"))
                else:
                    st.info("No explicit reason provided.")
            with c2:
                st.markdown(f"**Risk Band:** {data.get('risk_band')} (Score: {data.get('risk_score')})")
                st.markdown("**Execution Summary:**")
                
                # Format output as summary instead of raw JSON
                result_data = data.get("result", {})
                if disposition == "blocked":
                    st.markdown("*Execution was blocked. No data returned from database.*")
                elif disposition == "shadow_block":
                    st.markdown("*Execution was simulated (shadowed). Returned safe mock data to the agent.*")
                elif disposition == "pending_hitl":
                    st.markdown("*Execution is suspended awaiting Administrator Approval.*")
                elif tool == "get_schema":
                    tables = result_data.get("schema", {}).keys()
                    st.markdown(f"*Successfully retrieved schema for {len(tables)} tables.*")
                elif tool == "execute_sql":
                    rows = result_data.get("rows", [])
                    st.markdown(f"*Successfully executed query. Returned {len(rows)} rows.*")
                else:
                    st.markdown(f"*Action '{tool}' completed successfully.*")
                    
            st.divider()
            
        if st.button("Clear Results"):
            st.session_state.scenario_results = None
            st.rerun()

# ========================================================
# Page 3: Admin Dashboard
# ========================================================
elif page.startswith("📊 Admin Dashboard"):
    st.title("🛡️ WAF Policy Admin Dashboard")
    st.caption("Real-Time Analytics & Security Policy Enforcement Visualizer")

    # Auto-refresh control
    auto_refresh = st.sidebar.checkbox("Auto-refresh (every 3 seconds)", value=True)

    # 0. Admin HITL Review Queue
    st.subheader("🔔 Human-in-the-Loop Review Queue")
    
    pending_reviews = []
    try:
        p_res = requests.get(f"{BACKEND_URL}/admin/reviews", timeout=3)
        if p_res.status_code == 200:
            pending_reviews = p_res.json()
    except Exception as e:
        st.warning(f"Unable to load review queue: {e}")
        
    if not pending_reviews:
        st.success("✅ No pending reviews in the queue. All clear!")
    else:
        st.warning(f"There are {len(pending_reviews)} action(s) suspended awaiting approval:")
        import json
        for rev in pending_reviews:
            with st.container():
                st.markdown(f"**Review ID:** `{rev['review_id']}` | **Session:** `{rev['session_id']}` | **Tool:** `{rev['tool']}` | **Risk Score:** `{rev['risk_score']}`")
                st.code(json.dumps(rev['params'], indent=2), language="json")
                
                # Approve / Deny buttons
                col_app, col_deny, col_sp = st.columns([1, 1, 8])
                with col_app:
                    if st.button("Approve ✅", key=f"app-{rev['review_id']}"):
                        try:
                            resolve_res = requests.post(f"{BACKEND_URL}/admin/reviews/{rev['review_id']}/resolve", json={"decision": "approved"}, timeout=5)
                            if resolve_res.status_code == 200:
                                st.success("Approved successfully!")
                                time.sleep(0.5)
                                st.rerun()
                            else:
                                st.error("Failed to approve.")
                        except Exception as err:
                            st.error(str(err))
                with col_deny:
                    if st.button("Deny ❌", key=f"deny-{rev['review_id']}"):
                        try:
                            resolve_res = requests.post(f"{BACKEND_URL}/admin/reviews/{rev['review_id']}/resolve", json={"decision": "denied"}, timeout=5)
                            if resolve_res.status_code == 200:
                                st.success("Denied successfully!")
                                time.sleep(0.5)
                                st.rerun()
                            else:
                                st.error("Failed to deny.")
                        except Exception as err:
                            st.error(str(err))
            st.divider()

    # Fetch logs from FastAPI
    logs = []
    try:
        res = requests.get(LOGS_ENDPOINT, timeout=5)
        if res.status_code == 200:
            logs = res.json()
        else:
            st.error(f"Failed to fetch logs: HTTP {res.status_code}")
    except Exception as e:
        st.error(f"Error connecting to proxy logs endpoint: {e}")

    if not logs:
        st.info("No tool transaction log entries found in the audit database. Start chatting to generate logs!")
    else:
        # 1. Metrics Calculation
        total_intercepts = len(logs)
        blocked_calls = sum(1 for log in logs if log.get("disposition") == "blocked")
        shadow_calls = sum(1 for log in logs if log.get("disposition") == "shadow_block")
        active_sessions = len(set(log.get("session_id") for log in logs))
        block_rate = (blocked_calls / total_intercepts * 100) if total_intercepts > 0 else 0.0

        # Display Metrics Cards
        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric("Total Intercepts", total_intercepts)
        col2.metric("Blocked Calls", blocked_calls, delta=None, delta_color="inverse")
        col3.metric("Shadow Blocks", shadow_calls)
        col4.metric("Block Rate", f"{block_rate:.1f}%")
        col5.metric("Active Sessions", active_sessions)

        st.divider()

        # 2. Charts Section
        df = pd.DataFrame(logs)
        
        chart_col1, chart_col2 = st.columns(2)

        with chart_col1:
            st.subheader("📈 System Load (Calls over Time)")
            if not df.empty:
                # Parse timestamp and group into time series
                df["datetime"] = pd.to_datetime(df["ts"])
                # Group by 10 seconds intervals
                df_grouped = df.resample("10s", on="datetime").size().reset_index(name="Calls")
                df_grouped = df_grouped.tail(15) # Show last 15 periods
                st.line_chart(df_grouped.set_index("datetime")["Calls"])
            else:
                st.write("Insufficient metrics data.")

        with chart_col2:
            st.subheader("📊 Violations by Rule Type")
            # Loop logs and count rule violations
            violation_counts = {"rate_limit": 0, "param_blocklist": 0, "data_scope": 0, "sequence": 0}
            for log in logs:
                for res in log.get("rule_results", []):
                    if res.get("outcome") == "violation":
                        rule = res.get("rule")
                        if rule in violation_counts:
                            violation_counts[rule] += 1
            
            df_violations = pd.DataFrame(list(violation_counts.items()), columns=["Rule Type", "Count"])
            st.bar_chart(df_violations.set_index("Rule Type")["Count"])

        st.divider()

        # 3. Log Feed Table
        st.subheader("📡 Real-Time Interception Feed")
        
        # Format df columns for display
        df["Time"] = df["ts"].apply(format_time)
        df["SQL / Params"] = df["params"].apply(lambda x: x.get("sql", str(x)) if isinstance(x, dict) else str(x))
        
        # Primary reason field extraction
        def get_failure_reason(rule_results):
            for r in rule_results:
                if r.get("outcome") == "violation":
                    return r.get("reason", "")
            return ""
            
        df["Reason"] = df["rule_results"].apply(get_failure_reason)

        display_df = df[["Time", "session_id", "tool", "SQL / Params", "risk_band", "disposition", "Reason"]]
        display_df.columns = ["Time", "Session ID", "Tool", "Parameters", "Risk Band", "Disposition", "Reason"]
        
        st.dataframe(display_df, use_container_width=True, hide_index=True)

        # 4. Security Patrol Reports Section
        st.divider()
        st.subheader("📂 Security Patrol Reports")
        
        reports_dir = os.path.join(os.getcwd(), "reports")
        if os.path.exists(reports_dir):
            report_files = [f for f in os.listdir(reports_dir) if f.endswith(".html")]
            report_files.sort(reverse=True)
            
            if not report_files:
                st.info("No security reports generated yet. Ask the chat agent to 'generate a security report'.")
            else:
                for file in report_files:
                    file_path = os.path.join(reports_dir, file)
                    creation_time = datetime.fromtimestamp(os.path.getctime(file_path)).strftime("%Y-%m-%d %H:%M:%S")
                    
                    col_file, col_dl, col_view = st.columns([4, 1, 1])
                    with col_file:
                        st.markdown(f"📄 **{file}** (Generated: {creation_time})")
                    with col_dl:
                        with open(file_path, "r", encoding="utf-8") as f:
                            html_data = f.read()
                        st.download_button("Download 📥", data=html_data, file_name=file, mime="text/html", key=f"dl-{file}")
                    with col_view:
                        if st.button("View 👁️", key=f"view-{file}"):
                            st.session_state.active_view_report = file_path
                            st.rerun()
                            
                # If a report is selected to view, show it in an iframe!
                if "active_view_report" in st.session_state and st.session_state.active_view_report:
                    st.divider()
                    st.markdown(f"### 👁️ Viewing: `{os.path.basename(st.session_state.active_view_report)}`")
                    if st.button("Close Viewer ✖️"):
                        st.session_state.active_view_report = None
                        st.rerun()
                    else:
                        with open(st.session_state.active_view_report, "r", encoding="utf-8") as f:
                            report_html = f.read()
                        import streamlit.components.v1 as components
                        components.html(report_html, height=600, scrolling=True)
        else:
            st.info("No security reports folder found. Ask the chat agent to generate a report.")

    # Autorefresh trigger loop
    if auto_refresh:
        time.sleep(3)
        st.rerun()
