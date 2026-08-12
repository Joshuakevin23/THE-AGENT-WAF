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
page = st.sidebar.radio("Navigation", ["🤖 Chat Agent Console", nav_label])

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
# Page 2: Admin Dashboard
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
