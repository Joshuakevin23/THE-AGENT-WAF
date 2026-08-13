const API_URL = "http://13.203.97.200:8000"; // Assuming testing on the EC2 or local, let's use relative or current host
const currentHost = window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1" 
    ? `http://${window.location.host}` 
    : `http://${window.location.host}`; // Fallback to same host (since we mount it on FastAPI)

const wsHost = window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1"
    ? `ws://${window.location.host}/ws/events`
    : `ws://${window.location.host}/ws/events`;

// State
let sessionId = "sess-" + Math.floor(Math.random() * 1000000);
let isAnimating = false;

// DOM Elements
const chatInput = document.getElementById("chat-input");
const sendBtn = document.getElementById("send-btn");
const chatHistory = document.getElementById("chat-history");
const typingIndicator = document.getElementById("typing-indicator");
const logsList = document.getElementById("logs-list");
const emptyLogs = document.getElementById("empty-logs");
const wsStatus = document.getElementById("ws-status");

// Pipeline Elements
const pProgress = document.getElementById("pipeline-progress");
const nIntercept = document.getElementById("node-intercept");
const nAnalyze = document.getElementById("node-analyze");
const nDecision = document.getElementById("node-decision");
const nHitl = document.getElementById("node-hitl");
const nExecute = document.getElementById("node-execute");

const nodes = [nIntercept, nAnalyze, nDecision, nHitl, nExecute];

// Initialize WebSocket
function initWebSocket() {
    const ws = new WebSocket(wsHost);
    
    ws.onopen = () => {
        wsStatus.innerHTML = "🟢 Connected";
        wsStatus.style.color = "var(--status-allow)";
    };
    
    ws.onclose = () => {
        wsStatus.innerHTML = "🔴 Disconnected - Reconnecting...";
        wsStatus.style.color = "var(--status-block)";
        setTimeout(initWebSocket, 3000);
    };

    ws.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            if (data.session_id === sessionId) {
                // If the event belongs to our session, render log and animate pipeline!
                renderLog(data);
                animatePipeline(data);
            }
        } catch (e) {
            console.error("WS Parse error", e);
        }
    };
}
initWebSocket();

// Chat Interaction
chatInput.addEventListener("keypress", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
    }
});

sendBtn.addEventListener("click", sendMessage);

async function sendMessage() {
    const query = chatInput.value.trim();
    if (!query) return;

    // Add user message
    addMessage(query, "user");
    chatInput.value = "";
    
    typingIndicator.style.display = "flex";
    sendBtn.disabled = true;

    try {
        const response = await fetch(`${currentHost}/chat`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                query: query,
                session_id: sessionId
            })
        });
        
        const data = await response.json();
        
        if (data.status === "success" || data.status === "pending") {
            addMessage(data.response, "agent");
        } else {
            addMessage("Error: " + data.error, "agent");
        }
    } catch (err) {
        addMessage("Connection error while talking to proxy.", "agent");
    } finally {
        typingIndicator.style.display = "none";
        sendBtn.disabled = false;
        chatInput.focus();
    }
}

function addMessage(text, role) {
    const msgDiv = document.createElement("div");
    msgDiv.className = `message message-${role}`;
    
    const bubble = document.createElement("div");
    bubble.className = "bubble";
    
    // Convert markdown basic formatting (bold, newlines)
    let formattedText = text.replace(/\n/g, "<br>");
    bubble.innerHTML = formattedText;
    
    msgDiv.appendChild(bubble);
    chatHistory.appendChild(msgDiv);
    chatHistory.scrollTop = chatHistory.scrollHeight;
}

// Render WAF Logs
function renderLog(log) {
    if (emptyLogs) emptyLogs.remove();
    
    const item = document.createElement("div");
    item.className = "log-item";
    
    let badgeClass = "badge-allow";
    let badgeText = "ALLOWED";
    if (log.disposition === "blocked") {
        badgeClass = "badge-block";
        badgeText = "BLOCKED";
    } else if (log.disposition === "shadow_block") {
        badgeClass = "badge-shadow";
        badgeText = "SHADOWED";
    } else if (log.disposition === "pending_hitl") {
        badgeClass = "badge-pending";
        badgeText = "PENDING HITL";
    }

    item.innerHTML = `
        <div class="log-header">
            <span class="log-tool">${log.tool}</span>
            <span class="badge ${badgeClass}">${badgeText}</span>
        </div>
        <div class="log-details">
            ${JSON.stringify(log.params)}
        </div>
        ${log.rule_results && log.rule_results.length > 0 ? 
          `<div style="font-size: 11px; color: var(--text-secondary)">Risk Score: ${log.risk_score} (${log.risk_band})</div>` 
          : ""}
    `;
    
    logsList.prepend(item);
}

// Pipeline Animations
async function animatePipeline(logData) {
    if (isAnimating) return; // Basic lock to prevent overlap
    isAnimating = true;

    // Reset all nodes
    nodes.forEach(n => {
        n.className = "pipeline-node";
    });
    pProgress.style.width = "0%";

    const sleep = (ms) => new Promise(r => setTimeout(r, ms));

    // 1. Intercept
    nIntercept.classList.add("active");
    await sleep(400);

    // 2. Analyze
    pProgress.style.width = "25%";
    nIntercept.classList.remove("active");
    nIntercept.classList.add("success");
    nAnalyze.classList.add("active");
    await sleep(600);

    // 3. Decision
    pProgress.style.width = "50%";
    nAnalyze.classList.remove("active");
    nAnalyze.classList.add("success");
    nDecision.classList.add("active");
    await sleep(500);

    nDecision.classList.remove("active");

    if (logData.disposition === "pending_hitl") {
        pProgress.style.width = "75%";
        nDecision.classList.add("shadow"); // Yellow decision
        nHitl.classList.add("active", "pending");
        await sleep(1000);
        // Wait here, doesn't execute
    } else if (logData.disposition === "blocked") {
        nDecision.classList.add("blocked");
        // Stops here!
    } else {
        // Allowed or Shadow
        nDecision.classList.add("success");
        if (logData.risk_score >= 3) {
            pProgress.style.width = "75%";
            nHitl.classList.add("success"); // Approved by HITL previously
        }
        pProgress.style.width = "100%";
        nExecute.classList.add("active");
        
        await sleep(600);
        nExecute.classList.remove("active");
        nExecute.classList.add(logData.disposition === "shadow_block" ? "shadow" : "success");
    }

    await sleep(2000); // Hold final state before resetting flag
    isAnimating = false;
}
