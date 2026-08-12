// Session persistence
let sessionId = `sess-chat-${Math.floor(Date.now() / 1000)}`;

// DOM Elements
const apiKeyInput = document.getElementById("api-key-input");
const modelSelect = document.getElementById("model-select");
const chatMessages = document.getElementById("chat-messages");
const chatInput = document.getElementById("chat-input");
const sendBtn = document.getElementById("send-btn");

// Load API Key from localStorage
if (localStorage.getItem("groq_api_key")) {
  apiKeyInput.value = localStorage.getItem("groq_api_key");
}

// Save API Key on edit
apiKeyInput.addEventListener("input", () => {
  localStorage.setItem("groq_api_key", apiKeyInput.value.trim());
});

// Send on Enter (without Shift)
chatInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    sendMessage();
  }
});

sendBtn.addEventListener("click", sendMessage);

async function sendMessage() {
  const query = chatInput.value.trim();
  if (!query) return;

  const apiKey = apiKeyInput.value.trim();
  const model = modelSelect.value;

  // Clear input
  chatInput.value = "";
  chatInput.focus();

  // Disable UI during processing
  setLoading(true);

  // Append user message
  appendMessage("user", query);

  // Append typing indicator for agent
  const typingIndicator = appendTypingIndicator();
  chatMessages.scrollTop = chatMessages.scrollHeight;

  try {
    const response = await fetch("http://localhost:8000/chat", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        query: query,
        session_id: sessionId,
        api_key: apiKey || null,
        model: model
      })
    });

    const data = await response.json();
    
    // Remove typing indicator
    typingIndicator.remove();

    if (data.status === "success") {
      // Append assistant final response and WAF traces
      appendMessage("assistant", data.response, data.steps);
    } else {
      // Append backend error
      appendMessage("assistant", `❌ Error: ${data.error || "An unknown error occurred"}`);
    }
  } catch (err) {
    typingIndicator.remove();
    appendMessage("assistant", `❌ Error connecting to server: ${err.message}`);
  } finally {
    setLoading(false);
    chatMessages.scrollTop = chatMessages.scrollHeight;
  }
}

function setLoading(isLoading) {
  // Inputs are kept enabled to allow sending multiple queries simultaneously
}

function appendMessage(sender, text, steps = []) {
  const messageDiv = document.createElement("div");
  messageDiv.className = `message message-${sender}`;

  const bubbleDiv = document.createElement("div");
  bubbleDiv.className = `bubble bubble-${sender}`;
  
  // Basic rendering of response (replacing newlines with line breaks)
  bubbleDiv.innerHTML = text.replace(/\n/g, "<br/>");

  messageDiv.appendChild(bubbleDiv);

  // If there are tool/WAF validation steps, append the trace
  if (steps && steps.length > 0) {
    const traceDiv = document.createElement("div");
    traceDiv.className = "trace-container";
    
    const traceTitle = document.createElement("div");
    traceTitle.className = "trace-title";
    traceTitle.textContent = "🛡️ WAF Interception trace";
    traceDiv.appendChild(traceTitle);

    steps.forEach(step => {
      const stepDiv = document.createElement("div");
      stepDiv.className = "trace-step";

      // Status dot mapping
      let dotClass = "status-allowed";
      if (step.disposition === "blocked") dotClass = "status-blocked";
      else if (step.disposition === "shadow_block") dotClass = "status-shadow";

      const dot = document.createElement("span");
      dot.className = `status-indicator ${dotClass}`;

      // Args summary
      const argsStr = step.args ? JSON.stringify(step.args) : "{}";
      const infoSpan = document.createElement("span");
      infoSpan.innerHTML = `Called <strong>${step.tool}</strong>: WAF <strong>${step.disposition}</strong> (Risk: ${step.risk_band} - ${step.risk_score})`;
      
      if (step.disposition === "blocked" || step.disposition === "shadow_block") {
        infoSpan.innerHTML += `<br/><span style="color: var(--accent-block); font-size: 11px;">↳ Reason: ${step.reason}</span>`;
      }

      stepDiv.appendChild(dot);
      stepDiv.appendChild(infoSpan);
      traceDiv.appendChild(stepDiv);
    });

    messageDiv.appendChild(traceDiv);
  }

  chatMessages.appendChild(messageDiv);
}

function appendTypingIndicator() {
  const messageDiv = document.createElement("div");
  messageDiv.className = "message message-assistant";

  const bubbleDiv = document.createElement("div");
  bubbleDiv.className = "bubble bubble-assistant";
  
  const indicator = document.createElement("div");
  indicator.className = "typing-indicator";
  indicator.innerHTML = `
    <div class="typing-dot"></div>
    <div class="typing-dot"></div>
    <div class="typing-dot"></div>
  `;

  bubbleDiv.appendChild(indicator);
  messageDiv.appendChild(bubbleDiv);
  chatMessages.appendChild(messageDiv);

  return messageDiv;
}
