// Metrics State
let totalCalls = 0;
let blockedCalls = 0;
let shadowBlocks = 0;
const sessions = new Set();
const ruleViolationCounts = {
  rate_limit: 0,
  param_blocklist: 0,
  data_scope: 0,
  sequence: 0
};

// Rolling Time buckets for Calls/Min (last 10 buckets of 5s each)
const timeBuckets = Array(10).fill(0);
const timeLabels = Array(10).fill("");
let currentBucketCalls = 0;

// Chart.js instances
let loadChart;
let violationsChart;

// DOM Elements
const wsStatusDot = document.getElementById("ws-status-dot");
const wsStatusText = document.getElementById("ws-status-text");
const logBody = document.getElementById("log-body");
const logEmptyState = document.getElementById("log-empty-state");
const sessionCountEl = document.getElementById("session-count");

const metricTotal = document.getElementById("metric-total");
const metricBlocked = document.getElementById("metric-blocked");
const metricShadow = document.getElementById("metric-shadow");
const metricRate = document.getElementById("metric-rate");

// Initialize Charts
function initCharts() {
  // 1. Line Chart (System Load)
  const ctxLoad = document.getElementById("chart-load").getContext("2d");
  
  // Initialize labels with empty placeholders
  const now = new Date();
  for (let i = 9; i >= 0; i--) {
    const t = new Date(now.getTime() - i * 5000);
    timeLabels[9 - i] = t.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }

  loadChart = new Chart(ctxLoad, {
    type: 'line',
    data: {
      labels: timeLabels,
      datasets: [{
        label: 'Calls / 5s',
        data: timeBuckets,
        borderColor: '#6366f1',
        backgroundColor: 'rgba(99, 102, 241, 0.05)',
        borderWidth: 2,
        tension: 0.4,
        fill: true,
        pointBackgroundColor: '#6366f1'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        x: {
          grid: { color: 'rgba(255, 255, 255, 0.05)' },
          ticks: { color: '#9ca3af', font: { size: 10 } }
        },
        y: {
          grid: { color: 'rgba(255, 255, 255, 0.05)' },
          ticks: { color: '#9ca3af', stepSize: 1, beginAtZero: true },
          min: 0
        }
      }
    }
  });

  // 2. Bar Chart (Violations by Type)
  const ctxViolations = document.getElementById("chart-violations").getContext("2d");
  violationsChart = new Chart(ctxViolations, {
    type: 'bar',
    data: {
      labels: ['Rate Limit', 'Blocklist', 'Data Scope', 'Sequence'],
      datasets: [{
        data: [0, 0, 0, 0],
        backgroundColor: [
          'rgba(99, 102, 241, 0.8)', // indigo
          'rgba(245, 158, 11, 0.8)', // amber
          'rgba(239, 68, 68, 0.8)',  // red
          'rgba(16, 185, 129, 0.8)'  // green
        ],
        borderWidth: 0,
        borderRadius: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        x: {
          grid: { display: false },
          ticks: { color: '#9ca3af', font: { size: 11 } }
        },
        y: {
          grid: { color: 'rgba(255, 255, 255, 0.05)' },
          ticks: { color: '#9ca3af', stepSize: 1, beginAtZero: true },
          min: 0
        }
      }
    }
  });
}

// Update Rolling Load Chart every 5 seconds
setInterval(() => {
  // Push current call count to buckets
  timeBuckets.push(currentBucketCalls);
  timeBuckets.shift();

  // Reset current bucket accumulator
  currentBucketCalls = 0;

  // Update timestamps
  const t = new Date();
  const timeStr = t.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  timeLabels.push(timeStr);
  timeLabels.shift();

  if (loadChart) {
    loadChart.data.labels = timeLabels;
    loadChart.data.datasets[0].data = timeBuckets;
    loadChart.update('none'); // 'none' skips full animation for smoother scrolling
  }
}, 5000);

// Connect to WAF websocket
function connectWebSocket() {
  const wsUrl = `ws://${window.location.host || 'localhost:8000'}/ws/events`;
  const ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    wsStatusDot.classList.add("connected");
    wsStatusText.textContent = "Connected";
    wsStatusText.style.color = "var(--accent-allow)";
  };

  ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    handleNewCall(data);
  };

  ws.onclose = () => {
    wsStatusDot.classList.remove("connected");
    wsStatusText.textContent = "Disconnected";
    wsStatusText.style.color = "var(--accent-block)";
    // Attempt reconnection after 3 seconds
    setTimeout(connectWebSocket, 3000);
  };

  ws.onerror = (err) => {
    console.error("WebSocket error:", err);
    ws.close();
  };
}

function handleNewCall(call) {
  // Hide empty state if visible
  if (logEmptyState.style.display !== "none") {
    logEmptyState.style.display = "none";
  }

  // Update Metrics state
  totalCalls++;
  currentBucketCalls++;
  sessions.add(call.session_id);

  if (call.disposition === "blocked") {
    blockedCalls++;
  } else if (call.disposition === "shadow_block") {
    shadowBlocks++;
  }

  // Update DOM metrics cards
  metricTotal.textContent = totalCalls;
  metricBlocked.textContent = blockedCalls;
  metricShadow.textContent = shadowBlocks;
  
  const blockRate = ((blockedCalls / totalCalls) * 100).toFixed(1);
  metricRate.textContent = `${blockRate}%`;
  
  sessionCountEl.textContent = `${sessions.size} Session${sessions.size !== 1 ? 's' : ''} Active`;

  // Parse violations for bar chart
  let isRateViolation = false;
  let isBlocklistViolation = false;
  let isScopeViolation = false;
  let isSeqViolation = false;

  if (call.rule_results) {
    call.rule_results.forEach(res => {
      if (res.outcome === "violation") {
        if (res.rule === "rate_limit") {
          ruleViolationCounts.rate_limit++;
          isRateViolation = true;
        } else if (res.rule === "param_blocklist") {
          ruleViolationCounts.param_blocklist++;
          isBlocklistViolation = true;
        } else if (res.rule === "data_scope") {
          ruleViolationCounts.data_scope++;
          isScopeViolation = true;
        } else if (res.rule === "sequence") {
          ruleViolationCounts.sequence++;
          isSeqViolation = true;
        }
      }
    });

    if (violationsChart) {
      violationsChart.data.datasets[0].data = [
        ruleViolationCounts.rate_limit,
        ruleViolationCounts.param_blocklist,
        ruleViolationCounts.data_scope,
        ruleViolationCounts.sequence
      ];
      violationsChart.update();
    }
  }

  // Extract primary failure reason
  let reason = "";
  if (call.disposition === "blocked" || call.disposition === "shadow_block") {
    const failedRule = call.rule_results.find(r => r.outcome === "violation");
    if (failedRule) {
      reason = failedRule.reason;
    } else if (call.risk_band === "HIGH") {
      reason = "Risk score HIGH (pending HITL)";
    }
  }

  // Create table row
  const row = document.createElement("tr");
  row.className = "new-row";

  // Parse time
  const timeStr = new Date(call.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  
  // Status Badge Class
  let badgeClass = "badge-allowed";
  if (call.disposition === "blocked") badgeClass = "badge-blocked";
  else if (call.disposition === "shadow_block") badgeClass = "badge-shadow";

  // Risk Badge Class
  let riskClass = "risk-low";
  if (call.risk_band === "MED") riskClass = "risk-med";
  else if (call.risk_band === "HIGH") riskClass = "risk-high";

  // Format params display
  const paramVal = call.params.sql || JSON.stringify(call.params);

  row.innerHTML = `
    <td>${timeStr}</td>
    <td><span class="code-text" style="max-width: 120px;">${call.session_id}</span></td>
    <td><span class="code-text" style="max-width: 140px; color: #a5b4fc;">${call.tool}</span></td>
    <td><span class="code-text" title='${JSON.stringify(call.params)}'>${paramVal}</span></td>
    <td><span class="risk-badge ${riskClass}">${call.risk_band} (${call.risk_score})</span></td>
    <td><span class="badge ${badgeClass}">${call.disposition}</span></td>
    <td style="color: #ef4444; font-size: 12px; font-weight: 500;">${reason}</td>
  `;

  // Insert at top of body
  if (logBody.firstChild) {
    logBody.insertBefore(row, logBody.firstChild);
  } else {
    logBody.appendChild(row);
  }

  // Prune table to maximum 50 rows to keep DOM fast
  if (logBody.children.length > 50) {
    logBody.removeChild(logBody.lastChild);
  }
}

// Startup
window.addEventListener("DOMContentLoaded", () => {
  initCharts();
  connectWebSocket();
});
