/**
 * WebAudit 360 — Chrome Extension Popup Controller
 * Author: Harsh Patel
 */

let activeTabUrl = "";
let apiBaseUrl = "http://localhost:8000";
let apiKey = "";

document.addEventListener("DOMContentLoaded", async () => {
  // Load saved settings
  if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.sync) {
    chrome.storage.sync.get(["webaudit_api_url", "webaudit_api_key"], (items) => {
      if (items.webaudit_api_url) {
        apiBaseUrl = items.webaudit_api_url;
        document.getElementById("api-url-input").value = apiBaseUrl;
      }
      if (items.webaudit_api_key) {
        apiKey = items.webaudit_api_key;
        document.getElementById("api-key-input").value = apiKey;
      }
    });
  }

  // Resolve current active tab
  if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.query) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0] && tabs[0].url) {
        activeTabUrl = tabs[0].url;
        document.getElementById("active-url-display").textContent = activeTabUrl;
      }
    });
  } else {
    // Fallback for standalone preview
    activeTabUrl = "https://example.com";
    document.getElementById("active-url-display").textContent = activeTabUrl;
  }

  // Settings toggle
  const settingsToggle = document.getElementById("btn-settings-toggle");
  const settingsPanel = document.getElementById("settings-panel");
  settingsToggle.addEventListener("click", () => {
    settingsPanel.style.display = settingsPanel.style.display === "none" ? "block" : "none";
  });

  // Save settings
  document.getElementById("btn-save-settings").addEventListener("click", () => {
    apiBaseUrl = document.getElementById("api-url-input").value.trim() || "http://localhost:8000";
    apiKey = document.getElementById("api-key-input").value.trim();
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.sync) {
      chrome.storage.sync.set({ webaudit_api_url: apiBaseUrl, webaudit_api_key: apiKey }, () => {
        settingsPanel.style.display = "none";
      });
    } else {
      settingsPanel.style.display = "none";
    }
  });

  // Launch Audit
  document.getElementById("btn-start-audit").addEventListener("click", triggerAudit);
});

async function triggerAudit() {
  const btn = document.getElementById("btn-start-audit");
  const progressBox = document.getElementById("progress-container");
  const resultsBox = document.getElementById("results-container");
  const progressBar = document.getElementById("progress-bar-fill");
  const progressMsg = document.getElementById("progress-message");

  btn.disabled = true;
  progressBox.style.display = "block";
  resultsBox.style.display = "none";
  progressBar.style.width = "20%";
  progressMsg.textContent = "Dispatched audit to WebAudit 360 engine...";

  try {
    const headers = { "Content-Type": "application/json" };
    if (apiKey) {
      headers["Authorization"] = `Bearer ${apiKey}`;
    }

    const payload = {
      target_url: activeTabUrl,
      scan_mode: "SINGLE_PAGE",
      device_profile: "DESKTOP",
      selected_modules: ["PERFORMANCE", "SEO", "ACCESSIBILITY", "SECURITY_PASSIVE"]
    };

    const res = await fetch(`${apiBaseUrl}/api/v1/audits`, {
      method: "POST",
      headers: headers,
      body: JSON.stringify(payload)
    });

    if (!res.ok) {
      throw new Error(`API responded with HTTP ${res.status}`);
    }

    const auditData = await res.json();
    const auditId = auditData.id;

    progressBar.style.width = "50%";
    progressMsg.textContent = `Audit #${auditId} running... Measuring telemetry...`;

    // Poll status until completion
    pollAuditStatus(auditId);
  } catch (err) {
    progressBox.style.display = "none";
    btn.disabled = false;
    alert(`Could not trigger audit: ${err.message}`);
  }
}

async function pollAuditStatus(auditId) {
  const progressBar = document.getElementById("progress-bar-fill");
  const progressMsg = document.getElementById("progress-message");
  const progressBox = document.getElementById("progress-container");
  const resultsBox = document.getElementById("results-container");
  const btn = document.getElementById("btn-start-audit");

  let attempts = 0;
  const interval = setInterval(async () => {
    attempts++;
    try {
      const headers = {};
      if (apiKey) headers["Authorization"] = `Bearer ${apiKey}`;

      const res = await fetch(`${apiBaseUrl}/api/v1/audits/${auditId}`, { headers });
      if (res.ok) {
        const audit = await res.json();
        if (audit.status === "COMPLETED") {
          clearInterval(interval);
          progressBar.style.width = "100%";
          progressBox.style.display = "none";
          resultsBox.style.display = "block";
          btn.disabled = false;

          // Render summary
          const overall = Math.round(audit.overall_score || 0);
          document.getElementById("result-score").textContent = overall;
          document.getElementById("result-label").textContent = overall >= 85 ? "Excellent" : (overall >= 65 ? "Good" : "Needs Work");
          document.getElementById("score-perf").textContent = Math.round(audit.score_performance || 0);
          document.getElementById("score-seo").textContent = Math.round(audit.score_seo || 0);
          document.getElementById("score-a11y").textContent = Math.round(audit.score_accessibility || 0);
          document.getElementById("score-sec").textContent = Math.round(audit.score_security || 0);

          document.getElementById("link-full-report").href = `${apiBaseUrl}/audit-report.html?audit_id=${auditId}`;
        } else if (audit.status === "FAILED") {
          clearInterval(interval);
          progressBox.style.display = "none";
          btn.disabled = false;
          alert("Audit failed during background processing.");
        } else {
          progressBar.style.width = `${Math.min(90, 50 + attempts * 5)}%`;
        }
      }
    } catch (e) {
      // transient network wait
    }

    if (attempts > 30) {
      clearInterval(interval);
      progressBox.style.display = "none";
      btn.disabled = false;
      alert("Audit execution timed out.");
    }
  }, 1000);
}
