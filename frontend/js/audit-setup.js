/**
 * WebAudit 360 — Audit Setup & Launch Controller
 * Creator: Harsh Patel
 */

import { apiClient } from "./api.js";
import { isValidUrl, showToast } from "./utils.js";

export function initAuditSetup() {
  const form = document.getElementById("new-audit-form");
  if (!form) return;

  // Pre-fill target URL from query parameter or sessionStorage if present
  const urlParams = new URLSearchParams(window.location.search);
  const targetParam = urlParams.get("target") || sessionStorage.getItem("webaudit360_prefill_url");
  if (targetParam && form.target_url) {
    form.target_url.value = decodeURIComponent(targetParam);
    sessionStorage.removeItem("webaudit360_prefill_url");
  }

  form.addEventListener("submit", handleAuditSubmit);
}

async function handleAuditSubmit(e) {
  e.preventDefault();
  const form = e.target;
  const submitBtn = form.querySelector("button[type='submit']");

  let targetUrl = form.target_url.value.trim();
  if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
    targetUrl = "https://" + targetUrl;
    form.target_url.value = targetUrl;
  }

  if (!isValidUrl(targetUrl)) {
    showToast("Please enter a valid website URL (e.g., https://example.com)", "error");
    return;
  }

  const scanMode = form.scan_mode ? form.scan_mode.value : "SINGLE_PAGE";
  const deviceProfile = form.device_profile ? form.device_profile.value : "DESKTOP";

  // Selected modules
  const moduleCheckboxes = form.querySelectorAll("input[name='modules']:checked");
  const selectedModules = Array.from(moduleCheckboxes).map(cb => cb.value);

  if (selectedModules.length === 0) {
    showToast("Please select at least one audit module", "warning");
    return;
  }

  const crawlLimits = {
    max_pages: parseInt(form.max_pages ? form.max_pages.value : 50, 10),
    max_depth: parseInt(form.max_depth ? form.max_depth.value : 3, 10)
  };

  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerHTML = `<span>Starting Engine Fleet...</span>`;
  }

  try {
    const payload = {
      target_url: targetUrl,
      scan_mode: scanMode,
      device_profile: deviceProfile,
      modules: selectedModules,
      crawl_limits: crawlLimits
    };

    const audit = await apiClient.post("/audits", payload);
    showToast("Audit submitted! Connecting to live telemetry...", "success");

    // Redirect to live monitoring screen
    window.location.href = `live-audit.html?id=${audit.id}`;
  } catch (err) {
    showToast(err.message || "Failed to submit audit. Check URL or network access.", "error");
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerHTML = `<span>Launch Audit</span>`;
    }
  }
}
