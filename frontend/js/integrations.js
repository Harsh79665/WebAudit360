/**
 * WebAudit 360 — Integrations, API Keys & Webhooks Manager
 * Creator: Harsh Patel
 */

import { apiClient } from "./api.js";
import { escapeHtml, formatDate, showToast } from "./utils.js";
import { renderIcons } from "./icons.js";

export async function initIntegrationsView() {
  const genKeyBtn = document.getElementById("generate-api-key-btn");
  if (genKeyBtn) {
    genKeyBtn.addEventListener("click", handleGenerateApiKey);
  }

  const webhookForm = document.getElementById("create-webhook-form");
  if (webhookForm) {
    webhookForm.addEventListener("submit", handleCreateWebhook);
  }

  // Bind global action handlers for table row actions
  window.revokeApiKey = handleRevokeApiKey;
  window.deleteWebhook = handleDeleteWebhook;
  window.testWebhook = handleTestWebhook;

  await Promise.all([loadApiKeys(), loadWebhooks()]);
}

/**
 * Loads and renders all API keys for the current workspace.
 */
export async function loadApiKeys() {
  const container = document.getElementById("api-keys-table-container");
  if (!container) return;

  try {
    const keys = await apiClient.get("/api-keys");

    if (!Array.isArray(keys) || keys.length === 0) {
      container.innerHTML = `
        <div class="empty-state" style="padding: var(--space-xl);">
          <div class="empty-state-icon"><span data-icon="code"></span></div>
          <h3 class="empty-state-title">No API Keys Generated</h3>
          <p class="empty-state-desc">Generate an API key above to integrate WebAudit 360 with CI/CD pipelines, CLI runners, or developer scripts.</p>
        </div>
      `;
      renderIcons(container);
      return;
    }

    let html = `
      <div class="data-table-container">
        <table class="data-table">
          <thead>
            <tr>
              <th>Label</th>
              <th>Key Token</th>
              <th>Status</th>
              <th>Expires At</th>
              <th>Created</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
    `;

    keys.forEach(k => {
      const isExpired = k.expires_at && new Date(k.expires_at) < new Date();
      const statusBadge = isExpired
        ? `<span class="badge" style="background:var(--badge-critical-bg); color:var(--badge-critical-text);">EXPIRED</span>`
        : k.is_active
          ? `<span class="badge" style="background:var(--accent-glow); color:var(--accent-primary);">ACTIVE</span>`
          : `<span class="badge" style="background:var(--bg-tertiary); color:var(--text-muted);">REVOKED</span>`;

      html += `
        <tr>
          <td><strong>${escapeHtml(k.label)}</strong></td>
          <td><code>${escapeHtml(k.prefix)}••••••••</code></td>
          <td>${statusBadge}</td>
          <td>${k.expires_at ? formatDate(k.expires_at) : 'Never'}</td>
          <td>${formatDate(k.created_at)}</td>
          <td>
            <button class="btn btn-danger btn-sm" onclick="window.revokeApiKey(${k.id})" title="Revoke API Key">
              <span data-icon="trash"></span> Revoke
            </button>
          </td>
        </tr>
      `;
    });

    html += `</tbody></table></div>`;
    container.innerHTML = html;
    renderIcons(container);
  } catch (err) {
    container.innerHTML = `<div class="empty-state"><p class="text-danger">Failed to load API keys: ${escapeHtml(err.message)}</p></div>`;
  }
}

/**
 * Generates a new API key via backend API and displays plaintext secret once.
 */
async function handleGenerateApiKey() {
  const displayEl = document.getElementById("api-key-display");
  const labelInput = document.getElementById("api-key-label-input");
  const label = (labelInput && labelInput.value.trim()) || "CI/CD Deployment Key";

  try {
    const data = await apiClient.post("/api-keys", {
      label: label,
      expires_in_days: 365
    });

    if (labelInput) labelInput.value = "";

    if (displayEl) {
      displayEl.innerHTML = `
        <div class="glass-panel" style="padding:var(--space-md); border-color:var(--accent-primary); margin-top:var(--space-md); animation: fadeIn 0.3s ease;">
          <div class="flex items-center justify-between" style="margin-bottom:6px;">
            <div class="text-xs" style="color:var(--accent-primary); font-weight:700;">
              Secret API Key Generated (${escapeHtml(data.label)}) — Copy Now (Only Shown Once):
            </div>
          </div>
          <div class="flex items-center gap-sm">
            <code style="font-size:0.95rem; color:var(--accent-cyan); font-weight:700; background:rgba(0,0,0,0.25); padding:8px 14px; border-radius:6px; flex:1; overflow-x:auto;">
              ${escapeHtml(data.api_key)}
            </code>
            <button class="btn btn-secondary btn-sm" onclick="navigator.clipboard.writeText('${data.api_key}'); alert('API Key copied to clipboard!');">
              <span data-icon="copy"></span> Copy Key
            </button>
          </div>
        </div>
      `;
      renderIcons(displayEl);
    }

    showToast("API Key Generated", "Secret key generated and stored securely.", "success");
    await loadApiKeys();
  } catch (err) {
    showToast("Error Generating Key", err.message || "Failed to generate API key.", "error");
  }
}

/**
 * Revokes an existing API key.
 */
async function handleRevokeApiKey(keyId) {
  if (!confirm("Are you sure you want to revoke this API key? Applications using it will immediately lose access.")) {
    return;
  }

  try {
    await apiClient.delete(`/api-keys/${keyId}`);
    showToast("Key Revoked", "API key revoked and deleted successfully.", "success");
    await loadApiKeys();
  } catch (err) {
    showToast("Revocation Error", err.message || "Failed to revoke API key.", "error");
  }
}

/**
 * Loads and renders all registered webhooks.
 */
export async function loadWebhooks() {
  const container = document.getElementById("webhooks-table-container");
  if (!container) return;

  try {
    const webhooks = await apiClient.get("/webhooks");

    if (!Array.isArray(webhooks) || webhooks.length === 0) {
      container.innerHTML = `
        <div class="empty-state" style="padding: var(--space-xl); margin-top: var(--space-lg);">
          <div class="empty-state-icon"><span data-icon="activity"></span></div>
          <h3 class="empty-state-title">No Webhooks Registered</h3>
          <p class="empty-state-desc">Register a destination URL above to receive real-time POST event notifications with HMAC signatures.</p>
        </div>
      `;
      renderIcons(container);
      return;
    }

    let html = `
      <div class="data-table-container" style="margin-top: var(--space-lg);">
        <table class="data-table">
          <thead>
            <tr>
              <th>Target URL</th>
              <th>Subscribed Events</th>
              <th>Status</th>
              <th>Created</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
    `;

    webhooks.forEach(w => {
      const eventsHtml = (w.events || [])
        .map(e => `<span class="badge" style="font-size:0.75rem; margin-right:4px;">${escapeHtml(e)}</span>`)
        .join("");

      html += `
        <tr>
          <td><code style="color:var(--accent-primary); font-size:0.875rem;">${escapeHtml(w.url)}</code></td>
          <td>${eventsHtml || '<span class="text-muted">all</span>'}</td>
          <td><span class="badge" style="background:var(--accent-glow); color:var(--accent-primary);">${w.is_active ? 'ACTIVE' : 'INACTIVE'}</span></td>
          <td>${formatDate(w.created_at)}</td>
          <td>
            <div class="flex items-center gap-xs">
              <button class="btn btn-secondary btn-sm" onclick="window.testWebhook(${w.id})" title="Send Test Ping">
                <span data-icon="send"></span> Test
              </button>
              <button class="btn btn-danger btn-sm" onclick="window.deleteWebhook(${w.id})" title="Delete Webhook">
                <span data-icon="trash"></span>
              </button>
            </div>
          </td>
        </tr>
      `;
    });

    html += `</tbody></table></div>`;
    container.innerHTML = html;
    renderIcons(container);
  } catch (err) {
    container.innerHTML = `<div class="empty-state"><p class="text-danger">Failed to load webhooks: ${escapeHtml(err.message)}</p></div>`;
  }
}

/**
 * Registers a new webhook destination and displays HMAC signing secret once.
 */
async function handleCreateWebhook(e) {
  e.preventDefault();
  const form = e.target;
  const url = form.webhook_url.value.trim();
  const secretDisplay = document.getElementById("webhook-secret-display");

  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    showToast("Invalid URL", "Webhook destination must begin with https://", "error");
    return;
  }

  try {
    const data = await apiClient.post("/webhooks", {
      url: url,
      events: ["audit.completed", "regression.detected"]
    });

    form.reset();

    if (secretDisplay) {
      secretDisplay.innerHTML = `
        <div class="glass-panel" style="padding:var(--space-md); border-color:var(--color-good); margin-top:var(--space-md); animation: fadeIn 0.3s ease;">
          <div class="text-xs" style="color:var(--color-good); font-weight:700; margin-bottom:4px;">
            Webhook Registered! HMAC Secret Key (Save Now - Only Shown Once):
          </div>
          <div class="flex items-center gap-sm">
            <code style="font-size:0.95rem; color:var(--accent-cyan); font-weight:700; background:rgba(0,0,0,0.25); padding:8px 14px; border-radius:6px; flex:1; overflow-x:auto;">
              ${escapeHtml(data.secret)}
            </code>
            <button class="btn btn-secondary btn-sm" onclick="navigator.clipboard.writeText('${data.secret}'); alert('HMAC secret copied to clipboard!');">
              <span data-icon="copy"></span> Copy Secret
            </button>
          </div>
          <div class="text-xs text-muted" style="margin-top:6px;">
            Use this secret key to verify incoming payload signatures via the <code>X-WebAudit360-Signature</code> header.
          </div>
        </div>
      `;
      renderIcons(secretDisplay);
    }

    showToast("Webhook Registered", "Webhook destination configured and HMAC secret generated.", "success");
    await loadWebhooks();
  } catch (err) {
    showToast("Registration Error", err.message || "Failed to register webhook.", "error");
  }
}

/**
 * Sends a test ping to an existing webhook destination.
 */
async function handleTestWebhook(webhookId) {
  showToast("Testing Webhook", "Dispatching cryptographic test ping...", "info");

  try {
    const res = await apiClient.post(`/webhooks/${webhookId}/test`);
    if (res.success) {
      showToast("Ping Success", `${res.message} (${res.response_time_ms}ms)`, "success");
    } else {
      showToast("Ping Failed", res.message || "Destination rejected ping.", "error");
    }
  } catch (err) {
    showToast("Test Ping Error", err.message || "Failed to dispatch test ping.", "error");
  }
}

/**
 * Deletes a registered webhook destination.
 */
async function handleDeleteWebhook(webhookId) {
  if (!confirm("Are you sure you want to delete this webhook? Event delivery will cease immediately.")) {
    return;
  }

  try {
    await apiClient.delete(`/webhooks/${webhookId}`);
    showToast("Webhook Deleted", "Webhook destination deleted successfully.", "success");
    await loadWebhooks();
  } catch (err) {
    showToast("Delete Error", err.message || "Failed to delete webhook.", "error");
  }
}
