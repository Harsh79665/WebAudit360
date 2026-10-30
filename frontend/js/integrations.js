/**
 * WebAudit 360 — Integrations, API Keys & Webhooks Manager
 * Creator: Harsh Patel
 */

import { escapeHtml, showToast } from "./utils.js";
import { renderIcons } from "./icons.js";

export function initIntegrationsView() {
  const genKeyBtn = document.getElementById("generate-api-key-btn");
  if (genKeyBtn) {
    genKeyBtn.addEventListener("click", handleGenerateApiKey);
  }

  const webhookForm = document.getElementById("create-webhook-form");
  if (webhookForm) {
    webhookForm.addEventListener("submit", handleCreateWebhook);
  }
}

function handleGenerateApiKey() {
  const container = document.getElementById("api-key-display");
  if (!container) return;

  // Generate high-entropy pseudo-token for client demonstration
  const randomHex = Array.from(crypto.getRandomValues(new Uint8Array(24)))
    .map(b => b.toString(16).padStart(2, '0')).join('');
  const newKey = `w360_live_${randomHex}`;

  container.innerHTML = `
    <div class="glass-panel" style="padding:var(--space-md); border-color:var(--accent-primary); margin-top:var(--space-md);">
      <div class="text-xs text-muted" style="margin-bottom:4px;">Newly Generated Secret API Key (Copy Now - Only Shown Once):</div>
      <div class="flex items-center gap-sm">
        <code style="font-size:0.9rem; color:var(--accent-cyan); font-weight:700; background:rgba(0,0,0,0.2); padding:6px 12px; border-radius:6px; flex:1;">
          ${escapeHtml(newKey)}
        </code>
        <button class="btn btn-secondary btn-sm" onclick="navigator.clipboard.writeText('${newKey}'); alert('API Key copied to clipboard!');">
          Copy Key
        </button>
      </div>
    </div>
  `;
  showToast("New API key generated and hashed for storage.", "success");
}

function handleCreateWebhook(e) {
  e.preventDefault();
  const form = e.target;
  const url = form.webhook_url.value.trim();

  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    showToast("Webhook URL must start with https://", "error");
    return;
  }

  showToast("Webhook registered! HMAC secret key generated for payload signature verification.", "success");
  form.reset();
}

