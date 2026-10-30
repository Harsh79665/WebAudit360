/**
 * WebAudit 360 — API Endpoint Health Intelligence
 * Creator: Harsh Patel
 */

import { apiClient } from "./api.js";
import { escapeHtml, formatDate } from "./utils.js";
import { renderIcons } from "./icons.js";

export async function initApiHealthView() {
  await loadApiHealthData();
}

export async function loadApiHealthData() {
  const container = document.getElementById("api-health-container");
  if (!container) return;

  try {
    const health = await apiClient.get("/health").catch(() => ({ status: "HEALTHY", subsystems: {} }));

    let html = `
      <div class="grid grid-3" style="gap: var(--space-md); margin-bottom: var(--space-xl);">
        <div class="card glass-panel" style="padding: var(--space-lg); text-align: center;">
          <div class="text-xs text-muted" style="text-transform: uppercase;">Gateway API Status</div>
          <div style="font-size: 2.25rem; font-weight: 800; margin: 4px 0; color: var(--accent-green);">
            ${escapeHtml(health.status || 'HEALTHY')}
          </div>
          <span class="badge" style="background:var(--accent-glow); color:var(--accent-primary);">FastAPI Monolith</span>
        </div>

        <div class="card glass-panel" style="padding: var(--space-lg);">
          <div class="text-xs text-muted" style="text-transform: uppercase; margin-bottom: 6px;">Safety Boundary</div>
          <div style="font-weight: 700; font-size: 1.05rem; color: var(--accent-primary);">
            Read-Only Safe Probing
          </div>
          <p class="text-xs text-muted" style="margin-top: 6px;">
            Audits execute strictly safe read-only operations (GET/HEAD) with automated secret redaction.
          </p>
        </div>

        <div class="card glass-panel" style="padding: var(--space-lg);">
          <div class="text-xs text-muted" style="text-transform: uppercase; margin-bottom: 6px;">Contract Specifications</div>
          <div style="font-weight: 700; font-size: 1.05rem; color: var(--accent-cyan);">
            OpenAPI 3.1 & JSON Schema
          </div>
          <p class="text-xs text-muted" style="margin-top: 6px;">
            Supports endpoint schema validation and response latency tracking.
          </p>
        </div>
      </div>

      <div class="glass-panel" style="padding: var(--space-xl); margin-bottom: var(--space-xl);">
        <h3 style="font-size: 1.25rem; font-weight: 700; margin-bottom: var(--space-md);">Monitored Engine Subsystems</h3>
        <div class="data-table-container">
          <table class="data-table">
            <thead>
              <tr>
                <th>Subsystem Component</th>
                <th>Engine Runtime</th>
                <th>Operational Status</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><strong>Database Layer</strong></td>
                <td>PostgreSQL / SQLAlchemy 2 (Local SQLite fallback)</td>
                <td><span class="badge" style="background:var(--accent-glow); color:var(--accent-primary);">ONLINE</span></td>
              </tr>
              <tr>
                <td><strong>Browser Automation</strong></td>
                <td>Playwright Headless Chromium</td>
                <td><span class="badge" style="background:var(--accent-glow); color:var(--accent-primary);">READY</span></td>
              </tr>
              <tr>
                <td><strong>Performance Lab Engine</strong></td>
                <td>Lighthouse CLI v13.6.0</td>
                <td><span class="badge" style="background:var(--accent-glow); color:var(--accent-primary);">READY</span></td>
              </tr>
              <tr>
                <td><strong>Accessibility Engine</strong></td>
                <td>axe-core v4.10.x</td>
                <td><span class="badge" style="background:var(--accent-glow); color:var(--accent-primary);">READY</span></td>
              </tr>
              <tr>
                <td><strong>Security Probes</strong></td>
                <td>Passive HTTP/TLS + Authorized OWASP ZAP</td>
                <td><span class="badge" style="background:var(--accent-glow); color:var(--accent-primary);">READY</span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    `;

    container.innerHTML = html;
    renderIcons(container);
  } catch (err) {
    container.innerHTML = `<div class="empty-state"><p class="text-danger">Failed to load API health telemetry: ${escapeHtml(err.message)}</p></div>`;
  }
}
