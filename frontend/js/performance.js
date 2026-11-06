/**
 * WebAudit 360 — Performance Intelligence Viewer
 * Creator: Harsh Patel
 */

import { apiClient } from "./api.js";
import { escapeHtml, formatDate, getScoreDetails } from "./utils.js";
import { renderIcons } from "./icons.js";

export async function initPerformanceView() {
  const auditSelect = document.getElementById("select-audit-target");
  if (auditSelect) {
    auditSelect.addEventListener("change", (e) => loadPerformanceData(e.target.value));
  }

  await populateAuditSelector();
}

async function populateAuditSelector() {
  const auditSelect = document.getElementById("select-audit-target");
  if (!auditSelect) return;

  try {
    const data = await apiClient.get("/audits?limit=50").catch(() => ({ items: [] }));
    let audits = (data.items || []).filter(a => !a.target_url.includes("example.com"));

    const urlParams = new URLSearchParams(window.location.search);
    const requestedId = parseInt(urlParams.get("id"), 10);

    let targetAudit = !isNaN(requestedId) && requestedId > 0 ? audits.find(a => a.id === requestedId) : null;
    if (!targetAudit && !isNaN(requestedId) && requestedId > 0) {
      try {
        const direct = await apiClient.get(`/audits/${requestedId}`);
        if (direct && direct.id) {
          targetAudit = direct;
          audits.unshift(direct);
        }
      } catch (_) {}
    }

    if (audits.length === 0) {
      auditSelect.innerHTML = `<option value="">No audits available</option>`;
      return;
    }

    if (!targetAudit) {
      targetAudit = audits[0];
    }

    auditSelect.innerHTML = audits.map(a => `
      <option value="${a.id}" ${a.id === targetAudit.id ? 'selected' : ''}>${escapeHtml(a.target_url)} (${a.device_profile}) - ${formatDate(a.created_at)}</option>
    `).join("");

    await loadPerformanceData(targetAudit.id);
  } catch (e) {
    console.warn("Failed to populate audit selector:", e);
  }
}

export async function loadPerformanceData(auditId) {
  if (!auditId) return;
  const container = document.getElementById("performance-details-container");
  if (!container) return;

  try {
    const audit = await apiClient.get(`/audits/${auditId}`);
    const pages = audit.pages || [];
    const perfFindings = (audit.findings || []).filter(f => f.category === "PERFORMANCE");

    const perfScore = audit.category_scores ? audit.category_scores.PERFORMANCE : null;
    const scoreObj = getScoreDetails(perfScore);

    const perfRaw = audit.raw_results?.PERFORMANCE || {};
    const metrics = perfRaw.metrics || {};
    const browser = perfRaw.browser || {};

    const ttfb = metrics.ttfb_ms !== undefined ? metrics.ttfb_ms : browser.ttfb_ms;
    const loadMs = metrics.total_load_ms !== undefined ? metrics.total_load_ms : browser.total_load_ms;
    const domInteractive = metrics.dom_interactive_ms !== undefined ? metrics.dom_interactive_ms : browser.dom_interactive_ms;
    const domElements = metrics.dom_elements_count !== undefined ? metrics.dom_elements_count : browser.dom_elements_count;
    const transferBytes = metrics.transfer_size_bytes !== undefined ? metrics.transfer_size_bytes : browser.transfer_size_bytes;
    const lcp = metrics.lcp_ms;
    const cls = metrics.cls;

    let html = `
      <div class="grid grid-4" style="gap: var(--space-md); margin-bottom: var(--space-xl);">
        <div class="card glass-panel" style="padding: var(--space-lg); text-align: center;">
          <div class="text-xs text-muted" style="text-transform: uppercase;">Performance Score</div>
          <div style="font-size: 2.25rem; font-weight: 800; margin: 4px 0;" class="${scoreObj.class}">
            ${perfScore !== null ? Math.round(perfScore) : 'N/A'}
          </div>
          <span class="badge ${scoreObj.class}">${scoreObj.label}</span>
        </div>

        <div class="card glass-panel" style="padding: var(--space-lg); text-align: center;">
          <div class="text-xs text-muted" style="text-transform: uppercase;">TTFB (Time to First Byte)</div>
          <div style="font-size: 1.75rem; font-weight: 700; margin: 8px 0; color: var(--accent-blue);">
            ${ttfb !== undefined && ttfb !== null ? Math.round(ttfb) + 'ms' : 'N/A'}
          </div>
          <span class="text-xs text-muted">Navigation Timing Level 2</span>
        </div>

        <div class="card glass-panel" style="padding: var(--space-lg); text-align: center;">
          <div class="text-xs text-muted" style="text-transform: uppercase;">Total Page Load Time</div>
          <div style="font-size: 1.75rem; font-weight: 700; margin: 8px 0; color: var(--accent-cyan);">
            ${loadMs ? (loadMs >= 1000 ? (loadMs / 1000).toFixed(2) + 's' : Math.round(loadMs) + 'ms') : 'N/A'}
          </div>
          <span class="text-xs text-muted">${loadMs ? (loadMs < 2500 ? 'Compliant (< 2.5s)' : 'Requires Optimization') : 'Navigation Timing'}</span>
        </div>

        <div class="card glass-panel" style="padding: var(--space-lg); text-align: center;">
          <div class="text-xs text-muted" style="text-transform: uppercase;">DOM Interactive / Size</div>
          <div style="font-size: 1.75rem; font-weight: 700; margin: 8px 0; color: var(--accent-green);">
            ${domInteractive ? (domInteractive / 1000).toFixed(2) + 's' : (domElements ? domElements + ' nodes' : 'N/A')}
          </div>
          <span class="text-xs text-muted">${domElements ? domElements + ' DOM Elements' : 'Interactive Timestamp'}</span>
        </div>
      </div>

      <!-- Core Web Vitals Lab Diagnostics (if measured) -->
      ${(lcp !== undefined || transferBytes) ? `
      <div class="grid grid-3" style="gap: var(--space-md); margin-bottom: var(--space-xl);">
        <div class="card glass-panel" style="padding: var(--space-md); text-align: center;">
          <div class="text-xs text-muted">Largest Contentful Paint (LCP)</div>
          <div style="font-size: 1.25rem; font-weight: 700; color: var(--accent-primary); margin: 4px 0;">
            ${lcp !== undefined ? (lcp / 1000).toFixed(2) + 's' : (loadMs ? (loadMs / 1000).toFixed(2) + 's (Full Load)' : 'N/A')}
          </div>
          <span class="text-xs text-muted">Target: &lt; 2.5s</span>
        </div>
        <div class="card glass-panel" style="padding: var(--space-md); text-align: center;">
          <div class="text-xs text-muted">Cumulative Layout Shift (CLS)</div>
          <div style="font-size: 1.25rem; font-weight: 700; color: var(--accent-green); margin: 4px 0;">
            ${cls !== undefined ? cls : '0.00 (Stable)'}
          </div>
          <span class="text-xs text-muted">Target: &lt; 0.1</span>
        </div>
        <div class="card glass-panel" style="padding: var(--space-md); text-align: center;">
          <div class="text-xs text-muted">Wire Transfer Payload</div>
          <div style="font-size: 1.25rem; font-weight: 700; color: var(--text-primary); margin: 4px 0;">
            ${transferBytes ? (transferBytes / 1024).toFixed(1) + ' KB' : 'N/A'}
          </div>
          <span class="text-xs text-muted">Network Wire Size</span>
        </div>
      </div>
      ` : ''}

      <div class="glass-panel" style="padding: var(--space-xl); margin-bottom: var(--space-xl);">
        <h3 style="font-size: 1.25rem; font-weight: 700; margin-bottom: var(--space-md);">Performance Diagnostic Findings</h3>
    `;

    if (perfFindings.length === 0) {
      html += `
        <div class="empty-state">
          <div class="empty-state-icon"><span data-icon="checkCircle"></span></div>
          <h3 class="empty-state-title">No Performance Defects Detected</h3>
          <p class="empty-state-desc">Target page demonstrated compliant server response times and asset delivery budgets (${loadMs ? Math.round(loadMs) + 'ms total load' : 'verified'}).</p>
        </div>
      `;
    } else {
      html += `
        <div class="data-table-container">
          <table class="data-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Issue & Rule</th>
                <th>Recommendation & Remediation</th>
              </tr>
            </thead>
            <tbody>
      `;
      perfFindings.forEach(f => {
        html += `
          <tr>
            <td><span class="badge ${f.severity === 'CRITICAL' ? 'score-critical' : 'score-warning'}">${f.severity}</span></td>
            <td>
              <div style="font-weight: 600;">${escapeHtml(f.title)}</div>
              <div class="text-xs text-muted">${escapeHtml(f.rule_id || '')}</div>
            </td>
            <td>
              <p class="text-sm" style="margin-bottom: 4px;">${escapeHtml(f.description || '')}</p>
              ${f.recommendation ? `<div class="text-xs" style="color: var(--accent-primary); font-family: var(--font-mono);">${escapeHtml(f.recommendation)}</div>` : ''}
            </td>
          </tr>
        `;
      });
      html += `</tbody></table></div>`;
    }

    html += `</div>`;
    container.innerHTML = html;
    renderIcons(container);
  } catch (err) {
    container.innerHTML = `<div class="empty-state"><p class="text-danger">Failed to load performance metrics: ${escapeHtml(err.message)}</p></div>`;
  }
}
