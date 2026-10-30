/**
 * WebAudit 360 — Responsive Intelligence Viewer
 * Creator: Harsh Patel
 */

import { apiClient } from "./api.js";
import { escapeHtml, formatDate, getScoreDetails } from "./utils.js";
import { renderIcons } from "./icons.js";

export async function initResponsiveView() {
  const auditSelect = document.getElementById("select-audit-target");
  if (auditSelect) {
    auditSelect.addEventListener("change", (e) => loadResponsiveData(e.target.value));
  }

  await populateAuditSelector();
}

async function populateAuditSelector() {
  const auditSelect = document.getElementById("select-audit-target");
  if (!auditSelect) return;

  try {
    const data = await apiClient.get("/audits?limit=20").catch(() => ({ items: [] }));
    const audits = data.items || [];

    if (audits.length === 0) {
      auditSelect.innerHTML = `<option value="">No audits available</option>`;
      return;
    }

    auditSelect.innerHTML = audits.map(a => `
      <option value="${a.id}">${escapeHtml(a.target_url)} - ${formatDate(a.created_at)}</option>
    `).join("");

    await loadResponsiveData(audits[0].id);
  } catch (e) {
    console.warn("Failed to load audits for Responsive:", e);
  }
}

export async function loadResponsiveData(auditId) {
  if (!auditId) return;
  const container = document.getElementById("responsive-details-container");
  if (!container) return;

  try {
    const audit = await apiClient.get(`/audits/${auditId}`);
    const respFindings = (audit.findings || []).filter(f => f.category === "RESPONSIVE");
    const respScore = audit.category_scores ? audit.category_scores.RESPONSIVE : null;
    const scoreObj = getScoreDetails(respScore);

    let html = `
      <div class="grid grid-3" style="gap: var(--space-md); margin-bottom: var(--space-xl);">
        <div class="card glass-panel" style="padding: var(--space-lg); text-align: center;">
          <div class="text-xs text-muted" style="text-transform: uppercase;">Responsive Health</div>
          <div style="font-size: 2.25rem; font-weight: 800; margin: 4px 0;" class="${scoreObj.class}">
            ${respScore !== null ? Math.round(respScore) : 'N/A'}
          </div>
          <span class="badge ${scoreObj.class}">${scoreObj.label}</span>
        </div>

        <div class="card glass-panel" style="padding: var(--space-lg);">
          <div class="text-xs text-muted" style="text-transform: uppercase; margin-bottom: 6px;">Emulated Viewports</div>
          <div style="font-size: 0.95rem; font-weight: 600; color: var(--accent-primary);">
            390×844 (Mobile) &bull; 768×1024 (Tablet) &bull; 1440×900 (Desktop)
          </div>
          <p class="text-xs text-muted" style="margin-top: 6px;">
            Detects horizontal scroll overflow, clipping, and undersized touch targets (&lt;48×48px).
          </p>
        </div>

        <div class="card glass-panel" style="padding: var(--space-lg);">
          <div class="text-xs text-muted" style="text-transform: uppercase; margin-bottom: 6px;">Emulation Disclaimer</div>
          <div style="font-size: 0.95rem; font-weight: 600; color: var(--text-secondary);">
            Emulated Browser Session
          </div>
          <p class="text-xs text-muted" style="margin-top: 6px;">
            Viewport emulation simulates layout dimensions, not physical GPU hardware acceleration.
          </p>
        </div>
      </div>

      <div class="glass-panel" style="padding: var(--space-xl); margin-bottom: var(--space-xl);">
        <h3 style="font-size: 1.25rem; font-weight: 700; margin-bottom: var(--space-md);">Responsive & Viewport Diagnostics</h3>
    `;

    if (respFindings.length === 0) {
      html += `
        <div class="empty-state">
          <div class="empty-state-icon"><span data-icon="smartphone"></span></div>
          <h3 class="empty-state-title">No Horizontal Overflow or Layout Clipping</h3>
          <p class="empty-state-desc">The target page renders within boundary constraints across all tested viewports.</p>
        </div>
      `;
    } else {
      html += `
        <div class="data-table-container">
          <table class="data-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Diagnostic</th>
                <th>Observed Evidence</th>
                <th>Remediation Guide</th>
              </tr>
            </thead>
            <tbody>
      `;
      respFindings.forEach(f => {
        html += `
          <tr>
            <td><span class="badge ${f.severity === 'CRITICAL' ? 'score-critical' : 'score-warning'}">${f.severity}</span></td>
            <td>
              <div style="font-weight: 600;">${escapeHtml(f.title)}</div>
              <div class="text-xs text-muted">Rule: ${escapeHtml(f.rule_id || '')}</div>
            </td>
            <td>
              <code style="font-size: 0.75rem; background: var(--bg-surface); padding: 4px 8px; border-radius: 4px; display: block; max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                ${escapeHtml(f.evidence_snippet || f.description || 'Viewport Measurement')}
              </code>
            </td>
            <td>
              <p class="text-xs" style="color: var(--text-secondary);">${escapeHtml(f.recommendation || f.description || '')}</p>
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
    container.innerHTML = `<div class="empty-state"><p class="text-danger">Failed to load responsive findings: ${escapeHtml(err.message)}</p></div>`;
  }
}
