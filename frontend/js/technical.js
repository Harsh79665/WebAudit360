/**
 * WebAudit 360 — Technical Health Intelligence Viewer
 * Creator: Harsh Patel
 */

import { apiClient } from "./api.js";
import { escapeHtml, formatDate, getScoreDetails } from "./utils.js";
import { renderIcons } from "./icons.js";

export async function initTechnicalView() {
  const auditSelect = document.getElementById("select-audit-target");
  if (auditSelect) {
    auditSelect.addEventListener("change", (e) => loadTechnicalData(e.target.value));
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

    await loadTechnicalData(audits[0].id);
  } catch (e) {
    console.warn("Failed to load audits for Technical Health:", e);
  }
}

export async function loadTechnicalData(auditId) {
  if (!auditId) return;
  const container = document.getElementById("technical-details-container");
  if (!container) return;

  try {
    const audit = await apiClient.get(`/audits/${auditId}`);
    const techFindings = (audit.findings || []).filter(f => f.category === "TECHNICAL");
    const techScore = audit.category_scores ? audit.category_scores.TECHNICAL : null;
    const scoreObj = getScoreDetails(techScore);

    let html = `
      <div class="grid grid-3" style="gap: var(--space-md); margin-bottom: var(--space-xl);">
        <div class="card glass-panel" style="padding: var(--space-lg); text-align: center;">
          <div class="text-xs text-muted" style="text-transform: uppercase;">Technical Health Score</div>
          <div style="font-size: 2.25rem; font-weight: 800; margin: 4px 0;" class="${scoreObj.class}">
            ${techScore !== null ? Math.round(techScore) : 'N/A'}
          </div>
          <span class="badge ${scoreObj.class}">${scoreObj.label}</span>
        </div>

        <div class="card glass-panel" style="padding: var(--space-lg);">
          <div class="text-xs text-muted" style="text-transform: uppercase; margin-bottom: 6px;">Runtime Health Telemetry</div>
          <div style="font-weight: 700; font-size: 1.05rem; color: var(--accent-primary);">
            Console & Network Monitor
          </div>
          <p class="text-xs text-muted" style="margin-top: 6px;">
            Inspects HTTP response statuses, broken internal/external links, and unhandled JS exceptions.
          </p>
        </div>

        <div class="card glass-panel" style="padding: var(--space-lg);">
          <div class="text-xs text-muted" style="text-transform: uppercase; margin-bottom: 6px;">Crawl Discovery Depth</div>
          <div style="font-size: 1.05rem; font-weight: 700; color: var(--accent-cyan);">
            ${audit.pages ? audit.pages.length : 1} Page(s) Scanned
          </div>
          <p class="text-xs text-muted" style="margin-top: 6px;">
            Target: ${escapeHtml(audit.target_url)}
          </p>
        </div>
      </div>

      <div class="glass-panel" style="padding: var(--space-xl); margin-bottom: var(--space-xl);">
        <h3 style="font-size: 1.25rem; font-weight: 700; margin-bottom: var(--space-md);">Technical Defect Log</h3>
    `;

    if (techFindings.length === 0) {
      html += `
        <div class="empty-state">
          <div class="empty-state-icon"><span data-icon="checkCircle"></span></div>
          <h3 class="empty-state-title">No Broken Links or Runtime Errors</h3>
          <p class="empty-state-desc">All resource requests returned 200 OK without console exceptions or redirect loops.</p>
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
                <th>Resolution Advice</th>
              </tr>
            </thead>
            <tbody>
      `;
      techFindings.forEach(f => {
        html += `
          <tr>
            <td><span class="badge ${f.severity === 'CRITICAL' ? 'score-critical' : 'score-warning'}">${f.severity}</span></td>
            <td>
              <div style="font-weight: 600;">${escapeHtml(f.title)}</div>
              <div class="text-xs text-muted">Rule: ${escapeHtml(f.rule_id || '')}</div>
            </td>
            <td>
              <code style="font-size: 0.75rem; background: var(--bg-surface); padding: 4px 8px; border-radius: 4px; display: block; max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                ${escapeHtml(f.evidence_snippet || f.description || 'Network Telemetry')}
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
    container.innerHTML = `<div class="empty-state"><p class="text-danger">Failed to load technical findings: ${escapeHtml(err.message)}</p></div>`;
  }
}

