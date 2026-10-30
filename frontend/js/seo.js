/**
 * WebAudit 360 — SEO Intelligence Viewer
 * Creator: Harsh Patel
 */

import { apiClient } from "./api.js";
import { escapeHtml, formatDate, getScoreDetails } from "./utils.js";
import { renderIcons } from "./icons.js";

export async function initSEOView() {
  const auditSelect = document.getElementById("select-audit-target");
  if (auditSelect) {
    auditSelect.addEventListener("change", (e) => loadSEOData(e.target.value));
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
      <option value="${a.id}">${escapeHtml(a.target_url)} (${a.scan_mode}) - ${formatDate(a.created_at)}</option>
    `).join("");

    await loadSEOData(audits[0].id);
  } catch (e) {
    console.warn("Failed to load audits for SEO:", e);
  }
}

export async function loadSEOData(auditId) {
  if (!auditId) return;
  const container = document.getElementById("seo-details-container");
  if (!container) return;

  try {
    const audit = await apiClient.get(`/audits/${auditId}`);
    const seoFindings = (audit.findings || []).filter(f => f.category === "SEO");
    const seoScore = audit.category_scores ? audit.category_scores.SEO : null;
    const scoreObj = getScoreDetails(seoScore);

    let html = `
      <div class="grid grid-3" style="gap: var(--space-md); margin-bottom: var(--space-xl);">
        <div class="card glass-panel" style="padding: var(--space-lg); text-align: center;">
          <div class="text-xs text-muted" style="text-transform: uppercase;">SEO Health Score</div>
          <div style="font-size: 2.25rem; font-weight: 800; margin: 4px 0;" class="${scoreObj.class}">
            ${seoScore !== null ? Math.round(seoScore) : 'N/A'}
          </div>
          <span class="badge ${scoreObj.class}">${scoreObj.label}</span>
        </div>

        <div class="card glass-panel" style="padding: var(--space-lg);">
          <div class="text-xs text-muted" style="text-transform: uppercase; margin-bottom: 6px;">Crawled Target URL</div>
          <div style="font-weight: 600; font-size: 0.95rem; word-break: break-all;">
            ${escapeHtml(audit.target_url)}
          </div>
          <div class="text-xs text-muted" style="margin-top: 6px;">Crawl Mode: ${escapeHtml(audit.scan_mode)}</div>
        </div>

        <div class="card glass-panel" style="padding: var(--space-lg);">
          <div class="text-xs text-muted" style="text-transform: uppercase; margin-bottom: 6px;">SEO Checks Summary</div>
          <div style="font-size: 1.15rem; font-weight: 700; color: var(--accent-primary);">
            ${seoFindings.length} SEO Diagnostics Flagged
          </div>
          <div class="text-xs text-muted" style="margin-top: 6px;">Headings, Meta, Canonicals, Open Graph</div>
        </div>
      </div>

      <div class="glass-panel" style="padding: var(--space-xl); margin-bottom: var(--space-xl);">
        <h3 style="font-size: 1.25rem; font-weight: 700; margin-bottom: var(--space-md);">SEO Evidence & Rule Analysis</h3>
    `;

    if (seoFindings.length === 0) {
      html += `
        <div class="empty-state">
          <div class="empty-state-icon"><span data-icon="checkCircle"></span></div>
          <h3 class="empty-state-title">Compliant Search Metadata</h3>
          <p class="empty-state-desc">Page exhibits proper title length, unique H1 header hierarchy, and valid canonical configuration.</p>
        </div>
      `;
    } else {
      html += `
        <div class="data-table-container">
          <table class="data-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Diagnostic Title</th>
                <th>Observed Evidence</th>
                <th>Remediation Advice</th>
              </tr>
            </thead>
            <tbody>
      `;
      seoFindings.forEach(f => {
        html += `
          <tr>
            <td><span class="badge ${f.severity === 'CRITICAL' ? 'score-critical' : 'score-warning'}">${f.severity}</span></td>
            <td>
              <div style="font-weight: 600;">${escapeHtml(f.title)}</div>
              <div class="text-xs text-muted">Rule: ${escapeHtml(f.rule_id || '')}</div>
            </td>
            <td>
              <code style="font-size: 0.75rem; background: var(--bg-surface); padding: 4px 8px; border-radius: 4px; display: block; max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                ${escapeHtml(f.evidence_snippet || f.description || 'Observed via HTML DOM')}
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
    container.innerHTML = `<div class="empty-state"><p class="text-danger">Failed to load SEO findings: ${escapeHtml(err.message)}</p></div>`;
  }
}

