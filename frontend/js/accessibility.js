/**
 * WebAudit 360 — Accessibility (axe-core WCAG 2.1/2.2 AA) Viewer
 * Creator: Harsh Patel
 */

import { apiClient } from "./api.js";
import { escapeHtml, formatDate, getScoreDetails } from "./utils.js";
import { renderIcons } from "./icons.js";

export async function initAccessibilityView() {
  const auditSelect = document.getElementById("select-audit-target");
  if (auditSelect) {
    auditSelect.addEventListener("change", (e) => loadAccessibilityData(e.target.value));
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
      <option value="${a.id}">${escapeHtml(a.target_url)} (${a.device_profile}) - ${formatDate(a.created_at)}</option>
    `).join("");

    await loadAccessibilityData(audits[0].id);
  } catch (e) {
    console.warn("Failed to load audits for Accessibility:", e);
  }
}

export async function loadAccessibilityData(auditId) {
  if (!auditId) return;
  const container = document.getElementById("accessibility-details-container");
  if (!container) return;

  try {
    const audit = await apiClient.get(`/audits/${auditId}`);
    const a11yFindings = (audit.findings || []).filter(f => f.category === "ACCESSIBILITY");
    const a11yScore = audit.category_scores ? audit.category_scores.ACCESSIBILITY : null;
    const scoreObj = getScoreDetails(a11yScore);

    let html = `
      <div class="grid grid-3" style="gap: var(--space-md); margin-bottom: var(--space-xl);">
        <div class="card glass-panel" style="padding: var(--space-lg); text-align: center;">
          <div class="text-xs text-muted" style="text-transform: uppercase;">Accessibility Score</div>
          <div style="font-size: 2.25rem; font-weight: 800; margin: 4px 0;" class="${scoreObj.class}">
            ${a11yScore !== null ? Math.round(a11yScore) : 'N/A'}
          </div>
          <span class="badge ${scoreObj.class}">${scoreObj.label}</span>
        </div>

        <div class="card glass-panel" style="padding: var(--space-lg);">
          <div class="text-xs text-muted" style="text-transform: uppercase; margin-bottom: 6px;">Evaluation Engine</div>
          <div style="font-weight: 700; font-size: 1.15rem; color: var(--accent-primary);">
            axe-core v4.10.x inside Playwright
          </div>
          <p class="text-xs text-muted" style="margin-top: 6px;">
            Audits color contrast, ARIA landmarks, form labels, image alt text, and document structure.
          </p>
        </div>

        <div class="card glass-panel" style="padding: var(--space-lg);">
          <div class="text-xs text-muted" style="text-transform: uppercase; margin-bottom: 6px;">Automated Testing Boundary</div>
          <div style="font-size: 0.95rem; font-weight: 600; color: var(--accent-warning);">
            ~30-40% of WCAG Rules Covered
          </div>
          <p class="text-xs text-muted" style="margin-top: 6px;">
            Manual verification with screen readers (NVDA/VoiceOver) is required for comprehensive compliance.
          </p>
        </div>
      </div>

      <div class="glass-panel" style="padding: var(--space-xl); margin-bottom: var(--space-xl);">
        <h3 style="font-size: 1.25rem; font-weight: 700; margin-bottom: var(--space-md);">WCAG 2.1 / 2.2 AA Violations</h3>
    `;

    if (a11yFindings.length === 0) {
      html += `
        <div class="empty-state">
          <div class="empty-state-icon"><span data-icon="checkCircle"></span></div>
          <h3 class="empty-state-title">No Automated Accessibility Violations Detected</h3>
          <p class="empty-state-desc">The page passed all automated axe-core test criteria.</p>
        </div>
      `;
    } else {
      html += `
        <div class="data-table-container">
          <table class="data-table">
            <thead>
              <tr>
                <th>Impact</th>
                <th>Violation</th>
                <th>CSS Selector / Element</th>
                <th>Remediation Guide</th>
              </tr>
            </thead>
            <tbody>
      `;
      a11yFindings.forEach(f => {
        html += `
          <tr>
            <td><span class="badge ${f.severity === 'CRITICAL' ? 'score-critical' : 'score-warning'}">${f.severity}</span></td>
            <td>
              <div style="font-weight: 600;">${escapeHtml(f.title)}</div>
              <div class="text-xs text-muted">Rule: ${escapeHtml(f.rule_id || '')}</div>
            </td>
            <td>
              <code style="font-size: 0.75rem; background: var(--bg-surface); padding: 4px 8px; border-radius: 4px; display: block; max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                ${escapeHtml(f.evidence_snippet || 'DOM Node')}
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
    container.innerHTML = `<div class="empty-state"><p class="text-danger">Failed to load accessibility findings: ${escapeHtml(err.message)}</p></div>`;
  }
}

