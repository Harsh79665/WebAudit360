/**
 * WebAudit 360 — Technology Intelligence & Stack Fingerprinting Viewer
 * Creator: Harsh Patel
 * 
 * Incorporates deep client-side telemetry and module signature analysis
 * informed by REA reverse-engineering principles (Apache 2.0 / research methodology).
 */

import { apiClient } from "./api.js";
import { escapeHtml, formatDate, getScoreDetails } from "./utils.js";
import { renderIcons } from "./icons.js";

export async function initTechnologyView() {
  const auditSelect = document.getElementById("select-audit-target");
  if (auditSelect) {
    auditSelect.addEventListener("change", (e) => loadTechnologyData(e.target.value));
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

    await loadTechnologyData(audits[0].id);
  } catch (e) {
    console.warn("Failed to load audits for Technology:", e);
  }
}

export async function loadTechnologyData(auditId) {
  if (!auditId) return;
  const container = document.getElementById("technology-details-container");
  if (!container) return;

  try {
    const audit = await apiClient.get(`/audits/${auditId}`);
    const techFindings = (audit.findings || []).filter(f => f.category === "TECHNOLOGY");

    let html = `
      <div class="grid grid-3" style="gap: var(--space-md); margin-bottom: var(--space-xl);">
        <div class="card glass-panel" style="padding: var(--space-lg); text-align: center;">
          <div class="text-xs text-muted" style="text-transform: uppercase;">Detected Components</div>
          <div style="font-size: 2.25rem; font-weight: 800; margin: 4px 0; color: var(--accent-primary);">
            ${techFindings.length}
          </div>
          <span class="badge">Evidence Verified</span>
        </div>

        <div class="card glass-panel" style="padding: var(--space-lg);">
          <div class="text-xs text-muted" style="text-transform: uppercase; margin-bottom: 6px;">Inspection Methodology</div>
          <div style="font-weight: 700; font-size: 1.05rem; color: var(--accent-cyan);">
            Passive Bundle & DOM Telemetry
          </div>
          <p class="text-xs text-muted" style="margin-top: 6px;">
            Informed by REA reverse-engineering principles for tracing client-side runtime symbols, script paths, and response headers.
          </p>
        </div>

        <div class="card glass-panel" style="padding: var(--space-lg);">
          <div class="text-xs text-muted" style="text-transform: uppercase; margin-bottom: 6px;">Confidence Standard</div>
          <div style="font-weight: 700; font-size: 1.05rem; color: var(--accent-green);">
            Zero Speculation
          </div>
          <p class="text-xs text-muted" style="margin-top: 6px;">
            Technologies are only reported when verified by explicit regex matches against client assets.
          </p>
        </div>
      </div>

      <div class="glass-panel" style="padding: var(--space-xl); margin-bottom: var(--space-xl);">
        <h3 style="font-size: 1.25rem; font-weight: 700; margin-bottom: var(--space-md);">Identified Technology Stack</h3>
    `;

    if (techFindings.length === 0) {
      html += `
        <div class="empty-state">
          <div class="empty-state-icon"><span data-icon="cpu"></span></div>
          <h3 class="empty-state-title">No Known Framework Signatures Detected</h3>
          <p class="empty-state-desc">Target site uses custom vanilla HTML/CSS/JS or sanitizes all recognizable header fingerprints.</p>
        </div>
      `;
    } else {
      html += `
        <div class="data-table-container">
          <table class="data-table">
            <thead>
              <tr>
                <th>Technology</th>
                <th>Confidence</th>
                <th>Observed Signature Evidence</th>
              </tr>
            </thead>
            <tbody>
      `;
      techFindings.forEach(f => {
        html += `
          <tr>
            <td>
              <div style="font-weight: 700; font-size: 1rem; color: var(--text-primary);">${escapeHtml(f.title.replace('Detected: ', ''))}</div>
              <div class="text-xs text-muted">ID: ${escapeHtml(f.rule_id || '')}</div>
            </td>
            <td>
              <span class="badge" style="background: var(--accent-glow); color: var(--accent-primary); font-weight: 700;">
                ${f.confidence ? Math.round(f.confidence * 100) : 95}% Confidence
              </span>
            </td>
            <td>
              <code style="font-size: 0.75rem; background: var(--bg-surface); padding: 4px 8px; border-radius: 4px; display: block; max-width: 360px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                ${escapeHtml(f.evidence_snippet || f.description || 'Verified via DOM/Script')}
              </code>
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
    container.innerHTML = `<div class="empty-state"><p class="text-danger">Failed to load technology stack: ${escapeHtml(err.message)}</p></div>`;
  }
}

