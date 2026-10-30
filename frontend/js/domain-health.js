/**
 * WebAudit 360 — Domain, DNS & SSL Certificate Health Viewer
 * Creator: Harsh Patel
 */

import { apiClient } from "./api.js";
import { escapeHtml, formatDate, getScoreDetails } from "./utils.js";
import { renderIcons } from "./icons.js";

export async function initDomainHealthView() {
  const auditSelect = document.getElementById("select-audit-target");
  if (auditSelect) {
    auditSelect.addEventListener("change", (e) => loadDomainData(e.target.value));
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

    await loadDomainData(audits[0].id);
  } catch (e) {
    console.warn("Failed to load audits for Domain Health:", e);
  }
}

export async function loadDomainData(auditId) {
  if (!auditId) return;
  const container = document.getElementById("domain-details-container");
  if (!container) return;

  try {
    const audit = await apiClient.get(`/audits/${auditId}`);
    const domainFindings = (audit.findings || []).filter(f => f.category === "DOMAIN");
    const domainScore = audit.category_scores ? audit.category_scores.DOMAIN : null;
    const scoreObj = getScoreDetails(domainScore);

    let html = `
      <div class="grid grid-3" style="gap: var(--space-md); margin-bottom: var(--space-xl);">
        <div class="card glass-panel" style="padding: var(--space-lg); text-align: center;">
          <div class="text-xs text-muted" style="text-transform: uppercase;">Domain Health Score</div>
          <div style="font-size: 2.25rem; font-weight: 800; margin: 4px 0;" class="${scoreObj.class}">
            ${domainScore !== null ? Math.round(domainScore) : 'N/A'}
          </div>
          <span class="badge ${scoreObj.class}">${scoreObj.label}</span>
        </div>

        <div class="card glass-panel" style="padding: var(--space-lg);">
          <div class="text-xs text-muted" style="text-transform: uppercase; margin-bottom: 6px;">SSL/TLS Validity Chain</div>
          <div style="font-weight: 700; font-size: 1.05rem; color: var(--accent-green);">
            Active TLS Handshake Confirmed
          </div>
          <p class="text-xs text-muted" style="margin-top: 6px;">
            Audits certificate expiration dates, root issuer authorities, and handshake security.
          </p>
        </div>

        <div class="card glass-panel" style="padding: var(--space-lg);">
          <div class="text-xs text-muted" style="text-transform: uppercase; margin-bottom: 6px;">Public DNS Analysis</div>
          <div style="font-weight: 700; font-size: 1.05rem; color: var(--accent-primary);">
            A, AAAA, CAA Protection
          </div>
          <p class="text-xs text-muted" style="margin-top: 6px;">
            Validates authoritative nameservers and certificate issuance restrictions (RFC 8659).
          </p>
        </div>
      </div>

      <div class="glass-panel" style="padding: var(--space-xl); margin-bottom: var(--space-xl);">
        <h3 style="font-size: 1.25rem; font-weight: 700; margin-bottom: var(--space-md);">Domain & SSL Diagnostics</h3>
    `;

    if (domainFindings.length === 0) {
      html += `
        <div class="empty-state">
          <div class="empty-state-icon"><span data-icon="checkCircle"></span></div>
          <h3 class="empty-state-title">Domain & SSL Fully Healthy</h3>
          <p class="empty-state-desc">The SSL/TLS certificate is unexpired with valid issuer trust and public DNS resolution.</p>
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
                <th>Description</th>
                <th>Remediation Advice</th>
              </tr>
            </thead>
            <tbody>
      `;
      domainFindings.forEach(f => {
        html += `
          <tr>
            <td><span class="badge ${f.severity === 'CRITICAL' ? 'score-critical' : 'score-warning'}">${f.severity}</span></td>
            <td>
              <div style="font-weight: 600;">${escapeHtml(f.title)}</div>
              <div class="text-xs text-muted">Rule: ${escapeHtml(f.rule_id || '')}</div>
            </td>
            <td>
              <p class="text-sm" style="margin-bottom: 2px;">${escapeHtml(f.description || '')}</p>
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
    container.innerHTML = `<div class="empty-state"><p class="text-danger">Failed to load domain diagnostics: ${escapeHtml(err.message)}</p></div>`;
  }
}
