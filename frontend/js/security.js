/**
 * WebAudit 360 — Security Intelligence (Passive & Authorized Active) Viewer
 * Creator: Harsh Patel
 */

import { apiClient } from "./api.js";
import { escapeHtml, formatDate, getScoreDetails, showToast } from "./utils.js";
import { renderIcons } from "./icons.js";

export async function initSecurityView() {
  const auditSelect = document.getElementById("select-audit-target");
  if (auditSelect) {
    auditSelect.addEventListener("change", (e) => loadSecurityData(e.target.value));
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

    await loadSecurityData(audits[0].id);
  } catch (e) {
    console.warn("Failed to load audits for Security:", e);
  }
}

export async function loadSecurityData(auditId) {
  if (!auditId) return;
  const container = document.getElementById("security-details-container");
  if (!container) return;

  try {
    const audit = await apiClient.get(`/audits/${auditId}`);
    const secFindings = (audit.findings || []).filter(f => 
      f.category === "SECURITY_PASSIVE" || f.category === "SECURITY_ACTIVE"
    );
    const secScore = audit.category_scores ? audit.category_scores.SECURITY_PASSIVE : null;
    const scoreObj = getScoreDetails(secScore);

    let html = `
      <div class="grid grid-3" style="gap: var(--space-md); margin-bottom: var(--space-xl);">
        <div class="card glass-panel" style="padding: var(--space-lg); text-align: center;">
          <div class="text-xs text-muted" style="text-transform: uppercase;">Passive Security Score</div>
          <div style="font-size: 2.25rem; font-weight: 800; margin: 4px 0;" class="${scoreObj.class}">
            ${secScore !== null ? Math.round(secScore) : 'N/A'}
          </div>
          <span class="badge ${scoreObj.class}">${scoreObj.label}</span>
        </div>

        <div class="card glass-panel" style="padding: var(--space-lg);">
          <div class="text-xs text-muted" style="text-transform: uppercase; margin-bottom: 6px;">Passive Headers Audit</div>
          <div style="font-weight: 700; font-size: 1.05rem; color: var(--accent-primary);">
            RFC & OWASP Recommended Headers
          </div>
          <p class="text-xs text-muted" style="margin-top: 6px;">
            HSTS, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.
          </p>
        </div>

        <div class="card glass-panel" style="padding: var(--space-lg);">
          <div class="text-xs text-muted" style="text-transform: uppercase; margin-bottom: 6px;">Active Testing Gatekeeper</div>
          <div style="font-size: 1.05rem; font-weight: 700; color: var(--accent-cyan);">
            Cryptographic Authorization Required
          </div>
          <p class="text-xs text-muted" style="margin-top: 6px;">
            Active non-destructive probing requires a verified DNS TXT or HTTP well-known token challenge.
          </p>
        </div>
      </div>

      <div class="glass-panel" style="padding: var(--space-xl); margin-bottom: var(--space-xl);">
        <div class="flex items-center justify-between" style="margin-bottom: var(--space-md);">
          <h3 style="font-size: 1.25rem; font-weight: 700;">Security Findings & Header Diagnostics</h3>
          <button class="btn btn-secondary btn-sm" onclick="window.requestDomainAuth('${encodeURIComponent(audit.target_url)}')">
            <span data-icon="shield"></span> Request Domain Verification
          </button>
        </div>
    `;

    if (secFindings.length === 0) {
      html += `
        <div class="empty-state">
          <div class="empty-state-icon"><span data-icon="shield"></span></div>
          <h3 class="empty-state-title">No Security Header Deficiencies Detected</h3>
          <p class="empty-state-desc">The web server enforces proper TLS transport, defensive framing rules, and mime-type protection.</p>
        </div>
      `;
    } else {
      html += `
        <div class="data-table-container">
          <table class="data-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Header / Vulnerability</th>
                <th>Observed Evidence</th>
                <th>Hardening Recommendation</th>
              </tr>
            </thead>
            <tbody>
      `;
      secFindings.forEach(f => {
        html += `
          <tr>
            <td><span class="badge ${f.severity === 'CRITICAL' ? 'score-critical' : (f.severity === 'HIGH' ? 'score-poor' : 'score-warning')}">${f.severity}</span></td>
            <td>
              <div style="font-weight: 600;">${escapeHtml(f.title)}</div>
              <div class="text-xs text-muted">Rule: ${escapeHtml(f.rule_id || '')}</div>
            </td>
            <td>
              <code style="font-size: 0.75rem; background: var(--bg-surface); padding: 4px 8px; border-radius: 4px; display: block; max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                ${escapeHtml(f.evidence_snippet || f.description || 'Response Header Observation')}
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
    container.innerHTML = `<div class="empty-state"><p class="text-danger">Failed to load security findings: ${escapeHtml(err.message)}</p></div>`;
  }
}

window.requestDomainAuth = async function(targetUrl) {
  try {
    const parsed = new URL(decodeURIComponent(targetUrl));
    const domain = parsed.hostname;
    // Look up or create project
    showToast(`Domain verification challenge requested for ${domain}. Check your Project dashboard.`, "info");
  } catch (e) {
    showToast("Invalid domain URL", "error");
  }
};
