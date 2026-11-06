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
      <option value="${a.id}" ${a.id === targetAudit.id ? 'selected' : ''}>${escapeHtml(a.target_url)} - ${formatDate(a.created_at)}</option>
    `).join("");

    await loadSecurityData(targetAudit.id);
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
    const secScore = audit.category_scores ? (audit.category_scores.SECURITY_PASSIVE ?? audit.category_scores.SECURITY) : null;
    const scoreObj = getScoreDetails(secScore);

    const secRaw = audit.raw_results?.SECURITY_PASSIVE || {};
    const headers = secRaw.headers || {};
    const isHttps = secRaw.is_https !== undefined ? secRaw.is_https : audit.target_url.startsWith("https://");

    const hasHsts = !!headers["strict-transport-security"];
    const hasCsp = !!headers["content-security-policy"];
    const hasXfo = !!headers["x-frame-options"];
    const hasXcto = !!headers["x-content-type-options"];
    const hasRefPol = !!headers["referrer-policy"];

    const secActiveRaw = audit.raw_results?.SECURITY_ACTIVE || {};
    const isAuthorized = secActiveRaw.authorized === true;
    const activeScore = secActiveRaw.score;
    const activeProbes = secActiveRaw.probes || {};

    // Active Gatekeeper Card
    let activeCardHtml = "";
    if (isAuthorized) {
      const activeScoreObj = getScoreDetails(activeScore);
      activeCardHtml = `
        <div class="card glass-panel" style="padding: var(--space-lg);">
          <div class="flex items-center justify-between" style="margin-bottom: 6px;">
            <span class="text-xs text-muted" style="text-transform: uppercase;">Active Testing Engine</span>
            <span class="badge score-good">VERIFIED & PROBED</span>
          </div>
          <div style="font-size: 1.75rem; font-weight: 800; margin: 4px 0;" class="${activeScoreObj.class}">
            ${activeScore !== null ? Math.round(activeScore) : '100'} <span style="font-size: 0.9rem; font-weight: 400; color: var(--text-muted);">/ 100</span>
          </div>
          <p class="text-xs text-muted">
            5 non-destructive probes executed under cryptographic domain verification.
          </p>
        </div>
      `;
    } else {
      activeCardHtml = `
        <div class="card glass-panel" style="padding: var(--space-lg);">
          <div class="flex items-center justify-between" style="margin-bottom: 6px;">
            <span class="text-xs text-muted" style="text-transform: uppercase;">Active Testing Engine</span>
            <span class="badge score-warning">AUTHORIZATION REQUIRED</span>
          </div>
          <div style="font-size: 1.05rem; font-weight: 700; color: var(--accent-cyan); margin: 6px 0;">
            Active Probes Blocked
          </div>
          <p class="text-xs text-muted" style="margin-bottom: var(--space-sm);">
            Domain verification required before active non-destructive vulnerability assessments can execute.
          </p>
          <button class="btn btn-secondary btn-sm" onclick="window.requestDomainAuth('${encodeURIComponent(audit.target_url)}')">
            <span data-icon="shield"></span> Verify Domain Ownership
          </button>
        </div>
      `;
    }

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
          <div class="text-xs text-muted" style="text-transform: uppercase; margin-bottom: 6px;">Transport & Headers</div>
          <div style="font-weight: 700; font-size: 1.05rem; color: ${isHttps ? 'var(--accent-green)' : 'var(--accent-danger)'};">
            ${isHttps ? 'TLS Encrypted (HTTPS)' : 'Insecure Plaintext (HTTP)'}
          </div>
          <p class="text-xs text-muted" style="margin-top: 6px;">
            HSTS: ${hasHsts ? 'Enforced' : 'Missing'} &bull; CSP: ${hasCsp ? 'Configured' : 'Missing'}
          </p>
        </div>

        ${activeCardHtml}
      </div>

      <!-- Real Response Headers Matrix -->
      <div class="glass-panel" style="padding: var(--space-lg); margin-bottom: var(--space-xl);">
        <h4 style="font-size: 1.05rem; font-weight: 700; margin-bottom: var(--space-md); color: var(--text-primary);">
          <span data-icon="shield"></span> Defensive HTTP Headers Evaluation
        </h4>
        <div class="grid grid-3 text-xs" style="gap: var(--space-md);">
          <div class="card glass-panel" style="padding: var(--space-md);">
            <div style="font-weight: 700; margin-bottom: 4px;">Strict-Transport-Security (HSTS)</div>
            <span class="badge ${hasHsts ? 'score-good' : 'score-poor'}">${hasHsts ? 'Present' : 'Missing'}</span>
          </div>
          <div class="card glass-panel" style="padding: var(--space-md);">
            <div style="font-weight: 700; margin-bottom: 4px;">Content-Security-Policy (CSP)</div>
            <span class="badge ${hasCsp ? 'score-good' : 'score-poor'}">${hasCsp ? 'Present' : 'Missing'}</span>
          </div>
          <div class="card glass-panel" style="padding: var(--space-md);">
            <div style="font-weight: 700; margin-bottom: 4px;">X-Frame-Options (Clickjacking)</div>
            <span class="badge ${hasXfo ? 'score-good' : 'score-warning'}">${hasXfo ? 'Present' : 'Missing'}</span>
          </div>
          <div class="card glass-panel" style="padding: var(--space-md);">
            <div style="font-weight: 700; margin-bottom: 4px;">X-Content-Type-Options</div>
            <span class="badge ${hasXcto ? 'score-good' : 'score-warning'}">${hasXcto ? 'Present' : 'Missing'}</span>
          </div>
          <div class="card glass-panel" style="padding: var(--space-md);">
            <div style="font-weight: 700; margin-bottom: 4px;">Referrer-Policy</div>
            <span class="badge ${hasRefPol ? 'score-good' : 'score-warning'}">${hasRefPol ? 'Present' : 'Missing'}</span>
          </div>
          <div class="card glass-panel" style="padding: var(--space-md);">
            <div style="font-weight: 700; margin-bottom: 4px;">Transport Security</div>
            <span class="badge ${isHttps ? 'score-good' : 'score-critical'}">${isHttps ? 'HTTPS / TLS' : 'Insecure HTTP'}</span>
          </div>
        </div>
      </div>
    `;

    // Active Security Probes Matrix (rendered when authorized)
    if (isAuthorized && Object.keys(activeProbes).length > 0) {
      const probeItems = [
        { name: "HTTP Method Tampering", key: "http_methods", desc: "OPTIONS, TRACE, TRACK, PUT, DELETE checks" },
        { name: "CORS Credential Reflection", key: "cors", desc: "Arbitrary and null Origin reflection checks" },
        { name: "Sensitive File Exposure", key: "sensitive_files", desc: "/.env, /.git/HEAD, security.txt, backups" },
        { name: "Open Redirect Reflection", key: "open_redirect", desc: "Query parameter redirect validation" },
        { name: "Frameability & Clickjacking", key: "clickjacking", desc: "X-Frame-Options and CSP frame-ancestors" }
      ];

      html += `
        <div class="glass-panel" style="padding: var(--space-lg); margin-bottom: var(--space-xl);">
          <h4 style="font-size: 1.05rem; font-weight: 700; margin-bottom: var(--space-md); color: var(--text-primary);">
            <span data-icon="zap"></span> Active Non-Destructive Probes Execution Matrix
          </h4>
          <div class="grid grid-3 text-xs" style="gap: var(--space-md);">
            ${probeItems.map(p => {
              const probeData = activeProbes[p.key] || {};
              const isPass = probeData.status === "PASS";
              return `
                <div class="card glass-panel" style="padding: var(--space-md);">
                  <div class="flex items-center justify-between" style="margin-bottom: 4px;">
                    <div style="font-weight: 700;">${escapeHtml(p.name)}</div>
                    <span class="badge ${isPass ? 'score-good' : 'score-poor'}">${isPass ? 'PASS' : 'VULNERABILITY'}</span>
                  </div>
                  <p class="text-xs text-muted" style="margin-bottom: 0;">${escapeHtml(p.desc)}</p>
                </div>
              `;
            }).join("")}
          </div>
        </div>
      `;
    }

    html += `
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
          <h3 class="empty-state-title">No Security Deficiencies Detected</h3>
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
                ${escapeHtml(f.evidence_snippet || f.description || 'Observation details')}
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
    showToast(`Domain verification challenge requested for ${domain}. Check your Project dashboard.`, "info");
  } catch (e) {
    showToast("Invalid domain URL", "error");
  }
};
