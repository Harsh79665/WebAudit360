/**
 * WebAudit 360 — Third-Party Dependency & Origin Analyzer
 * Creator: Harsh Patel
 */

import { apiClient } from "./api.js";
import { escapeHtml, formatDate } from "./utils.js";
import { renderIcons } from "./icons.js";

export async function initDependenciesView() {
  const auditSelect = document.getElementById("select-audit-target");
  if (auditSelect) {
    auditSelect.addEventListener("change", (e) => loadDependenciesData(e.target.value));
  }

  await populateAuditSelector();
}

async function populateAuditSelector() {
  const auditSelect = document.getElementById("select-audit-target");
  if (!auditSelect) return;

  try {
    const data = await apiClient.get("/audits?limit=20").catch(() => ({ items: [] }));
    const audits = (data.items || []).filter(a => !a.target_url.includes("example.com"));

    if (audits.length === 0) {
      auditSelect.innerHTML = `<option value="">No audits available</option>`;
      return;
    }

    auditSelect.innerHTML = audits.map(a => `
      <option value="${a.id}">${escapeHtml(a.target_url)} - ${formatDate(a.created_at)}</option>
    `).join("");

    await loadDependenciesData(audits[0].id);
  } catch (e) {
    console.warn("Failed to load audits for Dependencies:", e);
  }
}

export async function loadDependenciesData(auditId) {
  if (!auditId) return;
  const container = document.getElementById("dependencies-details-container");
  if (!container) return;

  try {
    const audit = await apiClient.get(`/audits/${auditId}`);
    const depRaw = audit.raw_results?.THIRD_PARTY || {};
    const rawOrigins = depRaw.origins || [];
    const depFindings = (audit.findings || []).filter(f => f.category === "THIRD_PARTY");

    const totalCount = Math.max(rawOrigins.length, depFindings.length);

    let html = `
      <div class="grid grid-3" style="gap: var(--space-md); margin-bottom: var(--space-xl);">
        <div class="card glass-panel" style="padding: var(--space-lg); text-align: center;">
          <div class="text-xs text-muted" style="text-transform: uppercase;">External Origins</div>
          <div style="font-size: 2.25rem; font-weight: 800; margin: 4px 0; color: var(--accent-primary);">
            ${totalCount}
          </div>
          <span class="badge">Tracked Origins</span>
        </div>

        <div class="card glass-panel" style="padding: var(--space-lg);">
          <div class="text-xs text-muted" style="text-transform: uppercase; margin-bottom: 6px;">Supply-Chain Analysis</div>
          <div style="font-weight: 700; font-size: 1.05rem; color: var(--accent-cyan);">
            Scripts, Fonts, CDNs & Assets
          </div>
          <p class="text-xs text-muted" style="margin-top: 6px;">
            Measures third-party network requests that could impact page rendering, privacy, or resilience.
          </p>
        </div>

        <div class="card glass-panel" style="padding: var(--space-lg);">
          <div class="text-xs text-muted" style="text-transform: uppercase; margin-bottom: 6px;">Zero False Attribution</div>
          <div style="font-weight: 700; font-size: 1.05rem; color: var(--accent-green);">
            Observed Network Traffic
          </div>
          <p class="text-xs text-muted" style="margin-top: 6px;">
            No service is marked malicious without verifiable security signatures.
          </p>
        </div>
      </div>

      <!-- Verified Third-Party Domains Card -->
      ${rawOrigins.length > 0 ? `
      <div class="glass-panel" style="padding: var(--space-lg); margin-bottom: var(--space-xl);">
        <h4 style="font-size: 1.05rem; font-weight: 700; margin-bottom: var(--space-md); color: var(--text-primary);">
          <span data-icon="share"></span> Observed Outbound Network Origins
        </h4>
        <div class="grid grid-3" style="gap: var(--space-sm);">
          ${rawOrigins.map(origin => `
            <div class="card glass-panel" style="padding: var(--space-sm) var(--space-md); display: flex; align-items: center; justify-content: space-between;">
              <code style="font-size: 0.85rem; color: var(--accent-blue);">${escapeHtml(origin)}</code>
              <span class="badge score-good" style="font-size: 0.7rem;">Verified</span>
            </div>
          `).join('')}
        </div>
      </div>
      ` : ''}

      <div class="glass-panel" style="padding: var(--space-xl); margin-bottom: var(--space-xl);">
        <h3 style="font-size: 1.25rem; font-weight: 700; margin-bottom: var(--space-md);">Third-Party Origin Breakdown</h3>
    `;

    if (totalCount === 0) {
      html += `
        <div class="empty-state">
          <div class="empty-state-icon"><span data-icon="checkCircle"></span></div>
          <h3 class="empty-state-title">No Excessive Third-Party Dependencies Observed</h3>
          <p class="empty-state-desc">The page primarily serves assets from its own first-party origin.</p>
        </div>
      `;
    } else {
      html += `
        <div class="data-table-container">
          <table class="data-table">
            <thead>
              <tr>
                <th>Origin Host</th>
                <th>Resource / Diagnostic</th>
                <th>Impact & Guidance</th>
              </tr>
            </thead>
            <tbody>
      `;

      if (depFindings.length > 0) {
        depFindings.forEach(f => {
          html += `
            <tr>
              <td>
                <div style="font-weight: 700; color: var(--text-primary);">${escapeHtml(f.title.replace('Third-Party Origin: ', ''))}</div>
                <div class="text-xs text-muted">Rule: ${escapeHtml(f.rule_id || '')}</div>
              </td>
              <td>
                <code style="font-size: 0.75rem; background: var(--bg-surface); padding: 4px 8px; border-radius: 4px; display: block; max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                  ${escapeHtml(f.evidence_snippet || f.description || 'Observed Resource URL')}
                </code>
              </td>
              <td>
                <p class="text-xs" style="color: var(--text-secondary);">${escapeHtml(f.recommendation || f.description || '')}</p>
              </td>
            </tr>
          `;
        });
      } else {
        rawOrigins.forEach(origin => {
          html += `
            <tr>
              <td>
                <div style="font-weight: 700; color: var(--text-primary);">${escapeHtml(origin)}</div>
                <div class="text-xs text-muted">Observed External Host</div>
              </td>
              <td>
                <code style="font-size: 0.75rem; background: var(--bg-surface); padding: 4px 8px; border-radius: 4px; display: block;">
                  https://${escapeHtml(origin)}/*
                </code>
              </td>
              <td>
                <p class="text-xs" style="color: var(--text-secondary);">External asset loaded. Ensure integrity attributes (SRI) and caching are configured.</p>
              </td>
            </tr>
          `;
        });
      }

      html += `</tbody></table></div>`;
    }

    html += `</div>`;
    container.innerHTML = html;
    renderIcons(container);
  } catch (err) {
    container.innerHTML = `<div class="empty-state"><p class="text-danger">Failed to load dependencies: ${escapeHtml(err.message)}</p></div>`;
  }
}
