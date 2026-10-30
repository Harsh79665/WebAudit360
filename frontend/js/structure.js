/**
 * WebAudit 360 — Website Structure Explorer
 * Creator: Harsh Patel
 */

import { apiClient } from "./api.js";
import { escapeHtml, formatDate } from "./utils.js";
import { renderIcons } from "./icons.js";

export async function initStructureView() {
  const auditSelect = document.getElementById("select-audit-target");
  if (auditSelect) {
    auditSelect.addEventListener("change", (e) => loadStructureData(e.target.value));
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

    await loadStructureData(audits[0].id);
  } catch (e) {
    console.warn("Failed to load audits for Structure Explorer:", e);
  }
}

export async function loadStructureData(auditId) {
  if (!auditId) return;
  const container = document.getElementById("structure-details-container");
  if (!container) return;

  try {
    const audit = await apiClient.get(`/audits/${auditId}`);
    const pages = audit.pages || [];

    let html = `
      <div class="grid grid-3" style="gap: var(--space-md); margin-bottom: var(--space-xl);">
        <div class="card glass-panel" style="padding: var(--space-lg); text-align: center;">
          <div class="text-xs text-muted" style="text-transform: uppercase;">Discovered URLs</div>
          <div style="font-size: 2.25rem; font-weight: 800; margin: 4px 0; color: var(--accent-primary);">
            ${pages.length || 1}
          </div>
          <span class="badge">Internal Tree</span>
        </div>

        <div class="card glass-panel" style="padding: var(--space-lg);">
          <div class="text-xs text-muted" style="text-transform: uppercase; margin-bottom: 6px;">Crawl Coverage</div>
          <div style="font-weight: 700; font-size: 1.05rem; color: var(--accent-cyan);">
            Single-Origin Boundary Enforced
          </div>
          <p class="text-xs text-muted" style="margin-top: 6px;">
            Crawler only traverses allowed host paths and respects robots directives and cycle limits.
          </p>
        </div>

        <div class="card glass-panel" style="padding: var(--space-lg);">
          <div class="text-xs text-muted" style="text-transform: uppercase; margin-bottom: 6px;">Orphan Detection</div>
          <div style="font-weight: 700; font-size: 1.05rem; color: var(--accent-green);">
            Active Splay & Link Tracking
          </div>
          <p class="text-xs text-muted" style="margin-top: 6px;">
            Identifies pages discovered via sitemaps lacking incoming in-body navigation links.
          </p>
        </div>
      </div>

      <div class="glass-panel" style="padding: var(--space-xl); margin-bottom: var(--space-xl);">
        <h3 style="font-size: 1.25rem; font-weight: 700; margin-bottom: var(--space-md);">Discovered Internal Pages & Crawl Hierarchy</h3>
    `;

    if (pages.length === 0) {
      html += `
        <div class="data-table-container">
          <table class="data-table">
            <thead>
              <tr>
                <th>Page URL</th>
                <th>Crawl Depth</th>
                <th>HTTP Status</th>
                <th>Score</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>
                  <div class="table-target-cell">
                    <span data-icon="globe"></span>
                    <span style="font-weight:600;">${escapeHtml(audit.target_url)}</span>
                  </div>
                </td>
                <td><span class="badge">Depth 0 (Root)</span></td>
                <td><span class="badge" style="background:var(--accent-glow); color:var(--accent-primary);">200 OK</span></td>
                <td>${audit.overall_score !== null ? Math.round(audit.overall_score) : 'N/A'}</td>
              </tr>
            </tbody>
          </table>
        </div>
      `;
    } else {
      html += `
        <div class="data-table-container">
          <table class="data-table">
            <thead>
              <tr>
                <th>Page URL</th>
                <th>Crawl Depth</th>
                <th>HTTP Status</th>
                <th>Page Score</th>
              </tr>
            </thead>
            <tbody>
      `;
      pages.forEach(p => {
        html += `
          <tr>
            <td>
              <div class="table-target-cell">
                <span data-icon="fileText"></span>
                <span style="font-weight:600;">${escapeHtml(p.url)}</span>
              </div>
            </td>
            <td><span class="badge">Depth ${p.depth || 0}</span></td>
            <td><span class="badge">${p.http_status || 200}</span></td>
            <td>${p.page_score !== null && p.page_score !== undefined ? Math.round(p.page_score) : 'N/A'}</td>
          </tr>
        `;
      });
      html += `</tbody></table></div>`;
    }

    html += `</div>`;
    container.innerHTML = html;
    renderIcons(container);
  } catch (err) {
    container.innerHTML = `<div class="empty-state"><p class="text-danger">Failed to load website structure: ${escapeHtml(err.message)}</p></div>`;
  }
}
