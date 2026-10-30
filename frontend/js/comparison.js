/**
 * WebAudit 360 — Audit Comparison & Benchmark Engine
 * Creator: Harsh Patel
 */

import { apiClient } from "./api.js";
import { escapeHtml, formatDate, getScoreDetails } from "./utils.js";
import { renderIcons } from "./icons.js";

export async function initComparisonView() {
  const form = document.getElementById("compare-audits-form");
  if (form) {
    form.addEventListener("submit", handleRunComparison);
  }

  await populateComparisonSelectors();
}

async function populateComparisonSelectors() {
  const selectA = document.getElementById("select-audit-a");
  const selectB = document.getElementById("select-audit-b");
  if (!selectA || !selectB) return;

  try {
    const data = await apiClient.get("/audits?limit=20").catch(() => ({ items: [] }));
    const audits = data.items || [];

    if (audits.length < 2) {
      selectA.innerHTML = `<option value="">Need at least 2 audits to compare</option>`;
      selectB.innerHTML = `<option value="">Need at least 2 audits to compare</option>`;
      return;
    }

    const optionsA = audits.map((a, i) => `
      <option value="${a.id}" ${i === 0 ? 'selected' : ''}>${escapeHtml(a.target_url)} (${a.device_profile}) - ${formatDate(a.created_at)}</option>
    `).join("");

    const optionsB = audits.map((a, i) => `
      <option value="${a.id}" ${i === 1 ? 'selected' : ''}>${escapeHtml(a.target_url)} (${a.device_profile}) - ${formatDate(a.created_at)}</option>
    `).join("");

    selectA.innerHTML = optionsA;
    selectB.innerHTML = optionsB;

    await executeComparison(audits[0].id, audits[1].id);
  } catch (e) {
    console.warn("Failed to populate comparison audits:", e);
  }
}

async function handleRunComparison(e) {
  e.preventDefault();
  const selectA = document.getElementById("select-audit-a");
  const selectB = document.getElementById("select-audit-b");
  if (!selectA || !selectB) return;
  await executeComparison(selectA.value, selectB.value);
}

export async function executeComparison(idA, idB) {
  const container = document.getElementById("comparison-results-container");
  if (!container || !idA || !idB) return;

  try {
    const [auditA, auditB] = await Promise.all([
      apiClient.get(`/audits/${idA}`),
      apiClient.get(`/audits/${idB}`)
    ]);

    const scoreA = auditA.overall_score !== null ? Math.round(auditA.overall_score) : null;
    const scoreB = auditB.overall_score !== null ? Math.round(auditB.overall_score) : null;
    const delta = (scoreA !== null && scoreB !== null) ? (scoreB - scoreA) : null;

    let deltaHtml = "";
    if (delta !== null) {
      if (delta > 0) {
        deltaHtml = `<span class="badge" style="background:#10B981; color:#fff; font-weight:700;">+${delta} pts Improved</span>`;
      } else if (delta < 0) {
        deltaHtml = `<span class="badge" style="background:#EF4444; color:#fff; font-weight:700;">${delta} pts Regressed</span>`;
      } else {
        deltaHtml = `<span class="badge">0 pts No Change</span>`;
      }
    }

    let html = `
      <div class="grid grid-2" style="gap: var(--space-xl); margin-bottom: var(--space-xl);">
        <!-- Audit A Card -->
        <div class="card glass-panel" style="padding: var(--space-xl);">
          <div class="text-xs text-muted" style="text-transform: uppercase;">Baseline Audit A</div>
          <h3 style="font-size: 1.25rem; font-weight: 700; margin: 4px 0 12px; word-break: break-all;">
            ${escapeHtml(auditA.target_url)}
          </h3>
          <div class="flex items-center gap-md" style="margin-bottom: var(--space-md);">
            <div style="font-size: 2.5rem; font-weight: 800; color: var(--accent-primary);">
              ${scoreA !== null ? scoreA : 'N/A'}
            </div>
            <div>
              <div>${escapeHtml(auditA.scan_mode)} &bull; ${escapeHtml(auditA.device_profile)}</div>
              <div class="text-xs text-muted">${formatDate(auditA.created_at)}</div>
            </div>
          </div>
        </div>

        <!-- Audit B Card -->
        <div class="card glass-panel" style="padding: var(--space-xl);">
          <div class="text-xs text-muted" style="text-transform: uppercase;">Comparison Target B</div>
          <h3 style="font-size: 1.25rem; font-weight: 700; margin: 4px 0 12px; word-break: break-all;">
            ${escapeHtml(auditB.target_url)}
          </h3>
          <div class="flex items-center gap-md" style="margin-bottom: var(--space-md);">
            <div style="font-size: 2.5rem; font-weight: 800; color: var(--accent-cyan);">
              ${scoreB !== null ? scoreB : 'N/A'}
            </div>
            <div>
              <div>${escapeHtml(auditB.scan_mode)} &bull; ${escapeHtml(auditB.device_profile)}</div>
              <div class="text-xs text-muted">${formatDate(auditB.created_at)}</div>
            </div>
          </div>
          <div style="margin-top: 4px;">${deltaHtml}</div>
        </div>
      </div>

      <!-- Categories Delta Table -->
      <div class="glass-panel" style="padding: var(--space-xl);">
        <h3 style="font-size: 1.25rem; font-weight: 700; margin-bottom: var(--space-md);">Category Score Comparison</h3>
        <div class="data-table-container">
          <table class="data-table">
            <thead>
              <tr>
                <th>Audit Category</th>
                <th>Audit A Score</th>
                <th>Audit B Score</th>
                <th>Variance (Delta)</th>
              </tr>
            </thead>
            <tbody>
    `;

    const allCategories = ["PERFORMANCE", "SEO", "ACCESSIBILITY", "SECURITY_PASSIVE", "TECHNICAL", "DOMAIN"];
    allCategories.forEach(cat => {
      const valA = auditA.category_scores ? auditA.category_scores[cat] : null;
      const valB = auditB.category_scores ? auditB.category_scores[cat] : null;
      let varStr = "N/A";
      if (valA !== null && valA !== undefined && valB !== null && valB !== undefined) {
        const diff = Math.round(valB - valA);
        varStr = diff > 0 ? `+${diff}` : `${diff}`;
      }

      html += `
        <tr>
          <td><strong>${cat.replace('_', ' ')}</strong></td>
          <td>${valA !== null && valA !== undefined ? Math.round(valA) : 'N/A'}</td>
          <td>${valB !== null && valB !== undefined ? Math.round(valB) : 'N/A'}</td>
          <td><span class="badge">${varStr}</span></td>
        </tr>
      `;
    });

    html += `</tbody></table></div></div>`;
    container.innerHTML = html;
    renderIcons(container);
  } catch (err) {
    container.innerHTML = `<div class="empty-state"><p class="text-danger">Failed to execute comparison: ${escapeHtml(err.message)}</p></div>`;
  }
}
