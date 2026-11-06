/**
 * WebAudit 360 — Audit Comparison & Benchmark Engine
 * Creator: Harsh Patel
 */

import { apiClient } from "./api.js";
import { escapeHtml, formatDate, getScoreDetails } from "./utils.js";
import { renderIcons } from "./icons.js";

export async function initComparisonView() {
  // Tab toggling
  const tabLive = document.getElementById("tab-live-urls");
  const tabStored = document.getElementById("tab-stored-audits");
  const livePanel = document.getElementById("live-url-panel");
  const storedPanel = document.getElementById("stored-audits-panel");

  if (tabLive && tabStored) {
    tabLive.addEventListener("click", () => {
      tabLive.className = "btn btn-primary btn-sm";
      tabStored.className = "btn btn-secondary btn-sm";
      livePanel.style.display = "block";
      storedPanel.style.display = "none";
    });

    tabStored.addEventListener("click", () => {
      tabStored.className = "btn btn-primary btn-sm";
      tabLive.className = "btn btn-secondary btn-sm";
      storedPanel.style.display = "block";
      livePanel.style.display = "none";
    });
  }

  // Live URL benchmark form
  const liveForm = document.getElementById("compare-urls-form");
  if (liveForm) {
    liveForm.addEventListener("submit", handleRunLiveComparison);
  }

  // Stored audits form
  const storedForm = document.getElementById("compare-audits-form");
  if (storedForm) {
    storedForm.addEventListener("submit", handleRunComparison);
  }

  await populateComparisonSelectors();
}

async function handleRunLiveComparison(e) {
  e.preventDefault();
  const urlA = document.getElementById("url-a").value.trim();
  const urlB = document.getElementById("url-b").value.trim();
  const container = document.getElementById("comparison-results-container");
  const btn = document.getElementById("btn-run-live-comparison");

  if (!urlA || !urlB) return;

  btn.disabled = true;
  btn.innerHTML = `<span data-icon="refreshCw" class="spin"></span> Running Benchmark...`;
  renderIcons(btn);

  container.innerHTML = `
    <div class="glass-panel p-xl text-center">
      <div class="text-xl font-bold mb-sm">Executing Comparative Intelligence Audit...</div>
      <p class="text-muted text-sm">Measuring Core Web Vitals, security posture, and sustainability metrics for both targets...</p>
    </div>
  `;

  try {
    const data = await apiClient.post("/api/v1/comparisons", {
      target_url_a: urlA,
      target_url_b: urlB,
      device_profile: "BOTH",
      scan_mode: "SINGLE_PAGE"
    });
    renderLiveComparisonResults(data);
  } catch (err) {
    container.innerHTML = `<div class="empty-state"><p class="text-danger">Failed to benchmark URLs: ${escapeHtml(err.message)}</p></div>`;
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<span data-icon="zap"></span> Run Competitor Benchmark`;
    renderIcons(btn);
  }
}

function renderLiveComparisonResults(data) {
  const container = document.getElementById("comparison-results-container");
  if (!container || !data) return;

  const scoreA = Math.round(data.scores_a?.overall || 0);
  const scoreB = Math.round(data.scores_b?.overall || 0);
  const deltaOverall = data.deltas?.overall || 0;

  let deltaHtml = "";
  if (deltaOverall > 0) {
    deltaHtml = `<span class="badge" style="background:#10B981; color:#fff; font-weight:700;">+${deltaOverall} pts Site A Advantage</span>`;
  } else if (deltaOverall < 0) {
    deltaHtml = `<span class="badge" style="background:#EF4444; color:#fff; font-weight:700;">${deltaOverall} pts Site B Advantage</span>`;
  } else {
    deltaHtml = `<span class="badge">Tie Score</span>`;
  }

  // Insights list
  let insightsHtml = "";
  if (data.insights && data.insights.length > 0) {
    insightsHtml = `
      <div class="glass-panel" style="padding: var(--space-xl); margin-bottom: var(--space-xl);">
        <h3 style="font-size: 1.25rem; font-weight: 700; margin-bottom: var(--space-md);">Automated Competitive Insights</h3>
        <ul style="list-style-type: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 8px;">
          ${data.insights.map(i => `<li class="flex items-center gap-sm text-sm"><span class="badge badge-primary">INSIGHT</span> <span>${escapeHtml(i)}</span></li>`).join("")}
        </ul>
      </div>
    `;
  }

  let html = `
    <div class="grid grid-2" style="gap: var(--space-xl); margin-bottom: var(--space-xl);">
      <!-- Site A Card -->
      <div class="card glass-panel" style="padding: var(--space-xl);">
        <div class="text-xs text-muted font-bold" style="text-transform: uppercase;">Primary Site A</div>
        <h3 style="font-size: 1.25rem; font-weight: 700; margin: 4px 0 12px; word-break: break-all;">
          ${escapeHtml(data.target_url_a)}
        </h3>
        <div class="flex items-center gap-md" style="margin-bottom: var(--space-md);">
          <div style="font-size: 3rem; font-weight: 900; color: var(--accent-primary);">
            ${scoreA}
          </div>
          <div>
            <div class="font-bold text-sm">${escapeHtml(data.scores_a?.overall_label || 'Rating')}</div>
            <div class="text-xs text-muted">Winner: ${escapeHtml(data.winner)}</div>
          </div>
        </div>
      </div>

      <!-- Site B Card -->
      <div class="card glass-panel" style="padding: var(--space-xl);">
        <div class="text-xs text-muted font-bold" style="text-transform: uppercase;">Competitor Site B</div>
        <h3 style="font-size: 1.25rem; font-weight: 700; margin: 4px 0 12px; word-break: break-all;">
          ${escapeHtml(data.target_url_b)}
        </h3>
        <div class="flex items-center gap-md" style="margin-bottom: var(--space-md);">
          <div style="font-size: 3rem; font-weight: 900; color: var(--accent-cyan);">
            ${scoreB}
          </div>
          <div>
            <div class="font-bold text-sm">${escapeHtml(data.scores_b?.overall_label || 'Rating')}</div>
            <div class="text-xs text-muted">${deltaHtml}</div>
          </div>
        </div>
      </div>
    </div>

    ${insightsHtml}

    <!-- Category Delta Table -->
    <div class="glass-panel" style="padding: var(--space-xl); margin-bottom: var(--space-xl);">
      <h3 style="font-size: 1.25rem; font-weight: 700; margin-bottom: var(--space-md);">Category Score Comparison & Deltas</h3>
      <div class="data-table-container">
        <table class="data-table">
          <thead>
            <tr>
              <th>Audit Category</th>
              <th>Site A Score</th>
              <th>Site B Score</th>
              <th>Variance (Delta)</th>
            </tr>
          </thead>
          <tbody>
            ${renderCategoryRow("Performance", data.scores_a?.performance, data.scores_b?.performance, data.deltas?.performance)}
            ${renderCategoryRow("SEO", data.scores_a?.seo, data.scores_b?.seo, data.deltas?.seo)}
            ${renderCategoryRow("Accessibility", data.scores_a?.accessibility, data.scores_b?.accessibility, data.deltas?.accessibility)}
            ${renderCategoryRow("Security", data.scores_a?.security, data.scores_b?.security, data.deltas?.security)}
            ${renderCategoryRow("Technical Health", data.scores_a?.technical, data.scores_b?.technical, data.deltas?.technical)}
            ${renderCategoryRow("Carbon Footprint", data.scores_a?.carbon, data.scores_b?.carbon, data.deltas?.carbon)}
          </tbody>
        </table>
      </div>
    </div>
  `;

  container.innerHTML = html;
  renderIcons(container);
}

function renderCategoryRow(label, scoreA, scoreB, delta) {
  const sA = scoreA !== null && scoreA !== undefined ? Math.round(scoreA) : "N/A";
  const sB = scoreB !== null && scoreB !== undefined ? Math.round(scoreB) : "N/A";
  let badge = `<span class="badge">0</span>`;
  if (delta !== null && delta !== undefined) {
    if (delta > 0) {
      badge = `<span class="badge" style="background:#10B981; color:#fff;">+${delta} (Site A)</span>`;
    } else if (delta < 0) {
      badge = `<span class="badge" style="background:#EF4444; color:#fff;">${delta} (Site B)</span>`;
    }
  }

  return `
    <tr>
      <td><strong>${label}</strong></td>
      <td>${sA}</td>
      <td>${sB}</td>
      <td>${badge}</td>
    </tr>
  `;
}

async function populateComparisonSelectors() {
  const selectA = document.getElementById("select-audit-a");
  const selectB = document.getElementById("select-audit-b");
  if (!selectA || !selectB) return;

  try {
    const data = await apiClient.get("/api/v1/audits?limit=20").catch(() => ({ items: [] }));
    const audits = data.items || [];

    if (audits.length < 2) {
      selectA.innerHTML = `<option value="">Need at least 2 audits to compare</option>`;
      selectB.innerHTML = `<option value="">Need at least 2 audits to compare</option>`;
      return;
    }

    const optionsA = audits.map((a, i) => `
      <option value="${a.id}" ${i === 0 ? 'selected' : ''}>#${a.id} — ${escapeHtml(a.target_url)} (${a.device_profile})</option>
    `).join("");

    const optionsB = audits.map((a, i) => `
      <option value="${a.id}" ${i === 1 ? 'selected' : ''}>#${a.id} — ${escapeHtml(a.target_url)} (${a.device_profile})</option>
    `).join("");

    selectA.innerHTML = optionsA;
    selectB.innerHTML = optionsB;
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
    const diffData = await apiClient.get(`/api/v1/comparisons/diff?audit_a_id=${idA}&audit_b_id=${idB}`);
    const [auditA, auditB] = await Promise.all([
      apiClient.get(`/api/v1/audits/${idA}`),
      apiClient.get(`/api/v1/audits/${idB}`)
    ]);

    const compData = {
      target_url_a: auditA.target_url,
      target_url_b: auditB.target_url,
      scores_a: {
        overall: auditA.overall_score,
        overall_label: getScoreDetails(auditA.overall_score).label,
        performance: auditA.score_performance,
        seo: auditA.score_seo,
        accessibility: auditA.score_accessibility,
        security: auditA.score_security,
        technical: auditA.score_technical,
        carbon: auditA.category_scores?.CARBON_ESG
      },
      scores_b: {
        overall: auditB.overall_score,
        overall_label: getScoreDetails(auditB.overall_score).label,
        performance: auditB.score_performance,
        seo: auditB.score_seo,
        accessibility: auditB.score_accessibility,
        security: auditB.score_security,
        technical: auditB.score_technical,
        carbon: auditB.category_scores?.CARBON_ESG
      },
      deltas: diffData.deltas,
      insights: [
        diffData.deltas.overall > 0 ? `Audit #${idA} leads by +${diffData.deltas.overall} points over Audit #${idB}.` : `Audit #${idB} leads by +${Math.abs(diffData.deltas.overall)} points.`
      ],
      winner: diffData.deltas.overall >= 0 ? auditA.target_url : auditB.target_url
    };

    renderLiveComparisonResults(compData);
  } catch (err) {
    container.innerHTML = `<div class="empty-state"><p class="text-danger">Failed to diff audits: ${escapeHtml(err.message)}</p></div>`;
  }
}
