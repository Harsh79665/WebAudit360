/**
 * WebAudit 360 — Dashboard Module
 * Creator: Harsh Patel
 */

import { apiClient } from "./api.js";
import { getScoreDetails, formatDate, escapeHtml, showToast } from "./utils.js";
import { renderIcons } from "./icons.js";

export async function initDashboard() {
  const refreshBtn = document.getElementById("refresh-dashboard-btn");
  if (refreshBtn) {
    refreshBtn.addEventListener("click", () => loadDashboardData());
  }

  await loadDashboardData();
}

export async function loadDashboardData() {
  const container = document.getElementById("audits-container");
  const projEl = document.getElementById("metric-projects-count");
  const auditEl = document.getElementById("metric-audits-count");
  const issueEl = document.getElementById("metric-issues-count");
  const critEl = document.getElementById("metric-critical-count");

  try {
    const [auditsData, projectsData, findingsData] = await Promise.all([
      apiClient.get("/audits").catch(() => ({ items: [], total: 0 })),
      apiClient.get("/projects").catch(() => ({ items: [], total: 0 })),
      apiClient.get("/findings?status=OPEN").catch(() => ({ items: [], total: 0 }))
    ]);

    const audits = (auditsData.items || []).filter(a => !a.target_url.includes("example.com"));
    const projects = projectsData.items || [];
    const findings = findingsData.items || [];

    if (projEl) projEl.textContent = projects.length || "0";
    if (auditEl) auditEl.textContent = audits.length || "0";
    if (issueEl) issueEl.textContent = findings.length || "0";
    if (critEl) {
      const criticalCount = findings.filter(f => f.severity === "CRITICAL").length;
      critEl.textContent = criticalCount;
    }

    if (!container) return;

    if (audits.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon"><span data-icon="gauge"></span></div>
          <h3 class="empty-state-title">No Audits Performed Yet</h3>
          <p class="empty-state-desc">
            Submit your first website URL to measure performance, test accessibility, inspect SEO metadata, and evaluate security headers.
          </p>
          <a href="new-audit.html" class="btn btn-primary">
            <span data-icon="zap"></span>
            <span>Launch First Audit</span>
          </a>
        </div>
      `;
      renderIcons(container);
      return;
    }

    let tableHtml = `
      <div class="data-table-container">
        <table class="data-table">
          <thead>
            <tr>
              <th>Target Website</th>
              <th>Mode & Device</th>
              <th>Overall Score</th>
              <th>Status</th>
              <th>Scanned Date</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
    `;

    const urlParams = new URLSearchParams(window.location.search);
    const requestedId = parseInt(urlParams.get("id"), 10);

    audits.forEach((audit) => {
      const scoreObj = getScoreDetails(audit.overall_score);
      const isHighlight = requestedId && audit.id === requestedId;
      tableHtml += `
        <tr style="${isHighlight ? 'background: var(--accent-glow, rgba(6, 182, 212, 0.12));' : ''}">
          <td>
            <div class="table-target-cell">
              <span data-icon="globe"></span>
              <a href="audit-report.html?id=${audit.id}" class="table-target-url" title="${escapeHtml(audit.target_url)}">
                ${escapeHtml(audit.target_url)}
              </a>
            </div>
          </td>
          <td>${escapeHtml(audit.scan_mode)} &bull; ${escapeHtml(audit.device_profile)}</td>
          <td>
            <span class="score-pill ${scoreObj.class}">
              ${audit.overall_score !== null ? Math.round(audit.overall_score) : 'N/A'} - ${scoreObj.label}
            </span>
          </td>
          <td><span class="badge">${escapeHtml(audit.status)}</span></td>
          <td>${formatDate(audit.created_at)}</td>
          <td>
            <a href="audit-report.html?id=${audit.id}" class="btn btn-secondary btn-sm">View Report</a>
          </td>
        </tr>
      `;
    });

    tableHtml += `
          </tbody>
        </table>
      </div>
    `;

    container.innerHTML = tableHtml;
    renderIcons(container);
  } catch (err) {
    console.warn("Failed to load dashboard data:", err);
  }
}

