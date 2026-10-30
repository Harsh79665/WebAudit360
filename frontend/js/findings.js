/**
 * WebAudit 360 — Findings & Issue Lifecycle Manager
 * Creator: Harsh Patel
 */

import { apiClient } from "./api.js";
import { formatDate, escapeHtml, showToast, getSeverityDetails } from "./utils.js";
import { renderIcons } from "./icons.js";

export async function initFindingsManager() {
  const filterCategory = document.getElementById("filter-category");
  const filterSeverity = document.getElementById("filter-severity");
  const filterStatus = document.getElementById("filter-status");

  [filterCategory, filterSeverity, filterStatus].forEach(el => {
    if (el) {
      el.addEventListener("change", () => loadFindings());
    }
  });

  await loadFindings();
}

export async function loadFindings() {
  const container = document.getElementById("findings-table-body");
  const countEl = document.getElementById("findings-count");
  if (!container) return;

  const catVal = document.getElementById("filter-category")?.value || "";
  const sevVal = document.getElementById("filter-severity")?.value || "";
  const statVal = document.getElementById("filter-status")?.value || "";

  let query = "/findings?limit=50";
  if (catVal) query += `&category=${encodeURIComponent(catVal)}`;
  if (sevVal) query += `&severity=${encodeURIComponent(sevVal)}`;
  if (statVal) query += `&status=${encodeURIComponent(statVal)}`;

  try {
    const data = await apiClient.get(query).catch(() => ({ items: [], total: 0 }));
    const findings = data.items || [];

    if (countEl) countEl.textContent = `${data.total || findings.length} issues`;

    if (findings.length === 0) {
      container.innerHTML = `
        <tr>
          <td colspan="6" style="text-align:center; padding:var(--space-2xl);">
            <div class="empty-state">
              <div class="empty-state-icon"><span data-icon="checkCircle"></span></div>
              <h3 class="empty-state-title">No Findings Matching Filters</h3>
              <p class="empty-state-desc">All evaluated rules are either passing or no scans matching the selected criteria have been run.</p>
            </div>
          </td>
        </tr>
      `;
      renderIcons(container);
      return;
    }

    let rowsHtml = "";
    findings.forEach((f) => {
      const sev = getSeverityDetails(f.severity);
      rowsHtml += `
        <tr>
          <td>
            <span class="badge ${sev.class}">${escapeHtml(f.severity)}</span>
          </td>
          <td>
            <div style="font-weight:600; color:var(--text-primary); margin-bottom:2px;">
              ${escapeHtml(f.title)}
            </div>
            <div class="text-xs text-muted">Rule: ${escapeHtml(f.rule_id || 'N/A')}</div>
          </td>
          <td>
            <span class="badge">${escapeHtml(f.category)}</span>
          </td>
          <td>
            <select class="form-select text-xs" style="padding:4px 8px; border-radius:12px;" onchange="window.updateFindingStatus(${f.id}, this.value)">
              <option value="OPEN" ${f.status === 'OPEN' ? 'selected' : ''}>OPEN</option>
              <option value="ACKNOWLEDGED" ${f.status === 'ACKNOWLEDGED' ? 'selected' : ''}>ACKNOWLEDGED</option>
              <option value="FIXED" ${f.status === 'FIXED' ? 'selected' : ''}>FIXED</option>
              <option value="ACCEPTED_RISK" ${f.status === 'ACCEPTED_RISK' ? 'selected' : ''}>ACCEPTED RISK</option>
            </select>
          </td>
          <td>${formatDate(f.created_at)}</td>
          <td>
            <button class="btn btn-secondary btn-sm" onclick="window.retestFinding(${f.id})" title="Queue Automated Retest">
              <span data-icon="refreshCw"></span> Retest
            </button>
          </td>
        </tr>
      `;
    });

    container.innerHTML = rowsHtml;
    renderIcons(container);
  } catch (err) {
    showToast("Error loading findings: " + err.message, "error");
  }
}

window.updateFindingStatus = async function(findingId, newStatus) {
  try {
    await apiClient.put(`/findings/${findingId}/status`, { status: newStatus });
    showToast(`Finding status updated to ${newStatus}`, "success");
  } catch (err) {
    showToast(err.message || "Failed to update finding status", "error");
    await loadFindings();
  }
};

window.retestFinding = async function(findingId) {
  try {
    const res = await apiClient.post(`/findings/${findingId}/retest`);
    showToast(res.message || "Retest triggered successfully!", "success");
  } catch (err) {
    showToast(err.message || "Retest could not be scheduled", "error");
  }
};
