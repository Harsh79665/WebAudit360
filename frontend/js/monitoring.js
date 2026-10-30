/**
 * WebAudit 360 — Continuous Monitoring & Recurring Schedules Manager
 * Creator: Harsh Patel
 */

import { apiClient } from "./api.js";
import { escapeHtml, formatDate, showToast } from "./utils.js";
import { renderIcons } from "./icons.js";

export async function initMonitoringView() {
  const form = document.getElementById("create-schedule-form");
  if (form) {
    form.addEventListener("submit", handleCreateSchedule);
  }

  await loadSchedules();
}

export async function loadSchedules() {
  const container = document.getElementById("schedules-container");
  if (!container) return;

  try {
    const data = await apiClient.get("/monitoring").catch(() => ({ items: [], total: 0 }));
    const schedules = data.items || [];

    if (schedules.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon"><span data-icon="activity"></span></div>
          <h3 class="empty-state-title">No Recurring Monitoring Schedules Active</h3>
          <p class="empty-state-desc">
            Configure automated daily, weekly, or monthly audits to monitor Core Web Vitals regressions, SSL certificate expirations, and new vulnerabilities.
          </p>
        </div>
      `;
      renderIcons(container);
      return;
    }

    let html = `
      <div class="data-table-container">
        <table class="data-table">
          <thead>
            <tr>
              <th>Target Domain / Project</th>
              <th>Frequency</th>
              <th>Profile</th>
              <th>Next Run Time</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
    `;

    schedules.forEach(s => {
      html += `
        <tr>
          <td><strong>${escapeHtml(s.target_url || 'Project ' + s.project_id)}</strong></td>
          <td><span class="badge">${escapeHtml(s.frequency)}</span></td>
          <td>${escapeHtml(s.device_profile)}</td>
          <td>${s.next_run_at ? formatDate(s.next_run_at) : 'Scheduled'}</td>
          <td><span class="badge" style="background:var(--accent-glow); color:var(--accent-primary);">${s.is_active ? 'ACTIVE' : 'PAUSED'}</span></td>
          <td>
            <button class="btn btn-danger btn-sm" onclick="window.deleteSchedule(${s.id})" title="Delete Schedule">
              <span data-icon="trash"></span>
            </button>
          </td>
        </tr>
      `;
    });

    html += `</tbody></table></div>`;
    container.innerHTML = html;
    renderIcons(container);
  } catch (err) {
    container.innerHTML = `<div class="empty-state"><p class="text-danger">Failed to load monitoring schedules: ${escapeHtml(err.message)}</p></div>`;
  }
}

async function handleCreateSchedule(e) {
  e.preventDefault();
  const form = e.target;
  const targetUrl = form.target_url.value.trim();
  const frequency = form.frequency.value;
  const deviceProfile = form.device_profile ? form.device_profile.value : "DESKTOP";

  if (!targetUrl) {
    showToast("Target URL is required", "warning");
    return;
  }

  try {
    await apiClient.post("/monitoring", {
      target_url: targetUrl,
      frequency: frequency,
      device_profile: deviceProfile,
      modules: ["performance", "seo", "security_passive", "technology", "domain"]
    });
    showToast("Monitoring schedule created successfully!", "success");
    form.reset();
    await loadSchedules();
  } catch (err) {
    showToast(err.message || "Failed to create schedule", "error");
  }
}

window.deleteSchedule = async function(scheduleId) {
  if (!confirm("Are you sure you want to cancel this recurring schedule?")) return;
  try {
    await apiClient.delete(`/monitoring/${scheduleId}`);
    showToast("Schedule removed successfully.", "success");
    await loadSchedules();
  } catch (err) {
    showToast(err.message || "Failed to delete schedule", "error");
  }
};

