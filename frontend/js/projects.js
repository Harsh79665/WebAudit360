/**
 * WebAudit 360 — Projects & Domain Ownership Management
 * Creator: Harsh Patel
 */

import { apiClient } from "./api.js";
import { formatDate, escapeHtml, showToast } from "./utils.js";
import { renderIcons } from "./icons.js";

export async function initProjects() {
  const newProjectForm = document.getElementById("create-project-form");
  if (newProjectForm) {
    newProjectForm.addEventListener("submit", handleCreateProject);
  }

  await loadProjectsList();
}

export async function loadProjectsList() {
  const container = document.getElementById("projects-container");
  if (!container) return;

  try {
    const data = await apiClient.get("/projects").catch(() => ({ items: [], total: 0 }));
    const projects = data.items || [];

    if (projects.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon"><span data-icon="layers"></span></div>
          <h3 class="empty-state-title">No Projects Created Yet</h3>
          <p class="empty-state-desc">
            Projects group your domains, audits, and security authorization challenges into manageable spaces.
          </p>
          <button class="btn btn-primary" onclick="document.getElementById('create-project-modal').showModal()">
            <span data-icon="plus"></span>
            <span>Create Your First Project</span>
          </button>
        </div>
      `;
      renderIcons(container);
      return;
    }

    let html = `
      <div class="grid grid-3" style="gap: var(--space-lg);">
    `;

    projects.forEach((proj) => {
      html += `
        <div class="card glass-panel" style="display:flex; flex-direction:column; justify-content:space-between; padding:var(--space-lg);">
          <div>
            <div class="flex items-center justify-between" style="margin-bottom:var(--space-sm);">
              <h3 style="font-size:1.15rem; font-weight:700;">${escapeHtml(proj.name)}</h3>
              <span class="badge">Active</span>
            </div>
            <p class="text-muted text-sm" style="margin-bottom:var(--space-md);">${escapeHtml(proj.domain || 'No domain attached')}</p>
            <p class="text-sm" style="color:var(--text-secondary); margin-bottom:var(--space-lg);">${escapeHtml(proj.description || 'No description provided.')}</p>
          </div>
          <div class="flex items-center justify-between" style="border-top:1px solid var(--border-color); padding-top:var(--space-md);">
            <span class="text-xs text-muted">Created ${formatDate(proj.created_at)}</span>
            <div class="flex gap-xs">
              <a href="new-audit.html?target=${encodeURIComponent('https://' + (proj.domain || ''))}" class="btn btn-secondary btn-sm" title="Scan Domain">
                <span data-icon="zap"></span>
              </a>
              <button class="btn btn-danger btn-sm" onclick="window.deleteProject(${proj.id})" title="Delete Project">
                <span data-icon="trash"></span>
              </button>
            </div>
          </div>
        </div>
      `;
    });

    html += `</div>`;
    container.innerHTML = html;
    renderIcons(container);
  } catch (err) {
    showToast("Failed to load projects list: " + err.message, "error");
  }
}

async function handleCreateProject(e) {
  e.preventDefault();
  const form = e.target;
  const name = form.name.value.trim();
  const domain = form.domain.value.trim().replace(/^https?:\/\//i, "").split("/")[0];
  const description = form.description ? form.description.value.trim() : "";

  if (!name) {
    showToast("Project name is required", "warning");
    return;
  }

  try {
    await apiClient.post("/projects", { name, domain, description });
    showToast("Project created successfully!", "success");
    form.reset();
    const modal = document.getElementById("create-project-modal");
    if (modal) modal.close();
    await loadProjectsList();
  } catch (err) {
    showToast(err.message || "Failed to create project", "error");
  }
}

window.deleteProject = async function(projectId) {
  if (!confirm("Are you sure you want to delete this project? This will remove associated audit records.")) {
    return;
  }

  try {
    await apiClient.delete(`/projects/${projectId}`);
    showToast("Project deleted successfully.", "success");
    await loadProjectsList();
  } catch (err) {
    showToast(err.message || "Failed to delete project", "error");
  }
};

