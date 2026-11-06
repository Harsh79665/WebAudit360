/**
 * WebAudit 360 — Team Collaboration & Workspace RBAC Controller
 * Creator: Harsh Patel
 */

import { apiClient } from "./api.js";
import { auth } from "./auth.js";
import { escapeHtml, formatDate, showToast } from "./utils.js";
import { renderIcons } from "./icons.js";

export async function initTeamView() {
  const inviteForm = document.getElementById("invite-member-form");
  if (inviteForm) {
    inviteForm.addEventListener("submit", handleInviteMember);
  }

  // Expose global actions for inline table event binding
  window.handleRoleChange = handleRoleChange;
  window.handleRemoveMember = handleRemoveMember;
  window.copyInvitePassword = copyInvitePassword;

  await loadTeamMembers();
}

export async function loadTeamMembers() {
  const tbody = document.getElementById("team-members-tbody");
  if (!tbody) return;

  try {
    tbody.innerHTML = `
      <tr>
        <td colspan="5" class="text-center text-muted" style="padding: var(--space-xl);">
          <span data-icon="refreshCw" class="spin"></span> Loading workspace members...
        </td>
      </tr>
    `;
    renderIcons(tbody);

    const data = await apiClient.get("/team").catch(() => ({ items: [], total: 0 }));
    const members = data.items || [];

    if (members.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="5" class="text-center text-muted" style="padding: var(--space-xl);">
            No workspace members found.
          </td>
        </tr>
      `;
      return;
    }

    const currentUser = auth.getUser() || {};
    const isOwnerOrAdmin = ["OWNER", "ADMIN"].includes(currentUser.role);
    const activeOwners = members.filter(m => m.role === "OWNER" && m.is_active);
    const isOwner = currentUser.role === "OWNER";

    tbody.innerHTML = members.map(m => {
      const isSelf = currentUser.id === m.id || currentUser.email === m.email;
      const isSoleOwner = m.role === "OWNER" && activeOwners.length <= 1;
      const isTargetOwner = m.role === "OWNER";
      const cannotModifyTarget = isTargetOwner && !isOwner;

      // Role selector or static badge
      let roleHtml = "";
      if (!isOwnerOrAdmin || isSoleOwner || cannotModifyTarget) {
        const badgeColor = m.role === "OWNER" ? "background:var(--accent-glow); color:var(--accent-primary); font-weight:700;" : "";
        roleHtml = `<span class="badge" style="${badgeColor}">${m.role}</span>`;
      } else {
        roleHtml = `
          <select class="form-select form-select-sm" style="max-width: 160px; font-size: 0.8rem;" onchange="window.handleRoleChange(${m.id}, this.value)">
            ${currentUser.role === "OWNER" ? `<option value="OWNER" ${m.role === "OWNER" ? "selected" : ""}>OWNER</option>` : ""}
            <option value="ADMIN" ${m.role === "ADMIN" ? "selected" : ""}>ADMIN</option>
            <option value="DEVELOPER" ${m.role === "DEVELOPER" ? "selected" : ""}>DEVELOPER</option>
            <option value="VIEWER" ${m.role === "VIEWER" ? "selected" : ""}>VIEWER</option>
          </select>
        `;
      }

      // Actions column
      let actionHtml = "";
      if (isSelf) {
        actionHtml = `<span class="text-xs text-muted">Current User</span>`;
      } else if (isSoleOwner) {
        actionHtml = `<span class="text-xs text-muted">Primary Owner</span>`;
      } else if (cannotModifyTarget) {
        actionHtml = `<span class="text-xs text-muted">Protected Owner</span>`;
      } else if (isOwnerOrAdmin && m.is_active) {
        actionHtml = `
          <button class="btn btn-danger btn-sm" onclick="window.handleRemoveMember(${m.id}, '${escapeHtml(m.email)}')" title="Revoke access">
            <span data-icon="trash"></span> Remove
          </button>
        `;
      } else {
        actionHtml = `<span class="text-xs text-muted">—</span>`;
      }

      return `
        <tr data-member-id="${m.id}" style="${!m.is_active ? 'opacity: 0.55;' : ''}">
          <td>
            <div style="font-weight: 700; color: var(--text-primary);">${escapeHtml(m.full_name || "Team Member")}</div>
            <div class="text-xs text-muted">Joined ${formatDate(m.created_at)}</div>
          </td>
          <td><code>${escapeHtml(m.email)}</code></td>
          <td>${roleHtml}</td>
          <td>
            <span class="badge ${m.is_active ? 'score-good' : 'score-poor'}">
              ${m.is_active ? 'ACTIVE' : 'DEACTIVATED'}
            </span>
          </td>
          <td>${actionHtml}</td>
        </tr>
      `;
    }).join("");

    renderIcons(tbody);
  } catch (err) {
    tbody.innerHTML = `
      <tr>
        <td colspan="5" class="text-center text-danger" style="padding: var(--space-xl);">
          Failed to load team members: ${escapeHtml(err.message)}
        </td>
      </tr>
    `;
  }
}

export async function handleInviteMember(e) {
  e.preventDefault();
  const form = e.target;
  const emailInput = document.getElementById("invite-email");
  const nameInput = document.getElementById("invite-name");
  const roleSelect = document.getElementById("invite-role");
  const submitBtn = document.getElementById("invite-submit-btn");
  const resultContainer = document.getElementById("invite-result-container");

  const email = emailInput?.value.trim();
  const fullName = nameInput?.value.trim() || undefined;
  const role = roleSelect?.value || "DEVELOPER";

  if (!email) {
    showToast("Email address required", "", "error");
    return;
  }

  try {
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.innerHTML = `<span data-icon="refreshCw" class="spin"></span> Sending Invite...`;
      renderIcons(submitBtn);
    }

    const res = await apiClient.post("/team/invite", {
      email,
      full_name: fullName,
      role
    });

    showToast("Invitation Created", `Invited ${res.email} as ${res.role}`, "success");
    form.reset();

    // Display temporary password banner if returned
    if (res.initial_password && resultContainer) {
      resultContainer.style.display = "block";
      resultContainer.innerHTML = `
        <div class="card glass-panel" style="border: 1px solid var(--accent-primary); background: var(--accent-glow); padding: var(--space-md); margin-top: var(--space-md);">
          <div class="flex items-center justify-between" style="flex-wrap: wrap; gap: var(--space-sm);">
            <div>
              <div style="font-weight: 700; color: var(--text-primary); font-size: 0.95rem;">
                Temporary Credentials Generated for <code>${escapeHtml(res.email)}</code>
              </div>
              <p class="text-xs text-muted" style="margin-top: 2px;">
                Share this initial password with your team member. It will not be shown again.
              </p>
            </div>
            <div class="flex items-center gap-xs">
              <input type="text" id="generated-password-field" value="${escapeHtml(res.initial_password)}" readonly class="form-input" style="font-family: monospace; font-size: 0.85rem; max-width: 220px;" />
              <button class="btn btn-secondary btn-sm" onclick="window.copyInvitePassword()">
                <span data-icon="copy"></span> Copy
              </button>
            </div>
          </div>
        </div>
      `;
      renderIcons(resultContainer);
    }

    await loadTeamMembers();
  } catch (err) {
    showToast("Invitation Failed", err.message, "error");
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerHTML = `<span data-icon="plus"></span> Send Invitation`;
      renderIcons(submitBtn);
    }
  }
}

export async function handleRoleChange(memberId, newRole) {
  try {
    const res = await apiClient.request(`/team/members/${memberId}/role`, {
      method: "PATCH",
      body: JSON.stringify({ role: newRole })
    });

    showToast("Role Updated", `Role updated to ${res.role} for ${res.email}`, "success");
    await loadTeamMembers();
  } catch (err) {
    showToast("Role Update Failed", err.message, "error");
    await loadTeamMembers(); // Revert select value in UI
  }
}

export async function handleRemoveMember(memberId, memberEmail) {
  const confirmed = window.confirm(
    `Are you sure you want to remove team member ${memberEmail} from the workspace?\nThey will immediately lose access to all projects and audit runs.`
  );
  if (!confirmed) return;

  try {
    await apiClient.delete(`/team/members/${memberId}`);
    showToast("Member Removed", `${memberEmail} has been removed.`, "info");
    await loadTeamMembers();
  } catch (err) {
    showToast("Removal Failed", err.message, "error");
  }
}

export function copyInvitePassword() {
  const input = document.getElementById("generated-password-field");
  if (!input) return;
  input.select();
  navigator.clipboard.writeText(input.value).then(() => {
    showToast("Copied to Clipboard", "Password copied successfully.", "success");
  }).catch(() => {
    showToast("Copy Failed", "Please manually copy the password.", "warning");
  });
}
