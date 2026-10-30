/**
 * WebAudit 360 — Authentication & Session State
 * Creator: Harsh Patel
 */

import { apiClient } from "./api.js";
import { showToast } from "./utils.js";

const USER_STORAGE_KEY = "webaudit360_user";

export const auth = {
  getUser() {
    try {
      const data = localStorage.getItem(USER_STORAGE_KEY);
      return data ? JSON.parse(data) : null;
    } catch {
      return null;
    }
  },

  setUser(user) {
    if (user) {
      localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(user));
    } else {
      localStorage.removeItem(USER_STORAGE_KEY);
    }
    this.updateNavAuthState();
  },

  isAuthenticated() {
    return !!apiClient.getAccessToken() && !!this.getUser();
  },

  async login(email, password) {
    const data = await apiClient.post("/auth/login", { email, password });
    apiClient.setTokens(data.access_token, data.refresh_token);
    this.setUser(data.user);
    showToast("Login Successful", `Welcome back, ${data.user.full_name || data.user.email}!`, "success");
    return data;
  },

  async register(email, password, fullName) {
    const data = await apiClient.post("/auth/register", {
      email,
      password,
      full_name: fullName
    });
    apiClient.setTokens(data.access_token, data.refresh_token);
    this.setUser(data.user);
    showToast("Registration Successful", "Your account has been created.", "success");
    return data;
  },

  async logout() {
    try {
      await apiClient.post("/auth/logout", {}).catch(() => {});
    } finally {
      apiClient.clearTokens();
      this.setUser(null);
      showToast("Logged Out", "You have been logged out safely.", "info");
      window.location.href = "index.html";
    }
  },

  updateNavAuthState() {
    const authActions = document.getElementById("nav-auth-actions");
    if (!authActions) return;

    if (this.isAuthenticated()) {
      const user = this.getUser();
      authActions.innerHTML = `
        <a href="dashboard.html" class="btn btn-secondary btn-sm">Dashboard</a>
        <button id="logout-btn" class="btn btn-outline btn-sm">Log Out</button>
      `;
      const logoutBtn = document.getElementById("logout-btn");
      if (logoutBtn) logoutBtn.addEventListener("click", () => this.logout());
    } else {
      authActions.innerHTML = `
        <a href="login.html" class="btn btn-secondary btn-sm btn-login">Sign In</a>
        <a href="new-audit.html" class="btn btn-primary btn-sm">Start Audit</a>
      `;
    }
  }
};

