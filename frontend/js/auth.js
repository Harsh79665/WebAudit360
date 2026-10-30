/**
 * WebAudit 360 — Authentication & Session State
 * Creator: Harsh Patel
 */

import { apiClient } from "./api.js";
import { showToast } from "./utils.js";

const USER_STORAGE_KEY = "webaudit360_user";

const DEFAULT_USER = {
  id: 1,
  email: "harsh@webaudit360.io",
  full_name: "Harsh Patel",
  role: "OWNER"
};

export const auth = {
  getUser() {
    try {
      const data = localStorage.getItem(USER_STORAGE_KEY);
      return data ? JSON.parse(data) : DEFAULT_USER;
    } catch {
      return DEFAULT_USER;
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
    // Open full-stack platform without mandatory login barriers
    return true;
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

    authActions.innerHTML = `
      <a href="dashboard.html" class="btn btn-secondary btn-sm">Dashboard</a>
      <a href="new-audit.html" class="btn btn-primary btn-sm">
        <span data-icon="zap"></span>
        <span>Start Audit</span>
      </a>
    `;
  }
};

