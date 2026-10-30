/**
 * WebAudit 360 — Theme Manager
 * Author: Harsh Patel
 * Purpose: Classic White Default (Light) and Spatial Dark Mode.
 * Ensures zero-flash theme persistence via localStorage.
 */

const THEME_STORAGE_KEY = "webaudit360_theme";

export function initTheme() {
  const savedTheme = localStorage.getItem(THEME_STORAGE_KEY) || "light";
  applyTheme(savedTheme);

  // Setup theme toggle buttons
  const toggleButtons = document.querySelectorAll(".theme-toggle-capsule, #theme-toggle");
  toggleButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      const currentTheme = document.documentElement.getAttribute("data-theme") || "light";
      const newTheme = currentTheme === "dark" ? "light" : "dark";
      applyTheme(newTheme);
      localStorage.setItem(THEME_STORAGE_KEY, newTheme);
    });
  });
}

export function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  
  // Update capsule toggle visual active states
  const lightOptions = document.querySelectorAll(".theme-toggle-option[data-theme-val='light']");
  const darkOptions = document.querySelectorAll(".theme-toggle-option[data-theme-val='dark']");
  
  if (theme === "dark") {
    lightOptions.forEach((el) => el.classList.remove("active"));
    darkOptions.forEach((el) => el.classList.add("active"));
  } else {
    lightOptions.forEach((el) => el.classList.add("active"));
    darkOptions.forEach((el) => el.classList.remove("active"));
  }
}
