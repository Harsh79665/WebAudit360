/**
 * WebAudit 360 — Frontend Utilities
 * Creator: Harsh Patel
 */

import { CONFIG } from "./config.js";
import { getIcon } from "./icons.js";

/**
 * Validates a target URL: must have http/https protocol and valid hostname
 */
export function validateUrl(urlString) {
  if (!urlString || typeof urlString !== "string") {
    return { valid: false, error: "Please enter a valid website URL." };
  }
  
  let formatted = urlString.trim();
  if (!/^https?:\/\//i.test(formatted)) {
    formatted = "https://" + formatted;
  }

  try {
    const parsed = new URL(formatted);
    if (!["http:", "https:"].includes(parsed.protocol)) {
      return { valid: false, error: "Only HTTP and HTTPS URLs are supported." };
    }
    if (!parsed.hostname || !parsed.hostname.includes(".")) {
      return { valid: false, error: "Please enter a fully-qualified domain name (e.g. example.com)." };
    }
    return { valid: true, url: parsed.href, hostname: parsed.hostname };
  } catch (err) {
    return { valid: false, error: "Invalid URL format." };
  }
}

/**
 * Maps a numeric score (0-100) to its WebAudit 360 label and CSS class
 */
export function getScoreDetails(score) {
  if (score === null || score === undefined || isNaN(score)) {
    return { label: "N/A", class: "score-na", textClass: "text-muted", color: "var(--text-muted)" };
  }
  const num = Math.round(score);
  if (num >= 90) return { label: "Excellent", class: "score-excellent", textClass: "text-excellent", color: "var(--color-excellent)" };
  if (num >= 75) return { label: "Good", class: "score-good", textClass: "text-good", color: "var(--color-good)" };
  if (num >= 50) return { label: "Needs Improvement", class: "score-warning", textClass: "text-warning", color: "var(--color-warning)" };
  if (num >= 25) return { label: "Poor", class: "score-poor", textClass: "text-poor", color: "var(--color-poor)" };
  return { label: "Critical", class: "score-critical", textClass: "text-critical", color: "var(--color-critical)" };
}

/**
 * Sanitizes HTML string to prevent XSS
 */
export function escapeHtml(str) {
  if (!str) return "";
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

/**
 * Formats ISO date string to readable locale date/time
 */
export function formatDate(isoString) {
  if (!isoString) return "N/A";
  const date = new Date(isoString);
  if (isNaN(date.getTime())) return "N/A";
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit"
  });
}

/**
 * Displays an accessible toast notification
 */
export function showToast(title, message = "", type = "info", duration = 4000) {
  let container = document.querySelector(".toast-container");
  if (!container) {
    container = document.createElement("div");
    container.className = "toast-container";
    document.body.appendChild(container);
  }

  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.setAttribute("role", "alert");
  toast.setAttribute("aria-live", "polite");

  let iconName = "alertCircle";
  if (type === "success") iconName = "check";
  if (type === "error") iconName = "alertTriangle";

  toast.innerHTML = `
    <div class="toast-icon">${getIcon(iconName)}</div>
    <div class="toast-content">
      <div class="toast-title">${escapeHtml(title)}</div>
      ${message ? `<div class="toast-message">${escapeHtml(message)}</div>` : ""}
    </div>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(10px)";
    toast.style.transition = "all 0.3s ease";
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

/**
 * Dynamically updates copyright year in footer
 */
export function initFooterYear() {
  const yearEl = document.getElementById("footer-year");
  if (yearEl) {
    yearEl.textContent = new Date().getFullYear();
  }
}

