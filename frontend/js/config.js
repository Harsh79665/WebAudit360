/**
 * WebAudit 360 — Platform Configuration & Constants
 * Creator: Harsh Patel
 */

export const CONFIG = {
  APP_NAME: "WebAudit 360",
  VERSION: "1.0.0",
  CREATOR: "Harsh Patel",
  API_BASE_URL: window.location.origin.includes("localhost") || window.location.origin.includes("127.0.0.1")
    ? "http://127.0.0.1:8000/api/v1"
    : "/api/v1",
  WS_BASE_URL: window.location.origin.includes("localhost") || window.location.origin.includes("127.0.0.1")
    ? "ws://127.0.0.1:8000/api/v1/ws"
    : `${window.location.protocol === "https:" ? "wss:" : "ws:"}//${window.location.host}/api/v1/ws`,
  
  SCORE_THRESHOLDS: {
    EXCELLENT: { min: 90, label: "Excellent", class: "score-excellent" },
    GOOD: { min: 75, label: "Good", class: "score-good" },
    WARNING: { min: 50, label: "Needs Improvement", class: "score-warning" },
    POOR: { min: 25, label: "Poor", class: "score-poor" },
    CRITICAL: { min: 0, label: "Critical", class: "score-critical" }
  },

  DEFAULT_CRAWL_LIMITS: {
    maxPages: 100,
    maxDepth: 5,
    concurrency: 2,
    httpTimeoutSec: 20
  }
};

