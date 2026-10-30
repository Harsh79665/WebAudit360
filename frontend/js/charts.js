/**
 * WebAudit 360 — Chart.js Helper Utilities
 * Creator: Harsh Patel
 * 
 * Manages theme-aware data visualizations:
 * - Category score radar charts
 * - Severity distribution doughnut charts
 * - Metric comparison bar charts
 */

export const ChartHelper = {
  isDarkMode() {
    return document.documentElement.getAttribute("data-theme") === "dark";
  },

  getColors() {
    const dark = this.isDarkMode();
    return {
      textColor: dark ? "#94A3B8" : "#64748B",
      gridColor: dark ? "rgba(255, 255, 255, 0.08)" : "rgba(0, 0, 0, 0.06)",
      accentBlue: "#2563EB",
      accentCyan: "#06B6D4",
      accentGreen: "#10B981",
      accentYellow: "#F59E0B",
      accentRed: "#EF4444"
    };
  },

  createRadarChart(canvasEl, categories = {}) {
    if (!window.Chart || !canvasEl) return null;
    const colors = this.getColors();

    const labels = Object.keys(categories);
    const data = Object.values(categories).map(v => v !== null && v !== undefined ? v : 0);

    return new window.Chart(canvasEl, {
      type: "radar",
      data: {
        labels: labels,
        datasets: [{
          label: "Audit Scores",
          data: data,
          backgroundColor: "rgba(37, 99, 235, 0.2)",
          borderColor: colors.accentBlue,
          pointBackgroundColor: colors.accentCyan,
          pointBorderColor: "#fff",
          pointHoverBackgroundColor: "#fff",
          pointHoverBorderColor: colors.accentCyan,
          borderWidth: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          r: {
            min: 0,
            max: 100,
            ticks: { stepSize: 20, color: colors.textColor, backdropColor: "transparent" },
            grid: { color: colors.gridColor },
            pointLabels: { color: colors.textColor, font: { size: 12, weight: "bold" } }
          }
        },
        plugins: {
          legend: { display: false }
        }
      }
    });
  },

  createSeverityDoughnut(canvasEl, counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }) {
    if (!window.Chart || !canvasEl) return null;
    const colors = this.getColors();

    return new window.Chart(canvasEl, {
      type: "doughnut",
      data: {
        labels: ["Critical", "High", "Medium", "Low", "Info"],
        datasets: [{
          data: [counts.CRITICAL || 0, counts.HIGH || 0, counts.MEDIUM || 0, counts.LOW || 0, counts.INFO || 0],
          backgroundColor: ["#EF4444", "#F97316", "#F59E0B", "#10B981", "#3B82F6"],
          borderWidth: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "bottom",
            labels: { color: colors.textColor, boxWidth: 12 }
          }
        },
        cutout: "70%"
      }
    });
  },

  createBarChart(canvasEl, labels = [], data = [], label = "Metrics") {
    if (!window.Chart || !canvasEl) return null;
    const colors = this.getColors();

    return new window.Chart(canvasEl, {
      type: "bar",
      data: {
        labels: labels,
        datasets: [{
          label: label,
          data: data,
          backgroundColor: colors.accentBlue,
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: {
            grid: { display: false },
            ticks: { color: colors.textColor }
          },
          y: {
            min: 0,
            grid: { color: colors.gridColor },
            ticks: { color: colors.textColor }
          }
        },
        plugins: {
          legend: { display: false }
        }
      }
    });
  }
};
