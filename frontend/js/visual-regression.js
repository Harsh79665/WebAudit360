/**
 * WebAudit 360 — Visual Regression & Layout Stability Viewer
 * Creator: Harsh Patel
 */

import { apiClient } from "./api.js";
import { escapeHtml, formatDate, getScoreDetails } from "./utils.js";
import { renderIcons } from "./icons.js";

let currentVisualData = null;
let activeViewport = "desktop";
let activeMode = "side-by-side"; // 'side-by-side' | 'slider' | 'diff-only'

export async function initVisualRegressionView() {
  const auditSelect = document.getElementById("select-audit-target");
  if (auditSelect) {
    auditSelect.addEventListener("change", (e) => loadVisualData(e.target.value));
  }

  await populateAuditSelector();
}

async function populateAuditSelector() {
  const auditSelect = document.getElementById("select-audit-target");
  if (!auditSelect) return;

  try {
    const data = await apiClient.get("/audits?limit=50").catch(() => ({ items: [] }));
    let audits = (data.items || []).filter(a => !a.target_url.includes("example.com"));

    const urlParams = new URLSearchParams(window.location.search);
    const requestedId = parseInt(urlParams.get("id"), 10);

    let targetAudit = !isNaN(requestedId) && requestedId > 0 ? audits.find(a => a.id === requestedId) : null;
    if (!targetAudit && !isNaN(requestedId) && requestedId > 0) {
      try {
        const direct = await apiClient.get(`/audits/${requestedId}`);
        if (direct && direct.id) {
          targetAudit = direct;
          audits.unshift(direct);
        }
      } catch (_) {}
    }

    if (audits.length === 0) {
      auditSelect.innerHTML = `<option value="">No audits available</option>`;
      return;
    }

    if (!targetAudit) {
      targetAudit = audits[0];
    }

    auditSelect.innerHTML = audits.map(a => `
      <option value="${a.id}" ${a.id === targetAudit.id ? 'selected' : ''}>
        #${a.id} — ${escapeHtml(a.target_url)} (${formatDate(a.created_at)})
      </option>
    `).join("");

    await loadVisualData(targetAudit.id);
  } catch (e) {
    console.warn("Failed to populate audit selector:", e);
  }
}

export async function loadVisualData(auditId) {
  if (!auditId) return;
  const container = document.getElementById("visual-details-container");
  if (!container) return;

  container.innerHTML = `
    <div style="text-align: center; padding: var(--space-2xl);">
      <div class="spinner" style="margin: 0 auto var(--space-md);"></div>
      <p class="text-muted text-sm">Loading visual regression comparison data...</p>
    </div>
  `;

  try {
    const visual = await apiClient.get(`/audits/${auditId}/visual`);
    currentVisualData = visual;
    renderVisualWorkbench(container);
  } catch (err) {
    // If /visual returned 404 or empty, try loading raw audit to check if visual ran
    try {
      const audit = await apiClient.get(`/audits/${auditId}`);
      if (audit.raw_results && audit.raw_results.VISUAL) {
        currentVisualData = {
          audit_id: audit.id,
          target_url: audit.target_url,
          ...audit.raw_results.VISUAL
        };
        renderVisualWorkbench(container);
        return;
      }
    } catch (_) {}

    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon"><span data-icon="alertTriangle"></span></div>
        <h3 class="empty-state-title">No Visual Data Available</h3>
        <p class="empty-state-desc">This audit was completed before the Visual Regression Engine was active or without VISUAL module selected.</p>
        <a href="new-audit.html" class="btn btn-primary"><span data-icon="zap"></span> Run New Visual Audit</a>
      </div>
    `;
    renderIcons(container);
  }
}

function renderVisualWorkbench(container) {
  if (!currentVisualData) return;

  const data = currentVisualData;
  const score = data.score !== null && data.score !== undefined ? data.score : 100.0;
  const scoreObj = getScoreDetails(score);
  const mismatch = data.overall_mismatch_percentage || 0.0;
  const isBaseline = data.baseline_established;

  const viewports = data.viewports || {};
  const availableViewports = Object.keys(viewports);
  if (!availableViewports.includes(activeViewport) && availableViewports.length > 0) {
    activeViewport = availableViewports[0];
  }

  const vpData = viewports[activeViewport] || {
    width: 1280, height: 800, mismatch_percentage: 0, diff_pixels: 0, total_pixels: 0
  };

  let html = `
    <!-- Top Metric Cards -->
    <div class="grid grid-3" style="gap: var(--space-md); margin-bottom: var(--space-xl);">
      <div class="card glass-panel" style="padding: var(--space-lg); text-align: center;">
        <div class="text-xs text-muted" style="text-transform: uppercase; font-weight: 700;">Visual Health Score</div>
        <div style="font-size: 2.25rem; font-weight: 800; margin: 4px 0;" class="${scoreObj.class}">
          ${Math.round(score)}%
        </div>
        <span class="badge ${scoreObj.class}">${scoreObj.label}</span>
      </div>

      <div class="card glass-panel" style="padding: var(--space-lg);">
        <div class="text-xs text-muted" style="text-transform: uppercase; font-weight: 700; margin-bottom: 6px;">Pixel Variance (${activeViewport.toUpperCase()})</div>
        <div style="font-size: 1.35rem; font-weight: 800; color: ${vpData.mismatch_percentage > 1.0 ? 'var(--color-critical)' : 'var(--accent-green)'};">
          ${vpData.mismatch_percentage.toFixed(2)}% Mismatch
        </div>
        <p class="text-xs text-muted" style="margin-top: 6px;">
          ${(vpData.diff_pixels || 0).toLocaleString()} changed pixels out of ${(vpData.total_pixels || 0).toLocaleString()} total.
        </p>
      </div>

      <div class="card glass-panel" style="padding: var(--space-lg);">
        <div class="text-xs text-muted" style="text-transform: uppercase; font-weight: 700; margin-bottom: 6px;">Comparison Reference</div>
        <div style="font-size: 1.15rem; font-weight: 700; color: var(--accent-primary);">
          ${isBaseline ? 'Initial Baseline Established' : `Baseline: Audit #${data.baseline_audit_id}`}
        </div>
        <p class="text-xs text-muted" style="margin-top: 6px;">
          ${isBaseline ? 'This capture serves as the ground truth reference for future scans.' : 'Compared against the preceding production baseline scan.'}
        </p>
      </div>
    </div>

    <!-- Workbench Controls Bar -->
    <div class="glass-panel" style="padding: var(--space-md) var(--space-lg); margin-bottom: var(--space-lg); display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: var(--space-md);">
      <!-- Viewport Switcher -->
      <div class="flex items-center gap-xs">
        <span class="text-xs text-muted" style="font-weight: 700; margin-right: 6px;">VIEWPORT:</span>
        <button class="btn btn-sm ${activeViewport === 'desktop' ? 'btn-primary' : 'btn-secondary'} vp-tab-btn" data-vp="desktop">
          <span data-icon="monitor"></span> Desktop (1280×800)
        </button>
        <button class="btn btn-sm ${activeViewport === 'mobile' ? 'btn-primary' : 'btn-secondary'} vp-tab-btn" data-vp="mobile">
          <span data-icon="smartphone"></span> Mobile (390×844)
        </button>
      </div>

      <!-- Mode Switcher -->
      <div class="flex items-center gap-xs">
        <span class="text-xs text-muted" style="font-weight: 700; margin-right: 6px;">VIEW MODE:</span>
        <button class="btn btn-sm ${activeMode === 'side-by-side' ? 'btn-primary' : 'btn-secondary'} mode-tab-btn" data-mode="side-by-side">
          <span data-icon="columns"></span> Side-by-Side
        </button>
        <button class="btn btn-sm ${activeMode === 'slider' ? 'btn-primary' : 'btn-secondary'} mode-tab-btn" data-mode="slider">
          <span data-icon="sliders"></span> Split Slider
        </button>
        <button class="btn btn-sm ${activeMode === 'diff-only' ? 'btn-primary' : 'btn-secondary'} mode-tab-btn" data-mode="diff-only">
          <span data-icon="eye"></span> Diff Mask
        </button>
      </div>
    </div>

    <!-- Active Visual Display Panel -->
    <div class="glass-panel" style="padding: var(--space-xl); margin-bottom: var(--space-xl);">
  `;

  if (!vpData.current_url && !vpData.baseline_url) {
    html += `
      <div class="empty-state" style="padding: var(--space-xl) 0;">
        <div class="empty-state-icon"><span data-icon="alertTriangle"></span></div>
        <h3 class="empty-state-title">Visual Snapshots Not Yet Available</h3>
        <p class="empty-state-desc" style="max-width: 580px; margin: 0 auto var(--space-lg);">
          Visual regression capture has not completed for Audit #${data.audit_id}. Run an audit with the VISUAL module selected to generate side-by-side diffs.
        </p>
        <a href="new-audit.html?target=${encodeURIComponent(data.target_url || '')}" class="btn btn-primary">
          <span data-icon="zap"></span> Run New Visual Audit
        </a>
      </div>
    `;
  } else if (isBaseline || !vpData.has_baseline) {
    html += `
      <div class="empty-state" style="padding: var(--space-lg) 0;">
        <div class="empty-state-icon" style="color: var(--accent-green);"><span data-icon="checkCircle"></span></div>
        <h3 class="empty-state-title">Initial Baseline Established</h3>
        <p class="empty-state-desc" style="max-width: 580px; margin: 0 auto var(--space-lg);">
          No previous baseline capture existed for this URL. This capture is recorded as the reference standard.
          Run a subsequent scan to calculate pixel-by-pixel layout shifts and visual regressions.
        </p>
      </div>

      <div style="max-width: 800px; margin: 0 auto; text-align: center;">
        <div style="font-weight: 700; margin-bottom: var(--space-sm); font-size: 0.95rem;">Current Reference Screenshot (${activeViewport.toUpperCase()})</div>
        <div class="card glass-panel" style="overflow: hidden; padding: 0; display: inline-block; border: 1px solid var(--border-color);">
          <img src="${vpData.current_url || ''}" alt="Baseline capture" style="max-width: 100%; height: auto; display: block;" class="zoomable-img" />
        </div>
      </div>
    `;
  } else if (activeMode === "side-by-side") {
    html += `
      <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: var(--space-md);">
        <h3 style="font-size: 1.15rem; font-weight: 700;">Side-by-Side Visual Verification</h3>
        <div class="text-xs text-muted flex items-center gap-sm">
          <span style="display: inline-block; width: 12px; height: 12px; background: rgb(255, 0, 128); border-radius: 2px;"></span>
          Magenta highlights denote detected pixel shifts (&gt;15 RGB threshold)
        </div>
      </div>

      <div class="grid grid-3" style="gap: var(--space-md); align-items: start;">
        <!-- Baseline Column -->
        <div class="card glass-panel" style="padding: var(--space-md);">
          <div class="flex items-center justify-between" style="margin-bottom: var(--space-xs);">
            <strong style="font-size: 0.9rem;">Baseline Reference</strong>
            <span class="badge" style="background: var(--bg-surface); color: var(--text-secondary);">Audit #${data.baseline_audit_id}</span>
          </div>
          <div style="border: 1px solid var(--border-color); border-radius: var(--radius-sm); overflow: hidden; background: #000;">
            <img src="${vpData.baseline_url}" alt="Baseline" style="width: 100%; height: auto; display: block; cursor: zoom-in;" class="zoomable-img" />
          </div>
        </div>

        <!-- Diff Overlay Column -->
        <div class="card glass-panel" style="padding: var(--space-md); border-color: ${vpData.mismatch_percentage > 1.0 ? 'rgba(255, 0, 128, 0.4)' : 'var(--border-color)'};">
          <div class="flex items-center justify-between" style="margin-bottom: var(--space-xs);">
            <strong style="font-size: 0.9rem; color: rgb(255, 0, 128);">Visual Diff Mask</strong>
            <span class="badge" style="background: rgba(255, 0, 128, 0.15); color: rgb(255, 0, 128); font-weight: 700;">
              ${vpData.mismatch_percentage.toFixed(2)}% Shift
            </span>
          </div>
          <div style="border: 1px solid var(--border-color); border-radius: var(--radius-sm); overflow: hidden; background: #000;">
            <img src="${vpData.diff_url}" alt="Diff Mask" style="width: 100%; height: auto; display: block; cursor: zoom-in;" class="zoomable-img" />
          </div>
        </div>

        <!-- Current Column -->
        <div class="card glass-panel" style="padding: var(--space-md);">
          <div class="flex items-center justify-between" style="margin-bottom: var(--space-xs);">
            <strong style="font-size: 0.9rem;">Current Capture</strong>
            <span class="badge btn-primary">Audit #${data.audit_id}</span>
          </div>
          <div style="border: 1px solid var(--border-color); border-radius: var(--radius-sm); overflow: hidden; background: #000;">
            <img src="${vpData.current_url}" alt="Current" style="width: 100%; height: auto; display: block; cursor: zoom-in;" class="zoomable-img" />
          </div>
        </div>
      </div>
    `;
  } else if (activeMode === "slider") {
    html += `
      <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: var(--space-md);">
        <div>
          <h3 style="font-size: 1.15rem; font-weight: 700;">Interactive Before / After Split Slider</h3>
          <p class="text-xs text-muted">Drag the slider or hover to reveal the baseline (left) vs. current capture (right).</p>
        </div>
        <span class="badge ${vpData.mismatch_percentage > 1.0 ? 'score-warning' : 'score-good'}">
          ${vpData.mismatch_percentage.toFixed(2)}% Variance
        </span>
      </div>

      <div class="split-slider-container" id="visual-split-slider" style="position: relative; max-width: 900px; margin: 0 auto; overflow: hidden; border: 1px solid var(--border-color); border-radius: var(--radius-md); user-select: none;">
        <!-- Current Image (Full Underneath) -->
        <img src="${vpData.current_url}" alt="Current" style="width: 100%; display: block;" />

        <!-- Baseline Image (Clipped on Top) -->
        <div id="slider-clipped-layer" style="position: absolute; top: 0; left: 0; width: 50%; height: 100%; overflow: hidden; border-right: 2px solid var(--accent-primary); box-shadow: 2px 0 10px rgba(0,0,0,0.5);">
          <img src="${vpData.baseline_url}" alt="Baseline" style="position: absolute; top: 0; left: 0; width: 900px; max-width: none; height: 100%; object-fit: cover;" id="slider-baseline-img" />
        </div>

        <!-- Slider Range Input -->
        <input type="range" min="0" max="100" value="50" class="split-range-input" id="split-range-input"
          style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; opacity: 0; cursor: ew-resize; z-index: 10; margin: 0;" />
        
        <!-- Divider Handle Pill -->
        <div id="slider-handle" style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); width: 36px; height: 36px; background: var(--accent-primary); border-radius: 50%; display: flex; align-items: center; justify-content: center; color: #fff; box-shadow: 0 4px 12px rgba(0,0,0,0.4); pointer-events: none; z-index: 5;">
          <span data-icon="sliders" style="width: 16px; height: 16px;"></span>
        </div>
      </div>
    `;
  } else if (activeMode === "diff-only") {
    html += `
      <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: var(--space-md);">
        <div>
          <h3 style="font-size: 1.15rem; font-weight: 700;">High-Contrast Layout Shift Diff Mask</h3>
          <p class="text-xs text-muted">Highlights pixels with &gt;15 luminance change against baseline #${data.baseline_audit_id}.</p>
        </div>
        <div class="badge" style="background: rgba(255,0,128,0.15); color: rgb(255,0,128); font-weight: 700;">
          ${vpData.mismatch_percentage.toFixed(2)}% Mismatch (${(vpData.diff_pixels || 0).toLocaleString()} px)
        </div>
      </div>

      <div style="max-width: 900px; margin: 0 auto; text-align: center;">
        <div class="card glass-panel" style="padding: 0; overflow: hidden; border: 1px solid var(--border-color); display: inline-block;">
          <img src="${vpData.diff_url}" alt="Diff Mask Full" style="width: 100%; height: auto; display: block; cursor: zoom-in;" class="zoomable-img" />
        </div>
      </div>
    `;
  }

  html += `</div>`; // Close panel

  container.innerHTML = html;
  renderIcons(container);

  // Wire Viewport Tabs
  container.querySelectorAll(".vp-tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      activeViewport = btn.dataset.vp;
      renderVisualWorkbench(container);
    });
  });

  // Wire Mode Tabs
  container.querySelectorAll(".mode-tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      activeMode = btn.dataset.mode;
      renderVisualWorkbench(container);
    });
  });

  // Wire Split Slider
  const sliderInput = document.getElementById("split-range-input");
  const clippedLayer = document.getElementById("slider-clipped-layer");
  const handle = document.getElementById("slider-handle");
  const baselineImg = document.getElementById("slider-baseline-img");
  const sliderContainer = document.getElementById("visual-split-slider");

  if (sliderInput && clippedLayer && handle && baselineImg && sliderContainer) {
    const updateSlider = (val) => {
      clippedLayer.style.width = `${val}%`;
      handle.style.left = `${val}%`;
      baselineImg.style.width = `${sliderContainer.offsetWidth}px`;
    };

    sliderInput.addEventListener("input", (e) => updateSlider(e.target.value));
    window.addEventListener("resize", () => {
      if (baselineImg && sliderContainer) baselineImg.style.width = `${sliderContainer.offsetWidth}px`;
    });
    // Initial size alignment
    setTimeout(() => {
      if (baselineImg && sliderContainer) baselineImg.style.width = `${sliderContainer.offsetWidth}px`;
    }, 50);
  }

  // Wire Zoomable Images (Lightbox)
  container.querySelectorAll(".zoomable-img").forEach(img => {
    img.addEventListener("click", () => openLightbox(img.src));
  });
}

function openLightbox(imgSrc) {
  const existing = document.getElementById("visual-lightbox-modal");
  if (existing) existing.remove();

  const modal = document.createElement("div");
  modal.id = "visual-lightbox-modal";
  modal.style.cssText = `
    position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
    background: rgba(10, 15, 29, 0.88); backdrop-filter: blur(8px);
    z-index: 99999; display: flex; align-items: center; justify-content: center;
    padding: var(--space-xl); cursor: zoom-out;
  `;

  modal.innerHTML = `
    <div style="position: relative; max-width: 95vw; max-height: 95vh; overflow: auto; border-radius: var(--radius-md); box-shadow: 0 20px 50px rgba(0,0,0,0.6);">
      <img src="${imgSrc}" style="max-width: 100%; height: auto; display: block;" />
      <button style="position: absolute; top: 12px; right: 12px; background: rgba(0,0,0,0.6); color: #fff; border: 1px solid rgba(255,255,255,0.2); border-radius: 50%; width: 36px; height: 36px; cursor: pointer; display: flex; align-items: center; justify-content: center;">
        <span data-icon="x"></span>
      </button>
    </div>
  `;

  modal.addEventListener("click", () => modal.remove());
  document.body.appendChild(modal);
  renderIcons(modal);
}
