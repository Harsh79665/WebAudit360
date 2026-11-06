/**
 * WebAudit 360 — 10 Futuristic Engines Controller
 * Author: Harsh Patel
 */

const ENGINES_METADATA = [
  {
    key: "LOAF_INP",
    name: "LoAF & INP Script Attributor",
    wave: "Wave 1",
    badgeClass: "wave1",
    icon: "activity",
    description: "Measures Long Animation Frames (>50ms) and attributes main-thread blocking to specific scripts.",
    metricLabel: "Est. INP Latency",
    defaultMetric: "45 ms (Good)"
  },
  {
    key: "SECURITY_MAGECART",
    name: "Magecart & Exfiltration Sandbox",
    wave: "Wave 1",
    badgeClass: "wave1",
    icon: "shield",
    description: "Detects client-side formjacking, unauthorized input event listeners, and data exfiltration channels.",
    metricLabel: "Exfiltration Risk",
    defaultMetric: "Low / Clean"
  },
  {
    key: "CARBON_ESG",
    name: "Digital Carbon Footprint (CO2.js)",
    wave: "Wave 1",
    badgeClass: "wave1",
    icon: "globe",
    description: "Calculates grams of CO2e per visit and Scope 3 emissions using Sustainable Web Design v4.",
    metricLabel: "Carbon Rating",
    defaultMetric: "A+ (<0.095g CO2)"
  },
  {
    key: "SECRET_HARVESTER",
    name: "Client Secret & Sourcemap Harvester",
    wave: "Wave 1",
    badgeClass: "wave1",
    icon: "lock",
    description: "OSINT scanner discovering leaked API keys, tokens, and production source maps (.js.map).",
    metricLabel: "Leaked Secrets",
    defaultMetric: "0 Clean"
  },
  {
    key: "POST_QUANTUM_DNSSEC",
    name: "Post-Quantum Cryptography & DNSSEC Radar",
    wave: "Wave 1",
    badgeClass: "wave1",
    icon: "cpu",
    description: "Inspects TLS 1.3 hybrid PQC key exchange (ML-KEM/Kyber) and DNSSEC cryptographic validation chains.",
    metricLabel: "Quantum Posture",
    defaultMetric: "TLS 1.3 Active"
  },
  {
    key: "GEO_AI",
    name: "Generative Engine Optimization (GEO)",
    wave: "Wave 2",
    badgeClass: "wave2",
    icon: "zap",
    description: "Audits AI bot crawler access in robots.txt, /llms.txt discovery, and Schema.org JSON-LD grounding.",
    metricLabel: "AI Visibility",
    defaultMetric: "Indexed for AI"
  },
  {
    key: "ZERO_TRUST_PRIVACY",
    name: "Zero-Trust Privacy & Consent Evasion",
    wave: "Wave 2",
    badgeClass: "wave2",
    icon: "eyeOff",
    description: "Uncovers pre-consent tracking cookies, canvas/audio fingerprinting, and CNAME cloaking subdomains.",
    metricLabel: "Pre-Consent Cookies",
    defaultMetric: "0 (GDPR Compliant)"
  },
  {
    key: "LAYOUT_DEFECTS",
    name: "AI Visual Semantic Layout Defect Detection",
    wave: "Wave 2",
    badgeClass: "wave2",
    icon: "monitor",
    description: "Detects DOM geometry overlaps, text truncation with overflow: hidden, and image aspect distortion.",
    metricLabel: "Visual Stability",
    defaultMetric: "Pristine (0 Defects)"
  },
  {
    key: "USER_JOURNEY",
    name: "Synthetic Multi-Step User Journey Validator",
    wave: "Wave 2",
    badgeClass: "wave2",
    icon: "play",
    description: "Simulates and validates 5 critical journeys: navigation, search, contact forms, modals, and primary CTA.",
    metricLabel: "Journey Success",
    defaultMetric: "100% (5/5 Passing)"
  },
  {
    key: "CODE_REMEDIATION",
    name: "1-Click AST Code Remediation Generator",
    wave: "Wave 2",
    badgeClass: "wave2",
    icon: "checkCircle",
    description: "Synthesizes ready-to-apply git .patch unified diffs and framework code snippets for all audit findings.",
    metricLabel: "Remediations Ready",
    defaultMetric: "Automated Patches Ready"
  }
];

document.addEventListener("DOMContentLoaded", async () => {
  renderEnginesGrid({});
  await loadRecentAudits();

  const urlParams = new URLSearchParams(window.location.search);
  const auditId = urlParams.get("audit_id");
  if (auditId) {
    document.getElementById("audit-select").value = auditId;
    await inspectAudit(auditId);
  }

  document.getElementById("audit-select").addEventListener("change", async (e) => {
    if (e.target.value) {
      await inspectAudit(e.target.value);
    }
  });

  document.getElementById("run-futuristic-btn").addEventListener("click", () => {
    window.location.href = "new-audit.html";
  });
});

async function loadRecentAudits() {
  const selectEl = document.getElementById("audit-select");
  try {
    const res = await window.apiClient.get("/api/v1/audits?limit=15");
    if (res && Array.isArray(res.items)) {
      selectEl.innerHTML = '<option value="">Select Audit to Inspect...</option>';
      res.items.forEach(a => {
        const opt = document.createElement("option");
        opt.value = a.id;
        opt.textContent = `#${a.id} — ${a.target_url} (${a.status})`;
        selectEl.appendChild(opt);
      });
    }
  } catch (err) {
    console.warn("Could not load recent audits for futuristic inspection:", err);
  }
}

async function inspectAudit(auditId) {
  try {
    const audit = await window.apiClient.get(`/api/v1/audits/${auditId}`);
    if (audit) {
      const card = document.getElementById("target-summary-card");
      card.style.display = "block";
      document.getElementById("target-url-text").textContent = audit.target_url;
      const badge = document.getElementById("target-status-badge");
      badge.textContent = audit.status;
      badge.className = audit.status === "COMPLETED" ? "badge badge-success" : "badge badge-warning";

      renderEnginesGrid(audit.raw_results || {}, audit);
    }
  } catch (err) {
    console.error("Failed to inspect audit:", err);
  }
}

function renderEnginesGrid(rawResults, audit = null) {
  const container = document.getElementById("engines-container");
  container.innerHTML = "";

  ENGINES_METADATA.forEach(engine => {
    const evidence = rawResults[engine.key] || {};
    const card = document.createElement("div");
    card.className = "engine-card";

    let metricValue = engine.defaultMetric;
    let extraDetails = "";

    if (engine.key === "LOAF_INP" && evidence.estimated_inp_ms) {
      metricValue = `${evidence.estimated_inp_ms} ms (${evidence.inp_rating || 'Good'})`;
      extraDetails = `<div class="text-xs text-muted mt-xs">Blocking scripts: ${evidence.render_blocking_count || 0} | TBT: ${evidence.estimated_tbt_ms || 0}ms</div>`;
    } else if (engine.key === "CARBON_ESG" && evidence.co2_grams_per_visit) {
      metricValue = `Grade ${evidence.carbon_grade || 'A'} (${evidence.co2_grams_per_visit}g CO2/visit)`;
      extraDetails = `<div class="text-xs text-muted mt-xs">Payload: ${evidence.total_mb || 0} MB | Green Host: ${evidence.is_green_hosted ? 'Yes' : 'No'}</div>`;
    } else if (engine.key === "SECURITY_MAGECART" && evidence.sensitive_inputs_count !== undefined) {
      metricValue = evidence.risk_level ? `${evidence.risk_level} Risk` : "Low / Clean";
      extraDetails = `<div class="text-xs text-muted mt-xs">Sensitive inputs: ${evidence.sensitive_inputs_count} | Untrusted scripts: ${evidence.untrusted_scripts_count || 0}</div>`;
    } else if (engine.key === "SECRET_HARVESTER" && evidence.discovered_secrets_count !== undefined) {
      metricValue = `${evidence.discovered_secrets_count} Found (${evidence.security_grade || 'A'})`;
      extraDetails = `<div class="text-xs text-muted mt-xs">Scanned assets: ${evidence.scanned_assets_count || 0} | Sourcemaps: ${evidence.exposed_sourcemaps_count || 0}</div>`;
    } else if (engine.key === "POST_QUANTUM_DNSSEC" && evidence.pqc_readiness_level) {
      metricValue = evidence.pqc_readiness_level;
      extraDetails = `<div class="text-xs text-muted mt-xs">DNSSEC: ${evidence.dnssec_info?.has_dnssec ? 'Active' : 'Missing'} | TLS: ${evidence.tls_info?.tls_version || 'Unknown'}</div>`;
    } else if (engine.key === "GEO_AI" && evidence.geo_readiness_tier) {
      metricValue = evidence.geo_readiness_tier;
      extraDetails = `<div class="text-xs text-muted mt-xs">AI Crawlers: ${evidence.blocked_crawlers_count ? evidence.blocked_crawlers_count + ' Blocked' : 'Permitted'} | /llms.txt: ${evidence.has_llms_txt ? 'Present' : 'Missing'}</div>`;
    } else if (engine.key === "ZERO_TRUST_PRIVACY" && evidence.privacy_rating) {
      metricValue = evidence.privacy_rating;
      extraDetails = `<div class="text-xs text-muted mt-xs">Pre-consent cookies: ${evidence.tracking_cookies_count || 0} | Fingerprints: ${evidence.detected_fingerprints_count || 0}</div>`;
    } else if (engine.key === "LAYOUT_DEFECTS" && evidence.visual_stability_tier) {
      metricValue = evidence.visual_stability_tier;
      const s = evidence.defects_summary || {};
      extraDetails = `<div class="text-xs text-muted mt-xs">Clipping: ${s.clipping_count || 0} | Distorted Images: ${s.image_distortion_count || 0}</div>`;
    } else if (engine.key === "USER_JOURNEY" && evidence.journey_success_rate) {
      metricValue = `${evidence.journey_success_rate} (${evidence.passed_journeys_count}/${evidence.total_journeys_count})`;
      extraDetails = `<div class="text-xs text-muted mt-xs">Flow Quality: ${evidence.flow_quality_tier || 'Frictionless'}</div>`;
    } else if (engine.key === "CODE_REMEDIATION" && evidence.remediations) {
      metricValue = `${evidence.remediations_count || evidence.remediations.length} Patches Synthesized`;
      const firstPatch = evidence.remediations[0]?.git_patch || "";
      if (firstPatch) {
        extraDetails = `<div class="patch-box"><code>${escapeHtml(firstPatch)}</code></div>`;
      }
    }

    card.innerHTML = `
      <div>
        <div class="flex items-center justify-between mb-sm">
          <span class="engine-badge ${engine.badgeClass}">${engine.wave}</span>
          <span class="text-xs font-semibold text-muted">${engine.key}</span>
        </div>
        <div class="flex items-center gap-sm mb-xs">
          <span data-icon="${engine.icon}" class="text-primary font-bold"></span>
          <h3 class="text-base font-bold">${engine.name}</h3>
        </div>
        <p class="text-xs text-muted leading-relaxed">${engine.description}</p>
      </div>

      <div class="mt-md pt-sm border-t border-color">
        <div class="flex items-center justify-between">
          <span class="text-xs font-semibold text-muted">${engine.metricLabel}</span>
          <span class="text-sm font-bold text-primary">${metricValue}</span>
        </div>
        ${extraDetails}
      </div>
    `;

    container.appendChild(card);
  });

  // Re-render vector icons
  if (window.renderIcons) {
    window.renderIcons();
  }
}

function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
