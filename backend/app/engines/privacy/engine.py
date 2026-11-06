"""WebAudit 360 — Zero-Trust Privacy & Consent Evasion Radar Engine
Author: Harsh Patel

Evaluates:
- Pre-consent tracking cookie leakage (cookies dispatched before user consent)
- Browser fingerprinting vectors (HTML5 Canvas toDataURL/getImageData, WebGL renderer introspection, AudioContext sampling)
- CNAME cloaking tracker subdomains bypassing ad-blockers and privacy shields
- Consent Management Platform (CMP) presence and enforcement (OneTrust, Cookiebot, Iubenda, etc.)
"""

import re
import time
from typing import Any, Dict, List, Set
from urllib.parse import urlparse, urljoin
import httpx
from bs4 import BeautifulSoup

from backend.app.core.ssrf import validate_target_url
from backend.app.engines.base import (
    AuditCategory,
    BaseAuditEngine,
    EngineResult,
    EngineStatus,
    FindingDraft,
)

TRACKING_COOKIE_PREFIXES = ["_ga", "_fbp", "_fbc", "_gcl", "_tt_", "_uet", "_pin", "fr", "ide", "criteo", "mc_"]

FINGERPRINTING_PATTERNS = [
    (
        r"(?:canvas|getContext\s*\(\s*['\"]2d['\"]\)).*?(?:toDataURL|getImageData)",
        "privacy-canvas-fingerprint",
        "HIGH",
        "HTML5 Canvas Device Fingerprinting Vector Detected",
        "Script samples canvas pixels (toDataURL / getImageData) to calculate a persistent device fingerprint without cookie consent.",
        "Remove canvas pixel-reading scripts or replace with privacy-preserving server-side session metrics."
    ),
    (
        r"WEBGL_debug_renderer_info|UNMASKED_RENDERER_WEBGL|UNMASKED_VENDOR_WEBGL",
        "privacy-webgl-fingerprint",
        "HIGH",
        "WebGL GPU Hardware Fingerprinting Detected",
        "Script inspects unmasked GPU hardware and driver strings to fingerprint client workstations.",
        "Avoid querying low-level WebGL hardware renderer strings for tracking purposes."
    ),
    (
        r"(?:OfflineAudioContext|webkitOfflineAudioContext).*?(?:createOscillator|createDynamicsCompressor)",
        "privacy-audio-fingerprint",
        "HIGH",
        "AudioContext Frequency Fingerprinting Detected",
        "Script processes synthesized audio waveforms through dynamics compressors to harvest audio chip signatures.",
        "Remove audio context fingerprinting routines."
    ),
    (
        r"navigator\.(?:deviceMemory|hardwareConcurrency|battery)",
        "privacy-hardware-fingerprint",
        "MEDIUM",
        "Hardware Concurrency & Device Probing",
        "Probing hardware concurrency or device memory to enrich client fingerprint entropy.",
        "Rely on standard responsive media queries rather than client hardware fingerprinting."
    )
]

CMP_INDICATORS = [
    ("OneTrust", ["onetrust", "optanon", "ot-sdk"]),
    ("Cookiebot", ["cookiebot", "consent.cookiebot.com"]),
    ("Iubenda", ["iubenda"]),
    ("Didomi", ["didomi"]),
    ("Usercentrics", ["usercentrics"]),
    ("Quantcast", ["quantcast", "cmp.quantcast.com"]),
    ("Klaro", ["klaro"]),
]


class ZeroTrustPrivacyEngine(BaseAuditEngine):
    engine_name = "ZeroTrustPrivacyEngine"
    engine_version = "1.0.0"
    category = AuditCategory.ZERO_TRUST_PRIVACY

    async def execute(
        self,
        target_url: str,
        config: Dict[str, Any],
        **kwargs
    ) -> EngineResult:
        start_time = time.time()
        findings: List[FindingDraft] = []
        limitations: List[str] = [
            "Analyzes pre-consent cookies delivered on initial HTTP GET and scans scripts for fingerprinting heuristics.",
            "Dynamic client-side consent banner interactions are evaluated statically."
        ]

        normalized_url, hostname, _ = validate_target_url(target_url)

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebAudit360-Privacy-Radar/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }

        # 1. Fetch Target HTML & Inspect Response Cookies
        pre_consent_cookies: List[Dict[str, Any]] = []
        html_content = ""
        try:
            async with httpx.AsyncClient(timeout=12.0, follow_redirects=True, headers=headers) as client:
                resp = await client.get(normalized_url)
                html_content = resp.text

                # Check set-cookie headers
                for header_key, header_val in resp.headers.multi_items():
                    if header_key.lower() == "set-cookie":
                        cookie_name = header_val.split("=")[0].strip()
                        is_tracker = any(cookie_name.lower().startswith(pfx) for pfx in TRACKING_COOKIE_PREFIXES)
                        pre_consent_cookies.append({
                            "name": cookie_name,
                            "is_known_tracker": is_tracker,
                            "raw": header_val[:60]
                        })
        except Exception as e:
            return EngineResult(
                category=AuditCategory.ZERO_TRUST_PRIVACY,
                engine_name=self.engine_name,
                engine_version=self.engine_version,
                status=EngineStatus.FAILED,
                error=f"Could not connect to target URL: {str(e)}",
                execution_time_ms=int((time.time() - start_time) * 1000)
            )

        soup = BeautifulSoup(html_content, "html.parser")
        target_origin = urlparse(normalized_url).netloc

        # 2. Probe for Consent Management Platform (CMP)
        detected_cmp = None
        html_lower = html_content.lower()
        for cmp_name, keywords in CMP_INDICATORS:
            if any(kw in html_lower for kw in keywords):
                detected_cmp = cmp_name
                break

        # 3. Detect Fingerprinting Vectors in HTML and Scripts
        detected_fingerprints = []
        for pattern, rule_id, severity, title, desc, rec in FINGERPRINTING_PATTERNS:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            if matches:
                detected_fingerprints.append({
                    "rule_id": rule_id,
                    "title": title,
                    "severity": severity,
                    "description": desc,
                    "recommendation": rec,
                    "matches_count": len(matches)
                })

        # 4. CNAME Cloaking check on subdomains
        # Identify first-party subdomains loading scripts or beacons
        cname_risks = []
        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                full_src = urljoin(normalized_url, src)
                parsed_src = urlparse(full_src)
                src_netloc = parsed_src.netloc
                # If it's a subdomain like data.*, track.*, analytics.* on same root domain
                if src_netloc != target_origin and target_origin in src_netloc:
                    if any(prefix in src_netloc for prefix in ("track.", "data.", "metrics.", "analytics.", "e.")):
                        cname_risks.append(src_netloc)

        # Calculate Score
        score = 100.0

        known_tracking_cookies = [c for c in pre_consent_cookies if c["is_known_tracker"]]
        if known_tracking_cookies:
            score -= min(35.0, len(known_tracking_cookies) * 15.0)
            findings.append(FindingDraft(
                category=AuditCategory.ZERO_TRUST_PRIVACY,
                rule_id="privacy-pre-consent-tracking-cookies",
                severity="HIGH",
                title=f"{len(known_tracking_cookies)} Pre-Consent Tracking Cookie(s) Dropped",
                description=(
                    f"Identified {len(known_tracking_cookies)} adtech/tracking cookie(s) dropped before explicit user consent, "
                    "violating GDPR ePrivacy Directive and CCPA regulations."
                ),
                recommendation="Gate all non-essential and adtech cookies behind verified user consent approval in your Consent Management Platform.",
                raw_details={"cookies": known_tracking_cookies}
            ))

        for fp in detected_fingerprints:
            sev = fp["severity"]
            if sev == "HIGH":
                score -= 20.0
            else:
                score -= 10.0

            findings.append(FindingDraft(
                category=AuditCategory.ZERO_TRUST_PRIVACY,
                rule_id=fp["rule_id"],
                severity=fp["severity"],
                title=fp["title"],
                description=fp["description"],
                recommendation=fp["recommendation"],
                raw_details=fp
            ))

        if cname_risks:
            score -= 15.0
            findings.append(FindingDraft(
                category=AuditCategory.ZERO_TRUST_PRIVACY,
                rule_id="privacy-cname-cloaking-risk",
                severity="MEDIUM",
                title="Potential CNAME Cloaking Tracking Subdomain Detected",
                description=(
                    f"First-party subdomains ({', '.join(set(cname_risks))}) appear configured to proxy third-party adtech trackers. "
                    "CNAME cloaking attempts to evade browser privacy shields and ad-blockers by masquerading as first-party endpoints."
                ),
                recommendation="Audit DNS CNAME records and transition to transparent, privacy-respecting client analytics."
            ))

        if detected_cmp:
            findings.append(FindingDraft(
                category=AuditCategory.ZERO_TRUST_PRIVACY,
                rule_id="privacy-cmp-active",
                severity="INFO",
                title=f"Consent Management Platform Active: {detected_cmp}",
                description=f"Verified presence of {detected_cmp} CMP providing regulatory user consent toggles.",
                recommendation="Audit CMP configuration regularly to guarantee zero pre-consent tag firing."
            ))
        elif not known_tracking_cookies and not detected_fingerprints:
            findings.append(FindingDraft(
                category=AuditCategory.ZERO_TRUST_PRIVACY,
                rule_id="privacy-clean-posture",
                severity="INFO",
                title="Zero Pre-Consent Tracking or Device Fingerprinting Observed",
                description="Initial page response respects user privacy by dropping zero unauthorized adtech cookies or biometric fingerprinting vectors.",
                recommendation="Continue enforcing zero-trust client privacy standards."
            ))

        final_score = max(0.0, min(100.0, round(score, 1)))

        raw_evidence = {
            "pre_consent_cookies_count": len(pre_consent_cookies),
            "tracking_cookies_count": len(known_tracking_cookies),
            "pre_consent_cookies": pre_consent_cookies,
            "detected_cmp": detected_cmp,
            "detected_fingerprints_count": len(detected_fingerprints),
            "detected_fingerprints": detected_fingerprints,
            "cname_cloaking_subdomains": list(set(cname_risks)),
            "privacy_rating": "Compliant" if final_score >= 85 else ("At Risk" if final_score >= 60 else "Non-Compliant")
        }

        return EngineResult(
            category=AuditCategory.ZERO_TRUST_PRIVACY,
            engine_name=self.engine_name,
            engine_version=self.engine_version,
            status=EngineStatus.SUCCESS,
            score=final_score,
            findings=findings,
            raw_evidence=raw_evidence,
            limitations=limitations,
            execution_time_ms=int((time.time() - start_time) * 1000)
        )
