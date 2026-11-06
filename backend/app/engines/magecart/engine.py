"""WebAudit 360 — Client-Side Magecart & Runtime Exfiltration Sandbox Engine
Author: Harsh Patel

Evaluates:
- Sensitive form input vulnerability (password, credit card, CVV, billing address)
- Formjacking & DOM listener manipulation risk
- Dangerous runtime JavaScript patterns (eval, atob, Function constructor, String.fromCharCode unpacking)
- Third-party script provenance & untrusted CDN origins
- Data exfiltration avenues (unrestricted CSP connect-src, sendBeacon, WebSocket destinations)
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


SUSPICIOUS_OBFUSCATION_PATTERNS = [
    (r"\beval\s*\(", "eval_execution", "Dynamic string execution via eval()"),
    (r"\bFunction\s*\(\s*['\"]", "function_constructor", "Dynamic code generation via Function constructor"),
    (r"atob\s*\([A-Za-z0-9+/=]{40,}\)", "base64_payload", "Base64 encoded payload unpacking via atob()"),
    (r"String\.fromCharCode\s*\((?:\s*\d+\s*,\s*){8,}", "from_char_code", "Obfuscated character-code payload decoding"),
    (r"document\.cookie\b.*?=\s*.*?(?:fetch|sendBeacon|XMLHttpRequest)", "cookie_exfiltration", "Direct cookie extraction tied to network dispatch"),
    (r"(?:addEventListener|attachEvent)\s*\(\s*['\"](?:keypress|keydown|keyup|input)['\"]", "keystroke_hook", "Keystroke event listener hooking input fields"),
]

SENSITIVE_INPUT_KEYWORDS = ["card", "cvv", "cvc", "credit", "cc-", "exp", "password", "ssn", "billing", "bank", "account"]

WELL_KNOWN_TRUSTED_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com", "googletagmanager.com",
    "cloudflare.com", "cdnjs.cloudflare.com", "stripe.com", "paypal.com",
    "jsdelivr.net", "unpkg.com", "github.com", "facebook.net"
}


class MagecartEngine(BaseAuditEngine):
    engine_name = "MagecartEngine"
    engine_version = "1.0.0"
    category = AuditCategory.SECURITY_MAGECART

    async def execute(
        self,
        target_url: str,
        config: Dict[str, Any],
        **kwargs
    ) -> EngineResult:
        start_time = time.time()
        findings: List[FindingDraft] = []
        limitations: List[str] = [
            "Passive and static sandbox inspection of DOM, CSP, and loaded script assets.",
            "Polymorphic runtime payloads delivered conditionally to specific geo-IPs may require continuous synthetic session recording."
        ]

        normalized_url, hostname, _ = validate_target_url(target_url)

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebAudit360-Magecart-Sandbox/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }

        try:
            async with httpx.AsyncClient(timeout=12.0, follow_redirects=True, headers=headers) as client:
                resp = await client.get(normalized_url)
                html_content = resp.text
                response_headers = {k.lower(): v for k, v in resp.headers.items()}
        except Exception as e:
            return EngineResult(
                category=AuditCategory.SECURITY_MAGECART,
                engine_name=self.engine_name,
                engine_version=self.engine_version,
                status=EngineStatus.FAILED,
                error=f"Could not connect to target URL: {str(e)}",
                execution_time_ms=int((time.time() - start_time) * 1000)
            )

        soup = BeautifulSoup(html_content, "html.parser")
        parsed_target = urlparse(normalized_url)
        target_domain = parsed_target.netloc

        # 1. Audit Sensitive Inputs
        sensitive_inputs = []
        for inp in soup.find_all(["input", "textarea", "select"]):
            inp_type = (inp.get("type") or "text").lower()
            inp_name = (inp.get("name") or "").lower()
            inp_id = (inp.get("id") or "").lower()
            inp_autocomplete = (inp.get("autocomplete") or "").lower()

            is_sensitive = (
                inp_type == "password" or
                any(kw in inp_name for kw in SENSITIVE_INPUT_KEYWORDS) or
                any(kw in inp_id for kw in SENSITIVE_INPUT_KEYWORDS) or
                any(kw in inp_autocomplete for kw in SENSITIVE_INPUT_KEYWORDS)
            )
            if is_sensitive:
                sensitive_inputs.append({
                    "tag": inp.name,
                    "type": inp_type,
                    "name": inp_name,
                    "id": inp_id
                })

        # 2. CSP connect-src / script-src Audit
        csp_header = response_headers.get("content-security-policy", "")
        has_csp = bool(csp_header)
        has_connect_src = "connect-src" in csp_header.lower()
        has_script_src = "script-src" in csp_header.lower()

        # 3. Third-party script provenance
        third_party_scripts = []
        untrusted_scripts = []
        inline_script_bodies = []

        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                full_src = urljoin(normalized_url, src)
                script_netloc = urlparse(full_src).netloc
                if script_netloc and script_netloc != target_domain:
                    third_party_scripts.append(full_src)
                    # Check against known trusted CDNs
                    is_known = any(script_netloc == trusted or script_netloc.endswith("." + trusted) for trusted in WELL_KNOWN_TRUSTED_DOMAINS)
                    if not is_known:
                        untrusted_scripts.append(full_src)
            else:
                body = script.string or ""
                if body.strip():
                    inline_script_bodies.append(body)

        # 4. Pattern inspection for obfuscation and exfiltration in inline scripts and raw HTML
        detected_patterns = []
        combined_text = html_content
        for pattern, pattern_id, desc in SUSPICIOUS_OBFUSCATION_PATTERNS:
            matches = re.findall(pattern, combined_text, re.IGNORECASE)
            if matches:
                detected_patterns.append({
                    "pattern_id": pattern_id,
                    "description": desc,
                    "match_count": len(matches)
                })

        # Calculate Score & Formulate Findings
        score = 100.0

        if sensitive_inputs and not has_connect_src:
            score -= 25.0
            findings.append(FindingDraft(
                category=AuditCategory.SECURITY_MAGECART,
                rule_id="magecart-sensitive-inputs-unprotected-csp",
                severity="HIGH",
                title="Sensitive Payment/Credential Form Lacks CSP connect-src Isolation",
                description=(
                    f"Found {len(sensitive_inputs)} sensitive credential/payment input field(s), but Content Security Policy (CSP) "
                    "omits a strict 'connect-src' directive. Malicious skimmers can freely exfiltrate harvested keystrokes to rogue endpoints."
                ),
                recommendation="Deploy a strict CSP 'connect-src' directive restricting outbound XMLHttpRequest, fetch, and WebSocket destinations.",
                raw_details={"sensitive_input_count": len(sensitive_inputs), "inputs": sensitive_inputs[:5]}
            ))

        if untrusted_scripts:
            score -= min(30.0, len(untrusted_scripts) * 10.0)
            findings.append(FindingDraft(
                category=AuditCategory.SECURITY_MAGECART,
                rule_id="magecart-untrusted-third-party-scripts",
                severity="MEDIUM",
                title=f"{len(untrusted_scripts)} Third-Party Scripts from Unverified Origins",
                description=(
                    f"Loaded {len(untrusted_scripts)} external JavaScript assets from unverified or unknown third-party domains. "
                    "Supply chain attacks frequently compromise unmanaged foreign CDN assets."
                ),
                recommendation="Enforce Subresource Integrity (SRI) hashes on all external scripts or vendor the assets locally.",
                evidence_snippet="\n".join(untrusted_scripts[:5]),
                raw_details={"untrusted_scripts": untrusted_scripts}
            ))

        high_risk_patterns = [p for p in detected_patterns if p["pattern_id"] in ("eval_execution", "base64_payload", "keystroke_hook")]
        if high_risk_patterns:
            score -= min(35.0, len(high_risk_patterns) * 15.0)
            findings.append(FindingDraft(
                category=AuditCategory.SECURITY_MAGECART,
                rule_id="magecart-suspicious-obfuscation-patterns",
                severity="HIGH",
                title="Potential Skimming / Obfuscated Runtime Behavior Detected",
                description="Identified suspicious runtime patterns (eval, base64 payload unpacking, or input hook listeners) characteristic of client-side skimmers.",
                recommendation="Audit bundled JavaScript sources for unauthorized code injections and remove dynamic eval() usage.",
                raw_details={"detected_patterns": high_risk_patterns}
            ))
        elif not sensitive_inputs and not untrusted_scripts:
            findings.append(FindingDraft(
                category=AuditCategory.SECURITY_MAGECART,
                rule_id="magecart-posture-clean",
                severity="INFO",
                title="Clean Client-Side Skimming & Supply-Chain Posture",
                description="Zero malicious DOM hooking patterns or unvetted foreign CDN dependencies observed.",
                recommendation="Maintain strict Subresource Integrity and least-privilege CSP policies."
            ))

        final_score = max(0.0, min(100.0, round(score, 1)))

        raw_evidence = {
            "sensitive_inputs_count": len(sensitive_inputs),
            "sensitive_inputs": sensitive_inputs,
            "has_csp": has_csp,
            "has_connect_src": has_connect_src,
            "has_script_src": has_script_src,
            "third_party_scripts_count": len(third_party_scripts),
            "untrusted_scripts_count": len(untrusted_scripts),
            "untrusted_scripts": untrusted_scripts,
            "detected_obfuscation_patterns": detected_patterns,
            "risk_level": "High" if final_score < 60 else ("Medium" if final_score < 80 else "Low")
        }

        return EngineResult(
            category=AuditCategory.SECURITY_MAGECART,
            engine_name=self.engine_name,
            engine_version=self.engine_version,
            status=EngineStatus.SUCCESS,
            score=final_score,
            findings=findings,
            raw_evidence=raw_evidence,
            limitations=limitations,
            execution_time_ms=int((time.time() - start_time) * 1000)
        )
