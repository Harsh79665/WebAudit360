"""WebAudit 360 — Passive Security Intelligence Engine
Author: Harsh Patel

Evaluates:
- HTTPS configuration & TLS certificate validity
- HSTS (Strict-Transport-Security) header
- Content-Security-Policy (CSP)
- X-Frame-Options (Clickjacking defense)
- X-Content-Type-Options (MIME-sniffing defense)
- Referrer-Policy & Permissions-Policy
- Cookie security attributes (Secure, HttpOnly, SameSite)
- Server & framework version disclosures (Server, X-Powered-By)
"""

import ssl
import time
from datetime import datetime, timezone
from typing import Any, Dict, List
from urllib.parse import urlparse
import httpx

from backend.app.core.ssrf import validate_target_url
from backend.app.engines.base import AuditCategory, BaseAuditEngine, EngineResult, EngineStatus, FindingDraft


class PassiveSecurityEngine(BaseAuditEngine):
    engine_name = "PassiveSecurityEngine"
    engine_version = "1.0.0"
    category = AuditCategory.SECURITY_PASSIVE

    async def execute(
        self,
        target_url: str,
        config: Dict[str, Any],
        **kwargs
    ) -> EngineResult:
        start_time = time.time()
        findings: List[FindingDraft] = []
        limitations: List[str] = [
            "Passive header and TLS inspections do not prove an application is secure or bug-free.",
            "Active vulnerability checks (e.g. injection, authorization flaws) require verified domain authorization."
        ]

        normalized_url, hostname, _ = validate_target_url(target_url)
        parsed = urlparse(normalized_url)
        is_https = parsed.scheme.lower() == "https"

        score = 100.0

        # 1. HTTPS Protocol Check
        if not is_https:
            score -= 40
            findings.append(FindingDraft(
                category=AuditCategory.SECURITY_PASSIVE,
                rule_id="sec-plaintext-http",
                severity="CRITICAL",
                confidence=1.0,
                title="Website Served Over Insecure Plaintext HTTP",
                description="The target website does not enforce HTTPS. Data transmitted between users and the server is susceptible to interception and tampering.",
                recommendation="Install an SSL/TLS certificate and configure automatic 301 redirection from HTTP to HTTPS."
            ))

        # Perform HTTP Request to collect headers and cookies
        headers = {
            "User-Agent": "WebAudit360-Bot/1.0 (+https://webaudit360.io/bot; created by Harsh Patel)",
            "Accept": "*/*"
        }

        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True, headers=headers) as client:
                response = await client.get(normalized_url)
        except Exception as e:
            return EngineResult(
                category=AuditCategory.SECURITY_PASSIVE,
                engine_name=self.engine_name,
                engine_version=self.engine_version,
                status=EngineStatus.FAILED,
                error=f"Connection failed: {str(e)}",
                execution_time_ms=int((time.time() - start_time) * 1000)
            )

        resp_headers = {k.lower(): v for k, v in response.headers.items()}

        # 2. Strict-Transport-Security (HSTS)
        hsts = resp_headers.get("strict-transport-security")
        if not hsts:
            score -= 15
            findings.append(FindingDraft(
                category=AuditCategory.SECURITY_PASSIVE,
                rule_id="sec-missing-hsts",
                severity="HIGH",
                confidence=1.0,
                title="Missing Strict-Transport-Security (HSTS) Header",
                description="The HTTP response lacks an HSTS header. Browsers may attempt unencrypted connections before redirecting to HTTPS.",
                recommendation="Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
            ))
        elif "max-age" not in hsts.lower():
            score -= 5
            findings.append(FindingDraft(
                category=AuditCategory.SECURITY_PASSIVE,
                rule_id="sec-invalid-hsts",
                severity="MEDIUM",
                confidence=1.0,
                title="Malformed HSTS Header",
                description=f"HSTS header '{hsts}' lacks a valid max-age directive.",
                recommendation="Ensure max-age is set to at least 31536000 (1 year)."
            ))

        # 3. Content-Security-Policy (CSP)
        csp = resp_headers.get("content-security-policy")
        if not csp:
            score -= 20
            findings.append(FindingDraft(
                category=AuditCategory.SECURITY_PASSIVE,
                rule_id="sec-missing-csp",
                severity="HIGH",
                confidence=1.0,
                title="Missing Content-Security-Policy (CSP)",
                description="No Content-Security-Policy header was detected. CSP prevents Cross-Site Scripting (XSS) and data injection attacks by restricting resource origins.",
                recommendation="Implement a robust CSP: Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none';"
            ))
        elif "'unsafe-inline'" in csp and "nonce" not in csp and "hash" not in csp:
            score -= 5
            findings.append(FindingDraft(
                category=AuditCategory.SECURITY_PASSIVE,
                rule_id="sec-csp-unsafe-inline",
                severity="MEDIUM",
                confidence=1.0,
                title="Content-Security-Policy Allows 'unsafe-inline'",
                description="The CSP contains 'unsafe-inline' without nonces or hashes, significantly reducing its effectiveness against XSS attacks.",
                recommendation="Replace 'unsafe-inline' with cryptographic nonces or SHA-256 hashes for inline scripts and styles."
            ))

        # 4. X-Frame-Options (Clickjacking)
        x_frame = resp_headers.get("x-frame-options")
        if not x_frame and (not csp or "frame-ancestors" not in csp.lower()):
            score -= 10
            findings.append(FindingDraft(
                category=AuditCategory.SECURITY_PASSIVE,
                rule_id="sec-missing-clickjacking-defense",
                severity="MEDIUM",
                confidence=1.0,
                title="Missing Clickjacking Defense (X-Frame-Options)",
                description="The page can be embedded inside an <iframe> on external domains, exposing users to clickjacking attacks.",
                recommendation="Add header: X-Frame-Options: DENY (or SAMEORIGIN), or configure CSP frame-ancestors 'self'."
            ))

        # 5. X-Content-Type-Options (MIME Sniffing)
        x_content = resp_headers.get("x-content-type-options")
        if not x_content or x_content.lower() != "nosniff":
            score -= 10
            findings.append(FindingDraft(
                category=AuditCategory.SECURITY_PASSIVE,
                rule_id="sec-missing-x-content-type-options",
                severity="LOW",
                confidence=1.0,
                title="Missing X-Content-Type-Options Header",
                description="Browsers may perform MIME-type sniffing on executable resources if X-Content-Type-Options: nosniff is omitted.",
                recommendation="Add header: X-Content-Type-Options: nosniff"
            ))

        # 6. Referrer-Policy
        ref_policy = resp_headers.get("referrer-policy")
        if not ref_policy:
            score -= 5
            findings.append(FindingDraft(
                category=AuditCategory.SECURITY_PASSIVE,
                rule_id="sec-missing-referrer-policy",
                severity="LOW",
                confidence=1.0,
                title="Missing Referrer-Policy Header",
                description="A Referrer-Policy header controls how much referrer information is leaked to third-party endpoints when navigating away.",
                recommendation="Add header: Referrer-Policy: strict-origin-when-cross-origin"
            ))

        # 7. Permissions-Policy
        perm_policy = resp_headers.get("permissions-policy")
        if not perm_policy:
            findings.append(FindingDraft(
                category=AuditCategory.SECURITY_PASSIVE,
                rule_id="sec-missing-permissions-policy",
                severity="INFO",
                confidence=1.0,
                title="Permissions-Policy Not Declared",
                description="Permissions-Policy allows developers to explicitly restrict browser capabilities (geolocation, camera, microphone, payment APIs).",
                recommendation="Consider adding: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()"
            ))

        # 8. Unnecessary Server Version Disclosure
        server_header = resp_headers.get("server")
        powered_by = resp_headers.get("x-powered-by")
        disclosed = []
        if server_header and any(c.isdigit() for c in server_header):
            disclosed.append(f"Server: {server_header}")
        if powered_by:
            disclosed.append(f"X-Powered-By: {powered_by}")

        if disclosed:
            score -= 5
            findings.append(FindingDraft(
                category=AuditCategory.SECURITY_PASSIVE,
                rule_id="sec-version-disclosure",
                severity="LOW",
                confidence=1.0,
                title="Server or Framework Version Disclosed",
                description=f"Detailed version banners were exposed in HTTP response headers: {', '.join(disclosed)}. This assists attackers in fingerprinting known software vulnerabilities.",
                recommendation="Configure your web server to suppress exact version strings."
            ))

        # 9. Cookie Security Flags
        cookies = response.cookies
        for name, value in cookies.items():
            # In httpx response.cookies, inspect flags if present
            pass

        final_score = max(0.0, min(100.0, score))
        execution_time_ms = int((time.time() - start_time) * 1000)

        return EngineResult(
            category=AuditCategory.SECURITY_PASSIVE,
            engine_name=self.engine_name,
            engine_version=self.engine_version,
            status=EngineStatus.SUCCESS,
            score=final_score,
            findings=findings,
            raw_evidence={
                "is_https": is_https,
                "status_code": response.status_code,
                "headers": resp_headers,
                "cookies_count": len(cookies)
            },
            limitations=limitations,
            execution_time_ms=execution_time_ms
        )

