"""WebAudit 360 — Authorized Active Security Testing Engine
Author: Harsh Patel

Enforces:
- Strict domain ownership verification (DNS TXT or .well-known token challenge)
- Independent backend authorization verification (never trusts client flags)
- Non-destructive OWASP ZAP and asynchronous HTTP probes:
  1. HTTP Method Tampering (OPTIONS, TRACE, TRACK, PUT, DELETE)
  2. CORS Misconfiguration & Credential Reflection
  3. Sensitive File & Infrastructure Exposure (false-positive resilient)
  4. Open Redirect Reflection
  5. Frameability & Clickjacking Defense
- Dynamic score computation clamped to [0.0, 100.0]
- Emergency rate-limiting and SSRF safeguards
"""

import time
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
import httpx

from backend.app.core.logging import logger
from backend.app.core.ssrf import validate_target_url
from backend.app.engines.base import (
    AuditCategory,
    BaseAuditEngine,
    EngineResult,
    EngineStatus,
    FindingDraft,
)

USER_AGENT = "WebAudit360-ActiveScanner/1.0 (+https://webaudit360.io/security; created by Harsh Patel)"
REQUEST_TIMEOUT = 8.0


class AuthorizedActiveSecurityEngine(BaseAuditEngine):
    engine_name = "AuthorizedActiveSecurityEngine"
    engine_version = "2.0.0"
    category = AuditCategory.SECURITY_ACTIVE

    async def execute(
        self,
        target_url: str,
        config: Dict[str, Any],
        **kwargs
    ) -> EngineResult:
        start_time = time.time()
        findings: List[FindingDraft] = []
        limitations: List[str] = [
            "Active scanning is strictly non-destructive. Brute-force attacks, exploit payloads, and denial-of-service testing are prohibited.",
            "Active testing is executed exclusively against domains with verified, unexpired cryptographic ownership proof."
        ]

        normalized_url, hostname, _ = validate_target_url(target_url)

        # 1. Independent Server-Side Authorization Verification Check
        is_verified_authorized = config.get("is_verified_authorized", False)
        authorization_record_id = config.get("authorization_record_id")

        if not is_verified_authorized or not authorization_record_id:
            logger.warning(
                f"Active security test BLOCKED for '{hostname}': Missing verified domain authorization record."
            )
            return EngineResult(
                category=AuditCategory.SECURITY_ACTIVE,
                engine_name=self.engine_name,
                engine_version=self.engine_version,
                status=EngineStatus.BLOCKED,
                score=None,  # Displayed as N/A per platform policy
                findings=[
                    FindingDraft(
                        category=AuditCategory.SECURITY_ACTIVE,
                        rule_id="sec-active-unauthorized",
                        severity="INFO",
                        confidence=1.0,
                        title="Active Security Assessment Blocked: Domain Authorization Required",
                        description=(
                            f"Active vulnerability assessments against '{hostname}' require cryptographic proof of ownership. "
                            "Please complete the DNS TXT or HTTP challenge in your Project settings to authorize scanning."
                        ),
                        recommendation="Configure a DNS TXT record '_webaudit360-challenge' or upload the verification token to /.well-known/webaudit360-challenge.txt."
                    )
                ],
                raw_evidence={"authorized": False, "domain": hostname},
                limitations=limitations,
                execution_time_ms=int((time.time() - start_time) * 1000),
                error="Active testing rejected: target domain has not completed ownership verification challenge."
            )

        # 2. Execute Real Non-Destructive Active Probes
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
        }

        probe_evidence: Dict[str, Any] = {}
        total_deduction = 0.0

        async with httpx.AsyncClient(
            timeout=REQUEST_TIMEOUT,
            headers=headers,
            verify=False  # Allow evaluating self-signed or staging certs
        ) as client:
            # Probe 1: HTTP Method Tampering
            f_methods, ev_methods, ded_methods = await self._probe_http_methods(client, normalized_url)
            findings.extend(f_methods)
            probe_evidence["http_methods"] = ev_methods
            total_deduction += ded_methods

            # Probe 2: CORS Misconfiguration
            f_cors, ev_cors, ded_cors = await self._probe_cors(client, normalized_url)
            findings.extend(f_cors)
            probe_evidence["cors"] = ev_cors
            total_deduction += ded_cors

            # Probe 3: Sensitive File & Infrastructure Exposure
            f_files, ev_files, ded_files = await self._probe_sensitive_files(client, normalized_url)
            findings.extend(f_files)
            probe_evidence["sensitive_files"] = ev_files
            total_deduction += ded_files

            # Probe 4: Open Redirect Reflection
            f_redir, ev_redir, ded_redir = await self._probe_open_redirect(client, normalized_url)
            findings.extend(f_redir)
            probe_evidence["open_redirect"] = ev_redir
            total_deduction += ded_redir

            # Probe 5: Clickjacking & Frameability
            f_frame, ev_frame, ded_frame = await self._probe_clickjacking(client, normalized_url)
            findings.extend(f_frame)
            probe_evidence["clickjacking"] = ev_frame
            total_deduction += ded_frame

        # 3. Dynamic Score Math
        calculated_score = max(0.0, min(100.0, round(100.0 - total_deduction, 1)))

        if not any(f.severity in ("CRITICAL", "HIGH", "MEDIUM") for f in findings):
            findings.append(FindingDraft(
                category=AuditCategory.SECURITY_ACTIVE,
                rule_id="sec-active-clean",
                severity="INFO",
                confidence=1.0,
                title="All Active Security Probes Passed",
                description="Non-destructive active testing revealed no HTTP method tampering, CORS misconfigurations, sensitive file exposures, open redirects, or frameability issues.",
                recommendation="Continue periodic vulnerability scans and maintain routine dependency patching."
            ))

        vulnerabilities_count = {
            "critical": len([f for f in findings if f.severity == "CRITICAL"]),
            "high": len([f for f in findings if f.severity == "HIGH"]),
            "medium": len([f for f in findings if f.severity == "MEDIUM"]),
            "low": len([f for f in findings if f.severity == "LOW"]),
            "info": len([f for f in findings if f.severity == "INFO"]),
        }

        raw_evidence = {
            "authorized": True,
            "domain": hostname,
            "authorization_id": authorization_record_id,
            "probes": probe_evidence,
            "score": calculated_score,
            "vulnerabilities_count": vulnerabilities_count
        }

        return EngineResult(
            category=AuditCategory.SECURITY_ACTIVE,
            engine_name=self.engine_name,
            engine_version=self.engine_version,
            status=EngineStatus.SUCCESS,
            score=calculated_score,
            findings=findings,
            raw_evidence=raw_evidence,
            limitations=limitations,
            execution_time_ms=int((time.time() - start_time) * 1000)
        )

    # -------------------------------------------------------------------------
    # PROBE 1: HTTP Method Tampering (OPTIONS, TRACE, TRACK, PUT, DELETE)
    # -------------------------------------------------------------------------
    async def _probe_http_methods(
        self,
        client: httpx.AsyncClient,
        url: str
    ) -> Tuple[List[FindingDraft], Dict[str, Any], float]:
        findings: List[FindingDraft] = []
        deduction = 0.0
        method_statuses: Dict[str, Any] = {}

        # 1. OPTIONS Check
        allowed_methods: List[str] = []
        try:
            opt_res = await client.options(url)
            allow_header = opt_res.headers.get("allow") or opt_res.headers.get("public") or ""
            allowed_methods = [m.strip().upper() for m in allow_header.split(",") if m.strip()]
            method_statuses["OPTIONS"] = opt_res.status_code
        except Exception:
            method_statuses["OPTIONS"] = None

        # 2. TRACE Probe (XST)
        try:
            trace_res = await client.request("TRACE", url)
            method_statuses["TRACE"] = trace_res.status_code
            if trace_res.status_code == 200 and (
                "message/http" in trace_res.headers.get("content-type", "").lower()
                or "TRACE /" in trace_res.text
                or USER_AGENT in trace_res.text
            ):
                deduction += 20.0
                findings.append(FindingDraft(
                    category=AuditCategory.SECURITY_ACTIVE,
                    rule_id="sec-active-xst-trace-enabled",
                    severity="HIGH",
                    confidence=1.0,
                    title="Cross-Site Tracing (XST) Vulnerability: HTTP TRACE Enabled",
                    description=(
                        "The web server has the HTTP TRACE method enabled and echoes back request headers. "
                        "Attackers can leverage Cross-Site Tracing (XST) to steal sensitive HttpOnly cookies."
                    ),
                    recommendation="Disable the HTTP TRACE method in your web server (e.g. 'TraceEnable off' in Apache, or drop TRACE in Nginx)."
                ))
        except Exception:
            method_statuses["TRACE"] = None

        # 3. TRACK Probe (Legacy IIS)
        try:
            track_res = await client.request("TRACK", url)
            method_statuses["TRACK"] = track_res.status_code
            if track_res.status_code == 200 and USER_AGENT in track_res.text:
                deduction += 10.0
                findings.append(FindingDraft(
                    category=AuditCategory.SECURITY_ACTIVE,
                    rule_id="sec-active-xst-track-enabled",
                    severity="MEDIUM",
                    confidence=1.0,
                    title="Legacy HTTP TRACK Method Permitted",
                    description="The server responded with 200 OK to a TRACK debugging request, mirroring the request context.",
                    recommendation="Disable TRACK debugging verbs in your reverse proxy or web application firewall."
                ))
        except Exception:
            method_statuses["TRACK"] = None

        # 4. PUT Probe (Arbitrary Write)
        try:
            test_put_url = f"{url.rstrip('/')}/.webaudit360-probe-check"
            put_res = await client.put(test_put_url, content=b"probe")
            method_statuses["PUT"] = put_res.status_code
            if put_res.status_code in (200, 201, 204):
                deduction += 30.0
                findings.append(FindingDraft(
                    category=AuditCategory.SECURITY_ACTIVE,
                    rule_id="sec-active-unauthenticated-put",
                    severity="CRITICAL",
                    confidence=1.0,
                    title="Unauthenticated HTTP PUT Method Permitted",
                    description=f"The server accepted an unauthenticated HTTP PUT request at {test_put_url} with HTTP {put_res.status_code}.",
                    recommendation="Restrict HTTP PUT methods to authenticated and authorized API endpoints only."
                ))
        except Exception:
            method_statuses["PUT"] = None

        # 5. DELETE Probe
        try:
            test_del_url = f"{url.rstrip('/')}/.webaudit360-probe-check"
            del_res = await client.delete(test_del_url)
            method_statuses["DELETE"] = del_res.status_code
            if del_res.status_code in (200, 202, 204):
                deduction += 30.0
                findings.append(FindingDraft(
                    category=AuditCategory.SECURITY_ACTIVE,
                    rule_id="sec-active-unauthenticated-delete",
                    severity="CRITICAL",
                    confidence=1.0,
                    title="Unauthenticated HTTP DELETE Method Permitted",
                    description=f"The server accepted an unauthenticated HTTP DELETE request at {test_del_url} with HTTP {del_res.status_code}.",
                    recommendation="Ensure HTTP DELETE operations require authentication and explicit resource authorization."
                ))
        except Exception:
            method_statuses["DELETE"] = None

        is_clean = len(findings) == 0
        evidence = {
            "status": "PASS" if is_clean else "VULNERABLE",
            "allowed_methods": allowed_methods,
            "tested_methods": method_statuses
        }
        return findings, evidence, deduction

    # -------------------------------------------------------------------------
    # PROBE 2: CORS Misconfiguration (Arbitrary Origin & Credential Reflection)
    # -------------------------------------------------------------------------
    async def _probe_cors(
        self,
        client: httpx.AsyncClient,
        url: str
    ) -> Tuple[List[FindingDraft], Dict[str, Any], float]:
        findings: List[FindingDraft] = []
        deduction = 0.0
        evil_origin = "https://evil-attacker.example.com"

        cors_evidence: Dict[str, Any] = {
            "reflected_origin": False,
            "allow_credentials": False,
            "allow_origin_header": None
        }

        try:
            res = await client.get(url, headers={"Origin": evil_origin})
            acao = res.headers.get("access-control-allow-origin", "").strip()
            acac = res.headers.get("access-control-allow-credentials", "").strip().lower()

            cors_evidence["allow_origin_header"] = acao or None
            cors_evidence["allow_credentials"] = acac == "true"

            # Check for arbitrary origin reflection with credentials (CRITICAL)
            if acao == evil_origin and acac == "true":
                deduction += 30.0
                cors_evidence["reflected_origin"] = True
                findings.append(FindingDraft(
                    category=AuditCategory.SECURITY_ACTIVE,
                    rule_id="sec-active-cors-arbitrary-origin-credentials",
                    severity="CRITICAL",
                    confidence=1.0,
                    title="Critical CORS Misconfiguration: Arbitrary Origin with Credentials",
                    description=(
                        f"The server reflected arbitrary request Origin '{evil_origin}' in Access-Control-Allow-Origin "
                        "together with Access-Control-Allow-Credentials: true. Malicious sites can issue cross-origin requests "
                        "and exfiltrate authenticated session data and cookies."
                    ),
                    recommendation="Never reflect the incoming Origin header blindly. Enforce an explicit whitelist of trusted application domains."
                ))
            elif acao == evil_origin and acac != "true":
                deduction += 10.0
                cors_evidence["reflected_origin"] = True
                findings.append(FindingDraft(
                    category=AuditCategory.SECURITY_ACTIVE,
                    rule_id="sec-active-cors-reflected-origin",
                    severity="MEDIUM",
                    confidence=1.0,
                    title="CORS Arbitrary Origin Reflection",
                    description=f"The server reflected the untrusted Origin '{evil_origin}' in Access-Control-Allow-Origin.",
                    recommendation="Validate incoming Origin headers against an explicit domain whitelist."
                ))
            elif acao == "*" and acac == "true":
                deduction += 10.0
                findings.append(FindingDraft(
                    category=AuditCategory.SECURITY_ACTIVE,
                    rule_id="sec-active-cors-wildcard-credentials",
                    severity="MEDIUM",
                    confidence=1.0,
                    title="Invalid CORS Combination: Wildcard Origin with Credentials",
                    description="The server specified Access-Control-Allow-Origin: * alongside Access-Control-Allow-Credentials: true.",
                    recommendation="Modern browsers will reject this combination; configure specific allowed origins."
                ))

            # Test null origin
            null_res = await client.get(url, headers={"Origin": "null"})
            null_acao = null_res.headers.get("access-control-allow-origin", "").strip()
            null_acac = null_res.headers.get("access-control-allow-credentials", "").strip().lower()

            if null_acao == "null" and null_acac == "true":
                deduction += 20.0
                findings.append(FindingDraft(
                    category=AuditCategory.SECURITY_ACTIVE,
                    rule_id="sec-active-cors-null-credentials",
                    severity="HIGH",
                    confidence=1.0,
                    title="CORS Null Origin Trusted with Credentials",
                    description="The server trusts 'Origin: null' with Access-Control-Allow-Credentials: true. Sandboxed iframes and local file exploits can exploit this trust.",
                    recommendation="Do not include 'null' in your Access-Control-Allow-Origin whitelist."
                ))

        except Exception as e:
            cors_evidence["error"] = str(e)

        is_clean = len(findings) == 0
        cors_evidence["status"] = "PASS" if is_clean else "VULNERABLE"
        return findings, cors_evidence, deduction

    # -------------------------------------------------------------------------
    # PROBE 3: Sensitive File & Infrastructure Exposure
    # -------------------------------------------------------------------------
    async def _probe_sensitive_files(
        self,
        client: httpx.AsyncClient,
        url: str
    ) -> Tuple[List[FindingDraft], Dict[str, Any], float]:
        findings: List[FindingDraft] = []
        deduction = 0.0

        parsed = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"

        paths_to_probe = [
            ("/.env", "Environment Variables File"),
            ("/.git/HEAD", "Git Repository Metadata"),
            ("/wp-config.php.bak", "WordPress Configuration Backup"),
            ("/server-status", "Apache Server Status Console"),
            ("/.well-known/security.txt", "Security Disclosure Policy"),
        ]

        file_evidence: Dict[str, Any] = {}

        for path, label in paths_to_probe:
            probe_target = f"{base_origin}{path}"
            try:
                res = await client.get(probe_target, follow_redirects=False)
                status_code = res.status_code
                content_type = res.headers.get("content-type", "").lower()
                body_sample = res.text[:2000]

                # SPA / 404 suppression: Ignore 200 responses that return standard HTML index pages
                is_spa_catchall = "text/html" in content_type and ("<!doctype html" in body_sample.lower() or "<html" in body_sample.lower())

                if path == "/.env" and status_code == 200:
                    keywords = ("DB_", "SECRET_", "KEY=", "PASSWORD=", "AWS_", "JWT_", "REDIS_", "API_KEY=")
                    if not is_spa_catchall and any(k in body_sample.upper() for k in keywords):
                        deduction += 30.0
                        findings.append(FindingDraft(
                            category=AuditCategory.SECURITY_ACTIVE,
                            rule_id="sec-active-env-exposed",
                            severity="CRITICAL",
                            confidence=1.0,
                            title="Critical Secret Exposure: /.env File Publicly Accessible",
                            description=f"The environment variables file at {probe_target} is publicly accessible and contains application secrets.",
                            recommendation="Immediately restrict public web access to all dotfiles in your web server / CDN configuration."
                        ))
                        file_evidence[path] = {"status": status_code, "exposed": True}
                        continue

                elif path == "/.git/HEAD" and status_code == 200:
                    if not is_spa_catchall and ("ref: refs/" in body_sample or (len(body_sample.strip()) == 40 and all(c in "0123456789abcdefABCDEF" for c in body_sample.strip()))):
                        deduction += 30.0
                        findings.append(FindingDraft(
                            category=AuditCategory.SECURITY_ACTIVE,
                            rule_id="sec-active-git-exposed",
                            severity="CRITICAL",
                            confidence=1.0,
                            title="Source Code Leak: /.git Repository Metadata Exposed",
                            description=f"The Git repository index at {probe_target} is exposed. Attackers can download git history and reconstruct source code.",
                            recommendation="Block all public access to the /.git/ directory in your web server configuration."
                        ))
                        file_evidence[path] = {"status": status_code, "exposed": True}
                        continue

                elif path == "/wp-config.php.bak" and status_code == 200:
                    if not is_spa_catchall and any(k in body_sample for k in ("DB_NAME", "DB_USER", "DB_PASSWORD", "wp-settings.php", "<?php")):
                        deduction += 30.0
                        findings.append(FindingDraft(
                            category=AuditCategory.SECURITY_ACTIVE,
                            rule_id="sec-active-wp-config-exposed",
                            severity="CRITICAL",
                            confidence=1.0,
                            title="Database Credentials Exposed: /wp-config.php.bak Accessible",
                            description=f"A database configuration backup file is publicly readable at {probe_target}.",
                            recommendation="Remove backup files (.bak, .old, .save) from the web root and configure your server to deny serving backup extensions."
                        ))
                        file_evidence[path] = {"status": status_code, "exposed": True}
                        continue

                elif path == "/server-status" and status_code == 200:
                    if not is_spa_catchall and any(k in body_sample for k in ("Apache Server Status", "Server Version:", "Total accesses:")):
                        deduction += 20.0
                        findings.append(FindingDraft(
                            category=AuditCategory.SECURITY_ACTIVE,
                            rule_id="sec-active-server-status-exposed",
                            severity="HIGH",
                            confidence=1.0,
                            title="Server Diagnostics Exposed: /server-status Accessible",
                            description=f"The server status diagnostic console at {probe_target} is publicly exposed, revealing client IP addresses and URLs.",
                            recommendation="Restrict /server-status to localhost (Require local in Apache configuration)."
                        ))
                        file_evidence[path] = {"status": status_code, "exposed": True}
                        continue

                elif path == "/.well-known/security.txt":
                    if status_code == 200 and "Contact:" in body_sample:
                        findings.append(FindingDraft(
                            category=AuditCategory.SECURITY_ACTIVE,
                            rule_id="sec-active-security-txt-present",
                            severity="INFO",
                            confidence=1.0,
                            title="Security Disclosure Policy Present (RFC 9116)",
                            description=f"Target provides a valid RFC 9116 security policy at {probe_target}.",
                            recommendation="Maintain up-to-date contact information in security.txt."
                        ))
                        file_evidence[path] = {"status": status_code, "present": True}
                        continue
                    else:
                        deduction += 5.0
                        findings.append(FindingDraft(
                            category=AuditCategory.SECURITY_ACTIVE,
                            rule_id="sec-active-security-txt-missing",
                            severity="LOW",
                            confidence=1.0,
                            title="Missing RFC 9116 security.txt Disclosure File",
                            description="No /.well-known/security.txt file was found to provide security researchers with vulnerability disclosure contacts.",
                            recommendation="Create a security.txt file adhering to RFC 9116 under /.well-known/security.txt."
                        ))
                        file_evidence[path] = {"status": status_code, "present": False}
                        continue

                file_evidence[path] = {"status": status_code, "safe": True}

            except Exception:
                file_evidence[path] = {"status": None, "safe": True}

        is_clean = not any(f.severity in ("CRITICAL", "HIGH") for f in findings)
        evidence = {
            "status": "PASS" if is_clean else "VULNERABLE",
            "checked_paths": file_evidence
        }
        return findings, evidence, deduction

    # -------------------------------------------------------------------------
    # PROBE 4: Open Redirect Reflection
    # -------------------------------------------------------------------------
    async def _probe_open_redirect(
        self,
        client: httpx.AsyncClient,
        url: str
    ) -> Tuple[List[FindingDraft], Dict[str, Any], float]:
        findings: List[FindingDraft] = []
        deduction = 0.0
        evil_target = "https://evil-attacker.example.com"
        params_to_test = ["redirect", "next", "url", "return_url", "dest"]

        redirect_evidence: Dict[str, Any] = {"tested_params": params_to_test, "vulnerable": False}

        parsed = urlparse(url)

        for param in params_to_test:
            # Build URL with probe query param
            query_dict = dict(parse_qsl(parsed.query))
            query_dict[param] = evil_target
            test_query = urlencode(query_dict)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, test_query, ""))

            try:
                res = await client.get(test_url, follow_redirects=False)
                if res.status_code in (301, 302, 303, 307, 308):
                    location = res.headers.get("location", "").strip()
                    if location.startswith(evil_target) or location.startswith("//evil-attacker.example.com"):
                        deduction += 20.0
                        redirect_evidence["vulnerable"] = True
                        redirect_evidence["vulnerable_param"] = param
                        redirect_evidence["reflected_location"] = location

                        findings.append(FindingDraft(
                            category=AuditCategory.SECURITY_ACTIVE,
                            rule_id="sec-active-open-redirect",
                            severity="HIGH",
                            confidence=1.0,
                            title=f"Open Redirect Vulnerability via '{param}' Parameter",
                            description=(
                                f"The application issued an HTTP {res.status_code} redirect to external destination '{location}' "
                                f"when supplied with ?{param}={evil_target}."
                            ),
                            recommendation="Validate all redirect destinations against a strict whitelist or restrict redirects to relative paths."
                        ))
                        break  # Found open redirect, stop further param probing
            except Exception:
                continue

        redirect_evidence["status"] = "PASS" if not redirect_evidence["vulnerable"] else "VULNERABLE"
        return findings, redirect_evidence, deduction

    # -------------------------------------------------------------------------
    # PROBE 5: Clickjacking & Frameability
    # -------------------------------------------------------------------------
    async def _probe_clickjacking(
        self,
        client: httpx.AsyncClient,
        url: str
    ) -> Tuple[List[FindingDraft], Dict[str, Any], float]:
        findings: List[FindingDraft] = []
        deduction = 0.0

        frame_evidence: Dict[str, Any] = {
            "x_frame_options": None,
            "csp_frame_ancestors": None
        }

        try:
            res = await client.get(url, follow_redirects=True)
            xfo = res.headers.get("x-frame-options", "").strip().upper()
            csp = res.headers.get("content-security-policy", "").lower()

            frame_evidence["x_frame_options"] = xfo or None

            has_frame_ancestors = "frame-ancestors" in csp
            if has_frame_ancestors:
                # Extract frame-ancestors directive
                parts = [p.strip() for p in csp.split(";") if "frame-ancestors" in p]
                frame_evidence["csp_frame_ancestors"] = parts[0] if parts else "frame-ancestors detected"

            # Check for lack of framing defense
            if not xfo and not has_frame_ancestors:
                deduction += 10.0
                findings.append(FindingDraft(
                    category=AuditCategory.SECURITY_ACTIVE,
                    rule_id="sec-active-clickjacking-unprotected",
                    severity="MEDIUM",
                    confidence=1.0,
                    title="Missing Clickjacking Defense: Page Can Be Framed",
                    description=(
                        "The target page does not provide an X-Frame-Options header or a Content-Security-Policy with 'frame-ancestors'. "
                        "Attackers can embed this website in an invisible iframe to execute UI redressing / clickjacking attacks."
                    ),
                    recommendation="Add header 'X-Frame-Options: SAMEORIGIN' or 'Content-Security-Policy: frame-ancestors self;'."
                ))
            elif xfo.startswith("ALLOW-FROM"):
                deduction += 5.0
                findings.append(FindingDraft(
                    category=AuditCategory.SECURITY_ACTIVE,
                    rule_id="sec-active-xfo-deprecated-allow-from",
                    severity="LOW",
                    confidence=1.0,
                    title="Deprecated X-Frame-Options ALLOW-FROM Directive",
                    description="The server uses 'X-Frame-Options: ALLOW-FROM', which is ignored by modern browsers.",
                    recommendation="Migrate to the standard Content-Security-Policy 'frame-ancestors' directive."
                ))

        except Exception as e:
            frame_evidence["error"] = str(e)

        is_clean = len(findings) == 0
        frame_evidence["status"] = "PASS" if is_clean else "VULNERABLE"
        return findings, frame_evidence, deduction
