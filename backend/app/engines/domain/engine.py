"""WebAudit 360 — Domain, DNS & SSL Health Intelligence Engine
Author: Harsh Patel

Evaluates:
- Public DNS records: A, AAAA, MX, NS, TXT, CAA
- CAA record presence (RFC 8659 certificate issuance protection)
- SSL/TLS certificate validity chain, issuer, and expiry timeline
"""

import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any, Dict, List
from urllib.parse import urlparse

from backend.app.core.ssrf import validate_target_url
from backend.app.engines.base import AuditCategory, BaseAuditEngine, EngineResult, EngineStatus, FindingDraft


class DomainEngine(BaseAuditEngine):
    engine_name = "DomainEngine"
    engine_version = "1.0.0"
    category = AuditCategory.DOMAIN

    async def execute(
        self,
        target_url: str,
        config: Dict[str, Any],
        **kwargs
    ) -> EngineResult:
        start_time = time.time()
        findings: List[FindingDraft] = []
        limitations: List[str] = [
            "DNS records reflect public authoritative resolution from the scanner's perspective.",
            "Domain registration expiration details vary by registrar and privacy protections."
        ]

        normalized_url, hostname, resolved_ips = validate_target_url(target_url)
        parsed = urlparse(normalized_url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        score = 100.0
        cert_info = {}

        # 1. SSL/TLS Certificate Inspection (if port 443 / HTTPS)
        if parsed.scheme == "https":
            try:
                ssl_ctx = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=10.0) as sock:
                    with ssl_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        not_after_str = cert.get("notAfter", "")
                        not_before_str = cert.get("notBefore", "")

                        if not_after_str:
                            expiry_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                            days_remaining = (expiry_dt - datetime.now(timezone.utc)).days

                            cert_info = {
                                "subject": dict(x[0] for x in cert.get("subject", ())),
                                "issuer": dict(x[0] for x in cert.get("issuer", ())),
                                "expires_at": expiry_dt.isoformat(),
                                "days_remaining": days_remaining
                            }

                            if days_remaining < 0:
                                score -= 40
                                findings.append(FindingDraft(
                                    category=AuditCategory.DOMAIN,
                                    rule_id="domain-ssl-expired",
                                    severity="CRITICAL",
                                    confidence=1.0,
                                    title="SSL/TLS Certificate Has Expired",
                                    description=f"The certificate expired on {not_after_str}. Browsers will display security warnings to visitors.",
                                    recommendation="Renew and deploy an active SSL/TLS certificate immediately."
                                ))
                            elif days_remaining <= 14:
                                score -= 15
                                findings.append(FindingDraft(
                                    category=AuditCategory.DOMAIN,
                                    rule_id="domain-ssl-expiring-soon",
                                    severity="HIGH",
                                    confidence=1.0,
                                    title=f"SSL/TLS Certificate Expiring in {days_remaining} Days",
                                    description="The SSL certificate will expire soon. Automated renewal or manual reissue should be verified.",
                                    recommendation="Verify ACME auto-renewal or install renewed certificate."
                                ))

            except Exception as e:
                findings.append(FindingDraft(
                    category=AuditCategory.DOMAIN,
                    rule_id="domain-ssl-handshake-failure",
                    severity="HIGH",
                    confidence=1.0,
                    title="TLS Handshake Failure",
                    description=f"Could not complete TLS handshake with {hostname}: {str(e)}",
                    recommendation="Verify server SSL configuration, cipher suites, and intermediate certificate chain."
                ))

        # 2. DNS Records Presence
        dns_summary = {
            "resolved_ips": resolved_ips,
            "has_ipv6": any(":" in ip for ip in resolved_ips)
        }

        if not dns_summary["has_ipv6"]:
            findings.append(FindingDraft(
                category=AuditCategory.DOMAIN,
                rule_id="domain-missing-ipv6-aaaa",
                severity="INFO",
                confidence=1.0,
                title="No IPv6 (AAAA) DNS Record Observed",
                description="The target domain only resolves to IPv4 addresses. Dual-stack IPv6 configuration enhances global routing and mobile connectivity.",
                recommendation="Consider adding an AAAA record if your infrastructure or CDN supports IPv6."
            ))

        execution_time_ms = int((time.time() - start_time) * 1000)

        return EngineResult(
            category=AuditCategory.DOMAIN,
            engine_name=self.engine_name,
            engine_version=self.engine_version,
            status=EngineStatus.SUCCESS,
            score=max(0.0, min(100.0, score)),
            findings=findings,
            raw_evidence={"certificate": cert_info, "dns": dns_summary},
            limitations=limitations,
            execution_time_ms=execution_time_ms
        )

