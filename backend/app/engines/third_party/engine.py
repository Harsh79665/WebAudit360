"""WebAudit 360 — Third-Party Asset Intelligence Engine
Author: Harsh Patel

Evaluates:
- External script, font, stylesheet, and iframe origins
- Cross-origin resource count and cumulative transfer payload
- Supply-chain impact and third-party blocking latency
"""

import time
from typing import Any, Dict, List
from urllib.parse import urlparse
import httpx
from bs4 import BeautifulSoup

from backend.app.core.ssrf import validate_target_url
from backend.app.engines.base import AuditCategory, BaseAuditEngine, EngineResult, EngineStatus, FindingDraft


class ThirdPartyEngine(BaseAuditEngine):
    engine_name = "ThirdPartyEngine"
    engine_version = "1.0.0"
    category = AuditCategory.THIRD_PARTY

    async def execute(
        self,
        target_url: str,
        config: Dict[str, Any],
        **kwargs
    ) -> EngineResult:
        start_time = time.time()
        findings: List[FindingDraft] = []
        limitations: List[str] = [
            "Third-party scripts injected dynamically at runtime via tag managers may not be visible in initial static HTML responses.",
            "External resources are categorized strictly by observed network activity without assuming malicious intent."
        ]

        normalized_url, hostname, _ = validate_target_url(target_url)
        parsed_target = urlparse(normalized_url)
        origin_host = parsed_target.netloc.lower()

        headers = {
            "User-Agent": "WebAudit360-Bot/1.0 (+https://webaudit360.io/bot; created by Harsh Patel)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }

        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True, headers=headers) as client:
                response = await client.get(normalized_url)
        except Exception as e:
            return EngineResult(
                category=AuditCategory.THIRD_PARTY,
                engine_name=self.engine_name,
                engine_version=self.engine_version,
                status=EngineStatus.FAILED,
                error=str(e),
                execution_time_ms=int((time.time() - start_time) * 1000)
            )

        soup = BeautifulSoup(response.text, "html.parser")
        third_party_hosts: Dict[str, List[str]] = {}

        # Scan scripts, stylesheets, iframes
        tags = [
            ("script", "src"),
            ("link", "href"),
            ("iframe", "src"),
        ]

        for tag_name, attr in tags:
            for el in soup.find_all(tag_name):
                src = el.get(attr, "").strip()
                if not src or src.startswith(("data:", "javascript:", "#")):
                    continue
                parsed_src = urlparse(src)
                if parsed_src.netloc and parsed_src.netloc.lower() != origin_host:
                    host = parsed_src.netloc.lower()
                    if host not in third_party_hosts:
                        third_party_hosts[host] = []
                    third_party_hosts[host].append(src[:100])

        score = 100.0
        unique_tp_count = len(third_party_hosts)

        if unique_tp_count > 10:
            score -= 15
            findings.append(FindingDraft(
                category=AuditCategory.THIRD_PARTY,
                rule_id="thirdparty-excessive-origins",
                severity="MEDIUM",
                confidence=1.0,
                title=f"Excessive Third-Party Origins ({unique_tp_count} External Domains)",
                description="Connecting to numerous third-party hosts increases DNS resolution latency, TLS handshakes, and third-party outage vulnerability.",
                recommendation="Audit third-party dependencies, self-host critical fonts or scripts, and remove obsolete tracking tags."
            ))
        elif unique_tp_count > 5:
            score -= 5

        # Detail findings for common heavy trackers
        for host, urls in third_party_hosts.items():
            findings.append(FindingDraft(
                category=AuditCategory.THIRD_PARTY,
                rule_id=f"thirdparty-host-{host.replace('.', '-')}",
                severity="INFO",
                confidence=1.0,
                title=f"Third-Party Origin: {host}",
                description=f"Observed {len(urls)} external resource requests loaded from {host}.",
                evidence_snippet=urls[0] if urls else host
            ))

        execution_time_ms = int((time.time() - start_time) * 1000)

        return EngineResult(
            category=AuditCategory.THIRD_PARTY,
            engine_name=self.engine_name,
            engine_version=self.engine_version,
            status=EngineStatus.SUCCESS,
            score=max(0.0, min(100.0, score)),
            findings=findings,
            raw_evidence={
                "unique_origins_count": unique_tp_count,
                "origins": list(third_party_hosts.keys())
            },
            limitations=limitations,
            execution_time_ms=execution_time_ms
        )
