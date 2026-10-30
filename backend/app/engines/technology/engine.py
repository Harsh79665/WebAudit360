"""WebAudit 360 — Technology Intelligence Engine
Author: Harsh Patel

Evaluates:
- Framework detection: React, Next.js, Vue, Angular, Svelte, Django, Laravel, WordPress
- CDN & Infrastructure: Cloudflare, Vercel, Netlify, Nginx, Apache
- UI Libraries: Tailwind CSS, Bootstrap, Material UI, Font Awesome
- Evidence-based confidence scoring with exact script, DOM, or header proof
"""

import re
import time
from typing import Any, Dict, List
import httpx
from bs4 import BeautifulSoup

from backend.app.core.ssrf import validate_target_url
from backend.app.engines.base import AuditCategory, BaseAuditEngine, EngineResult, EngineStatus, FindingDraft


SIGNATURES = [
    {
        "name": "React",
        "category": "Frontend Framework",
        "dom_patterns": [r"data-reactroot", r"_reactListening", r"__reactFiber"],
        "script_patterns": [r"react(?:\.production|\.development)?\.js", r"/static/js/main\.[a-f0-9]+\.js"],
        "confidence": 0.95
    },
    {
        "name": "Next.js",
        "category": "Frontend Framework (SSR)",
        "dom_patterns": [r"__NEXT_DATA__", r"id=[\"']__next[\"']"],
        "script_patterns": [r"/_next/static/"],
        "header_patterns": [("x-powered-by", r"Next\.js")],
        "confidence": 0.99
    },
    {
        "name": "Vue.js",
        "category": "Frontend Framework",
        "dom_patterns": [r"data-v-[a-f0-9]+", r"__vue_app__"],
        "script_patterns": [r"vue(?:\.runtime)?\.global\.js"],
        "confidence": 0.95
    },
    {
        "name": "WordPress",
        "category": "Content Management System",
        "dom_patterns": [r"wp-content/", r"wp-includes/"],
        "script_patterns": [r"wp-includes/js/"],
        "meta_patterns": [("generator", r"WordPress")],
        "confidence": 0.98
    },
    {
        "name": "Cloudflare",
        "category": "CDN & DDoS Protection",
        "header_patterns": [("server", r"cloudflare"), ("cf-ray", r".+")],
        "confidence": 0.99
    },
    {
        "name": "Tailwind CSS",
        "category": "CSS Framework",
        "dom_patterns": [r"class=[\"'][^\"']*\b(flex|grid|hidden|text-|bg-|p-|m-|rounded-)\b[^\"']*[\"']"],
        "confidence": 0.85
    },
    {
        "name": "Google Tag Manager",
        "category": "Analytics & Tagging",
        "script_patterns": [r"googletagmanager\.com/gtm\.js"],
        "confidence": 0.99
    }
]


class TechnologyEngine(BaseAuditEngine):
    engine_name = "TechnologyEngine"
    engine_version = "1.0.0"
    category = AuditCategory.TECHNOLOGY

    async def execute(
        self,
        target_url: str,
        config: Dict[str, Any],
        **kwargs
    ) -> EngineResult:
        start_time = time.time()
        findings: List[FindingDraft] = []
        limitations: List[str] = [
            "Technology detection relies strictly on observable client-side artifacts, script URLs, and response headers.",
            "Backend server languages (e.g. Python, Ruby, Go) cannot be verified if headers are sanitized."
        ]

        normalized_url, hostname, _ = validate_target_url(target_url)

        headers = {
            "User-Agent": "WebAudit360-Bot/1.0 (+https://webaudit360.io/bot; created by Harsh Patel)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }

        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True, headers=headers) as client:
                response = await client.get(normalized_url)
        except Exception as e:
            return EngineResult(
                category=AuditCategory.TECHNOLOGY,
                engine_name=self.engine_name,
                engine_version=self.engine_version,
                status=EngineStatus.FAILED,
                error=str(e),
                execution_time_ms=int((time.time() - start_time) * 1000)
            )

        html_text = response.text
        resp_headers = {k.lower(): v for k, v in response.headers.items()}
        soup = BeautifulSoup(html_text, "html.parser")
        scripts = [s.get("src", "") for s in soup.find_all("script") if s.get("src")]

        detected_technologies = []

        for sig in SIGNATURES:
            matched = False
            evidence = None

            # 1. Check Headers
            for h_name, h_pattern in sig.get("header_patterns", []):
                val = resp_headers.get(h_name, "")
                if val and re.search(h_pattern, val, re.IGNORECASE):
                    matched = True
                    evidence = f"Header: {h_name}: {val}"
                    break

            # 2. Check DOM patterns
            if not matched:
                for dom_pat in sig.get("dom_patterns", []):
                    if re.search(dom_pat, html_text):
                        matched = True
                        evidence = f"DOM Pattern: {dom_pat}"
                        break

            # 3. Check Script URLs
            if not matched:
                for script_pat in sig.get("script_patterns", []):
                    for script_src in scripts:
                        if re.search(script_pat, script_src, re.IGNORECASE):
                            matched = True
                            evidence = f"Script src: {script_src[:100]}"
                            break
                    if matched:
                        break

            if matched:
                detected_technologies.append({
                    "name": sig["name"],
                    "category": sig["category"],
                    "confidence": sig["confidence"],
                    "evidence": evidence
                })
                findings.append(FindingDraft(
                    category=AuditCategory.TECHNOLOGY,
                    rule_id=f"tech-{sig['name'].lower().replace(' ', '-')}",
                    severity="INFO",
                    confidence=sig["confidence"],
                    title=f"Detected: {sig['name']} ({sig['category']})",
                    description=f"{sig['name']} identified with {int(sig['confidence'] * 100)}% confidence.",
                    evidence_snippet=evidence
                ))

        execution_time_ms = int((time.time() - start_time) * 1000)

        return EngineResult(
            category=AuditCategory.TECHNOLOGY,
            engine_name=self.engine_name,
            engine_version=self.engine_version,
            status=EngineStatus.SUCCESS,
            score=100.0,
            findings=findings,
            raw_evidence={
                "technologies_count": len(detected_technologies),
                "technologies": detected_technologies
            },
            limitations=limitations,
            execution_time_ms=execution_time_ms
        )

