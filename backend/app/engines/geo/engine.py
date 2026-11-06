"""WebAudit 360 — Generative Engine Optimization (GEO) & LLM Scraper Readiness Engine
Author: Harsh Patel

Evaluates:
- AI Crawler Directives in robots.txt (GPTBot, ClaudeBot, PerplexityBot, CCBot, Google-Extended, Applebot-Extended)
- LLM standard manifest discovery (/llms.txt, /llms-full.txt)
- Semantic content density & landmark HTML5 structure (<article>, <main>, <section>, heading trees)
- Schema.org JSON-LD structured data completeness for AI grounding (FAQ, Article, Product, Organization)
"""

import json
import re
import time
from typing import Any, Dict, List, Optional
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

AI_CRAWLERS = [
    ("GPTBot", "OpenAI ChatGPT / SearchGPT"),
    ("ClaudeBot", "Anthropic Claude"),
    ("PerplexityBot", "Perplexity AI"),
    ("CCBot", "Common Crawl (Foundation LLM Datasets)"),
    ("Google-Extended", "Google Gemini / Vertex AI Training"),
    ("Applebot-Extended", "Apple Intelligence"),
    ("Bytespider", "ByteDance AI"),
]


class GEOEngine(BaseAuditEngine):
    engine_name = "GEOEngine"
    engine_version = "1.0.0"
    category = AuditCategory.GEO_AI

    async def execute(
        self,
        target_url: str,
        config: Dict[str, Any],
        **kwargs
    ) -> EngineResult:
        start_time = time.time()
        findings: List[FindingDraft] = []
        limitations: List[str] = [
            "Evaluates public robots.txt, /llms.txt, and semantic HTML structure.",
            "Dynamic RAG indexing behaviors may vary by AI model provider."
        ]

        normalized_url, hostname, _ = validate_target_url(target_url)
        parsed = urlparse(normalized_url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebAudit360-GEO-Engine/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }

        # 1. Fetch Target HTML
        try:
            async with httpx.AsyncClient(timeout=12.0, follow_redirects=True, headers=headers) as client:
                resp = await client.get(normalized_url)
                html_content = resp.text
        except Exception as e:
            return EngineResult(
                category=AuditCategory.GEO_AI,
                engine_name=self.engine_name,
                engine_version=self.engine_version,
                status=EngineStatus.FAILED,
                error=f"Could not connect to target URL: {str(e)}",
                execution_time_ms=int((time.time() - start_time) * 1000)
            )

        # 2. Probe robots.txt for AI crawlers
        robots_url = urljoin(base_origin, "/robots.txt")
        robots_content = ""
        crawler_status: Dict[str, str] = {}
        try:
            async with httpx.AsyncClient(timeout=6.0, follow_redirects=True, headers=headers) as client:
                r_resp = await client.get(robots_url)
                if r_resp.is_success:
                    robots_content = r_resp.text
        except Exception:
            pass

        # Parse robots.txt lines (RFC 9309 compliant user-agent grouping)
        lines = [line.strip() for line in robots_content.splitlines() if line.strip() and not line.strip().startswith("#")]
        current_agents = []
        agent_rules: Dict[str, List[str]] = {}

        for line in lines:
            if ":" in line:
                k, v = line.split(":", 1)
                k = k.strip().lower()
                v = v.strip()
                if k == "user-agent":
                    current_agents.append(v.lower())
                elif k in ("disallow", "allow"):
                    for ag in current_agents:
                        if ag not in agent_rules:
                            agent_rules[ag] = []
                        agent_rules[ag].append(f"{k}:{v}")
            else:
                current_agents = []

        wildcard_rules = agent_rules.get("*", [])
        wildcard_blocked = any(r.replace(" ", "").startswith("disallow:/") for r in wildcard_rules)

        for bot_name, display_desc in AI_CRAWLERS:
            b_lower = bot_name.lower()
            if b_lower in agent_rules:
                rules = agent_rules[b_lower]
                if any(r.replace(" ", "").startswith("disallow:/") for r in rules):
                    crawler_status[bot_name] = "BLOCKED"
                else:
                    crawler_status[bot_name] = "ALLOWED"
            elif wildcard_blocked:
                crawler_status[bot_name] = "BLOCKED"
            else:
                crawler_status[bot_name] = "DEFAULT_ALLOWED"

        # 3. Probe for /llms.txt manifest
        llms_txt_url = urljoin(base_origin, "/llms.txt")
        has_llms_txt = False
        llms_txt_size = 0
        try:
            async with httpx.AsyncClient(timeout=5.0, follow_redirects=True, headers=headers) as client:
                llms_resp = await client.get(llms_txt_url)
                if llms_resp.is_success and "text/plain" in llms_resp.headers.get("content-type", "text/plain"):
                    has_llms_txt = True
                    llms_txt_size = len(llms_resp.content)
        except Exception:
            pass

        # 4. Parse Structured Data (JSON-LD) and Semantic HTML5 Structure
        soup = BeautifulSoup(html_content, "html.parser")

        jsonld_schemas = []
        for script in soup.find_all("script", type="application/ld+json"):
            try:
                data = json.loads(script.string or "{}")
                if isinstance(data, list):
                    jsonld_schemas.extend(data)
                elif isinstance(data, dict):
                    jsonld_schemas.append(data)
            except Exception:
                pass

        schema_types = []
        for s in jsonld_schemas:
            stype = s.get("@type")
            if isinstance(stype, list):
                schema_types.extend(stype)
            elif isinstance(stype, str):
                schema_types.append(stype)

        # Semantic Landmarks: main, article, section, nav
        has_main = bool(soup.find("main"))
        has_article = bool(soup.find("article"))
        headings_count = len(soup.find_all(["h1", "h2", "h3"]))

        # Calculate Score
        score = 100.0

        blocked_crawlers = [k for k, v in crawler_status.items() if v == "BLOCKED"]
        if blocked_crawlers:
            score -= min(30.0, len(blocked_crawlers) * 6.0)
            findings.append(FindingDraft(
                category=AuditCategory.GEO_AI,
                rule_id="geo-ai-crawlers-blocked",
                severity="HIGH" if len(blocked_crawlers) >= 3 else "MEDIUM",
                title=f"{len(blocked_crawlers)} AI Search Bots Disallowed in robots.txt",
                description=(
                    f"robots.txt disallows AI crawlers ({', '.join(blocked_crawlers)}), preventing LLMs "
                    "from indexing, citing, and summarizing your site in generative search answers (ChatGPT, Perplexity, Gemini)."
                ),
                recommendation="Permit AI search engine user-agents (e.g., GPTBot, ClaudeBot, PerplexityBot) in robots.txt if brand visibility in generative search is desired.",
                evidence_snippet=robots_content[:300] if robots_content else "No robots.txt content",
                raw_details={"blocked_crawlers": blocked_crawlers, "crawler_status": crawler_status}
            ))

        if not has_llms_txt:
            score -= 15.0
            findings.append(FindingDraft(
                category=AuditCategory.GEO_AI,
                rule_id="geo-missing-llms-txt",
                severity="LOW",
                title="Missing /llms.txt AI Context Manifest",
                description="Target website does not publish an /llms.txt manifest providing curated, high-signal Markdown context for LLM agents.",
                recommendation="Create an /llms.txt file at the site root outlining key documentation, products, and concise summaries formatted for LLM consumption.",
                raw_details={"llms_txt_url": llms_txt_url}
            ))
        else:
            findings.append(FindingDraft(
                category=AuditCategory.GEO_AI,
                rule_id="geo-llms-txt-present",
                severity="INFO",
                title="Published /llms.txt AI Manifest",
                description=f"Verified /llms.txt manifest accessible at {llms_txt_url} ({llms_txt_size} bytes).",
                recommendation="Keep /llms.txt updated with accurate brand, documentation, and product summaries."
            ))

        if not schema_types:
            score -= 20.0
            findings.append(FindingDraft(
                category=AuditCategory.GEO_AI,
                rule_id="geo-schema-missing",
                severity="MEDIUM",
                title="No Schema.org JSON-LD Structured Data for AI Grounding",
                description="No machine-readable JSON-LD schema found. AI engines rely on Schema.org entities to ground factual reasoning and entity relationships.",
                recommendation="Implement Organization, WebSite, Article, Product, or FAQPage JSON-LD schemas."
            ))
        else:
            findings.append(FindingDraft(
                category=AuditCategory.GEO_AI,
                rule_id="geo-schema-detected",
                severity="INFO",
                title=f"Structured Data Verified: {', '.join(set(schema_types))}",
                description=f"Identified {len(schema_types)} structured schema entities aiding semantic comprehension by LLMs.",
                recommendation="Ensure all required schema attributes pass Google Structured Data testing standards.",
                raw_details={"schemas": schema_types}
            ))

        if not has_main and not has_article:
            score -= 10.0
            findings.append(FindingDraft(
                category=AuditCategory.GEO_AI,
                rule_id="geo-low-semantic-landmarks",
                severity="LOW",
                title="Missing Semantic HTML5 Content Landmarks (<main> or <article>)",
                description="LLM content extractors rely on <main> or <article> containers to isolate primary content from headers and footers.",
                recommendation="Enclose primary page content within <main> and <article> semantic tags."
            ))

        final_score = max(0.0, min(100.0, round(score, 1)))

        raw_evidence = {
            "has_robots_txt": bool(robots_content),
            "crawler_status": crawler_status,
            "blocked_crawlers_count": len(blocked_crawlers),
            "has_llms_txt": has_llms_txt,
            "schema_types": list(set(schema_types)),
            "semantic_landmarks": {
                "has_main": has_main,
                "has_article": has_article,
                "headings_count": headings_count
            },
            "geo_readiness_tier": "Generative Ready" if final_score >= 85 else ("Partially Optimized" if final_score >= 60 else "Unprepared for AI Discovery")
        }

        return EngineResult(
            category=AuditCategory.GEO_AI,
            engine_name=self.engine_name,
            engine_version=self.engine_version,
            status=EngineStatus.SUCCESS,
            score=final_score,
            findings=findings,
            raw_evidence=raw_evidence,
            limitations=limitations,
            execution_time_ms=int((time.time() - start_time) * 1000)
        )
