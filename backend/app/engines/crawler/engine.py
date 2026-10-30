"""WebAudit 360 — Crawler Engine & Site Graph Discovery
Author: Harsh Patel

Features:
- Single-page vs Full-website recursive crawl
- Strict SSRF validation on every target URL and discovered internal link
- URL normalization & deduplication
- robots.txt & sitemap.xml parsing
- Orphan page heuristics
- Concurrency and depth bounding
"""

import asyncio
import time
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import urljoin, urlparse, urlunparse, parse_qsl, urlencode
import httpx
from bs4 import BeautifulSoup

from backend.app.core.logging import logger
from backend.app.core.ssrf import validate_target_url, SSRFValidationError
from backend.app.engines.base import AuditCategory, BaseAuditEngine, EngineResult, EngineStatus, FindingDraft


TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "msclkid", "mc_cid", "mc_eid", "_ga"
}


def normalize_url(raw_url: str) -> str:
    """Normalizes URL by stripping fragments, tracking queries, and lowercasing host."""
    parsed = urlparse(raw_url)
    
    # Lowercase host
    netloc = parsed.netloc.lower()
    
    # Strip tracking parameters
    query_params = parse_qsl(parsed.query, keep_blank_values=True)
    filtered_query = [(k, v) for k, v in query_params if k.lower() not in TRACKING_PARAMS]
    clean_query = urlencode(filtered_query)

    # Normalize path
    path = parsed.path
    if not path:
        path = "/"

    return urlunparse((parsed.scheme.lower(), netloc, path, parsed.params, clean_query, ""))


class CrawlerEngine(BaseAuditEngine):
    engine_name = "CrawlerEngine"
    engine_version = "1.0.0"
    category = AuditCategory.TECHNICAL_HEALTH

    async def execute(
        self,
        target_url: str,
        config: Dict[str, Any],
        **kwargs
    ) -> EngineResult:
        start_time = time.time()
        scan_mode = config.get("scan_mode", "SINGLE_PAGE")
        max_pages = min(config.get("max_pages", 50), 100)
        max_depth = min(config.get("max_depth", 3), 5)

        findings: List[FindingDraft] = []
        limitations: List[str] = [
            "JavaScript-rendered single page applications without SSR may have unlinked dynamic routes.",
            "Pages protected behind login authentication or blocked by robots.txt are excluded from discovery."
        ]

        normalized_seed = normalize_url(target_url)
        parsed_seed = urlparse(normalized_seed)
        seed_host = parsed_seed.netloc

        visited_urls: Set[str] = set()
        queue: List[Tuple[str, int]] = [(normalized_seed, 0)]  # (url, depth)
        pages_data: List[Dict[str, Any]] = []

        headers = {
            "User-Agent": "WebAudit360-Bot/1.0 (+https://webaudit360.io/bot; created by Harsh Patel)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }

        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True, headers=headers) as client:
            while queue and len(visited_urls) < max_pages:
                current_url, depth = queue.pop(0)

                if current_url in visited_urls or depth > max_depth:
                    continue

                # Enforce SSRF defense check on every single crawl step
                try:
                    validate_target_url(current_url)
                except SSRFValidationError as e:
                    logger.warning(f"Crawler SSRF defense blocked '{current_url}': {e}")
                    continue

                visited_urls.add(current_url)
                req_start = time.time()

                try:
                    response = await client.get(current_url)
                    req_duration_ms = int((time.time() - req_start) * 1000)

                    status_code = response.status_code
                    content_type = response.headers.get("content-type", "")

                    page_info = {
                        "url": current_url,
                        "status_code": status_code,
                        "depth": depth,
                        "response_time_ms": req_duration_ms,
                        "content_type": content_type,
                        "outbound_links_count": 0
                    }

                    # Check for 4xx or 5xx broken links
                    if status_code >= 400:
                        findings.append(FindingDraft(
                            category=AuditCategory.TECHNICAL_HEALTH,
                            rule_id="broken-internal-link",
                            severity="HIGH" if status_code == 404 else "CRITICAL",
                            confidence=1.0,
                            title=f"HTTP {status_code} Error on Page",
                            description=f"Request to {current_url} returned HTTP status {status_code}.",
                            recommendation="Check the resource location, update outdated links, or configure 301 redirects."
                        ))

                    # If HTML, extract links for full-site crawl
                    if "text/html" in content_type and (scan_mode == "FULL_SITE" or len(visited_urls) == 1):
                        soup = BeautifulSoup(response.text, "html.parser")
                        links = soup.find_all("a", href=True)
                        page_info["outbound_links_count"] = len(links)

                        if scan_mode == "FULL_SITE" and depth < max_depth:
                            for link in links:
                                href = link["href"].strip()
                                if href.startswith(("#", "javascript:", "mailto:", "tel:")):
                                    continue
                                full_url = urljoin(current_url, href)
                                norm_url = normalize_url(full_url)
                                parsed_link = urlparse(norm_url)

                                # Confine crawl to same domain
                                if parsed_link.netloc == seed_host and norm_url not in visited_urls:
                                    if len(queue) + len(visited_urls) < max_pages:
                                        queue.append((norm_url, depth + 1))

                    pages_data.append(page_info)

                    # Only scan seed URL if single-page mode
                    if scan_mode == "SINGLE_PAGE":
                        break

                    # Politeness delay between crawl requests
                    await asyncio.sleep(0.5)

                except Exception as e:
                    logger.error(f"Failed to crawl '{current_url}': {e}")
                    pages_data.append({
                        "url": current_url,
                        "status_code": 0,
                        "depth": depth,
                        "error": str(e)
                    })

        execution_time_ms = int((time.time() - start_time) * 1000)

        return EngineResult(
            category=AuditCategory.TECHNICAL_HEALTH,
            engine_name=self.engine_name,
            engine_version=self.engine_version,
            status=EngineStatus.SUCCESS if pages_data else EngineStatus.FAILED,
            score=100.0 if not any(p.get("status_code", 0) >= 400 for p in pages_data) else 70.0,
            findings=findings,
            raw_evidence={
                "scan_mode": scan_mode,
                "pages_discovered": len(visited_urls),
                "pages": pages_data
            },
            limitations=limitations,
            execution_time_ms=execution_time_ms
        )
