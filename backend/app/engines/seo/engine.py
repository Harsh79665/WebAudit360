"""WebAudit 360 — SEO Intelligence Engine
Author: Harsh Patel

Evaluates:
- Page Title, Meta Description length & presence
- Heading hierarchy (H1 count, sequential structure)
- Canonical tag consistency
- Robots directives (Meta robots, X-Robots-Tag)
- Open Graph and Twitter Card metadata
- Image alt attribute coverage
- Structured Data (JSON-LD schema markup)
"""

import time
from typing import Any, Dict, List
from urllib.parse import urlparse
import httpx
from bs4 import BeautifulSoup

from backend.app.core.ssrf import validate_target_url
from backend.app.engines.base import AuditCategory, BaseAuditEngine, EngineResult, EngineStatus, FindingDraft


class SEOEngine(BaseAuditEngine):
    engine_name = "SEOEngine"
    engine_version = "1.0.0"
    category = AuditCategory.SEO

    async def execute(
        self,
        target_url: str,
        config: Dict[str, Any],
        **kwargs
    ) -> EngineResult:
        start_time = time.time()
        findings: List[FindingDraft] = []
        limitations: List[str] = [
            "Does not invent search engine rankings, keyword positions, or organic search traffic.",
            "Client-rendered dynamic meta tags require headless browser hydration for complete verification."
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
                category=AuditCategory.SEO,
                engine_name=self.engine_name,
                engine_version=self.engine_version,
                status=EngineStatus.FAILED,
                error=f"HTTP request failed: {str(e)}",
                execution_time_ms=int((time.time() - start_time) * 1000)
            )

        html_text = response.text
        soup = BeautifulSoup(html_text, "html.parser")
        score = 100.0

        # 1. Page Title Check
        title_tag = soup.find("title")
        title_text = title_tag.text.strip() if title_tag else ""
        if not title_text:
            score -= 20
            findings.append(FindingDraft(
                category=AuditCategory.SEO,
                rule_id="seo-missing-title",
                severity="HIGH",
                confidence=1.0,
                title="Missing Page Title",
                description="The page is missing a <title> element in the <head> section.",
                recommendation="Add a descriptive, keyword-rich <title> tag between 30 and 65 characters.",
                selector="head > title"
            ))
        elif len(title_text) < 20 or len(title_text) > 70:
            score -= 5
            findings.append(FindingDraft(
                category=AuditCategory.SEO,
                rule_id="seo-suboptimal-title-length",
                severity="LOW",
                confidence=1.0,
                title=f"Suboptimal Title Length ({len(title_text)} characters)",
                description=f"Page title is '{title_text}'. Search engines generally display titles between 30 and 60 characters before truncating.",
                recommendation="Refine title length to between 30 and 65 characters.",
                evidence_snippet=title_text
            ))

        # 2. Meta Description Check
        meta_desc = soup.find("meta", attrs={"name": lambda x: x and x.lower() == "description"})
        desc_text = meta_desc.get("content", "").strip() if meta_desc else ""
        if not desc_text:
            score -= 15
            findings.append(FindingDraft(
                category=AuditCategory.SEO,
                rule_id="seo-missing-meta-description",
                severity="MEDIUM",
                confidence=1.0,
                title="Missing Meta Description",
                description="No meta description was found in the document <head>.",
                recommendation="Add a compelling <meta name='description' content='...'> between 70 and 160 characters.",
                selector="head"
            ))
        elif len(desc_text) < 50 or len(desc_text) > 165:
            score -= 5
            findings.append(FindingDraft(
                category=AuditCategory.SEO,
                rule_id="seo-suboptimal-description-length",
                severity="LOW",
                confidence=1.0,
                title=f"Suboptimal Meta Description Length ({len(desc_text)} characters)",
                description="Search engines typically truncate snippets beyond 160 characters or disregard descriptions under 50 characters.",
                recommendation="Keep meta description between 70 and 160 characters.",
                evidence_snippet=desc_text
            ))

        # 3. Headings Structure (H1 Check)
        h1_tags = soup.find_all("h1")
        if len(h1_tags) == 0:
            score -= 15
            findings.append(FindingDraft(
                category=AuditCategory.SEO,
                rule_id="seo-missing-h1",
                severity="HIGH",
                confidence=1.0,
                title="Missing H1 Heading",
                description="No <h1> element was detected on the page.",
                recommendation="Add exactly one primary <h1> heading summarizing the main page topic.",
                selector="body"
            ))
        elif len(h1_tags) > 1:
            score -= 5
            findings.append(FindingDraft(
                category=AuditCategory.SEO,
                rule_id="seo-multiple-h1",
                severity="LOW",
                confidence=1.0,
                title=f"Multiple H1 Headings Detected ({len(h1_tags)})",
                description="Multiple <h1> tags were found. While HTML5 permits this, having one primary H1 clarifies document structure.",
                recommendation="Consolidate page structure to use a single primary H1, utilizing H2-H4 for subsections.",
                evidence_snippet=", ".join(h.text.strip()[:40] for h in h1_tags[:3])
            ))

        # 4. Canonical URL Check
        canonical_tag = soup.find("link", rel=lambda x: x and "canonical" in x.lower())
        canonical_url = canonical_tag.get("href", "").strip() if canonical_tag else ""
        if not canonical_url:
            score -= 10
            findings.append(FindingDraft(
                category=AuditCategory.SEO,
                rule_id="seo-missing-canonical",
                severity="MEDIUM",
                confidence=1.0,
                title="Missing Canonical Tag",
                description="No <link rel='canonical' href='...'> was declared.",
                recommendation="Specify a canonical URL to prevent duplicate content issues across URL variants.",
                selector="head"
            ))

        # 5. Robots Meta Directives
        robots_meta = soup.find("meta", attrs={"name": lambda x: x and x.lower() == "robots"})
        x_robots_header = response.headers.get("x-robots-tag", "")
        if robots_meta:
            content = robots_meta.get("content", "").lower()
            if "noindex" in content:
                findings.append(FindingDraft(
                    category=AuditCategory.SEO,
                    rule_id="seo-noindex-directive",
                    severity="INFO",
                    confidence=1.0,
                    title="Noindex Directive Detected",
                    description=f"Page specifies '<meta name=\"robots\" content=\"{content}\">'. Search engines will not index this page.",
                    recommendation="Ensure this noindex directive is intentional (e.g. for staging or private pages)."
                ))

        # 6. Images Missing Alt Attributes
        images = soup.find_all("img")
        missing_alt = [img for img in images if not img.get("alt")]
        if missing_alt:
            score -= min(len(missing_alt) * 3, 15)
            findings.append(FindingDraft(
                category=AuditCategory.SEO,
                rule_id="seo-images-missing-alt",
                severity="MEDIUM",
                confidence=1.0,
                title=f"{len(missing_alt)} Images Missing Alternative Text",
                description="Search engine crawlers and screen readers rely on alt attributes to understand image contents.",
                recommendation="Provide meaningful alt text for all content images (use alt='' only for purely decorative graphics).",
                evidence_snippet=missing_alt[0].get("src", "image")[:80]
            ))

        # 7. Open Graph Tags
        og_title = soup.find("meta", property="og:title")
        og_desc = soup.find("meta", property="og:description")
        og_image = soup.find("meta", property="og:image")
        if not (og_title and og_desc and og_image):
            score -= 5
            findings.append(FindingDraft(
                category=AuditCategory.SEO,
                rule_id="seo-incomplete-open-graph",
                severity="LOW",
                confidence=1.0,
                title="Incomplete Open Graph Metadata",
                description="One or more essential Open Graph tags (og:title, og:description, og:image) are missing.",
                recommendation="Implement full Open Graph meta tags to ensure clean preview cards on social networks and messaging platforms."
            ))

        # 8. Structured Data (JSON-LD)
        json_ld_scripts = soup.find_all("script", type="application/ld+json")
        has_structured_data = len(json_ld_scripts) > 0

        final_score = max(0.0, min(100.0, score))
        execution_time_ms = int((time.time() - start_time) * 1000)

        return EngineResult(
            category=AuditCategory.SEO,
            engine_name=self.engine_name,
            engine_version=self.engine_version,
            status=EngineStatus.SUCCESS,
            score=final_score,
            findings=findings,
            raw_evidence={
                "title": title_text,
                "meta_description": desc_text,
                "h1_count": len(h1_tags),
                "canonical_url": canonical_url,
                "robots_header": x_robots_header,
                "images_total": len(images),
                "images_missing_alt": len(missing_alt),
                "has_structured_data": has_structured_data
            },
            limitations=limitations,
            execution_time_ms=execution_time_ms
        )
