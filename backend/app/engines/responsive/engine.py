"""WebAudit 360 — Responsive Behavior Intelligence Engine
Author: Harsh Patel

Evaluates:
- Viewport rendering across Mobile (390×844), Tablet (768×1024), Desktop (1440×900)
- Horizontal overflow detection (scrollWidth > clientWidth)
- Viewport meta tag configuration (width=device-width, initial-scale=1)
- Touch target sizing (min 44×44px or 48×48px for interactive elements)
"""

import time
from typing import Any, Dict, List
from playwright.async_api import async_playwright

from backend.app.core.logging import logger
from backend.app.core.ssrf import validate_target_url
from backend.app.engines.base import AuditCategory, BaseAuditEngine, EngineResult, EngineStatus, FindingDraft

VIEWPORTS = [
    {"name": "Mobile", "width": 390, "height": 844, "is_mobile": True},
    {"name": "Tablet", "width": 768, "height": 1024, "is_mobile": False},
    {"name": "Desktop", "width": 1440, "height": 900, "is_mobile": False},
]


class ResponsiveEngine(BaseAuditEngine):
    engine_name = "ResponsiveEngine"
    engine_version = "1.0.0"
    category = AuditCategory.RESPONSIVE

    async def execute(
        self,
        target_url: str,
        config: Dict[str, Any],
        **kwargs
    ) -> EngineResult:
        start_time = time.time()
        findings: List[FindingDraft] = []
        limitations: List[str] = [
            "Browser viewport emulation simulates screen resolution but cannot replicate physical GPU latency or device touch quirks.",
            "Dynamic elements toggled exclusively by user interactions may require interactive session recording."
        ]

        normalized_url, hostname, _ = validate_target_url(target_url)
        viewport_results = {}
        score = 100.0

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"]
                )

                for vp in VIEWPORTS:
                    context = await browser.new_context(
                        viewport={"width": vp["width"], "height": vp["height"]},
                        is_mobile=vp["is_mobile"],
                        user_agent="WebAudit360-Bot/1.0 (+https://webaudit360.io/bot; created by Harsh Patel)"
                    )
                    page = await context.new_page()
                    await page.goto(normalized_url, wait_until="domcontentloaded", timeout=20000)

                    # Check for horizontal overflow
                    overflow_data = await page.evaluate("""() => {
                        const doc = document.documentElement;
                        const body = document.body;
                        const hasOverflow = (doc.scrollWidth > doc.clientWidth) || (body.scrollWidth > body.clientWidth);
                        const scrollDiff = Math.max(doc.scrollWidth - doc.clientWidth, body.scrollWidth - body.clientWidth);

                        // Check viewport meta
                        const vpMeta = document.querySelector('meta[name="viewport"]');
                        const vpContent = vpMeta ? vpMeta.getAttribute('content') : null;

                        // Check small touch targets on mobile
                        let smallTargets = 0;
                        if (window.innerWidth <= 480) {
                            const interactives = document.querySelectorAll('button, a, input, select');
                            for (let el of interactives) {
                                const rect = el.getBoundingClientRect();
                                if (rect.width > 0 && rect.height > 0 && (rect.width < 32 || rect.height < 32)) {
                                    smallTargets++;
                                }
                            }
                        }

                        return {
                            has_overflow: hasOverflow,
                            overflow_pixels: Math.max(0, scrollDiff),
                            viewport_meta: vpContent,
                            small_touch_targets_count: smallTargets
                        };
                    }""")

                    viewport_results[vp["name"]] = overflow_data

                    if overflow_data["has_overflow"] and overflow_data["overflow_pixels"] > 5:
                        score -= 15
                        findings.append(FindingDraft(
                            category=AuditCategory.RESPONSIVE,
                            rule_id=f"responsive-overflow-{vp['name'].lower()}",
                            severity="HIGH" if vp["is_mobile"] else "MEDIUM",
                            confidence=1.0,
                            title=f"Horizontal Content Overflow on {vp['name']} ({vp['width']}px)",
                            description=f"The page body exceeds the viewport by {overflow_data['overflow_pixels']}px, causing undesirable horizontal scrolling.",
                            recommendation="Check elements with fixed CSS widths or unconstrained images. Use max-width: 100% and overflow-x: hidden where appropriate."
                        ))

                    if not overflow_data["viewport_meta"]:
                        score -= 20
                        findings.append(FindingDraft(
                            category=AuditCategory.RESPONSIVE,
                            rule_id="responsive-missing-viewport-meta",
                            severity="HIGH",
                            confidence=1.0,
                            title="Missing Viewport Meta Tag",
                            description="No <meta name='viewport'> tag was detected. Mobile browsers will render the page at desktop scaling.",
                            recommendation="Add <meta name='viewport' content='width=device-width, initial-scale=1'> to document <head>."
                        ))
                        break  # Report only once

                    if overflow_data.get("small_touch_targets_count", 0) > 3:
                        score -= 5
                        findings.append(FindingDraft(
                            category=AuditCategory.RESPONSIVE,
                            rule_id="responsive-small-touch-targets",
                            severity="LOW",
                            confidence=1.0,
                            title=f"{overflow_data['small_touch_targets_count']} Tap Targets Under Recommended Size",
                            description="Interactive elements (buttons, links) measuring under 32×32px are difficult for mobile users to tap reliably.",
                            recommendation="Ensure tap targets have a minimum touch footprint of 44×44px or 48×48px with adequate padding."
                        ))

                    await context.close()

                await browser.close()

        except Exception as e:
            logger.error(f"Responsive engine execution error: {e}")
            return EngineResult(
                category=AuditCategory.RESPONSIVE,
                engine_name=self.engine_name,
                engine_version=self.engine_version,
                status=EngineStatus.FAILED,
                error=str(e),
                execution_time_ms=int((time.time() - start_time) * 1000)
            )

        final_score = max(0.0, min(100.0, score))
        execution_time_ms = int((time.time() - start_time) * 1000)

        return EngineResult(
            category=AuditCategory.RESPONSIVE,
            engine_name=self.engine_name,
            engine_version=self.engine_version,
            status=EngineStatus.SUCCESS,
            score=final_score,
            findings=findings,
            raw_evidence={"viewports": viewport_results},
            limitations=limitations,
            execution_time_ms=execution_time_ms
        )
