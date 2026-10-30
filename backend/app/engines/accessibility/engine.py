"""WebAudit 360 — Accessibility Intelligence Engine (WCAG 2.1 / 2.2 AA)
Author: Harsh Patel

Evaluates:
- axe-core automated rules via headless Playwright Chromium sessions
- Contrast ratios, form labels, image alt text, ARIA attributes, landmarks, and headings
- Traceable CSS selectors and exact HTML snippets
- Transparent labeling of automated results vs. tests requiring manual review
"""

import time
from typing import Any, Dict, List
from playwright.async_api import async_playwright

from backend.app.core.logging import logger
from backend.app.core.ssrf import validate_target_url
from backend.app.engines.base import AuditCategory, BaseAuditEngine, EngineResult, EngineStatus, FindingDraft


# Bundled axe-core runner script evaluating standard WCAG 2.0, 2.1, 2.2 AA rules
AXE_RUNNER_SCRIPT = """
async () => {
    if (typeof axe === 'undefined') {
        const script = document.createElement('script');
        script.src = 'https://cdnjs.cloudflare.com/ajax/libs/axe-core/4.10.2/axe.min.js';
        document.head.appendChild(script);
        await new Promise((resolve, reject) => {
            script.onload = resolve;
            script.onerror = () => reject(new Error('Failed to load axe-core from CDN'));
            setTimeout(() => reject(new Error('axe-core load timeout')), 5000);
        });
    }
    return await axe.run(document, {
        runOnly: {
            type: 'tag',
            values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'best-practice']
        }
    });
}
"""


class AccessibilityEngine(BaseAuditEngine):
    engine_name = "AccessibilityEngine"
    engine_version = "1.0.0"
    category = AuditCategory.ACCESSIBILITY

    async def execute(
        self,
        target_url: str,
        config: Dict[str, Any],
        **kwargs
    ) -> EngineResult:
        start_time = time.time()
        findings: List[FindingDraft] = []
        limitations: List[str] = [
            "Automated accessibility testing with axe-core evaluates approximately 30-40% of WCAG success criteria.",
            "Screen reader flow, cognitive reading comprehension, and keyboard trap edge cases require human manual review.",
            "Tests that cannot be automatically verified are not reported as passed."
        ]

        normalized_url, hostname, _ = validate_target_url(target_url)

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"]
                )
                context = await browser.new_context(
                    viewport={"width": 1280, "height": 800},
                    user_agent="WebAudit360-Bot/1.0 (+https://webaudit360.io/bot; created by Harsh Patel)"
                )
                page = await context.new_page()

                # Navigate with timeout
                await page.goto(normalized_url, wait_until="domcontentloaded", timeout=20000)

                # Inject and run axe-core
                axe_results = await page.evaluate(AXE_RUNNER_SCRIPT)
                await browser.close()

        except Exception as e:
            logger.error(f"Playwright axe-core execution error on '{normalized_url}': {e}")
            return EngineResult(
                category=AuditCategory.ACCESSIBILITY,
                engine_name=self.engine_name,
                engine_version=self.engine_version,
                status=EngineStatus.FAILED,
                error=f"Browser automation error: {str(e)}",
                execution_time_ms=int((time.time() - start_time) * 1000)
            )

        violations = axe_results.get("violations", [])
        passes = axe_results.get("passes", [])
        incomplete = axe_results.get("incomplete", [])

        # Calculate score based on violation count and impact weights
        # Critical = -15, Serious = -10, Moderate = -5, Minor = -2
        deductions = 0.0
        impact_map = {
            "critical": ("CRITICAL", 15.0),
            "serious": ("HIGH", 10.0),
            "moderate": ("MEDIUM", 5.0),
            "minor": ("LOW", 2.0),
        }

        for v in violations:
            rule_id = v.get("id", "axe-violation")
            impact = v.get("impact", "moderate")
            severity, weight = impact_map.get(impact, ("MEDIUM", 5.0))
            deductions += weight

            # Extract nodes and selectors
            nodes = v.get("nodes", [])
            primary_selector = nodes[0].get("target", ["body"])[0] if nodes else "body"
            html_snippet = nodes[0].get("html", "")[:200] if nodes else ""

            findings.append(FindingDraft(
                category=AuditCategory.ACCESSIBILITY,
                rule_id=f"wcag-{rule_id}",
                severity=severity,
                confidence=1.0,
                title=v.get("help", rule_id),
                description=v.get("description", ""),
                recommendation=f"Review rule documentation: {v.get('helpUrl', 'https://dequeuniversity.com/rules/axe/4.10')}",
                selector=str(primary_selector),
                evidence_snippet=html_snippet,
                raw_details={"tags": v.get("tags", []), "nodes_count": len(nodes)}
            ))

        # Add manual review reminder for incomplete tests
        if incomplete:
            findings.append(FindingDraft(
                category=AuditCategory.ACCESSIBILITY,
                rule_id="wcag-manual-review-required",
                severity="INFO",
                confidence=1.0,
                title=f"{len(incomplete)} Criteria Require Manual Human Review",
                description="Automated tests could not definitively verify specific items (such as complex color contrast on gradient backgrounds). These require manual verification.",
                recommendation="Perform interactive screen reader testing (NVDA / VoiceOver) and manual keyboard navigation."
            ))

        score = max(0.0, min(100.0, 100.0 - deductions))
        execution_time_ms = int((time.time() - start_time) * 1000)

        return EngineResult(
            category=AuditCategory.ACCESSIBILITY,
            engine_name=self.engine_name,
            engine_version=self.engine_version,
            status=EngineStatus.SUCCESS,
            score=score,
            findings=findings,
            raw_evidence={
                "violations_count": len(violations),
                "passes_count": len(passes),
                "incomplete_count": len(incomplete),
                "axe_version": "4.10.2"
            },
            limitations=limitations,
            execution_time_ms=execution_time_ms
        )

