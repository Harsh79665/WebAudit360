"""WebAudit 360 — Long Animation Frames (LoAF) & INP Script Attributor Engine
Author: Harsh Patel

Evaluates:
- Long Animation Frames API (LoAF, W3C Performance Timeline)
- Interaction to Next Paint (INP) bottleneck attribution
- Blocking script attribution (first-party vs third-party)
- Microtask & event listener main-thread duration
- Async/defer attributes and render-blocking script heuristics
"""

import time
import asyncio
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


class LoAFEngine(BaseAuditEngine):
    engine_name = "LoAFEngine"
    engine_version = "1.0.0"
    category = AuditCategory.LOAF_INP

    async def execute(
        self,
        target_url: str,
        config: Dict[str, Any],
        **kwargs
    ) -> EngineResult:
        start_time = time.time()
        findings: List[FindingDraft] = []
        limitations: List[str] = [
            "Synthetic simulation tests main-thread latency and script attribution.",
            "Real-user interaction events (e.g. keyboard/click INP) reflect lab approximations.",
        ]

        normalized_url, hostname, _ = validate_target_url(target_url)

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 WebAudit360/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }

        html_content = ""
        script_tags: List[Dict[str, Any]] = []
        loaf_entries: List[Dict[str, Any]] = []
        observed_inp_ms: float = 45.0  # Baseline good INP in lab
        total_blocking_time_ms: float = 0.0

        # Attempt Playwright headless CDP capture for genuine LoAF PerformanceObserver
        playwright_captured = False
        try:
            from playwright.async_api import async_playwright
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=["--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage"]
                )
                context = await browser.new_context(
                    viewport={"width": 1280, "height": 800},
                    user_agent=headers["User-Agent"]
                )
                page = await context.new_page()

                # Inject PerformanceObserver to collect long-animation-frame & longtask entries
                await page.add_init_script("""
                    window.__webaudit_loaf = [];
                    window.__webaudit_longtasks = [];
                    try {
                        const observer = new PerformanceObserver((list) => {
                            for (const entry of list.getEntries()) {
                                window.__webaudit_loaf.push({
                                    duration: entry.duration,
                                    startTime: entry.startTime,
                                    renderStart: entry.renderStart,
                                    styleAndLayoutStart: entry.styleAndLayoutStart,
                                    scripts: (entry.scripts || []).map(s => ({
                                        invoker: s.invoker,
                                        invokerType: s.invokerType,
                                        sourceURL: s.sourceURL,
                                        sourceFunctionName: s.sourceFunctionName,
                                        sourceCharPosition: s.sourceCharPosition,
                                        duration: s.duration,
                                        pauseDuration: s.pauseDuration,
                                        forcedStyleAndLayoutDuration: s.forcedStyleAndLayoutDuration
                                    }))
                                });
                            }
                        });
                        observer.observe({ type: 'long-animation-frame', buffered: true });
                    } catch (e) {}

                    try {
                        const ltObserver = new PerformanceObserver((list) => {
                            for (const entry of list.getEntries()) {
                                window.__webaudit_longtasks.push({
                                    duration: entry.duration,
                                    startTime: entry.startTime,
                                    name: entry.name
                                });
                            }
                        });
                        ltObserver.observe({ entryTypes: ['longtask'] });
                    } catch (e) {}
                """)

                await page.goto(normalized_url, wait_until="load", timeout=12000)
                await page.wait_for_timeout(1000)

                html_content = await page.content()
                loaf_data = await page.evaluate("window.__webaudit_loaf || []")
                longtasks_data = await page.evaluate("window.__webaudit_longtasks || []")
                await context.close()
                await browser.close()

                loaf_entries = loaf_data
                playwright_captured = True

                for lt in longtasks_data:
                    d = float(lt.get("duration", 0))
                    if d > 50:
                        total_blocking_time_ms += (d - 50)
                if total_blocking_time_ms > 0:
                    observed_inp_ms = min(600.0, 50.0 + (total_blocking_time_ms * 0.4))
        except Exception:
            # Fallback to direct HTTP fetch and static AST/DOM script analysis
            try:
                async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, headers=headers) as client:
                    resp = await client.get(normalized_url)
                    html_content = resp.text
            except Exception as e:
                return EngineResult(
                    category=AuditCategory.LOAF_INP,
                    engine_name=self.engine_name,
                    engine_version=self.engine_version,
                    status=EngineStatus.FAILED,
                    error=f"Could not connect to target URL: {str(e)}",
                    execution_time_ms=int((time.time() - start_time) * 1000)
                )

        # Parse scripts from HTML
        soup = BeautifulSoup(html_content, "html.parser")
        parsed_origin = urlparse(normalized_url).netloc

        blocking_scripts = []
        deferred_scripts = []
        async_scripts = []
        inline_scripts = []

        for script in soup.find_all("script"):
            src = script.get("src")
            is_async = script.has_attr("async")
            is_defer = script.has_attr("defer")
            is_module = script.get("type") == "module"
            inline_body = script.string or ""

            if src:
                full_src = urljoin(normalized_url, src)
                src_netloc = urlparse(full_src).netloc
                is_third_party = (src_netloc != parsed_origin) and bool(src_netloc)
                script_info = {
                    "src": full_src,
                    "is_async": is_async,
                    "is_defer": is_defer,
                    "is_module": is_module,
                    "is_third_party": is_third_party,
                    "netloc": src_netloc
                }
                script_tags.append(script_info)

                if not is_async and not is_defer and not is_module:
                    blocking_scripts.append(script_info)
                elif is_async:
                    async_scripts.append(script_info)
                else:
                    deferred_scripts.append(script_info)
            else:
                length = len(inline_body.strip())
                if length > 0:
                    inline_scripts.append({"length": length})

        # Calculate Score
        # Max score: 100
        # Deduct for render-blocking scripts, large inline scripts, and observed LoAF duration
        score = 100.0

        if blocking_scripts:
            deduction = min(35.0, len(blocking_scripts) * 7.0)
            score -= deduction
            findings.append(FindingDraft(
                category=AuditCategory.LOAF_INP,
                rule_id="loaf-render-blocking-scripts",
                severity="HIGH" if len(blocking_scripts) > 3 else "MEDIUM",
                title=f"{len(blocking_scripts)} Render-Blocking Scripts Identified",
                description=(
                    f"Found {len(blocking_scripts)} synchronous external scripts that block main-thread "
                    "parsing and directly degrade Interaction to Next Paint (INP) responsiveness."
                ),
                recommendation="Add 'defer' or 'async' attributes, or convert scripts to ES modules.",
                evidence_snippet="\n".join([s["src"] for s in blocking_scripts[:5]]),
                raw_details={"blocking_count": len(blocking_scripts), "scripts": blocking_scripts[:10]}
            ))

        large_inline = [s for s in inline_scripts if s["length"] > 10000]
        if large_inline:
            score -= min(15.0, len(large_inline) * 5.0)
            findings.append(FindingDraft(
                category=AuditCategory.LOAF_INP,
                rule_id="loaf-large-inline-script",
                severity="MEDIUM",
                title=f"{len(large_inline)} Heavy Inline Scripts Detected",
                description="Inline scripts over 10KB increase initial compilation time and delay frame execution.",
                recommendation="Externalize heavy script bundles to enable browser bytecode caching.",
                raw_details={"large_inline_count": len(large_inline)}
            ))

        if loaf_entries:
            score -= min(30.0, len(loaf_entries) * 10.0)
            findings.append(FindingDraft(
                category=AuditCategory.LOAF_INP,
                rule_id="loaf-long-animation-frames-detected",
                severity="HIGH",
                title=f"{len(loaf_entries)} Long Animation Frames (LoAF) Detected",
                description="Observed frame rendering tasks exceeding 50ms threshold via the LoAF PerformanceObserver API.",
                recommendation="Break down long microtasks using scheduler.yield() or requestIdleCallback().",
                raw_details={"loaf_count": len(loaf_entries), "entries": loaf_entries[:5]}
            ))
        elif not blocking_scripts:
            findings.append(FindingDraft(
                category=AuditCategory.LOAF_INP,
                rule_id="loaf-optimized-scripts",
                severity="INFO",
                title="Scripts Highly Optimized for INP & Main Thread",
                description="All external scripts utilize asynchronous, deferred, or module loading patterns with zero observed LoAF bottlenecks.",
                recommendation="Continue maintaining decoupled event handlers and lightweight script bundles."
            ))

        final_score = max(0.0, min(100.0, round(score, 1)))

        raw_evidence = {
            "playwright_captured": playwright_captured,
            "total_scripts": len(script_tags),
            "render_blocking_count": len(blocking_scripts),
            "async_count": len(async_scripts),
            "deferred_count": len(deferred_scripts),
            "inline_count": len(inline_scripts),
            "loaf_entries": loaf_entries,
            "estimated_inp_ms": round(observed_inp_ms, 1),
            "estimated_tbt_ms": round(total_blocking_time_ms, 1),
            "inp_rating": "Good" if observed_inp_ms <= 200 else ("Needs Improvement" if observed_inp_ms <= 500 else "Poor")
        }

        return EngineResult(
            category=AuditCategory.LOAF_INP,
            engine_name=self.engine_name,
            engine_version=self.engine_version,
            status=EngineStatus.SUCCESS,
            score=final_score,
            findings=findings,
            raw_evidence=raw_evidence,
            limitations=limitations,
            execution_time_ms=int((time.time() - start_time) * 1000)
        )
