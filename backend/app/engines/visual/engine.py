"""WebAudit 360 — Visual Regression & Layout Stability Engine
Author: Harsh Patel

Captures deterministic screenshots across Desktop (1280x800) and Mobile (390x844) viewports
using headless Playwright, resolves historical baseline captures, and calculates pixel-level
perceptual diffs and visual health scores using Pillow.
"""

import os
import time
from typing import Any, Dict, List, Optional, Tuple
from PIL import Image, ImageChops
from playwright.async_api import async_playwright
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.core.ssrf import validate_target_url
from backend.app.engines.base import (
    AuditCategory,
    BaseAuditEngine,
    EngineResult,
    EngineStatus,
    FindingDraft,
)
from backend.app.models.entities import Audit, AuditStatus

VIEWPORTS = [
    {"name": "desktop", "width": 1280, "height": 800, "is_mobile": False},
    {"name": "mobile", "width": 390, "height": 844, "is_mobile": True},
]

# CSS injected into page context to prevent false-positive visual diffs
ANIMATION_NEUTRALIZATION_CSS = """
*, *::before, *::after {
    animation-duration: 0s !important;
    animation-delay: 0s !important;
    transition-duration: 0s !important;
    transition-delay: 0s !important;
    caret-color: transparent !important;
}
"""


def get_screenshots_dir() -> str:
    """Returns the absolute path to the screenshot storage directory, creating it if needed."""
    directory = os.path.join(settings.STORAGE_LOCAL_DIR, "screenshots")
    os.makedirs(directory, exist_ok=True)
    return directory


def compute_image_diff(
    baseline_path: str,
    current_path: str,
    diff_output_path: str,
    threshold: int = 15
) -> Tuple[float, int, int]:
    """
    Computes pixel-by-pixel diff between baseline and current screenshots using Pillow.
    
    Returns:
        Tuple of (mismatch_percentage, diff_pixels_count, total_pixels)
    """
    with Image.open(baseline_path) as b_img, Image.open(current_path) as c_img:
        b_rgba = b_img.convert("RGBA")
        c_rgba = c_img.convert("RGBA")

        # Handle potential dimension mismatch by padding to common canvas
        max_w = max(b_rgba.width, c_rgba.width)
        max_h = max(b_rgba.height, c_rgba.height)

        if b_rgba.size != (max_w, max_h):
            padded_b = Image.new("RGBA", (max_w, max_h), (255, 255, 255, 255))
            padded_b.paste(b_rgba, (0, 0))
            b_rgba = padded_b

        if c_rgba.size != (max_w, max_h):
            padded_c = Image.new("RGBA", (max_w, max_h), (255, 255, 255, 255))
            padded_c.paste(c_rgba, (0, 0))
            c_rgba = padded_c

        total_pixels = max_w * max_h

        # Compute difference and grayscale mask
        diff = ImageChops.difference(b_rgba, c_rgba)
        gray_diff = diff.convert("L")

        # Histogram-based counting for fast C-level evaluation
        histogram = gray_diff.histogram()
        # Sum count of pixels above tolerance threshold (filters anti-aliasing artifacts)
        diff_pixels = sum(histogram[threshold + 1:])
        mismatch_pct = round((diff_pixels / total_pixels) * 100.0, 3)

        # Generate visual diff mask image
        # Mask: 255 where diff > threshold, 0 elsewhere
        mask = gray_diff.point(lambda p: 255 if p > threshold else 0, mode="L")

        # Dimmed current image as background
        white_bg = Image.new("RGBA", (max_w, max_h), (255, 255, 255, 255))
        dimmed_current = Image.blend(c_rgba, white_bg, 0.55)

        # Magenta highlight for changed pixels
        highlight = Image.new("RGBA", (max_w, max_h), (255, 0, 128, 255))

        # Composite highlight onto dimmed current image using the binary mask
        diff_image = Image.composite(highlight, dimmed_current, mask)
        diff_image.save(diff_output_path, "PNG", optimize=True)

        return mismatch_pct, diff_pixels, total_pixels


class VisualRegressionEngine(BaseAuditEngine):
    engine_name = "VisualRegressionEngine"
    engine_version = "1.0.0"
    category = AuditCategory.VISUAL

    async def execute(
        self,
        target_url: str,
        config: Dict[str, Any],
        **kwargs
    ) -> EngineResult:
        start_time = time.time()
        findings: List[FindingDraft] = []
        limitations: List[str] = [
            "Visual regression captures fixed viewports (1280x800 and 390x844); dynamic height pages are aligned at origin.",
            "CSS animations and transitions are neutralized to prevent false-positive transient diffs.",
        ]

        normalized_url, hostname, _ = validate_target_url(target_url)
        audit_id = config.get("audit_id", int(time.time()))
        project_id = config.get("project_id")
        session: Optional[AsyncSession] = config.get("session")

        screenshots_dir = get_screenshots_dir()
        viewport_results: Dict[str, Any] = {}
        mismatch_percentages: List[float] = []

        # Step 1: Resolve baseline audit
        baseline_audit_id: Optional[int] = config.get("baseline_audit_id")
        if baseline_audit_id is None and session is not None:
            baseline_audit_id = await self._find_baseline_audit_id(
                session, normalized_url, project_id, audit_id
            )

        try:
            # Step 2: Capture screenshots with Playwright
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        "--disable-font-subpixel-positioning"
                    ]
                )

                for vp in VIEWPORTS:
                    vp_name = vp["name"]
                    context = await browser.new_context(
                        viewport={"width": vp["width"], "height": vp["height"]},
                        is_mobile=vp["is_mobile"],
                        user_agent="WebAudit360-Bot/1.0 (+https://webaudit360.io/bot; created by Harsh Patel)",
                        reduced_motion="reduce",
                        color_scheme="light"
                    )
                    page = await context.new_page()

                    # Freeze animations on page load
                    await page.add_init_script(f"""
                        window.addEventListener('DOMContentLoaded', () => {{
                            const style = document.createElement('style');
                            style.textContent = `{ANIMATION_NEUTRALIZATION_CSS}`;
                            document.head.appendChild(style);
                        }});
                    """)

                    try:
                        await page.goto(normalized_url, wait_until="networkidle", timeout=30000)
                    except Exception:
                        # Fallback if networkidle times out
                        await page.goto(normalized_url, wait_until="load", timeout=20000)

                    await page.wait_for_timeout(500)  # brief stabilization

                    current_filename = f"{audit_id}_{vp_name}.png"
                    current_path = os.path.join(screenshots_dir, current_filename)
                    await page.screenshot(path=current_path, full_page=False)

                    # Step 3: Diff against baseline if available
                    has_baseline = False
                    baseline_filename = None
                    diff_filename = None
                    mismatch_pct = 0.0
                    diff_pixels = 0
                    total_pixels = vp["width"] * vp["height"]

                    if baseline_audit_id:
                        potential_baseline_filename = f"{baseline_audit_id}_{vp_name}.png"
                        potential_baseline_path = os.path.join(screenshots_dir, potential_baseline_filename)

                        if os.path.exists(potential_baseline_path):
                            has_baseline = True
                            baseline_filename = potential_baseline_filename
                            diff_filename = f"{audit_id}_diff_{vp_name}.png"
                            diff_path = os.path.join(screenshots_dir, diff_filename)

                            mismatch_pct, diff_pixels, total_pixels = compute_image_diff(
                                baseline_path=potential_baseline_path,
                                current_path=current_path,
                                diff_output_path=diff_path
                            )
                            mismatch_percentages.append(mismatch_pct)

                    if not has_baseline:
                        # This capture is established as the baseline
                        baseline_filename = current_filename
                        mismatch_pct = 0.0
                        mismatch_percentages.append(0.0)

                    viewport_results[vp_name] = {
                        "width": vp["width"],
                        "height": vp["height"],
                        "current_screenshot": current_filename,
                        "baseline_screenshot": baseline_filename,
                        "diff_screenshot": diff_filename,
                        "mismatch_percentage": mismatch_pct,
                        "diff_pixels": diff_pixels,
                        "total_pixels": total_pixels,
                        "has_baseline": has_baseline
                    }

                    # Step 4: Emit findings for noticeable regressions
                    if mismatch_pct > 5.0:
                        findings.append(FindingDraft(
                            category=AuditCategory.VISUAL,
                            rule_id=f"vis-layout-shift-{vp_name}",
                            severity="HIGH",
                            confidence=1.0,
                            title=f"Significant Visual Shift on {vp_name.title()} ({mismatch_pct:.2f}% mismatch)",
                            description=(
                                f"Visual regression analysis identified {diff_pixels:,} mismatched pixels "
                                f"({mismatch_pct:.2f}%) compared to baseline capture #{baseline_audit_id}."
                            ),
                            recommendation="Inspect the highlighted diff image to verify unintended CSS reflow, overlapping layers, or broken assets.",
                            raw_details={"viewport": vp_name, "mismatch_percentage": mismatch_pct, "diff_pixels": diff_pixels}
                        ))
                    elif mismatch_pct > 1.0:
                        findings.append(FindingDraft(
                            category=AuditCategory.VISUAL,
                            rule_id=f"vis-layout-shift-{vp_name}",
                            severity="MEDIUM",
                            confidence=0.95,
                            title=f"Minor Layout Shift on {vp_name.title()} ({mismatch_pct:.2f}% mismatch)",
                            description=(
                                f"Observed a {mismatch_pct:.2f}% pixel variance against the baseline audit. "
                                f"May reflect minor margin or content adjustments."
                            ),
                            recommendation="Review the diff overlay to ensure changes align with intended design updates.",
                            raw_details={"viewport": vp_name, "mismatch_percentage": mismatch_pct, "diff_pixels": diff_pixels}
                        ))

                    await context.close()

                await browser.close()

        except Exception as e:
            logger.error(f"VisualRegressionEngine execution failed: {e}", exc_info=True)
            return EngineResult(
                category=AuditCategory.VISUAL,
                engine_name=self.engine_name,
                engine_version=self.engine_version,
                status=EngineStatus.FAILED,
                error=str(e),
                execution_time_ms=int((time.time() - start_time) * 1000)
            )

        # Step 5: Calculate visual stability score
        max_mismatch = max(mismatch_percentages) if mismatch_percentages else 0.0
        visual_score = max(0.0, round(100.0 - (max_mismatch * 5.0), 1))
        baseline_established = not any(v.get("has_baseline") for v in viewport_results.values())

        raw_evidence = {
            "baseline_established": baseline_established,
            "baseline_audit_id": baseline_audit_id if not baseline_established else audit_id,
            "score": visual_score,
            "overall_mismatch_percentage": max_mismatch,
            "viewports": viewport_results
        }

        return EngineResult(
            category=AuditCategory.VISUAL,
            engine_name=self.engine_name,
            engine_version=self.engine_version,
            status=EngineStatus.SUCCESS,
            score=visual_score,
            findings=findings,
            raw_evidence=raw_evidence,
            limitations=limitations,
            execution_time_ms=int((time.time() - start_time) * 1000)
        )

    async def _find_baseline_audit_id(
        self,
        session: AsyncSession,
        target_url: str,
        project_id: Optional[int],
        current_audit_id: int
    ) -> Optional[int]:
        """Queries for the latest completed audit for the same URL/Project prior to current_audit_id."""
        query = (
            select(Audit.id)
            .where(
                Audit.target_url == target_url,
                Audit.id < current_audit_id,
                Audit.status == AuditStatus.COMPLETED
            )
        )
        if project_id:
            query = query.where(Audit.project_id == project_id)
        query = query.order_by(Audit.created_at.desc(), Audit.id.desc()).limit(1)

        result = await session.execute(query)
        return result.scalar_one_or_none()
