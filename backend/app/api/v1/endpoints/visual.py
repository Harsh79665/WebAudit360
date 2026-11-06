"""WebAudit 360 — Visual Regression API Routes
Author: Harsh Patel
"""

import os
import re
from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.models.entities import Audit
from backend.app.schemas import VisualRegressionResponse, ViewportVisualDiff
from backend.app.engines.visual.engine import get_screenshots_dir, VisualRegressionEngine
from backend.app.core.logging import logger

router = APIRouter(tags=["Visual Regression"])

# Regex for safe screenshot filenames (audit_id + optional suffix + .png)
SAFE_FILENAME_REGEX = re.compile(r"^[a-zA-Z0-9_\-]+\.png$")


@router.get("/screenshots/{filename}", response_class=FileResponse)
async def get_screenshot(filename: str):
    """
    Safely streams visual regression screenshots and diff mask images.
    Enforces strict filename validation and directory containment to prevent path traversal.
    """
    if not SAFE_FILENAME_REGEX.match(filename):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid screenshot filename format."
        )

    screenshots_dir = os.path.abspath(get_screenshots_dir())
    requested_path = os.path.abspath(os.path.join(screenshots_dir, filename))

    # Path traversal guard: must be strictly inside screenshots_dir
    if not requested_path.startswith(screenshots_dir) or not os.path.exists(requested_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Screenshot not found."
        )

    return FileResponse(
        requested_path,
        media_type="image/png",
        headers={"Cache-Control": "public, max-age=86400, immutable"}
    )


@router.get("/audits/{audit_id}/visual", response_model=VisualRegressionResponse)
async def get_audit_visual_data(
    audit_id: int,
    session: AsyncSession = Depends(get_db)
):
    """
    Retrieves visual regression comparison data, baseline details, diff metrics,
    and screenshot URLs for a given audit run.
    """
    result = await session.execute(select(Audit).where(Audit.id == audit_id))
    audit = result.scalars().first()
    if not audit:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit not found."
        )

    raw_results = audit.raw_results or {}
    visual_raw = raw_results.get("VISUAL", {})

    # If visual regression hasn't been run yet for this audit, capture on demand
    if not visual_raw and audit.target_url:
        try:
            engine = VisualRegressionEngine()
            res = await engine.execute(
                audit.target_url,
                {"audit_id": audit.id, "project_id": audit.project_id, "session": session}
            )
            visual_raw = res.raw_evidence
            updated_raw = dict(raw_results)
            updated_raw["VISUAL"] = visual_raw
            audit.raw_results = updated_raw
            await session.commit()
            await session.refresh(audit)
        except Exception as e:
            logger.warning(f"On-demand visual capture for audit #{audit_id} skipped: {e}")

    viewports_response: Dict[str, ViewportVisualDiff] = {}
    raw_viewports = visual_raw.get("viewports", {})

    for vp_name, vp_data in raw_viewports.items():
        current_file = vp_data.get("current_screenshot")
        baseline_file = vp_data.get("baseline_screenshot")
        diff_file = vp_data.get("diff_screenshot")

        viewports_response[vp_name] = ViewportVisualDiff(
            width=vp_data.get("width", 1280),
            height=vp_data.get("height", 800),
            current_url=f"/api/v1/screenshots/{current_file}" if current_file else None,
            baseline_url=f"/api/v1/screenshots/{baseline_file}" if baseline_file else None,
            diff_url=f"/api/v1/screenshots/{diff_file}" if diff_file else None,
            mismatch_percentage=vp_data.get("mismatch_percentage", 0.0),
            diff_pixels=vp_data.get("diff_pixels", 0),
            total_pixels=vp_data.get("total_pixels", 0),
            has_baseline=vp_data.get("has_baseline", False)
        )

    return VisualRegressionResponse(
        audit_id=audit.id,
        target_url=audit.target_url,
        baseline_audit_id=visual_raw.get("baseline_audit_id"),
        baseline_established=visual_raw.get("baseline_established", False),
        score=visual_raw.get("score"),
        overall_mismatch_percentage=visual_raw.get("overall_mismatch_percentage", 0.0),
        viewports=viewports_response
    )
