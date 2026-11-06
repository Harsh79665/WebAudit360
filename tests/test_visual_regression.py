"""WebAudit 360 — Visual Regression Test Suite
Author: Harsh Patel
"""

import os
import tempfile
import pytest
import pytest_asyncio
from PIL import Image
from unittest.mock import AsyncMock, patch
import httpx

from backend.app.main import app
from backend.app.core.database import init_db
from backend.app.engines.base import AuditCategory, EngineStatus
from backend.app.engines.visual.engine import (
    VisualRegressionEngine,
    compute_image_diff,
    get_screenshots_dir,
)
from backend.app.api.v1.endpoints.visual import SAFE_FILENAME_REGEX


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    await init_db()


def test_safe_filename_regex():
    """Verify screenshot filename sanitization rules."""
    assert SAFE_FILENAME_REGEX.match("12_desktop.png")
    assert SAFE_FILENAME_REGEX.match("12_diff_desktop.png")
    assert SAFE_FILENAME_REGEX.match("999_mobile.png")
    assert not SAFE_FILENAME_REGEX.match("../12_desktop.png")
    assert not SAFE_FILENAME_REGEX.match("test/12.png")
    assert not SAFE_FILENAME_REGEX.match("payload.php")
    assert not SAFE_FILENAME_REGEX.match("test.png.exe")


def test_pillow_diff_calculation_identical_images():
    """Verify that identical images yield 0.0% mismatch and 100% stability."""
    with tempfile.TemporaryDirectory() as tmpdir:
        b_path = os.path.join(tmpdir, "baseline.png")
        c_path = os.path.join(tmpdir, "current.png")
        diff_path = os.path.join(tmpdir, "diff.png")

        img = Image.new("RGBA", (100, 100), (255, 255, 255, 255))
        img.save(b_path)
        img.save(c_path)

        mismatch_pct, diff_pixels, total_pixels = compute_image_diff(b_path, c_path, diff_path)
        assert mismatch_pct == 0.0
        assert diff_pixels == 0
        assert total_pixels == 10000
        assert os.path.exists(diff_path)


def test_pillow_diff_calculation_with_variations():
    """Verify that deliberate pixel mutations produce proportional mismatch metrics."""
    with tempfile.TemporaryDirectory() as tmpdir:
        b_path = os.path.join(tmpdir, "baseline.png")
        c_path = os.path.join(tmpdir, "current.png")
        diff_path = os.path.join(tmpdir, "diff.png")

        # Baseline: white 100x100
        img_b = Image.new("RGBA", (100, 100), (255, 255, 255, 255))
        img_b.save(b_path)

        # Current: 500 mutated pixels (5% of total)
        img_c = Image.new("RGBA", (100, 100), (255, 255, 255, 255))
        for x in range(50):
            for y in range(10):
                img_c.putpixel((x, y), (20, 20, 20, 255))
        img_c.save(c_path)

        mismatch_pct, diff_pixels, total_pixels = compute_image_diff(b_path, c_path, diff_path)
        assert mismatch_pct == 5.0
        assert diff_pixels == 500
        assert total_pixels == 10000
        assert os.path.exists(diff_path)


@pytest.mark.asyncio
async def test_visual_engine_baseline_establishment():
    """Verify that when no baseline exists, engine establishes the initial reference standard."""
    engine = VisualRegressionEngine()
    with tempfile.TemporaryDirectory() as tmpdir:
        with patch("backend.app.engines.visual.engine.get_screenshots_dir", return_value=tmpdir):
            with patch("backend.app.engines.visual.engine.async_playwright") as mock_pw:
                # Mock playwright browser & screenshot
                mock_page = AsyncMock()
                mock_context = AsyncMock()
                mock_context.new_page.return_value = mock_page
                mock_browser = AsyncMock()
                mock_browser.new_context.return_value = mock_context

                async def mock_screenshot(path, **kwargs):
                    img = Image.new("RGBA", (1280, 800), (255, 255, 255, 255))
                    img.save(path)

                mock_page.screenshot.side_effect = mock_screenshot

                mock_playwright = AsyncMock()
                mock_playwright.chromium.launch.return_value = mock_browser
                mock_pw.return_value.__aenter__.return_value = mock_playwright

                result = await engine.execute(
                    "https://example.com",
                    config={"audit_id": 999, "baseline_audit_id": None}
                )

                assert result.status == EngineStatus.SUCCESS
                assert result.category == AuditCategory.VISUAL
                assert result.score == 100.0
                assert result.raw_evidence["baseline_established"] is True
                assert result.raw_evidence["overall_mismatch_percentage"] == 0.0
                assert "desktop" in result.raw_evidence["viewports"]
                assert "mobile" in result.raw_evidence["viewports"]


@pytest.mark.asyncio
async def test_get_screenshot_endpoint_security():
    """Verify path traversal prevention and file streaming on /api/v1/screenshots."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Invalid filename with directory traversal
        res_bad = await client.get("/api/v1/screenshots/..%2Fsecret.png")
        assert res_bad.status_code in (400, 404)

        res_invalid = await client.get("/api/v1/screenshots/script.js")
        assert res_invalid.status_code == 400

        # Non-existent file
        res_not_found = await client.get("/api/v1/screenshots/nonexistent_99999.png")
        assert res_not_found.status_code == 404

        # Real file in screenshots directory
        screenshots_dir = get_screenshots_dir()
        test_filename = "test_sample_capture.png"
        test_file_path = os.path.join(screenshots_dir, test_filename)
        img = Image.new("RGBA", (50, 50), (100, 150, 200, 255))
        img.save(test_file_path)

        try:
            res_ok = await client.get(f"/api/v1/screenshots/{test_filename}")
            assert res_ok.status_code == 200
            assert res_ok.headers["content-type"] == "image/png"
            assert "public, max-age=86400, immutable" in res_ok.headers["cache-control"]
        finally:
            if os.path.exists(test_file_path):
                os.remove(test_file_path)


@pytest.mark.asyncio
async def test_get_audit_visual_endpoint():
    """Verify GET /api/v1/audits/{id}/visual returns structured visual diff metadata."""
    from backend.app.core.database import AsyncSessionLocal
    from backend.app.models.entities import Audit, AuditStatus, DeviceProfile, ScanMode

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Create audit with VISUAL evidence
        async with AsyncSessionLocal() as session:
            audit = Audit(
                target_url="https://example.com",
                scan_mode=ScanMode.SINGLE_PAGE,
                device_profile=DeviceProfile.DESKTOP,
                status=AuditStatus.COMPLETED,
                scoring_version="1.0.0",
                pages_discovered=1,
                pages_scanned=1,
                pages_failed=0,
                execution_time_ms=500,
                selected_modules=["VISUAL"],
                raw_results={
                    "VISUAL": {
                        "baseline_established": False,
                        "baseline_audit_id": 100,
                        "score": 97.5,
                        "overall_mismatch_percentage": 0.5,
                        "viewports": {
                            "desktop": {
                                "width": 1280,
                                "height": 800,
                                "current_screenshot": "101_desktop.png",
                                "baseline_screenshot": "100_desktop.png",
                                "diff_screenshot": "101_diff_desktop.png",
                                "mismatch_percentage": 0.5,
                                "diff_pixels": 5120,
                                "total_pixels": 1024000,
                                "has_baseline": True
                            }
                        }
                    }
                }
            )
            session.add(audit)
            await session.commit()
            await session.refresh(audit)
            audit_id = audit.id

        res = await client.get(f"/api/v1/audits/{audit_id}/visual")
        assert res.status_code == 200
        data = res.json()
        assert data["audit_id"] == audit_id
        assert data["baseline_audit_id"] == 100
        assert data["score"] == 97.5
        assert data["overall_mismatch_percentage"] == 0.5
        assert "desktop" in data["viewports"]
        vp = data["viewports"]["desktop"]
        assert vp["current_url"] == "/api/v1/screenshots/101_desktop.png"
        assert vp["baseline_url"] == "/api/v1/screenshots/100_desktop.png"
        assert vp["diff_url"] == "/api/v1/screenshots/101_diff_desktop.png"
        assert vp["mismatch_percentage"] == 0.5
        assert vp["diff_pixels"] == 5120
        assert vp["has_baseline"] is True
