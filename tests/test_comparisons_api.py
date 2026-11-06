"""WebAudit 360 — Competitor Comparison API Automated Tests
Author: Harsh Patel
"""

from unittest.mock import AsyncMock, MagicMock, patch
import pytest
import httpx

from backend.app.main import app
from backend.app.engines.base import EngineResult, EngineStatus, AuditCategory


@pytest.mark.asyncio
async def test_competitor_comparison_rejects_ssrf_loopback():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        res = await client.post("/api/v1/comparisons", json={
            "target_url_a": "https://example.com",
            "target_url_b": "http://127.0.0.1:8000/internal"
        })
        assert res.status_code == 400
        assert "SSRF" in res.json()["detail"]


@pytest.mark.asyncio
async def test_competitor_comparison_full_flow():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Mock engine executions for both URLs
        mock_perf_a = EngineResult(
            category=AuditCategory.PERFORMANCE,
            engine_name="PerformanceEngine",
            engine_version="1.0.0",
            status=EngineStatus.SUCCESS,
            score=95.0,
            raw_evidence={"core_web_vitals": {"lcp": {"value": 1.2}, "cls": {"value": 0.01}, "fcp": {"value": 0.8}}}
        )
        mock_perf_b = EngineResult(
            category=AuditCategory.PERFORMANCE,
            engine_name="PerformanceEngine",
            engine_version="1.0.0",
            status=EngineStatus.SUCCESS,
            score=70.0,
            raw_evidence={"core_web_vitals": {"lcp": {"value": 3.4}, "cls": {"value": 0.15}, "fcp": {"value": 2.1}}}
        )
        mock_seo = EngineResult(
            category=AuditCategory.SEO,
            engine_name="SEOEngine",
            engine_version="1.0.0",
            status=EngineStatus.SUCCESS,
            score=88.0,
            raw_evidence={}
        )
        mock_a11y = EngineResult(
            category=AuditCategory.ACCESSIBILITY,
            engine_name="AccessibilityEngine",
            engine_version="1.0.0",
            status=EngineStatus.SUCCESS,
            score=90.0,
            raw_evidence={}
        )
        mock_sec = EngineResult(
            category=AuditCategory.SECURITY_PASSIVE,
            engine_name="PassiveSecurityEngine",
            engine_version="1.0.0",
            status=EngineStatus.SUCCESS,
            score=85.0,
            raw_evidence={}
        )
        mock_tech = EngineResult(
            category=AuditCategory.TECHNOLOGY,
            engine_name="TechnologyEngine",
            engine_version="1.0.0",
            status=EngineStatus.SUCCESS,
            score=90.0,
            raw_evidence={"technologies": [{"name": "React"}]}
        )
        mock_carb = EngineResult(
            category=AuditCategory.CARBON_ESG,
            engine_name="CarbonEngine",
            engine_version="1.0.0",
            status=EngineStatus.SUCCESS,
            score=90.0,
            raw_evidence={"co2_grams_per_visit": 0.12}
        )

        with patch("backend.app.engines.performance.engine.PerformanceEngine.execute", side_effect=[mock_perf_a, mock_perf_b]), \
             patch("backend.app.engines.seo.engine.SEOEngine.execute", return_value=mock_seo), \
             patch("backend.app.engines.accessibility.engine.AccessibilityEngine.execute", return_value=mock_a11y), \
             patch("backend.app.engines.security.passive.PassiveSecurityEngine.execute", return_value=mock_sec), \
             patch("backend.app.engines.technology.engine.TechnologyEngine.execute", return_value=mock_tech), \
             patch("backend.app.engines.carbon.engine.CarbonEngine.execute", return_value=mock_carb):

            res = await client.post("/api/v1/comparisons", json={
                "target_url_a": "https://example.com",
                "target_url_b": "https://iana.org"
            })
            assert res.status_code == 200
            data = res.json()
            assert data["target_url_a"] == "https://example.com"
            assert data["target_url_b"] == "https://iana.org"
            assert data["scores_a"]["overall"] is not None
            assert data["scores_b"]["overall"] is not None
            assert data["deltas"]["performance"] == 25.0  # 95.0 - 70.0
            assert len(data["insights"]) > 0
            assert data["winner"] == "example.com"
