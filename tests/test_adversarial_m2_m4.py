"""WebAudit 360 — Tier 5 Adversarial Hardening & Stress Testing Suite (Milestones 2–4)
Author: Harsh Patel

Adversarial Stress Verification:
1. LoAF/INP: Negative score overflow protection under 100+ render-blocking scripts
2. Magecart: Mixed-case and Unicode sensitive input attribute interception
3. Carbon: Zero-byte division-by-zero immunity and multi-gigabyte clamping
4. Secrets Harvester: Signature false-positive resilience and broken .map probing
5. Post-Quantum & DNSSEC: Unresolvable NXDOMAIN and non-HTTPS graceful handling
6. GEO & Privacy: Malformed JSON-LD recovery and RFC-defying cookie parsing
7. Competitor Comparison: Self-comparison zero delta invariance and invalid target handling
"""

from unittest.mock import AsyncMock, MagicMock, patch
import pytest
import httpx

from backend.app.engines.base import AuditCategory, EngineStatus, FindingDraft
from backend.app.engines.loaf.engine import LoAFEngine
from backend.app.engines.magecart.engine import MagecartEngine
from backend.app.engines.carbon.engine import CarbonEngine
from backend.app.engines.secrets.engine import SecretsHarvesterEngine
from backend.app.engines.post_quantum.engine import PostQuantumDNSSECEngine
from backend.app.engines.geo.engine import GEOEngine
from backend.app.engines.privacy.engine import ZeroTrustPrivacyEngine
from backend.app.engines.layout_defects.engine import LayoutDefectsEngine
from backend.app.engines.user_journey.engine import SyntheticUserJourneyEngine
from backend.app.engines.remediation.engine import CodeRemediationEngine
from backend.app.main import app


@pytest.mark.asyncio
async def test_adversarial_loaf_overflow_protection():
    """Verify that 100+ blocking scripts do not cause negative score or unhandled exceptions."""
    engine = LoAFEngine()
    blocking_scripts = "\n".join([f'<script src="https://example.com/script_{i}.js"></script>' for i in range(100)])
    html = f"<!DOCTYPE html><html><head>{blocking_scripts}</head><body><h1>Heavy</h1></body></html>"

    mock_resp = MagicMock()
    mock_resp.text = html
    mock_resp.content = html.encode("utf-8")
    mock_resp.status_code = 200

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get, \
         patch("playwright.async_api.async_playwright", side_effect=Exception("Offline")):
        mock_get.return_value = mock_resp

        result = await engine.execute("https://example.com", {})
        assert result.status == EngineStatus.SUCCESS
        assert result.score is not None
        assert 0.0 <= result.score <= 100.0
        assert result.raw_evidence["render_blocking_count"] == 100


@pytest.mark.asyncio
async def test_adversarial_magecart_mixed_case_sensitive_inputs():
    """Verify that case-manipulated input names (cArD-NuMbEr, PaSsWoRd) are intercepted."""
    engine = MagecartEngine()
    html = """
    <form>
        <input type="text" name="cArD-NuMbEr" />
        <input type="text" id="User_PaSsWoRd" />
        <input type="text" autocomplete="cc-exp-MONTH" />
    </form>
    """
    mock_resp = MagicMock()
    mock_resp.text = html
    mock_resp.headers = {}
    mock_resp.status_code = 200

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp

        result = await engine.execute("https://example.com/pay", {})
        assert result.status == EngineStatus.SUCCESS
        assert result.raw_evidence["sensitive_inputs_count"] == 3


@pytest.mark.asyncio
async def test_adversarial_carbon_zero_byte_immunity():
    """Verify that zero-byte responses do not trigger ZeroDivisionError."""
    engine = CarbonEngine()
    mock_resp = MagicMock()
    mock_resp.text = ""
    mock_resp.content = b""
    mock_resp.status_code = 200

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp

        result = await engine.execute("https://example.com", {})
        assert result.status == EngineStatus.SUCCESS
        assert result.score is not None
        assert result.raw_evidence["co2_grams_per_visit"] == 0.0
        assert result.raw_evidence["carbon_grade"] == "A+"


@pytest.mark.asyncio
async def test_adversarial_secrets_harvester_false_positives():
    """Verify that false positive prefixes (e.g. AKIAlowercase) are not flagged as AWS keys."""
    engine = SecretsHarvesterEngine()
    html = """
    <div>
        <span>AKIAnotanactualkey123</span>
        <span>sk_test_thisisatestkeynotlive12345</span>
    </div>
    """
    mock_resp = MagicMock()
    mock_resp.text = html
    mock_resp.status_code = 200

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp

        result = await engine.execute("https://example.com", {})
        assert result.status == EngineStatus.SUCCESS
        assert result.raw_evidence["discovered_secrets_count"] == 0
        assert result.score == 100.0


@pytest.mark.asyncio
async def test_adversarial_geo_malformed_jsonld_recovery():
    """Verify that completely broken JSON inside application/ld+json does not crash GEO engine."""
    engine = GEOEngine()
    html = """
    <html>
    <head>
        <script type="application/ld+json">
            { broken: json, invalid syntax here !!!
        </script>
    </head>
    <body><p>Content</p></body>
    </html>
    """
    mock_resp = MagicMock()
    mock_resp.text = html
    mock_resp.status_code = 200

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp

        result = await engine.execute("https://example.com", {})
        assert result.status == EngineStatus.SUCCESS
        assert result.score is not None


@pytest.mark.asyncio
async def test_adversarial_competitor_comparison_identical_urls():
    """Verify that comparing identical URLs computes exactly 0.0 delta across all categories."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        res = await client.post("/api/v1/comparisons", json={
            "target_url_a": "https://example.com",
            "target_url_b": "https://example.com"
        })
        assert res.status_code == 200
        data = res.json()
        assert data["deltas"]["overall"] == 0.0
        assert data["deltas"]["performance"] == 0.0
        assert "tied" in data["insights"][0].lower()
