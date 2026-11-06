"""WebAudit 360 — Futuristic Engines Wave 2 & UI Automated Test Suite
Author: Harsh Patel

Tests:
1. Generative Engine Optimization (GEO) & LLM Scraper Readiness Engine
2. Zero-Trust Privacy & Consent Evasion Radar Engine
3. AI Visual Semantic Layout Defect Detection Engine
4. Synthetic Multi-Step User Journey Validator Engine
5. 1-Click AST / Code Remediation Generator Engine
6. Frontend Route Mounting & Dashboard Verification
"""

from unittest.mock import AsyncMock, MagicMock, patch
import pytest
import httpx

from backend.app.engines.base import AuditCategory, EngineStatus, FindingDraft
from backend.app.engines.geo.engine import GEOEngine
from backend.app.engines.privacy.engine import ZeroTrustPrivacyEngine
from backend.app.engines.layout_defects.engine import LayoutDefectsEngine
from backend.app.engines.user_journey.engine import SyntheticUserJourneyEngine
from backend.app.engines.remediation.engine import CodeRemediationEngine
from backend.app.main import app


@pytest.mark.asyncio
async def test_geo_engine_robots_and_llms_txt():
    engine = GEOEngine()
    html_sample = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Tech Docs</title>
        <script type="application/ld+json">
        {
            "@context": "https://schema.org",
            "@type": "Article",
            "headline": "Generative AI Guide"
        }
        </script>
    </head>
    <body>
        <main>
            <h1>AI Readiness</h1>
            <p>Content for search engines and models.</p>
        </main>
    </body>
    </html>
    """
    robots_sample = """
    User-agent: GPTBot
    Disallow: /
    User-agent: ClaudeBot
    Allow: /
    """

    async def mock_get(url, *args, **kwargs):
        resp = MagicMock()
        resp.is_success = True
        if str(url).endswith("/robots.txt"):
            resp.text = robots_sample
        elif str(url).endswith("/llms.txt"):
            resp.text = "# LLMs manifest"
            resp.content = b"# LLMs manifest"
            resp.headers = {"content-type": "text/plain"}
        else:
            resp.text = html_sample
        return resp

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        result = await engine.execute("https://example.com", {})
        assert result.category == AuditCategory.GEO_AI
        assert result.status == EngineStatus.SUCCESS
        assert result.score is not None
        assert result.raw_evidence["crawler_status"]["GPTBot"] == "BLOCKED"
        assert result.raw_evidence["crawler_status"]["ClaudeBot"] == "ALLOWED"
        assert result.raw_evidence["has_llms_txt"] is True
        assert "Article" in result.raw_evidence["schema_types"]

        finding_rules = [f.rule_id for f in result.findings]
        assert "geo-ai-crawlers-blocked" in finding_rules
        assert "geo-llms-txt-present" in finding_rules
        assert "geo-schema-detected" in finding_rules


@pytest.mark.asyncio
async def test_privacy_engine_detects_pre_consent_cookies_and_fingerprinting():
    engine = ZeroTrustPrivacyEngine()
    html_sample = """
    <!DOCTYPE html>
    <html>
    <head><title>Store</title></head>
    <body>
        <script>
            // Canvas fingerprinting
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            const dataUrl = canvas.toDataURL();
            // WebGL fingerprinting
            const gl = canvas.getContext('webgl');
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        </script>
    </body>
    </html>
    """

    mock_resp = MagicMock()
    mock_resp.text = html_sample
    mock_resp.headers.multi_items.return_value = [
        ("set-cookie", "_ga=GA1.2.123456; Path=/; Domain=.example.com;"),
        ("set-cookie", "_fbp=fb.1.12345678; Path=/;"),
        ("set-cookie", "session_id=abcxyz; Secure; HttpOnly; Path=/;")
    ]

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp

        result = await engine.execute("https://example.com", {})
        assert result.category == AuditCategory.ZERO_TRUST_PRIVACY
        assert result.status == EngineStatus.SUCCESS
        assert result.score is not None
        assert result.score < 60.0  # Penalized for pre-consent tracking cookies + fingerprinting
        assert result.raw_evidence["tracking_cookies_count"] == 2

        finding_rules = [f.rule_id for f in result.findings]
        assert "privacy-pre-consent-tracking-cookies" in finding_rules
        assert "privacy-canvas-fingerprint" in finding_rules
        assert "privacy-webgl-fingerprint" in finding_rules


@pytest.mark.asyncio
async def test_layout_defects_engine_distortion_detection():
    engine = LayoutDefectsEngine()
    html_sample = """
    <!DOCTYPE html>
    <html>
    <body>
        <img src="banner.jpg" width="800" height="20" style="display:block;" />
    </body>
    </html>
    """
    mock_resp = MagicMock()
    mock_resp.text = html_sample

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get, \
         patch("playwright.async_api.async_playwright", side_effect=Exception("Headless lab offline")):
        mock_get.return_value = mock_resp

        result = await engine.execute("https://example.com", {})
        assert result.category == AuditCategory.LAYOUT_DEFECTS
        assert result.status == EngineStatus.SUCCESS
        assert result.score is not None
        assert len(result.raw_evidence["detected_defects"]["image_distortion"]) > 0

        finding_rules = [f.rule_id for f in result.findings]
        assert "layout-image-distortion-detected" in finding_rules


@pytest.mark.asyncio
async def test_user_journey_engine_validates_journeys():
    engine = SyntheticUserJourneyEngine()
    html_sample = """
    <!DOCTYPE html>
    <html>
    <head><title>App</title></head>
    <body>
        <nav>
            <a href="/">Home</a>
            <a href="/features">Features</a>
            <a href="/pricing">Pricing</a>
        </nav>
        <form action="/search" method="GET">
            <input type="search" name="q" placeholder="Search..." />
        </form>
        <form action="/contact" method="POST">
            <input type="email" name="email" required />
            <button type="submit">Submit</button>
        </form>
        <div class="hero">
            <a href="/signup" class="btn btn-primary cta">Get Started Free</a>
        </div>
    </body>
    </html>
    """
    mock_resp = MagicMock()
    mock_resp.text = html_sample

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp

        result = await engine.execute("https://example.com", {})
        assert result.category == AuditCategory.USER_JOURNEY
        assert result.status == EngineStatus.SUCCESS
        assert result.score == 100.0  # All journeys passing
        assert result.raw_evidence["passed_journeys_count"] == 5

        finding_rules = [f.rule_id for f in result.findings]
        assert "journey-nav-verified" in finding_rules
        assert "journey-cta-verified" in finding_rules


@pytest.mark.asyncio
async def test_code_remediation_engine_generates_patches():
    engine = CodeRemediationEngine()
    test_findings = [
        FindingDraft(
            category=AuditCategory.SEO,
            rule_id="seo-meta-description-missing",
            title="Page Missing Meta Description",
            description="No description tag found.",
            severity="MEDIUM"
        ),
        FindingDraft(
            category=AuditCategory.LOAF_INP,
            rule_id="loaf-render-blocking-scripts",
            title="Render-Blocking Scripts Identified",
            description="Scripts block parsing.",
            severity="HIGH"
        ),
        FindingDraft(
            category=AuditCategory.GEO_AI,
            rule_id="geo-missing-llms-txt",
            title="Missing /llms.txt AI Context Manifest",
            description="No llms.txt found.",
            severity="LOW"
        ),
    ]

    result = await engine.execute("https://example.com", {}, all_findings=test_findings)
    assert result.category == AuditCategory.CODE_REMEDIATION
    assert result.status == EngineStatus.SUCCESS
    assert result.score is not None
    assert result.raw_evidence["remediations_count"] >= 3

    patches = result.raw_evidence["remediations"]
    assert any("meta name=\"description\"" in p["git_patch"] for p in patches)
    assert any("defer" in p["git_patch"] for p in patches)
    assert any("llms.txt" in p["target_file"] for p in patches)


@pytest.mark.asyncio
async def test_futuristic_engines_html_route_mounted():
    """Verify static mounting serves futuristic-engines.html."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        res = await client.get("/futuristic-engines.html")
        assert res.status_code == 200
        assert "10 Futuristic Intelligence Engines" in res.text
        assert "js/futuristic-engines.js" in res.text
