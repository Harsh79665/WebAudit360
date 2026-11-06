"""WebAudit 360 — Futuristic Engines Wave 1 Automated Test Suite
Author: Harsh Patel

Tests:
1. LoAF & INP Script Attributor Engine
2. Magecart & Exfiltration Sandbox Engine
3. Digital Carbon Footprint & Scope 3 ESG Audit (CO2.js) Engine
4. Client Secret & Sourcemap Harvester Engine
5. Post-Quantum Cryptography & DNSSEC Radar Engine
"""

from unittest.mock import AsyncMock, MagicMock, patch
import pytest
import httpx

from backend.app.engines.base import AuditCategory, EngineStatus
from backend.app.engines.loaf.engine import LoAFEngine
from backend.app.engines.magecart.engine import MagecartEngine
from backend.app.engines.carbon.engine import CarbonEngine
from backend.app.engines.secrets.engine import SecretsHarvesterEngine, shannon_entropy
from backend.app.engines.post_quantum.engine import PostQuantumDNSSECEngine


@pytest.mark.asyncio
async def test_loaf_engine_render_blocking_detection():
    engine = LoAFEngine()
    html_sample = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>LoAF Test Page</title>
        <script src="https://example.com/blocking1.js"></script>
        <script src="https://example.com/blocking2.js"></script>
        <script src="https://example.com/deferred.js" defer></script>
        <script src="https://example.com/async.js" async></script>
    </head>
    <body>
        <h1>Testing LoAF & INP</h1>
    </body>
    </html>
    """

    mock_resp = MagicMock()
    mock_resp.text = html_sample
    mock_resp.content = html_sample.encode("utf-8")
    mock_resp.status_code = 200

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        # Force playwright failure to exercise resilient HTML/DOM parser path
        with patch("playwright.async_api.async_playwright", side_effect=Exception("Lab headless display offline")):
            result = await engine.execute("https://example.com", {})
            assert result.category == AuditCategory.LOAF_INP
            assert result.status == EngineStatus.SUCCESS
            assert result.score is not None
            assert result.score < 100.0  # Deducted for blocking scripts
            assert result.raw_evidence["render_blocking_count"] == 2
            assert result.raw_evidence["deferred_count"] == 1
            assert result.raw_evidence["async_count"] == 1

            # Check finding
            finding_rules = [f.rule_id for f in result.findings]
            assert "loaf-render-blocking-scripts" in finding_rules


@pytest.mark.asyncio
async def test_magecart_engine_detects_unprotected_inputs_and_untrusted_cdn():
    engine = MagecartEngine()
    html_sample = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Checkout</title>
        <script src="https://suspicious-cdn-evil.xyz/skimmer.js"></script>
    </head>
    <body>
        <form action="/pay" method="POST">
            <input type="text" name="cc-number" placeholder="Card Number" />
            <input type="password" name="cvv" placeholder="CVV" />
            <button type="submit">Pay</button>
        </form>
        <script>
            eval("console.log('test')");
        </script>
    </body>
    </html>
    """

    mock_resp = MagicMock()
    mock_resp.text = html_sample
    mock_resp.headers = {}  # Missing CSP connect-src
    mock_resp.status_code = 200

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp

        result = await engine.execute("https://example.com/checkout", {})
        assert result.category == AuditCategory.SECURITY_MAGECART
        assert result.status == EngineStatus.SUCCESS
        assert result.score is not None
        assert result.score < 60.0  # High risk: sensitive inputs without CSP + untrusted CDN + eval

        finding_rules = [f.rule_id for f in result.findings]
        assert "magecart-sensitive-inputs-unprotected-csp" in finding_rules
        assert "magecart-untrusted-third-party-scripts" in finding_rules
        assert "magecart-suspicious-obfuscation-patterns" in finding_rules


@pytest.mark.asyncio
async def test_carbon_engine_swd_v4_calculations():
    engine = CarbonEngine()
    html_sample = "<html><body>" + "<p>Content</p>" * 5000 + "</body></html>"  # ~115KB HTML

    async def mock_client_get(url, *args, **kwargs):
        resp = MagicMock()
        if "greencheck" in str(url):
            resp.is_success = True
            resp.json.return_value = {"green": True, "hostedby": "Sustainable Cloud Provider"}
        else:
            resp.is_success = True
            resp.text = html_sample
            resp.content = html_sample.encode("utf-8")
        return resp

    with patch("httpx.AsyncClient.get", side_effect=mock_client_get):
        result = await engine.execute("https://example.com", {})
        assert result.category == AuditCategory.CARBON_ESG
        assert result.status == EngineStatus.SUCCESS
        assert result.score is not None
        assert result.raw_evidence["is_green_hosted"] is True
        assert result.raw_evidence["hosting_provider"] == "Sustainable Cloud Provider"
        assert result.raw_evidence["co2_grams_per_visit"] > 0
        assert result.raw_evidence["carbon_grade"] in ("A+", "A", "B", "C", "D", "E", "F")

        finding_rules = [f.rule_id for f in result.findings]
        assert "carbon-verified-green-hosting" in finding_rules


@pytest.mark.asyncio
async def test_secrets_harvester_detects_credentials_and_sourcemaps():
    engine = SecretsHarvesterEngine()
    dummy_stripe = "sk_" + "live_" + "1234567890abcdef1234567890"
    html_sample = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <script src="https://example.com/static/bundle.js"></script>
    </head>
    <body>
        <script>
            const stripeKey = "{dummy_stripe}";
            const awsKey = "AKIAIOSFODNN7EXAMPLE";
        </script>
    </body>
    </html>
    """
    js_sample = """
    console.log("App loaded");
    //# sourceMappingURL=bundle.js.map
    """

    async def mock_get(url, *args, **kwargs):
        resp = MagicMock()
        resp.is_success = True
        if str(url).endswith(".js"):
            resp.text = js_sample
            resp.headers = {"content-type": "application/javascript"}
        else:
            resp.text = html_sample
            resp.headers = {"content-type": "text/html"}
        return resp

    async def mock_head(url, *args, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {"content-length": "1048576"}
        return resp

    with patch("httpx.AsyncClient.get", side_effect=mock_get), \
         patch("httpx.AsyncClient.head", side_effect=mock_head):

        result = await engine.execute("https://example.com", {})
        assert result.category == AuditCategory.SECRET_HARVESTER
        assert result.status == EngineStatus.SUCCESS
        assert result.score is not None
        assert result.score < 50.0  # Heavy deductions for Stripe live secret + AWS key + sourcemap

        finding_rules = [f.rule_id for f in result.findings]
        assert "secret-stripe-secret-key" in finding_rules
        assert "secret-aws-access-key" in finding_rules
        assert "secret-sourcemap-exposed" in finding_rules

        # Ensure secrets are masked in evidence
        for f in result.findings:
            if f.rule_id == "secret-stripe-secret-key":
                assert "sk_live_" in f.title
                assert "*" in f.title


def test_shannon_entropy_calculation():
    # Low entropy: repetitive characters
    assert shannon_entropy("aaaaaaaa") == 0.0
    # High entropy: diverse character set
    high_ent = shannon_entropy("AKIAIOSFODNN7EXAMPLE")
    assert high_ent > 3.0


@pytest.mark.asyncio
async def test_post_quantum_dnssec_engine_handles_http_and_dns():
    engine = PostQuantumDNSSECEngine()

    # Test with standard domain
    result = await engine.execute("http://example.com", {})
    assert result.category == AuditCategory.POST_QUANTUM_DNSSEC
    assert result.status == EngineStatus.SUCCESS
    assert result.score is not None
    # HTTP should receive legacy/non-HTTPS deduction
    assert result.raw_evidence["pqc_readiness_level"] is not None
    assert any(f.rule_id == "pqc-tls-legacy-version" for f in result.findings)
