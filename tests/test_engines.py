"""WebAudit 360 — Audit Engine Unit Tests
Author: Harsh Patel
"""

import pytest
from backend.app.engines.base import AuditCategory, EngineStatus
from backend.app.engines.crawler.engine import normalize_url, CrawlerEngine
from backend.app.engines.seo.engine import SEOEngine
from backend.app.engines.security.passive import PassiveSecurityEngine
from backend.app.engines.security.active import AuthorizedActiveSecurityEngine
from backend.app.engines.technology.engine import TechnologyEngine
from backend.app.engines.third_party.engine import ThirdPartyEngine
from backend.app.engines.domain.engine import DomainEngine


def test_url_normalization():
    """Verify URL normalization strips fragments and tracking query params."""
    raw = "https://EXAMPLE.com/path/?utm_source=twitter&fbclid=1234#section"
    normalized = normalize_url(raw)
    assert normalized == "https://example.com/path/"


@pytest.mark.asyncio
async def test_active_security_engine_blocks_unauthorized():
    """Verify that the Active Security Engine refuses to run without verified domain authorization."""
    engine = AuthorizedActiveSecurityEngine()
    result = await engine.execute(
        "https://example.com",
        config={"is_verified_authorized": False, "authorization_record_id": None}
    )
    assert result.status == EngineStatus.BLOCKED
    assert result.score is None  # Reported as N/A per policy
    assert len(result.findings) > 0
    assert "Domain Authorization Required" in result.findings[0].title


@pytest.mark.asyncio
async def test_seo_engine_execution():
    """Verify SEO engine executes and generates structured findings."""
    engine = SEOEngine()
    result = await engine.execute("https://example.com", config={})
    assert result.status in (EngineStatus.SUCCESS, EngineStatus.FAILED)
    assert result.category == AuditCategory.SEO
    if result.status == EngineStatus.SUCCESS:
        assert result.score is not None
        assert 0.0 <= result.score <= 100.0
        assert "title" in result.raw_evidence


@pytest.mark.asyncio
async def test_passive_security_engine_execution():
    """Verify passive security engine inspects headers and certificates."""
    engine = PassiveSecurityEngine()
    result = await engine.execute("https://example.com", config={})
    assert result.status in (EngineStatus.SUCCESS, EngineStatus.FAILED)
    assert result.category == AuditCategory.SECURITY_PASSIVE
    if result.status == EngineStatus.SUCCESS:
        assert result.score is not None
        assert "headers" in result.raw_evidence


@pytest.mark.asyncio
async def test_technology_engine_execution():
    """Verify technology intelligence engine detects observable components."""
    engine = TechnologyEngine()
    result = await engine.execute("https://example.com", config={})
    assert result.status in (EngineStatus.SUCCESS, EngineStatus.FAILED)
    assert result.category == AuditCategory.TECHNOLOGY
    if result.status == EngineStatus.SUCCESS:
        assert result.score == 100.0
        assert "technologies" in result.raw_evidence


@pytest.mark.asyncio
async def test_third_party_engine_execution():
    """Verify third-party engine checks external origins."""
    engine = ThirdPartyEngine()
    result = await engine.execute("https://example.com", config={})
    assert result.status in (EngineStatus.SUCCESS, EngineStatus.FAILED)
    assert result.category == AuditCategory.THIRD_PARTY
    if result.status == EngineStatus.SUCCESS:
        assert result.score is not None
        assert "unique_origins_count" in result.raw_evidence


@pytest.mark.asyncio
async def test_domain_engine_execution():
    """Verify domain engine checks DNS and TLS certificates."""
    engine = DomainEngine()
    result = await engine.execute("https://example.com", config={})
    assert result.status in (EngineStatus.SUCCESS, EngineStatus.FAILED)
    assert result.category == AuditCategory.DOMAIN
    if result.status == EngineStatus.SUCCESS:
        assert result.score is not None
        assert "dns" in result.raw_evidence

