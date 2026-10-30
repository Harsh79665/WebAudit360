"""WebAudit 360 — Audit Lifecycle & SSRF Enforced API Tests
Author: Harsh Patel
"""

import pytest
import pytest_asyncio
import httpx
from backend.app.main import app
from backend.app.core.database import init_db


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    await init_db()


@pytest.mark.asyncio
async def test_audit_submission_and_ssrf_rejection():
    """Verify that private network audit submissions are rejected with 400 Bad Request."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Submit illegal loopback target
        bad_payload = {
            "target_url": "http://127.0.0.1:8000",
            "scan_mode": "SINGLE_PAGE",
            "device_profile": "BOTH"
        }
        res = await client.post("/api/v1/audits", json=bad_payload)
        assert res.status_code == 400
        assert "restricted" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_audit_submission_valid_target():
    """Verify that a valid public domain audit submission creates a QUEUED job."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        valid_payload = {
            "target_url": "https://example.com",
            "scan_mode": "SINGLE_PAGE",
            "device_profile": "DESKTOP",
            "selected_modules": ["SEO", "SECURITY_PASSIVE"]
        }
        res = await client.post("/api/v1/audits", json=valid_payload)
        assert res.status_code == 201
        data = res.json()
        assert data["target_url"] == "https://example.com"
        assert data["status"] in ("QUEUED", "RUNNING", "COMPLETED")
        assert "id" in data

        # Retrieve audit details
        audit_id = data["id"]
        detail_res = await client.get(f"/api/v1/audits/{audit_id}")
        assert detail_res.status_code == 200
        detail_data = detail_res.json()
        assert detail_data["id"] == audit_id


@pytest.mark.asyncio
async def test_health_check_endpoint():
    """Verify that /health reports online status."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        res = await client.get("/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] in ("HEALTHY", "DEGRADED")
        assert data["platform"] == "WebAudit 360"
        assert data["creator"] == "Harsh Patel"
