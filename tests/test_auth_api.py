"""WebAudit 360 — Authentication & Profile API Integration Tests
Author: Harsh Patel
"""

import uuid
import pytest
import pytest_asyncio
import httpx
from backend.app.main import app
from backend.app.core.database import init_db


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    await init_db()


@pytest.mark.asyncio
async def test_user_registration_and_login():
    """Test full registration, authentication, token return, and profile retrieval flow."""
    unique_email = f"test_{uuid.uuid4().hex[:8]}@webaudit360.io"
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Register new user
        reg_payload = {
            "email": unique_email,
            "password": "SecurePassword123!",
            "full_name": "Test Developer"
        }
        res = await client.post("/api/v1/auth/register", json=reg_payload)
        assert res.status_code == 201
        data = res.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["user"]["email"] == reg_payload["email"]
        token = data["access_token"]

        # 2. Login with registered credentials
        login_payload = {
            "email": unique_email,
            "password": "SecurePassword123!"
        }
        login_res = await client.post("/api/v1/auth/login", json=login_payload)
        assert login_res.status_code == 200
        login_data = login_res.json()
        assert login_data["user"]["full_name"] == "Test Developer"

        # 3. Retrieve /auth/me with Bearer token
        me_res = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert me_res.status_code == 200
        me_data = me_res.json()
        assert me_data["email"] == reg_payload["email"]
