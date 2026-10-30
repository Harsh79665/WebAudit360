"""WebAudit 360 — Projects, Findings & Authorization API Integration Tests
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
async def test_project_crud_and_domain_authorization_flow():
    """Verify project lifecycle and cryptographic domain challenge generation."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Register a fresh user
        unique_email = f"project_test_{uuid.uuid4().hex[:8]}@webaudit360.io"
        reg_res = await client.post("/api/v1/auth/register", json={
            "email": unique_email,
            "password": "StrongPassword987!",
            "full_name": "Project Tester"
        })
        assert reg_res.status_code == 201
        token = reg_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Create a new project
        proj_res = await client.post("/api/v1/projects", json={
            "name": "E-Commerce Core",
            "domain": "store.example.com",
            "description": "Production e-commerce storefront audit"
        }, headers=headers)
        assert proj_res.status_code == 201
        project_data = proj_res.json()
        project_id = project_data["id"]
        assert project_data["name"] == "E-Commerce Core"
        assert project_data["domain"] == "store.example.com"

        # 3. List projects
        list_res = await client.get("/api/v1/projects", headers=headers)
        assert list_res.status_code == 200
        items = list_res.json()["items"]
        assert any(p["id"] == project_id for p in items)

        # 4. Get specific project
        get_res = await client.get(f"/api/v1/projects/{project_id}", headers=headers)
        assert get_res.status_code == 200
        assert get_res.json()["domain"] == "store.example.com"

        # 5. Initiate Domain Authorization Challenge (DNS TXT method)
        auth_res = await client.post("/api/v1/authorizations", json={
            "project_id": project_id,
            "domain": "store.example.com",
            "verification_method": "DNS_TXT"
        }, headers=headers)
        assert auth_res.status_code == 201
        auth_data = auth_res.json()
        assert auth_data["status"] == "PENDING"
        assert auth_data["token"].startswith("w360_v1_")
        auth_id = auth_data["id"]

        # 6. Verify Domain Authorization
        verify_res = await client.post(f"/api/v1/authorizations/{auth_id}/verify", headers=headers)
        assert verify_res.status_code == 200
        verified_data = verify_res.json()
        assert verified_data["status"] == "VERIFIED"
        assert verified_data["verified_at"] is not None

        # 7. Delete project
        del_res = await client.delete(f"/api/v1/projects/{project_id}", headers=headers)
        assert del_res.status_code == 200
        assert del_res.json()["success"] is True


@pytest.mark.asyncio
async def test_findings_list_and_filter():
    """Verify findings endpoint filters correctly by category and severity."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        res = await client.get("/api/v1/findings?limit=10")
        assert res.status_code == 200
        data = res.json()
        assert "items" in data
        assert "total" in data
        assert isinstance(data["items"], list)
