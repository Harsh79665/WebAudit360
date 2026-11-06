"""WebAudit 360 — Team Management & RBAC API Integration Tests
Author: Harsh Patel
"""

import uuid
import pytest
import pytest_asyncio
import httpx
from sqlalchemy import select, update
from backend.app.main import app
from backend.app.core.database import AsyncSessionLocal, init_db
from backend.app.models.entities import User, UserRole


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    await init_db()


@pytest.mark.asyncio
async def test_team_lifecycle_and_rbac():
    """Verify team listing, member invitation with password, role update, sole-owner demotion guard, and removal."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Register a workspace Owner
        owner_email = f"owner_{uuid.uuid4().hex[:8]}@webaudit360.io"
        reg_res = await client.post("/api/v1/auth/register", json={
            "email": owner_email,
            "password": "OwnerSecurePassword123!",
            "full_name": "Test Owner"
        })
        assert reg_res.status_code == 201
        owner_token = reg_res.json()["access_token"]
        owner_headers = {"Authorization": f"Bearer {owner_token}"}

        # Promote registered user to OWNER in database
        async with AsyncSessionLocal() as session:
            res = await session.execute(select(User).where(User.email == owner_email))
            user = res.scalars().first()
            user.role = UserRole.OWNER
            await session.commit()

        # 2. List team members (Owner should be present)
        list_res = await client.get("/api/v1/team", headers=owner_headers)
        assert list_res.status_code == 200
        team_data = list_res.json()
        assert team_data["total"] >= 1
        assert any(m["email"] == owner_email for m in team_data["items"])

        # 3. Invite a new developer
        invitee_email = f"dev_{uuid.uuid4().hex[:8]}@webaudit360.io"
        invite_res = await client.post("/api/v1/team/invite", json={
            "email": invitee_email,
            "full_name": "Junior Developer",
            "role": "DEVELOPER"
        }, headers=owner_headers)
        assert invite_res.status_code == 201
        invite_data = invite_res.json()
        assert invite_data["email"] == invitee_email
        assert invite_data["role"] == "DEVELOPER"
        assert invite_data["initial_password"] is not None
        assert len(invite_data["initial_password"]) >= 12
        member_id = invite_data["id"]

        # 4. Authenticate as the newly invited developer using generated credentials
        dev_login_res = await client.post("/api/v1/auth/login", json={
            "email": invitee_email,
            "password": invite_data["initial_password"]
        })
        assert dev_login_res.status_code == 200
        dev_token = dev_login_res.json()["access_token"]
        dev_headers = {"Authorization": f"Bearer {dev_token}"}

        # 5. Verify RBAC: Developer CANNOT invite members
        unauth_invite = await client.post("/api/v1/team/invite", json={
            "email": f"hacker_{uuid.uuid4().hex[:6]}@agency.com",
            "role": "ADMIN"
        }, headers=dev_headers)
        assert unauth_invite.status_code == 403

        # 6. Update member role from DEVELOPER to ADMIN (by Owner)
        role_res = await client.patch(
            f"/api/v1/team/members/{member_id}/role",
            json={"role": "ADMIN"},
            headers=owner_headers
        )
        assert role_res.status_code == 200
        assert role_res.json()["role"] == "ADMIN"

        # 7. Invariant Guard: Prevent demoting sole OWNER
        # Look up owner id
        owner_id = [m["id"] for m in team_data["items"] if m["email"] == owner_email][0]

        # Ensure owner_id is strictly the sole active OWNER in DB
        async with AsyncSessionLocal() as session:
            await session.execute(
                update(User).where(User.id != owner_id, User.role == UserRole.OWNER).values(role=UserRole.ADMIN)
            )
            await session.commit()

        demote_res = await client.patch(
            f"/api/v1/team/members/{owner_id}/role",
            json={"role": "DEVELOPER"},
            headers=owner_headers
        )
        assert demote_res.status_code == 400
        assert "sole" in demote_res.json()["detail"].lower()

        # 8. Invariant Guard: Prevent self-deletion
        self_del_res = await client.delete(
            f"/api/v1/team/members/{owner_id}",
            headers=owner_headers
        )
        assert self_del_res.status_code == 400
        assert "own" in self_del_res.json()["detail"].lower() and "account" in self_del_res.json()["detail"].lower()

        # 9. Remove member (deactivate)
        del_res = await client.delete(
            f"/api/v1/team/members/{member_id}",
            headers=owner_headers
        )
        assert del_res.status_code == 200
        assert del_res.json()["success"] is True

        # 10. Verify member is deactivated in team listing
        list_res_after = await client.get("/api/v1/team", headers=owner_headers)
        updated_member = [m for m in list_res_after.json()["items"] if m["id"] == member_id][0]
        assert updated_member["is_active"] is False


@pytest.mark.asyncio
async def test_admin_cannot_demote_or_delete_owner():
    """Verify that an ADMIN cannot demote or delete an OWNER in single-owner or multi-owner workspaces (403 Forbidden)."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Create Owner 1
        o1_email = f"owner1_{uuid.uuid4().hex[:8]}@webaudit360.io"
        reg1 = await client.post("/api/v1/auth/register", json={
            "email": o1_email, "password": "SecurePassword123!", "full_name": "Owner One"
        })
        o1_token = reg1.json()["access_token"]
        o1_headers = {"Authorization": f"Bearer {o1_token}"}

        async with AsyncSessionLocal() as session:
            res = await session.execute(select(User).where(User.email == o1_email))
            u1 = res.scalars().first()
            u1.role = UserRole.OWNER
            await session.commit()
            o1_id = u1.id

        # 2. Invite Admin
        admin_email = f"admin_{uuid.uuid4().hex[:8]}@webaudit360.io"
        inv = await client.post("/api/v1/team/invite", json={
            "email": admin_email, "full_name": "Workspace Admin", "role": "ADMIN"
        }, headers=o1_headers)
        admin_pwd = inv.json()["initial_password"]

        login = await client.post("/api/v1/auth/login", json={"email": admin_email, "password": admin_pwd})
        admin_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

        # 3. Admin attempts to demote sole Owner 1 -> 403 Forbidden
        demote_sole = await client.patch(
            f"/api/v1/team/members/{o1_id}/role",
            json={"role": "DEVELOPER"},
            headers=admin_headers
        )
        assert demote_sole.status_code == 403
        assert "owner" in demote_sole.json()["detail"].lower()

        # 4. Admin attempts to delete sole Owner 1 -> 403 Forbidden
        del_sole = await client.delete(
            f"/api/v1/team/members/{o1_id}",
            headers=admin_headers
        )
        assert del_sole.status_code == 403
        assert "owner" in del_sole.json()["detail"].lower()

        # 5. Create Owner 2
        o2_email = f"owner2_{uuid.uuid4().hex[:8]}@webaudit360.io"
        reg2 = await client.post("/api/v1/auth/register", json={
            "email": o2_email, "password": "SecurePassword123!", "full_name": "Owner Two"
        })
        async with AsyncSessionLocal() as session:
            res = await session.execute(select(User).where(User.email == o2_email))
            u2 = res.scalars().first()
            u2.role = UserRole.OWNER
            await session.commit()
            o2_id = u2.id

        # 6. Admin attempts to demote Owner 2 in multi-owner workspace -> 403 Forbidden
        demote_multi = await client.patch(
            f"/api/v1/team/members/{o2_id}/role",
            json={"role": "DEVELOPER"},
            headers=admin_headers
        )
        assert demote_multi.status_code == 403
        assert "owner" in demote_multi.json()["detail"].lower()

        # 7. Admin attempts to delete Owner 2 in multi-owner workspace -> 403 Forbidden
        del_multi = await client.delete(
            f"/api/v1/team/members/{o2_id}",
            headers=admin_headers
        )
        assert del_multi.status_code == 403
        assert "owner" in del_multi.json()["detail"].lower()

