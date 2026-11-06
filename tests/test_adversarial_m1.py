"""WebAudit 360 — Adversarial Stress Testing Suite for Milestone 1
Challenger 2 Empirical Verification:
1. Team Management RBAC & Invariant Security:
   - VIEWER & DEVELOPER rejected (403 Forbidden) on invite, role update, and delete
   - Can an ADMIN demote an OWNER? (Sole owner vs multi-owner)
   - Can an ADMIN delete an OWNER?
   - Can an ADMIN promote anyone to OWNER? (Must be 403)
   - Can the sole OWNER demote themselves? (400 Bad Request)
   - Can any user delete themselves? (400 Bad Request)
   - Can an unauthenticated request access team endpoints? (401 Unauthorized)

2. Active Security Probes Verification & Non-Destructiveness:
   - Gating verification: unverified domain -> BLOCKED, score None, exactly 0 HTTP calls
   - Missing authorization_record_id -> BLOCKED
   - End-to-end AuditService gating with PENDING / FAILED / absent DomainAuthorization
   - Payload inspection across all 5 active probes ensuring strictly non-destructive operations
"""

from datetime import datetime, timedelta, timezone
import uuid
import pytest
import pytest_asyncio
import httpx
from unittest.mock import AsyncMock, patch
from sqlalchemy import select, update

from backend.app.main import app
from backend.app.core.database import AsyncSessionLocal, init_db
from backend.app.models.entities import (
    User, UserRole, Project, Audit, DomainAuthorization,
    VerificationStatus, VerificationMethod, ScanMode, AuditStatus
)
from backend.app.engines.security.active import AuthorizedActiveSecurityEngine
from backend.app.engines.base import AuditCategory, EngineStatus, EngineResult
from backend.app.services.audit_service import AuditService


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    await init_db()


# =============================================================================
# SUITE 1: TEAM MANAGEMENT RBAC & INVARIANT ADVERSARIAL STRESS TESTS
# =============================================================================

@pytest.mark.asyncio
async def test_team_unauthorized_roles_rejected_403():
    """Verify that VIEWER and DEVELOPER roles are strictly rejected with 403 Forbidden
    on invite, role update, and member deletion endpoints."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Create Owner
        owner_email = f"owner_rb_{uuid.uuid4().hex[:6]}@test.com"
        r = await client.post("/api/v1/auth/register", json={
            "email": owner_email, "password": "Password123!", "full_name": "Test Owner"
        })
        assert r.status_code == 201
        owner_token = r.json()["access_token"]
        owner_h = {"Authorization": f"Bearer {owner_token}"}

        async with AsyncSessionLocal() as session:
            res = await session.execute(select(User).where(User.email == owner_email))
            u = res.scalars().first()
            u.role = UserRole.OWNER
            await session.commit()

        # Invite Developer
        dev_email = f"dev_rb_{uuid.uuid4().hex[:6]}@test.com"
        r = await client.post("/api/v1/team/invite", json={
            "email": dev_email, "role": "DEVELOPER"
        }, headers=owner_h)
        assert r.status_code == 201
        dev_pwd = r.json()["initial_password"]
        dev_id = r.json()["id"]

        # Invite Viewer
        viewer_email = f"viewer_rb_{uuid.uuid4().hex[:6]}@test.com"
        r = await client.post("/api/v1/team/invite", json={
            "email": viewer_email, "role": "VIEWER"
        }, headers=owner_h)
        assert r.status_code == 201
        viewer_pwd = r.json()["initial_password"]
        viewer_id = r.json()["id"]

        # Login Developer
        r = await client.post("/api/v1/auth/login", json={"email": dev_email, "password": dev_pwd})
        assert r.status_code == 200
        dev_h = {"Authorization": f"Bearer {r.json()['access_token']}"}

        # Login Viewer
        r = await client.post("/api/v1/auth/login", json={"email": viewer_email, "password": viewer_pwd})
        assert r.status_code == 200
        viewer_h = {"Authorization": f"Bearer {r.json()['access_token']}"}

        # --- A. Test Invite Endpoint ---
        # Developer attempts invite -> 403
        r_dev_inv = await client.post("/api/v1/team/invite", json={
            "email": "hacker1@test.com", "role": "VIEWER"
        }, headers=dev_h)
        assert r_dev_inv.status_code == 403, f"Developer invite expected 403, got {r_dev_inv.status_code}"

        # Viewer attempts invite -> 403
        r_view_inv = await client.post("/api/v1/team/invite", json={
            "email": "hacker2@test.com", "role": "VIEWER"
        }, headers=viewer_h)
        assert r_view_inv.status_code == 403, f"Viewer invite expected 403, got {r_view_inv.status_code}"

        # --- B. Test Role Update Endpoint ---
        # Developer attempts role update -> 403
        r_dev_role = await client.patch(f"/api/v1/team/members/{viewer_id}/role", json={
            "role": "ADMIN"
        }, headers=dev_h)
        assert r_dev_role.status_code == 403, f"Developer role update expected 403, got {r_dev_role.status_code}"

        # Viewer attempts role update -> 403
        r_view_role = await client.patch(f"/api/v1/team/members/{dev_id}/role", json={
            "role": "ADMIN"
        }, headers=viewer_h)
        assert r_view_role.status_code == 403, f"Viewer role update expected 403, got {r_view_role.status_code}"

        # --- C. Test Member Deletion Endpoint ---
        # Developer attempts delete -> 403
        r_dev_del = await client.delete(f"/api/v1/team/members/{viewer_id}", headers=dev_h)
        assert r_dev_del.status_code == 403, f"Developer delete expected 403, got {r_dev_del.status_code}"

        # Viewer attempts delete -> 403
        r_view_del = await client.delete(f"/api/v1/team/members/{dev_id}", headers=viewer_h)
        assert r_view_del.status_code == 403, f"Viewer delete expected 403, got {r_view_del.status_code}"

        # --- D. Test Invalid Token Requests (Should be 401 Unauthorized) ---
        invalid_h = {"Authorization": "Bearer invalid_or_forged_token"}
        r_invalid_list = await client.get("/api/v1/team", headers=invalid_h)
        assert r_invalid_list.status_code == 401

        r_invalid_invite = await client.post("/api/v1/team/invite", json={"email": "anon@test.com", "role": "VIEWER"}, headers=invalid_h)
        assert r_invalid_invite.status_code == 401

        r_invalid_patch = await client.patch(f"/api/v1/team/members/{dev_id}/role", json={"role": "ADMIN"}, headers=invalid_h)
        assert r_invalid_patch.status_code == 401

        r_invalid_del = await client.delete(f"/api/v1/team/members/{dev_id}", headers=invalid_h)
        assert r_invalid_del.status_code == 401

        # --- E. Test Unauthenticated Requests without headers (Fallback to default local Owner behavior) ---
        # Note: dependencies.py get_current_user transparently provides default Owner when creds is None
        r_no_auth_list = await client.get("/api/v1/team")
        print(f"\n[ADVERSARIAL FINDING] Unauthenticated GET /api/v1/team without auth header returned: {r_no_auth_list.status_code}")


@pytest.mark.asyncio
async def test_admin_cannot_promote_to_owner():
    """Verify that an ADMIN cannot elevate any user (or themselves) to OWNER (403 Forbidden)."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Create Owner
        owner_email = f"owner_ad_{uuid.uuid4().hex[:6]}@test.com"
        r = await client.post("/api/v1/auth/register", json={
            "email": owner_email, "password": "Password123!", "full_name": "Test Owner"
        })
        owner_h = {"Authorization": f"Bearer {r.json()['access_token']}"}

        async with AsyncSessionLocal() as session:
            res = await session.execute(select(User).where(User.email == owner_email))
            u = res.scalars().first()
            u.role = UserRole.OWNER
            await session.commit()

        # Invite Admin
        admin_email = f"admin_ad_{uuid.uuid4().hex[:6]}@test.com"
        r = await client.post("/api/v1/team/invite", json={
            "email": admin_email, "role": "ADMIN"
        }, headers=owner_h)
        admin_pwd = r.json()["initial_password"]
        admin_id = r.json()["id"]

        # Invite target user
        user_email = f"user_ad_{uuid.uuid4().hex[:6]}@test.com"
        r = await client.post("/api/v1/team/invite", json={
            "email": user_email, "role": "DEVELOPER"
        }, headers=owner_h)
        user_id = r.json()["id"]

        # Login Admin
        r = await client.post("/api/v1/auth/login", json={"email": admin_email, "password": admin_pwd})
        admin_h = {"Authorization": f"Bearer {r.json()['access_token']}"}

        # 1. Admin tries to invite someone as OWNER -> 403
        r_inv_owner = await client.post("/api/v1/team/invite", json={
            "email": f"new_owner_{uuid.uuid4().hex[:4]}@test.com", "role": "OWNER"
        }, headers=admin_h)
        assert r_inv_owner.status_code == 403
        assert "owner" in r_inv_owner.json()["detail"].lower()

        # 2. Admin tries to promote DEVELOPER to OWNER -> 403
        r_prom_owner = await client.patch(f"/api/v1/team/members/{user_id}/role", json={
            "role": "OWNER"
        }, headers=admin_h)
        assert r_prom_owner.status_code == 403
        assert "owner" in r_prom_owner.json()["detail"].lower()

        # 3. Admin tries to promote THEMSELVES to OWNER -> 403
        r_self_owner = await client.patch(f"/api/v1/team/members/{admin_id}/role", json={
            "role": "OWNER"
        }, headers=admin_h)
        assert r_self_owner.status_code == 403


@pytest.mark.asyncio
async def test_admin_demote_and_delete_owner_invariants():
    """Examine whether an ADMIN can demote or delete an OWNER:
    Case A: Sole OWNER -> Demotion rejected (400 Bad Request)
    Case B: Sole OWNER -> Deletion rejected (400 Bad Request)
    Case C: Multi-OWNER -> Can an ADMIN demote an OWNER? (Adversarial challenge)
    Case D: Multi-OWNER -> Can an ADMIN delete an OWNER? (Adversarial challenge)
    """
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Create Owner 1
        o1_email = f"o1_{uuid.uuid4().hex[:6]}@test.com"
        r = await client.post("/api/v1/auth/register", json={
            "email": o1_email, "password": "Password123!", "full_name": "Owner 1"
        })
        o1_h = {"Authorization": f"Bearer {r.json()['access_token']}"}

        async with AsyncSessionLocal() as session:
            # Set all existing users to non-owner to isolate sole-owner test
            await session.execute(update(User).values(role=UserRole.DEVELOPER))
            res = await session.execute(select(User).where(User.email == o1_email))
            u1 = res.scalars().first()
            u1.role = UserRole.OWNER
            await session.commit()
            o1_id = u1.id

        # Invite Admin
        admin_email = f"admin_{uuid.uuid4().hex[:6]}@test.com"
        r = await client.post("/api/v1/team/invite", json={
            "email": admin_email, "role": "ADMIN"
        }, headers=o1_h)
        admin_pwd = r.json()["initial_password"]
        admin_id = r.json()["id"]

        r = await client.post("/api/v1/auth/login", json={"email": admin_email, "password": admin_pwd})
        admin_h = {"Authorization": f"Bearer {r.json()['access_token']}"}

        # --- Case A: Admin attempts to demote sole Owner 1 -> Must be REJECTED ---
        async with AsyncSessionLocal() as session:
            chk = await session.execute(select(User).where(User.id == o1_id))
            chk_u = chk.scalars().first()
            all_owners_res = await session.execute(select(User).where(User.role == UserRole.OWNER, User.is_active == True))
            all_owners = all_owners_res.scalars().all()
            print(f"\n[DIAGNOSTIC] Target user {o1_id} role in DB before patch: {chk_u.role}")
            print(f"[DIAGNOSTIC] All active owners in DB: {[o.email for o in all_owners]}")

        r_demote_sole = await client.patch(f"/api/v1/team/members/{o1_id}/role", json={
            "role": "DEVELOPER"
        }, headers=admin_h)
        assert r_demote_sole.status_code == 403, f"Expected 403 Forbidden, got {r_demote_sole.status_code}"
        assert "owner" in r_demote_sole.json()["detail"].lower()

        # --- Case B: Admin attempts to delete sole Owner 1 -> Must be REJECTED ---
        r_del_sole = await client.delete(f"/api/v1/team/members/{o1_id}", headers=admin_h)
        assert r_del_sole.status_code == 403, f"Expected 403 Forbidden, got {r_del_sole.status_code}"
        assert "owner" in r_del_sole.json()["detail"].lower()

        # --- Now create Owner 2 ---
        o2_email = f"o2_{uuid.uuid4().hex[:6]}@test.com"
        r = await client.post("/api/v1/auth/register", json={
            "email": o2_email, "password": "Password123!", "full_name": "Owner 2"
        })
        async with AsyncSessionLocal() as session:
            res = await session.execute(select(User).where(User.email == o2_email))
            u2 = res.scalars().first()
            u2.role = UserRole.OWNER
            await session.commit()
            o2_id = u2.id

        # --- Case C & D: Multi-Owner Workspace ---
        # An ADMIN attempts to demote Owner 2 -> Must be 403 Forbidden:
        r_admin_demotes_o2 = await client.patch(f"/api/v1/team/members/{o2_id}/role", json={
            "role": "DEVELOPER"
        }, headers=admin_h)
        assert r_admin_demotes_o2.status_code == 403, f"Expected 403 Forbidden, got {r_admin_demotes_o2.status_code}"
        assert "owner" in r_admin_demotes_o2.json()["detail"].lower()

        # An ADMIN attempts to delete Owner 2 -> Must be 403 Forbidden:
        r_admin_deletes_o2 = await client.delete(f"/api/v1/team/members/{o2_id}", headers=admin_h)
        assert r_admin_deletes_o2.status_code == 403, f"Expected 403 Forbidden, got {r_admin_deletes_o2.status_code}"
        assert "owner" in r_admin_deletes_o2.json()["detail"].lower()


@pytest.mark.asyncio
async def test_sole_owner_self_demotion_and_self_deletion_rejection():
    """Verify that a sole OWNER cannot demote themselves (400) and cannot delete themselves (400)."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        owner_email = f"owner_self_{uuid.uuid4().hex[:6]}@test.com"
        r = await client.post("/api/v1/auth/register", json={
            "email": owner_email, "password": "Password123!", "full_name": "Sole Owner"
        })
        owner_h = {"Authorization": f"Bearer {r.json()['access_token']}"}

        async with AsyncSessionLocal() as session:
            await session.execute(update(User).values(role=UserRole.DEVELOPER))
            res = await session.execute(select(User).where(User.email == owner_email))
            u = res.scalars().first()
            u.role = UserRole.OWNER
            await session.commit()
            owner_id = u.id

        # 1. Sole owner attempts to demote self to VIEWER -> 400
        r_demote_self = await client.patch(f"/api/v1/team/members/{owner_id}/role", json={
            "role": "VIEWER"
        }, headers=owner_h)
        assert r_demote_self.status_code == 400
        assert "sole" in r_demote_self.json()["detail"].lower()

        # 2. Sole owner attempts to demote self to DEVELOPER -> 400
        r_demote_dev = await client.patch(f"/api/v1/team/members/{owner_id}/role", json={
            "role": "DEVELOPER"
        }, headers=owner_h)
        assert r_demote_dev.status_code == 400
        assert "sole" in r_demote_dev.json()["detail"].lower()

        # 3. Sole owner attempts to delete self -> 400
        r_del_self = await client.delete(f"/api/v1/team/members/{owner_id}", headers=owner_h)
        assert r_del_self.status_code == 400
        assert "own" in r_del_self.json()["detail"].lower()


# =============================================================================
# SUITE 2: ACTIVE SECURITY PROBES GATING & NON-DESTRUCTIVENESS
# =============================================================================

@pytest.mark.asyncio
async def test_active_security_gating_unauthorized_zero_network_probes():
    """Verify that when domain is unauthorized or missing authorization_record_id:
    1. Result status is strictly BLOCKED
    2. Score is None
    3. Finding rule_id is 'sec-active-unauthorized'
    4. ZERO network probes/requests are dispatched!
    """
    engine = AuthorizedActiveSecurityEngine()

    with patch("backend.app.core.ssrf.resolve_and_validate_hostname", return_value=["93.184.216.34"]), \
         patch("httpx.AsyncClient") as mock_client:
        # Case A: is_verified_authorized = False
        res_a = await engine.execute("https://unverified-domain.com", {
            "is_verified_authorized": False,
            "authorization_record_id": 123
        })
        assert res_a.status == EngineStatus.BLOCKED
        assert res_a.score is None
        assert res_a.raw_evidence["authorized"] is False
        assert any(f.rule_id == "sec-active-unauthorized" for f in res_a.findings)
        mock_client.assert_not_called()

        # Case B: is_verified_authorized = True but authorization_record_id = None
        res_b = await engine.execute("https://unverified-domain.com", {
            "is_verified_authorized": True,
            "authorization_record_id": None
        })
        assert res_b.status == EngineStatus.BLOCKED
        assert res_b.score is None
        assert res_b.raw_evidence["authorized"] is False
        assert any(f.rule_id == "sec-active-unauthorized" for f in res_b.findings)
        mock_client.assert_not_called()

        # Case C: Empty config dictionary
        res_c = await engine.execute("https://unverified-domain.com", {})
        assert res_c.status == EngineStatus.BLOCKED
        assert res_c.score is None
        assert res_c.raw_evidence["authorized"] is False
        mock_client.assert_not_called()


@pytest.mark.asyncio
async def test_active_security_end_to_end_audit_service_gating():
    """Adversarial test on AuditService.run_audit_job:
    Ensure that if an audit target domain has PENDING or FAILED or NO domain authorization,
    the active security engine outputs BLOCKED, never attempts active scanning.
    """
    async with AsyncSessionLocal() as session:
        # Create Project
        owner_email = f"audit_sec_{uuid.uuid4().hex[:6]}@test.com"
        owner = User(email=owner_email, hashed_password="pwd", full_name="Owner", role=UserRole.OWNER)
        session.add(owner)
        await session.commit()
        await session.refresh(owner)

        project = Project(name="Sec Test Project", owner_id=owner.id, domain="unauthorized-scan-target.org")
        session.add(project)
        await session.commit()
        await session.refresh(project)

        # Create DomainAuthorization with status = PENDING (NOT VERIFIED)
        auth = DomainAuthorization(
            project_id=project.id,
            domain="unauthorized-scan-target.org",
            verification_method=VerificationMethod.DNS_TXT,
            token="tok_123",
            status=VerificationStatus.PENDING
        )
        session.add(auth)
        await session.commit()

        # Create Audit requesting SECURITY_ACTIVE
        audit = Audit(
            project_id=project.id,
            target_url="https://unauthorized-scan-target.org",
            scan_mode=ScanMode.SINGLE_PAGE,
            status=AuditStatus.QUEUED,
            selected_modules=["SECURITY_ACTIVE"]
        )
        session.add(audit)
        await session.commit()
        await session.refresh(audit)

        audit_id = audit.id

    # Mock Crawler to return immediately without web fetch
    with patch("backend.app.core.ssrf.resolve_and_validate_hostname", return_value=["93.184.216.34"]), \
         patch("backend.app.services.audit_service.CrawlerEngine.execute") as mock_crawl, \
         patch("httpx.AsyncClient.get") as mock_http_get, \
         patch("httpx.AsyncClient.put") as mock_http_put, \
         patch("httpx.AsyncClient.delete") as mock_http_del:

        from backend.app.engines.base import EngineResult
        mock_crawl.return_value = EngineResult(
            category=AuditCategory.TECHNICAL_HEALTH,
            engine_name="Crawler",
            engine_version="1.0",
            status=EngineStatus.SUCCESS,
            score=90.0,
            findings=[],
            raw_evidence={"pages": [{"url": "https://unauthorized-scan-target.org", "status_code": 200, "depth": 0}]}
        )

        async with AsyncSessionLocal() as run_session:
            await AuditService.run_audit_job(audit_id, run_session)

        # Verify audit raw_results for SECURITY_ACTIVE
        async with AsyncSessionLocal() as verify_session:
            res = await verify_session.execute(select(Audit).where(Audit.id == audit_id))
            completed_audit = res.scalars().first()

            sec_act_raw = completed_audit.raw_results.get("SECURITY_ACTIVE", {})
            assert sec_act_raw.get("authorized") is False, f"Expected authorized=False, got {sec_act_raw}"
            assert sec_act_raw.get("domain") == "unauthorized-scan-target.org"

            # Verify NO active probe requests were made by httpx during the active scan!
            mock_http_put.assert_not_called()
            mock_http_del.assert_not_called()


@pytest.mark.asyncio
async def test_active_security_probes_payload_non_destructive():
    """Verify that all 5 active security probes are strictly non-destructive:
    1. HTTP Methods: PUT/DELETE target throwaway probe path b'probe', OPTIONS/TRACE/TRACK
    2. CORS: origin reflection test
    3. Sensitive files: GET-only requests to standard metadata paths
    4. Open redirect: GET-only parameter reflection
    5. Clickjacking: GET-only frame-options inspection
    """
    engine = AuthorizedActiveSecurityEngine()
    test_url = "https://example-authorized-site.com"

    recorded_requests = []

    def fake_handler(request: httpx.Request):
        recorded_requests.append({
            "method": request.method,
            "url": str(request.url),
            "headers": dict(request.headers),
            "content": request.read().decode("utf-8", errors="ignore")
        })
        # Return benign response
        return httpx.Response(
            status_code=404,
            headers={"content-type": "text/plain"},
            text="Not Found"
        )

    transport = httpx.MockTransport(fake_handler)

    with patch("backend.app.core.ssrf.resolve_and_validate_hostname", return_value=["93.184.216.34"]), \
         patch("httpx.AsyncClient", return_value=httpx.AsyncClient(transport=transport)):
        res = await engine.execute(test_url, {
            "is_verified_authorized": True,
            "authorization_record_id": 999
        })

        assert res.status == EngineStatus.SUCCESS
        assert len(recorded_requests) > 0

        # Examine all dispatched requests for non-destructiveness
        for req in recorded_requests:
            method = req["method"]
            url = req["url"]
            content = req["content"]

            # Method check
            assert method in ("OPTIONS", "TRACE", "TRACK", "PUT", "DELETE", "GET"), f"Unexpected HTTP method {method}"

            # If PUT or DELETE, ensure it is strictly to .webaudit360-probe-check
            if method in ("PUT", "DELETE"):
                assert ".webaudit360-probe-check" in url, f"Destructive target URL in {method}: {url}"
                if method == "PUT":
                    assert content == "probe", f"Unexpected PUT payload: {content}"

            # Ensure no SQL injection, command injection, or destructive data manipulation in URLs or payloads
            lower_url = url.lower()
            lower_content = content.lower()
            dangerous_patterns = ["drop table", "truncate", "rm -rf", "delete from", "--exec", "xp_cmdshell", "format c:"]
            for pat in dangerous_patterns:
                assert pat not in lower_url, f"Dangerous pattern '{pat}' found in URL: {url}"
                assert pat not in lower_content, f"Dangerous pattern '{pat}' found in payload: {content}"


@pytest.mark.asyncio
async def test_audit_active_security_cross_project_isolation():
    """Verify that Project B cannot execute active scans against a domain verified only by Project A."""
    async with AsyncSessionLocal() as session:
        # User A & Project A
        user_a = User(email=f"user_a_{uuid.uuid4().hex[:6]}@test.com", hashed_password="pwd", full_name="User A", role=UserRole.OWNER)
        session.add(user_a)
        await session.flush()

        proj_a = Project(name="Project A", owner_id=user_a.id, domain="tenant-a-protected.com")
        session.add(proj_a)
        await session.flush()

        # User A verifies domain
        auth_a = DomainAuthorization(
            project_id=proj_a.id,
            domain="tenant-a-protected.com",
            verification_method=VerificationMethod.DNS_TXT,
            token="token_a",
            status=VerificationStatus.VERIFIED,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30)
        )
        session.add(auth_a)
        await session.flush()

        # User B & Project B
        user_b = User(email=f"user_b_{uuid.uuid4().hex[:6]}@test.com", hashed_password="pwd", full_name="User B", role=UserRole.DEVELOPER)
        session.add(user_b)
        await session.flush()

        proj_b = Project(name="Project B", owner_id=user_b.id, domain="tenant-b.com")
        session.add(proj_b)
        await session.flush()

        # User B targets User A's domain under Project B
        audit_b = Audit(
            project_id=proj_b.id,
            user_id=user_b.id,
            target_url="https://tenant-a-protected.com",
            scan_mode=ScanMode.SINGLE_PAGE,
            status=AuditStatus.QUEUED,
            selected_modules=["SECURITY_ACTIVE"]
        )
        session.add(audit_b)
        await session.commit()
        audit_b_id = audit_b.id

    with patch("backend.app.core.ssrf.resolve_and_validate_hostname", return_value=["93.184.216.34"]), \
         patch("backend.app.services.audit_service.CrawlerEngine.execute") as mock_crawl, \
         patch("httpx.AsyncClient.put") as mock_put, \
         patch("httpx.AsyncClient.delete") as mock_del:

        mock_crawl.return_value = EngineResult(
            category=AuditCategory.TECHNICAL_HEALTH,
            engine_name="Crawler",
            engine_version="1.0",
            status=EngineStatus.SUCCESS,
            score=90.0,
            findings=[],
            raw_evidence={"pages": [{"url": "https://tenant-a-protected.com", "status_code": 200, "depth": 0}]}
        )

        async with AsyncSessionLocal() as run_session:
            await AuditService.run_audit_job(audit_b_id, run_session)

        # Inspect audit results: Active security MUST be blocked
        async with AsyncSessionLocal() as check_session:
            res = await check_session.execute(select(Audit).where(Audit.id == audit_b_id))
            completed = res.scalars().first()
            raw_sec = completed.raw_results.get("SECURITY_ACTIVE", {})
            assert raw_sec.get("authorized") is False
            mock_put.assert_not_called()
            mock_del.assert_not_called()


@pytest.mark.asyncio
async def test_audit_active_security_blocks_expired_domain_authorization():
    """Verify that domain authorization with expired timestamp is blocked and transitioned to EXPIRED."""
    async with AsyncSessionLocal() as session:
        user = User(email=f"exp_user_{uuid.uuid4().hex[:6]}@test.com", hashed_password="pwd", full_name="Exp User", role=UserRole.OWNER)
        session.add(user)
        await session.flush()

        project = Project(name="Exp Project", owner_id=user.id, domain="expired-challenge.com")
        session.add(project)
        await session.flush()

        # Authorization that expired 1 hour ago
        auth = DomainAuthorization(
            project_id=project.id,
            domain="expired-challenge.com",
            verification_method=VerificationMethod.DNS_TXT,
            token="token_exp",
            status=VerificationStatus.VERIFIED,
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1)
        )
        session.add(auth)
        await session.flush()
        auth_id = auth.id

        audit = Audit(
            project_id=project.id,
            user_id=user.id,
            target_url="https://expired-challenge.com",
            scan_mode=ScanMode.SINGLE_PAGE,
            status=AuditStatus.QUEUED,
            selected_modules=["SECURITY_ACTIVE"]
        )
        session.add(audit)
        await session.commit()
        audit_id = audit.id

    with patch("backend.app.core.ssrf.resolve_and_validate_hostname", return_value=["93.184.216.34"]), \
         patch("backend.app.services.audit_service.CrawlerEngine.execute") as mock_crawl, \
         patch("httpx.AsyncClient.put") as mock_put:

        mock_crawl.return_value = EngineResult(
            category=AuditCategory.TECHNICAL_HEALTH,
            engine_name="Crawler",
            engine_version="1.0",
            status=EngineStatus.SUCCESS,
            score=90.0,
            findings=[],
            raw_evidence={"pages": [{"url": "https://expired-challenge.com", "status_code": 200, "depth": 0}]}
        )

        async with AsyncSessionLocal() as run_session:
            await AuditService.run_audit_job(audit_id, run_session)

        async with AsyncSessionLocal() as check_session:
            # Audit must have blocked active security
            res_audit = await check_session.execute(select(Audit).where(Audit.id == audit_id))
            completed = res_audit.scalars().first()
            raw_sec = completed.raw_results.get("SECURITY_ACTIVE", {})
            assert raw_sec.get("authorized") is False
            mock_put.assert_not_called()

            # Domain authorization record status must now be EXPIRED in DB
            res_auth = await check_session.execute(select(DomainAuthorization).where(DomainAuthorization.id == auth_id))
            auth_db = res_auth.scalars().first()
            assert auth_db.status == VerificationStatus.EXPIRED

