"""WebAudit 360 — API Keys & Webhooks Subsystem Automated Tests
Author: Harsh Patel
"""

import hashlib
import hmac
from unittest.mock import AsyncMock, MagicMock, patch
import uuid
import pytest
import pytest_asyncio
import httpx
from backend.app.main import app
from backend.app.core.database import init_db
from backend.app.api.v1.endpoints.webhooks import sign_webhook_payload


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    await init_db()


@pytest.mark.asyncio
async def test_api_key_full_lifecycle():
    """Tests creating, authenticating, listing, and revoking scoped API keys."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Register test user to isolate keys
        unique_email = f"key_tester_{uuid.uuid4().hex[:8]}@webaudit360.io"
        reg_res = await client.post("/api/v1/auth/register", json={
            "email": unique_email,
            "password": "SecurePassword123!",
            "full_name": "API Key Tester"
        })
        assert reg_res.status_code == 201
        jwt_token = reg_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {jwt_token}"}

        # 2. Create API Key
        create_res = await client.post("/api/v1/api-keys", json={
            "label": "GitHub Actions CI",
            "expires_in_days": 90
        }, headers=headers)
        assert create_res.status_code == 201
        key_data = create_res.json()
        raw_key = key_data["api_key"]
        assert raw_key.startswith("w360_live_")
        assert key_data["prefix"] == raw_key[:16]
        assert key_data["label"] == "GitHub Actions CI"
        key_id = key_data["id"]

        # 3. List API Keys (must not expose raw_key)
        list_res = await client.get("/api/v1/api-keys", headers=headers)
        assert list_res.status_code == 200
        keys_list = list_res.json()
        assert len(keys_list) >= 1
        matched = [k for k in keys_list if k["id"] == key_id][0]
        assert "api_key" not in matched
        assert matched["prefix"] == raw_key[:16]

        # 4. Authenticate against /api/v1/auth/me using Scoped API Key Bearer token
        api_headers = {"Authorization": f"Bearer {raw_key}"}
        me_res = await client.get("/api/v1/auth/me", headers=api_headers)
        assert me_res.status_code == 200
        me_data = me_res.json()
        assert me_data["email"] == unique_email
        assert me_data["full_name"] == "API Key Tester"

        # 5. Access /api/v1/api-keys using Scoped API Key
        keys_with_api_key = await client.get("/api/v1/api-keys", headers=api_headers)
        assert keys_with_api_key.status_code == 200

        # 6. Reject invalid API Key
        bad_headers = {"Authorization": "Bearer w360_live_invalidkey0000000000000000"}
        bad_res = await client.get("/api/v1/auth/me", headers=bad_headers)
        assert bad_res.status_code == 401

        # 7. Revoke API Key
        del_res = await client.delete(f"/api/v1/api-keys/{key_id}", headers=headers)
        assert del_res.status_code == 200
        assert del_res.json()["success"] is True

        # 8. Verify revoked key can no longer authenticate
        revoked_res = await client.get("/api/v1/auth/me", headers=api_headers)
        assert revoked_res.status_code == 401


@pytest.mark.asyncio
async def test_webhook_full_lifecycle():
    """Tests registering, listing, test pinging, and deleting HMAC webhooks."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Register user
        unique_email = f"wh_tester_{uuid.uuid4().hex[:8]}@webaudit360.io"
        reg_res = await client.post("/api/v1/auth/register", json={
            "email": unique_email,
            "password": "SecurePassword123!",
            "full_name": "Webhook Tester"
        })
        assert reg_res.status_code == 201
        jwt_token = reg_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {jwt_token}"}

        # 2. Reject invalid URL scheme
        bad_res = await client.post("/api/v1/webhooks", json={
            "url": "ftp://example.com/webhook"
        }, headers=headers)
        assert bad_res.status_code == 400

        # 3. Create Webhook
        dest_url = "https://example.com/webaudit-events"
        create_res = await client.post("/api/v1/webhooks", json={
            "url": dest_url,
            "events": ["audit.completed", "regression.detected"]
        }, headers=headers)
        assert create_res.status_code == 201
        wh_data = create_res.json()
        assert wh_data["url"] == dest_url
        assert wh_data["secret"].startswith("whsec_")
        assert len(wh_data["events"]) == 2
        webhook_id = wh_data["id"]

        # 4. List Webhooks (must not expose secret)
        list_res = await client.get("/api/v1/webhooks", headers=headers)
        assert list_res.status_code == 200
        items = list_res.json()
        assert len(items) >= 1
        matched = [w for w in items if w["id"] == webhook_id][0]
        assert "secret" not in matched
        assert matched["url"] == dest_url

        # 5. Dispatch test ping and intercept outbound request to verify HMAC signature
        mock_http_client = AsyncMock()
        mock_http_client.post.return_value = httpx.Response(
            200, json={"received": True, "message": "Ping acknowledged"}
        )
        mock_cm = MagicMock()
        mock_cm.__aenter__.return_value = mock_http_client
        mock_cm.__aexit__.return_value = None

        with patch("backend.app.api.v1.endpoints.webhooks.httpx.AsyncClient", return_value=mock_cm):
            test_res = await client.post(f"/api/v1/webhooks/{webhook_id}/test", headers=headers)
            assert test_res.status_code == 200
            ping_res = test_res.json()
            assert ping_res["success"] is True
            assert ping_res["status_code"] == 200
            assert "response_time_ms" in ping_res

            # Intercept and verify outbound HTTP request
            mock_http_client.post.assert_called_once()
            called_url = mock_http_client.post.call_args[0][0]
            called_kwargs = mock_http_client.post.call_args.kwargs
            sent_content = called_kwargs["content"]
            sent_headers = called_kwargs["headers"]

            assert called_url == dest_url
            assert sent_headers["Content-Type"] == "application/json"
            assert sent_headers["X-WebAudit360-Event"] == "ping"
            assert "X-WebAudit360-Delivery" in sent_headers
            assert "X-WebAudit360-Signature" in sent_headers

            # Verify HMAC-SHA256 signature using the raw secret returned to the client
            expected_signature = "sha256=" + hmac.new(
                wh_data["secret"].encode("utf-8"),
                sent_content,
                hashlib.sha256
            ).hexdigest()
            assert sent_headers["X-WebAudit360-Signature"] == expected_signature

            # Adversarial verification: verify signature mismatch if wrong secret or tampered body
            wrong_sig = "sha256=" + hmac.new(b"whsec_wrongsecret1234567890", sent_content, hashlib.sha256).hexdigest()
            assert sent_headers["X-WebAudit360-Signature"] != wrong_sig

            tampered_sig = "sha256=" + hmac.new(wh_data["secret"].encode("utf-8"), sent_content + b"tampered", hashlib.sha256).hexdigest()
            assert sent_headers["X-WebAudit360-Signature"] != tampered_sig

        # 6. Delete Webhook
        del_res = await client.delete(f"/api/v1/webhooks/{webhook_id}", headers=headers)
        assert del_res.status_code == 200
        assert del_res.json()["success"] is True

        # 7. Confirm deletion
        list_res_after = await client.get("/api/v1/webhooks", headers=headers)
        assert all(w["id"] != webhook_id for w in list_res_after.json())


@pytest.mark.asyncio
async def test_webhook_signature_cryptographic_verification():
    """Adversarially tests HMAC-SHA256 signature generation and payload tampering detection."""
    secret = "whsec_7936a53bc778cf168923058b75e182ea81d0df9c8eecfe1e"
    payload = b'{"event":"ping","data":{"status":"active"}}'

    signature = sign_webhook_payload(secret, payload)

    # 1. Receiver verifying with same secret succeeds
    expected = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    assert signature == expected

    # 2. Tampered payload fails verification
    tampered_payload = b'{"event":"ping","data":{"status":"active","injected":true}}'
    assert signature != hmac.new(secret.encode("utf-8"), tampered_payload, hashlib.sha256).hexdigest()

    # 3. Wrong secret fails verification
    assert signature != hmac.new(b"whsec_differentsecret", payload, hashlib.sha256).hexdigest()

    # 4. Regression check: using sha256 hash of secret as signing key fails verification
    bogus_hash_key = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    assert signature != hmac.new(bogus_hash_key.encode("utf-8"), payload, hashlib.sha256).hexdigest()


@pytest.mark.asyncio
async def test_webhook_creation_rejects_loopback_ssrf():
    """Verify that webhook registration blocks loopback addresses (127.0.0.1)."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Register user
        reg_res = await client.post("/api/v1/auth/register", json={
            "email": f"ssrf_tester_{uuid.uuid4().hex[:6]}@webaudit360.io",
            "password": "Password123!",
            "full_name": "SSRF Tester"
        })
        headers = {"Authorization": f"Bearer {reg_res.json()['access_token']}"}

        # Attempt to create webhook targeting localhost
        res = await client.post("/api/v1/webhooks", json={
            "url": "http://127.0.0.1:8000/internal-listener"
        }, headers=headers)
        assert res.status_code == 400
        assert "ssrf" in res.json()["detail"].lower() or "restricted" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_webhook_creation_rejects_cloud_metadata_ssrf():
    """Verify that webhook registration blocks cloud metadata endpoints (169.254.169.254)."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        reg_res = await client.post("/api/v1/auth/register", json={
            "email": f"meta_tester_{uuid.uuid4().hex[:6]}@webaudit360.io",
            "password": "Password123!",
            "full_name": "Metadata Tester"
        })
        headers = {"Authorization": f"Bearer {reg_res.json()['access_token']}"}

        res = await client.post("/api/v1/webhooks", json={
            "url": "http://169.254.169.254/latest/meta-data/"
        }, headers=headers)
        assert res.status_code == 400
        assert "restricted" in res.json()["detail"].lower() or "prohibited" in res.json()["detail"].lower()

