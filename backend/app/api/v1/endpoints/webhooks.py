"""WebAudit 360 — HMAC-Signed Webhook Management API
Author: Harsh Patel

Provides endpoints for registering, listing, deleting, and testing webhook endpoints.
Webhooks deliver real-time notifications for completed audits, regressions, and security findings.
Payloads are cryptographically authenticated via X-WebAudit360-Signature (HMAC-SHA256).
"""

from datetime import datetime, timezone
import hashlib
import hmac
import json
import secrets
import time
from typing import List, Optional
import uuid
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.core.ssrf import validate_target_url, SSRFValidationError
from backend.app.models.entities import Project, User, Webhook
from backend.app.schemas import (
    StatusResponse,
    WebhookCreate,
    WebhookCreatedResponse,
    WebhookResponse,
    WebhookTestResponse,
)
from backend.app.api.v1.dependencies import get_current_user

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])


def sign_webhook_payload(secret: str, payload_bytes: bytes) -> str:
    """
    Computes HMAC-SHA256 signature for outgoing webhook payload.
    Used for X-WebAudit360-Signature generation and recipient authentication.
    """
    return hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()



@router.get("", response_model=List[WebhookResponse])
async def list_webhooks(
    project_id: Optional[int] = Query(None, description="Filter by project ID"),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db)
):
    """
    Lists registered webhooks for projects owned by the authenticated user.
    """
    query = (
        select(Webhook)
        .join(Project, Webhook.project_id == Project.id)
        .where(Project.owner_id == user.id)
    )
    if project_id is not None:
        query = query.where(Webhook.project_id == project_id)

    query = query.order_by(Webhook.created_at.desc())
    result = await session.execute(query)
    webhooks = result.scalars().all()
    return [WebhookResponse.model_validate(w) for w in webhooks]


@router.post("", response_model=WebhookCreatedResponse, status_code=status.HTTP_201_CREATED)
async def create_webhook(
    payload: WebhookCreate,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db)
):
    """
    Registers a new webhook endpoint and generates a cryptographic HMAC signing secret.
    The secret is returned strictly ONCE in this response.
    """
    url_clean = payload.url.strip()
    try:
        normalized_url, hostname, resolved_ips = validate_target_url(url_clean)
    except SSRFValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Webhook target URL failed SSRF validation: {str(e)}"
        )

    parsed = urlparse(normalized_url)
    if settings.ENVIRONMENT == "production" and parsed.scheme.lower() != "https":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Webhook URLs must use HTTPS protocol in production."
        )

    # Resolve or create default project if not explicitly supplied
    target_project_id = payload.project_id
    if target_project_id is not None:
        p_query = select(Project).where(Project.id == target_project_id, Project.owner_id == user.id)
        p_res = await session.execute(p_query)
        if not p_res.scalars().first():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Project ID {target_project_id} not found or not owned by user."
            )
    else:
        p_query = select(Project).where(Project.owner_id == user.id)
        p_res = await session.execute(p_query)
        existing_project = p_res.scalars().first()
        if existing_project:
            target_project_id = existing_project.id
        else:
            new_project = Project(
                owner_id=user.id,
                name="Default Workspace",
                domain="localhost",
                description="Auto-generated workspace project for integrations."
            )
            session.add(new_project)
            await session.flush()
            target_project_id = new_project.id

    raw_secret = f"whsec_{secrets.token_hex(24)}"

    webhook = Webhook(
        project_id=target_project_id,
        url=normalized_url,
        secret_hash=raw_secret,
        events=payload.events,
        is_active=True
    )
    session.add(webhook)
    await session.commit()
    await session.refresh(webhook)

    return WebhookCreatedResponse(
        id=webhook.id,
        project_id=webhook.project_id,
        url=webhook.url,
        events=webhook.events,
        is_active=webhook.is_active,
        created_at=webhook.created_at,
        secret=raw_secret
    )


@router.delete("/{webhook_id}", response_model=StatusResponse)
async def delete_webhook(
    webhook_id: int,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db)
):
    """
    Deletes a registered webhook destination.
    """
    query = (
        select(Webhook)
        .join(Project, Webhook.project_id == Project.id)
        .where(Webhook.id == webhook_id, Project.owner_id == user.id)
    )
    result = await session.execute(query)
    webhook = result.scalars().first()

    if not webhook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Webhook not found or not owned by user."
        )

    await session.delete(webhook)
    await session.commit()

    return StatusResponse(success=True, message="Webhook deleted successfully.")


@router.post("/{webhook_id}/test", response_model=WebhookTestResponse)
async def test_webhook(
    webhook_id: int,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db)
):
    """
    Dispatches an instantaneous signed ping event to verify destination connectivity
    and HMAC signature generation.
    """
    query = (
        select(Webhook)
        .join(Project, Webhook.project_id == Project.id)
        .where(Webhook.id == webhook_id, Project.owner_id == user.id)
    )
    result = await session.execute(query)
    webhook = result.scalars().first()

    if not webhook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Webhook not found or not owned by user."
        )

    # Re-verify destination URL against SSRF defense before making outgoing request
    try:
        validate_target_url(webhook.url)
    except SSRFValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Webhook target URL failed SSRF validation: {str(e)}"
        )

    ping_payload = {
        "event": "ping",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "webhook_id": webhook.id,
        "message": "WebAudit 360 webhook test ping",
        "data": {
            "status": "active" if webhook.is_active else "inactive",
            "events": webhook.events,
            "url": webhook.url
        }
    }
    payload_bytes = json.dumps(ping_payload, separators=(",", ":")).encode("utf-8")
    signature = sign_webhook_payload(webhook.secret_hash, payload_bytes)

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "WebAudit360-Webhook-Delivery/1.0",
        "X-WebAudit360-Event": "ping",
        "X-WebAudit360-Delivery": str(uuid.uuid4()),
        "X-WebAudit360-Signature": f"sha256={signature}",
    }

    start_time = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            res = await client.post(webhook.url, content=payload_bytes, headers=headers)
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            return WebhookTestResponse(
                success=res.is_success,
                status_code=res.status_code,
                response_time_ms=elapsed_ms,
                message=f"Webhook test ping returned HTTP {res.status_code}."
            )
    except Exception as e:
        elapsed_ms = int((time.perf_counter() - start_time) * 1000)
        return WebhookTestResponse(
            success=False,
            status_code=None,
            response_time_ms=elapsed_ms,
            message=f"Webhook test delivery failed: {str(e)}"
        )
