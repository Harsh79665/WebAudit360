"""WebAudit 360 — Scoped API Keys Management API
Author: Harsh Patel

Provides endpoints for creating, listing, and revoking scoped developer API keys.
Keys use the 'w360_live_' prefix, are hashed with SHA-256 for persistent storage,
and are verified in dependencies.py via standard Bearer authentication.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import secrets
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.database import get_db
from backend.app.models.entities import ApiKey, User
from backend.app.schemas import (
    ApiKeyCreate,
    ApiKeyCreatedResponse,
    ApiKeyResponse,
    StatusResponse,
)
from backend.app.api.v1.dependencies import get_current_user

router = APIRouter(prefix="/api-keys", tags=["API Keys"])


@router.get("", response_model=List[ApiKeyResponse])
async def list_api_keys(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db)
):
    """
    Lists all API keys created by the authenticated user.
    Plaintext secrets are never returned; only labels, prefixes, and validity metadata are exposed.
    """
    query = (
        select(ApiKey)
        .where(ApiKey.user_id == user.id)
        .order_by(ApiKey.created_at.desc())
    )
    result = await session.execute(query)
    keys = result.scalars().all()
    return [ApiKeyResponse.model_validate(k) for k in keys]


@router.post("", response_model=ApiKeyCreatedResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    payload: ApiKeyCreate,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db)
):
    """
    Generates a new high-entropy scoped API key.
    The complete plaintext key is returned strictly ONCE in this response.
    """
    raw_token = f"w360_live_{secrets.token_hex(16)}"
    key_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    prefix = raw_token[:16]

    expires_at = None
    if payload.expires_in_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=payload.expires_in_days)

    key_record = ApiKey(
        user_id=user.id,
        label=payload.label.strip(),
        key_hash=key_hash,
        prefix=prefix,
        is_active=True,
        expires_at=expires_at,
    )
    session.add(key_record)
    await session.commit()
    await session.refresh(key_record)

    return ApiKeyCreatedResponse(
        id=key_record.id,
        user_id=key_record.user_id,
        label=key_record.label,
        prefix=key_record.prefix,
        is_active=key_record.is_active,
        expires_at=key_record.expires_at,
        created_at=key_record.created_at,
        api_key=raw_token,
    )


@router.delete("/{key_id}", response_model=StatusResponse)
async def revoke_api_key(
    key_id: int,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db)
):
    """
    Permanently revokes and removes an API key.
    Immediate invalidation across all subsequent bearer requests.
    """
    query = select(ApiKey).where(ApiKey.id == key_id, ApiKey.user_id == user.id)
    result = await session.execute(query)
    key_record = result.scalars().first()

    if not key_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found or not owned by current user."
        )

    await session.delete(key_record)
    await session.commit()

    return StatusResponse(success=True, message="API key revoked successfully.")
