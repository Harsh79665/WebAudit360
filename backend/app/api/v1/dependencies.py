"""WebAudit 360 — FastAPI Route Dependencies & Authentication Gatekeepers
Author: Harsh Patel

Supports dual Bearer token authentication:
1. Scoped API Keys with 'w360_live_' prefix validated against ApiKey.key_hash (SHA-256).
2. Standard JWT access tokens validated via core/security.py.
Provides transparent default workspace owner fallback when unauthenticated.
"""

from datetime import datetime, timezone
import hashlib
from typing import Optional
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.database import get_db
from backend.app.core.security import decode_token
from backend.app.models.entities import ApiKey, User, UserRole

security_scheme = HTTPBearer(auto_error=False)


async def get_current_user_optional(
    creds: Optional[HTTPAuthorizationCredentials] = Security(security_scheme),
    session: AsyncSession = Depends(get_db)
) -> Optional[User]:
    """
    Retrieves authenticated user from Bearer credentials (JWT or Scoped API Key).
    Returns None if anonymous or if token is invalid/expired.
    """
    if not creds or not creds.credentials:
        return None

    raw_token = creds.credentials.strip()

    # 1. API Key Authentication (w360_live_<hex>)
    if raw_token.startswith("w360_live_"):
        key_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        query = select(ApiKey).where(ApiKey.key_hash == key_hash, ApiKey.is_active == True)
        result = await session.execute(query)
        api_key = result.scalars().first()
        if not api_key:
            return None

        # Check expiration if configured
        if api_key.expires_at:
            now = datetime.now(timezone.utc)
            expires_at = api_key.expires_at
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at < now:
                return None

        user_query = select(User).where(User.id == api_key.user_id, User.is_active == True)
        user_res = await session.execute(user_query)
        return user_res.scalars().first()

    # 2. JWT Access Token Authentication
    try:
        payload = decode_token(raw_token)
        user_id = payload.get("sub")
        if not user_id:
            return None
        result = await session.execute(select(User).where(User.id == int(user_id)))
        user = result.scalars().first()
        return user if user and user.is_active else None
    except Exception:
        return None


async def get_current_user(
    creds: Optional[HTTPAuthorizationCredentials] = Security(security_scheme),
    user: Optional[User] = Depends(get_current_user_optional),
    session: AsyncSession = Depends(get_db)
) -> User:
    """
    Retrieves current user. If valid credentials provided, returns authenticated user.
    If credentials were provided but are invalid/expired, raises 401 Unauthorized.
    If unauthenticated (creds is None), transparently provides the default workspace owner
    (Harsh Patel) to ensure seamless local operation.
    """
    if creds is not None and creds.credentials:
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired credentials (API key or JWT token).",
                headers={"WWW-Authenticate": "Bearer"}
            )
        return user

    if user:
        return user

    # Provision or fetch default workspace owner for open-access local dev
    result = await session.execute(select(User).where(User.email == "harsh@webaudit360.io"))
    default_user = result.scalars().first()
    if not default_user:
        default_user = User(
            email="harsh@webaudit360.io",
            full_name="Harsh Patel",
            hashed_password="[LOCAL_WORKSPACE_USER]",
            role=UserRole.OWNER,
            is_active=True
        )
        session.add(default_user)
        await session.commit()
        await session.refresh(default_user)
    return default_user
