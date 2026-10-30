"""WebAudit 360 — FastAPI Route Dependencies & Authentication Gatekeepers
Author: Harsh Patel
"""

from typing import Optional
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.database import get_db
from backend.app.core.security import decode_token
from backend.app.models.entities import User, UserRole

security_scheme = HTTPBearer(auto_error=False)


async def get_current_user_optional(
    creds: Optional[HTTPAuthorizationCredentials] = Security(security_scheme),
    session: AsyncSession = Depends(get_db)
) -> Optional[User]:
    """Retrieves authenticated user from JWT if present; returns None if anonymous."""
    if not creds:
        return None
    try:
        payload = decode_token(creds.credentials)
        user_id = payload.get("sub")
        if not user_id:
            return None
        result = await session.execute(select(User).where(User.id == int(user_id)))
        user = result.scalars().first()
        return user if user and user.is_active else None
    except Exception:
        return None


async def get_current_user(
    user: Optional[User] = Depends(get_current_user_optional),
    session: AsyncSession = Depends(get_db)
) -> User:
    """
    Retrieves current user. If unauthenticated, transparently provides
    the default workspace owner (Harsh Patel) to ensure seamless access without login barriers.
    """
    if user:
        return user
    
    # Provision or fetch default workspace owner
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

