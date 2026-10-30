"""WebAudit 360 — Authentication API Routes
Author: Harsh Patel
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from backend.app.models.entities import User, UserRole
from backend.app.schemas import (
    AuthSuccessResponse,
    RefreshTokenRequest,
    StatusResponse,
    TokenResponse,
    UserLogin,
    UserRegister,
    UserResponse,
)
from backend.app.api.v1.dependencies import get_current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=AuthSuccessResponse, status_code=status.HTTP_201_CREATED)
async def register_user(payload: UserRegister, session: AsyncSession = Depends(get_db)):
    """Registers a new developer user account."""
    existing = await session.execute(select(User).where(User.email == payload.email))
    if existing.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists."
        )

    user = User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name,
        role=UserRole.DEVELOPER,
        is_active=True
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)

    access_token = create_access_token({"sub": str(user.id), "email": user.email})
    refresh_token = create_refresh_token({"sub": str(user.id), "email": user.email})

    return AuthSuccessResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        user=UserResponse.model_validate(user)
    )


@router.post("/login", response_model=AuthSuccessResponse)
async def login_user(payload: UserLogin, session: AsyncSession = Depends(get_db)):
    """Authenticates credentials and returns short-lived access & refresh tokens."""
    result = await session.execute(select(User).where(User.email == payload.email))
    user = result.scalars().first()

    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password credentials."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated."
        )

    access_token = create_access_token({"sub": str(user.id), "email": user.email})
    refresh_token = create_refresh_token({"sub": str(user.id), "email": user.email})

    return AuthSuccessResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        user=UserResponse.model_validate(user)
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_access_token(payload: RefreshTokenRequest, session: AsyncSession = Depends(get_db)):
    """Refreshes an access token using an active refresh token."""
    try:
        data = decode_token(payload.refresh_token)
        if data.get("type") != "refresh":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token type.")

        user_id = data.get("sub")
        result = await session.execute(select(User).where(User.id == int(user_id)))
        user = result.scalars().first()

        if not user or not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User inactive or removed.")

        new_access = create_access_token({"sub": str(user.id), "email": user.email})
        new_refresh = create_refresh_token({"sub": str(user.id), "email": user.email})

        return TokenResponse(
            access_token=new_access,
            refresh_token=new_refresh,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Expired or invalid refresh token.")


@router.post("/logout", response_model=StatusResponse)
async def logout_user():
    """Logs out current user session."""
    return StatusResponse(success=True, message="Logged out successfully.")


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(user: User = Depends(get_current_user)):
    """Returns the authenticated user's profile."""
    return UserResponse.model_validate(user)
