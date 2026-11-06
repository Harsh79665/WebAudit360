"""WebAudit 360 — Team Management & Workspace RBAC Endpoints
Author: Harsh Patel
"""

import secrets
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.database import get_db
from backend.app.core.logging import logger
from backend.app.core.security import hash_password
from backend.app.models.entities import User, UserRole
from backend.app.schemas import (
    StatusResponse,
    TeamInviteRequest,
    TeamMemberListResponse,
    TeamMemberResponse,
    TeamRoleUpdateRequest,
)
from backend.app.api.v1.dependencies import get_current_user

router = APIRouter(prefix="/team", tags=["Team Collaboration & RBAC"])


ROLE_HIERARCHY_ORDER = {
    UserRole.OWNER: 0,
    UserRole.ADMIN: 1,
    UserRole.DEVELOPER: 2,
    UserRole.VIEWER: 3,
}


@router.get("", response_model=TeamMemberListResponse)
async def list_team_members(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db)
):
    """
    Lists all workspace team members ordered by role hierarchy:
    OWNER -> ADMIN -> DEVELOPER -> VIEWER, then by created_at.
    """
    stmt = select(User).order_by(User.created_at.asc())
    result = await session.execute(stmt)
    users = result.scalars().all()

    # Sort in memory by role hierarchy precedence, then created_at
    sorted_users = sorted(
        users,
        key=lambda u: (ROLE_HIERARCHY_ORDER.get(u.role, 99), u.created_at)
    )

    items = [TeamMemberResponse.model_validate(u) for u in sorted_users]
    return TeamMemberListResponse(items=items, total=len(items))


@router.post("/invite", response_model=TeamMemberResponse, status_code=status.HTTP_201_CREATED)
async def invite_team_member(
    payload: TeamInviteRequest,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db)
):
    """
    Invites a new colleague to the workspace with the specified role.
    Generates a cryptographically strong initial access password.
    Requires OWNER or ADMIN privileges.
    """
    # 1. RBAC Gate: Only OWNER or ADMIN may invite members
    if current_user.role not in (UserRole.OWNER, UserRole.ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only workspace Owners and Admins are permitted to invite team members."
        )

    # 2. Prevent Admins from elevating new members to OWNER
    if payload.role == UserRole.OWNER and current_user.role != UserRole.OWNER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only an existing workspace Owner can appoint another Owner."
        )

    # 3. Prevent duplicate accounts
    existing = await session.execute(
        select(User).where(User.email == payload.email.strip().lower())
    )
    if existing.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"An account with email '{payload.email}' already exists in this workspace."
        )

    # 4. Generate high-entropy temporary initial password (16 characters)
    temp_password = f"W360_{secrets.token_urlsafe(9)}!9"

    # 5. Determine display name
    full_name = payload.full_name
    if not full_name or not full_name.strip():
        full_name = payload.email.split("@")[0].replace(".", " ").title()

    new_user = User(
        email=payload.email.strip().lower(),
        hashed_password=hash_password(temp_password),
        full_name=full_name.strip(),
        role=payload.role,
        is_active=True
    )
    session.add(new_user)
    await session.commit()
    await session.refresh(new_user)

    logger.info(
        f"Team member '{new_user.email}' (role={new_user.role.value}) invited by '{current_user.email}'."
    )

    response = TeamMemberResponse.model_validate(new_user)
    response.initial_password = temp_password
    return response


@router.patch("/members/{member_id}/role", response_model=TeamMemberResponse)
async def update_member_role(
    member_id: int,
    payload: TeamRoleUpdateRequest,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db)
):
    """
    Updates the RBAC role of a team member.
    Enforces sole-OWNER demotion protection and role escalation constraints.
    """
    # 1. RBAC Gate: Only OWNER or ADMIN may change roles
    if current_user.role not in (UserRole.OWNER, UserRole.ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only workspace Owners and Admins can modify team roles."
        )

    # 2. Locate target user
    result = await session.execute(select(User).where(User.id == member_id))
    target_user = result.scalars().first()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Team member #{member_id} does not exist."
        )

    # 3. Only an OWNER can promote someone to OWNER
    if payload.role == UserRole.OWNER and current_user.role != UserRole.OWNER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only an existing workspace Owner can promote a member to Owner."
        )

    # 4. Only an OWNER can modify an existing OWNER's role
    if target_user.role == UserRole.OWNER and current_user.role != UserRole.OWNER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only workspace Owners are permitted to modify an Owner's role."
        )

    # 5. Invariant: Sole OWNER demotion guard
    if target_user.role == UserRole.OWNER and payload.role != UserRole.OWNER:
        owner_count_res = await session.execute(
            select(func.count(User.id)).where(
                User.role == UserRole.OWNER,
                User.is_active == True,
                User.id != member_id
            )
        )
        other_active_owners = owner_count_res.scalar() or 0
        if other_active_owners == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot demote the sole workspace OWNER. Appoint another active OWNER before modifying this role."
            )

    # 5. Apply role update
    old_role = target_user.role.value
    target_user.role = payload.role
    await session.commit()
    await session.refresh(target_user)

    logger.info(
        f"Team member '{target_user.email}' role transitioned from {old_role} to {target_user.role.value} by '{current_user.email}'."
    )
    return TeamMemberResponse.model_validate(target_user)


@router.delete("/members/{member_id}", response_model=StatusResponse)
async def remove_team_member(
    member_id: int,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db)
):
    """
    Removes or deactivates a team member from the workspace.
    Guards against self-deletion and removing the sole OWNER.
    """
    # 1. RBAC Gate: Only OWNER or ADMIN may remove members
    if current_user.role not in (UserRole.OWNER, UserRole.ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only workspace Owners and Admins can remove team members."
        )

    # 2. Locate target user
    result = await session.execute(select(User).where(User.id == member_id))
    target_user = result.scalars().first()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Team member #{member_id} does not exist."
        )

    # 3. Guard: Prevent self-deletion
    if target_user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot remove your own active account from the workspace."
        )

    # 4. Guard: Only an OWNER can remove another OWNER
    if target_user.role == UserRole.OWNER and current_user.role != UserRole.OWNER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only workspace Owners are permitted to remove an Owner."
        )

    # 5. Guard: Prevent removing the sole OWNER
    if target_user.role == UserRole.OWNER:
        owner_count_res = await session.execute(
            select(func.count(User.id)).where(
                User.role == UserRole.OWNER,
                User.is_active == True,
                User.id != member_id
            )
        )
        other_active_owners = owner_count_res.scalar() or 0
        if other_active_owners == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot remove the sole workspace OWNER."
            )

    # 5. Soft-deactivate to preserve database foreign-key integrity (audits, projects)
    target_user.is_active = False
    await session.commit()

    logger.info(
        f"Team member '{target_user.email}' deactivated by '{current_user.email}'."
    )
    return StatusResponse(
        success=True,
        message=f"Team member '{target_user.email}' has been successfully removed from the workspace."
    )
