"""WebAudit 360 — Projects API Routes
Author: Harsh Patel
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.database import get_db
from backend.app.models.entities import Project, User
from backend.app.schemas import ProjectCreate, ProjectListResponse, ProjectResponse, StatusResponse
from backend.app.api.v1.dependencies import get_current_user

router = APIRouter(prefix="/projects", tags=["Projects"])


@router.get("", response_model=ProjectListResponse)
async def list_projects(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db)
):
    """Lists projects owned by current user with pagination."""
    query = select(Project).where(Project.owner_id == user.id).offset(skip).limit(limit)
    result = await session.execute(query)
    projects = result.scalars().all()

    total_query = select(func.count(Project.id)).where(Project.owner_id == user.id)
    total = (await session.execute(total_query)).scalar() or 0

    return ProjectListResponse(
        items=[ProjectResponse.model_validate(p) for p in projects],
        total=total
    )


@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_project(
    payload: ProjectCreate,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db)
):
    """Creates a new project domain container."""
    project = Project(
        owner_id=user.id,
        name=payload.name,
        domain=payload.domain,
        description=payload.description
    )
    session.add(project)
    await session.commit()
    await session.refresh(project)
    return ProjectResponse.model_validate(project)


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: int,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db)
):
    """Retrieves project details, verifying tenant ownership."""
    result = await session.execute(
        select(Project).where(Project.id == project_id, Project.owner_id == user.id)
    )
    project = result.scalars().first()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")
    return ProjectResponse.model_validate(project)


@router.delete("/{project_id}", response_model=StatusResponse)
async def delete_project(
    project_id: int,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db)
):
    """Deletes a project and its associated audits."""
    result = await session.execute(
        select(Project).where(Project.id == project_id, Project.owner_id == user.id)
    )
    project = result.scalars().first()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")

    await session.delete(project)
    await session.commit()
    return StatusResponse(success=True, message="Project deleted successfully.")

