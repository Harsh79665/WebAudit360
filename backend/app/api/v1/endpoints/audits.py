"""WebAudit 360 — Audits API Routes
Author: Harsh Patel
"""

import asyncio
from typing import List, Optional
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.database import AsyncSessionLocal, get_db
from backend.app.core.logging import logger
from backend.app.core.ssrf import validate_target_url, SSRFValidationError
from backend.app.models.entities import Audit, AuditFinding, AuditPage, AuditStatus, User
from backend.app.schemas import (
    AuditCreate,
    AuditListResponse,
    AuditResponse,
    FindingListResponse,
    FindingResponse,
    StatusResponse,
)
from backend.app.api.v1.dependencies import get_current_user_optional
from backend.app.services.audit_service import AuditService

router = APIRouter(prefix="/audits", tags=["Audits"])


async def run_audit_background_task(audit_id: int):
    """Asynchronous background runner for orchestrating audit execution."""
    async with AsyncSessionLocal() as session:
        await AuditService.run_audit_job(audit_id, session)


@router.post("", response_model=AuditResponse, status_code=status.HTTP_201_CREATED)
async def submit_audit(
    payload: AuditCreate,
    background_tasks: BackgroundTasks,
    current_user: Optional[User] = Depends(get_current_user_optional),
    session: AsyncSession = Depends(get_db)
):
    """
    Submits a new website audit job.
    Enforces strict SSRF validation before queueing the audit pipeline.
    """
    try:
        normalized_url, hostname, resolved_ips = validate_target_url(payload.target_url)
    except SSRFValidationError as e:
        logger.warning(f"Audit submission rejected by SSRF defense: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    audit = Audit(
        project_id=payload.project_id,
        user_id=current_user.id if current_user else None,
        target_url=normalized_url,
        scan_mode=payload.scan_mode,
        device_profile=payload.device_profile,
        status=AuditStatus.QUEUED,
        selected_modules=payload.selected_modules,
        config={
            "max_pages": payload.max_pages or 50,
            "max_depth": payload.max_depth or 3,
            "concurrency": payload.concurrency or 2
        }
    )
    session.add(audit)
    await session.commit()
    await session.refresh(audit)

    # Queue background task (or Celery worker)
    background_tasks.add_task(run_audit_background_task, audit.id)

    return AuditResponse.model_validate(audit)


@router.get("", response_model=AuditListResponse)
async def list_audits(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    project_id: Optional[int] = None,
    current_user: Optional[User] = Depends(get_current_user_optional),
    session: AsyncSession = Depends(get_db)
):
    """Lists audit records ordered by most recent first."""
    query = select(Audit)
    if project_id:
        query = query.where(Audit.project_id == project_id)
    elif current_user:
        query = query.where((Audit.user_id == current_user.id) | (Audit.user_id.is_(None)))

    query = query.order_by(Audit.created_at.desc()).offset(skip).limit(limit)
    result = await session.execute(query)
    audits = result.scalars().all()

    total_query = select(func.count(Audit.id))
    if project_id:
        total_query = total_query.where(Audit.project_id == project_id)
    elif current_user:
        total_query = total_query.where((Audit.user_id == current_user.id) | (Audit.user_id.is_(None)))
    total = (await session.execute(total_query)).scalar() or 0

    return AuditListResponse(
        items=[AuditResponse.model_validate(a) for a in audits],
        total=total
    )


@router.get("/{audit_id}", response_model=AuditResponse)
async def get_audit(audit_id: int, session: AsyncSession = Depends(get_db)):
    """Retrieves full details and calculated scores of an audit run."""
    result = await session.execute(select(Audit).where(Audit.id == audit_id))
    audit = result.scalars().first()
    if not audit:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found.")
    return AuditResponse.model_validate(audit)


@router.post("/{audit_id}/cancel", response_model=StatusResponse)
async def cancel_audit(audit_id: int, session: AsyncSession = Depends(get_db)):
    """Requests emergency cancellation of an active scan."""
    result = await session.execute(select(Audit).where(Audit.id == audit_id))
    audit = result.scalars().first()
    if not audit:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found.")

    if audit.status in (AuditStatus.COMPLETED, AuditStatus.FAILED, AuditStatus.CANCELLED):
        return StatusResponse(success=False, message=f"Audit is already in terminal state: {audit.status.value}")

    audit.status = AuditStatus.CANCELLED
    await session.commit()
    return StatusResponse(success=True, message=f"Audit #{audit_id} cancelled.")


@router.get("/{audit_id}/findings", response_model=FindingListResponse)
async def get_audit_findings(
    audit_id: int,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    session: AsyncSession = Depends(get_db)
):
    """Retrieves all actionable technical findings for an audit."""
    query = select(AuditFinding).where(AuditFinding.audit_id == audit_id)
    if category:
        query = query.where(AuditFinding.category == category.upper())
    if severity:
        query = query.where(AuditFinding.severity == severity.upper())

    result = await session.execute(query)
    findings = result.scalars().all()

    return FindingListResponse(
        items=[FindingResponse.model_validate(f) for f in findings],
        total=len(findings)
    )

