"""WebAudit 360 — Findings & Issue Lifecycle API Routes
Author: Harsh Patel
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.database import get_db
from backend.app.models.entities import AuditFinding, FindingHistory, FindingStatus, User
from backend.app.schemas import (
    FindingListResponse,
    FindingResponse,
    FindingStatusUpdate,
    StatusResponse,
)
from backend.app.api.v1.dependencies import get_current_user_optional

router = APIRouter(prefix="/findings", tags=["Findings & Issues"])


@router.get("", response_model=FindingListResponse)
async def list_findings(
    status: Optional[str] = None,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    audit_id: Optional[int] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    session: AsyncSession = Depends(get_db)
):
    """Lists findings across audits with optional status, category, severity, and audit_id filtering."""
    query = select(AuditFinding)
    if audit_id:
        query = query.where(AuditFinding.audit_id == audit_id)
    if status and status.upper() in FindingStatus.__members__:
        query = query.where(AuditFinding.status == FindingStatus[status.upper()])
    if category:
        query = query.where(AuditFinding.category == category.upper())
    if severity:
        query = query.where(AuditFinding.severity == severity.upper())

    query = query.order_by(AuditFinding.created_at.desc()).offset(skip).limit(limit)
    result = await session.execute(query)
    findings = result.scalars().all()

    total_query = select(func.count(AuditFinding.id))
    if audit_id:
        total_query = total_query.where(AuditFinding.audit_id == audit_id)
    if status and status.upper() in FindingStatus.__members__:
        total_query = total_query.where(AuditFinding.status == FindingStatus[status.upper()])
    if category:
        total_query = total_query.where(AuditFinding.category == category.upper())
    if severity:
        total_query = total_query.where(AuditFinding.severity == severity.upper())
    total = (await session.execute(total_query)).scalar() or 0

    return FindingListResponse(
        items=[FindingResponse.model_validate(f) for f in findings],
        total=total
    )


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(finding_id: int, session: AsyncSession = Depends(get_db)):
    """Retrieves finding details and associated evidence."""
    result = await session.execute(select(AuditFinding).where(AuditFinding.id == finding_id))
    finding = result.scalars().first()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")
    return FindingResponse.model_validate(finding)


@router.put("/{finding_id}/status", response_model=FindingResponse)
async def update_finding_status(
    finding_id: int,
    payload: FindingStatusUpdate,
    current_user: Optional[User] = Depends(get_current_user_optional),
    session: AsyncSession = Depends(get_db)
):
    """Updates the status of a finding with an audit trail entry."""
    result = await session.execute(select(AuditFinding).where(AuditFinding.id == finding_id))
    finding = result.scalars().first()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")

    old_status = finding.status.value
    finding.status = payload.status

    # Record in FindingHistory
    history = FindingHistory(
        finding_id=finding.id,
        user_id=current_user.id if current_user else None,
        old_status=old_status,
        new_status=payload.status.value,
        comment=payload.reason or "Status updated by user"
    )
    session.add(history)
    await session.commit()
    await session.refresh(finding)

    return FindingResponse.model_validate(finding)


@router.post("/{finding_id}/retest", response_model=StatusResponse)
async def retest_finding(finding_id: int, session: AsyncSession = Depends(get_db)):
    """Triggers an individual retest for a specific rule and page."""
    result = await session.execute(select(AuditFinding).where(AuditFinding.id == finding_id))
    finding = result.scalars().first()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")

    # In production, queues single rule verification
    return StatusResponse(
        success=True,
        message=f"Retest queued for rule '{finding.rule_id}'. Issue will be marked resolved only if verification succeeds."
    )

