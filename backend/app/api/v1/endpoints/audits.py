"""WebAudit 360 — Audits API Routes
Author: Harsh Patel
"""

import asyncio
from typing import List, Optional
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.database import AsyncSessionLocal, get_db
from backend.app.core.logging import logger
from backend.app.core.ssrf import validate_target_url, SSRFValidationError
from backend.app.models.entities import Audit, AuditFinding, AuditPage, AuditStatus, User
from backend.app.schemas import (
    AuditCreate,
    AuditDetailResponse,
    AuditListResponse,
    AuditPageResponse,
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


@router.get("/{audit_id}", response_model=AuditDetailResponse)
async def get_audit(audit_id: int, session: AsyncSession = Depends(get_db)):
    """Retrieves full details, findings, pages, and calculated scores of an audit run."""
    result = await session.execute(
        select(Audit)
        .options(selectinload(Audit.pages), selectinload(Audit.findings))
        .where(Audit.id == audit_id)
    )
    audit = result.scalars().first()
    if not audit:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found.")

    findings_list = audit.findings or []
    raw_res = audit.raw_results or {}

    perf_score = audit.score_performance or raw_res.get("PERFORMANCE", {}).get("score")
    if perf_score is None:
        perf_score = 92.0 if not any(f.category == "PERFORMANCE" and f.severity.value in ("HIGH", "CRITICAL") for f in findings_list) else 70.0

    seo_score = audit.score_seo or raw_res.get("SEO", {}).get("score") or 95.0

    a11y_score = audit.score_accessibility or raw_res.get("ACCESSIBILITY", {}).get("score")
    if a11y_score is None:
        a11y_score = 90.0 if not any(f.category == "ACCESSIBILITY" and f.severity.value in ("HIGH", "CRITICAL") for f in findings_list) else 75.0

    sec_score = audit.score_security or raw_res.get("SECURITY_PASSIVE", {}).get("score") or 90.0
    tech_score = audit.score_technical or raw_res.get("TECHNICAL_HEALTH", {}).get("score") or 100.0

    category_scores = {
        "PERFORMANCE": perf_score,
        "SEO": seo_score,
        "ACCESSIBILITY": a11y_score,
        "SECURITY": sec_score,
        "SECURITY_PASSIVE": sec_score,
        "TECHNICAL": tech_score,
        "TECHNICAL_HEALTH": tech_score,
        "DOMAIN": 100.0 if not any(f.category == "DOMAIN" and f.severity.value in ("HIGH", "CRITICAL") for f in findings_list) else 70.0,
        "RESPONSIVE": 100.0 if not any(f.category == "RESPONSIVE" and f.severity.value in ("HIGH", "CRITICAL") for f in findings_list) else 75.0,
        "TECHNOLOGY": 100.0 if not any(f.category == "TECHNOLOGY" and f.severity.value in ("HIGH", "CRITICAL") for f in findings_list) else 80.0,
        "THIRD_PARTY": 100.0 if not any(f.category == "THIRD_PARTY" and f.severity.value in ("HIGH", "CRITICAL") for f in findings_list) else 75.0,
        # 10 Futuristic Engines
        "LOAF_INP": (audit.raw_results or {}).get("LOAF_INP", {}).get("score") if (audit.raw_results or {}).get("LOAF_INP", {}).get("score") is not None else (100.0 if not any(f.category == "LOAF_INP" and f.severity.value in ("HIGH", "CRITICAL") for f in findings_list) else 75.0),
        "SECURITY_MAGECART": (audit.raw_results or {}).get("SECURITY_MAGECART", {}).get("score") if (audit.raw_results or {}).get("SECURITY_MAGECART", {}).get("score") is not None else (100.0 if not any(f.category == "SECURITY_MAGECART" and f.severity.value in ("HIGH", "CRITICAL") for f in findings_list) else 65.0),
        "CARBON_ESG": (audit.raw_results or {}).get("CARBON_ESG", {}).get("score") if (audit.raw_results or {}).get("CARBON_ESG", {}).get("score") is not None else (90.0 if not any(f.category == "CARBON_ESG" and f.severity.value in ("HIGH", "CRITICAL") for f in findings_list) else 60.0),
        "SECRET_HARVESTER": (audit.raw_results or {}).get("SECRET_HARVESTER", {}).get("score") if (audit.raw_results or {}).get("SECRET_HARVESTER", {}).get("score") is not None else (100.0 if not any(f.category == "SECRET_HARVESTER" and f.severity.value in ("HIGH", "CRITICAL") for f in findings_list) else 50.0),
        "POST_QUANTUM_DNSSEC": (audit.raw_results or {}).get("POST_QUANTUM_DNSSEC", {}).get("score") if (audit.raw_results or {}).get("POST_QUANTUM_DNSSEC", {}).get("score") is not None else (100.0 if not any(f.category == "POST_QUANTUM_DNSSEC" and f.severity.value in ("HIGH", "CRITICAL") for f in findings_list) else 70.0),
        "GEO_AI": (audit.raw_results or {}).get("GEO_AI", {}).get("score") if (audit.raw_results or {}).get("GEO_AI", {}).get("score") is not None else (95.0 if not any(f.category == "GEO_AI" and f.severity.value in ("HIGH", "CRITICAL") for f in findings_list) else 70.0),
        "ZERO_TRUST_PRIVACY": (audit.raw_results or {}).get("ZERO_TRUST_PRIVACY", {}).get("score") if (audit.raw_results or {}).get("ZERO_TRUST_PRIVACY", {}).get("score") is not None else (100.0 if not any(f.category == "ZERO_TRUST_PRIVACY" and f.severity.value in ("HIGH", "CRITICAL") for f in findings_list) else 65.0),
        "LAYOUT_DEFECTS": (audit.raw_results or {}).get("LAYOUT_DEFECTS", {}).get("score") if (audit.raw_results or {}).get("LAYOUT_DEFECTS", {}).get("score") is not None else (100.0 if not any(f.category == "LAYOUT_DEFECTS" and f.severity.value in ("HIGH", "CRITICAL") for f in findings_list) else 75.0),
        "USER_JOURNEY": (audit.raw_results or {}).get("USER_JOURNEY", {}).get("score") if (audit.raw_results or {}).get("USER_JOURNEY", {}).get("score") is not None else (100.0 if not any(f.category == "USER_JOURNEY" and f.severity.value in ("HIGH", "CRITICAL") for f in findings_list) else 70.0),
        "CODE_REMEDIATION": (audit.raw_results or {}).get("CODE_REMEDIATION", {}).get("score") if (audit.raw_results or {}).get("CODE_REMEDIATION", {}).get("score") is not None else 95.0,
    }

    audit_resp = AuditResponse.model_validate(audit)
    if audit_resp.score_performance is None:
        audit_resp.score_performance = perf_score
    if audit_resp.score_seo is None:
        audit_resp.score_seo = seo_score
    if audit_resp.score_accessibility is None:
        audit_resp.score_accessibility = a11y_score
    if audit_resp.score_security is None:
        audit_resp.score_security = sec_score
    if audit_resp.score_technical is None:
        audit_resp.score_technical = tech_score

    return AuditDetailResponse(
        **audit_resp.model_dump(),
        raw_results=audit.raw_results or {},
        findings=[FindingResponse.model_validate(f) for f in findings_list],
        pages=[AuditPageResponse.model_validate(p) for p in (audit.pages or [])],
        category_scores=category_scores
    )


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

