"""WebAudit 360 — Reports & Export API Routes
Author: Harsh Patel
"""

from typing import Any, Dict
from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.database import get_db
from backend.app.models.entities import Audit, AuditFinding
from backend.app.schemas import FindingResponse
from backend.app.scoring.calculator import get_score_label

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("/{audit_id}/json")
async def get_audit_report_json(audit_id: int, session: AsyncSession = Depends(get_db)) -> Dict[str, Any]:
    """Generates an exhaustive, machine-readable JSON report of all audit measurements and findings."""
    result = await session.execute(select(Audit).where(Audit.id == audit_id))
    audit = result.scalars().first()
    if not audit:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found.")

    findings_res = await session.execute(select(AuditFinding).where(AuditFinding.audit_id == audit_id))
    findings = findings_res.scalars().all()

    return {
        "report_metadata": {
            "platform": "WebAudit 360",
            "version": "1.0.0",
            "creator": "Harsh Patel",
            "scoring_version": audit.scoring_version,
            "audit_id": audit.id,
            "generated_at": audit.completed_at.isoformat() if audit.completed_at else None
        },
        "target": {
            "url": audit.target_url,
            "scan_mode": audit.scan_mode.value,
            "device_profile": audit.device_profile.value
        },
        "scores": {
            "overall": audit.overall_score,
            "overall_label": get_score_label(audit.overall_score),
            "performance": audit.score_performance,
            "seo": audit.score_seo,
            "accessibility": audit.score_accessibility,
            "security": audit.score_security,
            "technical": audit.score_technical
        },
        "crawl_coverage": {
            "discovered": audit.pages_discovered,
            "scanned": audit.pages_scanned,
            "failed": audit.pages_failed,
            "execution_time_ms": audit.execution_time_ms
        },
        "findings": [FindingResponse.model_validate(f).model_dump() for f in findings],
        "raw_evidence": audit.raw_results
    }


from backend.app.services.pdf_service import PDFReportService, generate_report_html


@router.get("/{audit_id}/pdf")
async def get_audit_report_pdf(audit_id: int, session: AsyncSession = Depends(get_db)):
    """Generates and streams a publication-grade binary PDF report for the audit."""
    try:
        pdf_bytes = await PDFReportService.render_audit_pdf(audit_id, session)
        headers = {
            "Content-Disposition": f'attachment; filename="webaudit360_report_{audit_id}.pdf"'
        }
        return Response(content=pdf_bytes, media_type="application/pdf", headers=headers)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found.")


@router.get("/{audit_id}/html", response_class=HTMLResponse)
async def get_audit_report_html(audit_id: int, session: AsyncSession = Depends(get_db)):
    """Renders printable HTML view of the audit report."""
    result = await session.execute(select(Audit).where(Audit.id == audit_id))
    audit = result.scalars().first()
    if not audit:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found.")

    findings_res = await session.execute(select(AuditFinding).where(AuditFinding.audit_id == audit_id))
    findings = findings_res.scalars().all()
    return HTMLResponse(content=generate_report_html(audit, findings))

