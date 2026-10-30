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


@router.get("/{audit_id}/pdf")
async def get_audit_report_pdf(audit_id: int, session: AsyncSession = Depends(get_db)):
    """Generates a publication-grade HTML printable report for the audit."""
    result = await session.execute(select(Audit).where(Audit.id == audit_id))
    audit = result.scalars().first()
    if not audit:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found.")

    findings_res = await session.execute(select(AuditFinding).where(AuditFinding.audit_id == audit_id))
    findings = findings_res.scalars().all()

    overall_label = get_score_label(audit.overall_score)

    html_content = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Audit Report — {audit.target_url} — WebAudit 360</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 40px; color: #0f172a; line-height: 1.5; }}
    .header {{ border-bottom: 2px solid #2563eb; padding-bottom: 20px; margin-bottom: 30px; }}
    .brand {{ font-size: 24px; font-weight: 800; color: #2563eb; }}
    .title {{ font-size: 28px; font-weight: 800; margin: 10px 0; }}
    .scores-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin: 30px 0; text-align: center; }}
    .score-card {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 15px; }}
    .score-val {{ font-size: 32px; font-weight: 800; color: #2563eb; }}
    .finding-card {{ border: 1px solid #e2e8f0; border-left: 4px solid #f59e0b; border-radius: 6px; padding: 15px; margin-bottom: 15px; }}
    .finding-title {{ font-weight: 700; font-size: 16px; margin-bottom: 5px; }}
    .footer {{ margin-top: 50px; font-size: 12px; color: #64748b; border-top: 1px solid #e2e8f0; padding-top: 15px; text-align: center; }}
  </style>
</head>
<body>
  <div class="header">
    <div class="brand">WebAudit 360</div>
    <div class="title">Website Intelligence Audit Report</div>
    <div>Target: <strong>{audit.target_url}</strong> &bull; Scanned: {audit.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
  </div>

  <h2>Overall Health Rating: {round(audit.overall_score or 0)} / 100 ({overall_label})</h2>
  <div class="scores-grid">
    <div class="score-card"><div class="score-val">{round(audit.score_performance or 0)}</div><div>Performance</div></div>
    <div class="score-card"><div class="score-val">{round(audit.score_seo or 0)}</div><div>SEO</div></div>
    <div class="score-card"><div class="score-val">{round(audit.score_accessibility or 0)}</div><div>Accessibility</div></div>
    <div class="score-card"><div class="score-val">{round(audit.score_security or 0)}</div><div>Security</div></div>
    <div class="score-card"><div class="score-val">{round(audit.score_technical or 0)}</div><div>Best Practices</div></div>
  </div>

  <h3>Actionable Technical Findings ({len(findings)})</h3>
  {''.join([f'''
    <div class="finding-card">
      <div class="finding-title">{f.title} <span style="font-size: 12px; color: #dc2626;">[{f.severity.value}]</span></div>
      <div>{f.description}</div>
      {f'<div style="margin-top: 8px; font-weight: 600; color: #2563eb;">Fix: {f.recommendation}</div>' if f.recommendation else ''}
    </div>
  ''' for f in findings])}

  <div class="footer">
    &copy; 2026 WebAudit 360 &bull; Platform Created by Harsh Patel. Traceable Evidence & No-Fake-Data Policy Enforced.
  </div>
</body>
</html>
"""

    return HTMLResponse(content=html_content)

