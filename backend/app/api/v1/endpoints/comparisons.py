"""WebAudit 360 — Competitor URL Comparison API Routes
Author: Harsh Patel

Provides side-by-side URL benchmarking, category delta calculations,
Core Web Vitals comparisons, and automated competitive insights.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.app.core.database import get_db
from backend.app.core.ssrf import validate_target_url, SSRFValidationError
from backend.app.models.entities import Audit, DeviceProfile, ScanMode, User
from backend.app.api.v1.dependencies import get_current_user_optional
from backend.app.engines.performance.engine import PerformanceEngine
from backend.app.engines.seo.engine import SEOEngine
from backend.app.engines.accessibility.engine import AccessibilityEngine
from backend.app.engines.security.passive import PassiveSecurityEngine
from backend.app.engines.technology.engine import TechnologyEngine
from backend.app.engines.carbon.engine import CarbonEngine
from backend.app.scoring.calculator import calculate_overall_score, get_score_label

router = APIRouter(prefix="/comparisons", tags=["Competitor Comparison"])


class CompetitorComparisonRequest(BaseModel):
    target_url_a: str = Field(..., description="Primary website URL to benchmark")
    target_url_b: str = Field(..., description="Competitor website URL to compare against")
    device_profile: DeviceProfile = DeviceProfile.BOTH
    scan_mode: ScanMode = ScanMode.SINGLE_PAGE
    modules: List[str] = Field(default_factory=lambda: ["PERFORMANCE", "SEO", "ACCESSIBILITY", "SECURITY_PASSIVE", "CARBON_ESG"])


class ScoreBreakdown(BaseModel):
    overall: Optional[float] = None
    overall_label: str = "N/A"
    performance: Optional[float] = None
    seo: Optional[float] = None
    accessibility: Optional[float] = None
    security: Optional[float] = None
    technical: Optional[float] = None
    carbon: Optional[float] = None


class CompetitorComparisonResponse(BaseModel):
    target_url_a: str
    target_url_b: str
    scores_a: ScoreBreakdown
    scores_b: ScoreBreakdown
    deltas: Dict[str, float] = Field(..., description="Positive indicates Site A leads; Negative indicates Site B leads")
    web_vitals_comparison: Dict[str, Any]
    technology_comparison: Dict[str, Any]
    insights: List[str]
    winner: str


@router.post("", response_model=CompetitorComparisonResponse)
async def compare_urls(
    payload: CompetitorComparisonRequest,
    current_user: Optional[User] = Depends(get_current_user_optional),
    session: AsyncSession = Depends(get_db)
):
    """
    Executes a side-by-side comparative audit between two target URLs,
    computing granular category score deltas, CWV metrics, and competitive advantages.
    """
    # 1. SSRF Validation for both URLs
    try:
        norm_a, host_a, _ = validate_target_url(payload.target_url_a)
        norm_b, host_b, _ = validate_target_url(payload.target_url_b)
    except SSRFValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Comparison target failed SSRF validation: {str(e)}"
        )

    # 2. Run benchmark engines for both targets
    perf_engine = PerformanceEngine()
    seo_engine = SEOEngine()
    a11y_engine = AccessibilityEngine()
    sec_engine = PassiveSecurityEngine()
    tech_engine = TechnologyEngine()
    carbon_engine = CarbonEngine()

    try:
        # Site A execution
        res_perf_a = await perf_engine.execute(norm_a, {})
        res_seo_a = await seo_engine.execute(norm_a, {})
        res_a11y_a = await a11y_engine.execute(norm_a, {})
        res_sec_a = await sec_engine.execute(norm_a, {})
        res_tech_a = await tech_engine.execute(norm_a, {})
        res_carb_a = await carbon_engine.execute(norm_a, {})

        # Site B execution
        if norm_a == norm_b:
            res_perf_b = res_perf_a
            res_seo_b = res_seo_a
            res_a11y_b = res_a11y_a
            res_sec_b = res_sec_a
            res_tech_b = res_tech_a
            res_carb_b = res_carb_a
        else:
            res_perf_b = await perf_engine.execute(norm_b, {})
            res_seo_b = await seo_engine.execute(norm_b, {})
            res_a11y_b = await a11y_engine.execute(norm_b, {})
            res_sec_b = await sec_engine.execute(norm_b, {})
            res_tech_b = await tech_engine.execute(norm_b, {})
            res_carb_b = await carbon_engine.execute(norm_b, {})
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to benchmark target websites: {str(e)}"
        )

    # 3. Overall scores
    score_ov_a, _ = calculate_overall_score(
        score_perf=res_perf_a.score,
        score_seo=res_seo_a.score,
        score_a11y=res_a11y_a.score,
        score_sec=res_sec_a.score,
        score_tech=res_tech_a.score
    )
    score_ov_b, _ = calculate_overall_score(
        score_perf=res_perf_b.score,
        score_seo=res_seo_b.score,
        score_a11y=res_a11y_b.score,
        score_sec=res_sec_b.score,
        score_tech=res_tech_b.score
    )

    scores_a = ScoreBreakdown(
        overall=score_ov_a,
        overall_label=get_score_label(score_ov_a),
        performance=res_perf_a.score,
        seo=res_seo_a.score,
        accessibility=res_a11y_a.score,
        security=res_sec_a.score,
        technical=res_tech_a.score,
        carbon=res_carb_a.score
    )

    scores_b = ScoreBreakdown(
        overall=score_ov_b,
        overall_label=get_score_label(score_ov_b),
        performance=res_perf_b.score,
        seo=res_seo_b.score,
        accessibility=res_a11y_b.score,
        security=res_sec_b.score,
        technical=res_tech_b.score,
        carbon=res_carb_b.score
    )

    # 4. Deltas: Site A minus Site B
    def calc_delta(val_a: Optional[float], val_b: Optional[float]) -> float:
        if val_a is not None and val_b is not None:
            return round(val_a - val_b, 1)
        return 0.0

    deltas = {
        "overall": calc_delta(scores_a.overall, scores_b.overall),
        "performance": calc_delta(scores_a.performance, scores_b.performance),
        "seo": calc_delta(scores_a.seo, scores_b.seo),
        "accessibility": calc_delta(scores_a.accessibility, scores_b.accessibility),
        "security": calc_delta(scores_a.security, scores_b.security),
        "technical": calc_delta(scores_a.technical, scores_b.technical),
        "carbon": calc_delta(scores_a.carbon, scores_b.carbon),
    }

    # 5. Core Web Vitals Comparison
    cwv_a = res_perf_a.raw_evidence.get("core_web_vitals", {})
    cwv_b = res_perf_b.raw_evidence.get("core_web_vitals", {})

    cwv_comparison = {
        "lcp": {
            "site_a": cwv_a.get("lcp", {}).get("value"),
            "site_b": cwv_b.get("lcp", {}).get("value"),
            "unit": "s",
        },
        "cls": {
            "site_a": cwv_a.get("cls", {}).get("value"),
            "site_b": cwv_b.get("cls", {}).get("value"),
            "unit": "score",
        },
        "fcp": {
            "site_a": cwv_a.get("fcp", {}).get("value"),
            "site_b": cwv_b.get("fcp", {}).get("value"),
            "unit": "s",
        }
    }

    # 6. Technology comparison
    tech_a = res_tech_a.raw_evidence.get("technologies", [])
    tech_b = res_tech_b.raw_evidence.get("technologies", [])
    tech_comparison = {
        "site_a_tech": [t.get("name") for t in tech_a if isinstance(t, dict)],
        "site_b_tech": [t.get("name") for t in tech_b if isinstance(t, dict)],
    }

    # 7. Automated Competitive Insights
    insights = []
    if deltas["overall"] > 0:
        insights.append(f"{host_a} leads overall by +{deltas['overall']} points.")
    elif deltas["overall"] < 0:
        insights.append(f"{host_b} leads overall by +{abs(deltas['overall'])} points.")
    else:
        insights.append(f"{host_a} and {host_b} are currently tied in overall health.")

    if deltas["performance"] > 5:
        insights.append(f"{host_a} demonstrates superior Core Web Vitals and load performance (+{deltas['performance']} pts).")
    elif deltas["performance"] < -5:
        insights.append(f"{host_b} loads faster with superior runtime responsiveness (+{abs(deltas['performance'])} pts).")

    if deltas["security"] > 10:
        insights.append(f"{host_a} enforces significantly stricter TLS and HTTP security headers.")
    elif deltas["security"] < -10:
        insights.append(f"{host_b} has superior security posture; {host_a} is missing key defensive headers.")

    if deltas["carbon"] > 10:
        insights.append(f"{host_a} has a cleaner Scope 3 ESG digital carbon footprint (lighter payload).")

    winner = host_a if (score_ov_a or 0) >= (score_ov_b or 0) else host_b

    return CompetitorComparisonResponse(
        target_url_a=norm_a,
        target_url_b=norm_b,
        scores_a=scores_a,
        scores_b=scores_b,
        deltas=deltas,
        web_vitals_comparison=cwv_comparison,
        technology_comparison=tech_comparison,
        insights=insights,
        winner=winner
    )


@router.get("/diff")
async def diff_stored_audits(
    audit_a_id: int,
    audit_b_id: int,
    session: AsyncSession = Depends(get_db)
):
    """
    Computes delta and comparison metrics between any two existing stored audit records.
    """
    stmt_a = select(Audit).where(Audit.id == audit_a_id)
    stmt_b = select(Audit).where(Audit.id == audit_b_id)

    res_a = (await session.execute(stmt_a)).scalars().first()
    res_b = (await session.execute(stmt_b)).scalars().first()

    if not res_a or not res_b:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="One or both audit IDs were not found."
        )

    delta_overall = round((res_a.overall_score or 0) - (res_b.overall_score or 0), 1)
    return {
        "audit_a": {
            "id": res_a.id,
            "url": res_a.target_url,
            "overall_score": res_a.overall_score,
            "created_at": res_a.created_at.isoformat() if res_a.created_at else None
        },
        "audit_b": {
            "id": res_b.id,
            "url": res_b.target_url,
            "overall_score": res_b.overall_score,
            "created_at": res_b.created_at.isoformat() if res_b.created_at else None
        },
        "deltas": {
            "overall": delta_overall,
            "performance": round((res_a.score_performance or 0) - (res_b.score_performance or 0), 1),
            "seo": round((res_a.score_seo or 0) - (res_b.score_seo or 0), 1),
            "accessibility": round((res_a.score_accessibility or 0) - (res_b.score_accessibility or 0), 1),
            "security": round((res_a.score_security or 0) - (res_b.score_security or 0), 1),
            "technical": round((res_a.score_technical or 0) - (res_b.score_technical or 0), 1),
        }
    }
