"""WebAudit 360 — Audit Orchestration Service
Author: Harsh Patel

Coordinates engine execution, real-time WebSocket event dispatching,
score calculation, and atomic database persistence.
"""

import asyncio
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.logging import logger
from backend.app.core.ssrf import validate_target_url
from backend.app.models.entities import (
    Audit,
    AuditFinding,
    AuditPage,
    AuditStatus,
    FindingHistory,
    FindingSeverity,
    FindingStatus,
)
from backend.app.engines.crawler.engine import CrawlerEngine
from backend.app.engines.performance.engine import PerformanceEngine
from backend.app.engines.seo.engine import SEOEngine
from backend.app.engines.accessibility.engine import AccessibilityEngine
from backend.app.engines.security.passive import PassiveSecurityEngine
from backend.app.engines.security.active import AuthorizedActiveSecurityEngine
from backend.app.engines.responsive.engine import ResponsiveEngine
from backend.app.engines.technology.engine import TechnologyEngine
from backend.app.engines.third_party.engine import ThirdPartyEngine
from backend.app.engines.domain.engine import DomainEngine
from backend.app.scoring.calculator import calculate_overall_score


# Active WebSocket subscriber queues keyed by audit_id
AUDIT_EVENT_SUBSCRIBERS: Dict[int, List[asyncio.Queue]] = {}


async def broadcast_audit_event(audit_id: int, event: Dict[str, Any]):
    """Broadcasts a live scan lifecycle event to all connected WebSocket clients."""
    subscribers = AUDIT_EVENT_SUBSCRIBERS.get(audit_id, [])
    for q in subscribers:
        await q.put(event)


class AuditService:
    @staticmethod
    async def run_audit_job(audit_id: int, session: AsyncSession):
        """
        Executes a complete multi-layer audit job.
        Runs selected engines, calculates scores, and persists all traceable findings.
        """
        logger.info(f"Starting audit job #{audit_id}...")

        # 1. Fetch Audit record
        result = await session.execute(select(Audit).where(Audit.id == audit_id))
        audit = result.scalars().first()
        if not audit:
            logger.error(f"Audit #{audit_id} not found in database.")
            return

        audit.status = AuditStatus.RUNNING
        audit.started_at = datetime.now(timezone.utc)
        await session.commit()

        await broadcast_audit_event(audit_id, {
            "type": "audit_started",
            "audit_id": audit_id,
            "target_url": audit.target_url,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

        target_url = audit.target_url
        selected_modules = audit.selected_modules or [
            "PERFORMANCE", "SEO", "ACCESSIBILITY", "SECURITY_PASSIVE",
            "RESPONSIVE", "TECHNICAL_HEALTH", "TECHNOLOGY", "THIRD_PARTY"
        ]

        t_start = time.time()
        score_perf = None
        score_seo = None
        score_a11y = None
        score_sec = None
        score_tech = None

        raw_results = {}

        try:
            # Step A: Crawler Engine
            crawler = CrawlerEngine()
            await broadcast_audit_event(audit_id, {"type": "module_started", "module": "CRAWLER"})
            crawl_res = await crawler.execute(target_url, {
                "scan_mode": audit.scan_mode.value,
                "max_pages": audit.config.get("max_pages", 50),
                "max_depth": audit.config.get("max_depth", 3)
            })
            raw_results["CRAWLER"] = crawl_res.raw_evidence
            score_tech = crawl_res.score

            # Persist discovered pages
            pages = crawl_res.raw_evidence.get("pages", [])
            audit.pages_discovered = len(pages)
            audit.pages_scanned = len([p for p in pages if p.get("status_code", 0) > 0])
            audit.pages_failed = len([p for p in pages if p.get("status_code", 0) >= 400 or p.get("status_code", 0) == 0])

            primary_page_id = None
            for idx, p_info in enumerate(pages):
                page_rec = AuditPage(
                    audit_id=audit_id,
                    url=p_info["url"],
                    path=p_info["url"],
                    status_code=p_info.get("status_code"),
                    crawl_depth=p_info.get("depth", 0),
                    response_time_ms=p_info.get("response_time_ms"),
                    content_type=p_info.get("content_type"),
                    is_orphan=False
                )
                session.add(page_rec)
                await session.flush()
                if idx == 0:
                    primary_page_id = page_rec.id

            await broadcast_audit_event(audit_id, {
                "type": "crawler_progress",
                "discovered": audit.pages_discovered,
                "scanned": audit.pages_scanned,
                "current_page": target_url
            })

            # Step B: SEO Engine
            if "SEO" in selected_modules:
                await broadcast_audit_event(audit_id, {"type": "module_started", "module": "SEO"})
                seo_engine = SEOEngine()
                seo_res = await seo_engine.execute(target_url, {})
                score_seo = seo_res.score
                raw_results["SEO"] = seo_res.raw_evidence
                AuditService._persist_findings(session, audit_id, primary_page_id, seo_res.findings)
                await broadcast_audit_event(audit_id, {"type": "module_completed", "module": "SEO", "score": score_seo})

            # Step C: Passive Security Engine
            if "SECURITY_PASSIVE" in selected_modules or "SECURITY" in selected_modules:
                await broadcast_audit_event(audit_id, {"type": "module_started", "module": "SECURITY_PASSIVE"})
                sec_engine = PassiveSecurityEngine()
                sec_res = await sec_engine.execute(target_url, {})
                score_sec = sec_res.score
                raw_results["SECURITY_PASSIVE"] = sec_res.raw_evidence
                AuditService._persist_findings(session, audit_id, primary_page_id, sec_res.findings)
                await broadcast_audit_event(audit_id, {"type": "module_completed", "module": "SECURITY_PASSIVE", "score": score_sec})

            # Step D: Performance Engine (Lighthouse & Playwright)
            if "PERFORMANCE" in selected_modules:
                await broadcast_audit_event(audit_id, {"type": "module_started", "module": "PERFORMANCE"})
                perf_engine = PerformanceEngine()
                perf_res = await perf_engine.execute(target_url, {"device_profile": audit.device_profile.value})
                score_perf = perf_res.score
                raw_results["PERFORMANCE"] = perf_res.raw_evidence
                AuditService._persist_findings(session, audit_id, primary_page_id, perf_res.findings)
                await broadcast_audit_event(audit_id, {"type": "module_completed", "module": "PERFORMANCE", "score": score_perf})

            # Step E: Accessibility Engine (axe-core via Playwright)
            if "ACCESSIBILITY" in selected_modules:
                await broadcast_audit_event(audit_id, {"type": "module_started", "module": "ACCESSIBILITY"})
                a11y_engine = AccessibilityEngine()
                a11y_res = await a11y_engine.execute(target_url, {})
                score_a11y = a11y_res.score
                raw_results["ACCESSIBILITY"] = a11y_res.raw_evidence
                AuditService._persist_findings(session, audit_id, primary_page_id, a11y_res.findings)
                await broadcast_audit_event(audit_id, {"type": "module_completed", "module": "ACCESSIBILITY", "score": score_a11y})

            # Step F: Responsive Engine
            if "RESPONSIVE" in selected_modules:
                resp_engine = ResponsiveEngine()
                resp_res = await resp_engine.execute(target_url, {})
                raw_results["RESPONSIVE"] = resp_res.raw_evidence
                AuditService._persist_findings(session, audit_id, primary_page_id, resp_res.findings)

            # Step G: Technology Engine
            if "TECHNOLOGY" in selected_modules:
                tech_engine = TechnologyEngine()
                tech_res = await tech_engine.execute(target_url, {})
                raw_results["TECHNOLOGY"] = tech_res.raw_evidence
                AuditService._persist_findings(session, audit_id, primary_page_id, tech_res.findings)

            # Step H: Third-Party Dependencies
            if "THIRD_PARTY" in selected_modules:
                tp_engine = ThirdPartyEngine()
                tp_res = await tp_engine.execute(target_url, {})
                raw_results["THIRD_PARTY"] = tp_res.raw_evidence
                AuditService._persist_findings(session, audit_id, primary_page_id, tp_res.findings)

            # Step I: Domain Health
            domain_engine = DomainEngine()
            domain_res = await domain_engine.execute(target_url, {})
            raw_results["DOMAIN"] = domain_res.raw_evidence
            AuditService._persist_findings(session, audit_id, primary_page_id, domain_res.findings)

            # Calculate Overall Score using transparent versioned algorithm
            overall_score, scoring_meta = calculate_overall_score(
                score_perf=score_perf,
                score_seo=score_seo,
                score_a11y=score_a11y,
                score_sec=score_sec,
                score_tech=score_tech
            )

            audit.overall_score = overall_score
            audit.score_performance = score_perf
            audit.score_seo = score_seo
            audit.score_accessibility = score_a11y
            audit.score_security = score_sec
            audit.score_technical = score_tech
            audit.raw_results = raw_results
            audit.execution_time_ms = int((time.time() - t_start) * 1000)
            audit.completed_at = datetime.now(timezone.utc)
            audit.status = AuditStatus.COMPLETED

            await session.commit()

            await broadcast_audit_event(audit_id, {
                "type": "audit_completed",
                "audit_id": audit_id,
                "overall_score": overall_score,
                "execution_time_ms": audit.execution_time_ms
            })
            logger.info(f"Audit #{audit_id} completed successfully with score {overall_score}.")

        except Exception as e:
            logger.error(f"Audit #{audit_id} failed with unhandled exception: {e}", exc_info=True)
            audit.status = AuditStatus.FAILED
            await session.commit()
            await broadcast_audit_event(audit_id, {
                "type": "audit_failed",
                "audit_id": audit_id,
                "error": str(e)
            })

    @staticmethod
    def _persist_findings(session: AsyncSession, audit_id: int, page_id: Optional[int], findings: List[Any]):
        """Persists findings generated by audit engines."""
        for f in findings:
            finding_rec = AuditFinding(
                audit_id=audit_id,
                page_id=page_id,
                category=f.category.value if hasattr(f.category, "value") else str(f.category),
                rule_id=f.rule_id,
                severity=FindingSeverity[f.severity.upper()] if f.severity.upper() in FindingSeverity.__members__ else FindingSeverity.INFO,
                confidence=f.confidence,
                title=f.title,
                description=f.description,
                recommendation=f.recommendation,
                selector=f.selector,
                evidence_snippet=f.evidence_snippet,
                raw_details=f.raw_details,
                status=FindingStatus.OPEN
            )
            session.add(finding_rec)
