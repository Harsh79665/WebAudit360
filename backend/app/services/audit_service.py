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
    DomainAuthorization,
    FindingHistory,
    FindingSeverity,
    FindingStatus,
    Project,
    VerificationStatus,
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
from backend.app.engines.visual.engine import VisualRegressionEngine
from backend.app.engines.loaf.engine import LoAFEngine
from backend.app.engines.magecart.engine import MagecartEngine
from backend.app.engines.carbon.engine import CarbonEngine
from backend.app.engines.secrets.engine import SecretsHarvesterEngine
from backend.app.engines.post_quantum.engine import PostQuantumDNSSECEngine
from backend.app.engines.geo.engine import GEOEngine
from backend.app.engines.privacy.engine import ZeroTrustPrivacyEngine
from backend.app.engines.layout_defects.engine import LayoutDefectsEngine
from backend.app.engines.user_journey.engine import SyntheticUserJourneyEngine
from backend.app.engines.remediation.engine import CodeRemediationEngine
from backend.app.scoring.calculator import calculate_overall_score


# Active WebSocket subscriber queues keyed by audit_id
AUDIT_EVENT_SUBSCRIBERS: Dict[int, List[asyncio.Queue]] = {}
AUDIT_EVENT_HISTORY: Dict[int, List[Dict[str, Any]]] = {}


async def broadcast_audit_event(audit_id: int, event: Dict[str, Any]):
    """Broadcasts a live scan lifecycle event to all connected WebSocket clients and buffers history."""
    if audit_id not in AUDIT_EVENT_HISTORY:
        AUDIT_EVENT_HISTORY[audit_id] = []
    AUDIT_EVENT_HISTORY[audit_id].append(event)

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
            "percent": 10,
            "message": "Sandbox initialized. Validating SSRF defenses and resolving target...",
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

        target_url = audit.target_url
        selected_modules = audit.selected_modules or [
            "PERFORMANCE", "SEO", "ACCESSIBILITY", "SECURITY_PASSIVE",
            "RESPONSIVE", "TECHNICAL_HEALTH", "TECHNOLOGY", "THIRD_PARTY",
            "VISUAL"
        ]

        t_start = time.time()
        score_perf = None
        score_seo = None
        score_a11y = None
        score_sec = None
        score_tech = None

        raw_results = {}

        try:
            # Step A: Crawler Engine (Base Discovery & Page Hierarchy)
            crawler = CrawlerEngine()
            await broadcast_audit_event(audit_id, {
                "type": "module_started",
                "module": "CRAWLER",
                "percent": 12,
                "message": "Crawler engine active. Discovering internal page hierarchy..."
            })
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

            AuditService._persist_findings(session, audit_id, primary_page_id, crawl_res.findings)

            await broadcast_audit_event(audit_id, {
                "type": "crawler_progress",
                "discovered": audit.pages_discovered,
                "scanned": audit.pages_scanned,
                "current_page": target_url,
                "percent": 20,
                "message": f"Crawled {audit.pages_scanned} pages successfully."
            })

            # Define ordered intelligence modules
            ordered_modules = [
                ("SEO", "SEO Intelligence & Meta", SEOEngine),
                ("SECURITY_PASSIVE", "Passive Security & TLS Posture", PassiveSecurityEngine),
                ("SECURITY_ACTIVE", "Active Security & Vulnerability Probes", AuthorizedActiveSecurityEngine),
                ("PERFORMANCE", "Core Web Vitals & Performance", PerformanceEngine),
                ("ACCESSIBILITY", "axe-core Accessibility (WCAG 2.1/2.2 AA)", AccessibilityEngine),
                ("RESPONSIVE", "Responsive Viewports & Overflow", ResponsiveEngine),
                ("VISUAL", "Visual Regression & Layout Stability", VisualRegressionEngine),
                ("TECHNICAL_HEALTH", "Technical Health & Diagnostics", None),
                ("TECHNOLOGY", "Technology Stack Detection", TechnologyEngine),
                ("THIRD_PARTY", "Third-Party Assets & Impact", ThirdPartyEngine),
                ("LOAF_INP", "LoAF & INP Script Attributor", LoAFEngine),
                ("SECURITY_MAGECART", "Magecart & Exfiltration Sandbox", MagecartEngine),
                ("CARBON_ESG", "Digital Carbon Footprint & Scope 3 ESG", CarbonEngine),
                ("SECRET_HARVESTER", "Client Secret & Sourcemap Harvester", SecretsHarvesterEngine),
                ("POST_QUANTUM_DNSSEC", "Post-Quantum Cryptography & DNSSEC Radar", PostQuantumDNSSECEngine),
                ("GEO_AI", "Generative Engine Optimization (GEO)", GEOEngine),
                ("ZERO_TRUST_PRIVACY", "Zero-Trust Privacy & Consent Evasion", ZeroTrustPrivacyEngine),
                ("LAYOUT_DEFECTS", "AI Visual Semantic Layout Defect Detection", LayoutDefectsEngine),
                ("USER_JOURNEY", "Synthetic Multi-Step User Journey Validator", SyntheticUserJourneyEngine),
                ("CODE_REMEDIATION", "1-Click AST Code Remediation Generator", CodeRemediationEngine),
            ]

            active_modules = [
                m for m in ordered_modules
                if m[0] in selected_modules or (m[0] in ("SECURITY_PASSIVE", "SECURITY_ACTIVE") and "SECURITY" in selected_modules)
            ]

            total_mods = max(1, len(active_modules))
            span = 70.0 / total_mods
            all_job_findings: List[Any] = list(crawl_res.findings)

            for idx, (mod_key, display_name, EngineCls) in enumerate(active_modules):
                start_pct = int(20 + idx * span)
                end_pct = int(20 + (idx + 1) * span)

                await broadcast_audit_event(audit_id, {
                    "type": "module_started",
                    "module": mod_key,
                    "percent": start_pct,
                    "message": f"Executing {display_name}..."
                })

                mod_score = None
                try:
                    if mod_key == "SEO":
                        seo_engine = SEOEngine()
                        seo_res = await seo_engine.execute(target_url, {})
                        score_seo = seo_res.score
                        raw_results["SEO"] = seo_res.raw_evidence
                        AuditService._persist_findings(session, audit_id, primary_page_id, seo_res.findings)
                        mod_score = score_seo

                    elif mod_key in ("SECURITY_PASSIVE", "SECURITY"):
                        sec_engine = PassiveSecurityEngine()
                        sec_res = await sec_engine.execute(target_url, {})
                        score_sec = sec_res.score
                        raw_results["SECURITY_PASSIVE"] = sec_res.raw_evidence
                        AuditService._persist_findings(session, audit_id, primary_page_id, sec_res.findings)
                        mod_score = score_sec

                    elif mod_key == "SECURITY_ACTIVE":
                        _, hostname, _ = validate_target_url(target_url)

                        # Check if target domain has verified ownership authorization
                        # Scoped strictly to audit.project_id or projects owned by audit.user_id
                        auth_rec: Optional[DomainAuthorization] = None

                        if audit.project_id:
                            # 1. Project-scoped check
                            auth_stmt = select(DomainAuthorization).where(
                                DomainAuthorization.project_id == audit.project_id,
                                DomainAuthorization.domain == hostname,
                                DomainAuthorization.status == VerificationStatus.VERIFIED
                            )
                            auth_res = await session.execute(auth_stmt)
                            auth_rec = auth_res.scalars().first()

                        if not auth_rec and audit.user_id:
                            # 2. Creator-scoped check (projects owned by audit creator)
                            auth_stmt_user = (
                                select(DomainAuthorization)
                                .join(Project, DomainAuthorization.project_id == Project.id)
                                .where(
                                    Project.owner_id == audit.user_id,
                                    DomainAuthorization.domain == hostname,
                                    DomainAuthorization.status == VerificationStatus.VERIFIED
                                )
                            )
                            auth_res_user = await session.execute(auth_stmt_user)
                            auth_rec = auth_res_user.scalars().first()

                        # Validate expiration timestamp if a verified record was found
                        is_verified = False
                        auth_id = None
                        if auth_rec:
                            now_utc = datetime.now(timezone.utc)
                            exp = auth_rec.expires_at
                            if exp is not None:
                                if exp.tzinfo is None:
                                    exp = exp.replace(tzinfo=timezone.utc)
                                if exp <= now_utc:
                                    logger.warning(
                                        f"Domain authorization #{auth_rec.id} for '{hostname}' has expired at {exp}."
                                    )
                                    auth_rec.status = VerificationStatus.EXPIRED
                                    await session.flush()
                                    is_verified = False
                                    auth_id = None
                                else:
                                    is_verified = True
                                    auth_id = auth_rec.id
                            else:
                                is_verified = True
                                auth_id = auth_rec.id

                        active_sec_engine = AuthorizedActiveSecurityEngine()
                        active_res = await active_sec_engine.execute(
                            target_url,
                            {
                                "is_verified_authorized": is_verified,
                                "authorization_record_id": auth_id
                            }
                        )
                        raw_results["SECURITY_ACTIVE"] = active_res.raw_evidence
                        AuditService._persist_findings(session, audit_id, primary_page_id, active_res.findings)
                        mod_score = active_res.score

                        # If active security is authorized and produces a valid score, update/combine security score
                        if active_res.score is not None:
                            if score_sec is not None:
                                score_sec = round((score_sec + active_res.score) / 2.0, 1)
                            else:
                                score_sec = active_res.score

                    elif mod_key == "PERFORMANCE":
                        perf_engine = PerformanceEngine()
                        perf_res = await perf_engine.execute(target_url, {"device_profile": audit.device_profile.value})
                        score_perf = perf_res.score
                        raw_results["PERFORMANCE"] = perf_res.raw_evidence
                        AuditService._persist_findings(session, audit_id, primary_page_id, perf_res.findings)
                        mod_score = score_perf

                    elif mod_key == "ACCESSIBILITY":
                        a11y_engine = AccessibilityEngine()
                        a11y_res = await a11y_engine.execute(target_url, {})
                        score_a11y = a11y_res.score
                        raw_results["ACCESSIBILITY"] = a11y_res.raw_evidence
                        AuditService._persist_findings(session, audit_id, primary_page_id, a11y_res.findings)
                        mod_score = score_a11y

                    elif mod_key == "RESPONSIVE":
                        resp_engine = ResponsiveEngine()
                        resp_res = await resp_engine.execute(target_url, {})
                        raw_results["RESPONSIVE"] = resp_res.raw_evidence
                        AuditService._persist_findings(session, audit_id, primary_page_id, resp_res.findings)
                        mod_score = resp_res.score

                    elif mod_key == "VISUAL":
                        vis_engine = VisualRegressionEngine()
                        vis_res = await vis_engine.execute(
                            target_url,
                            {
                                "audit_id": audit_id,
                                "project_id": audit.project_id,
                                "device_profile": audit.device_profile.value if hasattr(audit.device_profile, "value") else str(audit.device_profile),
                                "session": session,
                            }
                        )
                        raw_results["VISUAL"] = vis_res.raw_evidence
                        AuditService._persist_findings(session, audit_id, primary_page_id, vis_res.findings)
                        mod_score = vis_res.score

                    elif mod_key == "TECHNICAL_HEALTH":
                        score_tech = score_tech or 100.0
                        mod_score = score_tech

                    elif mod_key == "TECHNOLOGY":
                        tech_engine = TechnologyEngine()
                        tech_res = await tech_engine.execute(target_url, {})
                        raw_results["TECHNOLOGY"] = tech_res.raw_evidence
                        AuditService._persist_findings(session, audit_id, primary_page_id, tech_res.findings)
                        mod_score = tech_res.score

                    elif mod_key == "THIRD_PARTY":
                        tp_engine = ThirdPartyEngine()
                        tp_res = await tp_engine.execute(target_url, {})
                        raw_results["THIRD_PARTY"] = tp_res.raw_evidence
                        AuditService._persist_findings(session, audit_id, primary_page_id, tp_res.findings)
                        mod_score = tp_res.score

                    elif mod_key == "LOAF_INP":
                        loaf_engine = LoAFEngine()
                        loaf_res = await loaf_engine.execute(target_url, {})
                        raw_results["LOAF_INP"] = loaf_res.raw_evidence
                        AuditService._persist_findings(session, audit_id, primary_page_id, loaf_res.findings)
                        mod_score = loaf_res.score

                    elif mod_key == "SECURITY_MAGECART":
                        magecart_engine = MagecartEngine()
                        magecart_res = await magecart_engine.execute(target_url, {})
                        raw_results["SECURITY_MAGECART"] = magecart_res.raw_evidence
                        AuditService._persist_findings(session, audit_id, primary_page_id, magecart_res.findings)
                        mod_score = magecart_res.score

                    elif mod_key == "CARBON_ESG":
                        carbon_engine = CarbonEngine()
                        carbon_res = await carbon_engine.execute(target_url, {})
                        raw_results["CARBON_ESG"] = carbon_res.raw_evidence
                        AuditService._persist_findings(session, audit_id, primary_page_id, carbon_res.findings)
                        mod_score = carbon_res.score

                    elif mod_key == "SECRET_HARVESTER":
                        secret_engine = SecretsHarvesterEngine()
                        secret_res = await secret_engine.execute(target_url, {})
                        raw_results["SECRET_HARVESTER"] = secret_res.raw_evidence
                        AuditService._persist_findings(session, audit_id, primary_page_id, secret_res.findings)
                        mod_score = secret_res.score

                    elif mod_key == "POST_QUANTUM_DNSSEC":
                        pq_engine = PostQuantumDNSSECEngine()
                        pq_res = await pq_engine.execute(target_url, {})
                        raw_results["POST_QUANTUM_DNSSEC"] = pq_res.raw_evidence
                        AuditService._persist_findings(session, audit_id, primary_page_id, pq_res.findings)
                        all_job_findings.extend(pq_res.findings)
                        mod_score = pq_res.score

                    elif mod_key == "GEO_AI":
                        geo_engine = GEOEngine()
                        geo_res = await geo_engine.execute(target_url, {})
                        raw_results["GEO_AI"] = geo_res.raw_evidence
                        AuditService._persist_findings(session, audit_id, primary_page_id, geo_res.findings)
                        all_job_findings.extend(geo_res.findings)
                        mod_score = geo_res.score

                    elif mod_key == "ZERO_TRUST_PRIVACY":
                        priv_engine = ZeroTrustPrivacyEngine()
                        priv_res = await priv_engine.execute(target_url, {})
                        raw_results["ZERO_TRUST_PRIVACY"] = priv_res.raw_evidence
                        AuditService._persist_findings(session, audit_id, primary_page_id, priv_res.findings)
                        all_job_findings.extend(priv_res.findings)
                        mod_score = priv_res.score

                    elif mod_key == "LAYOUT_DEFECTS":
                        layout_engine = LayoutDefectsEngine()
                        layout_res = await layout_engine.execute(target_url, {})
                        raw_results["LAYOUT_DEFECTS"] = layout_res.raw_evidence
                        AuditService._persist_findings(session, audit_id, primary_page_id, layout_res.findings)
                        all_job_findings.extend(layout_res.findings)
                        mod_score = layout_res.score

                    elif mod_key == "USER_JOURNEY":
                        journey_engine = SyntheticUserJourneyEngine()
                        journey_res = await journey_engine.execute(target_url, {})
                        raw_results["USER_JOURNEY"] = journey_res.raw_evidence
                        AuditService._persist_findings(session, audit_id, primary_page_id, journey_res.findings)
                        all_job_findings.extend(journey_res.findings)
                        mod_score = journey_res.score

                    elif mod_key == "CODE_REMEDIATION":
                        remed_engine = CodeRemediationEngine()
                        remed_res = await remed_engine.execute(target_url, {}, all_findings=all_job_findings)
                        raw_results["CODE_REMEDIATION"] = remed_res.raw_evidence
                        AuditService._persist_findings(session, audit_id, primary_page_id, remed_res.findings)
                        all_job_findings.extend(remed_res.findings)
                        mod_score = remed_res.score

                except Exception as mod_err:
                    logger.error(f"Module {mod_key} non-fatal error: {mod_err}")
                    mod_score = None

                await broadcast_audit_event(audit_id, {
                    "type": "module_completed",
                    "module": mod_key,
                    "score": mod_score,
                    "percent": end_pct,
                    "message": f"{display_name} complete (Score: {round(mod_score, 1) if mod_score is not None else 'N/A'})."
                })

            # Step: Domain Health
            await broadcast_audit_event(audit_id, {
                "type": "progress_update",
                "percent": 92,
                "message": "Inspecting domain health, DNS routing records, and SSL certificate..."
            })
            try:
                domain_engine = DomainEngine()
                domain_res = await domain_engine.execute(target_url, {})
                raw_results["DOMAIN"] = domain_res.raw_evidence
                AuditService._persist_findings(session, audit_id, primary_page_id, domain_res.findings)
            except Exception as dom_err:
                logger.warning(f"Domain engine non-fatal error: {dom_err}")

            await broadcast_audit_event(audit_id, {
                "type": "progress_update",
                "percent": 96,
                "message": "Synthesizing transparent v1.0.0 score matrix across all measured modules..."
            })

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
                "percent": 100,
                "overall_score": overall_score,
                "execution_time_ms": audit.execution_time_ms,
                "message": f"Audit successfully completed with overall score {round(overall_score, 1)}/100."
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

