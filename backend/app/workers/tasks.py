"""WebAudit 360 — Celery Scan Worker Tasks
Author: Harsh Patel
"""

import asyncio
from backend.app.workers.celery_app import celery_app
from backend.app.core.database import AsyncSessionLocal
from backend.app.core.logging import logger
from backend.app.services.audit_service import AuditService


@celery_app.task(name="tasks.execute_audit_job", bind=True, max_retries=1)
def execute_audit_job(self, audit_id: int):
    """Distributed worker task for executing an audit pipeline."""
    logger.info(f"[Celery Worker] Processing audit job #{audit_id}...")

    async def _runner():
        async with AsyncSessionLocal() as session:
            await AuditService.run_audit_job(audit_id, session)

    try:
        asyncio.run(_runner())
        logger.info(f"[Celery Worker] Audit job #{audit_id} completed successfully.")
        return {"status": "SUCCESS", "audit_id": audit_id}
    except Exception as exc:
        logger.error(f"[Celery Worker] Audit job #{audit_id} failed: {exc}")
        raise self.retry(exc=exc, countdown=10)

