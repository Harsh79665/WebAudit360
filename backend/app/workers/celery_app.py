"""WebAudit 360 — Celery Application Configuration
Author: Harsh Patel
"""

from celery import Celery
from backend.app.core.config import settings

celery_app = Celery(
    "webaudit360",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["backend.app.workers.tasks"]
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=300,  # 5 minutes maximum for scan jobs
    task_soft_time_limit=240,
    worker_concurrency=4,
    worker_prefetch_multiplier=1,
)
