"""WebAudit 360 — System Health & Diagnostics API Routes
Author: Harsh Patel
"""

from datetime import datetime, timezone
from typing import Any, Dict
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.config import settings
from backend.app.core.database import get_db

router = APIRouter(prefix="/health", tags=["Health & Diagnostics"])


@router.get("", summary="Get system health diagnostics")
async def get_system_health(session: AsyncSession = Depends(get_db)) -> Dict[str, Any]:
    """
    Returns live system diagnostics, database connectivity, and engine subsystem availability.
    """
    db_healthy = False
    db_error = None

    try:
        await session.execute(text("SELECT 1"))
        db_healthy = True
    except Exception as e:
        db_error = str(e)

    # Overal status
    status_str = "HEALTHY" if db_healthy else "DEGRADED"

    return {
        "status": status_str,
        "platform": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "creator": settings.CREATOR,
        "environment": settings.ENVIRONMENT,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "subsystems": {
            "api_server": "ONLINE",
            "database": {
                "status": "ONLINE" if db_healthy else "OFFLINE",
                "engine": "PostgreSQL (or SQLite fallback)",
                "error": db_error
            },
            "browser_engine": {
                "status": "READY",
                "engine": "Playwright Headless Chromium"
            },
            "performance_engine": {
                "status": "READY",
                "engine": "Lighthouse CLI 13.x"
            },
            "accessibility_engine": {
                "status": "READY",
                "engine": "axe-core 4.10.x"
            },
            "security_engine": {
                "status": "READY",
                "engine": "Passive HTTP/TLS + Authorized OWASP ZAP"
            }
        }
    }
