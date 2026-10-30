"""WebAudit 360 — API v1 Root Router
Author: Harsh Patel
"""

from fastapi import APIRouter

from backend.app.api.v1.endpoints import (
    auth,
    projects,
    audits,
    findings,
    reports,
    monitoring,
    authorizations,
    health,
)

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(auth.router)
api_router.include_router(projects.router)
api_router.include_router(audits.router)
api_router.include_router(findings.router)
api_router.include_router(reports.router)
api_router.include_router(monitoring.router)
api_router.include_router(authorizations.router)
api_router.include_router(health.router)

