"""WebAudit 360 — Main FastAPI Application
Author: Harsh Patel
"""

import os
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.app.core.config import settings
from backend.app.core.database import get_db, init_db
from backend.app.core.logging import logger
from backend.app.api.v1.router import api_router
from backend.app.api.v1.endpoints import websockets, health


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler managing database schemas and background connections."""
    logger.info(f"Initializing {settings.APP_NAME} v{settings.APP_VERSION} (Created by {settings.CREATOR})...")
    await init_db()
    yield
    logger.info(f"Shutting down {settings.APP_NAME}...")


def create_app() -> FastAPI:
    """Application factory for WebAudit 360."""
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=(
            "WebAudit 360 is an evidence-driven website intelligence and continuous monitoring platform "
            "architected by Harsh Patel. Inspects performance, SEO, accessibility, security, responsive behavior, "
            "and technical website health with reproducible measurements and zero fake data."
        ),
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/api/v1/openapi.json"
    )

    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS or ["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include API Routers
    app.include_router(api_router)
    app.include_router(websockets.router, prefix="/api/v1")

    # Root health endpoint alias
    @app.get("/health", tags=["Health & Diagnostics"], include_in_schema=False)
    async def root_health(session=Depends(get_db)):
        return await health.get_system_health(session)

    # Mount Frontend Static Assets
    frontend_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "frontend"
    )
    if os.path.exists(frontend_dir):
        app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")
        logger.info(f"Frontend static files mounted from {frontend_dir}")

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG
    )
