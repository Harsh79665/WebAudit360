"""WebAudit 360 — Pytest Configuration & Fixture Isolation
Author: Harsh Patel

Provides:
- In-memory / isolated SQLite database fixtures
- FastAPI test client fixtures
- Automatic schema generation before test sessions
"""

import asyncio
from typing import AsyncGenerator
import pytest
import pytest_asyncio
import httpx
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from backend.app.main import app
from backend.app.core.database import Base, get_db, init_db, AsyncSessionLocal
import backend.app.models  # Ensure all models are registered in Base.metadata


@pytest_asyncio.fixture(scope="function", autouse=True)
async def setup_test_db():
    """Ensures database schema is initialized for test execution."""
    await init_db()


@pytest_asyncio.fixture
async def async_client() -> AsyncGenerator[httpx.AsyncClient, None]:
    """Provides an isolated httpx.AsyncClient targeting the FastAPI ASGI application."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client
