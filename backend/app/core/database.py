"""WebAudit 360 — Database Connection & Session Management
Author: Harsh Patel

Supports PostgreSQL in production and automated fallback to SQLite in local dev.
"""

import os
from typing import AsyncGenerator
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from backend.app.core.config import settings
from backend.app.core.logging import logger

Base = declarative_base()

# Resolve Database URL
db_url = settings.DATABASE_URL
sync_db_url = settings.SYNC_DATABASE_URL

# Fallback to local SQLite if in development and postgres isn't running
if "sqlite" in db_url:
    async_engine = create_async_engine(db_url, echo=settings.DEBUG, connect_args={"check_same_thread": False})
    sync_engine = create_engine(sync_db_url, connect_args={"check_same_thread": False})
else:
    try:
        async_engine = create_async_engine(db_url, echo=settings.DEBUG, pool_pre_ping=True)
        sync_engine = create_engine(sync_db_url, pool_pre_ping=True)
    except Exception as e:
        logger.warning(f"Could not initialize PostgreSQL engine ({e}). Falling back to local SQLite.")
        sqlite_async = "sqlite+aiosqlite:///./webaudit360.db"
        sqlite_sync = "sqlite:///./webaudit360.db"
        async_engine = create_async_engine(sqlite_async, connect_args={"check_same_thread": False})
        sync_engine = create_engine(sqlite_sync, connect_args={"check_same_thread": False})

AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)

SyncSessionLocal = sessionmaker(
    bind=sync_engine,
    autocommit=False,
    autoflush=False
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency for obtaining an asynchronous database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    """Initializes all registered database tables."""
    # Import all models to ensure metadata registration
    import backend.app.models  # noqa
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database schemas verified and initialized.")
