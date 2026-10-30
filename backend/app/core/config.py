"""WebAudit 360 — Application Configuration Settings
Author: Harsh Patel
"""

import os
from typing import List, Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    APP_NAME: str = "WebAudit 360"
    APP_VERSION: str = "1.0.0"
    CREATOR: str = "Harsh Patel"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False

    # Server Binding
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Security & JWT Tokens
    SECRET_KEY: str = Field(
        default="webaudit360_super_secret_cryptographic_key_change_in_production_32b",
        description="HMAC secret key for JWT and webhook signatures"
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30

    # Database
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://postgres:postgres@localhost:5432/webaudit360",
        description="Async PostgreSQL database URL. Falls back to SQLite if unreachable in dev."
    )
    SYNC_DATABASE_URL: str = Field(
        default="postgresql://postgres:postgres@localhost:5432/webaudit360",
        description="Synchronous database URL for Celery workers & Alembic"
    )

    # Redis Broker & Cache
    REDIS_URL: str = "redis://localhost:6379/0"

    # CORS Allowed Origins
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8000",
    ]

    # Crawler Defaults
    CRAWLER_DEFAULT_MAX_PAGES: int = 100
    CRAWLER_DEFAULT_MAX_DEPTH: int = 5
    CRAWLER_DEFAULT_CONCURRENCY: int = 2
    CRAWLER_TIMEOUT_SECONDS: int = 20
    CRAWLER_POLITENESS_DELAY_SECONDS: float = 1.0
    CRAWLER_MAX_RESPONSE_BYTES: int = 10 * 1024 * 1024  # 10 MB

    # Storage
    STORAGE_TYPE: str = "local"  # "local" or "s3"
    STORAGE_LOCAL_DIR: str = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "storage_data")
    S3_BUCKET: Optional[str] = None
    S3_ENDPOINT_URL: Optional[str] = None
    S3_ACCESS_KEY: Optional[str] = None
    S3_SECRET_KEY: Optional[str] = None

    # Optional AI Explanations
    AI_PROVIDER_ENABLED: bool = False
    GEMINI_API_KEY: Optional[str] = None

    # OWASP ZAP (Active Testing)
    ZAP_PROXY_URL: Optional[str] = "http://localhost:8080"
    ZAP_API_KEY: Optional[str] = None


settings = Settings()

