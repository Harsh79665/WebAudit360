# ==============================================================================
# WebAudit 360 — Production Multi-Stage Dockerfile
# Creator: Harsh Patel
# ==============================================================================

FROM python:3.12-slim-bookworm AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# Install system dependencies & Node.js for Lighthouse CLI
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gnupg \
    build-essential \
    libpq-dev \
    git \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && npm install -g lighthouse@13.6.0 \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Install Playwright Chromium & OS dependencies
RUN playwright install-deps chromium && playwright install chromium

# Copy application source code
COPY . /app

# Non-root application user for container security
RUN useradd -m -u 1001 webaudit && \
    mkdir -p /app/storage_data && \
    chown -R webaudit:webaudit /app

USER webaudit

EXPOSE 8000

# Default command: FastAPI API Server
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
