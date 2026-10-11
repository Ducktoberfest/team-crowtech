# ==============================================================================
# Veyra AI Security Engine - Production Dockerfile for DigitalOcean App Platform
# ==============================================================================

# Base image: Python 3.12 slim for minimal attack surface and fast startup
FROM python:3.12-slim

# Prevent Python from buffering stdout/stderr and writing bytecode files
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000 \
    HOST=0.0.0.0 \
    DATABASE_PATH=/app/data/veyra.db

# Install system dependencies (curl for healthchecks)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged application user
RUN useradd -m -u 1000 -s /bin/bash appuser

# Set working directory
WORKDIR /app

# Install Python dependencies first for optimal Docker layer caching
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source code and benchmark dataset
COPY app/ /app/app/
COPY dataset/ /app/dataset/

# Create persistent storage mount directory for SQLite database
RUN mkdir -p /app/data && chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose default port (DigitalOcean App Platform dynamically injects $PORT)
EXPOSE 8000

# Container healthcheck querying the /health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://127.0.0.1:${PORT:-8000}/health || exit 1

# Production ASGI server launch command
# Shell form ensures ${PORT:-8000} is expanded at runtime by DigitalOcean
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 2 --access-log"]
