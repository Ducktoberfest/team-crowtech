"""
Veyra AI Prompt-Injection Defense Platform - Main Application Entrypoint.

Configures FastAPI application, restrictive CORS, static file serving for the cybersecurity
dashboard, database initialization, and routing.
"""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.config import get_settings
from app.database import init_db
from app.routes import router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context: initialize database and verify configuration."""
    try:
        init_db()
    except Exception as exc:
        import logging
        logging.getLogger("veyra.startup").warning(f"Database initialization deferred during startup: {exc}")
    yield


app = FastAPI(
    title="Veyra AI Security Engine",
    description=(
        "Production AI-powered prompt-injection defense platform and security boundary. "
        "Audits untrusted prompts and documents, defends downstream agents, and returns "
        "authoritative security verdicts (ALLOW, BLOCK, QUARANTINE)."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# Configure restrictive CORS settings
allowed_origins_env = os.environ.get("ALLOWED_ORIGINS", "*")
allowed_origins = [o.strip() for o in allowed_origins_env.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins if allowed_origins else ["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(router)

# Mount static frontend dashboard directory
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/", include_in_schema=False)
async def serve_dashboard():
    """Serve the cybersecurity SaaS frontend dashboard."""
    index_file = os.path.join(static_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {
        "name": "Veyra AI Security Engine",
        "status": "running",
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    """Return empty 204 for favicon to prevent unnecessary 404 or invocation overhead."""
    return Response(status_code=204)


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0")
    uvicorn.run("app.main:app", host=host, port=port, reload=False)
