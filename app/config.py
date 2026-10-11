"""
Configuration management for Veyra AI Security Engine.

Manages environment variables, inference endpoints, model settings, and security policy thresholds.
Designed for local development and DigitalOcean production deployments.
"""

import os
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application configuration for Veyra security engine.
    
    Environment variables:
        OLLAMA_API_KEY: Optional API key for hosted/cloud Ollama inference services.
        OLLAMA_MODEL: Open-weight model identifier (e.g. 'gemma2:9b', 'gemma2', 'gemma:7b').
        OLLAMA_BASE_URL: Base URL for Ollama API endpoint (e.g. 'http://localhost:11434' or remote URL).
        OLLAMA_TIMEOUT_SECONDS: Timeout for inference HTTP requests in seconds.
        VEYRA_DEMO_MODE: Explicitly enable offline deterministic mock mode for tests/demo.
        FAIL_CLOSED_ON_ERROR: If True, model failures default to QUARANTINE instead of failing open.
        RISK_THRESHOLD_BLOCK: Minimum risk score (0.0 - 1.0) to trigger a BLOCK decision.
        RISK_THRESHOLD_QUARANTINE: Minimum risk score (0.0 - 1.0) to trigger a QUARANTINE decision.
    """
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    # Model inference settings
    ollama_api_key: Optional[str] = Field(
        default=None,
        alias="OLLAMA_API_KEY",
        description="Bearer token or API key for authenticated Ollama Cloud or remote inference."
    )
    ollama_model: str = Field(
        default="gemma4:31b" if os.environ.get("VERCEL") or os.environ.get("VERCEL_ENV") else "gemma2:9b",
        alias="OLLAMA_MODEL",
        description="Target open-weight model name (default: gemma4:31b on Cloud, gemma2:9b local)."
    )
    ollama_base_url: str = Field(
        default="https://ollama.com" if os.environ.get("VERCEL") or os.environ.get("VERCEL_ENV") else "http://localhost:11434",
        alias="OLLAMA_BASE_URL",
        description="Inference provider base URL (e.g. https://ollama.com for Cloud, or http://localhost:11434 for local Droplet)."
    )
    ollama_timeout_seconds: float = Field(
        default=15.0,
        alias="OLLAMA_TIMEOUT_SECONDS",
        description="Timeout for model API requests in seconds."
    )

    # Security engine operation modes
    veyra_demo_mode: bool = Field(
        default=False,
        alias="VEYRA_DEMO_MODE",
        description="Enable simulated offline inference mode for testing or mock demonstrations."
    )
    fail_closed_on_error: bool = Field(
        default=True,
        alias="FAIL_CLOSED_ON_ERROR",
        description="Conservative posture: route suspicious or unanalyzed inputs to QUARANTINE if model fails."
    )

    # Decision thresholds (0.0 to 1.0)
    risk_threshold_block: float = Field(
        default=0.70,
        alias="RISK_THRESHOLD_BLOCK",
        ge=0.0,
        le=1.0,
        description="Risk score threshold at or above which prompts are categorized as BLOCK."
    )
    risk_threshold_quarantine: float = Field(
        default=0.35,
        alias="RISK_THRESHOLD_QUARANTINE",
        ge=0.0,
        le=1.0,
        description="Risk score threshold at or above which prompts are categorized as QUARANTINE."
    )


def get_settings() -> Settings:
    """Return an instance of application settings loaded from environment."""
    return Settings()
