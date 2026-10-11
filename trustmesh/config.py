"""
TrustMesh Production Configuration Manager
Uses pydantic-settings to manage environment variables and zero-trust runtime parameters.
"""

from __future__ import annotations
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class TrustMeshSettings(BaseSettings):
    """Production runtime settings for TrustMesh nodes and policy engines."""
    model_config = SettingsConfigDict(
        env_prefix="TRUSTMESH_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    environment: str = "production"
    host: str = "0.0.0.0"
    port: int = 8000
    clock_skew_seconds: int = 60
    db_url: str = "sqlite:///trustmesh_audit.db"
    enable_persistence: bool = True
    log_level: str = "INFO"
    trusted_roots_file: Optional[str] = None
    default_spend_ceiling: float = 600.0


# Global singleton instance
settings = TrustMeshSettings()
