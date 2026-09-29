"""
World Monitor Security Assessment Platform - Configuration
"""
import os
from pathlib import Path
from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    # Application
    app_name: str = "World Monitor Security Assessment"
    app_version: str = "1.0.0"
    debug: bool = True

    # Server
    host: str = "0.0.0.0"
    port: int = 8000

    # Database
    database_url: str = "sqlite:///./security_assessment.db"

    # Safety
    safe_mode: bool = True
    allowed_targets: List[str] = [
        "https://www.worldmonitor.app",
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ]

    # Target
    target_url: str = "https://www.worldmonitor.app"
    target_repo: str = "https://github.com/koala73/worldmonitor"
    target_local_path: str = "./target-source"

    # Rate Limiting
    rate_limit_requests: int = 10
    rate_limit_period: int = 60

    # Directories
    reports_dir: str = "./reports"
    evidence_dir: str = "./evidence"
    rules_dir: str = "./rules"

    # Base directory
    base_dir: Path = Path(__file__).resolve().parent.parent.parent

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

    def is_target_allowed(self, url: str) -> bool:
        """Check if a target URL is in the allowlist."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        return any(
            base_url.startswith(allowed) or url.startswith(allowed)
            for allowed in self.allowed_targets
        )


settings = Settings()
