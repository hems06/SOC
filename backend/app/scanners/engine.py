"""
Scan Engine - Orchestrates all security scanners
"""
from typing import List
from sqlalchemy.orm import Session
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.scanners.base import BaseFinding


class ScanEngine:
    """Orchestrates security scan execution."""

    def __init__(self, db: Session, project: Project, scan: Scan):
        self.db = db
        self.project = project
        self.scan = scan

    async def run_full_scan(self):
        """Run all scanners."""
        await self.run_source_scan()
        await self.run_secrets_scan()
        await self.run_dependency_scan()
        await self.run_headers_scan()
        await self.run_cors_scan()
        await self.run_api_scan()

    async def run_source_scan(self):
        """Run source code analysis."""
        from app.scanners.source_scanner import SourceCodeScanner
        scanner = SourceCodeScanner(self.db, self.project, self.scan)
        await scanner.scan()

    async def run_secrets_scan(self):
        """Run secrets detection."""
        from app.scanners.secrets_scanner import SecretsScanner
        scanner = SecretsScanner(self.db, self.project, self.scan)
        await scanner.scan()

    async def run_dependency_scan(self):
        """Run dependency analysis."""
        from app.scanners.dependency_scanner import DependencyScanner
        scanner = DependencyScanner(self.db, self.project, self.scan)
        await scanner.scan()

    async def run_headers_scan(self):
        """Run security headers check."""
        from app.scanners.headers_scanner import HeadersScanner
        scanner = HeadersScanner(self.db, self.project, self.scan)
        await scanner.scan()

    async def run_cors_scan(self):
        """Run CORS configuration check."""
        from app.scanners.cors_scanner import CorsScanner
        scanner = CorsScanner(self.db, self.project, self.scan)
        await scanner.scan()

    async def run_api_scan(self):
        """Run API security scan."""
        from app.scanners.api_scanner import ApiScanner
        scanner = ApiScanner(self.db, self.project, self.scan)
        await scanner.scan()

    async def run_auth_scan(self):
        """Run authentication analysis."""
        # Authentication analysis is primarily source-code based
        await self.run_source_scan()

    async def run_input_scan(self):
        """Run input validation analysis."""
        # Input validation is primarily source-code based
        await self.run_source_scan()
