"""
Secrets Scanner - Detects hardcoded secrets and credentials
"""
import os
import re
from typing import List
from app.scanners.base import BaseScanner, BaseFinding
from app.models.finding import Severity, Confidence
from app.models.evidence import EvidenceType


SECRET_PATTERNS = [
    {
        "id": "SECRET-001",
        "name": "AWS Access Key",
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": Severity.CRITICAL,
        "description": "AWS Access Key ID detected.",
    },
    {
        "id": "SECRET-002",
        "name": "AWS Secret Key",
        "pattern": r"""(?:aws_secret_access_key|secret_access_key)\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}""",
        "severity": Severity.CRITICAL,
        "description": "AWS Secret Access Key detected.",
    },
    {
        "id": "SECRET-003",
        "name": "Generic API Key",
        "pattern": r"""(?:api[_-]?key|apikey)\s*[=:]\s*['\"][A-Za-z0-9_\-]{16,}['\"]""",
        "severity": Severity.HIGH,
        "description": "Generic API key detected in source code.",
    },
    {
        "id": "SECRET-004",
        "name": "Private Key",
        "pattern": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
        "severity": Severity.CRITICAL,
        "description": "Private key detected in source code.",
    },
    {
        "id": "SECRET-005",
        "name": "Generic Password",
        "pattern": r"""(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]""",
        "severity": Severity.HIGH,
        "description": "Hardcoded password detected.",
    },
    {
        "id": "SECRET-006",
        "name": "JWT Token",
        "pattern": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "severity": Severity.HIGH,
        "description": "JWT token detected in source code.",
    },
    {
        "id": "SECRET-007",
        "name": "GitHub Token",
        "pattern": r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}",
        "severity": Severity.CRITICAL,
        "description": "GitHub personal access token detected.",
    },
    {
        "id": "SECRET-008",
        "name": "Google API Key",
        "pattern": r"AIza[0-9A-Za-z_-]{35}",
        "severity": Severity.HIGH,
        "description": "Google API key detected.",
    },
    {
        "id": "SECRET-009",
        "name": "Database Connection String",
        "pattern": r"""(?:mongodb|postgres|mysql|redis|amqp):\/\/[^\s'"]+""",
        "severity": Severity.HIGH,
        "description": "Database connection string with potential credentials detected.",
    },
    {
        "id": "SECRET-010",
        "name": "Bearer Token",
        "pattern": r"""['\"]Bearer\s+[A-Za-z0-9_\-\.]{20,}['\"]""",
        "severity": Severity.MEDIUM,
        "description": "Hardcoded Bearer token detected.",
    },
]


def redact_secret(value: str) -> str:
    """Redact a secret value for safe reporting."""
    if len(value) <= 8:
        return "***REDACTED***"
    return value[:4] + "***REDACTED***" + value[-4:]


class SecretsScanner(BaseScanner):
    """Scans source code for hardcoded secrets and credentials."""

    async def scan(self) -> List[BaseFinding]:
        findings = []
        source_path = self.project.local_source_path

        if not source_path or not os.path.exists(source_path):
            return findings

        self.update_progress(5)

        files_to_scan = self._collect_files(source_path)
        total_files = len(files_to_scan)

        if total_files == 0:
            return findings

        for idx, file_path in enumerate(files_to_scan):
            progress = 5 + int((idx / total_files) * 90)
            self.update_progress(progress)

            try:
                rel_path = os.path.relpath(file_path, source_path)

                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    lines = content.split("\n")

                for secret_rule in SECRET_PATTERNS:
                    pattern = re.compile(secret_rule["pattern"], re.IGNORECASE)

                    for line_num, line in enumerate(lines, 1):
                        if pattern.search(line):
                            # Skip example/test files and comments
                            stripped = line.strip()
                            if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
                                continue
                            if ".example" in rel_path or "test" in rel_path.lower():
                                continue

                            # Redact the match for safe reporting
                            match = pattern.search(line)
                            redacted_line = line[:match.start()] + redact_secret(match.group()) + line[match.end():]

                            start = max(0, line_num - 3)
                            end = min(len(lines), line_num + 2)
                            snippet_lines = lines[start:end]
                            redacted_snippet = "\n".join(
                                f"{i + start + 1}: {redact_secret(l) if i + start + 1 == line_num - 1 else l}"
                                for i, l in enumerate(snippet_lines)
                            )

                            finding = BaseFinding(
                                title=f"{secret_rule['name']} detected in {rel_path}",
                                severity=secret_rule["severity"],
                                confidence=Confidence.POTENTIAL,
                                category="secrets",
                                cwe_id="CWE-798",
                                cwe_name="Use of Hard-coded Credentials",
                                affected_component=rel_path,
                                affected_file=rel_path,
                                affected_line=str(line_num),
                                description=secret_rule["description"],
                                technical_details=f"Rule {secret_rule['id']} matched at {rel_path}:{line_num}\nRedacted match: {redact_secret(match.group()[:100])}",
                                code_snippet=redacted_snippet,
                                rule_id=secret_rule["id"],
                                impact="Exposed credentials could allow unauthorized access to external services or infrastructure.",
                                root_cause="Credentials stored directly in source code instead of environment variables or secrets management.",
                                remediation="Remove hardcoded credentials. Use environment variables, a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault), or a .env file excluded from version control.",
                                scanner_source="secrets_scanner",
                                retest_procedure=f"Search {rel_path} for the secret pattern and verify it has been removed or externalized.",
                            )

                            finding.add_evidence(
                                evidence_type=EvidenceType.SOURCE_CODE,
                                title=f"Secret in {rel_path}:{line_num}",
                                content=redacted_snippet,
                                file_path=rel_path,
                                line_start=str(line_num),
                                code_snippet=redacted_snippet,
                            )

                            findings.append(finding)
                            self.save_finding(finding)

            except Exception:
                continue

        self.update_progress(100)
        return findings

    def _collect_files(self, source_path: str) -> List[str]:
        """Collect files that might contain secrets."""
        scannable_extensions = {
            ".js", ".jsx", ".ts", ".tsx", ".py", ".rb",
            ".json", ".yml", ".yaml", ".env", ".conf",
            ".cfg", ".ini", ".properties", ".xml",
            ".sh", ".bash", ".zsh", ".tf", ".tfvars",
        }
        skip_dirs = {
            "node_modules", ".git", "__pycache__", "dist", "build",
            ".next", ".nuxt", "coverage", ".venv", "venv",
        }

        files = []
        for root, dirs, filenames in os.walk(source_path):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for filename in filenames:
                ext = os.path.splitext(filename)[1].lower()
                name_lower = filename.lower()
                if ext in scannable_extensions or name_lower in {
                    ".env", ".env.local", ".env.production", ".env.development",
                    "dockerfile", "docker-compose.yml", "docker-compose.yaml",
                }:
                    files.append(os.path.join(root, filename))

        return files
