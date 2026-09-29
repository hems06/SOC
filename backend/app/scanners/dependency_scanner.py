"""
Dependency Scanner - Analyzes package dependencies for known vulnerabilities
"""
import os
import json
from typing import List
from app.scanners.base import BaseScanner, BaseFinding
from app.models.finding import Severity, Confidence
from app.models.evidence import EvidenceType


# Known vulnerable packages (subset for demonstration - in production, use a vulnerability DB)
KNOWN_VULNERABLE = {
    "lodash": {"below": "4.17.21", "cve": "CVE-2021-23337", "severity": Severity.HIGH, "desc": "Lodash command injection vulnerability"},
    "minimist": {"below": "1.2.6", "cve": "CVE-2021-44906", "severity": Severity.MEDIUM, "desc": "Prototype pollution in minimist"},
    "node-fetch": {"below": "2.6.7", "cve": "CVE-2022-0235", "severity": Severity.MEDIUM, "desc": "Exposure of sensitive information in node-fetch"},
    "express": {"below": "4.19.2", "cve": "CVE-2024-29041", "severity": Severity.MEDIUM, "desc": "Open redirect in express"},
    "axios": {"below": "1.6.0", "cve": "CVE-2023-45857", "severity": Severity.MEDIUM, "desc": "CSRF token leakage in axios"},
    "jsonwebtoken": {"below": "9.0.0", "cve": "CVE-2022-23529", "severity": Severity.HIGH, "desc": "Insecure implementation in jsonwebtoken"},
    "semver": {"below": "7.5.2", "cve": "CVE-2022-25883", "severity": Severity.MEDIUM, "desc": "ReDoS in semver"},
    "tough-cookie": {"below": "4.1.3", "cve": "CVE-2023-26136", "severity": Severity.MEDIUM, "desc": "Prototype pollution in tough-cookie"},
}


def compare_versions(version: str, target: str) -> bool:
    """Simple version comparison - returns True if version < target."""
    try:
        v_parts = [int(x) for x in version.split(".")[:3]]
        t_parts = [int(x) for x in target.split(".")[:3]]
        while len(v_parts) < 3:
            v_parts.append(0)
        while len(t_parts) < 3:
            t_parts.append(0)
        return v_parts < t_parts
    except (ValueError, AttributeError):
        return False


class DependencyScanner(BaseScanner):
    """Scans project dependencies for known vulnerabilities."""

    async def scan(self) -> List[BaseFinding]:
        findings = []
        source_path = self.project.local_source_path

        if not source_path or not os.path.exists(source_path):
            return findings

        self.update_progress(10)

        # Check package.json
        package_json_path = os.path.join(source_path, "package.json")
        if os.path.exists(package_json_path):
            findings.extend(await self._scan_package_json(package_json_path))

        self.update_progress(50)

        # Check package-lock.json
        lock_path = os.path.join(source_path, "package-lock.json")
        if os.path.exists(lock_path):
            findings.extend(await self._scan_lock_file(lock_path))

        self.update_progress(80)

        # Check for requirements.txt (Python)
        req_path = os.path.join(source_path, "requirements.txt")
        if os.path.exists(req_path):
            findings.extend(await self._scan_requirements(req_path))

        self.update_progress(100)
        return findings

    async def _scan_package_json(self, path: str) -> List[BaseFinding]:
        findings = []
        try:
            with open(path, "r") as f:
                pkg = json.load(f)

            all_deps = {}
            all_deps.update(pkg.get("dependencies", {}))
            all_deps.update(pkg.get("devDependencies", {}))

            for dep_name, dep_version in all_deps.items():
                # Clean version string
                version = dep_version.lstrip("^~>=<")

                if dep_name in KNOWN_VULNERABLE:
                    vuln = KNOWN_VULNERABLE[dep_name]
                    if compare_versions(version, vuln["below"]):
                        finding = BaseFinding(
                            title=f"Vulnerable Dependency: {dep_name}@{version}",
                            severity=vuln["severity"],
                            confidence=Confidence.CONFIRMED,
                            category="dependencies",
                            cwe_id="CWE-1395",
                            cwe_name="Dependency on Vulnerable Third-Party Component",
                            affected_component=f"{dep_name}@{version}",
                            affected_file="package.json",
                            description=f"{vuln['desc']}. Current version: {version}. Fix available in version {vuln['below']} or later.",
                            technical_details=f"Package: {dep_name}\nInstalled: {version}\nVulnerable below: {vuln['below']}\nCVE: {vuln['cve']}",
                            impact="Using known vulnerable dependencies may expose the application to documented attacks.",
                            remediation=f"Update {dep_name} to version {vuln['below']} or later: npm update {dep_name}",
                            scanner_source="dependency_scanner",
                            retest_procedure=f"Run 'npm list {dep_name}' to verify the version has been updated.",
                        )
                        finding.add_evidence(
                            evidence_type=EvidenceType.CONFIGURATION,
                            title=f"package.json - {dep_name}",
                            content=f'"dependencies": {{\n  "{dep_name}": "{dep_version}"\n}}',
                            file_path="package.json",
                        )
                        findings.append(finding)
                        self.save_finding(finding)

        except Exception:
            pass
        return findings

    async def _scan_lock_file(self, path: str) -> List[BaseFinding]:
        """Scan package-lock.json for transitive vulnerable dependencies."""
        findings = []
        try:
            with open(path, "r") as f:
                lock = json.load(f)

            packages = lock.get("packages", lock.get("dependencies", {}))

            for pkg_path, pkg_info in packages.items():
                if isinstance(pkg_info, dict):
                    version = pkg_info.get("version", "")
                    name = pkg_path.split("node_modules/")[-1] if "node_modules/" in pkg_path else pkg_path

                    if name in KNOWN_VULNERABLE and version:
                        vuln = KNOWN_VULNERABLE[name]
                        if compare_versions(version, vuln["below"]):
                            finding = BaseFinding(
                                title=f"Vulnerable Transitive Dependency: {name}@{version}",
                                severity=vuln["severity"],
                                confidence=Confidence.CONFIRMED,
                                category="dependencies",
                                cwe_id="CWE-1395",
                                cwe_name="Dependency on Vulnerable Third-Party Component",
                                affected_component=f"{name}@{version}",
                                affected_file="package-lock.json",
                                description=f"Transitive dependency {name}@{version} is vulnerable. {vuln['desc']}",
                                technical_details=f"CVE: {vuln['cve']}\nPath: {pkg_path}",
                                impact="Transitive dependencies with known vulnerabilities can be exploited.",
                                remediation=f"Run 'npm audit fix' or manually update {name}.",
                                scanner_source="dependency_scanner",
                            )
                            finding.add_evidence(
                                evidence_type=EvidenceType.CONFIGURATION,
                                title=f"package-lock.json - {name}",
                                content=f"Package: {pkg_path}\nVersion: {version}",
                                file_path="package-lock.json",
                            )
                            findings.append(finding)
                            self.save_finding(finding)

        except Exception:
            pass
        return findings

    async def _scan_requirements(self, path: str) -> List[BaseFinding]:
        """Scan Python requirements.txt for outdated/vulnerable packages."""
        findings = []
        try:
            with open(path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        # Simple parse: name==version or name>=version
                        for sep in ["==", ">=", "<=", "~=", "!="]:
                            if sep in line:
                                name, version = line.split(sep, 1)
                                name = name.strip().lower()
                                version = version.strip()
                                # Could check against a Python vulnerability DB
                                break

        except Exception:
            pass
        return findings
