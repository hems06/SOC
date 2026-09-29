"""
Base Scanner - Abstract base for all security scanners
"""
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from app.models.project import Project
from app.models.scan import Scan
from app.models.finding import Finding, Severity, Confidence
from app.models.evidence import Evidence, EvidenceType


class BaseFinding:
    """Intermediate finding representation before DB storage."""
    def __init__(
        self,
        title: str,
        severity: str = Severity.INFORMATIONAL,
        confidence: str = Confidence.POTENTIAL,
        category: str = "",
        cwe_id: str = "",
        cwe_name: str = "",
        affected_component: str = "",
        affected_file: str = "",
        affected_line: str = "",
        affected_endpoint: str = "",
        description: str = "",
        technical_details: str = "",
        code_snippet: str = "",
        rule_id: str = "",
        steps_to_reproduce: str = "",
        poc: str = "",
        impact: str = "",
        root_cause: str = "",
        remediation: str = "",
        retest_procedure: str = "",
        scanner_source: str = "",
    ):
        self.title = title
        self.severity = severity
        self.confidence = confidence
        self.category = category
        self.cwe_id = cwe_id
        self.cwe_name = cwe_name
        self.affected_component = affected_component
        self.affected_file = affected_file
        self.affected_line = affected_line
        self.affected_endpoint = affected_endpoint
        self.description = description
        self.technical_details = technical_details
        self.code_snippet = code_snippet
        self.rule_id = rule_id
        self.steps_to_reproduce = steps_to_reproduce
        self.poc = poc
        self.impact = impact
        self.root_cause = root_cause
        self.remediation = remediation
        self.retest_procedure = retest_procedure
        self.scanner_source = scanner_source
        self.evidence_items: List[Dict[str, Any]] = []

    def add_evidence(
        self,
        evidence_type: str,
        title: str = "",
        content: str = "",
        **kwargs
    ):
        self.evidence_items.append({
            "evidence_type": evidence_type,
            "title": title,
            "content": content,
            **kwargs,
        })


class BaseScanner(ABC):
    """Abstract base class for all security scanners."""

    def __init__(self, db: Session, project: Project, scan: Scan):
        self.db = db
        self.project = project
        self.scan = scan
        self._finding_counter = self._get_next_finding_counter()
        self._evidence_counter = self._get_next_evidence_counter()

    def _get_next_finding_counter(self) -> int:
        last = self.db.query(Finding).order_by(Finding.finding_id.desc()).first()
        if last and last.finding_id:
            try:
                return int(last.finding_id.split("-")[1]) + 1
            except (IndexError, ValueError):
                pass
        return 1

    def _get_next_evidence_counter(self) -> int:
        last = self.db.query(Evidence).order_by(Evidence.evidence_id.desc()).first()
        if last and last.evidence_id:
            try:
                return int(last.evidence_id.split("-")[1]) + 1
            except (IndexError, ValueError):
                pass
        return 1

    def _next_finding_id(self) -> str:
        fid = f"FIND-{self._finding_counter:04d}"
        self._finding_counter += 1
        return fid

    def _next_evidence_id(self) -> str:
        eid = f"EVID-{self._evidence_counter:04d}"
        self._evidence_counter += 1
        return eid

    def save_finding(self, base_finding: BaseFinding) -> Finding:
        """Save a finding and its evidence to the database."""
        from app.risk.cvss import calculate_cvss

        # Calculate CVSS
        cvss_result = calculate_cvss(base_finding)

        finding = Finding(
            finding_id=self._next_finding_id(),
            project_id=self.project.id,
            scan_id=self.scan.id,
            title=base_finding.title,
            severity=base_finding.severity,
            confidence=base_finding.confidence,
            category=base_finding.category,
            cvss_score=cvss_result.get("score"),
            cvss_vector=cvss_result.get("vector"),
            cvss_details=cvss_result.get("details"),
            cwe_id=base_finding.cwe_id,
            cwe_name=base_finding.cwe_name,
            affected_component=base_finding.affected_component,
            affected_file=base_finding.affected_file,
            affected_line=base_finding.affected_line,
            affected_endpoint=base_finding.affected_endpoint,
            description=base_finding.description,
            technical_details=base_finding.technical_details,
            code_snippet=base_finding.code_snippet,
            rule_id=base_finding.rule_id,
            steps_to_reproduce=base_finding.steps_to_reproduce,
            poc=base_finding.poc,
            impact=base_finding.impact,
            root_cause=base_finding.root_cause,
            remediation=base_finding.remediation,
            retest_procedure=base_finding.retest_procedure,
            scanner_source=base_finding.scanner_source,
        )
        self.db.add(finding)
        self.db.flush()  # Get the ID

        # Save evidence
        for ev in base_finding.evidence_items:
            evidence = Evidence(
                evidence_id=self._next_evidence_id(),
                finding_id=finding.id,
                evidence_type=ev.get("evidence_type", EvidenceType.LOG),
                title=ev.get("title", ""),
                description=ev.get("description", ""),
                content=ev.get("content", ""),
                request_method=ev.get("request_method"),
                request_url=ev.get("request_url"),
                request_headers=ev.get("request_headers"),
                request_body=ev.get("request_body"),
                response_status=ev.get("response_status"),
                response_headers=ev.get("response_headers"),
                response_body=ev.get("response_body"),
                file_path=ev.get("file_path"),
                line_start=ev.get("line_start"),
                line_end=ev.get("line_end"),
                code_snippet=ev.get("code_snippet"),
            )
            self.db.add(evidence)

        self.db.commit()
        return finding

    def update_progress(self, progress: int):
        """Update scan progress."""
        self.scan.progress = min(progress, 100)
        self.db.commit()

    @abstractmethod
    async def scan(self) -> List[BaseFinding]:
        """Execute the scan and return findings."""
        pass
