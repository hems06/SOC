"""
Findings API - Vulnerability findings management
"""
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.finding import Finding, Severity, Confidence, FindingStatus

router = APIRouter(prefix="/api/findings", tags=["findings"])


# --- Pydantic Schemas ---

class FindingResponse(BaseModel):
    id: str
    finding_id: str
    project_id: str
    scan_id: Optional[str]
    title: str
    severity: str
    confidence: str
    status: str
    category: Optional[str]
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    cvss_details: Optional[dict]
    cwe_id: Optional[str]
    cwe_name: Optional[str]
    affected_component: Optional[str]
    affected_file: Optional[str]
    affected_line: Optional[str]
    affected_endpoint: Optional[str]
    description: Optional[str]
    technical_details: Optional[str]
    code_snippet: Optional[str]
    rule_id: Optional[str]
    steps_to_reproduce: Optional[str]
    poc: Optional[str]
    impact: Optional[str]
    root_cause: Optional[str]
    remediation: Optional[str]
    retest_procedure: Optional[str]
    scanner_source: Optional[str]
    is_ai_assisted: Optional[str]
    evidence_count: int = 0
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class FindingUpdate(BaseModel):
    severity: Optional[str] = None
    confidence: Optional[str] = None
    status: Optional[str] = None
    description: Optional[str] = None
    technical_details: Optional[str] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None
    retest_procedure: Optional[str] = None


class DashboardStats(BaseModel):
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    informational: int
    confirmed: int
    potential: int
    source_findings: int
    runtime_findings: int
    evidence_count: int
    categories: dict
    components: dict


# --- Routes ---

@router.get("/", response_model=List[FindingResponse])
def list_findings(
    project_id: Optional[str] = Query(None),
    scan_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    confidence: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """List findings with optional filters."""
    query = db.query(Finding)
    if project_id:
        query = query.filter(Finding.project_id == project_id)
    if scan_id:
        query = query.filter(Finding.scan_id == scan_id)
    if severity:
        query = query.filter(Finding.severity == severity)
    if confidence:
        query = query.filter(Finding.confidence == confidence)
    if status:
        query = query.filter(Finding.status == status)
    if category:
        query = query.filter(Finding.category == category)

    findings = query.order_by(Finding.created_at.desc()).all()

    result = []
    for f in findings:
        result.append(FindingResponse(
            id=f.id,
            finding_id=f.finding_id,
            project_id=f.project_id,
            scan_id=f.scan_id,
            title=f.title,
            severity=f.severity,
            confidence=f.confidence,
            status=f.status,
            category=f.category,
            cvss_score=f.cvss_score,
            cvss_vector=f.cvss_vector,
            cvss_details=f.cvss_details,
            cwe_id=f.cwe_id,
            cwe_name=f.cwe_name,
            affected_component=f.affected_component,
            affected_file=f.affected_file,
            affected_line=f.affected_line,
            affected_endpoint=f.affected_endpoint,
            description=f.description,
            technical_details=f.technical_details,
            code_snippet=f.code_snippet,
            rule_id=f.rule_id,
            steps_to_reproduce=f.steps_to_reproduce,
            poc=f.poc,
            impact=f.impact,
            root_cause=f.root_cause,
            remediation=f.remediation,
            retest_procedure=f.retest_procedure,
            scanner_source=f.scanner_source,
            is_ai_assisted=f.is_ai_assisted,
            evidence_count=len(f.evidence_items) if f.evidence_items else 0,
            created_at=f.created_at,
            updated_at=f.updated_at,
        ))
    return result


@router.get("/dashboard", response_model=DashboardStats)
def get_dashboard_stats(
    project_id: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """Get dashboard statistics."""
    query = db.query(Finding)
    if project_id:
        query = query.filter(Finding.project_id == project_id)

    findings = query.all()

    from app.models.evidence import Evidence
    evidence_query = db.query(Evidence)
    if project_id:
        evidence_query = evidence_query.join(Finding).filter(Finding.project_id == project_id)
    evidence_count = evidence_query.count()

    categories = {}
    components = {}
    source_findings = 0
    runtime_findings = 0

    for f in findings:
        cat = f.category or "uncategorized"
        categories[cat] = categories.get(cat, 0) + 1
        comp = f.affected_component or "unknown"
        components[comp] = components.get(comp, 0) + 1
        if f.scanner_source and "source" in f.scanner_source.lower():
            source_findings += 1
        else:
            runtime_findings += 1

    return DashboardStats(
        total_findings=len(findings),
        critical=sum(1 for f in findings if f.severity == "critical"),
        high=sum(1 for f in findings if f.severity == "high"),
        medium=sum(1 for f in findings if f.severity == "medium"),
        low=sum(1 for f in findings if f.severity == "low"),
        informational=sum(1 for f in findings if f.severity == "informational"),
        confirmed=sum(1 for f in findings if f.confidence == "confirmed"),
        potential=sum(1 for f in findings if f.confidence == "potential"),
        source_findings=source_findings,
        runtime_findings=runtime_findings,
        evidence_count=evidence_count,
        categories=categories,
        components=components,
    )


@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding(finding_id: str, db: Session = Depends(get_db)):
    """Get a specific finding."""
    finding = db.query(Finding).filter(
        (Finding.id == finding_id) | (Finding.finding_id == finding_id)
    ).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    return FindingResponse(
        id=finding.id,
        finding_id=finding.finding_id,
        project_id=finding.project_id,
        scan_id=finding.scan_id,
        title=finding.title,
        severity=finding.severity,
        confidence=finding.confidence,
        status=finding.status,
        category=finding.category,
        cvss_score=finding.cvss_score,
        cvss_vector=finding.cvss_vector,
        cvss_details=finding.cvss_details,
        cwe_id=finding.cwe_id,
        cwe_name=finding.cwe_name,
        affected_component=finding.affected_component,
        affected_file=finding.affected_file,
        affected_line=finding.affected_line,
        affected_endpoint=finding.affected_endpoint,
        description=finding.description,
        technical_details=finding.technical_details,
        code_snippet=finding.code_snippet,
        rule_id=finding.rule_id,
        steps_to_reproduce=finding.steps_to_reproduce,
        poc=finding.poc,
        impact=finding.impact,
        root_cause=finding.root_cause,
        remediation=finding.remediation,
        retest_procedure=finding.retest_procedure,
        scanner_source=finding.scanner_source,
        is_ai_assisted=finding.is_ai_assisted,
        evidence_count=len(finding.evidence_items) if finding.evidence_items else 0,
        created_at=finding.created_at,
        updated_at=finding.updated_at,
    )


@router.put("/{finding_id}", response_model=FindingResponse)
def update_finding(finding_id: str, update: FindingUpdate, db: Session = Depends(get_db)):
    """Update a finding's status or details."""
    finding = db.query(Finding).filter(
        (Finding.id == finding_id) | (Finding.finding_id == finding_id)
    ).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    update_data = update.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(finding, key, value)

    finding.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(finding)

    return FindingResponse(
        id=finding.id,
        finding_id=finding.finding_id,
        project_id=finding.project_id,
        scan_id=finding.scan_id,
        title=finding.title,
        severity=finding.severity,
        confidence=finding.confidence,
        status=finding.status,
        category=finding.category,
        cvss_score=finding.cvss_score,
        cvss_vector=finding.cvss_vector,
        cvss_details=finding.cvss_details,
        cwe_id=finding.cwe_id,
        cwe_name=finding.cwe_name,
        affected_component=finding.affected_component,
        affected_file=finding.affected_file,
        affected_line=finding.affected_line,
        affected_endpoint=finding.affected_endpoint,
        description=finding.description,
        technical_details=finding.technical_details,
        code_snippet=finding.code_snippet,
        rule_id=finding.rule_id,
        steps_to_reproduce=finding.steps_to_reproduce,
        poc=finding.poc,
        impact=finding.impact,
        root_cause=finding.root_cause,
        remediation=finding.remediation,
        retest_procedure=finding.retest_procedure,
        scanner_source=finding.scanner_source,
        is_ai_assisted=finding.is_ai_assisted,
        evidence_count=len(finding.evidence_items) if finding.evidence_items else 0,
        created_at=finding.created_at,
        updated_at=finding.updated_at,
    )
