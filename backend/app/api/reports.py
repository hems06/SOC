"""
Reports API - Report generation and export
"""
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.project import Project
from app.models.finding import Finding
from app.models.evidence import Evidence
from app.models.scan import Scan

router = APIRouter(prefix="/api/reports", tags=["reports"])


class ReportRequest(BaseModel):
    project_id: str
    format: str = "html"  # html, markdown
    include_evidence: bool = True
    include_remediation: bool = True
    redact_secrets: bool = True


@router.post("/generate")
def generate_report(request: ReportRequest, db: Session = Depends(get_db)):
    """Generate a security assessment report."""
    project = db.query(Project).filter(Project.id == request.project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    findings = db.query(Finding).filter(
        Finding.project_id == request.project_id
    ).order_by(Finding.severity).all()

    scans = db.query(Scan).filter(
        Scan.project_id == request.project_id
    ).all()

    from app.reports.generator import ReportGenerator
    generator = ReportGenerator(project, findings, scans, db)

    if request.format == "markdown":
        content = generator.generate_markdown(
            include_evidence=request.include_evidence,
            redact_secrets=request.redact_secrets,
        )
        return PlainTextResponse(content, media_type="text/markdown")
    else:
        content = generator.generate_html(
            include_evidence=request.include_evidence,
            redact_secrets=request.redact_secrets,
        )
        return HTMLResponse(content)


@router.get("/summary/{project_id}")
def get_report_summary(project_id: str, db: Session = Depends(get_db)):
    """Get a quick report summary."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    findings = db.query(Finding).filter(Finding.project_id == project_id).all()
    scans = db.query(Scan).filter(Scan.project_id == project_id).all()

    return {
        "project": project.name,
        "target": project.target_url,
        "status": project.status,
        "total_scans": len(scans),
        "completed_scans": sum(1 for s in scans if s.status == "completed"),
        "total_findings": len(findings),
        "by_severity": {
            "critical": sum(1 for f in findings if f.severity == "critical"),
            "high": sum(1 for f in findings if f.severity == "high"),
            "medium": sum(1 for f in findings if f.severity == "medium"),
            "low": sum(1 for f in findings if f.severity == "low"),
            "informational": sum(1 for f in findings if f.severity == "informational"),
        },
        "by_confidence": {
            "confirmed": sum(1 for f in findings if f.confidence == "confirmed"),
            "potential": sum(1 for f in findings if f.confidence == "potential"),
            "informational": sum(1 for f in findings if f.confidence == "informational"),
        },
        "generated_at": datetime.utcnow().isoformat(),
    }
