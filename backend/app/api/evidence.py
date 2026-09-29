"""
Evidence API - Evidence management for findings
"""
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.evidence import Evidence, EvidenceType
from app.models.finding import Finding

router = APIRouter(prefix="/api/evidence", tags=["evidence"])


class EvidenceResponse(BaseModel):
    id: str
    evidence_id: str
    finding_id: str
    evidence_type: str
    title: Optional[str]
    description: Optional[str]
    content: Optional[str]
    request_method: Optional[str]
    request_url: Optional[str]
    request_headers: Optional[dict]
    request_body: Optional[str]
    response_status: Optional[str]
    response_headers: Optional[dict]
    response_body: Optional[str]
    file_path: Optional[str]
    line_start: Optional[str]
    line_end: Optional[str]
    code_snippet: Optional[str]
    captured_at: datetime
    created_at: datetime

    class Config:
        from_attributes = True


@router.get("/", response_model=List[EvidenceResponse])
def list_evidence(
    finding_id: Optional[str] = Query(None),
    evidence_type: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """List evidence items."""
    query = db.query(Evidence)
    if finding_id:
        query = query.filter(Evidence.finding_id == finding_id)
    if evidence_type:
        query = query.filter(Evidence.evidence_type == evidence_type)
    return query.order_by(Evidence.created_at.desc()).all()


@router.get("/{evidence_id}", response_model=EvidenceResponse)
def get_evidence(evidence_id: str, db: Session = Depends(get_db)):
    """Get specific evidence."""
    evidence = db.query(Evidence).filter(
        (Evidence.id == evidence_id) | (Evidence.evidence_id == evidence_id)
    ).first()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return evidence
