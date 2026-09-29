"""
Scans API - Security scan management and execution
"""
import asyncio
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.scan import Scan, ScanType, ScanStatus
from app.models.project import Project

router = APIRouter(prefix="/api/scans", tags=["scans"])


# --- Pydantic Schemas ---

class ScanCreate(BaseModel):
    project_id: str
    scan_type: str = "full"
    scan_config: Optional[dict] = None


class ScanResponse(BaseModel):
    id: str
    project_id: str
    scan_type: str
    status: str
    progress: int
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    duration_seconds: Optional[int]
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    error_message: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


# --- Scan Execution ---

async def run_scan_task(scan_id: str, project_id: str, scan_type: str, scan_config: dict = None):
    """Background task to execute a security scan."""
    from app.database import SessionLocal
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.utcnow()
        db.commit()

        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            scan.status = ScanStatus.FAILED
            scan.error_message = "Project not found"
            db.commit()
            return

        # Import scanner engine
        from app.scanners.engine import ScanEngine
        engine = ScanEngine(db, project, scan)

        try:
            if scan_type == ScanType.FULL:
                await engine.run_full_scan()
            elif scan_type == ScanType.SOURCE_CODE:
                await engine.run_source_scan()
            elif scan_type == ScanType.HEADERS:
                await engine.run_headers_scan()
            elif scan_type == ScanType.CORS:
                await engine.run_cors_scan()
            elif scan_type == ScanType.SECRETS:
                await engine.run_secrets_scan()
            elif scan_type == ScanType.DEPENDENCIES:
                await engine.run_dependency_scan()
            elif scan_type == ScanType.AUTHENTICATION:
                await engine.run_auth_scan()
            elif scan_type == ScanType.API_SECURITY:
                await engine.run_api_scan()
            elif scan_type == ScanType.INPUT_VALIDATION:
                await engine.run_input_scan()
            else:
                await engine.run_full_scan()

            # Update scan completion
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.utcnow()
            if scan.started_at:
                scan.duration_seconds = int(
                    (scan.completed_at - scan.started_at).total_seconds()
                )

            # Count findings
            from app.models.finding import Finding
            findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
            scan.total_findings = len(findings)
            scan.critical_count = sum(1 for f in findings if f.severity == "critical")
            scan.high_count = sum(1 for f in findings if f.severity == "high")
            scan.medium_count = sum(1 for f in findings if f.severity == "medium")
            scan.low_count = sum(1 for f in findings if f.severity == "low")
            scan.info_count = sum(1 for f in findings if f.severity == "informational")
            scan.progress = 100

        except Exception as e:
            scan.status = ScanStatus.FAILED
            scan.error_message = str(e)
            scan.completed_at = datetime.utcnow()

        db.commit()
    finally:
        db.close()


# --- Routes ---

@router.get("/", response_model=List[ScanResponse])
def list_scans(
    project_id: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """List all scans, optionally filtered."""
    query = db.query(Scan)
    if project_id:
        query = query.filter(Scan.project_id == project_id)
    if status:
        query = query.filter(Scan.status == status)
    return query.order_by(Scan.created_at.desc()).all()


@router.post("/", response_model=ScanResponse, status_code=201)
async def create_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Create and start a new security scan."""
    # Verify project exists
    project = db.query(Project).filter(Project.id == scan_data.project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Create scan record
    scan = Scan(
        project_id=scan_data.project_id,
        scan_type=scan_data.scan_type,
        scan_config=scan_data.scan_config,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Start scan in background
    background_tasks.add_task(
        run_scan_task,
        scan.id,
        scan_data.project_id,
        scan_data.scan_type,
        scan_data.scan_config,
    )

    return scan


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    """Get scan details."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
def cancel_scan(scan_id: str, db: Session = Depends(get_db)):
    """Cancel a running scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status not in [ScanStatus.PENDING, ScanStatus.RUNNING]:
        raise HTTPException(status_code=400, detail="Scan cannot be cancelled")

    scan.status = ScanStatus.CANCELLED
    scan.completed_at = datetime.utcnow()
    db.commit()
    db.refresh(scan)
    return scan
