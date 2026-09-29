"""
Projects API - CRUD operations for assessment projects
"""
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.project import Project, ProjectStatus

router = APIRouter(prefix="/api/projects", tags=["projects"])


# --- Pydantic Schemas ---

class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = None
    target_url: str
    source_repo: Optional[str] = None
    local_source_path: Optional[str] = None
    scope: Optional[str] = None
    authorization_notes: Optional[str] = None


class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    target_url: Optional[str] = None
    source_repo: Optional[str] = None
    local_source_path: Optional[str] = None
    scope: Optional[str] = None
    authorization_notes: Optional[str] = None
    status: Optional[str] = None


class ProjectResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    target_url: str
    source_repo: Optional[str]
    local_source_path: Optional[str]
    scope: Optional[str]
    authorization_notes: Optional[str]
    status: str
    created_at: datetime
    updated_at: datetime
    scan_count: int = 0
    finding_count: int = 0

    class Config:
        from_attributes = True


# --- Routes ---

@router.get("/", response_model=List[ProjectResponse])
def list_projects(
    status: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """List all assessment projects."""
    query = db.query(Project)
    if status:
        query = query.filter(Project.status == status)
    projects = query.order_by(Project.created_at.desc()).all()

    result = []
    for p in projects:
        result.append(ProjectResponse(
            id=p.id,
            name=p.name,
            description=p.description,
            target_url=p.target_url,
            source_repo=p.source_repo,
            local_source_path=p.local_source_path,
            scope=p.scope,
            authorization_notes=p.authorization_notes,
            status=p.status,
            created_at=p.created_at,
            updated_at=p.updated_at,
            scan_count=len(p.scans) if p.scans else 0,
            finding_count=len(p.findings) if p.findings else 0,
        ))
    return result


@router.post("/", response_model=ProjectResponse, status_code=201)
def create_project(project: ProjectCreate, db: Session = Depends(get_db)):
    """Create a new assessment project."""
    db_project = Project(
        name=project.name,
        description=project.description,
        target_url=project.target_url,
        source_repo=project.source_repo,
        local_source_path=project.local_source_path,
        scope=project.scope,
        authorization_notes=project.authorization_notes,
    )
    db.add(db_project)
    db.commit()
    db.refresh(db_project)

    return ProjectResponse(
        id=db_project.id,
        name=db_project.name,
        description=db_project.description,
        target_url=db_project.target_url,
        source_repo=db_project.source_repo,
        local_source_path=db_project.local_source_path,
        scope=db_project.scope,
        authorization_notes=db_project.authorization_notes,
        status=db_project.status,
        created_at=db_project.created_at,
        updated_at=db_project.updated_at,
    )


@router.get("/{project_id}", response_model=ProjectResponse)
def get_project(project_id: str, db: Session = Depends(get_db)):
    """Get a specific project by ID."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    return ProjectResponse(
        id=project.id,
        name=project.name,
        description=project.description,
        target_url=project.target_url,
        source_repo=project.source_repo,
        local_source_path=project.local_source_path,
        scope=project.scope,
        authorization_notes=project.authorization_notes,
        status=project.status,
        created_at=project.created_at,
        updated_at=project.updated_at,
        scan_count=len(project.scans) if project.scans else 0,
        finding_count=len(project.findings) if project.findings else 0,
    )


@router.put("/{project_id}", response_model=ProjectResponse)
def update_project(project_id: str, update: ProjectUpdate, db: Session = Depends(get_db)):
    """Update a project."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    update_data = update.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(project, key, value)

    project.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(project)

    return ProjectResponse(
        id=project.id,
        name=project.name,
        description=project.description,
        target_url=project.target_url,
        source_repo=project.source_repo,
        local_source_path=project.local_source_path,
        scope=project.scope,
        authorization_notes=project.authorization_notes,
        status=project.status,
        created_at=project.created_at,
        updated_at=project.updated_at,
        scan_count=len(project.scans) if project.scans else 0,
        finding_count=len(project.findings) if project.findings else 0,
    )


@router.delete("/{project_id}", status_code=204)
def delete_project(project_id: str, db: Session = Depends(get_db)):
    """Delete a project and all related data."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    db.delete(project)
    db.commit()
