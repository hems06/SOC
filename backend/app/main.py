"""
World Monitor Security Assessment Platform - Main Application
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from app.config import settings
from app.database import init_db
from app.api import projects, scans, findings, evidence, reports

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Professional security assessment platform for analyzing the World Monitor application",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routes
app.include_router(projects.router)
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(evidence.router)
app.include_router(reports.router)


@app.on_event("startup")
async def startup():
    """Initialize database on startup."""
    init_db()


@app.get("/")
async def root():
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "safe_mode": settings.safe_mode,
        "status": "running",
    }


@app.get("/api/health")
async def health():
    return {"status": "healthy", "safe_mode": settings.safe_mode}


@app.get("/api/config")
async def get_config():
    return {
        "safe_mode": settings.safe_mode,
        "allowed_targets": settings.allowed_targets,
        "target_url": settings.target_url,
        "target_repo": settings.target_repo,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.host, port=settings.port, reload=True)
