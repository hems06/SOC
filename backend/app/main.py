"""
World Monitor Security Assessment Platform - Main Application
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os
import sys
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


if hasattr(sys, '_MEIPASS'):
    frontend_build_dir = os.path.join(sys._MEIPASS, 'frontend', 'dist')
else:
    frontend_build_dir = os.path.join(os.path.dirname(__file__), "../../frontend/dist")

@app.get("/")
async def serve_frontend():
    return FileResponse(os.path.join(frontend_build_dir, "index.html"))

# Mount static files (this will catch any remaining routes that aren't defined above)
app.mount("/", StaticFiles(directory=frontend_build_dir), name="static")


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
