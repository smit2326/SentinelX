import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.logger import logger
from app.db.seed_data import init_and_seed_db

# Routers
from app.api.v1.auth import router as auth_router
from app.api.v1.users import router as users_router
from app.api.v1.assets import router as assets_router
from app.api.v1.vulnerabilities import router as vulns_router
from app.api.v1.alerts import router as alerts_router
from app.api.v1.audit_logs import router as audit_router
from app.api.v1.config import router as config_router
from app.api.v1.reports import router as reports_router
from app.api.v1.telemetry import router as telemetry_router
from app.api.v1.network import router as network_router
from app.api.v1.openvas import router as openvas_router
from app.api.v1.cleaning import router as cleaning_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting {settings.PROJECT_NAME} v{settings.PROJECT_VERSION}...")
    # Initialize DB & Seed Data
    try:
        await init_and_seed_db()
    except Exception as e:
        logger.error(f"Error during database initialization: {e}")
    yield
    logger.info(f"Shutting down {settings.PROJECT_NAME}...")

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.PROJECT_VERSION,
    description="SENTINEL-X Enterprise Cybersecurity & Unified Threat Intelligence Platform",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API v1 Routers
app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(users_router, prefix=settings.API_V1_STR)
app.include_router(assets_router, prefix=settings.API_V1_STR)
app.include_router(vulns_router, prefix=settings.API_V1_STR)
app.include_router(alerts_router, prefix=settings.API_V1_STR)
app.include_router(audit_router, prefix=settings.API_V1_STR)
app.include_router(config_router, prefix=settings.API_V1_STR)
app.include_router(reports_router, prefix=settings.API_V1_STR)
app.include_router(telemetry_router, prefix=settings.API_V1_STR)
app.include_router(network_router, prefix=settings.API_V1_STR)
app.include_router(openvas_router, prefix=settings.API_V1_STR)
app.include_router(cleaning_router, prefix=settings.API_V1_STR)

@app.get("/api/health", tags=["Health"])
async def health_check():
    return {"status": "HEALTHY", "timestamp": "2026-09-14T20:10:00Z"}

@app.get("/api/info", tags=["Health"])
async def api_info():
    return {
        "platform": settings.PROJECT_NAME,
        "version": settings.PROJECT_VERSION,
        "status": "OPERATIONAL",
        "docs": "/docs",
        "api_v1": settings.API_V1_STR
    }

# Serve compiled frontend UI on port 8000 if dist exists
from pathlib import Path
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

frontend_dist = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"

if frontend_dist.exists():
    assets_dir = frontend_dist / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        file_path = frontend_dist / full_path
        if full_path and file_path.is_file():
            return FileResponse(file_path)
        return FileResponse(frontend_dist / "index.html")
else:
    @app.get("/", tags=["Health"])
    async def root():
        return {
            "platform": settings.PROJECT_NAME,
            "version": settings.PROJECT_VERSION,
            "status": "OPERATIONAL",
            "docs": "/docs",
            "api_v1": settings.API_V1_STR
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
