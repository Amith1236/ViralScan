"""
ViralScan - FastAPI Application Entry Point
"""
import structlog
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.config import settings
from app.middleware.logging import LoggingMiddleware
from app.middleware.security import SecurityHeadersMiddleware
from app.controllers import scan_controller, health_controller
from app.middleware.rate_limiter import limiter

log = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("viralscan.startup", env=settings.ENVIRONMENT)
    yield
    log.info("viralscan.shutdown")


def create_app() -> FastAPI:
    app = FastAPI(
        title="ViralScan",
        description="Secure file scanning powered by VirusTotal + Gemini AI",
        version="1.0.0",
        docs_url="/api/docs" if settings.ENVIRONMENT != "production" else None,
        redoc_url=None,
        lifespan=lifespan,
    )

    # Rate limiter state
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # Middleware (applied in reverse order — last added = outermost)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(LoggingMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )

    # API routers
    app.include_router(health_controller.router, prefix="/api")
    app.include_router(scan_controller.router, prefix="/api")

    # Serve frontend static files
    # app.mount("/static", StaticFiles(directory="/app/frontend/static"), name="static")

    # @app.get("/{full_path:path}", include_in_schema=False)
    # async def serve_frontend(full_path: str):
    #     return FileResponse("/app/frontend/templates/index.html")

    return app


app = create_app()
