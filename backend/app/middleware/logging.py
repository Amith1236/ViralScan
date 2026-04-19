"""Structured request logging -> using structlog"""
import time
import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

log = structlog.get_logger()


class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        duration_ms = round((time.perf_counter() - start) * 1000, 2)

        log.info(
            "http.request",
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            duration_ms=duration_ms,
            ip=request.client.host if request.client else "unknown",
        )
        return response
