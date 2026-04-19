"""
Security Headers Middleware
Adding hardened HTTP response headers to every response.
 - Prevent content sniffing and clickjacking
"""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        # Prevent browsers from sniffing content type (critical for file upload apps)
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # Force HTTPS in production
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # Disable referrer leakage
        response.headers["Referrer-Policy"] = "no-referrer"

        # Permissions policy — restrict browser features we don't use
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )

        # Content Security Policy
        # - Tight policy: only our own origin for scripts/styles
        # - No inline scripts (use nonce in production for even tighter CSP)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "  # loosen for dev; tighten with nonce in prod
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )

        return response
