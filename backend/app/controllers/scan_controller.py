"""
Scan Controller 
 - HTTP layer only
"""
import os
import structlog
from fastapi import APIRouter, UploadFile, File, HTTPException, Request, BackgroundTasks
from fastapi.responses import JSONResponse

from app.middleware.rate_limiter import limiter
from app.config import settings
from app.models.scan import (
    UploadResponse, ScanResultResponse, ExplainRequest,
    ExplainResponse, ScanStatus, ScanResult, ThreatLevel,
)
from app.services import virustotal, gemini, file_validator
from app.services.virustotal import VirusTotalError, RateLimitError

log = structlog.get_logger()
router = APIRouter(tags=["scan"])

# In-memory result cache (swap for Redis in a scaled deployment)
_scan_cache: dict[str, ScanResult] = {}


@router.post("/upload", response_model=UploadResponse, status_code=202)
@limiter.limit(settings.RATE_LIMIT_UPLOAD)
async def upload_file(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
):
    """
    Accept a file upload, validate it, submit to VirusTotal.
    Returns an analysis_id immediately — client polls /scan/{id} for results.
    """
    temp_path = None
    try:
        temp_path, safe_name, file_size = await file_validator.validate_and_save(file)

        analysis_id = await virustotal.submit_file(temp_path, safe_name)

        # Store a pending placeholder
        _scan_cache[analysis_id] = ScanResult(
            analysis_id=analysis_id,
            status=ScanStatus.PENDING,
            file_name=safe_name,
            file_size=file_size,
            threat_level=ThreatLevel.UNKNOWN,
        )

        # Delete the temp file in the background after submission
        background_tasks.add_task(_cleanup_temp, str(temp_path))

        log.info("upload.accepted", analysis_id=analysis_id, file=safe_name)
        return UploadResponse(analysis_id=analysis_id)

    except HTTPException:
        raise
    except RateLimitError as e:
        raise HTTPException(status_code=429, detail=str(e))
    except VirusTotalError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except Exception as e:
        log.error("upload.error", error=str(e))
        raise HTTPException(status_code=500, detail="An unexpected error occurred during upload.")
    finally:
        # Safety net: if background task hasn't fired, clean up now
        if temp_path and temp_path.exists():
            try:
                os.unlink(temp_path)
            except Exception:
                pass


@router.get("/scan/{analysis_id}", response_model=ScanResultResponse)
async def get_scan_result(analysis_id: str, request: Request):
    """
    Poll for scan results. Returns status=pending while VirusTotal is still scanning.
    Frontend polls this until status=completed or failed.
    """
    # Validate analysis_id format to prevent injection
    if not _is_valid_analysis_id(analysis_id):
        raise HTTPException(status_code=400, detail="Invalid analysis ID format.")

    try:
        result = await virustotal.get_analysis(analysis_id)

        if result is None:
            # Still processing — return the cached pending state
            cached = _scan_cache.get(analysis_id)
            if cached:
                return ScanResultResponse(result=cached)
            # Unknown ID
            return ScanResultResponse(result=ScanResult(
                analysis_id=analysis_id,
                status=ScanStatus.PENDING,
                file_name="unknown",
                file_size=0,
            ))

        # Backfill metadata from our cache
        cached = _scan_cache.get(analysis_id)
        if cached:
            result.file_name = cached.file_name
            result.file_size = cached.file_size

        _scan_cache[analysis_id] = result
        return ScanResultResponse(result=result)

    except VirusTotalError as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.post("/explain", response_model=ExplainResponse)
@limiter.limit(settings.RATE_LIMIT_EXPLAIN)
async def explain_results(request: Request, body: ExplainRequest):
    """
    Pass completed scan results to Gemini for a plain-English explanation.
    """
    if body.scan_result.status != ScanStatus.COMPLETED:
        raise HTTPException(
            status_code=400,
            detail="Cannot explain a scan that hasn't completed yet.",
        )

    try:
        explanation = await gemini.explain_scan(body.scan_result)
        log.info("explain.ok", analysis_id=body.analysis_id)
        return explanation
    except Exception as e:
        log.error("explain.error", error=str(e))
        raise HTTPException(status_code=502, detail="AI explanation service is temporarily unavailable.")


# ── Helpers ────────────────────────────────────────────────────────────────

def _is_valid_analysis_id(analysis_id: str) -> bool:
    """Analysis IDs from VirusTotal are base64url-encoded strings."""
    import re
    return bool(re.match(r'^[A-Za-z0-9_\-]{10,200}={0,2}$', analysis_id))


def _cleanup_temp(path: str) -> None:
    """Securely delete a temp file."""
    try:
        os.unlink(path)
        log.debug("cleanup.deleted", path=path)
    except FileNotFoundError:
        pass
    except Exception as e:
        log.warning("cleanup.failed", path=path, error=str(e))
