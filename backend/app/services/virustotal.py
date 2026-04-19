"""
VirusTotal Service
"""
import asyncio
import hashlib
import structlog
from pathlib import Path
from typing import Optional

import httpx

from app.config import settings
from app.models.scan import (
    ScanResult, ScanStats, ScanStatus, ThreatLevel, EngineResult,
)

log = structlog.get_logger()

VT_HEADERS = {
    "x-apikey": settings.VIRUSTOTAL_API_KEY,
    "Accept": "application/json",
}


def _classify_threat(stats: ScanStats) -> ThreatLevel:
    """Derive a simple threat level from engine vote counts."""
    if stats.malicious >= 3:
        return ThreatLevel.MALICIOUS
    if stats.malicious >= 1 or stats.suspicious >= 3:
        return ThreatLevel.SUSPICIOUS
    if stats.total > 0:
        return ThreatLevel.CLEAN
    return ThreatLevel.UNKNOWN


def _parse_stats(raw: dict) -> ScanStats:
    s = raw.get("stats", {})
    total = sum(s.get(k, 0) for k in
                ["malicious", "suspicious", "undetected", "harmless", "timeout", "failure"])
    return ScanStats(
        malicious=s.get("malicious", 0),
        suspicious=s.get("suspicious", 0),
        undetected=s.get("undetected", 0),
        harmless=s.get("harmless", 0),
        timeout=s.get("timeout", 0),
        failure=s.get("failure", 0),
        total=total,
    )


def _parse_engines(results: dict) -> dict[str, EngineResult]:
    engines = {}
    for engine_name, data in results.items():
        engines[engine_name] = EngineResult(
            engine_name=engine_name,
            category=data.get("category", "unknown"),
            result=data.get("result"),
            method=data.get("method"),
        )
    return engines


async def submit_file(file_path: Path, file_name: str) -> str:
    """
    Upload a file to VirusTotal.
    Returns the analysis_id for subsequent polling.
    Streams the file directly
    """
    log.info("vt.submit_file", file_name=file_name, size=file_path.stat().st_size)

    async with httpx.AsyncClient(timeout=60.0) as client:
        with open(file_path, "rb") as fh:
            files = {"file": (file_name, fh, "application/octet-stream")}
            response = await client.post(
                f"{settings.VIRUSTOTAL_BASE_URL}/files",
                headers=VT_HEADERS,
                files=files,
            )

        if response.status_code == 429:
            raise RateLimitError("VirusTotal rate limit reached. Please wait a moment.")
        if response.status_code not in (200, 201):
            log.error("vt.submit_failed", status=response.status_code, body=response.text)
            raise VirusTotalError(f"VirusTotal rejected the file (HTTP {response.status_code})")

        data = response.json()
        analysis_id = data["data"]["id"]
        log.info("vt.submit_ok", analysis_id=analysis_id)
        return analysis_id


async def get_analysis(analysis_id: str) -> ScanResult | None:
    """
    Poll VirusTotal for analysis results.
    Returns None if still queued or in progress.
     - Some files take several minutes to scan
    """
    log.debug("vt.poll", analysis_id=analysis_id)

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(
            f"{settings.VIRUSTOTAL_BASE_URL}/analyses/{analysis_id}",
            headers=VT_HEADERS,
        )

    if response.status_code == 404:
        raise VirusTotalError("Analysis not found - the ID may be invalid.")
    if response.status_code != 200:
        raise VirusTotalError(f"VirusTotal polling error (HTTP {response.status_code})")

    data = response.json()
    attributes = data["data"]["attributes"]
    status = attributes.get("status", "queued")

    if status not in ("completed",):
        return None  # Still processing

    stats = _parse_stats(attributes)
    engines = _parse_engines(attributes.get("results", {}))
    threat = _classify_threat(stats)

    # Pull file metadata from meta block if available
    meta = data.get("meta", {}).get("file_info", {})

    return ScanResult(
        analysis_id=analysis_id,
        status=ScanStatus.COMPLETED,
        file_name=meta.get("name", "unknown"),
        file_size=meta.get("size", 0),
        sha256=meta.get("sha256"),
        md5=meta.get("md5"),
        threat_level=threat,
        stats=stats,
        engines=engines,
        raw_attributes=attributes,
    )


async def poll_until_complete(
    analysis_id: str,
    file_name: str,
    file_size: int,
) -> ScanResult:
    """
    Blocking poll loop
    """
    for attempt in range(settings.VT_POLL_MAX_ATTEMPTS):
        result = await get_analysis(analysis_id)
        if result is not None:
            # Backfill file metadata not in VT analysis response
            result.file_name = file_name
            result.file_size = file_size
            return result

        log.debug("vt.still_processing", attempt=attempt, analysis_id=analysis_id)
        await asyncio.sleep(settings.VT_POLL_INTERVAL_SECONDS)

    raise VirusTotalError("Scan timed out - VirusTotal took too long to respond.")


def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# Custom Exceptions

class VirusTotalError(Exception):
    pass


class RateLimitError(VirusTotalError):
    pass
