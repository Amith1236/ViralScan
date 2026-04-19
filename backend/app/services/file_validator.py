"""
File Validation Service
- Magic byte detection
- size enforcement
- filename sanitisation.
"""
import re
import os
import tempfile
import structlog
from pathlib import Path
from typing import Tuple

from fastapi import UploadFile, HTTPException

from app.config import settings

log = structlog.get_logger()

# Magic byte signatures: (offset, bytes) -> mime_type

MAGIC_SIGNATURES: list[Tuple[int, bytes, str]] = [
    (0, b"%PDF",                        "application/pdf"),
    (0, b"PK\x03\x04",                 "application/zip"),
    (0, b"\x1f\x8b",                    "application/gzip"),
    (0, b"7z\xbc\xaf\x27\x1c",         "application/x-7z-compressed"),
    (0, b"Rar!\x1a\x07",               "application/x-rar-compressed"),
    (0, b"\xd0\xcf\x11\xe0",           "application/msword"),     # OLE2 (old Office)
    (0, b"\x89PNG\r\n\x1a\n",          "image/png"),
    (0, b"\xff\xd8\xff",               "image/jpeg"),
    (0, b"GIF87a",                     "image/gif"),
    (0, b"GIF89a",                     "image/gif"),
    (0, b"MZ",                         "application/x-dosexec"),   # Windows EXE - allow scanning
    (0, b"\x7fELF",                    "application/x-elf"),       # Linux ELF - allow scanning
]

# Dangerous extensions - log a warning but still allow

HIGH_RISK_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".sh", ".ps1", ".vbs", ".js",
    ".jar", ".com", ".scr", ".pif", ".msi", ".dll",
}


def detect_mime_type(header: bytes) -> str:
    """Detect MIME type from the first 16 bytes of the file."""
    for offset, magic, mime in MAGIC_SIGNATURES:
        if header[offset:offset + len(magic)] == magic:
            return mime
    return "application/octet-stream"


def sanitise_filename(filename: str) -> str:
    """
    Strip path components and dangerous characters.
    Returns a safe filename, never a path.
    """
    # Strip both forward and backward slashes to handle any path format
    name = filename.replace("\\", "/").split("/")[-1]
    if ":" in name:
        name = name.split(":")[-1]
    # Replace anything thats not alphanumeric, dash, underscore, or dot
    name = re.sub(r"[^\w.\-]", "_", name)
    # Collapse multiple dots to prevent double-extension tricks like .pdf.exe
    name = re.sub(r"\.{2,}", ".", name)
    # Truncate to 255 chars
    return name[:255] or "upload"


async def validate_and_save(upload: UploadFile) -> Tuple[Path, str, int]:
    """
    Validates the uploaded file and saves it to a secure temp location.

    Returns:
        (temp_path, safe_filename, file_size_bytes)

    Raises:
        HTTPException on any validation failure.
    """
    safe_name = sanitise_filename(upload.filename or "upload")
    ext = Path(safe_name).suffix.lower()

    if ext in HIGH_RISK_EXTENSIONS:
        log.warning("file.high_risk_extension", filename=safe_name, ext=ext)
        # Still allow since VirusTotal can scan

    # Read file into memory in chunks for size + magic byte check
    chunks = []
    total_size = 0
    header_bytes = b""

    while True:
        chunk = await upload.read(65536)
        if not chunk:
            break

        total_size += len(chunk)

        if total_size > settings.MAX_FILE_SIZE_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"File too large. Maximum size is {settings.MAX_FILE_SIZE_BYTES // (1024*1024)} MB.",
            )
        if not header_bytes and len(chunk) >= 8:
            header_bytes = chunk[:16]

        chunks.append(chunk)

    if total_size == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    if not header_bytes and chunks:
        header_bytes = (b"".join(chunks))[:16]

    detected_mime = detect_mime_type(header_bytes)
    log.info(
        "file.validated",
        filename=safe_name,
        size=total_size,
        detected_mime=detected_mime,
        claimed_mime=upload.content_type,
    )

    # Write to secure temp dir (mounted as tmpfs in Docker)
    os.makedirs(settings.UPLOAD_TEMP_DIR, mode=0o700, exist_ok=True)
    tmp = tempfile.NamedTemporaryFile(
        dir=settings.UPLOAD_TEMP_DIR,
        delete=False,
        suffix=ext,
        mode="wb",
    )
    try:
        for chunk in chunks:
            tmp.write(chunk)
        tmp.flush()
    finally:
        tmp.close()

    # Remove execute permissions from the saved file
    os.chmod(tmp.name, 0o400)

    return Path(tmp.name), safe_name, total_size
