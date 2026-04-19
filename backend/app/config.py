"""
Centralised application configuration
"""
from functools import lru_cache
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # App
    ENVIRONMENT: str = "development"
    SECRET_KEY: str = "change-me-in-production"
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8000"]

    # VirusTotal
    VIRUSTOTAL_API_KEY: str
    VIRUSTOTAL_BASE_URL: str = "https://www.virustotal.com/api/v3"
    VT_POLL_INTERVAL_SECONDS: int = 5
    VT_POLL_MAX_ATTEMPTS: int = 24  # 2 minutes max

    # Gemini
    GEMINI_API_KEY: str
    GEMINI_MODEL: str = "gemini-1.5-flash"

    # File Upload
    MAX_FILE_SIZE_BYTES: int = 32 * 1024 * 1024  # 32 MB (VT free tier limit)
    UPLOAD_TEMP_DIR: str = "/tmp/pdfsafe_uploads"  # tmpfs in Docker
    ALLOWED_MIME_TYPES: List[str] = [
        "application/pdf",
        "application/zip",
        "application/x-zip-compressed",
        "application/x-tar",
        "application/gzip",
        "application/x-7z-compressed",
        "application/vnd.ms-excel",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "text/plain",
        "image/png",
        "image/jpeg",
        "image/gif",
        "application/octet-stream",
    ]

    # Rate Limiting
    RATE_LIMIT_UPLOAD: str = "10/minute"
    RATE_LIMIT_EXPLAIN: str = "20/minute"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
