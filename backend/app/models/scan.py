"""
Schemas for request/response validation and domain objects
"""
from enum import Enum
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field


# Enums
class ScanStatus(str, Enum):
    QUEUED = "queued"
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"


class ThreatLevel(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


# VirusTotal Domain Models

class ScanStats(BaseModel):
    """Engine vote tallies from VirusTotal."""
    malicious: int = 0
    suspicious: int = 0
    undetected: int = 0
    harmless: int = 0
    timeout: int = 0
    failure: int = 0
    total: int = 0

    @property
    def detection_rate(self) -> float:
        if self.total == 0:
            return 0.0
        return round((self.malicious + self.suspicious) / self.total * 100, 1)


class EngineResult(BaseModel):
    """Single AV engine result."""
    engine_name: str
    category: str
    result: Optional[str] = None
    method: Optional[str] = None


class ScanResult(BaseModel):
    """Full scan result returned to the frontend."""
    analysis_id: str
    status: ScanStatus
    file_name: str
    file_size: int
    file_type: Optional[str] = None
    sha256: Optional[str] = None
    md5: Optional[str] = None
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    stats: Optional[ScanStats] = None
    engines: Dict[str, EngineResult] = Field(default_factory=dict)
    raw_attributes: Optional[Dict[str, Any]] = None


# API Response Models 
class UploadResponse(BaseModel):
    """Returned immediately after a file is submitted."""
    analysis_id: str
    message: str = "File submitted for scanning"


class ScanResultResponse(BaseModel):
    """Polling endpoint response."""
    result: ScanResult


class ExplainRequest(BaseModel):
    """Request body for the AI explanation endpoint."""
    analysis_id: str
    scan_result: ScanResult


class ExplainResponse(BaseModel):
    """Gemini-generated plain-English explanation."""
    explanation: str
    threat_level: ThreatLevel
    recommended_action: str


class ErrorResponse(BaseModel):
    detail: str
    code: Optional[str] = None
