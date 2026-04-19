"""
Integration tests for the scan API endpoints.
VirusTotal and Gemini calls are mocked
"""
import pytest
import io
from unittest.mock import patch
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.controllers import scan_controller
from app.models.scan import (
    ScanResult, ScanStatus, ThreatLevel, ScanStats, UploadResponse,
)


@pytest.fixture(autouse=True)
def clear_scan_cache():
    scan_controller._scan_cache.clear()


MOCK_ANALYSIS_ID = "dGVzdC1hbmFseXNpcy1pZA=="

MOCK_COMPLETED_RESULT = ScanResult(
    analysis_id=MOCK_ANALYSIS_ID,
    status=ScanStatus.COMPLETED,
    file_name="eicar.pdf",
    file_size=68,
    threat_level=ThreatLevel.MALICIOUS,
    stats=ScanStats(malicious=60, undetected=10, total=70),
)


@pytest.fixture
def pdf_bytes():
    """Minimal valid PDF magic bytes for testing."""
    return b"%PDF-1.4 fake content for testing purposes only"


@pytest.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac


class TestHealthEndpoint:
    @pytest.mark.asyncio
    async def test_health_returns_ok(self, client):
        response = await client.get("/api/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"


class TestUploadEndpoint:
    @pytest.mark.asyncio
    @patch("app.services.file_validator.validate_and_save")
    @patch("app.services.virustotal.submit_file")
    async def test_upload_success(self, mock_submit, mock_validate, client, pdf_bytes, tmp_path):
        temp_file = tmp_path / "test.pdf"
        temp_file.write_bytes(pdf_bytes)

        mock_validate.return_value = (temp_file, "test.pdf", len(pdf_bytes))
        mock_submit.return_value = MOCK_ANALYSIS_ID

        response = await client.post(
            "/api/upload",
            files={"file": ("test.pdf", io.BytesIO(pdf_bytes), "application/pdf")},
        )

        assert response.status_code == 202
        data = response.json()
        assert "analysis_id" in data
        assert data["analysis_id"] == MOCK_ANALYSIS_ID

    @pytest.mark.asyncio
    async def test_upload_empty_file_rejected(self, client):
        response = await client.post(
            "/api/upload",
            files={"file": ("empty.pdf", io.BytesIO(b""), "application/pdf")},
        )
        assert response.status_code in (400, 422, 500)

    @pytest.mark.asyncio
    async def test_upload_no_file_rejected(self, client):
        response = await client.post("/api/upload")
        assert response.status_code == 422


class TestScanResultEndpoint:
    @pytest.mark.asyncio
    @patch("app.services.virustotal.get_analysis")
    async def test_poll_completed_result(self, mock_get, client):
        mock_get.return_value = MOCK_COMPLETED_RESULT

        response = await client.get(f"/api/scan/{MOCK_ANALYSIS_ID}")
        assert response.status_code == 200
        data = response.json()["result"]
        assert data["status"] == "completed"
        assert data["threat_level"] == "malicious"

    @pytest.mark.asyncio
    @patch("app.services.virustotal.get_analysis")
    async def test_poll_still_pending(self, mock_get, client):
        mock_get.return_value = None  # Still processing

        response = await client.get(f"/api/scan/{MOCK_ANALYSIS_ID}")
        assert response.status_code == 200
        data = response.json()["result"]
        assert data["status"] == "pending"

    @pytest.mark.asyncio
    async def test_invalid_analysis_id_rejected(self, client):
        response = await client.get("/api/scan/../../../etc/passwd")
        assert response.status_code in (400, 404, 422)


class TestExplainEndpoint:
    @pytest.mark.asyncio
    @patch("app.services.gemini.explain_scan")
    async def test_explain_completed_scan(self, mock_explain, client):
        from app.models.scan import ExplainResponse
        mock_explain.return_value = ExplainResponse(
            explanation="This file is dangerous.",
            threat_level=ThreatLevel.MALICIOUS,
            recommended_action="Delete immediately.",
        )

        payload = {
            "analysis_id": MOCK_ANALYSIS_ID,
            "scan_result": MOCK_COMPLETED_RESULT.model_dump(),
        }
        response = await client.post("/api/explain", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert "explanation" in data
        assert "recommended_action" in data

    @pytest.mark.asyncio
    async def test_explain_pending_scan_rejected(self, client):
        pending_result = ScanResult(
            analysis_id=MOCK_ANALYSIS_ID,
            status=ScanStatus.PENDING,
            file_name="test.pdf",
            file_size=100,
        )
        payload = {
            "analysis_id": MOCK_ANALYSIS_ID,
            "scan_result": pending_result.model_dump(),
        }
        response = await client.post("/api/explain", json=payload)
        assert response.status_code == 400
