"""
Tests for Pydantic models and threat classification logic.
"""
import pytest
from app.models.scan import ScanStats, ThreatLevel, ScanStatus, ScanResult
from app.services.virustotal import _classify_threat


class TestScanStats:
    def test_detection_rate_zero_engines(self):
        stats = ScanStats(total=0)
        assert stats.detection_rate == 0.0

    def test_detection_rate_all_clean(self):
        stats = ScanStats(undetected=70, harmless=2, total=72)
        assert stats.detection_rate == 0.0

    def test_detection_rate_partial(self):
        stats = ScanStats(malicious=5, undetected=65, total=70)
        assert stats.detection_rate == pytest.approx(7.1, abs=0.1)

    def test_detection_rate_all_malicious(self):
        stats = ScanStats(malicious=70, total=70)
        assert stats.detection_rate == 100.0


class TestClassifyThreat:
    def test_malicious_threshold(self):
        stats = ScanStats(malicious=3, total=70)
        assert _classify_threat(stats) == ThreatLevel.MALICIOUS

    def test_single_malicious_is_suspicious(self):
        stats = ScanStats(malicious=1, total=70)
        assert _classify_threat(stats) == ThreatLevel.SUSPICIOUS

    def test_high_suspicious_count(self):
        stats = ScanStats(suspicious=5, total=70)
        assert _classify_threat(stats) == ThreatLevel.SUSPICIOUS

    def test_clean_file(self):
        stats = ScanStats(undetected=68, harmless=2, total=70)
        assert _classify_threat(stats) == ThreatLevel.CLEAN

    def test_no_engines_is_unknown(self):
        stats = ScanStats(total=0)
        assert _classify_threat(stats) == ThreatLevel.UNKNOWN


class TestScanResult:
    def test_default_threat_level(self):
        result = ScanResult(
            analysis_id="test-id",
            status=ScanStatus.PENDING,
            file_name="test.pdf",
            file_size=1024,
        )
        assert result.threat_level == ThreatLevel.UNKNOWN

    def test_completed_result(self):
        stats = ScanStats(malicious=5, undetected=65, total=70)
        result = ScanResult(
            analysis_id="abc123",
            status=ScanStatus.COMPLETED,
            file_name="evil.pdf",
            file_size=2048,
            threat_level=ThreatLevel.MALICIOUS,
            stats=stats,
        )
        assert result.stats.detection_rate > 0
        assert result.threat_level == ThreatLevel.MALICIOUS
