"""
Tests for the file validation service.
"""

from app.services.file_validator import sanitise_filename, detect_mime_type


class TestSanitiseFilename:
    def test_strips_path_traversal(self):
        assert sanitise_filename("../../etc/passwd") == "passwd"

    def test_strips_path_traversal_windows(self):
        assert sanitise_filename(r"C:\Windows\System32\evil.exe") == "evil.exe"

    def test_collapses_double_extension(self):
        result = sanitise_filename("invoice.pdf.exe")
        assert ".." not in result

    def test_removes_special_chars(self):
        result = sanitise_filename("my file (1) <script>.pdf")
        assert "<" not in result
        assert ">" not in result
        assert "(" not in result

    def test_truncates_long_name(self):
        long_name = "a" * 300 + ".pdf"
        assert len(sanitise_filename(long_name)) <= 255

    def test_preserves_normal_filename(self):
        assert sanitise_filename("report-2024.pdf") == "report-2024.pdf"

    def test_empty_filename_returns_default(self):
        result = sanitise_filename("")
        assert result == "upload"


class TestDetectMimeType:
    def test_detects_pdf(self):
        header = b"%PDF-1.4 " + b"\x00" * 8
        assert detect_mime_type(header) == "application/pdf"

    def test_detects_zip(self):
        header = b"PK\x03\x04" + b"\x00" * 12
        assert detect_mime_type(header) == "application/zip"

    def test_detects_png(self):
        header = b"\x89PNG\r\n\x1a\n" + b"\x00" * 8
        assert detect_mime_type(header) == "image/png"

    def test_detects_jpeg(self):
        header = b"\xff\xd8\xff\xe0" + b"\x00" * 12
        assert detect_mime_type(header) == "image/jpeg"

    def test_detects_exe(self):
        header = b"MZ" + b"\x00" * 14
        assert detect_mime_type(header) == "application/x-dosexec"

    def test_unknown_returns_octet_stream(self):
        header = b"\xde\xad\xbe\xef" + b"\x00" * 12
        assert detect_mime_type(header) == "application/octet-stream"
