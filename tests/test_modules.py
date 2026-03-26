"""Tests for G-CEDD modules."""

import pytest
from pathlib import Path

from g_cedd.modules.secret_analyzer import analyze_file, analyze_directory
from g_cedd.modules.path_checker import PathResult
from g_cedd.modules.workspace import _sanitize_target, create_target_workspace


class TestSecretAnalyzer:
    """Test secret analysis functionality."""

    def test_analyze_file_no_secrets(self, tmp_path):
        """Test analyzing a file with no secrets."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("This is just normal text with no secrets.")

        findings = analyze_file(str(test_file))
        assert findings == []

    def test_analyze_file_with_secret(self, tmp_path):
        """Test analyzing a file with a secret."""
        test_file = tmp_path / "test.env"
        test_file.write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")

        findings = analyze_file(str(test_file))
        assert len(findings) == 1
        assert findings[0].secret_type == "AWS Access Key ID"
        assert "AKIAIOSFODNN7EXAMPLE" in findings[0].matched_value

    def test_analyze_directory(self, tmp_path):
        """Test analyzing a directory."""
        # Create test files
        (tmp_path / "normal.txt").write_text("Normal text")
        (tmp_path / ".env").write_text("SECRET_KEY=sk_test_1234567890")

        findings = analyze_directory(str(tmp_path))
        assert len(findings) == 1
        assert findings[0].secret_type == "Stripe Test Key"


class TestWorkspace:
    """Test workspace management functionality."""

    def test_sanitize_target(self):
        """Test URL sanitization for directory names."""
        assert _sanitize_target("https://example.com") == "example_com"
        assert _sanitize_target("http://test.example.com/path") == "test_example_com_path"
        assert _sanitize_target("example.com:8080") == "example_com_8080"

    def test_create_target_workspace(self, tmp_path):
        """Test workspace creation."""
        workspace = create_target_workspace("https://example.com", base_dir=tmp_path)
        assert workspace.exists()
        assert workspace.name.startswith("example_com_")
        assert (workspace / "extracted").exists()


class TestPathResult:
    """Test PathResult dataclass."""

    def test_path_result_to_dict(self):
        """Test PathResult serialization."""
        result = PathResult(
            path="/.env",
            status_code=200,
            content_length=1024,
            content_type="text/plain",
            content_snippet="DB_PASSWORD=secret123",
            severity="high",
            exposed=True,
        )

        data = result.to_dict()
        assert data["path"] == "/.env"
        assert data["status_code"] == 200
        assert data["severity"] == "high"
        assert data["exposed"] is True