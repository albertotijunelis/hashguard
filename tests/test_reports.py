"""Tests for HashGuard reports module."""

import csv
import io
import json
from unittest.mock import MagicMock, patch

import pytest

from hashguard.reports import BatchAnalyzer, ReportGenerator


def _make_result(**overrides):
    """Create a mock FileAnalysisResult."""
    r = MagicMock()
    r.path = "/tmp/test.exe"
    r.file_size = 2048
    r.hashes = {"md5": "a" * 32, "sha1": "b" * 40, "sha256": "c" * 64}
    r.malicious = False
    r.description = ""
    r.analysis_time = 0.05
    r.to_dict.return_value = {
        "path": r.path,
        "file_size": r.file_size,
        "hashes": r.hashes,
        "malicious": r.malicious,
    }
    for k, v in overrides.items():
        setattr(r, k, v)
    return r


# ── BatchAnalyzer ────────────────────────────────────────────────────────────


class TestBatchAnalyzer:
    def test_init(self):
        ba = BatchAnalyzer()
        assert ba.results == []

    def test_get_summary_empty(self):
        ba = BatchAnalyzer()
        s = ba.get_summary()
        assert s["total_files"] == 0
        assert s["malicious_count"] == 0
        assert s["malicious_percentage"] == 0

    def test_get_summary_with_results(self):
        ba = BatchAnalyzer()
        ba.results = [
            _make_result(malicious=True, file_size=1000, analysis_time=0.1),
            _make_result(malicious=False, file_size=2000, analysis_time=0.2),
            _make_result(malicious=True, file_size=500, analysis_time=0.05),
        ]
        s = ba.get_summary()
        assert s["total_files"] == 3
        assert s["malicious_count"] == 2
        assert s["clean_count"] == 1
        assert s["total_size_bytes"] == 3500

    @patch("hashguard.reports.analyze")
    def test_analyze_directory(self, mock_analyze, tmp_path):
        (tmp_path / "a.txt").write_text("hello")
        (tmp_path / "b.txt").write_text("world")
        mock_analyze.return_value = _make_result()
        ba = BatchAnalyzer()
        results = ba.analyze_directory(str(tmp_path))
        assert len(results) == 2

    @patch("hashguard.reports.analyze")
    def test_analyze_directory_recursive(self, mock_analyze, tmp_path):
        """Cover recursive rglob (line 56) and analyze call (lines 66-67)."""
        sub = tmp_path / "subdir"
        sub.mkdir()
        (sub / "nested.txt").write_text("data")
        (tmp_path / "root.txt").write_text("data")
        mock_analyze.return_value = _make_result()
        ba = BatchAnalyzer()
        results = ba.analyze_directory(str(tmp_path), recursive=True)
        assert len(results) == 2

    def test_analyze_directory_nonexistent(self, tmp_path):
        ba = BatchAnalyzer()
        results = ba.analyze_directory(str(tmp_path / "nonexistent"))
        assert results == []

    @patch("hashguard.reports.analyze")
    def test_analyze_files(self, mock_analyze):
        mock_analyze.return_value = _make_result()
        ba = BatchAnalyzer()
        results = ba.analyze_files(["/tmp/a.exe", "/tmp/b.exe"])
        assert len(results) == 2

    @patch("hashguard.reports.analyze", side_effect=Exception("fail"))
    def test_analyze_files_handles_errors(self, mock_analyze):
        ba = BatchAnalyzer()
        results = ba.analyze_files(["/tmp/a.exe"])
        assert results == []  # errors are logged, not raised


# ── ReportGenerator ──────────────────────────────────────────────────────────


class TestReportGeneratorJSON:
    def test_json_output(self):
        results = [_make_result(), _make_result(malicious=True)]
        output = ReportGenerator.to_json(results)
        data = json.loads(output)
        assert isinstance(data, list)
        assert len(data) == 2

    def test_json_empty(self):
        output = ReportGenerator.to_json([])
        assert json.loads(output) == []


class TestReportGeneratorCSV:
    def test_csv_output(self):
        results = [_make_result(), _make_result(malicious=True)]
        output = ReportGenerator.to_csv(results)
        reader = csv.reader(io.StringIO(output))
        rows = list(reader)
        assert len(rows) == 3  # header + 2 rows
        assert rows[0][0] == "File Path"
        assert rows[1][5] == "NO"
        assert rows[2][5] == "YES"

    def test_csv_empty(self):
        output = ReportGenerator.to_csv([])
        assert output == ""


class TestReportGeneratorHTML:
    def test_html_output(self):
        results = [_make_result()]
        output = ReportGenerator.to_html(results)
        assert "<!DOCTYPE html>" in output
        assert "HashGuard" in output


class TestBatchAnalyzerNonRecursive:
    """Cover non-recursive glob branch (line 56)."""

    @patch("hashguard.reports.analyze")
    def test_non_recursive_glob(self, mock_analyze, tmp_path):
        sub = tmp_path / "subdir"
        sub.mkdir()
        (sub / "nested.txt").write_text("data")
        (tmp_path / "root.txt").write_text("data")
        mock_analyze.return_value = _make_result()
        ba = BatchAnalyzer()
        results = ba.analyze_directory(str(tmp_path), recursive=False)
        assert len(results) == 1  # only root.txt, not nested


class TestBatchAnalyzerDirectoryException:
    """Cover exception handler in analyze_directory (lines 66-67)."""

    @patch("hashguard.reports.analyze", side_effect=RuntimeError("parse error"))
    def test_analyze_directory_exception(self, mock_analyze, tmp_path):
        (tmp_path / "bad.bin").write_bytes(b"data")
        ba = BatchAnalyzer()
        results = ba.analyze_directory(str(tmp_path))
        assert results == []  # exception logged, not raised
