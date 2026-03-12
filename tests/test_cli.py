"""Tests for HashGuard CLI module."""

import sys
from unittest.mock import patch, MagicMock

import pytest

from hashguard import cli


class TestCLIImport:
    def test_module_imports(self):
        assert hasattr(cli, "main")
        assert hasattr(cli, "analyze_single")
        assert hasattr(cli, "analyze_url_single")
        assert hasattr(cli, "analyze_batch")


class TestPrintResult:
    """Test the _print_result helper produces output to stdout."""

    def _make_result(self, **overrides):
        r = MagicMock()
        r.path = "/tmp/test.exe"
        r.file_size = 1024
        r.hashes = {"md5": "a" * 32, "sha1": "b" * 40, "sha256": "c" * 64}
        r.malicious = False
        r.description = ""
        r.risk_score = {"score": 10, "verdict": "clean", "factors": []}
        r.vt_result = None
        r.threat_intel = None
        r.pe_info = None
        r.yara_matches = None
        r.strings_info = None
        r.analysis_time = 0.05
        for k, v in overrides.items():
            setattr(r, k, v)
        return r

    def test_prints_clean_file(self, capsys):
        result = self._make_result()
        cli._print_result(result)
        captured = capsys.readouterr()
        assert "CLEAN" in captured.out
        assert "c" * 64 in captured.out

    def test_prints_malicious_file(self, capsys):
        result = self._make_result(malicious=True, description="Trojan detected")
        cli._print_result(result)
        captured = capsys.readouterr()
        assert "MALICIOUS" in captured.out
        assert "Trojan detected" in captured.out

    def test_prints_risk_score_bar(self, capsys):
        result = self._make_result(
            risk_score={
                "score": 80,
                "verdict": "high",
                "factors": [{"name": "packed", "points": 20, "detail": "UPX"}],
            }
        )
        cli._print_result(result)
        captured = capsys.readouterr()
        assert "80/100" in captured.out
        assert "packed" in captured.out

    def test_prints_pe_info(self, capsys):
        pe = {
            "is_pe": True,
            "machine": "AMD64",
            "compile_time": "2024-01-01",
            "entry_point": "0x1000",
            "overall_entropy": 6.5,
            "packed": False,
            "sections": [{"name": ".text", "entropy": 6.0, "raw_size": 4096}],
            "warnings": ["Suspicious entropy"],
            "suspicious_imports": ["VirtualAlloc"],
        }
        result = self._make_result(pe_info=pe)
        cli._print_result(result)
        captured = capsys.readouterr()
        assert "AMD64" in captured.out
        assert ".text" in captured.out

    def test_prints_yara_matches(self, capsys):
        yara = {
            "matches": [
                {
                    "rule": "Suspicious_Packer",
                    "meta": {"description": "Packed binary", "severity": "high"},
                }
            ]
        }
        result = self._make_result(yara_matches=yara)
        cli._print_result(result)
        captured = capsys.readouterr()
        assert "Suspicious_Packer" in captured.out

    def test_prints_iocs(self, capsys):
        strings = {
            "has_iocs": True,
            "urls": ["http://evil.com"],
            "ips": [],
            "domains": [],
            "emails": [],
            "powershell_commands": [],
            "suspicious_paths": [],
            "crypto_wallets": [],
            "user_agents": [],
            "registry_keys": [],
        }
        result = self._make_result(strings_info=strings)
        cli._print_result(result)
        captured = capsys.readouterr()
        assert "http://evil.com" in captured.out

    def test_prints_vt_result(self, capsys):
        vt = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 30,
                        "undetected": 40,
                    }
                }
            }
        }
        result = self._make_result(vt_result=vt)
        cli._print_result(result)
        captured = capsys.readouterr()
        assert "30/70" in captured.out

    def test_prints_threat_intel(self, capsys):
        ti = {
            "hits": [
                {"source": "MalwareBazaar", "found": True, "malware_family": "Emotet"},
                {"source": "URLhaus", "found": False},
            ]
        }
        result = self._make_result(threat_intel=ti)
        cli._print_result(result)
        captured = capsys.readouterr()
        assert "MalwareBazaar" in captured.out
        assert "Emotet" in captured.out


class TestMainParser:
    def test_version_flag(self, capsys):
        with pytest.raises(SystemExit) as exc:
            with patch("sys.argv", ["hashguard", "--version"]):
                cli.main()
        assert exc.value.code == 0

    def test_web_mode(self):
        with patch("sys.argv", ["hashguard", "--web"]):
            with patch("hashguard.web.api.start_server") as mock:
                cli.main()
                mock.assert_called_once()

    @patch("hashguard.cli.analyze")
    def test_single_file(self, mock_analyze, tmp_path, capsys):
        f = tmp_path / "test.txt"
        f.write_text("hello")
        mock_result = MagicMock()
        mock_result.path = str(f)
        mock_result.file_size = 5
        mock_result.hashes = {"md5": "a" * 32, "sha1": "b" * 40, "sha256": "c" * 64}
        mock_result.malicious = False
        mock_result.description = ""
        mock_result.risk_score = {"score": 0, "verdict": "clean", "factors": []}
        mock_result.vt_result = None
        mock_result.threat_intel = None
        mock_result.pe_info = None
        mock_result.yara_matches = None
        mock_result.strings_info = None
        mock_result.analysis_time = 0.01
        mock_analyze.return_value = mock_result

        with patch("sys.argv", ["hashguard", str(f)]):
            with pytest.raises(SystemExit) as exc:
                cli.main()
            assert exc.value.code == 0

    @patch("hashguard.cli.analyze")
    def test_single_file_json(self, mock_analyze, tmp_path, capsys):
        f = tmp_path / "test.txt"
        f.write_text("hello")
        mock_result = MagicMock()
        mock_result.to_json.return_value = '{"test": true}'
        mock_analyze.return_value = mock_result

        with patch("sys.argv", ["hashguard", str(f), "--json"]):
            with pytest.raises(SystemExit) as exc:
                cli.main()
            assert exc.value.code == 0

    def test_file_not_found(self, capsys):
        with patch("sys.argv", ["hashguard", "/nonexistent/file.exe"]):
            with patch("hashguard.cli.analyze", side_effect=FileNotFoundError("not found")):
                with pytest.raises(SystemExit) as exc:
                    cli.main()
                assert exc.value.code == 1


class TestAnalyzeSingle:
    @patch("hashguard.cli.analyze")
    def test_success(self, mock_analyze):
        mock_result = MagicMock()
        mock_result.path = "/test"
        mock_result.file_size = 0
        mock_result.hashes = {}
        mock_result.malicious = False
        mock_result.description = ""
        mock_result.risk_score = {}
        mock_result.vt_result = None
        mock_result.threat_intel = None
        mock_result.pe_info = None
        mock_result.yara_matches = None
        mock_result.strings_info = None
        mock_result.analysis_time = 0
        mock_analyze.return_value = mock_result

        args = MagicMock()
        args.path = "/test"
        args.vt = False
        args.json = False
        assert cli.analyze_single(args) == 0

    def test_file_not_found(self):
        args = MagicMock()
        args.path = "/nonexistent"
        args.vt = False
        args.json = False
        with patch("hashguard.cli.analyze", side_effect=FileNotFoundError):
            assert cli.analyze_single(args) == 1


class TestAnalyzeURLSingle:
    @patch("hashguard.cli.analyze_url")
    def test_success(self, mock_analyze):
        mock_result = MagicMock()
        mock_result.path = "http://example.com/file"
        mock_result.file_size = 100
        mock_result.hashes = {}
        mock_result.malicious = False
        mock_result.description = ""
        mock_result.risk_score = {}
        mock_result.vt_result = None
        mock_result.threat_intel = None
        mock_result.pe_info = None
        mock_result.yara_matches = None
        mock_result.strings_info = None
        mock_result.analysis_time = 0
        mock_analyze.return_value = mock_result

        args = MagicMock()
        args.url = "http://example.com/file"
        args.vt = False
        args.json = False
        assert cli.analyze_url_single(args) == 0

    @patch("hashguard.cli.analyze_url", side_effect=Exception("timeout"))
    def test_error(self, mock_analyze):
        args = MagicMock()
        args.url = "http://example.com/file"
        args.vt = False
        args.json = False
        assert cli.analyze_url_single(args) == 1


class TestAnalyzeBatch:
    """Tests for batch analysis CLI."""

    @patch("hashguard.cli.BatchAnalyzer")
    def test_batch_directory(self, mock_ba_cls):
        mock_ba = MagicMock()
        mock_ba.analyze_directory.return_value = []
        mock_ba.get_summary.return_value = {
            "total_files": 0,
            "malicious_count": 0,
            "clean_count": 0,
            "malicious_percentage": 0,
            "total_size_bytes": 0,
            "total_analysis_time_seconds": 0,
        }
        mock_ba_cls.return_value = mock_ba

        args = MagicMock()
        args.directory = "/tmp/test"
        args.no_recursive = False
        args.pattern = "*"
        args.vt = False
        args.output = None
        assert cli.analyze_batch(args) == 0

    @patch("hashguard.cli.BatchAnalyzer")
    def test_batch_output_json(self, mock_ba_cls, tmp_path):
        mock_ba = MagicMock()
        mock_ba.analyze_directory.return_value = []
        mock_ba_cls.return_value = mock_ba

        out = str(tmp_path / "report.json")
        args = MagicMock()
        args.directory = "/tmp/test"
        args.no_recursive = False
        args.pattern = "*"
        args.vt = False
        args.output = out

        with patch("hashguard.cli.ReportGenerator") as mock_rg:
            mock_rg.to_json.return_value = '{"results": []}'
            assert cli.analyze_batch(args) == 0
            assert (tmp_path / "report.json").exists()

    @patch("hashguard.cli.BatchAnalyzer")
    def test_batch_output_csv(self, mock_ba_cls, tmp_path):
        mock_ba = MagicMock()
        mock_ba.analyze_directory.return_value = []
        mock_ba_cls.return_value = mock_ba

        out = str(tmp_path / "report.csv")
        args = MagicMock()
        args.directory = "/tmp/test"
        args.no_recursive = False
        args.pattern = "*"
        args.vt = False
        args.output = out

        with patch("hashguard.cli.ReportGenerator") as mock_rg:
            mock_rg.to_csv.return_value = "hash,status\n"
            assert cli.analyze_batch(args) == 0

    @patch("hashguard.cli.BatchAnalyzer")
    def test_batch_output_html(self, mock_ba_cls, tmp_path):
        mock_ba = MagicMock()
        mock_ba.analyze_directory.return_value = []
        mock_ba_cls.return_value = mock_ba

        out = str(tmp_path / "report.html")
        args = MagicMock()
        args.directory = "/tmp/test"
        args.no_recursive = False
        args.pattern = "*"
        args.vt = False
        args.output = out

        with patch("hashguard.cli.ReportGenerator") as mock_rg:
            mock_rg.to_html.return_value = "<html></html>"
            assert cli.analyze_batch(args) == 0

    @patch("hashguard.cli.BatchAnalyzer", side_effect=Exception("batch error"))
    def test_batch_exception(self, mock_ba_cls):
        args = MagicMock()
        args.directory = "/tmp/test"
        assert cli.analyze_batch(args) == 1


class TestAnalyzeSingleJSON:
    """Test analyze_single with JSON output."""

    @patch("hashguard.cli.analyze")
    def test_json_output(self, mock_analyze):
        mock_result = MagicMock()
        mock_result.to_json.return_value = '{"path": "test.exe"}'
        mock_analyze.return_value = mock_result

        args = MagicMock()
        args.path = "test.exe"
        args.vt = False
        args.json = True
        assert cli.analyze_single(args) == 0

    @patch("hashguard.cli.analyze", side_effect=RuntimeError("unexpected"))
    def test_generic_exception(self, mock_analyze):
        args = MagicMock()
        args.path = "test.exe"
        args.vt = False
        args.json = False
        assert cli.analyze_single(args) == 1


class TestEnsureUTF8:
    """Test _ensure_utf8_stdout."""

    def test_runs_without_error(self):
        cli._ensure_utf8_stdout()

    def test_non_windows(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "linux")
        cli._ensure_utf8_stdout()  # Should be a no-op


class TestPrintResultExtended:
    """Extended tests for _print_result covering more branches."""

    def test_prints_iocs(self, capsys):
        result = MagicMock()
        result.path = "test.exe"
        result.file_size = 100
        result.hashes = {"md5": "abc"}
        result.malicious = False
        result.description = ""
        result.risk_score = {"score": 50, "verdict": "suspicious", "factors": [
            {"name": "High entropy", "points": 10, "detail": "section .text"}
        ]}
        result.vt_result = None
        result.threat_intel = None
        result.pe_info = None
        result.yara_matches = None
        result.strings_info = {
            "has_iocs": True,
            "urls": ["http://evil.com/payload"],
            "ips": ["1.2.3.4"],
        }
        result.analysis_time = 0.5
        cli._print_result(result)
        out = capsys.readouterr().out
        assert "http://evil.com/payload" in out
        assert "1.2.3.4" in out


class TestPrintResultVTNoReport:
    """Cover VT 'No report available' branch (line 75)."""

    def test_vt_no_data(self, capsys):
        result = MagicMock()
        result.path = "t.exe"
        result.file_size = 10
        result.hashes = {"md5": "a" * 32}
        result.malicious = False
        result.description = ""
        result.risk_score = {}
        result.vt_result = {"data": {}}
        result.threat_intel = None
        result.pe_info = None
        result.yara_matches = None
        result.strings_info = None
        result.analysis_time = 0.01
        cli._print_result(result)
        out = capsys.readouterr().out
        assert "No report available" in out


class TestPrintResultPacker:
    """Cover packed PE packer_hint branch (line 95)."""

    def test_pe_packed(self, capsys):
        pe = {
            "is_pe": True,
            "machine": "I386",
            "compile_time": "",
            "entry_point": "0x1000",
            "overall_entropy": 7.5,
            "packed": True,
            "packer_hint": "UPX",
            "sections": [],
            "warnings": [],
            "suspicious_imports": [],
        }
        result = MagicMock()
        result.path = "t.exe"
        result.file_size = 10
        result.hashes = {"md5": "a" * 32}
        result.malicious = False
        result.description = ""
        result.risk_score = {}
        result.vt_result = None
        result.threat_intel = None
        result.pe_info = pe
        result.yara_matches = None
        result.strings_info = None
        result.analysis_time = 0.01
        cli._print_result(result)
        out = capsys.readouterr().out
        assert "UPX" in out


class TestPrintResultIOCTruncation:
    """Cover '... and N more' truncation (line 140)."""

    def test_ioc_truncation(self, capsys):
        result = MagicMock()
        result.path = "t.exe"
        result.file_size = 10
        result.hashes = {}
        result.malicious = False
        result.description = ""
        result.risk_score = {}
        result.vt_result = None
        result.threat_intel = None
        result.pe_info = None
        result.yara_matches = None
        result.strings_info = {
            "has_iocs": True,
            "urls": [f"http://evil{i}.com" for i in range(10)],
        }
        result.analysis_time = 0.01
        cli._print_result(result)
        out = capsys.readouterr().out
        assert "... and 5 more" in out


class TestAnalyzeUrlSinglePrintResult:
    """Cover URL print_result path (line 172)."""

    @patch("hashguard.cli.analyze_url")
    def test_url_prints_report(self, mock_analyze):
        mock_result = MagicMock()
        mock_result.path = "http://example.com"
        mock_result.file_size = 0
        mock_result.hashes = {}
        mock_result.malicious = False
        mock_result.description = ""
        mock_result.risk_score = {}
        mock_result.vt_result = None
        mock_result.threat_intel = None
        mock_result.pe_info = None
        mock_result.yara_matches = None
        mock_result.strings_info = None
        mock_result.analysis_time = 0.01
        mock_analyze.return_value = mock_result

        args = MagicMock()
        args.url = "http://example.com"
        args.vt = False
        args.json = False
        ret = cli.analyze_url_single(args)
        assert ret == 0


class TestBatchStdin:
    """Cover batch stdin reading path (lines 197-205, 219)."""

    @patch("hashguard.cli.BatchAnalyzer")
    def test_batch_from_stdin(self, mock_ba_cls, tmp_path):
        mock_ba = MagicMock()
        mock_ba.analyze_files.return_value = []
        mock_ba.get_summary.return_value = {
            "total_files": 0, "malicious_count": 0,
            "clean_count": 0, "malicious_percentage": 0,
            "total_size_bytes": 0, "total_analysis_time_seconds": 0,
        }
        mock_ba_cls.return_value = mock_ba

        args = MagicMock()
        args.directory = None
        args.vt = False
        args.output = None
        # Simulate stdin with file paths
        import io
        fake_stdin = io.StringIO("file1.exe\nfile2.exe\n")
        with patch("sys.stdin", fake_stdin):
            with patch.object(fake_stdin, "isatty", return_value=False):
                ret = cli.analyze_batch(args)
        assert ret == 0
        mock_ba.analyze_files.assert_called_once()

    @patch("hashguard.cli.BatchAnalyzer")
    def test_batch_no_files_returns_1(self, mock_ba_cls):
        mock_ba_cls.return_value = MagicMock()
        args = MagicMock()
        args.directory = None
        args.vt = False
        args.output = None
        import io
        fake_stdin = io.StringIO("")
        with patch("sys.stdin", fake_stdin):
            with patch.object(fake_stdin, "isatty", return_value=False):
                ret = cli.analyze_batch(args)
        assert ret == 1

    @patch("hashguard.cli.BatchAnalyzer")
    def test_batch_html_output(self, mock_ba_cls, tmp_path):
        mock_ba = MagicMock()
        mock_ba.analyze_files.return_value = []
        mock_ba_cls.return_value = mock_ba
        out = str(tmp_path / "report.html")
        args = MagicMock()
        args.directory = None
        args.vt = False
        args.output = out
        import io
        fake_stdin = io.StringIO("file1.exe\n")
        with patch("sys.stdin", fake_stdin):
            with patch.object(fake_stdin, "isatty", return_value=False):
                with patch("hashguard.cli.ReportGenerator") as mock_rg:
                    mock_rg.to_html.return_value = "<html></html>"
                    ret = cli.analyze_batch(args)
        assert ret == 0


class TestMainDispatch:
    """Cover main() dispatch paths (lines 348, 361-365, 369, 373, 379-380)."""

    def test_main_config_flag(self, tmp_path):
        cfg_file = tmp_path / "config.json"
        cfg_file.write_text('{"vt_api_key": ""}')
        with patch("sys.argv", ["hashguard", "--config", str(cfg_file), "--web"]):
            with patch("hashguard.web.api.start_server") as mock_srv:
                cli.main()
                mock_srv.assert_called_once()

    def test_main_no_args_launches_dashboard(self):
        with patch("sys.argv", ["hashguard"]):
            with patch("sys.stdin") as mock_stdin:
                mock_stdin.isatty.return_value = True
                with patch("hashguard.web.api.start_server") as mock_srv:
                    cli.main()
                    mock_srv.assert_called_once()

    def test_main_url_mode(self):
        with patch("sys.argv", ["hashguard", "--url", "http://example.com"]):
            with patch("hashguard.cli.analyze_url_single", return_value=0) as mock_url:
                with pytest.raises(SystemExit) as exc:
                    cli.main()
                assert exc.value.code == 0


class TestEnsureUTF8Reconfigure:
    """Cover _ensure_utf8_stdout reconfigure call (lines 29-30)."""

    def test_reconfigure_windows(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "win32")
        mock_stdout = MagicMock()
        monkeypatch.setattr("sys.stdout", mock_stdout)
        cli._ensure_utf8_stdout()
        mock_stdout.reconfigure.assert_called_once_with(encoding="utf-8", errors="replace")

    def test_reconfigure_exception(self, monkeypatch):
        """Cover exception handler in _ensure_utf8_stdout (lines 29-30)."""
        monkeypatch.setattr("sys.platform", "win32")
        mock_stdout = MagicMock()
        mock_stdout.reconfigure.side_effect = OSError("broken pipe")
        monkeypatch.setattr("sys.stdout", mock_stdout)
        # Should not raise
        cli._ensure_utf8_stdout()


class TestMainNoArgs:
    """Cover no-args help path (lines 379-380)."""

    def test_no_args_prints_help(self):
        with patch("sys.argv", ["hashguard"]):
            with pytest.raises(SystemExit) as exc:
                cli.main()
            assert exc.value.code == 0
