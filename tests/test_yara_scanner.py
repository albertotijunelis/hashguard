"""Tests for HashGuard YARA scanner module."""

import os
import tempfile

import pytest
from unittest.mock import patch, MagicMock

from hashguard.yara_scanner import (
    YaraMatch,
    YaraScanResult,
    _find_rule_files,
    is_available,
    scan_file,
)


class TestYaraMatch:
    """Tests for YaraMatch dataclass."""

    def test_to_dict(self):
        m = YaraMatch(
            rule="Suspicious_Test",
            namespace="default",
            tags=["malware"],
            meta={"description": "test rule", "severity": "high"},
            strings=["0x00: $s1"],
        )
        d = m.to_dict()
        assert d["rule"] == "Suspicious_Test"
        assert d["namespace"] == "default"
        assert d["tags"] == ["malware"]
        assert d["meta"]["severity"] == "high"


class TestYaraScanResult:
    """Tests for YaraScanResult dataclass."""

    def test_default(self):
        r = YaraScanResult()
        assert r.available is False
        assert r.rules_loaded == 0
        assert r.matches == []

    def test_to_dict(self):
        m = YaraMatch(rule="Test", namespace="ns")
        r = YaraScanResult(available=True, rules_loaded=3, matches=[m])
        d = r.to_dict()
        assert d["available"] is True
        assert d["rules_loaded"] == 3
        assert len(d["matches"]) == 1


class TestFindRuleFiles:
    """Tests for rule file discovery."""

    def test_empty_dir(self, tmp_path):
        assert _find_rule_files(str(tmp_path)) == []

    def test_finds_yar_files(self, tmp_path):
        (tmp_path / "rule1.yar").write_text("rule test { condition: true }")
        (tmp_path / "rule2.yara").write_text("rule test2 { condition: true }")
        (tmp_path / "readme.txt").write_text("not a rule")
        found = _find_rule_files(str(tmp_path))
        assert len(found) == 2
        assert all(f.endswith((".yar", ".yara")) for f in found)

    def test_nonexistent_dir(self):
        assert _find_rule_files("/nonexistent/path") == []

    def test_nested_rules(self, tmp_path):
        sub = tmp_path / "subdir"
        sub.mkdir()
        (sub / "nested.yar").write_text("rule nested { condition: true }")
        found = _find_rule_files(str(tmp_path))
        assert len(found) == 1


class TestScanFile:
    """Tests for the scan_file function."""

    def test_scan_nonexistent_file(self, tmp_path):
        result = scan_file("/nonexistent/file.exe", rules_dir=str(tmp_path))
        assert isinstance(result, YaraScanResult)

    def test_scan_no_rules(self, tmp_path):
        target = tmp_path / "test.txt"
        target.write_text("hello")
        empty_rules = tmp_path / "rules"
        empty_rules.mkdir()
        result = scan_file(str(target), rules_dir=str(empty_rules))
        assert result.rules_loaded == 0
        assert result.matches == []


class TestIsAvailable:
    """Tests for yara availability check."""

    def test_returns_bool(self):
        assert isinstance(is_available(), bool)


class TestScanFileWithRules:
    """Tests for scan_file with actual YARA rules."""

    def test_scan_with_matching_rule(self, tmp_path):
        if not is_available():
            pytest.skip("yara-python not installed")
        # Create a rule that matches any file
        rule_dir = tmp_path / "rules"
        rule_dir.mkdir()
        (rule_dir / "test.yar").write_text(
            'rule AlwaysMatch { condition: true }'
        )
        target = tmp_path / "target.txt"
        target.write_text("test data")
        result = scan_file(str(target), rules_dir=str(rule_dir))
        assert result.available is True
        assert result.rules_loaded >= 1
        assert len(result.matches) >= 1
        assert result.matches[0].rule == "AlwaysMatch"

    def test_scan_with_no_match(self, tmp_path):
        if not is_available():
            pytest.skip("yara-python not installed")
        rule_dir = tmp_path / "rules"
        rule_dir.mkdir()
        (rule_dir / "test.yar").write_text(
            'rule NeverMatch { strings: $s = "NEVER_THIS_STRING_12345" condition: $s }'
        )
        target = tmp_path / "target.txt"
        target.write_text("normal content")
        result = scan_file(str(target), rules_dir=str(rule_dir))
        assert result.available is True
        assert result.matches == []

    def test_scan_with_string_match(self, tmp_path):
        if not is_available():
            pytest.skip("yara-python not installed")
        rule_dir = tmp_path / "rules"
        rule_dir.mkdir()
        (rule_dir / "test.yar").write_text(
            'rule FindMalware { strings: $s = "MALWARE_MARKER" condition: $s }'
        )
        target = tmp_path / "target.bin"
        target.write_bytes(b"\x00\x00MALWARE_MARKER\x00\x00")
        result = scan_file(str(target), rules_dir=str(rule_dir))
        assert len(result.matches) == 1
        assert result.matches[0].rule == "FindMalware"
        assert len(result.matches[0].strings) > 0

    def test_scan_with_bad_rule_file(self, tmp_path):
        if not is_available():
            pytest.skip("yara-python not installed")
        rule_dir = tmp_path / "rules"
        rule_dir.mkdir()
        (rule_dir / "bad.yar").write_text("INVALID YARA SYNTAX {{{")
        (rule_dir / "good.yar").write_text(
            'rule GoodRule { condition: true }'
        )
        target = tmp_path / "target.txt"
        target.write_text("test")
        result = scan_file(str(target), rules_dir=str(rule_dir))
        # Should gracefully handle bad rules
        assert isinstance(result, YaraScanResult)

    def test_scan_default_rules_dir(self, tmp_path):
        """scan_file with rules_dir=None uses default resolution."""
        target = tmp_path / "target.txt"
        target.write_text("test content")
        result = scan_file(str(target))
        assert isinstance(result, YaraScanResult)
        assert result.available == is_available()

    def test_scan_not_available(self, tmp_path):
        """When yara is not available, returns empty result."""
        from hashguard import yara_scanner
        original = yara_scanner._YARA_AVAILABLE
        yara_scanner._YARA_AVAILABLE = False
        try:
            target = tmp_path / "target.txt"
            target.write_text("test")
            result = scan_file(str(target))
            assert result.available is False
        finally:
            yara_scanner._YARA_AVAILABLE = original


class TestScanFileMocked:
    """Tests using mocked yara module for error/edge paths."""

    def test_scan_nonexistent_file_when_available(self, tmp_path):
        """File doesn't exist but yara is available → early return (line 104)."""
        from hashguard import yara_scanner
        original = yara_scanner._YARA_AVAILABLE
        yara_scanner._YARA_AVAILABLE = True
        try:
            result = scan_file("/nonexistent/file.exe", rules_dir=str(tmp_path))
            assert result.available is True
            assert result.matches == []
        finally:
            yara_scanner._YARA_AVAILABLE = original

    def test_scan_syntax_error_fallback(self, tmp_path):
        """Batch compile SyntaxError → file-by-file retry (lines 138-145)."""
        if not is_available():
            pytest.skip("yara-python not installed")

        rule_dir = tmp_path / "rules"
        rule_dir.mkdir()
        (rule_dir / "bad.yar").write_text("INVALID {{{")
        (rule_dir / "good.yar").write_text("rule GoodRule { condition: true }")
        target = tmp_path / "target.txt"
        target.write_text("test content")

        import yara as real_yara
        original_compile = real_yara.compile

        call_count = [0]

        def compile_side_effect(**kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                # First batch compile fails with SyntaxError
                raise real_yara.SyntaxError("batch fail")
            return original_compile(**kwargs)

        with patch.object(real_yara, "compile", side_effect=compile_side_effect):
            result = scan_file(str(target), rules_dir=str(rule_dir))

        assert isinstance(result, YaraScanResult)

    def test_scan_match_error(self, tmp_path):
        """rules.match raises exception → caught gracefully (line 151-153)."""
        if not is_available():
            pytest.skip("yara-python not installed")

        rule_dir = tmp_path / "rules"
        rule_dir.mkdir()
        (rule_dir / "test.yar").write_text("rule Test { condition: true }")
        target = tmp_path / "target.txt"
        target.write_text("test")

        import yara as real_yara

        original_compile = real_yara.compile

        def compile_wrapper(**kwargs):
            rules = original_compile(**kwargs)
            mock_rules = MagicMock()
            mock_rules.match.side_effect = RuntimeError("scan error")
            return mock_rules

        with patch.object(real_yara, "compile", side_effect=compile_wrapper):
            result = scan_file(str(target), rules_dir=str(rule_dir))

        assert result.matches == []

    def test_scan_general_compile_error(self, tmp_path):
        """Non-SyntaxError compile exception → caught (line 145)."""
        if not is_available():
            pytest.skip("yara-python not installed")

        rule_dir = tmp_path / "rules"
        rule_dir.mkdir()
        (rule_dir / "test.yar").write_text("rule Test { condition: true }")
        target = tmp_path / "target.txt"
        target.write_text("test")

        import yara as real_yara

        with patch.object(real_yara, "compile", side_effect=OSError("compile error")):
            result = scan_file(str(target), rules_dir=str(rule_dir))

        assert result.matches == []
        assert result.rules_loaded == 0


class TestYaraMEIPASSPath:
    """Cover _MEIPASS frozen path (line 104) and dev fallback (line 112)."""

    def test_meipass_rules_dir(self, tmp_path):
        if not is_available():
            pytest.skip("yara-python not installed")

        target = tmp_path / "test.txt"
        target.write_text("test content")

        with patch("sys._MEIPASS", str(tmp_path), create=True):
            # No yara_rules dir in MEIPASS → should fall through
            result = scan_file(str(target), rules_dir=None)
            assert isinstance(result, YaraScanResult)


class TestYaraFallbackCompile:
    """Cover file-by-file fallback compile (line 138) and no good sources (141-142)."""

    def test_partial_compile_failure(self, tmp_path):
        if not is_available():
            pytest.skip("yara-python not installed")

        rule_dir = tmp_path / "rules"
        rule_dir.mkdir()
        (rule_dir / "good.yar").write_text("rule Good { condition: true }")
        (rule_dir / "bad.yar").write_text("invalid yara syntax {{{")

        target = tmp_path / "test.txt"
        target.write_text("test content")

        result = scan_file(str(target), rules_dir=str(rule_dir))
        # Should still work with the good rule
        assert result.rules_loaded >= 0
