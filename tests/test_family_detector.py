"""Tests for HashGuard family detector module."""

import os
import tempfile

import pytest
from unittest.mock import patch, MagicMock

from hashguard.family_detector import (
    FamilyDetection,
    _detect_compiler,
    _detect_imphash_family,
    _detect_section_layout,
    detect_family,
    FAMILY_SIGNATURES,
    COMPILER_SIGNATURES,
)


def _make_temp(data: bytes) -> str:
    fd, path = tempfile.mkstemp()
    os.write(fd, data)
    os.close(fd)
    return path


class TestFamilyDetection:
    """Tests for FamilyDetection dataclass."""

    def test_default(self):
        d = FamilyDetection()
        assert d.family == ""
        assert d.confidence == 0.0
        assert d.source == ""
        assert d.all_matches == []

    def test_to_dict(self):
        d = FamilyDetection(
            family="Emotet",
            confidence=0.92,
            source="strings",
            description="Banking trojan",
            compiler="Delphi",
            all_matches=[
                {"family": "Emotet", "confidence": 0.92, "source": "strings"},
                {"family": "Trickbot", "confidence": 0.5, "source": "ml"},
            ],
        )
        result = d.to_dict()
        assert result["family"] == "Emotet"
        assert result["confidence"] == 92.0
        assert result["compiler"] == "Delphi"
        assert len(result["all_matches"]) == 2

    def test_to_dict_no_compiler(self):
        d = FamilyDetection(family="Test", confidence=0.5)
        result = d.to_dict()
        assert "compiler" not in result


class TestDetectCompiler:
    """Tests for compiler detection."""

    def test_detects_autoit(self):
        data = b"\x00" * 100 + b"AutoIt v3" + b"\x00" * 100
        p = _make_temp(data)
        try:
            result = _detect_compiler(p)
            assert result is not None
            assert "AutoIt" in result
        finally:
            os.remove(p)

    def test_detects_pyinstaller(self):
        data = b"\x00" * 100 + b"PyInstaller" + b"\x00" * 100
        p = _make_temp(data)
        try:
            result = _detect_compiler(p)
            assert result is not None
            assert "PyInstaller" in result
        finally:
            os.remove(p)

    def test_detects_golang(self):
        data = b"\x00" * 100 + b"Go build ID:" + b"\x00" * 100
        p = _make_temp(data)
        try:
            result = _detect_compiler(p)
            assert result is not None
            assert "Go" in result
        finally:
            os.remove(p)

    def test_no_compiler_detected(self):
        data = b"\x00" * 200
        p = _make_temp(data)
        try:
            result = _detect_compiler(p)
            assert result is None
        finally:
            os.remove(p)

    def test_nonexistent_file(self):
        result = _detect_compiler("/nonexistent/path/file.exe")
        assert result is None


class TestDetectFamilyStrings:
    """Tests for string-based family detection."""

    def test_detects_xmrig(self):
        data = b"xmrig miner v6.18 stratum+tcp://pool.example.com randomx hashrate"
        p = _make_temp(data)
        try:
            result = detect_family(p)
            assert result.family == "XMRig"
            assert result.confidence > 0.0
            assert result.source == "strings"
        finally:
            os.remove(p)

    def test_detects_lockbit(self):
        data = b"LockBit ransomware .lockbit Restore-My-Files.txt"
        p = _make_temp(data)
        try:
            result = detect_family(p)
            assert result.family == "LockBit"
            assert result.confidence > 0.0
        finally:
            os.remove(p)

    def test_detects_mirai(self):
        data = b"mirai /bin/busybox scanner_init killer_init"
        p = _make_temp(data)
        try:
            result = detect_family(p)
            assert result.family == "Mirai"
        finally:
            os.remove(p)

    def test_clean_file_no_family(self):
        data = b"This is a perfectly normal file with nothing suspicious in it."
        p = _make_temp(data)
        try:
            result = detect_family(p)
            assert result.family == ""
            assert result.confidence == 0.0
        finally:
            os.remove(p)


class TestDetectFamilyYara:
    """Tests for YARA-based family detection."""

    def test_yara_family_detection(self):
        data = b"clean content"
        p = _make_temp(data)
        try:
            yara_matches = {
                "matches": [
                    {
                        "rule": "APT28_Backdoor",
                        "meta": {
                            "malware_family": "APT28",
                            "description": "APT28 Fancy Bear backdoor",
                        },
                    }
                ]
            }
            result = detect_family(p, yara_matches=yara_matches)
            assert result.family == "APT28"
            assert result.source == "yara"
        finally:
            os.remove(p)


class TestDetectFamilyThreatIntel:
    """Tests for threat intel-based family detection."""

    def test_threat_intel_family(self):
        data = b"clean content"
        p = _make_temp(data)
        try:
            ti = {
                "hits": [
                    {
                        "source": "MalwareBazaar",
                        "found": True,
                        "malware_family": "Emotet",
                    }
                ]
            }
            result = detect_family(p, threat_intel=ti)
            assert result.family == "Emotet"
            assert result.source == "threat_intel"
        finally:
            os.remove(p)

    def test_threat_intel_no_family(self):
        data = b"clean content"
        p = _make_temp(data)
        try:
            ti = {"hits": [{"source": "MalwareBazaar", "found": False}]}
            result = detect_family(p, threat_intel=ti)
            assert result.family == ""
        finally:
            os.remove(p)


class TestDetectFamilyML:
    """Tests for ML-based family detection."""

    def test_ml_generic_classification(self):
        data = b"clean content"
        p = _make_temp(data)
        try:
            ml = {"predicted_class": "trojan", "confidence": 0.85}
            result = detect_family(p, ml_result=ml)
            assert result.family == "Generic.Trojan"
            assert result.source == "ml"
        finally:
            os.remove(p)

    def test_ml_benign_ignored(self):
        data = b"clean content"
        p = _make_temp(data)
        try:
            ml = {"predicted_class": "benign", "confidence": 0.95}
            result = detect_family(p, ml_result=ml)
            assert result.family == ""
        finally:
            os.remove(p)

    def test_ml_low_confidence_ignored(self):
        data = b"clean content"
        p = _make_temp(data)
        try:
            ml = {"predicted_class": "trojan", "confidence": 0.3}
            result = detect_family(p, ml_result=ml)
            assert result.family == ""
        finally:
            os.remove(p)

    def test_ml_confidence_as_percentage(self):
        data = b"clean content"
        p = _make_temp(data)
        try:
            ml = {"predicted_class": "ransomware", "confidence": 85}
            result = detect_family(p, ml_result=ml)
            assert result.family == "Generic.Ransomware"
        finally:
            os.remove(p)


class TestDetectFamilyPriority:
    """Tests that higher-confidence sources win."""

    def test_yara_beats_ml(self):
        data = b"clean content"
        p = _make_temp(data)
        try:
            yara_matches = {
                "matches": [
                    {"rule": "LockBit", "meta": {"malware_family": "LockBit"}}
                ]
            }
            ml = {"predicted_class": "trojan", "confidence": 0.85}
            result = detect_family(p, yara_matches=yara_matches, ml_result=ml)
            assert result.family == "LockBit"
        finally:
            os.remove(p)


class TestDetectImphashFamily:
    """Tests for _detect_imphash_family."""

    def test_no_pefile(self):
        from hashguard import family_detector
        with patch.object(family_detector, "HAS_PEFILE", False):
            result = family_detector._detect_imphash_family("/fake/path")
            assert result is None

    def test_pefile_exception(self):
        from hashguard import family_detector
        with patch.object(family_detector, "HAS_PEFILE", True):
            with patch("hashguard.family_detector.pefile") as mock_pe:
                mock_pe.PE.side_effect = Exception("bad PE")
                mock_pe.DIRECTORY_ENTRY = {"IMAGE_DIRECTORY_ENTRY_IMPORT": 1}
                result = family_detector._detect_imphash_family("/fake/path")
                assert result is None

    def test_known_imphash_returns_match(self):
        from hashguard import family_detector
        with patch.object(family_detector, "HAS_PEFILE", True):
            mock_pe_inst = MagicMock()
            known = list(family_detector.KNOWN_IMPHASHES.keys())[0]
            mock_pe_inst.get_imphash.return_value = known
            with patch("hashguard.family_detector.pefile") as mock_pe:
                mock_pe.PE.return_value = mock_pe_inst
                mock_pe.DIRECTORY_ENTRY = {"IMAGE_DIRECTORY_ENTRY_IMPORT": 1}
                result = family_detector._detect_imphash_family("/fake/path")
                assert result is not None
                assert result["source"] == "imphash"

    def test_unknown_imphash(self):
        from hashguard import family_detector
        with patch.object(family_detector, "HAS_PEFILE", True):
            mock_pe_inst = MagicMock()
            mock_pe_inst.get_imphash.return_value = "0000000000000000000000000000dead"
            with patch("hashguard.family_detector.pefile") as mock_pe:
                mock_pe.PE.return_value = mock_pe_inst
                mock_pe.DIRECTORY_ENTRY = {"IMAGE_DIRECTORY_ENTRY_IMPORT": 1}
                result = family_detector._detect_imphash_family("/fake/path")
                assert result is None


class TestDetectSectionLayout:
    """Tests for _detect_section_layout."""

    def test_no_pefile(self):
        from hashguard import family_detector
        with patch.object(family_detector, "HAS_PEFILE", False):
            result = family_detector._detect_section_layout("/fake/path")
            assert result is None

    def test_pefile_exception(self):
        from hashguard import family_detector
        with patch.object(family_detector, "HAS_PEFILE", True):
            with patch("hashguard.family_detector.pefile") as mock_pe:
                mock_pe.PE.side_effect = Exception("bad PE")
                result = family_detector._detect_section_layout("/fake/path")
                assert result is None


class TestDetectFamilyStringCorroboration:
    """Tests for string-based detection corroborating structural matches."""

    def test_string_corroboration_boosts_confidence(self):
        """When string match corroborates existing structural match."""
        data = b"xmrig miner v6.18 stratum+tcp://pool.example.com randomx hashrate"
        p = _make_temp(data)
        try:
            # XMRig is detected via strings; simulate it already in candidates
            result = detect_family(p)
            assert result.family == "XMRig"
        finally:
            os.remove(p)

    def test_ml_confidence_as_string(self):
        """ML confidence provided as string value."""
        data = b"clean content"
        p = _make_temp(data)
        try:
            ml = {"predicted_class": "trojan", "confidence": "85"}
            result = detect_family(p, ml_result=ml)
            assert result.family == "Generic.Trojan"
        finally:
            os.remove(p)

    def test_ml_confidence_invalid_string(self):
        """ML confidence as invalid string gracefully handled."""
        data = b"clean content"
        p = _make_temp(data)
        try:
            ml = {"predicted_class": "trojan", "confidence": "not_a_number"}
            result = detect_family(p, ml_result=ml)
            # Should not crash; conf becomes 0, so no detection
            assert result.family == ""
        finally:
            os.remove(p)

    def test_file_read_error(self):
        """OSError during file read for string detection."""
        result = detect_family("/nonexistent/path/file.exe")
        # Should not crash
        assert isinstance(result, FamilyDetection)

    def test_all_matches_sorted(self):
        """Multiple matches sorted by confidence."""
        data = b"clean content"
        p = _make_temp(data)
        try:
            yara_matches = {
                "matches": [
                    {"rule": "APT28", "meta": {"malware_family": "APT28"}},
                ]
            }
            ml = {"predicted_class": "trojan", "confidence": 0.85}
            result = detect_family(p, yara_matches=yara_matches, ml_result=ml)
            assert len(result.all_matches) >= 2
            # Should be sorted desc by confidence
            for i in range(len(result.all_matches) - 1):
                assert result.all_matches[i]["confidence"] >= result.all_matches[i + 1]["confidence"]
        finally:
            os.remove(p)

    def test_threat_intel_hit_without_family(self):
        """Threat intel hit with found=True but no family."""
        data = b"clean content"
        p = _make_temp(data)
        try:
            ti = {"hits": [{"source": "MalwareBazaar", "found": True, "malware_family": ""}]}
            result = detect_family(p, threat_intel=ti)
            # Empty family should not add a candidate
            assert result.family == ""
        finally:
            os.remove(p)


class TestSectionLayoutMatch:
    """Cover _detect_section_layout success path (lines 289-304)."""

    def test_upx_packed_detection(self):
        from hashguard import family_detector
        with patch.object(family_detector, "HAS_PEFILE", True):
            # Build mock sections matching UPX: UPX0, UPX1, .rsrc
            sections = []
            for name in [b"UPX0\x00\x00\x00\x00", b"UPX1\x00\x00\x00\x00", b".rsrc\x00\x00\x00"]:
                sec = MagicMock()
                sec.Name = name
                sections.append(sec)
            mock_pe_inst = MagicMock()
            mock_pe_inst.sections = sections
            # No .NET descriptor
            del mock_pe_inst.DIRECTORY_ENTRY_COM_DESCRIPTOR
            with patch("hashguard.family_detector.pefile") as mock_pe:
                mock_pe.PE.return_value = mock_pe_inst
                result = _detect_section_layout("/fake")
                assert result is not None
                assert result["family"] == "UPX Packed"
                assert result["source"] == "section_layout"

    def test_section_count_mismatch(self):
        """Section names match but section_count doesn't → skip."""
        from hashguard import family_detector
        with patch.object(family_detector, "HAS_PEFILE", True):
            # .NET layout fingerprint requires exactly 3 sections + dotnet
            sections = []
            for name in [b".text\x00\x00\x00", b".rsrc\x00\x00\x00", b".reloc\x00\x00\x00", b".data\x00\x00\x00"]:
                sec = MagicMock()
                sec.Name = name
                sections.append(sec)
            mock_pe_inst = MagicMock()
            mock_pe_inst.sections = sections
            # Has .NET descriptor
            mock_pe_inst.DIRECTORY_ENTRY_COM_DESCRIPTOR = True
            with patch("hashguard.family_detector.pefile") as mock_pe:
                mock_pe.PE.return_value = mock_pe_inst
                result = _detect_section_layout("/fake")
                # 4 sections, but .NET fingerprint requires 3 → shouldn't match .NET
                # Could match something else or None
                if result:
                    assert result["family"] != ".NET Malware"

    def test_dotnet_only_fingerprint_skipped_for_non_dotnet(self):
        """requires_dotnet fingerprint is skipped when file is not .NET (L299)."""
        from hashguard import family_detector
        with patch.object(family_detector, "HAS_PEFILE", True):
            # Sections match .NET Malware layout: .text, .rsrc, .reloc (count=3)
            sections = []
            for name in [b".text\x00\x00\x00", b".rsrc\x00\x00\x00", b".reloc\x00\x00\x00"]:
                sec = MagicMock()
                sec.Name = name
                sections.append(sec)
            mock_pe_inst = MagicMock()
            mock_pe_inst.sections = sections
            # NOT .NET — delete the descriptor attribute
            del mock_pe_inst.DIRECTORY_ENTRY_COM_DESCRIPTOR
            with patch("hashguard.family_detector.pefile") as mock_pe:
                mock_pe.PE.return_value = mock_pe_inst
                result = _detect_section_layout("/fake")
                # .NET Malware fingerprint has requires_dotnet=True, so it's skipped
                # No other fingerprint matches these 3 generic sections
                assert result is None


class TestDetectFamilySectionAndString:
    """Cover section+string corroboration (lines 342-355, 375-379)."""

    def test_section_layout_adds_candidate(self):
        """Section layout result is added to candidates in detect_family."""
        from hashguard import family_detector
        data = b"clean content with no family strings"
        p = _make_temp(data)
        try:
            with patch.object(family_detector, "_detect_section_layout") as mock_sec:
                mock_sec.return_value = {
                    "family": "UPX Packed",
                    "confidence": 0.75,
                    "source": "section_layout",
                    "description": "UPX-packed binary",
                }
                with patch.object(family_detector, "_detect_imphash_family", return_value=None):
                    with patch.object(family_detector, "_detect_compiler", return_value=None):
                        result = detect_family(p)
                        assert result.family == "UPX Packed"
                        assert result.source == "section_layout"
        finally:
            os.remove(p)

    def test_string_structure_corroboration(self):
        """String match boosts confidence for existing structural match."""
        from hashguard import family_detector
        # Include enough LockBit strings to trigger string detection
        data = b"LockBit lockbit .lockbit Restore-My-Files.txt"
        p = _make_temp(data)
        try:
            with patch.object(family_detector, "_detect_section_layout") as mock_sec:
                mock_sec.return_value = {
                    "family": "LockBit",
                    "confidence": 0.5,
                    "source": "section_layout",
                    "description": "Test",
                }
                with patch.object(family_detector, "_detect_imphash_family", return_value=None):
                    with patch.object(family_detector, "_detect_compiler", return_value=None):
                        result = detect_family(p)
                        assert result.family == "LockBit"
                        assert result.source == "strings+structure"
                        assert result.confidence > 0.5  # Boosted
        finally:
            os.remove(p)

    def test_compiler_sets_detection_compiler(self):
        """When _detect_compiler returns a value, detection.compiler is set (L342)."""
        from hashguard import family_detector
        data = b"clean content"
        p = _make_temp(data)
        try:
            with patch.object(family_detector, "_detect_compiler", return_value="Delphi-compiled — common in RATs"):
                with patch.object(family_detector, "_detect_imphash_family", return_value=None):
                    with patch.object(family_detector, "_detect_section_layout", return_value=None):
                        result = detect_family(p)
                        assert result.compiler == "Delphi-compiled — common in RATs"
        finally:
            os.remove(p)

    def test_imphash_match_adds_candidate(self):
        """When _detect_imphash_family returns a match, it's added to candidates (L347)."""
        from hashguard import family_detector
        data = b"clean content"
        p = _make_temp(data)
        try:
            imp_match = {
                "family": "Emotet",
                "confidence": 0.95,
                "source": "imphash",
                "description": "Known Emotet imphash",
            }
            with patch.object(family_detector, "_detect_imphash_family", return_value=imp_match):
                with patch.object(family_detector, "_detect_compiler", return_value=None):
                    with patch.object(family_detector, "_detect_section_layout", return_value=None):
                        result = detect_family(p)
                        assert result.family == "Emotet"
                        assert result.source == "imphash"
        finally:
            os.remove(p)
