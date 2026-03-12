"""Tests for HashGuard PE analyzer module."""

import os
import struct
import tempfile
from unittest.mock import patch, MagicMock, PropertyMock

import pytest

from hashguard.pe_analyzer import (
    PEAnalysisResult,
    PESection,
    _entropy,
    _SUSPICIOUS_APIS,
    _PACKER_SECTIONS,
    _load_pe_indicators,
    analyze_pe,
    is_pe_file,
    PE_EXTENSIONS,
)


class TestEntropy:
    """Tests for Shannon entropy calculation."""

    def test_empty_data(self):
        assert _entropy(b"") == 0.0

    def test_uniform_data(self):
        # All same byte → entropy = 0
        assert _entropy(b"\x00" * 100) == 0.0

    def test_two_symbols_equal(self):
        # Two equal-frequency symbols → entropy ≈ 1.0
        data = b"\x00\x01" * 50
        ent = _entropy(data)
        assert abs(ent - 1.0) < 0.01

    def test_high_entropy(self):
        # Random-ish data should be high entropy
        data = bytes(range(256)) * 4
        ent = _entropy(data)
        assert ent > 7.9

    def test_low_entropy(self):
        data = b"AAAA" * 100
        ent = _entropy(data)
        assert ent == 0.0


class TestIsPEFile:
    """Tests for PE file detection."""

    def test_pe_by_extension(self, tmp_path):
        for ext in [".exe", ".dll", ".sys", ".scr"]:
            p = tmp_path / f"test{ext}"
            p.write_bytes(b"not a real PE")
            assert is_pe_file(str(p))

    def test_pe_by_mz_header(self, tmp_path):
        p = tmp_path / "test.bin"
        p.write_bytes(b"MZ" + b"\x00" * 100)
        assert is_pe_file(str(p))

    def test_non_pe_file(self, tmp_path):
        p = tmp_path / "test.txt"
        p.write_text("hello world")
        assert not is_pe_file(str(p))

    def test_nonexistent_file(self):
        assert not is_pe_file("/nonexistent/file.bin")


class TestPEAnalysisResult:
    """Tests for PEAnalysisResult dataclass."""

    def test_default_values(self):
        r = PEAnalysisResult()
        assert r.is_pe is False
        assert r.sections == []
        assert r.imports == {}
        assert r.suspicious_imports == []
        assert r.warnings == []
        assert r.packed is False

    def test_to_dict(self):
        sec = PESection(
            name=".text",
            virtual_size=4096,
            raw_size=4096,
            entropy=6.5,
            characteristics="EXEC | READ",
        )
        r = PEAnalysisResult(
            is_pe=True,
            machine="x86 (32-bit)",
            sections=[sec],
            imports={"kernel32.dll": ["CreateFileA"]},
            suspicious_imports=["kernel32.dll:VirtualAlloc"],
            packed=True,
            packer_hint="UPX",
            overall_entropy=7.2,
        )
        d = r.to_dict()
        assert d["is_pe"] is True
        assert d["machine"] == "x86 (32-bit)"
        assert len(d["sections"]) == 1
        assert d["sections"][0]["name"] == ".text"
        assert d["packed"] is True
        assert d["packer_hint"] == "UPX"


class TestAnalyzePE:
    """Tests for the analyze_pe function."""

    def test_non_pe_file(self, tmp_path):
        p = tmp_path / "test.txt"
        p.write_text("just text")
        result = analyze_pe(str(p))
        assert result.is_pe is False

    def test_invalid_pe_format(self, tmp_path):
        """File with MZ header but not a valid PE."""
        p = tmp_path / "fake.exe"
        p.write_bytes(b"MZ" + b"\x00" * 200)
        result = analyze_pe(str(p))
        # Should return without crashing, is_pe might be False
        assert isinstance(result, PEAnalysisResult)

    def test_nonexistent_file(self):
        result = analyze_pe("/nonexistent/file.exe")
        assert result.is_pe is False


# ── Indicators & constants ───────────────────────────────────────────────────


class TestLoadPEIndicators:
    def test_loaded_apis(self):
        assert isinstance(_SUSPICIOUS_APIS, set)
        assert len(_SUSPICIOUS_APIS) > 0

    def test_loaded_packer_sections(self):
        assert isinstance(_PACKER_SECTIONS, dict)

    def test_pe_extensions(self):
        for ext in [".exe", ".dll", ".sys", ".scr", ".drv", ".ocx", ".cpl"]:
            assert ext in PE_EXTENSIONS


# ── analyze_pe with mocked pefile ────────────────────────────────────────────


def _make_mock_section(name=b".text\x00\x00\x00", raw_data=b"\x00" * 512,
                       vsize=4096, rsize=512, chars=0x60000020):
    """Helper to create a mock PE section."""
    sec = MagicMock()
    sec.Name = name
    sec.get_data.return_value = raw_data
    sec.Misc_VirtualSize = vsize
    sec.SizeOfRawData = rsize
    sec.Characteristics = chars
    return sec


class TestAnalyzePEWithMockedPefile:
    """Test analyze_pe by mocking the pefile module."""

    def _make_pe_mock(self, machine=0x14C, timestamp=1609459200, ep=0x1000,
                      sections=None, imports=None):
        """Build a mock pefile.PE instance."""
        pe = MagicMock()
        pe.FILE_HEADER.Machine = machine
        pe.FILE_HEADER.TimeDateStamp = timestamp
        pe.OPTIONAL_HEADER.AddressOfEntryPoint = ep
        pe.sections = sections or [_make_mock_section()]
        if imports is not None:
            pe.DIRECTORY_ENTRY_IMPORT = imports
        else:
            del pe.DIRECTORY_ENTRY_IMPORT
        pe.parse_data_directories.return_value = None
        pe.close.return_value = None
        return pe

    @patch("hashguard.pe_analyzer.is_pe_file", return_value=True)
    def test_basic_pe_analysis(self, mock_ispe):
        pe_mock = self._make_pe_mock()
        mock_pefile = MagicMock()
        mock_pefile.PE.return_value = pe_mock
        mock_pefile.PEFormatError = type("PEFormatError", (Exception,), {})

        with patch.dict("sys.modules", {"pefile": mock_pefile}):
            with patch("hashguard.pe_analyzer.pefile", mock_pefile, create=True):
                result = analyze_pe("test.exe")

        assert result.is_pe is True
        assert result.machine == "x86 (32-bit)"
        assert result.entry_point == "0x00001000"
        assert len(result.sections) == 1

    @patch("hashguard.pe_analyzer.is_pe_file", return_value=True)
    def test_x64_machine(self, mock_ispe):
        pe_mock = self._make_pe_mock(machine=0x8664)
        mock_pefile = MagicMock()
        mock_pefile.PE.return_value = pe_mock
        mock_pefile.PEFormatError = type("PEFormatError", (Exception,), {})

        with patch.dict("sys.modules", {"pefile": mock_pefile}):
            with patch("hashguard.pe_analyzer.pefile", mock_pefile, create=True):
                result = analyze_pe("test.exe")

        assert result.machine == "x64 (64-bit)"

    @patch("hashguard.pe_analyzer.is_pe_file", return_value=True)
    def test_arm64_machine(self, mock_ispe):
        pe_mock = self._make_pe_mock(machine=0xAA64)
        mock_pefile = MagicMock()
        mock_pefile.PE.return_value = pe_mock
        mock_pefile.PEFormatError = type("PEFormatError", (Exception,), {})

        with patch.dict("sys.modules", {"pefile": mock_pefile}):
            with patch("hashguard.pe_analyzer.pefile", mock_pefile, create=True):
                result = analyze_pe("test.exe")

        assert result.machine == "ARM64"

    @patch("hashguard.pe_analyzer.is_pe_file", return_value=True)
    def test_unknown_machine(self, mock_ispe):
        pe_mock = self._make_pe_mock(machine=0x9999)
        mock_pefile = MagicMock()
        mock_pefile.PE.return_value = pe_mock
        mock_pefile.PEFormatError = type("PEFormatError", (Exception,), {})

        with patch.dict("sys.modules", {"pefile": mock_pefile}):
            with patch("hashguard.pe_analyzer.pefile", mock_pefile, create=True):
                result = analyze_pe("test.exe")

        assert "0x" in result.machine

    @patch("hashguard.pe_analyzer.is_pe_file", return_value=True)
    def test_high_entropy_packing_detection(self, mock_ispe):
        """Two high-entropy sections + overall > 7.0 → packed."""
        high_ent_data = bytes(range(256)) * 20  # ~8 bits entropy
        sec1 = _make_mock_section(name=b".data\x00\x00\x00", raw_data=high_ent_data,
                                  rsize=len(high_ent_data))
        sec2 = _make_mock_section(name=b".rsrc\x00\x00\x00", raw_data=high_ent_data,
                                  rsize=len(high_ent_data))
        pe_mock = self._make_pe_mock(sections=[sec1, sec2])
        mock_pefile = MagicMock()
        mock_pefile.PE.return_value = pe_mock
        mock_pefile.PEFormatError = type("PEFormatError", (Exception,), {})

        with patch.dict("sys.modules", {"pefile": mock_pefile}):
            with patch("hashguard.pe_analyzer.pefile", mock_pefile, create=True):
                result = analyze_pe("test.exe")

        assert result.packed is True
        assert "high entropy" in result.packer_hint.lower()

    @patch("hashguard.pe_analyzer.is_pe_file", return_value=True)
    def test_writable_exec_section_warning(self, mock_ispe):
        """Section with WRITE | EXEC should generate warning."""
        sec = _make_mock_section(
            name=b".text\x00\x00\x00",
            chars=0x20000000 | 0x40000000 | 0x80000000,  # EXEC | READ | WRITE
        )
        pe_mock = self._make_pe_mock(sections=[sec])
        mock_pefile = MagicMock()
        mock_pefile.PE.return_value = pe_mock
        mock_pefile.PEFormatError = type("PEFormatError", (Exception,), {})

        with patch.dict("sys.modules", {"pefile": mock_pefile}):
            with patch("hashguard.pe_analyzer.pefile", mock_pefile, create=True):
                result = analyze_pe("test.exe")

        assert any("writable and executable" in w for w in result.warnings)

    @patch("hashguard.pe_analyzer.is_pe_file", return_value=True)
    def test_packer_section_detection(self, mock_ispe):
        """Known packer section name → packed with hint."""
        if not _PACKER_SECTIONS:
            pytest.skip("No packer sections loaded")
        packer_name = next(iter(_PACKER_SECTIONS))
        padded = packer_name.encode().ljust(8, b"\x00")
        sec = _make_mock_section(name=padded)
        pe_mock = self._make_pe_mock(sections=[sec])
        mock_pefile = MagicMock()
        mock_pefile.PE.return_value = pe_mock
        mock_pefile.PEFormatError = type("PEFormatError", (Exception,), {})

        with patch.dict("sys.modules", {"pefile": mock_pefile}):
            with patch("hashguard.pe_analyzer.pefile", mock_pefile, create=True):
                result = analyze_pe("test.exe")

        assert result.packed is True
        assert result.packer_hint == _PACKER_SECTIONS[packer_name]

    @patch("hashguard.pe_analyzer.is_pe_file", return_value=True)
    def test_import_parsing_with_suspicious_api(self, mock_ispe):
        """Test import table parsing with a suspicious API."""
        if not _SUSPICIOUS_APIS:
            pytest.skip("No suspicious APIs loaded")
        sus_api = next(iter(_SUSPICIOUS_APIS))

        imp_func = MagicMock()
        imp_func.name = sus_api.encode()
        imp_func.ordinal = 1

        dll_entry = MagicMock()
        dll_entry.dll = b"kernel32.dll"
        dll_entry.imports = [imp_func]

        pe_mock = self._make_pe_mock(imports=[dll_entry])
        mock_pefile = MagicMock()
        mock_pefile.PE.return_value = pe_mock
        mock_pefile.PEFormatError = type("PEFormatError", (Exception,), {})

        with patch.dict("sys.modules", {"pefile": mock_pefile}):
            with patch("hashguard.pe_analyzer.pefile", mock_pefile, create=True):
                result = analyze_pe("test.exe")

        assert len(result.suspicious_imports) >= 1
        assert any(sus_api in s for s in result.suspicious_imports)
        assert any("suspicious API" in w for w in result.warnings)

    @patch("hashguard.pe_analyzer.is_pe_file", return_value=True)
    def test_invalid_timestamp(self, mock_ispe):
        """TimeDateStamp causes exception → compile_time = 'Invalid' (lines 166-167)."""
        pe_mock = self._make_pe_mock(timestamp=-999999999999)
        pe_mock.FILE_HEADER.TimeDateStamp = -999999999999
        mock_pefile = MagicMock()
        mock_pefile.PE.return_value = pe_mock
        mock_pefile.PEFormatError = type("PEFormatError", (Exception,), {})

        with patch.dict("sys.modules", {"pefile": mock_pefile}):
            with patch("hashguard.pe_analyzer.pefile", mock_pefile, create=True):
                result = analyze_pe("test.exe")

        assert result.compile_time == "Invalid"

    @patch("hashguard.pe_analyzer.is_pe_file", return_value=True)
    def test_section_name_decode_exception(self, mock_ispe):
        """Section Name.decode() raises → name is '<unknown>' (lines 180-181)."""
        sec = MagicMock()
        sec.Name.decode.side_effect = UnicodeDecodeError("utf-8", b"", 0, 1, "bad")
        sec.get_data.return_value = b"\x00" * 512
        sec.SizeOfRawData = 512
        sec.Misc_VirtualSize = 4096
        sec.Characteristics = 0x60000020

        pe_mock = self._make_pe_mock(sections=[sec])
        mock_pefile = MagicMock()
        mock_pefile.PE.return_value = pe_mock
        mock_pefile.PEFormatError = type("PEFormatError", (Exception,), {})

        with patch.dict("sys.modules", {"pefile": mock_pefile}):
            with patch("hashguard.pe_analyzer.pefile", mock_pefile, create=True):
                result = analyze_pe("test.exe")

        assert any(s.name == "<unknown>" for s in result.sections)

    @patch("hashguard.pe_analyzer.is_pe_file", return_value=True)
    def test_dll_name_decode_exception(self, mock_ispe):
        """DLL name decode raises → dll_name is '<unknown>' (lines 234-235)."""
        imp_func = MagicMock()
        imp_func.name = b"SomeFunc"
        imp_func.ordinal = 1

        dll_entry = MagicMock()
        dll_entry.dll.decode.side_effect = Exception("bad dll name")
        dll_entry.imports = [imp_func]

        pe_mock = self._make_pe_mock(imports=[dll_entry])
        mock_pefile = MagicMock()
        mock_pefile.PE.return_value = pe_mock
        mock_pefile.PEFormatError = type("PEFormatError", (Exception,), {})

        with patch.dict("sys.modules", {"pefile": mock_pefile}):
            with patch("hashguard.pe_analyzer.pefile", mock_pefile, create=True):
                result = analyze_pe("test.exe")

        assert "<unknown>" in result.imports

    @patch("hashguard.pe_analyzer.is_pe_file", return_value=True)
    def test_func_name_decode_exception(self, mock_ispe):
        """Import function name decode fails → fname = 'ord_N' (lines 241-242)."""
        imp_func = MagicMock()
        imp_func.name = MagicMock()
        imp_func.name.decode.side_effect = Exception("bad name")
        imp_func.ordinal = 42

        dll_entry = MagicMock()
        dll_entry.dll = b"kernel32.dll"
        dll_entry.imports = [imp_func]

        pe_mock = self._make_pe_mock(imports=[dll_entry])
        mock_pefile = MagicMock()
        mock_pefile.PE.return_value = pe_mock
        mock_pefile.PEFormatError = type("PEFormatError", (Exception,), {})

        with patch.dict("sys.modules", {"pefile": mock_pefile}):
            with patch("hashguard.pe_analyzer.pefile", mock_pefile, create=True):
                result = analyze_pe("test.exe")

        funcs = result.imports.get("kernel32.dll", [])
        assert any("ord_42" in f for f in funcs)

    @patch("hashguard.pe_analyzer.is_pe_file", return_value=True)
    def test_import_parsing_exception(self, mock_ispe):
        """parse_data_directories raises → caught gracefully (lines 247-248)."""
        pe_mock = self._make_pe_mock()
        pe_mock.parse_data_directories.side_effect = Exception("data dir error")
        mock_pefile = MagicMock()
        mock_pefile.PE.return_value = pe_mock
        mock_pefile.PEFormatError = type("PEFormatError", (Exception,), {})

        with patch.dict("sys.modules", {"pefile": mock_pefile}):
            with patch("hashguard.pe_analyzer.pefile", mock_pefile, create=True):
                result = analyze_pe("test.exe")

        assert result.is_pe is True
        assert result.imports == {}

    @patch("hashguard.pe_analyzer.is_pe_file", return_value=True)
    def test_import_parsing_clean_api(self, mock_ispe):
        """Non-suspicious imports should be recorded."""
        imp_func = MagicMock()
        imp_func.name = b"GetModuleHandleA"
        imp_func.ordinal = 1

        dll_entry = MagicMock()
        dll_entry.dll = b"kernel32.dll"
        dll_entry.imports = [imp_func]

        pe_mock = self._make_pe_mock(imports=[dll_entry])
        mock_pefile = MagicMock()
        mock_pefile.PE.return_value = pe_mock
        mock_pefile.PEFormatError = type("PEFormatError", (Exception,), {})

        with patch.dict("sys.modules", {"pefile": mock_pefile}):
            with patch("hashguard.pe_analyzer.pefile", mock_pefile, create=True):
                result = analyze_pe("test.exe")

        assert "kernel32.dll" in result.imports

    @patch("hashguard.pe_analyzer.is_pe_file", return_value=True)
    def test_pe_format_error(self, mock_ispe):
        """PEFormatError should return empty result."""
        mock_pefile = MagicMock()
        fmt_error = type("PEFormatError", (Exception,), {})
        mock_pefile.PEFormatError = fmt_error
        mock_pefile.PE.side_effect = fmt_error("bad format")

        with patch.dict("sys.modules", {"pefile": mock_pefile}):
            with patch("hashguard.pe_analyzer.pefile", mock_pefile, create=True):
                result = analyze_pe("test.exe")

        assert result.is_pe is False

    @patch("hashguard.pe_analyzer.is_pe_file", return_value=True)
    def test_generic_parse_exception(self, mock_ispe):
        """Generic exception during PE parsing should return empty result."""
        mock_pefile = MagicMock()
        mock_pefile.PEFormatError = type("PEFormatError", (Exception,), {})
        mock_pefile.PE.side_effect = RuntimeError("disk error")

        with patch.dict("sys.modules", {"pefile": mock_pefile}):
            with patch("hashguard.pe_analyzer.pefile", mock_pefile, create=True):
                result = analyze_pe("test.exe")

        assert result.is_pe is False

    @patch("hashguard.pe_analyzer.is_pe_file", return_value=True)
    def test_overall_entropy_calculation(self, mock_ispe):
        """Overall entropy should be weighted average of sections."""
        sec1 = _make_mock_section(name=b".text\x00\x00\x00",
                                  raw_data=b"\x00" * 100, rsize=100)
        sec2 = _make_mock_section(name=b".data\x00\x00\x00",
                                  raw_data=b"\x00" * 100, rsize=100)
        pe_mock = self._make_pe_mock(sections=[sec1, sec2])
        mock_pefile = MagicMock()
        mock_pefile.PE.return_value = pe_mock
        mock_pefile.PEFormatError = type("PEFormatError", (Exception,), {})

        with patch.dict("sys.modules", {"pefile": mock_pefile}):
            with patch("hashguard.pe_analyzer.pefile", mock_pefile, create=True):
                result = analyze_pe("test.exe")

        assert result.overall_entropy == 0.0

    @patch("hashguard.pe_analyzer.is_pe_file", return_value=True)
    def test_section_characteristics_flags(self, mock_ispe):
        """Test section characteristic flag parsing."""
        sec = _make_mock_section(chars=0x20000000)  # EXEC only
        pe_mock = self._make_pe_mock(sections=[sec])
        mock_pefile = MagicMock()
        mock_pefile.PE.return_value = pe_mock
        mock_pefile.PEFormatError = type("PEFormatError", (Exception,), {})

        with patch.dict("sys.modules", {"pefile": mock_pefile}):
            with patch("hashguard.pe_analyzer.pefile", mock_pefile, create=True):
                result = analyze_pe("test.exe")

        assert result.sections[0].characteristics == "EXEC"
