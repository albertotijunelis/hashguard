"""Tests for advanced PE analysis module."""

import struct
from unittest.mock import patch, MagicMock, PropertyMock
from pathlib import Path

import pytest

from hashguard.advanced_pe import (
    AdvancedPEResult,
    TLSInfo,
    AntiAnalysisInfo,
    OverlayInfo,
    SectionAnomaly,
    _entropy,
    _analyze_tls,
    _analyze_anti_analysis,
    _analyze_overlay,
    _analyze_sections,
    analyze_advanced_pe,
    ANTI_DEBUG_APIS,
    ANTI_VM_STRINGS,
    ANTI_SANDBOX_STRINGS,
    DEBUGGER_WINDOW_NAMES,
)


# ── Dataclass tests ──────────────────────────────────────────────────────────


class TestTLSInfo:
    def test_defaults(self):
        t = TLSInfo()
        assert t.has_tls is False
        assert t.callback_count == 0
        assert t.callback_addresses == []


class TestAntiAnalysisInfo:
    def test_defaults(self):
        a = AntiAnalysisInfo()
        assert a.total_detections == 0
        assert a.anti_debug_techniques == []


class TestOverlayInfo:
    def test_defaults(self):
        o = OverlayInfo()
        assert o.has_overlay is False
        assert o.size == 0


class TestSectionAnomaly:
    def test_creation(self):
        a = SectionAnomaly(name=".text", anomaly="W+X", severity="high")
        assert a.name == ".text"


class TestAdvancedPEResult:
    def test_to_dict_minimal(self):
        r = AdvancedPEResult(imphash="abc123")
        d = r.to_dict()
        assert d["imphash"] == "abc123"
        assert "tls" not in d
        assert "anti_analysis" not in d
        assert "overlay" not in d

    def test_to_dict_with_tls(self):
        r = AdvancedPEResult(
            imphash="abc",
            tls=TLSInfo(
                has_tls=True,
                callback_count=2,
                callback_addresses=["0x1000", "0x2000"],
                warning="TLS callbacks detected",
            ),
        )
        d = r.to_dict()
        assert d["tls"]["has_tls"] is True
        assert d["tls"]["callback_count"] == 2
        assert len(d["tls"]["callback_addresses"]) == 2

    def test_to_dict_with_anti_analysis(self):
        r = AdvancedPEResult(
            anti_analysis=AntiAnalysisInfo(
                anti_debug_techniques=[{"technique": "IsDebuggerPresent"}],
                anti_vm_techniques=[{"technique": "VMware"}],
                total_detections=2,
            )
        )
        d = r.to_dict()
        assert d["anti_analysis"]["total"] == 2
        assert len(d["anti_analysis"]["anti_debug"]) == 1
        assert len(d["anti_analysis"]["anti_vm"]) == 1

    def test_to_dict_with_overlay(self):
        r = AdvancedPEResult(
            overlay=OverlayInfo(
                has_overlay=True,
                offset=1024,
                size=2048,
                entropy=7.5,
                percentage=66.67,
            )
        )
        d = r.to_dict()
        assert d["overlay"]["has_overlay"] is True
        assert d["overlay"]["size"] == 2048
        assert d["overlay"]["percentage"] == 66.67

    def test_to_dict_with_section_anomalies(self):
        r = AdvancedPEResult(
            section_anomalies=[
                SectionAnomaly(name=".text", anomaly="W+X section", severity="high"),
            ]
        )
        d = r.to_dict()
        assert len(d["section_anomalies"]) == 1
        assert d["section_anomalies"][0]["severity"] == "high"


# ── Entropy tests ────────────────────────────────────────────────────────────


class TestEntropy:
    def test_empty(self):
        assert _entropy(b"") == 0.0

    def test_uniform_byte(self):
        assert _entropy(b"\x00" * 100) == 0.0

    def test_high_entropy(self):
        data = bytes(range(256)) * 10
        assert _entropy(data) > 7.9


# ── Constant completeness tests ──────────────────────────────────────────────


class TestConstants:
    def test_anti_debug_apis_populated(self):
        assert "IsDebuggerPresent" in ANTI_DEBUG_APIS
        assert "NtQueryInformationProcess" in ANTI_DEBUG_APIS
        assert len(ANTI_DEBUG_APIS) >= 10

    def test_anti_vm_strings_populated(self):
        labels = [s[0] for s in ANTI_VM_STRINGS]
        assert b"VMware" in labels
        assert b"VirtualBox" in labels
        assert len(ANTI_VM_STRINGS) >= 10

    def test_anti_sandbox_strings_populated(self):
        labels = [s[0] for s in ANTI_SANDBOX_STRINGS]
        assert b"SbieDll.dll" in labels
        assert len(ANTI_SANDBOX_STRINGS) >= 5

    def test_debugger_window_names(self):
        assert b"OllyDbg" in DEBUGGER_WINDOW_NAMES
        assert b"x64dbg" in DEBUGGER_WINDOW_NAMES


# ── analyze_advanced_pe tests ────────────────────────────────────────────────


class TestAnalyzeAdvancedPE:
    def test_nonexistent_file(self):
        result = analyze_advanced_pe("/no/such/file.exe")
        assert result.imphash == ""

    def test_non_pe_file(self, tmp_path):
        p = tmp_path / "test.txt"
        p.write_bytes(b"This is not a PE file")
        result = analyze_advanced_pe(str(p))
        assert result.imphash == ""

    def test_returns_result_dataclass(self, tmp_path):
        # Even for a file that fails PE parsing, should return AdvancedPEResult
        p = tmp_path / "bad.exe"
        p.write_bytes(b"MZ" + b"\x00" * 50)
        result = analyze_advanced_pe(str(p))
        assert isinstance(result, AdvancedPEResult)


# ── _analyze_tls tests ──────────────────────────────────────────────────────


class TestAnalyzeTLS:
    def test_no_tls_directory(self):
        pe = MagicMock(spec=[])  # No DIRECTORY_ENTRY_TLS attribute
        result = _analyze_tls(pe)
        assert result.has_tls is False
        assert result.callback_count == 0

    def test_tls_with_callbacks(self):
        pe = MagicMock()
        pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks = 0x10000
        pe.OPTIONAL_HEADER.ImageBase = 0x400000
        pe.get_offset_from_rva.return_value = 100
        pe.PE_TYPE = 0x10B  # PE32
        # Simulate 2 callbacks then null terminator
        pe.__data__ = (
            b"\x00" * 100
            + struct.pack("<I", 0x401000)
            + struct.pack("<I", 0x402000)
            + struct.pack("<I", 0)
        )
        result = _analyze_tls(pe)
        assert result.has_tls is True
        assert result.callback_count == 2
        assert len(result.callback_addresses) == 2
        assert "TLS callbacks detected" in result.warning

    def test_tls_no_callbacks(self):
        pe = MagicMock()
        pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks = 0
        result = _analyze_tls(pe)
        assert result.has_tls is True
        assert result.callback_count == 0


# ── _analyze_anti_analysis tests ────────────────────────────────────────────


class TestAnalyzeAntiAnalysis:
    def test_anti_debug_import_detected(self, tmp_path):
        pe = MagicMock()
        imp = MagicMock()
        imp.name = b"IsDebuggerPresent"
        dll = MagicMock()
        dll.imports = [imp]
        pe.DIRECTORY_ENTRY_IMPORT = [dll]

        f = tmp_path / "test.bin"
        f.write_bytes(b"NoVM strings here")

        import hashguard.advanced_pe as adv_pe
        mock_pefile = MagicMock()
        mock_pefile.DIRECTORY_ENTRY = {"IMAGE_DIRECTORY_ENTRY_IMPORT": 1}
        with patch.object(adv_pe, "pefile", mock_pefile, create=True):
            result = _analyze_anti_analysis(pe, f)
        assert len(result.anti_debug_techniques) >= 1
        techs = [t["technique"] for t in result.anti_debug_techniques]
        assert "IsDebuggerPresent" in techs

    def test_anti_vm_strings_detected(self, tmp_path):
        pe = MagicMock()
        del pe.DIRECTORY_ENTRY_IMPORT

        f = tmp_path / "test.bin"
        f.write_bytes(b"VMware VirtualBox VBOX vmtoolsd\x00")

        import hashguard.advanced_pe as adv_pe
        mock_pefile = MagicMock()
        mock_pefile.DIRECTORY_ENTRY = {"IMAGE_DIRECTORY_ENTRY_IMPORT": 1}
        with patch.object(adv_pe, "pefile", mock_pefile, create=True):
            result = _analyze_anti_analysis(pe, f)
        assert len(result.anti_vm_techniques) >= 3

    def test_anti_sandbox_strings_detected(self, tmp_path):
        pe = MagicMock()
        del pe.DIRECTORY_ENTRY_IMPORT

        f = tmp_path / "test.bin"
        f.write_bytes(b"SbieDll.dll\\sample\\sandbox\x00")

        import hashguard.advanced_pe as adv_pe
        mock_pefile = MagicMock()
        mock_pefile.DIRECTORY_ENTRY = {"IMAGE_DIRECTORY_ENTRY_IMPORT": 1}
        with patch.object(adv_pe, "pefile", mock_pefile, create=True):
            result = _analyze_anti_analysis(pe, f)
        assert len(result.anti_sandbox_techniques) >= 2

    def test_debugger_window_names_detected(self, tmp_path):
        pe = MagicMock()
        del pe.DIRECTORY_ENTRY_IMPORT

        f = tmp_path / "test.bin"
        f.write_bytes(b"OllyDbg x64dbg IDA WinDbg\x00")

        import hashguard.advanced_pe as adv_pe
        mock_pefile = MagicMock()
        mock_pefile.DIRECTORY_ENTRY = {"IMAGE_DIRECTORY_ENTRY_IMPORT": 1}
        with patch.object(adv_pe, "pefile", mock_pefile, create=True):
            result = _analyze_anti_analysis(pe, f)
        debugger_techs = [t for t in result.anti_debug_techniques if "FindWindow" in t.get("technique", "")]
        assert len(debugger_techs) >= 3

    def test_clean_file(self, tmp_path):
        pe = MagicMock()
        del pe.DIRECTORY_ENTRY_IMPORT

        f = tmp_path / "clean.bin"
        f.write_bytes(b"Hello world, nothing suspicious here.\n")

        import hashguard.advanced_pe as adv_pe
        mock_pefile = MagicMock()
        mock_pefile.DIRECTORY_ENTRY = {"IMAGE_DIRECTORY_ENTRY_IMPORT": 1}
        with patch.object(adv_pe, "pefile", mock_pefile, create=True):
            result = _analyze_anti_analysis(pe, f)
        assert result.total_detections == 0


# ── _analyze_overlay tests ──────────────────────────────────────────────────


class TestAnalyzeOverlay:
    def test_no_overlay(self):
        pe = MagicMock()
        pe.get_overlay_data_start_offset.return_value = None
        result = _analyze_overlay(pe, Path("dummy"))
        assert result.has_overlay is False

    def test_with_overlay(self, tmp_path):
        f = tmp_path / "test.exe"
        main_data = b"\x00" * 1000
        overlay_data = bytes(range(256)) * 4  # ~8 bits entropy
        f.write_bytes(main_data + overlay_data)

        pe = MagicMock()
        pe.get_overlay_data_start_offset.return_value = len(main_data)

        result = _analyze_overlay(pe, f)
        assert result.has_overlay is True
        assert result.offset == 1000
        assert result.size == len(overlay_data)
        assert result.percentage > 0
        assert result.entropy > 7.0

    def test_zero_overlay_size(self, tmp_path):
        f = tmp_path / "test.exe"
        f.write_bytes(b"\x00" * 1000)
        pe = MagicMock()
        pe.get_overlay_data_start_offset.return_value = 1000  # At the end
        result = _analyze_overlay(pe, f)
        assert result.has_overlay is False


# ── _analyze_sections tests ─────────────────────────────────────────────────


class TestAnalyzeSectionsDetailed:
    def _make_section(self, name=".text", chars=0x60000020, entropy=5.0,
                      raw_size=4096, vir_size=4096):
        sec = MagicMock()
        sec.Name = name.encode().ljust(8, b"\x00")
        sec.Characteristics = chars
        sec.get_entropy.return_value = entropy
        sec.SizeOfRawData = raw_size
        sec.Misc_VirtualSize = vir_size
        return sec

    def test_writable_executable_section(self):
        sec = self._make_section(chars=0x80000000 | 0x20000000)  # W+X
        pe = MagicMock()
        pe.sections = [sec]
        anomalies = _analyze_sections(pe)
        assert any("writable and executable" in a.anomaly for a in anomalies)
        assert any(a.severity == "high" for a in anomalies)

    def test_very_high_entropy(self):
        sec = self._make_section(entropy=7.5)
        pe = MagicMock()
        pe.sections = [sec]
        anomalies = _analyze_sections(pe)
        assert any("Very high entropy" in a.anomaly for a in anomalies)

    def test_high_entropy(self):
        sec = self._make_section(entropy=6.9)
        pe = MagicMock()
        pe.sections = [sec]
        anomalies = _analyze_sections(pe)
        assert any("High entropy" in a.anomaly for a in anomalies)

    def test_empty_section(self):
        sec = self._make_section(raw_size=0, vir_size=4096)
        pe = MagicMock()
        pe.sections = [sec]
        anomalies = _analyze_sections(pe)
        assert any("no raw data" in a.anomaly for a in anomalies)

    def test_raw_much_larger_than_virtual(self):
        sec = self._make_section(raw_size=100000, vir_size=1000)
        pe = MagicMock()
        pe.sections = [sec]
        anomalies = _analyze_sections(pe)
        assert any("larger than virtual" in a.anomaly for a in anomalies)

    def test_nonstandard_section_name(self):
        sec = self._make_section(name="UPX0")
        pe = MagicMock()
        pe.sections = [sec]
        anomalies = _analyze_sections(pe)
        assert any("Non-standard section name" in a.anomaly for a in anomalies)

    def test_standard_section_name_no_anomaly(self):
        sec = self._make_section(name=".text", entropy=5.0)
        pe = MagicMock()
        pe.sections = [sec]
        anomalies = _analyze_sections(pe)
        # Standard name, normal entropy, normal sizes → no anomalies
        assert len(anomalies) == 0

    def test_multiple_anomalies(self):
        sec = self._make_section(
            name="UPX0",
            chars=0x80000000 | 0x20000000,  # W+X
            entropy=7.5,
        )
        pe = MagicMock()
        pe.sections = [sec]
        anomalies = _analyze_sections(pe)
        assert len(anomalies) >= 3  # W+X, high entropy, non-standard name


# ── analyze_advanced_pe with mocked pefile ──────────────────────────────────


class TestAnalyzeAdvancedPEMocked:
    def _make_pe_mock(self):
        pe = MagicMock()
        pe.get_imphash.return_value = "abc123def456"
        pe.OPTIONAL_HEADER.MajorLinkerVersion = 14
        pe.OPTIONAL_HEADER.MinorLinkerVersion = 0
        pe.OPTIONAL_HEADER.DATA_DIRECTORY = []
        pe.parse_rich_header.return_value = {"values": [0x12345678]}
        pe.sections = []
        pe.get_overlay_data_start_offset.return_value = None
        pe.close.return_value = None
        # No TLS or debug by default
        del pe.DIRECTORY_ENTRY_TLS
        del pe.DIRECTORY_ENTRY_DEBUG
        del pe.DIRECTORY_ENTRY_COM_DESCRIPTOR
        del pe.DIRECTORY_ENTRY_IMPORT
        return pe

    @patch("hashguard.advanced_pe.HAS_PEFILE", True)
    def test_basic_advanced_analysis(self, tmp_path):
        pe_mock = self._make_pe_mock()
        mock_pefile = MagicMock()
        mock_pefile.PE.return_value = pe_mock
        mock_pefile.DIRECTORY_ENTRY = {"IMAGE_DIRECTORY_ENTRY_IMPORT": 1}
        mock_pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS = 0x20B

        f = tmp_path / "test.exe"
        f.write_bytes(b"MZ" + b"\x00" * 100)

        with patch("hashguard.advanced_pe.pefile", mock_pefile):
            result = analyze_advanced_pe(str(f))

        assert result.imphash == "abc123def456"
        assert result.linker_version == "14.0"
        assert result.rich_header_hash != ""

    @patch("hashguard.advanced_pe.HAS_PEFILE", True)
    def test_dotnet_detection(self, tmp_path):
        pe_mock = self._make_pe_mock()
        # Re-add COM descriptor for .NET
        pe_mock.DIRECTORY_ENTRY_COM_DESCRIPTOR = MagicMock()
        mock_pefile = MagicMock()
        mock_pefile.PE.return_value = pe_mock
        mock_pefile.DIRECTORY_ENTRY = {"IMAGE_DIRECTORY_ENTRY_IMPORT": 1}

        f = tmp_path / "test.exe"
        f.write_bytes(b"MZ" + b"\x00" * 100)

        with patch("hashguard.advanced_pe.pefile", mock_pefile):
            result = analyze_advanced_pe(str(f))

        assert result.is_dotnet is True

    @patch("hashguard.advanced_pe.HAS_PEFILE", True)
    def test_debug_info_detection(self, tmp_path):
        pe_mock = self._make_pe_mock()
        pe_mock.DIRECTORY_ENTRY_DEBUG = MagicMock()
        mock_pefile = MagicMock()
        mock_pefile.PE.return_value = pe_mock
        mock_pefile.DIRECTORY_ENTRY = {"IMAGE_DIRECTORY_ENTRY_IMPORT": 1}

        f = tmp_path / "test.exe"
        f.write_bytes(b"MZ" + b"\x00" * 100)

        with patch("hashguard.advanced_pe.pefile", mock_pefile):
            result = analyze_advanced_pe(str(f))

        assert result.has_debug_info is True


class TestDotNetViaDataDirectory:
    """Cover .NET detection via DATA_DIRECTORY iteration (lines 233-235)."""

    @patch("hashguard.advanced_pe.HAS_PEFILE", True)
    def test_dotnet_via_data_directory(self, tmp_path):
        pe_mock = MagicMock()
        pe_mock.get_imphash.return_value = ""
        pe_mock.OPTIONAL_HEADER.MajorLinkerVersion = 14
        pe_mock.OPTIONAL_HEADER.MinorLinkerVersion = 0
        # DATA_DIRECTORY with COM_DESCRIPTOR entry
        entry = MagicMock()
        entry.name = "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"
        entry.VirtualAddress = 0x2000
        pe_mock.OPTIONAL_HEADER.DATA_DIRECTORY = [entry]
        pe_mock.parse_rich_header.return_value = None
        pe_mock.sections = []
        pe_mock.get_overlay_data_start_offset.return_value = None
        pe_mock.close.return_value = None
        del pe_mock.DIRECTORY_ENTRY_TLS
        del pe_mock.DIRECTORY_ENTRY_DEBUG
        del pe_mock.DIRECTORY_ENTRY_COM_DESCRIPTOR
        del pe_mock.DIRECTORY_ENTRY_IMPORT

        mock_pefile = MagicMock()
        mock_pefile.PE.return_value = pe_mock
        mock_pefile.DIRECTORY_ENTRY = {"IMAGE_DIRECTORY_ENTRY_IMPORT": 1}

        f = tmp_path / "test.exe"
        f.write_bytes(b"MZ" + b"\x00" * 100)

        with patch("hashguard.advanced_pe.pefile", mock_pefile):
            result = analyze_advanced_pe(str(f))

        assert result.is_dotnet is True


class TestTLSCallbackParse:
    """Cover TLS callback parsing line 295."""

    @patch("hashguard.advanced_pe.HAS_PEFILE", True)
    def test_tls_callbacks_detected(self, tmp_path):
        import struct
        pe_mock = MagicMock()
        pe_mock.get_imphash.return_value = ""
        pe_mock.OPTIONAL_HEADER.MajorLinkerVersion = 14
        pe_mock.OPTIONAL_HEADER.MinorLinkerVersion = 0
        pe_mock.OPTIONAL_HEADER.DATA_DIRECTORY = []
        pe_mock.OPTIONAL_HEADER.ImageBase = 0x400000
        pe_mock.parse_rich_header.return_value = None
        pe_mock.sections = []
        pe_mock.get_overlay_data_start_offset.return_value = None
        pe_mock.close.return_value = None
        pe_mock.PE_TYPE = 0x10B  # PE32

        # TLS directory
        tls_struct = MagicMock()
        tls_struct.AddressOfCallBacks = 0x401000
        pe_mock.DIRECTORY_ENTRY_TLS.struct = tls_struct
        pe_mock.get_offset_from_rva.return_value = 0x100

        # Build fake __data__ with one callback address then 0
        addr1 = struct.pack("<I", 0x401234)
        addr2 = struct.pack("<I", 0)
        pe_mock.__data__ = b"\x00" * 0x100 + addr1 + addr2 + b"\x00" * 100
        pe_mock.__len__ = lambda s: len(pe_mock.__data__)

        del pe_mock.DIRECTORY_ENTRY_DEBUG
        del pe_mock.DIRECTORY_ENTRY_COM_DESCRIPTOR
        del pe_mock.DIRECTORY_ENTRY_IMPORT

        mock_pefile = MagicMock()
        mock_pefile.PE.return_value = pe_mock
        mock_pefile.DIRECTORY_ENTRY = {"IMAGE_DIRECTORY_ENTRY_IMPORT": 1}
        mock_pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS = 0x20B

        f = tmp_path / "test.exe"
        f.write_bytes(b"MZ" + b"\x00" * 100)

        with patch("hashguard.advanced_pe.pefile", mock_pefile):
            result = analyze_advanced_pe(str(f))

        assert result.tls.has_tls is True


class TestAntiAnalysisDetection:
    """Cover _analyze_anti_analysis and section anomalies."""

    def test_anti_debug_api_detected(self, tmp_path):
        """Anti-debug API found in imports (lines 329-337)."""
        from hashguard.advanced_pe import _analyze_anti_analysis

        pe_mock = MagicMock()
        imp1 = MagicMock()
        imp1.name = b"IsDebuggerPresent"
        imp2 = MagicMock()
        imp2.name = b"CheckRemoteDebuggerPresent"
        entry = MagicMock()
        entry.imports = [imp1, imp2]
        pe_mock.DIRECTORY_ENTRY_IMPORT = [entry]

        content = b"\x00" * 100
        f = tmp_path / "test.exe"
        f.write_bytes(content)

        result = _analyze_anti_analysis(pe_mock, f)
        assert result.total_detections > 0
        assert any("IsDebuggerPresent" in t["technique"] for t in result.anti_debug_techniques)

    def test_anti_vm_string_detected(self, tmp_path):
        """Anti-VM string found in file content (lines 347-350)."""
        from hashguard.advanced_pe import _analyze_anti_analysis

        pe_mock = MagicMock()
        del pe_mock.DIRECTORY_ENTRY_IMPORT
        pe_mock.parse_data_directories = MagicMock(side_effect=Exception("no imports"))

        f = tmp_path / "test.exe"
        f.write_bytes(b"MZ" + b"VMware" * 10 + b"\x00" * 100)

        result = _analyze_anti_analysis(pe_mock, f)
        assert any("VMware" in t.get("pattern", t.get("description", ""))
                    for t in result.anti_vm_techniques) or result.total_detections > 0

    def test_content_read_oserror(self, tmp_path):
        """OSError on file read sets content_lower to empty (lines 343-344)."""
        from hashguard.advanced_pe import _analyze_anti_analysis

        pe_mock = MagicMock()
        del pe_mock.DIRECTORY_ENTRY_IMPORT
        pe_mock.parse_data_directories = MagicMock(side_effect=Exception("no"))

        f = tmp_path / "nonexistent.exe"
        # Don't create the file — Path.read_bytes will raise
        result = _analyze_anti_analysis(pe_mock, f)
        assert result is not None


class TestSectionHighEntropy:
    """Cover section entropy check (lines 454-460)."""

    def test_section_medium_entropy(self):
        from hashguard.advanced_pe import _analyze_sections

        section = MagicMock()
        section.Name = b".text\x00\x00\x00"
        section.Characteristics = 0x40000000  # readable only
        section.get_entropy.return_value = 7.0  # Between 6.8 and 7.2
        section.SizeOfRawData = 1000
        section.Misc_VirtualSize = 1000

        pe_mock = MagicMock()
        pe_mock.sections = [section]

        anomalies = _analyze_sections(pe_mock)
        assert any("High entropy" in a.anomaly and "medium" == a.severity for a in anomalies)


class TestOverlayException:
    """Cover overlay analysis exception (lines 410-411)."""

    def test_overlay_exception(self, tmp_path):
        from hashguard.advanced_pe import _analyze_overlay

        pe_mock = MagicMock()
        pe_mock.get_overlay_data_start_offset.return_value = 100

        f = tmp_path / "test.exe"
        f.write_bytes(b"MZ" + b"\x00" * 200)

        # Make stat().st_size work but open() fail
        with patch("builtins.open", side_effect=OSError("can't read")):
            result = _analyze_overlay(pe_mock, f)
            # Should not crash, overlay info may be partial
            assert result is not None


class TestRichHeaderHashException:
    """Cover rich header hash computation exception (lines 251-252)."""

    def test_rich_header_exception(self, tmp_path):
        from hashguard.advanced_pe import analyze_advanced_pe

        pe_mock = MagicMock()
        pe_mock.get_imphash.return_value = ""
        pe_mock.OPTIONAL_HEADER.MajorLinkerVersion = 14
        pe_mock.OPTIONAL_HEADER.MinorLinkerVersion = 0
        pe_mock.OPTIONAL_HEADER.DATA_DIRECTORY = []
        pe_mock.sections = []
        del pe_mock.DIRECTORY_ENTRY_DEBUG
        del pe_mock.DIRECTORY_ENTRY_COM_DESCRIPTOR
        del pe_mock.DIRECTORY_ENTRY_TLS

        # Rich header parse returns data but struct.pack will fail
        pe_mock.parse_rich_header.return_value = {"values": ["not_an_int"]}

        mock_pefile = MagicMock()
        mock_pefile.PE.return_value = pe_mock
        mock_pefile.DIRECTORY_ENTRY = {"IMAGE_DIRECTORY_ENTRY_IMPORT": 1}
        mock_pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS = 0x20B

        f = tmp_path / "test.exe"
        f.write_bytes(b"MZ" + b"\x00" * 100)

        with patch("hashguard.advanced_pe.pefile", mock_pefile):
            result = analyze_advanced_pe(str(f))
            # Rich header hash exception caught silently
            assert result.rich_header_hash is None or result.rich_header_hash == ""


class TestAnalyzeAdvancedPEOuterException:
    """Cover outer exception handler (lines 266-267)."""

    def test_outer_exception_caught(self, tmp_path):
        from hashguard.advanced_pe import analyze_advanced_pe

        pe_mock = MagicMock()
        pe_mock.get_imphash.side_effect = RuntimeError("fatal")
        pe_mock.close = MagicMock()

        mock_pefile = MagicMock()
        mock_pefile.PE.return_value = pe_mock

        f = tmp_path / "test.exe"
        f.write_bytes(b"MZ" + b"\x00" * 100)

        with patch("hashguard.advanced_pe.pefile", mock_pefile):
            result = analyze_advanced_pe(str(f))
            assert result.imphash is None or result.imphash == ""
            pe_mock.close.assert_called()
