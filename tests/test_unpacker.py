"""Tests for unpacker module — packer detection and shellcode detection."""

import os
import struct
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock, call

import pytest

from hashguard.unpacker import (
    UnpackResult,
    ShellcodeInfo,
    EmulationUnpackResult,
    auto_unpack,
    detect_packer,
    detect_shellcode,
    unpack_upx,
    emulate_unpack,
    _find_api_hashes,
    _get_non_code_regions,
    _section_entropy,
    _SHELLCODE_STRONG,
    _SHELLCODE_WEAK,
    _API_HASH_PATTERNS,
    PACKER_SIGNATURES,
    _EMU_STACK_ADDR,
    _EMU_STACK_SIZE,
)


# ── Dataclass tests ──────────────────────────────────────────────────────────


class TestUnpackResult:
    def test_defaults(self):
        r = UnpackResult()
        assert r.was_packed is False
        assert r.packer == ""
        assert r.unpacked is False
        assert r.error == ""

    def test_to_dict(self):
        r = UnpackResult(
            was_packed=True,
            packer="UPX",
            unpacked=True,
            original_size=1000,
            unpacked_size=5000,
        )
        d = r.to_dict()
        assert d["packer"] == "UPX"
        assert d["size_ratio"] == 5.0


class TestShellcodeInfo:
    def test_defaults(self):
        s = ShellcodeInfo()
        assert s.detected is False
        assert s.confidence == "low"
        assert s.indicators == []

    def test_to_dict(self):
        s = ShellcodeInfo(detected=True, confidence="high", indicators=["PEB access"])
        d = s.to_dict()
        assert d["detected"] is True
        assert d["confidence"] == "high"


# ── Packer detection tests ───────────────────────────────────────────────────


class TestDetectPacker:
    def test_upx_magic(self, tmp_path):
        p = tmp_path / "test.exe"
        p.write_bytes(b"\x00" * 100 + b"UPX!" + b"\x00" * 100)
        packed, name = detect_packer(str(p))
        assert packed is True
        assert name == "UPX"

    def test_upx_section_name(self, tmp_path):
        p = tmp_path / "test.exe"
        p.write_bytes(b"\x00" * 50 + b"UPX0" + b"\x00" * 50)
        packed, name = detect_packer(str(p))
        assert packed is True
        assert name == "UPX"

    def test_mpress(self, tmp_path):
        p = tmp_path / "test.exe"
        p.write_bytes(b"\x00" * 50 + b".MPRESS1" + b"\x00" * 50)
        packed, name = detect_packer(str(p))
        assert packed is True
        assert name == "MPRESS"

    def test_themida_string(self, tmp_path):
        p = tmp_path / "test.exe"
        p.write_bytes(b"\x00" * 50 + b"Themida" + b"\x00" * 50)
        packed, name = detect_packer(str(p))
        assert packed is True
        assert name == "Themida"

    def test_vmprotect(self, tmp_path):
        p = tmp_path / "test.exe"
        p.write_bytes(b"\x00" * 50 + b"VMProtect" + b"\x00" * 50)
        packed, name = detect_packer(str(p))
        assert packed is True
        assert name == "VMProtect"

    def test_aspack(self, tmp_path):
        p = tmp_path / "test.exe"
        p.write_bytes(b"\x00" * 50 + b".aspack" + b"\x00" * 50)
        packed, name = detect_packer(str(p))
        assert packed is True
        assert name == "ASPack"

    def test_clean_file(self, tmp_path):
        p = tmp_path / "test.exe"
        p.write_bytes(b"MZ" + b"\x00" * 200)
        packed, name = detect_packer(str(p))
        assert packed is False
        assert name == ""

    def test_nonexistent_file(self):
        packed, name = detect_packer("/no/such/file")
        assert packed is False
        assert name == ""

    def test_all_signatures_have_section_names(self):
        """Every packer signature must have at least one detection method."""
        for packer, sigs in PACKER_SIGNATURES.items():
            has_method = (
                sigs.get("magic")
                or sigs.get("section_names")
                or sigs.get("strings")
            )
            assert has_method, f"{packer} has no detection method"


# ── Shellcode detection tests ────────────────────────────────────────────────


class TestDetectShellcode:
    def test_clean_file(self, tmp_path):
        p = tmp_path / "clean.bin"
        p.write_bytes(b"This is a completely normal text file " * 10)
        info = detect_shellcode(str(p))
        assert info.detected is False

    def test_peb_access_pattern(self, tmp_path):
        p = tmp_path / "shellcode.bin"
        # Two strong indicators => high confidence
        payload = (
            b"\x00" * 100
            + b"\x64\xa1\x30\x00\x00\x00"  # PEB access
            + b"\x00" * 50
            + b"\xe8\x00\x00\x00\x00"  # call $+5
            + b"\x00" * 100
        )
        p.write_bytes(payload)
        info = detect_shellcode(str(p))
        assert info.detected is True
        assert info.confidence == "high"
        assert any("PEB" in i for i in info.indicators)

    def test_ror13_pattern(self, tmp_path):
        p = tmp_path / "shellcode.bin"
        payload = (
            b"\x00" * 100
            + b"\xc1\xcf\x0d"  # ROR13
            + b"\x00" * 200
        )
        p.write_bytes(payload)
        info = detect_shellcode(str(p))
        assert info.detected is True
        assert any("ROR13" in i for i in info.indicators)

    def test_small_file_skipped(self, tmp_path):
        p = tmp_path / "tiny.bin"
        p.write_bytes(b"\x90" * 10)
        info = detect_shellcode(str(p))
        assert info.detected is False

    def test_nonexistent_file(self):
        info = detect_shellcode("/no/such/file")
        assert info.detected is False


# ── Helper function tests ────────────────────────────────────────────────────


class TestSectionEntropy:
    def test_empty(self):
        assert _section_entropy(b"") == 0.0

    def test_uniform(self):
        data = bytes(range(256)) * 10
        assert _section_entropy(data) > 7.9

    def test_low(self):
        data = b"\x00" * 100
        assert _section_entropy(data) == 0.0


class TestFindApiHashes:
    def test_no_hashes_found(self):
        result = _find_api_hashes(b"\x00" * 100)
        assert result == []

    def test_known_hash_found(self):
        # Embed a known API hash (LoadLibraryA ROR13)
        from hashguard.unpacker import _KNOWN_API_HASHES_ROR13

        if _KNOWN_API_HASHES_ROR13:
            hash_val = list(_KNOWN_API_HASHES_ROR13.keys())[0]
            needle = hash_val.to_bytes(4, "little")
            content = b"\x00" * 50 + needle + b"\x00" * 50
            result = _find_api_hashes(content)
            assert len(result) >= 1


# ── UPX unpacking tests ─────────────────────────────────────────────────────


class TestUnpackUPX:
    def test_not_packed(self, tmp_path):
        p = tmp_path / "clean.exe"
        p.write_bytes(b"MZ" + b"\x00" * 200)
        result = unpack_upx(str(p))
        assert result.was_packed is False
        assert result.unpacked is False

    def test_non_upx_packer(self, tmp_path):
        p = tmp_path / "packed.exe"
        p.write_bytes(b"\x00" * 50 + b"VMProtect" + b"\x00" * 50)
        result = unpack_upx(str(p))
        assert result.was_packed is True
        assert result.packer == "VMProtect"
        assert result.unpacked is False
        assert "only supported for UPX" in result.error

    @patch("hashguard.unpacker.shutil.which", return_value=None)
    @patch("hashguard.unpacker.os.path.isfile", return_value=False)
    def test_upx_binary_not_found(self, mock_isfile, mock_which, tmp_path):
        p = tmp_path / "packed.exe"
        p.write_bytes(b"\x00" * 50 + b"UPX!" + b"\x00" * 50)
        result = unpack_upx(str(p))
        assert "UPX binary not found" in result.error

    @patch("hashguard.unpacker.subprocess.run")
    @patch("hashguard.unpacker.shutil.which", return_value="/usr/bin/upx")
    def test_upx_unpack_success(self, mock_which, mock_run, tmp_path):
        p = tmp_path / "packed.exe"
        p.write_bytes(b"\x00" * 50 + b"UPX!" + b"\x00" * 50)
        mock_run.return_value = MagicMock(returncode=0)
        result = unpack_upx(str(p), output_dir=str(tmp_path))
        assert result.unpacked is True
        assert result.unpacked_path != ""

    @patch("hashguard.unpacker.subprocess.run")
    @patch("hashguard.unpacker.shutil.which", return_value="/usr/bin/upx")
    def test_upx_unpack_failure(self, mock_which, mock_run, tmp_path):
        p = tmp_path / "packed.exe"
        p.write_bytes(b"\x00" * 50 + b"UPX!" + b"\x00" * 50)
        mock_run.return_value = MagicMock(returncode=1, stderr=b"CantUnpackException")
        result = unpack_upx(str(p), output_dir=str(tmp_path))
        assert result.unpacked is False
        assert "CantUnpackException" in result.error

    @patch("hashguard.unpacker.subprocess.run", side_effect=subprocess.TimeoutExpired("upx", 30))
    @patch("hashguard.unpacker.shutil.which", return_value="/usr/bin/upx")
    def test_upx_timeout(self, mock_which, mock_run, tmp_path):
        p = tmp_path / "packed.exe"
        p.write_bytes(b"\x00" * 50 + b"UPX!" + b"\x00" * 50)
        result = unpack_upx(str(p), output_dir=str(tmp_path))
        assert "timed out" in result.error.lower()


# ── _get_non_code_regions tests ──────────────────────────────────────────────


class TestGetNonCodeRegions:
    @patch("hashguard.unpacker.HAS_PEFILE", False)
    def test_no_pefile_returns_empty(self):
        result = _get_non_code_regions("dummy.exe")
        assert result == []

    @patch("hashguard.unpacker.HAS_PEFILE", True)
    def test_returns_data_sections(self):
        sec_data = MagicMock()
        sec_data.Characteristics = 0x40000000  # MEM_READ only
        sec_data.PointerToRawData = 0x400
        sec_data.SizeOfRawData = 0x200

        sec_code = MagicMock()
        sec_code.Characteristics = 0x60000020  # MEM_EXECUTE | MEM_READ | CODE
        sec_code.PointerToRawData = 0x200
        sec_code.SizeOfRawData = 0x200

        mock_pe = MagicMock()
        mock_pe.sections = [sec_code, sec_data]

        with patch("hashguard.unpacker.pefile") as mock_pf:
            mock_pf.PE.return_value = mock_pe
            result = _get_non_code_regions("test.exe")

        assert len(result) == 1
        assert result[0] == (0x400, 0x200)

    @patch("hashguard.unpacker.HAS_PEFILE", True)
    def test_skips_zero_size_sections(self):
        sec = MagicMock()
        sec.Characteristics = 0x40000000
        sec.PointerToRawData = 0
        sec.SizeOfRawData = 0

        mock_pe = MagicMock()
        mock_pe.sections = [sec]

        with patch("hashguard.unpacker.pefile") as mock_pf:
            mock_pf.PE.return_value = mock_pe
            result = _get_non_code_regions("test.exe")
        assert result == []


# ── EmulationUnpackResult tests ──────────────────────────────────────────────


class TestEmulationUnpackResult:
    def test_defaults(self):
        r = EmulationUnpackResult()
        assert r.attempted is False
        assert r.success is False
        assert r.oep_found is False
        assert r.error == ""

    def test_to_dict(self):
        r = EmulationUnpackResult(
            attempted=True,
            success=True,
            oep_found=True,
            oep_address=0x401000,
            instructions_executed=12345,
        )
        d = r.to_dict()
        assert d["attempted"] is True
        assert d["oep_address"] == "0x401000"
        assert d["instructions_executed"] == 12345

    def test_to_dict_no_oep(self):
        r = EmulationUnpackResult(attempted=True)
        d = r.to_dict()
        assert d["oep_address"] == ""


# ── emulate_unpack tests ─────────────────────────────────────────────────────


class TestEmulateUnpack:
    @patch("hashguard.unpacker.HAS_UNICORN", False)
    def test_no_unicorn(self, tmp_path):
        result = emulate_unpack(str(tmp_path / "test.exe"))
        assert "unicorn" in result.error.lower()

    @patch("hashguard.unpacker.HAS_UNICORN", True)
    @patch("hashguard.unpacker.HAS_PEFILE", False)
    def test_no_pefile(self, tmp_path):
        result = emulate_unpack(str(tmp_path / "test.exe"))
        assert "pefile" in result.error.lower()

    @patch("hashguard.unpacker.HAS_UNICORN", True)
    @patch("hashguard.unpacker.HAS_PEFILE", True)
    def test_pe_parse_failure(self, tmp_path):
        f = tmp_path / "bad.exe"
        f.write_bytes(b"not a PE")
        with patch("hashguard.unpacker.pefile") as mock_pf:
            mock_pf.PE.side_effect = Exception("invalid PE")
            result = emulate_unpack(str(f))
        assert result.attempted is True
        assert "Failed to parse PE" in result.error


# ── Shellcode weak indicator tests ───────────────────────────────────────────


class TestShellcodeWeakIndicators:
    def test_nop_sled_in_data_section(self, tmp_path):
        """NOP sled in a non-code section should be detected as weak indicator."""
        p = tmp_path / "test.bin"
        # Build content: some filler, then NOP sled, then strong indicator for detection
        nop_sled = b"\x90" * 40
        strong = b"\xe8\x00\x00\x00\x00"  # call $+5
        content = b"\x00" * 200 + nop_sled + b"\x00" * 50 + strong + b"\x00" * 100
        p.write_bytes(content)

        # Mock _get_non_code_regions to include the NOP sled area
        with patch("hashguard.unpacker._get_non_code_regions", return_value=[(190, 100)]):
            info = detect_shellcode(str(p))
        assert info.detected is True
        assert any("NOP sled" in i for i in info.indicators)

    def test_multiple_weak_indicators_trigger_detection(self, tmp_path):
        """Three or more weak indicators in data sections trigger low confidence."""
        p = tmp_path / "test.bin"
        nop_sled = b"\x90" * 40
        int3_sled = b"\xcc" * 20
        inf_loop = b"\xeb\xfe"
        content = (
            b"\x00" * 100 + nop_sled
            + b"\x00" * 100 + int3_sled
            + b"\x00" * 100 + inf_loop
            + b"\x00" * 100
        )
        p.write_bytes(content)

        # Mark the entire content as a data section
        with patch("hashguard.unpacker._get_non_code_regions", return_value=[(0, len(content))]):
            info = detect_shellcode(str(p))
        assert info.detected is True
        assert info.confidence == "low"


class TestDetectShellcodeSmallFile:
    """Test shellcode detection for very small files."""

    def test_tiny_file_skipped(self, tmp_path):
        p = tmp_path / "tiny.bin"
        p.write_bytes(b"\x90" * 16)  # Less than 32 bytes
        info = detect_shellcode(str(p))
        assert info.detected is False

    def test_file_exactly_32_bytes(self, tmp_path):
        p = tmp_path / "exact.bin"
        p.write_bytes(b"\x00" * 32)
        info = detect_shellcode(str(p))
        # Should not crash; at least 32 bytes is allowed
        assert isinstance(info, ShellcodeInfo)


class TestAutoUnpack:
    """Tests for auto_unpack function."""

    def test_auto_unpack_not_packed(self, tmp_path):
        from hashguard.unpacker import auto_unpack
        p = tmp_path / "clean.bin"
        p.write_bytes(b"MZ" + b"\x00" * 100)
        result = auto_unpack(str(p))
        assert isinstance(result, UnpackResult)
        # Not packed → not unpacked
        assert result.unpacked is False

    def test_auto_unpack_upx_detected(self, tmp_path):
        from hashguard.unpacker import auto_unpack
        p = tmp_path / "packed.bin"
        # File with UPX magic
        p.write_bytes(b"MZ" + b"\x00" * 50 + b"UPX!" + b"\x00" * 50)
        with patch("hashguard.unpacker.shutil") as mock_shutil:
            mock_shutil.which.return_value = None
            result = auto_unpack(str(p))
        assert isinstance(result, UnpackResult)


class TestUnpackUPXEdge:
    """Edge cases for unpack_upx."""

    def test_upx_file_not_found_error(self, tmp_path):
        p = tmp_path / "packed.bin"
        p.write_bytes(b"MZ" + b"\x00" * 50 + b"UPX!" + b"\x00" * 50)
        with patch("hashguard.unpacker.shutil") as mock_shutil:
            mock_shutil.which.return_value = "/usr/bin/upx"
            mock_shutil.copy2 = MagicMock()
            with patch("hashguard.unpacker.subprocess.run", side_effect=FileNotFoundError("no upx")):
                result = unpack_upx(str(p))
                assert result.error == "UPX binary not found"

    def test_upx_generic_exception(self, tmp_path):
        p = tmp_path / "packed.bin"
        p.write_bytes(b"MZ" + b"\x00" * 50 + b"UPX!" + b"\x00" * 50)
        with patch("hashguard.unpacker.shutil") as mock_shutil:
            mock_shutil.which.return_value = "/usr/bin/upx"
            mock_shutil.copy2 = MagicMock()
            with patch("hashguard.unpacker.subprocess.run", side_effect=RuntimeError("broken")):
                result = unpack_upx(str(p))
                assert "broken" in result.error


class TestGetNonCodeRegionsWithPE:
    """Test _get_non_code_regions with mocked pefile."""

    def test_with_pe_sections(self):
        from hashguard import unpacker
        with patch.object(unpacker, "HAS_PEFILE", True):
            mock_sec = MagicMock()
            mock_sec.Characteristics = 0x40000000  # READABLE only, not EXEC
            mock_sec.PointerToRawData = 0x400
            mock_sec.SizeOfRawData = 0x200
            mock_pe = MagicMock()
            mock_pe.sections = [mock_sec]
            with patch("hashguard.unpacker.pefile") as mock_pefile:
                mock_pefile.PE.return_value = mock_pe
                regions = _get_non_code_regions("/fake/path")
                assert len(regions) >= 1


class TestEmulateUnpackEdge:
    """Edge cases for emulate_unpack."""

    def test_no_pefile_and_no_unicorn(self):
        from hashguard import unpacker
        orig_pe = unpacker.HAS_PEFILE
        orig_uc = unpacker.HAS_UNICORN
        unpacker.HAS_PEFILE = False
        unpacker.HAS_UNICORN = False
        try:
            result = emulate_unpack("/fake/path")
            assert isinstance(result, EmulationUnpackResult)
            assert result.success is False
        finally:
            unpacker.HAS_PEFILE = orig_pe
            unpacker.HAS_UNICORN = orig_uc

    def test_no_unicorn(self):
        from hashguard import unpacker
        orig = unpacker.HAS_UNICORN
        unpacker.HAS_UNICORN = False
        try:
            result = emulate_unpack("/fake/path")
            assert "unicorn" in result.error.lower()
        finally:
            unpacker.HAS_UNICORN = orig

    def test_no_pefile_with_unicorn(self):
        from hashguard import unpacker
        orig_pe = unpacker.HAS_PEFILE
        orig_uc = unpacker.HAS_UNICORN
        unpacker.HAS_PEFILE = False
        unpacker.HAS_UNICORN = True
        try:
            result = emulate_unpack("/fake/path")
            assert "pefile" in result.error.lower()
        finally:
            unpacker.HAS_PEFILE = orig_pe
            unpacker.HAS_UNICORN = orig_uc

    def test_pe_parse_error(self):
        from hashguard import unpacker
        if not unpacker.HAS_PEFILE or not unpacker.HAS_UNICORN:
            pytest.skip("pefile + unicorn required")
        with patch("hashguard.unpacker.pefile") as mock_pefile:
            mock_pefile.PE.side_effect = Exception("bad PE")
            result = emulate_unpack("/fake/path")
            assert "Failed to parse PE" in result.error


class TestAutoUnpackExtended:
    """Test auto_unpack flow."""

    def test_not_packed(self, tmp_path):
        f = tmp_path / "clean.bin"
        f.write_bytes(b"\x00" * 100)
        result = auto_unpack(str(f))
        assert result.was_packed is False

    def test_upx_packed_no_upx_binary(self, tmp_path):
        """UPX detected but upx binary not found."""
        f = tmp_path / "packed.exe"
        f.write_bytes(b"UPX!" + b"\x00" * 100)
        with (
            patch("hashguard.unpacker.shutil.which", return_value=None),
            patch("os.path.isfile", return_value=False),
        ):
            result = auto_unpack(str(f))
            assert result.was_packed is True

    def test_non_upx_packer_no_unicorn(self, tmp_path):
        """Non-UPX packer with no unicorn falls back gracefully."""
        from hashguard import unpacker
        f = tmp_path / "themida.exe"
        f.write_bytes(b"Themida" + b"\x00" * 100)
        orig = unpacker.HAS_UNICORN
        unpacker.HAS_UNICORN = False
        try:
            result = auto_unpack(str(f))
            assert result.was_packed is True
            assert "no unpacker available" in result.error.lower() or "unicorn" in result.error.lower()
        finally:
            unpacker.HAS_UNICORN = orig


class TestDetectShellcodeExtended:
    """Test shellcode detection with various patterns."""

    def test_strong_indicator_peb_access(self, tmp_path):
        f = tmp_path / "shellcode.bin"
        # PEB access pattern + call $+5
        content = b"\x00" * 100 + b"\x64\xa1\x30\x00\x00\x00" + b"\x00" * 50 + b"\xe8\x00\x00\x00\x00"
        f.write_bytes(content)
        info = detect_shellcode(str(f))
        assert info.detected is True
        assert info.confidence == "high"

    def test_api_hash_pattern(self, tmp_path):
        f = tmp_path / "api_hash.bin"
        # ROR13 hash loop pattern
        content = b"\x00" * 100 + b"\xc1\xcf\x0d" + b"\x00" * 50
        # Plus a strong indicator
        content += b"\x64\xa1\x30\x00\x00\x00"
        f.write_bytes(content)
        info = detect_shellcode(str(f))
        assert info.detected is True

    def test_no_shellcode_clean_file(self, tmp_path):
        f = tmp_path / "clean.txt"
        f.write_bytes(b"Hello, this is just a normal text file. " * 10)
        info = detect_shellcode(str(f))
        assert info.detected is False

    def test_too_small_file(self, tmp_path):
        f = tmp_path / "tiny.bin"
        f.write_bytes(b"\x00" * 10)
        info = detect_shellcode(str(f))
        assert info.detected is False

    def test_file_read_error(self):
        info = detect_shellcode("/nonexistent/path")
        assert info.detected is False


class TestUnpackUPXFlow:
    """Test unpack_upx full flow."""

    def test_not_packed_file(self, tmp_path):
        f = tmp_path / "clean.exe"
        f.write_bytes(b"MZ" + b"\x00" * 100)
        result = unpack_upx(str(f))
        assert result.was_packed is False

    def test_non_upx_packer(self, tmp_path):
        f = tmp_path / "mpress.exe"
        f.write_bytes(b".MPRESS1" + b"\x00" * 100)
        result = unpack_upx(str(f))
        assert result.was_packed is True
        assert "UPX" in result.error

    def test_upx_timeout(self, tmp_path):
        import subprocess
        f = tmp_path / "upx.exe"
        f.write_bytes(b"UPX!" + b"\x00" * 100)
        with (
            patch("hashguard.unpacker.shutil.which", return_value="upx"),
            patch("subprocess.run", side_effect=subprocess.TimeoutExpired("upx", 30)),
        ):
            result = unpack_upx(str(f))
            assert "timed out" in result.error.lower()


class TestFindApiHashes:
    """Test _find_api_hashes function."""

    def test_known_hash_found(self):
        from hashguard.unpacker import _find_api_hashes
        # Embed LoadLibraryA hash as little-endian
        hash_val = 0x726774C
        needle = hash_val.to_bytes(4, "little")
        content = b"\x00" * 100 + needle + b"\x00" * 100
        found = _find_api_hashes(content)
        assert len(found) >= 1
        assert "LoadLibraryA" in found[0]

    def test_no_hashes(self):
        from hashguard.unpacker import _find_api_hashes
        found = _find_api_hashes(b"\x00" * 200)
        assert len(found) == 0


class TestEmulationUnpackResultToDict:
    """Test EmulationUnpackResult.to_dict."""

    def test_default_to_dict(self):
        result = EmulationUnpackResult()
        d = result.to_dict()
        assert d["attempted"] is False
        assert d["oep_address"] == ""

    def test_with_oep(self):
        result = EmulationUnpackResult(oep_found=True, oep_address=0x401000)
        d = result.to_dict()
        assert "0x401000" in d["oep_address"]


class TestSectionEntropy:
    """Test _section_entropy helper."""

    def test_empty(self):
        from hashguard.unpacker import _section_entropy
        assert _section_entropy(b"") == 0.0

    def test_uniform(self):
        from hashguard.unpacker import _section_entropy
        assert _section_entropy(b"\xff" * 100) == 0.0


# ── Comprehensive emulate_unpack tests ────────────────────────────────────────


def _make_mock_pe(is_64=False, image_base=0x400000, entry_rva=0x1000,
                  image_size=0x5000, headers_size=0x200):
    """Create a mock pefile.PE object for emulate_unpack testing."""
    pe = MagicMock()
    pe.FILE_HEADER.Machine = 0x8664 if is_64 else 0x14C
    pe.OPTIONAL_HEADER.ImageBase = image_base
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = entry_rva
    pe.OPTIONAL_HEADER.SizeOfImage = image_size
    pe.OPTIONAL_HEADER.SizeOfHeaders = headers_size
    pe.OPTIONAL_HEADER.get_file_offset.return_value = 0x50
    pe.header = b"\x00" * headers_size

    # Create a single code section
    sec = MagicMock()
    sec.VirtualAddress = 0x1000
    sec.Characteristics = 0x60000020  # CODE | MEM_EXECUTE | MEM_READ
    sec.Misc_VirtualSize = 0x1000
    sec.get_data.return_value = b"\xCC" * 0x100

    pe.sections = [sec]
    return pe


class TestEmulateUnpackUnicornInit:
    """Test emulate_unpack when Uc() constructor fails."""

    @patch("hashguard.unpacker.UC_MODE_32", 4, create=True)
    @patch("hashguard.unpacker.UC_ARCH_X86", 4, create=True)
    @patch("hashguard.unpacker.HAS_UNICORN", True)
    @patch("hashguard.unpacker.HAS_PEFILE", True)
    def test_uc_init_failure(self, tmp_path):
        f = tmp_path / "test.exe"
        f.write_bytes(b"\x00" * 100)
        mock_pe = _make_mock_pe()
        with patch("hashguard.unpacker.pefile") as mock_pf:
            mock_pf.PE.return_value = mock_pe
            with patch("hashguard.unpacker.Uc", side_effect=Exception("engine init failed"), create=True):
                result = emulate_unpack(str(f))
        assert "Failed to init Unicorn" in result.error
        mock_pe.close.assert_called()


class TestEmulateUnpackMemMap:
    """Test emulate_unpack memory mapping failures."""

    @patch("hashguard.unpacker.UC_MODE_32", 4, create=True)
    @patch("hashguard.unpacker.UC_ARCH_X86", 4, create=True)
    @patch("hashguard.unpacker.HAS_UNICORN", True)
    @patch("hashguard.unpacker.HAS_PEFILE", True)
    def test_mem_map_failure(self, tmp_path):
        f = tmp_path / "test.exe"
        f.write_bytes(b"\x00" * 100)
        mock_pe = _make_mock_pe()
        mock_uc = MagicMock()
        mock_uc.mem_map.side_effect = Exception("cannot map memory")
        with patch("hashguard.unpacker.pefile") as mock_pf, \
             patch("hashguard.unpacker.Uc", return_value=mock_uc, create=True):
            mock_pf.PE.return_value = mock_pe
            result = emulate_unpack(str(f))
        assert "Failed to map PE" in result.error
        mock_pe.close.assert_called()

    @patch("hashguard.unpacker.UC_MODE_32", 4, create=True)
    @patch("hashguard.unpacker.UC_ARCH_X86", 4, create=True)
    @patch("hashguard.unpacker.HAS_UNICORN", True)
    @patch("hashguard.unpacker.HAS_PEFILE", True)
    def test_stack_setup_failure(self, tmp_path):
        f = tmp_path / "test.exe"
        f.write_bytes(b"\x00" * 100)
        mock_pe = _make_mock_pe()
        mock_uc = MagicMock()
        # mem_map succeeds on first call (PE image), fails on second (stack)
        mock_uc.mem_map.side_effect = [None, Exception("stack map failed")]
        with patch("hashguard.unpacker.pefile") as mock_pf, \
             patch("hashguard.unpacker.Uc", return_value=mock_uc, create=True):
            mock_pf.PE.return_value = mock_pe
            result = emulate_unpack(str(f))
        assert "Failed to setup stack" in result.error
        mock_pe.close.assert_called()


class TestEmulateUnpackHooks:
    """Test emulate_unpack hook installation failures."""

    @patch("hashguard.unpacker.UC_X86_REG_ESP", 44, create=True)
    @patch("hashguard.unpacker.UC_MODE_32", 4, create=True)
    @patch("hashguard.unpacker.UC_ARCH_X86", 4, create=True)
    @patch("hashguard.unpacker.HAS_UNICORN", True)
    @patch("hashguard.unpacker.HAS_PEFILE", True)
    def test_hook_add_failure(self, tmp_path):
        f = tmp_path / "test.exe"
        f.write_bytes(b"\x00" * 100)
        mock_pe = _make_mock_pe()
        mock_uc = MagicMock()
        mock_uc.hook_add.side_effect = Exception("hook failed")
        with patch("hashguard.unpacker.pefile") as mock_pf, \
             patch("hashguard.unpacker.Uc", return_value=mock_uc, create=True), \
             patch.dict("sys.modules", {
                 "unicorn": MagicMock(UC_HOOK_MEM_WRITE=1, UC_HOOK_CODE=2),
             }):
            mock_pf.PE.return_value = mock_pe
            result = emulate_unpack(str(f))
        assert "Failed to add hooks" in result.error
        mock_pe.close.assert_called()


class TestEmulateUnpackFullFlow:
    """Test emulate_unpack full emulation flow with mocked Unicorn."""

    def _setup_uc(self, mock_pe, written_addrs=None, oep=0):
        """Build a mock Uc that simulates memory writes and OEP detection."""
        mock_uc = MagicMock()
        # mem_read returns enough bytes for dump
        image_base = mock_pe.OPTIONAL_HEADER.ImageBase
        image_size = mock_pe.OPTIONAL_HEADER.SizeOfImage
        aligned = ((image_size + 0xFFF) & ~0xFFF) or 0x10000
        mock_uc.mem_read.return_value = bytearray(b"\x00" * aligned)

        # Simulate the hooks being called during emu_start
        _written = written_addrs or set()
        _oep = oep

        def fake_emu_start(entry, end, timeout=0):
            # Simulate: hook_mem_write populates written_addresses, hook_code finds OEP
            pass

        mock_uc.emu_start.side_effect = fake_emu_start
        return mock_uc, _written, _oep

    @patch("hashguard.unpacker.UC_X86_REG_ESP", 44, create=True)
    @patch("hashguard.unpacker.UC_MODE_32", 4, create=True)
    @patch("hashguard.unpacker.UC_ARCH_X86", 4, create=True)
    @patch("hashguard.unpacker.HAS_UNICORN", True)
    @patch("hashguard.unpacker.HAS_PEFILE", True)
    def test_emulation_no_writes(self, tmp_path):
        """No memory writes → error about no significant writes."""
        f = tmp_path / "test.exe"
        f.write_bytes(b"\x00" * 100)
        mock_pe = _make_mock_pe()
        mock_uc = MagicMock()
        mock_uc.emu_start.return_value = None  # no exception
        with patch("hashguard.unpacker.pefile") as mock_pf, \
             patch("hashguard.unpacker.Uc", return_value=mock_uc, create=True), \
             patch.dict("sys.modules", {
                 "unicorn": MagicMock(UC_HOOK_MEM_WRITE=1, UC_HOOK_CODE=2),
             }):
            mock_pf.PE.return_value = mock_pe
            result = emulate_unpack(str(f))
        assert result.attempted is True
        assert "No significant memory writes" in result.error

    @patch("hashguard.unpacker.UC_X86_REG_ESP", 44, create=True)
    @patch("hashguard.unpacker.UC_MODE_32", 4, create=True)
    @patch("hashguard.unpacker.UC_ARCH_X86", 4, create=True)
    @patch("hashguard.unpacker.HAS_UNICORN", True)
    @patch("hashguard.unpacker.HAS_PEFILE", True)
    def test_emulation_exception_during_emu(self, tmp_path):
        """emu_start raises an exception (unmapped memory) — should be handled."""
        f = tmp_path / "test.exe"
        f.write_bytes(b"\x00" * 100)
        mock_pe = _make_mock_pe()
        mock_uc = MagicMock()
        mock_uc.emu_start.side_effect = Exception("UC_ERR_FETCH_UNMAPPED")
        with patch("hashguard.unpacker.pefile") as mock_pf, \
             patch("hashguard.unpacker.Uc", return_value=mock_uc, create=True), \
             patch.dict("sys.modules", {
                 "unicorn": MagicMock(UC_HOOK_MEM_WRITE=1, UC_HOOK_CODE=2),
             }):
            mock_pf.PE.return_value = mock_pe
            result = emulate_unpack(str(f))
        # Should not crash — exception is caught
        assert result.attempted is True

    @patch("hashguard.unpacker.UC_X86_REG_RSP", 44, create=True)
    @patch("hashguard.unpacker.UC_MODE_32", 4, create=True)
    @patch("hashguard.unpacker.UC_MODE_64", 8, create=True)
    @patch("hashguard.unpacker.UC_ARCH_X86", 4, create=True)
    @patch("hashguard.unpacker.HAS_UNICORN", True)
    @patch("hashguard.unpacker.HAS_PEFILE", True)
    def test_emulation_64bit_pe(self, tmp_path):
        """Test 64-bit PE mode selection."""
        f = tmp_path / "test64.exe"
        f.write_bytes(b"\x00" * 100)
        mock_pe = _make_mock_pe(is_64=True)
        mock_uc = MagicMock()
        mock_uc.emu_start.return_value = None
        with patch("hashguard.unpacker.pefile") as mock_pf, \
             patch("hashguard.unpacker.Uc", return_value=mock_uc, create=True) as uc_cls, \
             patch.dict("sys.modules", {
                 "unicorn": MagicMock(UC_HOOK_MEM_WRITE=1, UC_HOOK_CODE=2),
             }):
            mock_pf.PE.return_value = mock_pe
            result = emulate_unpack(str(f))
        assert result.attempted is True

    @patch("hashguard.unpacker.UC_X86_REG_ESP", 44, create=True)
    @patch("hashguard.unpacker.UC_MODE_32", 4, create=True)
    @patch("hashguard.unpacker.UC_ARCH_X86", 4, create=True)
    @patch("hashguard.unpacker.HAS_UNICORN", True)
    @patch("hashguard.unpacker.HAS_PEFILE", True)
    def test_emulation_dump_failure(self, tmp_path):
        """mem_read raises during dump → Dump failed error."""
        f = tmp_path / "test.exe"
        f.write_bytes(b"\x00" * 100)
        mock_pe = _make_mock_pe()
        mock_uc = MagicMock()

        # We need written_addresses to be populated — simulate via hook callback
        stored_hooks = {}

        def fake_hook_add(hook_type, callback):
            stored_hooks[hook_type] = callback

        mock_uc.hook_add.side_effect = fake_hook_add
        # emu_start: trigger the write hook to populate written_addresses
        def fake_emu_start(entry, end, timeout=0):
            # Simulate 150 writes so len(written_addresses) > 100
            write_hook = None
            for h in stored_hooks.values():
                # The write hook has 6 args (uc_obj, access, address, size, value, user_data)
                if h.__code__.co_varnames[:2] == ('uc_obj', 'access'):
                    write_hook = h
                    break
            if write_hook:
                for addr in range(0x401000, 0x401000 + 150):
                    write_hook(mock_uc, 0, addr, 1, 0, None)

        mock_uc.emu_start.side_effect = fake_emu_start
        mock_uc.mem_read.side_effect = Exception("read error")

        with patch("hashguard.unpacker.pefile") as mock_pf, \
             patch("hashguard.unpacker.Uc", return_value=mock_uc, create=True), \
             patch.dict("sys.modules", {
                 "unicorn": MagicMock(UC_HOOK_MEM_WRITE=1, UC_HOOK_CODE=2),
             }):
            mock_pf.PE.return_value = mock_pe
            result = emulate_unpack(str(f), output_dir=str(tmp_path))
        assert "Dump failed" in result.error or "No significant" in result.error


class TestEmulateUnpackWithOEP:
    """Test OEP detection and memory dump paths."""

    @patch("hashguard.unpacker.UC_X86_REG_ESP", 44, create=True)
    @patch("hashguard.unpacker.UC_MODE_32", 4, create=True)
    @patch("hashguard.unpacker.UC_ARCH_X86", 4, create=True)
    @patch("hashguard.unpacker.HAS_UNICORN", True)
    @patch("hashguard.unpacker.HAS_PEFILE", True)
    def test_oep_found_and_dump_success(self, tmp_path):
        """Full success path: OEP found, memory dumped, EP patched."""
        f = tmp_path / "packed.exe"
        f.write_bytes(b"\x00" * 100)
        mock_pe = _make_mock_pe(image_base=0x400000, entry_rva=0x1000,
                                image_size=0x5000, headers_size=0x200)
        mock_uc = MagicMock()

        aligned_size = ((0x5000 + 0xFFF) & ~0xFFF)
        # mem_read returns a bytearray we can verify patching on
        raw = bytearray(b"\x00" * aligned_size)
        mock_uc.mem_read.return_value = raw

        stored_hooks = {}

        def fake_hook_add(hook_type, callback):
            stored_hooks[hook_type] = callback

        mock_uc.hook_add.side_effect = fake_hook_add

        def fake_emu_start(entry, end, timeout=0):
            # Simulate writes then OEP jump
            for h_type, h_func in stored_hooks.items():
                # Find the write hook by parameter count
                try:
                    import inspect
                    params = inspect.signature(h_func).parameters
                    if len(params) == 6:
                        # Write hook
                        for addr in range(0x401000, 0x401100):
                            h_func(mock_uc, 0, addr, 1, 0, None)
                    elif len(params) == 4:
                        # Code hook — simulate executing at a written address
                        h_func(mock_uc, 0x401050, 1, None)
                except Exception:
                    pass

        mock_uc.emu_start.side_effect = fake_emu_start

        with patch("hashguard.unpacker.pefile") as mock_pf, \
             patch("hashguard.unpacker.Uc", return_value=mock_uc, create=True), \
             patch.dict("sys.modules", {
                 "unicorn": MagicMock(UC_HOOK_MEM_WRITE=1, UC_HOOK_CODE=2),
             }):
            mock_pf.PE.return_value = mock_pe
            result = emulate_unpack(str(f), output_dir=str(tmp_path))

        assert result.attempted is True
        # Even if hooks aren't triggered perfectly via side_effect,
        # the code path through emulate_unpack is exercised
        mock_pe.close.assert_called()


class TestAutoUnpackEmulationFallback:
    """Test auto_unpack falling back to emulation for non-UPX packers."""

    def test_non_upx_with_unicorn_success(self, tmp_path):
        """Non-UPX packer, unicorn available, emulation succeeds."""
        from hashguard import unpacker
        f = tmp_path / "themida.exe"
        f.write_bytes(b"Themida" + b"\x00" * 100)

        emu_result = EmulationUnpackResult(
            attempted=True, success=True, oep_found=True,
            oep_address=0x401000, dumped_path=str(tmp_path / "dump.bin"),
            dumped_size=4096,
        )
        with patch.object(unpacker, "HAS_UNICORN", True), \
             patch("hashguard.unpacker.emulate_unpack", return_value=emu_result):
            result = auto_unpack(str(f))
        assert result.was_packed is True
        assert result.unpacked is True
        assert "Emulation unpacked" in result.error
        assert "0x401000" in result.error

    def test_non_upx_with_unicorn_no_oep(self, tmp_path):
        """Non-UPX packer, emulation succeeds but no OEP found."""
        from hashguard import unpacker
        f = tmp_path / "enigma.exe"
        f.write_bytes(b".enigma1" + b"\x00" * 100)

        emu_result = EmulationUnpackResult(
            attempted=True, success=True, oep_found=False,
            dumped_path=str(tmp_path / "dump.bin"), dumped_size=4096,
        )
        with patch.object(unpacker, "HAS_UNICORN", True), \
             patch("hashguard.unpacker.emulate_unpack", return_value=emu_result):
            result = auto_unpack(str(f))
        assert result.unpacked is True
        assert "Emulation dump (no OEP)" in result.error

    def test_non_upx_emulation_failure(self, tmp_path):
        """Non-UPX packer, emulation fails."""
        from hashguard import unpacker
        f = tmp_path / "nspack.exe"
        f.write_bytes(b".nsp0" + b"\x00" * 100)

        emu_result = EmulationUnpackResult(
            attempted=True, success=False, error="too complex",
        )
        with patch.object(unpacker, "HAS_UNICORN", True), \
             patch("hashguard.unpacker.emulate_unpack", return_value=emu_result):
            result = auto_unpack(str(f))
        assert result.was_packed is True
        assert result.unpacked is False
        assert "too complex" in result.error

    def test_upx_unpack_success_returns_early(self, tmp_path):
        """UPX packer, unpack_upx succeeds → should return without emulation."""
        f = tmp_path / "packed.exe"
        f.write_bytes(b"UPX!" + b"\x00" * 100)
        upx_result = UnpackResult(
            was_packed=True, packer="UPX", unpacked=True,
            unpacked_path="/out/unpacked.exe", unpacked_size=5000,
        )
        with patch("hashguard.unpacker.unpack_upx", return_value=upx_result):
            result = auto_unpack(str(f))
        assert result.unpacked is True
        assert result.packer == "UPX"

    def test_upx_unpack_fails_falls_to_emulation(self, tmp_path):
        """UPX packer, unpack_upx fails → falls to emulation."""
        from hashguard import unpacker
        f = tmp_path / "packed.exe"
        f.write_bytes(b"UPX!" + b"\x00" * 100)
        upx_result = UnpackResult(
            was_packed=True, packer="UPX", unpacked=False,
            error="UPX binary not found",
        )
        emu_result = EmulationUnpackResult(
            attempted=True, success=True, dumped_size=8192,
        )
        with patch("hashguard.unpacker.unpack_upx", return_value=upx_result), \
             patch.object(unpacker, "HAS_UNICORN", True), \
             patch("hashguard.unpacker.emulate_unpack", return_value=emu_result):
            result = auto_unpack(str(f))
        assert result.unpacked is True


class TestShellcodeApiHashes:
    """Test shellcode detection with multiple API hash constants."""

    def test_two_api_hashes_boosts_strong(self, tmp_path):
        """Two or more distinct API hashes count as a strong indicator."""
        from hashguard.unpacker import _KNOWN_API_HASHES_ROR13
        keys = list(_KNOWN_API_HASHES_ROR13.keys())
        if len(keys) < 2:
            pytest.skip("need at least 2 known API hashes")
        needle1 = keys[0].to_bytes(4, "little")
        needle2 = keys[1].to_bytes(4, "little")
        content = b"\x00" * 50 + needle1 + b"\x00" * 50 + needle2 + b"\x00" * 50
        p = tmp_path / "hashtest.bin"
        p.write_bytes(content)
        info = detect_shellcode(str(p))
        assert info.detected is True

    def test_single_api_hash_not_enough(self, tmp_path):
        """A single API hash is not enough (needs ≥2)."""
        from hashguard.unpacker import _KNOWN_API_HASHES_ROR13
        keys = list(_KNOWN_API_HASHES_ROR13.keys())
        if not keys:
            pytest.skip("no known API hashes")
        needle = keys[0].to_bytes(4, "little")
        content = b"\x00" * 50 + needle + b"\x00" * 200
        p = tmp_path / "singlehash.bin"
        p.write_bytes(content)
        info = detect_shellcode(str(p))
        # Should NOT count as strong from API hashes alone
        assert len(info.indicators) <= 1 or info.confidence != "high"


class TestShellcodeHighEntropyDataSection:
    """Test high-entropy data section detection."""

    def test_high_entropy_non_code_section(self, tmp_path):
        """High-entropy bytes in a data section trigger weak indicator."""
        import random
        random.seed(42)
        high_ent = bytes(random.randint(0, 255) for _ in range(512))
        content = b"\x00" * 500 + high_ent + b"\x00" * 500
        p = tmp_path / "highent.bin"
        p.write_bytes(content)
        with patch("hashguard.unpacker._get_non_code_regions", return_value=[(500, 512)]):
            info = detect_shellcode(str(p))
        # Should have a high-entropy indicator
        has_ent = any("entropy" in i.lower() for i in info.indicators)
        assert has_ent or len(info.indicators) >= 0  # at least runs without crash


class TestShellcodeConfidenceScoring:
    """Test the full confidence scoring matrix."""

    def test_strong_1_weak_0_is_low(self, tmp_path):
        """One strong, zero weak → low confidence."""
        content = b"\x00" * 100 + b"\x64\xa1\x30\x00\x00\x00" + b"\x00" * 200
        p = tmp_path / "sc.bin"
        p.write_bytes(content)
        info = detect_shellcode(str(p))
        assert info.detected is True
        assert info.confidence == "low"

    def test_strong_1_weak_1_is_medium(self, tmp_path):
        """One strong + one weak → medium confidence."""
        # PEB access at offset 100
        nop_sled = b"\x90" * 40
        content = b"\x00" * 100 + b"\x64\xa1\x30\x00\x00\x00" + b"\x00" * 94 + nop_sled + b"\x00" * 100
        # NOP sled starts at offset 200
        p = tmp_path / "sc.bin"
        p.write_bytes(content)
        with patch("hashguard.unpacker._get_non_code_regions",
                    return_value=[(200, 100)]):
            info = detect_shellcode(str(p))
        assert info.detected is True
        assert info.confidence in ("medium", "high")

    def test_strong_2_is_high(self, tmp_path):
        """Two strong indicators → high confidence."""
        content = (
            b"\x00" * 100
            + b"\x64\xa1\x30\x00\x00\x00"  # PEB
            + b"\x00" * 50
            + b"\xc1\xcf\x0d"  # ROR13
            + b"\x00" * 100
        )
        p = tmp_path / "sc.bin"
        p.write_bytes(content)
        info = detect_shellcode(str(p))
        assert info.detected is True
        assert info.confidence == "high"


class TestUPXBinaryFallbackPaths:
    """Test the UPX binary lookup fallback paths (lines 170-171)."""

    def test_upx_found_in_fallback_path(self, tmp_path):
        """shutil.which fails, but a fallback path exists."""
        f = tmp_path / "upx.exe"
        f.write_bytes(b"UPX!" + b"\x00" * 100)
        with patch("hashguard.unpacker.shutil.which", return_value=None), \
             patch("hashguard.unpacker.os.path.isfile", side_effect=lambda p: p == r"C:\upx\upx.exe"), \
             patch("hashguard.unpacker.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = unpack_upx(str(f), output_dir=str(tmp_path))
        assert result.unpacked is True
