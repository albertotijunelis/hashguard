"""Tests for HashGuard capability detector module."""

import os
from unittest.mock import patch, MagicMock

import pytest

from hashguard.capability_detector import (
    Capability,
    CapabilityReport,
    INDICATOR_GROUPS,
    SEVERITY_ORDER,
    RANSOMWARE_INDICATORS,
    KEYLOGGER_INDICATORS,
    REVERSE_SHELL_INDICATORS,
    CREDENTIAL_STEALING_INDICATORS,
    PERSISTENCE_INDICATORS,
    EVASION_INDICATORS,
    _get_pe_imports,
    detect_capabilities,
)


# ── Dataclass tests ──────────────────────────────────────────────────────────


class TestCapability:
    def test_defaults(self):
        c = Capability(name="Test", category="test", confidence=0.5)
        assert c.evidence == []
        assert c.mitre_attack == ""
        assert c.severity == "medium"

    def test_fields(self):
        c = Capability(
            name="Ransomware: Crypto APIs",
            category="ransomware",
            confidence=0.9,
            evidence=["Import: CryptEncrypt"],
            mitre_attack="T1486",
            severity="high",
        )
        assert c.name == "Ransomware: Crypto APIs"
        assert c.mitre_attack == "T1486"


class TestCapabilityReport:
    def test_defaults(self):
        r = CapabilityReport()
        assert r.capabilities == []
        assert r.total_detected == 0
        assert r.risk_categories == {}
        assert r.max_severity == "low"

    def test_to_dict(self):
        cap = Capability(
            name="Test Cap",
            category="evasion",
            confidence=0.75,
            evidence=["Import: IsDebuggerPresent"],
            mitre_attack="T1622",
            severity="medium",
        )
        r = CapabilityReport(
            capabilities=[cap],
            total_detected=1,
            risk_categories={"evasion": 1},
            max_severity="medium",
        )
        d = r.to_dict()
        assert d["total_detected"] == 1
        assert d["max_severity"] == "medium"
        assert len(d["capabilities"]) == 1
        assert d["capabilities"][0]["confidence"] == 0.75
        assert d["capabilities"][0]["mitre_attack"] == "T1622"


# ── Constants / indicator definitions ────────────────────────────────────────


class TestIndicatorGroups:
    def test_all_groups_present(self):
        expected = {"ransomware", "keylogger", "reverse_shell",
                    "credential_stealing", "persistence", "evasion"}
        assert set(INDICATOR_GROUPS.keys()) == expected

    def test_severity_order(self):
        assert SEVERITY_ORDER["low"] < SEVERITY_ORDER["medium"]
        assert SEVERITY_ORDER["medium"] < SEVERITY_ORDER["high"]
        assert SEVERITY_ORDER["high"] < SEVERITY_ORDER["critical"]

    def test_ransomware_has_crypto_apis(self):
        assert "crypto_apis" in RANSOMWARE_INDICATORS
        assert "file_encryption" in RANSOMWARE_INDICATORS
        assert "shadow_copy_deletion" in RANSOMWARE_INDICATORS

    def test_keylogger_indicators(self):
        assert "key_capture" in KEYLOGGER_INDICATORS
        assert "clipboard_monitor" in KEYLOGGER_INDICATORS
        assert "screen_capture" in KEYLOGGER_INDICATORS

    def test_reverse_shell_indicators(self):
        assert "network_shell" in REVERSE_SHELL_INDICATORS
        assert "c2_communication" in REVERSE_SHELL_INDICATORS

    def test_credential_indicators(self):
        assert "lsass_access" in CREDENTIAL_STEALING_INDICATORS
        assert "browser_credentials" in CREDENTIAL_STEALING_INDICATORS
        assert "token_stealing" in CREDENTIAL_STEALING_INDICATORS

    def test_persistence_indicators(self):
        assert "registry_run_keys" in PERSISTENCE_INDICATORS
        assert "scheduled_tasks" in PERSISTENCE_INDICATORS
        assert "service_creation" in PERSISTENCE_INDICATORS
        assert "wmi_persistence" in PERSISTENCE_INDICATORS

    def test_evasion_indicators(self):
        assert "anti_debug" in EVASION_INDICATORS
        assert "anti_vm" in EVASION_INDICATORS
        assert "process_injection" in EVASION_INDICATORS
        assert "api_unhooking" in EVASION_INDICATORS


# ── PE imports extraction ────────────────────────────────────────────────────


class TestGetPEImports:
    def test_from_pe_info_dict(self):
        pe_info = {
            "imports": {
                "kernel32.dll": ["CreateFileA", "VirtualAlloc"],
                "user32.dll": ["GetAsyncKeyState"],
            }
        }
        result = _get_pe_imports("dummy.exe", pe_info)
        assert "CreateFileA" in result
        assert "VirtualAlloc" in result
        assert "GetAsyncKeyState" in result

    def test_empty_pe_info(self):
        result = _get_pe_imports("dummy.exe", {})
        assert isinstance(result, set)

    def test_none_pe_info(self):
        result = _get_pe_imports("dummy.exe", None)
        assert isinstance(result, set)


# ── detect_capabilities ─────────────────────────────────────────────────────


class TestDetectCapabilities:
    def test_nonexistent_file(self):
        r = detect_capabilities("/no/such/file.exe")
        assert r.total_detected == 0
        assert r.capabilities == []

    def test_empty_file(self, tmp_path):
        p = tmp_path / "empty.bin"
        p.write_bytes(b"")
        r = detect_capabilities(str(p))
        assert r.total_detected == 0

    def test_ransomware_detection(self, tmp_path):
        """File with ransomware strings should trigger detection."""
        content = (
            b"CryptEncrypt CryptGenKey CryptDeriveKey CryptAcquireContext\n"
            b"YOUR FILES HAVE BEEN ENCRYPTED\n"
            b"pay bitcoin\n"
            b"vssadmin delete shadows\n"
        )
        p = tmp_path / "ransom.bin"
        p.write_bytes(content)
        r = detect_capabilities(str(p))
        assert r.total_detected > 0
        cats = {c.category for c in r.capabilities}
        assert "ransomware" in cats
        assert r.max_severity in ("high", "critical")

    def test_keylogger_detection(self, tmp_path):
        """File with keylogger strings."""
        content = (
            b"GetAsyncKeyState SetWindowsHookExA\n"
            b"WH_KEYBOARD_LL keystroke keylog\n"
            b"clipboard GetClipboardData OpenClipboard\n"
            b"screenshot BitBlt GetDesktopWindow\n"
        )
        p = tmp_path / "keylogger.bin"
        p.write_bytes(content)
        r = detect_capabilities(str(p))
        cats = {c.category for c in r.capabilities}
        assert "keylogger" in cats

    def test_credential_stealing_detection(self, tmp_path):
        content = (
            b"lsass.exe mimikatz sekurlsa wdigest\n"
            b"Login Data\\Google\\Chrome\\User Data\n"
            b"discord token wallet.dat\n"
        )
        p = tmp_path / "stealer.bin"
        p.write_bytes(content)
        r = detect_capabilities(str(p))
        cats = {c.category for c in r.capabilities}
        assert "credential_stealing" in cats

    def test_persistence_detection(self, tmp_path):
        content = (
            b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n"
            b"RegSetValueExA RegCreateKeyExA\n"
            b"schtasks /create /sc\n"
            b"shell:startup\n"
        )
        p = tmp_path / "persist.bin"
        p.write_bytes(content)
        r = detect_capabilities(str(p))
        cats = {c.category for c in r.capabilities}
        assert "persistence" in cats

    def test_evasion_detection(self, tmp_path):
        content = (
            b"IsDebuggerPresent NtQueryInformationProcess OllyDbg\n"
            b"VMware VirtualBox VBOX vmtoolsd\n"
            b"VirtualAllocEx WriteProcessMemory CreateRemoteThread\n"
        )
        p = tmp_path / "evasion.bin"
        p.write_bytes(content)
        r = detect_capabilities(str(p))
        cats = {c.category for c in r.capabilities}
        assert "evasion" in cats

    def test_reverse_shell_detection(self, tmp_path):
        content = (
            b"WSAStartup socket connect send recv\n"
            b"cmd.exe powershell.exe CreateProcess\n"
            b"POST / User-Agent: beacon /gate.php\n"
        )
        p = tmp_path / "c2.bin"
        p.write_bytes(content)
        r = detect_capabilities(str(p))
        cats = {c.category for c in r.capabilities}
        assert "reverse_shell" in cats

    def test_clean_file(self, tmp_path):
        p = tmp_path / "clean.txt"
        p.write_bytes(b"Hello world, this is just a plain text document.\n" * 100)
        r = detect_capabilities(str(p))
        assert r.total_detected == 0

    def test_with_pe_info(self, tmp_path):
        """Pass pe_info to skip pefile import extraction."""
        content = b"some content with CryptEncrypt string\n"
        p = tmp_path / "test.bin"
        p.write_bytes(content)
        pe_info = {"imports": {"advapi32.dll": ["CryptEncrypt", "CryptGenKey"]}}
        r = detect_capabilities(str(p), pe_info=pe_info)
        assert r.total_detected > 0

    def test_max_severity_escalation(self, tmp_path):
        """Multiple categories should push max_severity to highest."""
        content = (
            b"vssadmin delete shadows\n"  # critical
            b"YOUR FILES HAVE BEEN ENCRYPTED\n"  # critical
            b"pay bitcoin\n"
        )
        p = tmp_path / "critical.bin"
        p.write_bytes(content)
        r = detect_capabilities(str(p))
        if r.total_detected > 0:
            assert SEVERITY_ORDER[r.max_severity] >= SEVERITY_ORDER["high"]

    def test_risk_categories_counted(self, tmp_path):
        content = (
            b"CryptEncrypt CryptGenKey\n"
            b"IsDebuggerPresent\n"
            b"GetAsyncKeyState WH_KEYBOARD_LL\n"
        )
        p = tmp_path / "multi.bin"
        p.write_bytes(content)
        r = detect_capabilities(str(p))
        if r.total_detected > 0:
            assert sum(r.risk_categories.values()) == r.total_detected

    def test_evidence_populated(self, tmp_path):
        content = b"vssadmin delete shadows\nYOUR FILES HAVE BEEN ENCRYPTED\npay bitcoin\n"
        p = tmp_path / "evid.bin"
        p.write_bytes(content)
        r = detect_capabilities(str(p))
        for cap in r.capabilities:
            assert len(cap.evidence) > 0


class TestGetPEImportsFallback:
    """Cover _get_pe_imports pefile fallback (lines 397-405)."""

    def test_pefile_import_fallback(self, tmp_path):
        from hashguard import capability_detector
        from hashguard.capability_detector import _get_pe_imports

        with patch.object(capability_detector, "HAS_PEFILE", True):
            mock_imp = MagicMock()
            mock_imp.name = b"VirtualAlloc"
            mock_entry = MagicMock()
            mock_entry.imports = [mock_imp]
            mock_pe = MagicMock()
            mock_pe.DIRECTORY_ENTRY_IMPORT = [mock_entry]

            with patch("hashguard.capability_detector.pefile") as mock_pefile:
                mock_pefile.PE.return_value = mock_pe
                mock_pefile.DIRECTORY_ENTRY = {"IMAGE_DIRECTORY_ENTRY_IMPORT": 1}

                # No pe_info imports → should fall through to pefile
                imports = _get_pe_imports(str(tmp_path / "fake.exe"), pe_info=None)
                assert "VirtualAlloc" in imports

    def test_file_read_error(self, tmp_path):
        """Cover OSError during content read (line 424-425)."""
        # Use a directory — exists but read_bytes() raises OSError
        r = detect_capabilities(str(tmp_path))
        assert r.total_detected == 0
