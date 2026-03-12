"""Tests for the risk scoring engine."""

import pytest

from hashguard.risk_scorer import compute_risk, RiskScore


class TestComputeRisk:
    """Tests for compute_risk function."""

    def test_clean_file_no_signals(self):
        """No signals → score 0, verdict clean."""
        result = compute_risk()
        assert result.score == 0
        assert result.verdict == "clean"
        assert result.factors == []

    def test_known_hash_match(self):
        """Signature match alone → score 100, malicious."""
        result = compute_risk(signature_match=True, signature_name="Eicar")
        assert result.score == 100
        assert result.verdict == "malicious"
        assert any("Known malware" in f.name for f in result.factors)

    def test_packed_pe_adds_points(self):
        pe = {
            "is_pe": True,
            "packed": True,
            "packer_hint": "UPX",
            "overall_entropy": 7.5,
            "suspicious_imports": [],
        }
        result = compute_risk(pe_info=pe)
        assert result.score > 0
        names = [f.name for f in result.factors]
        assert "Packed executable" in names
        assert any("entropy" in n.lower() for n in names)

    def test_suspicious_imports(self):
        pe = {
            "is_pe": True,
            "overall_entropy": 5.0,
            "suspicious_imports": [
                "VirtualAlloc",
                "CreateRemoteThread",
                "WriteProcessMemory",
                "NtUnmapViewOfSection",
                "SetWindowsHookEx",
            ],
        }
        result = compute_risk(pe_info=pe)
        assert any("import" in f.name.lower() for f in result.factors)

    def test_yara_critical_high_score(self):
        yara = {
            "matches": [
                {
                    "rule": "Ransomware_Shadow",
                    "meta": {"severity": "critical", "description": "shadow copy"},
                },
            ]
        }
        result = compute_risk(yara_matches=yara)
        assert result.score >= 40

    def test_yara_low_severity(self):
        yara = {
            "matches": [
                {"rule": "Packer_UPX", "meta": {"severity": "low", "description": "UPX"}},
            ]
        }
        result = compute_risk(yara_matches=yara)
        assert result.score == 10

    def test_threat_intel_hit(self):
        ti = {"hits": [{"source": "MalwareBazaar", "found": True, "malware_family": "AgentTesla"}]}
        result = compute_risk(threat_intel=ti)
        assert result.score >= 40
        assert result.verdict in ("suspicious", "malicious")

    def test_virustotal_many_detections(self):
        vt = {"data": {"attributes": {"last_analysis_stats": {"malicious": 25, "undetected": 50}}}}
        result = compute_risk(vt_result=vt)
        assert result.score >= 50
        assert result.verdict in ("suspicious", "malicious")

    def test_virustotal_few_detections(self):
        vt = {"data": {"attributes": {"last_analysis_stats": {"malicious": 1, "undetected": 70}}}}
        result = compute_risk(vt_result=vt)
        assert 0 < result.score < 50

    def test_strings_powershell(self):
        si = {"powershell_commands": ["powershell -enc AAAA"]}
        result = compute_risk(strings_info=si)
        assert any("PowerShell" in f.name for f in result.factors)

    def test_strings_crypto_wallets(self):
        si = {"crypto_wallets": ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"]}
        result = compute_risk(strings_info=si)
        assert any("Crypto" in f.name for f in result.factors)

    def test_strings_many_urls(self):
        si = {"urls": [f"http://evil{i}.com" for i in range(10)]}
        result = compute_risk(strings_info=si)
        assert any("URL" in f.name for f in result.factors)

    def test_score_clamped_to_100(self):
        """Multiple high-score signals should not exceed 100."""
        result = compute_risk(
            signature_match=True,
            yara_matches={
                "matches": [
                    {"rule": "r1", "meta": {"severity": "critical"}},
                    {"rule": "r2", "meta": {"severity": "high"}},
                ]
            },
            threat_intel={"hits": [{"source": "X", "found": True}]},
        )
        assert result.score == 100

    def test_verdict_thresholds(self):
        # 10 points → clean
        r1 = compute_risk(
            pe_info={"is_pe": True, "overall_entropy": 5.0, "suspicious_imports": ["VirtualAlloc"]}
        )
        assert r1.verdict == "clean"

        # ~30 points → suspicious
        r2 = compute_risk(
            yara_matches={
                "matches": [
                    {"rule": "x", "meta": {"severity": "high"}},
                ]
            }
        )
        assert r2.verdict == "suspicious"

    def test_to_dict(self):
        result = compute_risk(signature_match=True)
        d = result.to_dict()
        assert d["score"] == 100
        assert d["verdict"] == "malicious"
        assert isinstance(d["factors"], list)
        assert d["factors"][0]["name"] == "Known malware hash"

    def test_wx_section_warning(self):
        pe = {
            "is_pe": True,
            "overall_entropy": 5.0,
            "warnings": [".text is writable and executable"],
            "suspicious_imports": [],
        }
        result = compute_risk(pe_info=pe)
        assert any("W+X" in f.name for f in result.factors)

    def test_high_entropy_68_72(self):
        pe = {
            "is_pe": True,
            "overall_entropy": 7.0,
            "suspicious_imports": [],
        }
        result = compute_risk(pe_info=pe)
        assert any("High entropy" in f.name for f in result.factors)

    def test_many_suspicious_imports_8plus(self):
        pe = {
            "is_pe": True,
            "overall_entropy": 5.0,
            "suspicious_imports": [
                "VirtualAlloc", "CreateRemoteThread", "WriteProcessMemory",
                "NtUnmapViewOfSection", "SetWindowsHookEx", "VirtualProtect",
                "CreateThread", "RtlMoveMemory",
            ],
        }
        result = compute_risk(pe_info=pe)
        assert any("Many suspicious imports" in f.name for f in result.factors)

    def test_many_urls_over_5(self):
        si = {"urls": [f"http://evil{i}.com" for i in range(8)]}
        result = compute_risk(strings_info=si)
        assert any("URL" in f.name for f in result.factors)

    def test_embedded_ips(self):
        si = {"ips": ["1.2.3.4", "5.6.7.8"]}
        result = compute_risk(strings_info=si)
        assert any("IP" in f.name for f in result.factors)

    def test_capability_severity_points(self):
        caps = {
            "capabilities": [
                {"name": "Ransomware", "severity": "critical", "confidence": 0.9},
                {"name": "Keylogger", "severity": "high", "confidence": 0.8},
            ]
        }
        result = compute_risk(capabilities=caps)
        assert result.score >= 50
        assert any("Ransomware" in f.name for f in result.factors)

    def test_ml_nonbenign_high_confidence(self):
        ml = {"predicted_class": "trojan", "confidence": 0.9}
        result = compute_risk(ml_result=ml)
        assert any("ML" in f.name for f in result.factors)
        factor = [f for f in result.factors if "ML" in f.name][0]
        assert factor.points == 35

    def test_ml_nonbenign_medium_confidence(self):
        ml = {"predicted_class": "ransomware", "confidence": 0.78}
        result = compute_risk(ml_result=ml)
        factor = [f for f in result.factors if "ML" in f.name][0]
        assert factor.points == 25

    def test_ml_nonbenign_low_confidence(self):
        ml = {"predicted_class": "worm", "confidence": 0.65}
        result = compute_risk(ml_result=ml)
        factor = [f for f in result.factors if "ML" in f.name][0]
        assert factor.points == 15

    def test_ml_benign_ignored(self):
        ml = {"predicted_class": "benign", "confidence": 0.99}
        result = compute_risk(ml_result=ml)
        assert not any("ML" in f.name for f in result.factors)

    def test_ml_low_confidence_ignored(self):
        ml = {"predicted_class": "trojan", "confidence": 0.5}
        result = compute_risk(ml_result=ml)
        assert not any("ML" in f.name for f in result.factors)

    def test_ml_anomaly_detected(self):
        ml = {"predicted_class": "benign", "confidence": 0.3, "is_anomaly": True}
        result = compute_risk(ml_result=ml)
        assert any("anomaly" in f.name.lower() for f in result.factors)

    def test_verdict_clean_boundary(self):
        # 5 points = clean
        result = compute_risk(
            pe_info={"is_pe": True, "overall_entropy": 5.0, "suspicious_imports": ["VirtualAlloc"]}
        )
        assert result.verdict == "clean"

    def test_verdict_suspicious_boundary(self):
        result = compute_risk(
            yara_matches={"matches": [{"rule": "x", "meta": {"severity": "medium"}}]}
        )
        assert result.score == 20
        assert result.verdict == "suspicious"

    def test_verdict_malicious_boundary(self):
        result = compute_risk(
            yara_matches={"matches": [{"rule": "x", "meta": {"severity": "critical"}}]}
        )
        assert result.score == 40
        assert result.verdict == "malicious"


class TestVTMediumDetections:
    """Cover VT 3-9 detection tier (line 151)."""

    def test_vt_medium_detections(self):
        vt = {"data": {"attributes": {"last_analysis_stats": {"malicious": 5, "undetected": 60}}}}
        result = compute_risk(vt_result=vt)
        assert any("VirusTotal" in f.name and f.points == 30 for f in result.factors)
