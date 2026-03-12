"""Tests for HashGuard STIX 2.1 Exporter."""

import json
from unittest.mock import patch, MagicMock

import pytest

from hashguard.stix_exporter import (
    HAS_STIX2,
    export_stix_bundle,
    _classify_malware_type,
    _is_valid_ipv4,
    _sanitize_domain,
    _safe_str,
)

pytestmark = pytest.mark.skipif(not HAS_STIX2, reason="stix2 not installed")


# ── Helper fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
def minimal_result():
    """Minimal analysis result with hashes only."""
    return {
        "hashes": {
            "sha256": "a" * 64,
            "sha1": "b" * 40,
            "md5": "c" * 32,
        },
        "malicious": False,
    }


@pytest.fixture
def full_malicious_result():
    """Full malicious result with all fields populated."""
    return {
        "filename": "evil.exe",
        "path": "C:\\Downloads\\evil.exe",
        "file_size": 102400,
        "malicious": True,
        "hashes": {
            "sha256": "a" * 64,
            "sha1": "b" * 40,
            "md5": "c" * 32,
        },
        "fuzzy_hashes": {
            "hashes": {
                "ssdeep": "96:abc123:def456",
                "tlsh": "T185d02210d3b5e01be770b87b0a1aaac301307047d000a200a025a57a0000022b000200",
            },
        },
        "strings": {
            "total_strings": 150,
            "has_iocs": True,
            "urls": ["http://evil.com/payload", "https://c2.bad-domain.org/gate"],
            "ips": ["192.168.1.100", "10.0.0.1"],
            "domains": ["evil.com", "c2.bad-domain.org"],
            "emails": ["attacker@evil.com"],
        },
        "yara_matches": {
            "available": True,
            "rules_loaded": 158,
            "matches": [
                {
                    "rule": "Ransomware_Generic",
                    "namespace": "ransomware",
                    "tags": ["ransomware"],
                    "meta": {
                        "description": "Detects generic ransomware patterns",
                        "author": "HashGuard",
                        "severity": "critical",
                    },
                    "strings": ["$s1", "$s2"],
                },
                {
                    "rule": "AntiDebug_Detect",
                    "namespace": "evasion",
                    "tags": ["evasion"],
                    "meta": {"description": "Anti-debug technique detected"},
                    "strings": ["$api1"],
                },
            ],
        },
        "threat_intel": {
            "hits": [
                {
                    "source": "MalwareBazaar",
                    "found": True,
                    "malware_family": "LockBit",
                    "tags": ["ransomware", "lockbit"],
                    "details": {},
                },
                {
                    "source": "VirusTotal",
                    "found": False,
                    "malware_family": "",
                    "tags": [],
                    "details": {},
                },
            ],
            "total_sources": 7,
            "flagged_count": 1,
            "successful_sources": 2,
        },
        "ml_classification": {
            "predicted_class": "ransomware",
            "confidence": 92.5,
            "probabilities": {"ransomware": 92.5, "benign": 2.0},
            "anomaly_score": -1.0,
            "is_anomaly": True,
            "features_used": 22,
        },
        "trained_model_prediction": {
            "predicted_class": "malicious",
            "confidence": 97.3,
            "model_id": "20260310_binary_rf",
            "probabilities": {"malicious": 97.3, "benign": 2.7},
        },
        "family_detection": {
            "family": "LockBit",
            "confidence": 95.0,
            "source": "yara",
            "description": "LockBit ransomware detected via YARA rules",
        },
        "capabilities": {
            "capabilities": [
                {
                    "name": "File encryption",
                    "category": "ransomware",
                    "confidence": 0.9,
                    "evidence": ["CryptEncrypt", "CreateFileA"],
                    "mitre_attack": "T1486",
                    "severity": "critical",
                },
                {
                    "name": "Process injection",
                    "category": "evasion",
                    "confidence": 0.8,
                    "evidence": ["VirtualAllocEx", "WriteProcessMemory"],
                    "mitre_attack": "T1055",
                    "severity": "high",
                },
            ],
            "total_detected": 2,
            "risk_categories": {"ransomware": 1, "evasion": 1},
            "max_severity": "critical",
        },
        "risk_score": {
            "score": 95,
            "verdict": "malicious",
            "factors": [
                {"name": "YARA", "points": 30, "detail": "Ransomware detected"},
                {"name": "Threat Intel", "points": 25, "detail": "Known malware"},
            ],
        },
    }


# ── Unit tests ───────────────────────────────────────────────────────────────


class TestHelpers:
    def test_classify_trojan(self):
        assert _classify_malware_type("trojan") == ["trojan"]

    def test_classify_ransomware(self):
        assert _classify_malware_type("LockBit") == ["unknown"]
        assert _classify_malware_type("ransomware_lockbit") == ["ransomware"]

    def test_classify_miner(self):
        assert _classify_malware_type("miner") == ["resource-exploitation"]

    def test_classify_unknown(self):
        assert _classify_malware_type("something_new") == ["unknown"]

    def test_is_valid_ipv4(self):
        assert _is_valid_ipv4("192.168.1.1")
        assert _is_valid_ipv4("0.0.0.0")
        assert _is_valid_ipv4("255.255.255.255")
        assert not _is_valid_ipv4("999.999.999.999")
        assert not _is_valid_ipv4("abc")
        assert not _is_valid_ipv4("")
        assert not _is_valid_ipv4("192.168.1")
        assert not _is_valid_ipv4("192.168.1.1.1")

    def test_sanitize_domain(self):
        assert _sanitize_domain("https://evil.com/path") == "evil.com"
        assert _sanitize_domain("http://test.org:8080/x") == "test.org"
        assert _sanitize_domain("example.COM") == "example.com"

    def test_safe_str(self):
        assert _safe_str(None) == ""
        assert _safe_str("  hello  ") == "hello"
        assert _safe_str(42) == "42"


# ── Bundle structure tests ───────────────────────────────────────────────────


class TestBundleStructure:
    def test_returns_valid_bundle(self, minimal_result):
        bundle = export_stix_bundle(minimal_result)
        assert bundle["type"] == "bundle"
        assert "id" in bundle
        assert bundle["id"].startswith("bundle--")
        assert "objects" in bundle
        assert len(bundle["objects"]) >= 1

    def test_identity_always_present(self, minimal_result):
        bundle = export_stix_bundle(minimal_result)
        identities = [o for o in bundle["objects"] if o["type"] == "identity"]
        assert len(identities) == 1
        assert identities[0]["name"] == "HashGuard"

    def test_file_observable_created(self, minimal_result):
        bundle = export_stix_bundle(minimal_result)
        files = [o for o in bundle["objects"] if o["type"] == "file"]
        assert len(files) == 1
        assert files[0]["hashes"]["SHA-256"] == "a" * 64
        assert files[0]["hashes"]["SHA-1"] == "b" * 40
        assert files[0]["hashes"]["MD5"] == "c" * 32

    def test_serializable_to_json(self, full_malicious_result):
        bundle = export_stix_bundle(full_malicious_result)
        # Must be JSON-serializable without errors
        serialized = json.dumps(bundle)
        assert len(serialized) > 100
        parsed = json.loads(serialized)
        assert parsed["type"] == "bundle"


class TestMalwareSDO:
    def test_malware_from_family(self, full_malicious_result):
        bundle = export_stix_bundle(full_malicious_result)
        malwares = [o for o in bundle["objects"] if o["type"] == "malware"]
        assert len(malwares) >= 1
        lockbit = [m for m in malwares if m["name"] == "LockBit"]
        assert len(lockbit) == 1
        assert lockbit[0]["is_family"] is True

    def test_malware_from_ml_when_no_family(self):
        result = {
            "hashes": {"sha256": "d" * 64},
            "malicious": True,
            "ml_classification": {
                "predicted_class": "trojan",
                "confidence": 80.0,
            },
        }
        bundle = export_stix_bundle(result)
        malwares = [o for o in bundle["objects"] if o["type"] == "malware"]
        assert len(malwares) >= 1
        assert malwares[0]["name"] == "trojan"
        assert malwares[0]["is_family"] is False

    def test_no_malware_when_clean(self, minimal_result):
        bundle = export_stix_bundle(minimal_result)
        malwares = [o for o in bundle["objects"] if o["type"] == "malware"]
        assert len(malwares) == 0

    def test_derived_from_relationship(self, full_malicious_result):
        bundle = export_stix_bundle(full_malicious_result)
        rels = [
            o
            for o in bundle["objects"]
            if o["type"] == "relationship" and o["relationship_type"] == "derived-from"
        ]
        assert len(rels) >= 1


class TestIOCObservables:
    def test_urls_extracted(self, full_malicious_result):
        bundle = export_stix_bundle(full_malicious_result)
        urls = [o for o in bundle["objects"] if o["type"] == "url"]
        assert len(urls) == 2
        values = {u["value"] for u in urls}
        assert "http://evil.com/payload" in values

    def test_ips_extracted(self, full_malicious_result):
        bundle = export_stix_bundle(full_malicious_result)
        ips = [o for o in bundle["objects"] if o["type"] == "ipv4-addr"]
        assert len(ips) == 2
        values = {i["value"] for i in ips}
        assert "192.168.1.100" in values

    def test_domains_extracted(self, full_malicious_result):
        bundle = export_stix_bundle(full_malicious_result)
        domains = [o for o in bundle["objects"] if o["type"] == "domain-name"]
        assert len(domains) == 2

    def test_emails_extracted(self, full_malicious_result):
        bundle = export_stix_bundle(full_malicious_result)
        emails = [o for o in bundle["objects"] if o["type"] == "email-addr"]
        assert len(emails) == 1
        assert emails[0]["value"] == "attacker@evil.com"

    def test_communicates_with_relationships(self, full_malicious_result):
        bundle = export_stix_bundle(full_malicious_result)
        comms = [
            o
            for o in bundle["objects"]
            if o["type"] == "relationship"
            and o["relationship_type"] == "communicates-with"
        ]
        # 2 urls + 2 ips + 2 domains = 6
        assert len(comms) == 6

    def test_no_iocs_on_clean_result(self, minimal_result):
        bundle = export_stix_bundle(minimal_result)
        urls = [o for o in bundle["objects"] if o["type"] == "url"]
        ips = [o for o in bundle["objects"] if o["type"] == "ipv4-addr"]
        assert len(urls) == 0
        assert len(ips) == 0


class TestYARAIndicators:
    def test_yara_indicators_created(self, full_malicious_result):
        bundle = export_stix_bundle(full_malicious_result)
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        assert len(indicators) == 2
        names = {i["name"] for i in indicators}
        assert "YARA: Ransomware_Generic" in names
        assert "YARA: AntiDebug_Detect" in names

    def test_yara_indicates_relationship(self, full_malicious_result):
        bundle = export_stix_bundle(full_malicious_result)
        indicates = [
            o
            for o in bundle["objects"]
            if o["type"] == "relationship" and o["relationship_type"] == "indicates"
        ]
        assert len(indicates) == 2

    def test_no_indicators_without_yara(self, minimal_result):
        bundle = export_stix_bundle(minimal_result)
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        assert len(indicators) == 0


class TestAttackPatterns:
    def test_attack_patterns_created(self, full_malicious_result):
        bundle = export_stix_bundle(full_malicious_result)
        patterns = [o for o in bundle["objects"] if o["type"] == "attack-pattern"]
        assert len(patterns) == 2
        names = {p["name"] for p in patterns}
        assert "File encryption" in names
        assert "Process injection" in names

    def test_mitre_external_references(self, full_malicious_result):
        bundle = export_stix_bundle(full_malicious_result)
        patterns = [o for o in bundle["objects"] if o["type"] == "attack-pattern"]
        for p in patterns:
            refs = p.get("external_references", [])
            assert len(refs) >= 1
            assert refs[0]["source_name"] == "mitre-attack"
            assert refs[0]["external_id"] in ("T1486", "T1055")

    def test_uses_relationship(self, full_malicious_result):
        bundle = export_stix_bundle(full_malicious_result)
        uses = [
            o
            for o in bundle["objects"]
            if o["type"] == "relationship" and o["relationship_type"] == "uses"
        ]
        assert len(uses) == 2

    def test_dedup_attack_patterns(self):
        """Duplicate ATT&CK IDs should only create one pattern."""
        result = {
            "hashes": {"sha256": "e" * 64},
            "malicious": True,
            "family_detection": {"family": "Test", "confidence": 90, "source": "yara"},
            "capabilities": {
                "capabilities": [
                    {"name": "Cap A", "mitre_attack": "T1055", "category": "evasion", "severity": "high"},
                    {"name": "Cap B", "mitre_attack": "T1055", "category": "evasion", "severity": "medium"},
                ],
            },
        }
        bundle = export_stix_bundle(result)
        patterns = [o for o in bundle["objects"] if o["type"] == "attack-pattern"]
        assert len(patterns) == 1


class TestAnalysisNote:
    def test_note_with_risk_and_ml(self, full_malicious_result):
        bundle = export_stix_bundle(full_malicious_result)
        notes = [o for o in bundle["objects"] if o["type"] == "note"]
        assert len(notes) == 1
        content = notes[0]["content"]
        assert "Risk Score: 95/100" in content
        assert "malicious" in content
        assert "ML Classification: ransomware" in content
        assert "Trained Model: malicious" in content

    def test_no_note_without_risk(self, minimal_result):
        bundle = export_stix_bundle(minimal_result)
        notes = [o for o in bundle["objects"] if o["type"] == "note"]
        assert len(notes) == 0


class TestFuzzyHashes:
    def test_ssdeep_in_file_hashes(self, full_malicious_result):
        bundle = export_stix_bundle(full_malicious_result)
        files = [o for o in bundle["objects"] if o["type"] == "file"]
        assert len(files) == 1
        assert "SSDEEP" in files[0]["hashes"]
        assert "TLSH" in files[0]["hashes"]


class TestEdgeCases:
    def test_empty_result(self):
        bundle = export_stix_bundle({})
        assert bundle["type"] == "bundle"
        # At least identity
        assert len(bundle["objects"]) >= 1

    def test_none_values_handled(self):
        result = {
            "hashes": {"sha256": None, "sha1": None, "md5": None},
            "strings": None,
            "yara_matches": None,
            "capabilities": None,
        }
        bundle = export_stix_bundle(result)
        assert bundle["type"] == "bundle"

    def test_malformed_strings_info(self):
        result = {
            "hashes": {"sha256": "f" * 64},
            "strings": {
                "urls": [None, "", "http://valid.com"],
                "ips": ["not-an-ip", "192.168.1.1"],
                "domains": [None, "valid.com", "nodot"],
                "emails": ["no-at-sign", "valid@test.com"],
            },
        }
        bundle = export_stix_bundle(result)
        urls = [o for o in bundle["objects"] if o["type"] == "url"]
        ips = [o for o in bundle["objects"] if o["type"] == "ipv4-addr"]
        domains = [o for o in bundle["objects"] if o["type"] == "domain-name"]
        emails = [o for o in bundle["objects"] if o["type"] == "email-addr"]
        assert len(urls) == 1  # only http://valid.com
        assert len(ips) == 1  # only 192.168.1.1
        assert len(domains) == 1  # only valid.com
        assert len(emails) == 1  # only valid@test.com

    def test_threat_intel_creates_malware_when_no_family(self):
        result = {
            "hashes": {"sha256": "a" * 64},
            "malicious": False,
            "threat_intel": {
                "hits": [
                    {
                        "source": "MalwareBazaar",
                        "found": True,
                        "malware_family": "Emotet",
                        "tags": [],
                        "details": {},
                    }
                ],
            },
        }
        bundle = export_stix_bundle(result)
        malwares = [o for o in bundle["objects"] if o["type"] == "malware"]
        assert len(malwares) == 1
        assert malwares[0]["name"] == "Emotet"


class TestFullBundleObjectCount:
    def test_full_result_object_count(self, full_malicious_result):
        bundle = export_stix_bundle(full_malicious_result)
        obj_types = {}
        for o in bundle["objects"]:
            t = o["type"]
            obj_types[t] = obj_types.get(t, 0) + 1

        assert obj_types["identity"] == 1
        assert obj_types["file"] == 1
        assert obj_types["malware"] >= 1
        assert obj_types["indicator"] == 2  # 2 YARA rules
        assert obj_types["attack-pattern"] == 2  # T1486, T1055
        assert obj_types["url"] == 2
        assert obj_types["ipv4-addr"] == 2
        assert obj_types["domain-name"] == 2
        assert obj_types["email-addr"] == 1
        assert obj_types["note"] == 1
        assert obj_types["relationship"] >= 10


# ── API endpoint test ────────────────────────────────────────────────────────


class TestSTIXEndpoint:
    @pytest.fixture
    def client(self):
        from hashguard.web.api import HAS_FASTAPI, app

        if not HAS_FASTAPI or not app:
            pytest.skip("FastAPI not available")
        from starlette.testclient import TestClient

        return TestClient(app)

    def test_export_stix_endpoint(self, client):
        sample = {
            "id": 1,
            "full_result": json.dumps(
                {
                    "hashes": {"sha256": "a" * 64},
                    "malicious": True,
                    "family_detection": {
                        "family": "TestMalware",
                        "confidence": 90,
                        "source": "yara",
                    },
                }
            ),
        }
        with patch("hashguard.database.get_sample_by_id", return_value=sample):
            resp = client.get("/api/export/stix/1")
            assert resp.status_code == 200
            data = resp.json()
            assert data["type"] == "bundle"
            malwares = [o for o in data["objects"] if o["type"] == "malware"]
            assert len(malwares) >= 1

    def test_export_stix_404(self, client):
        with patch("hashguard.database.get_sample_by_id", return_value=None):
            resp = client.get("/api/export/stix/999")
            assert resp.status_code == 404

    def test_export_stix_clean_sample(self, client):
        sample = {
            "id": 2,
            "full_result": json.dumps(
                {
                    "hashes": {"sha256": "b" * 64},
                    "malicious": False,
                }
            ),
        }
        with patch("hashguard.database.get_sample_by_id", return_value=sample):
            resp = client.get("/api/export/stix/2")
            assert resp.status_code == 200
            data = resp.json()
            assert data["type"] == "bundle"
            malwares = [o for o in data["objects"] if o["type"] == "malware"]
            assert len(malwares) == 0


class TestIPValidationEdge:
    """Cover _is_valid_ipv4 octet range check (lines 84-85)."""

    def test_ip_octet_out_of_range(self):
        from hashguard.stix_exporter import _is_valid_ipv4
        assert _is_valid_ipv4("256.1.1.1") is False
        assert _is_valid_ipv4("1.1.1.-1") is False
        assert _is_valid_ipv4("0.0.0.0") is True
        assert _is_valid_ipv4("255.255.255.255") is True


class TestExportStixNoStix2:
    """Cover RuntimeError when stix2 not installed (line 116)."""

    def test_no_stix2(self):
        from hashguard import stix_exporter
        with patch.object(stix_exporter, "HAS_STIX2", False):
            with pytest.raises(RuntimeError, match="stix2 library is required"):
                stix_exporter.export_stix_bundle({"hashes": {"sha256": "a" * 64}})
