"""Tests for HashGuard database module."""

import json
import os
import sqlite3
import threading

import pytest

from hashguard import database


@pytest.fixture(autouse=True)
def _use_tmp_db(tmp_path, monkeypatch):
    """Redirect the database to a temp directory for every test."""
    monkeypatch.setattr(database, "_DB_DIR", str(tmp_path))
    monkeypatch.setattr(database, "_DB_PATH", str(tmp_path / "hashguard.db"))
    # Reset any existing thread-local connection
    database._local = threading.local()


# ── helpers ──────────────────────────────────────────────────────────────────

_SAMPLE_RESULT = {
    "path": "/tmp/evil.exe",
    "file_size": 12345,
    "hashes": {
        "sha256": "a" * 64,
        "sha1": "b" * 40,
        "md5": "c" * 32,
    },
    "risk_score": {"score": 75, "verdict": "high"},
    "malicious": True,
    "description": "Detected as trojan",
    "strings_info": {
        "has_iocs": True,
        "iocs": {
            "urls": ["http://evil.com/payload"],
            "ips": ["1.2.3.4"],
        },
    },
    "fuzzy_hashes": {"hashes": {"ssdeep": "3:xyz", "tlsh": "T1abc"}},
}


# ── init / connection ────────────────────────────────────────────────────────


class TestConnection:
    def test_get_connection_creates_db(self, tmp_path):
        conn = database.get_connection()
        assert isinstance(conn, sqlite3.Connection)
        assert os.path.exists(str(tmp_path / "hashguard.db"))

    def test_init_db_creates_tables(self):
        database.init_db()
        conn = database.get_connection()
        tables = {
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        assert "samples" in tables
        assert "iocs" in tables
        assert "behaviors" in tables
        assert "families" in tables
        assert "clusters" in tables
        assert "timeline_events" in tables


# ── store / retrieve ─────────────────────────────────────────────────────────


class TestStoreSample:
    def test_store_returns_id(self):
        sid = database.store_sample(_SAMPLE_RESULT)
        assert isinstance(sid, int)
        assert sid >= 1

    def test_store_and_get_by_sha256(self):
        database.store_sample(_SAMPLE_RESULT)
        row = database.get_sample("a" * 64)
        assert row is not None
        assert row["sha256"] == "a" * 64
        assert row["risk_score"] == 75

    def test_store_duplicate_updates(self):
        sid1 = database.store_sample(_SAMPLE_RESULT)
        updated = dict(_SAMPLE_RESULT, risk_score={"score": 90, "verdict": "critical"})
        sid2 = database.store_sample(updated)
        assert sid1 == sid2
        row = database.get_sample("a" * 64)
        assert row["risk_score"] == 90

    def test_store_iocs(self):
        sid = database.store_sample(_SAMPLE_RESULT)
        iocs = database.get_sample_iocs(sid)
        assert len(iocs) >= 2
        types = {i["ioc_type"] for i in iocs}
        assert "urls" in types
        assert "ips" in types

    def test_store_capabilities(self):
        result = dict(
            _SAMPLE_RESULT,
            hashes={"sha256": "d" * 64, "sha1": "", "md5": ""},
            capabilities={
                "capabilities": [
                    {
                        "category": "network",
                        "name": "HTTP download",
                        "severity": "high",
                        "mitre_attack": "T1071",
                    }
                ]
            },
        )
        sid = database.store_sample(result)
        behaviors = database.get_sample_behaviors(sid)
        assert len(behaviors) == 1
        assert behaviors[0]["category"] == "network"


class TestGetSample:
    def test_get_nonexistent(self):
        assert database.get_sample("0" * 64) is None

    def test_get_by_id(self):
        sid = database.store_sample(_SAMPLE_RESULT)
        row = database.get_sample_by_id(sid)
        assert row is not None
        assert row["id"] == sid

    def test_get_by_id_nonexistent(self):
        database.init_db()
        assert database.get_sample_by_id(99999) is None


class TestGetAllSamples:
    def test_empty(self):
        database.init_db()
        assert database.get_all_samples() == []

    def test_returns_list(self):
        database.store_sample(_SAMPLE_RESULT)
        result = dict(
            _SAMPLE_RESULT,
            hashes={"sha256": "e" * 64, "sha1": "", "md5": ""},
        )
        database.store_sample(result)
        samples = database.get_all_samples()
        assert len(samples) == 2

    def test_limit_offset(self):
        for i in range(5):
            h = f"{i:064d}"
            r = dict(_SAMPLE_RESULT, hashes={"sha256": h, "sha1": "", "md5": ""})
            database.store_sample(r)
        assert len(database.get_all_samples(limit=2)) == 2
        assert len(database.get_all_samples(limit=10, offset=3)) == 2


# ── stats ────────────────────────────────────────────────────────────────────


class TestStats:
    def test_empty_stats(self):
        database.init_db()
        stats = database.get_stats()
        assert stats["total_samples"] == 0
        assert stats["malicious"] == 0
        assert stats["detection_rate"] == 0

    def test_stats_after_insert(self):
        database.store_sample(_SAMPLE_RESULT)
        clean = dict(
            _SAMPLE_RESULT,
            hashes={"sha256": "f" * 64, "sha1": "", "md5": ""},
            malicious=False,
            risk_score={"score": 10, "verdict": "clean"},
        )
        database.store_sample(clean)
        stats = database.get_stats()
        assert stats["total_samples"] == 2
        assert stats["malicious"] == 1
        assert stats["clean"] == 1
        assert stats["detection_rate"] == 50.0


# ── search ───────────────────────────────────────────────────────────────────


class TestSearch:
    def test_search_not_in_schema(self):
        """search_samples may or may not exist — handle gracefully."""
        database.init_db()
        if hasattr(database, "search_samples"):
            results = database.search_samples("evil")
            assert isinstance(results, list)


# ── cluster / timeline helpers ───────────────────────────────────────────────


class TestClusterAndTimeline:
    def test_store_cluster(self):
        if not hasattr(database, "store_cluster"):
            pytest.skip("store_cluster not available")
        database.init_db()
        sid = database.store_sample(_SAMPLE_RESULT)
        cid = database.store_cluster(
            name="Emotet cluster",
            algorithm="dbscan",
            members=[{"sample_id": sid, "similarity": 0.95}],
        )
        assert isinstance(cid, int)

    def test_get_clusters_empty(self):
        if not hasattr(database, "get_clusters"):
            pytest.skip("get_clusters not available")
        database.init_db()
        assert database.get_clusters() == []

    def test_store_timeline_event(self):
        if not hasattr(database, "store_timeline_event"):
            pytest.skip("store_timeline_event not available")
        database.init_db()
        sid = database.store_sample(_SAMPLE_RESULT)
        database.store_timeline_event(
            sample_id=sid,
            event_type="analysis",
            description="Initial scan",
        )
        events = database.get_timeline(sid)
        assert len(events) >= 1


# ── dataset feature store ────────────────────────────────────────────────────


class TestDatasetFeatureStore:
    """Tests for the dataset_features table and related functions."""

    def _reset_dataset_flag(self):
        """Reset the schema-applied flag so the table is recreated."""
        database._DATASET_SCHEMA_APPLIED = False

    def test_ensure_dataset_table_creates_table(self):
        self._reset_dataset_flag()
        database.init_db()
        database._ensure_dataset_table()
        conn = database.get_connection()
        tables = {
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        assert "dataset_features" in tables

    def test_store_dataset_features_basic(self):
        self._reset_dataset_flag()
        sid = database.store_sample(_SAMPLE_RESULT)
        feats = {
            "file_size": 12345,
            "file_size_log": 13.59,
            "byte_entropy": 4.5,
            "risk_score": 75,
            "label_verdict": "high",
            "label_is_malicious": 1,
            "label_family": "",
            "label_family_confidence": 0.0,
        }
        database.store_dataset_features(sid, "a" * 64, feats)
        conn = database.get_connection()
        row = conn.execute(
            "SELECT * FROM dataset_features WHERE sample_id = ?", (sid,)
        ).fetchone()
        assert row is not None
        assert dict(row)["sha256"] == "a" * 64
        assert dict(row)["file_size"] == 12345
        assert dict(row)["label_verdict"] == "high"

    def test_store_dataset_features_replace(self):
        """Inserting again for the same sample should replace (not duplicate)."""
        self._reset_dataset_flag()
        sid = database.store_sample(_SAMPLE_RESULT)
        feats1 = {"risk_score": 50, "label_verdict": "suspicious"}
        database.store_dataset_features(sid, "a" * 64, feats1)
        feats2 = {"risk_score": 90, "label_verdict": "malicious"}
        database.store_dataset_features(sid, "a" * 64, feats2)
        conn = database.get_connection()
        count = conn.execute("SELECT COUNT(*) FROM dataset_features WHERE sample_id = ?", (sid,)).fetchone()[0]
        assert count == 1
        row = conn.execute("SELECT risk_score, label_verdict FROM dataset_features WHERE sample_id = ?", (sid,)).fetchone()
        assert dict(row)["risk_score"] == 90
        assert dict(row)["label_verdict"] == "malicious"

    def test_get_dataset_stats_empty(self):
        self._reset_dataset_flag()
        database.init_db()
        stats = database.get_dataset_stats()
        assert stats["total"] == 0
        assert stats["malicious"] == 0
        assert stats["clean"] == 0
        assert isinstance(stats["verdict_distribution"], list)
        assert isinstance(stats["top_families"], list)
        assert stats["feature_count"] > 0

    def test_get_dataset_stats_with_data(self):
        self._reset_dataset_flag()
        sid1 = database.store_sample(_SAMPLE_RESULT)
        database.store_dataset_features(sid1, "a" * 64, {"label_is_malicious": 1, "label_verdict": "malicious", "label_family": "Emotet"})

        clean_result = dict(
            _SAMPLE_RESULT,
            hashes={"sha256": "b" * 64, "sha1": "", "md5": ""},
            malicious=False,
        )
        sid2 = database.store_sample(clean_result)
        database.store_dataset_features(sid2, "b" * 64, {"label_is_malicious": 0, "label_verdict": "clean", "label_family": ""})

        stats = database.get_dataset_stats()
        assert stats["total"] == 2
        assert stats["malicious"] == 1
        assert stats["clean"] == 1
        verdicts = {v["verdict"]: v["count"] for v in stats["verdict_distribution"]}
        assert verdicts.get("malicious") == 1
        assert verdicts.get("clean") == 1
        assert any(f["family"] == "Emotet" for f in stats["top_families"])

    def test_export_dataset_csv(self):
        self._reset_dataset_flag()
        sid = database.store_sample(_SAMPLE_RESULT)
        database.store_dataset_features(sid, "a" * 64, {"risk_score": 75, "label_verdict": "malicious"})
        csv_data = database.export_dataset("csv")
        assert "sha256" in csv_data
        assert "risk_score" in csv_data
        assert "a" * 64 in csv_data
        lines = csv_data.strip().split("\n")
        assert len(lines) == 2  # header + 1 row

    def test_export_dataset_jsonl(self):
        self._reset_dataset_flag()
        sid = database.store_sample(_SAMPLE_RESULT)
        database.store_dataset_features(sid, "a" * 64, {"risk_score": 75, "label_verdict": "malicious"})
        jsonl_data = database.export_dataset("jsonl")
        import json
        row = json.loads(jsonl_data.strip())
        assert row["sha256"] == "a" * 64
        assert row["risk_score"] == 75

    def test_export_dataset_empty(self):
        self._reset_dataset_flag()
        database.init_db()
        csv_data = database.export_dataset("csv")
        lines = csv_data.strip().split("\n")
        assert len(lines) == 1  # header only


class TestSearchIOCs:
    """Cover search_iocs function (lines 353-365)."""

    def test_search_iocs_empty(self):
        database.init_db()
        results = database.search_iocs("nonexistent_ioc_xyz")
        assert results == []

    def test_search_iocs_with_data(self):
        database.init_db()
        # store_sample stores IOCs from strings_info
        result_with_iocs = dict(
            _SAMPLE_RESULT,
            strings_info={
                "iocs": {
                    "urls": ["http://evil-c2.example.com/beacon"],
                    "ips": ["203.0.113.42"],
                }
            },
        )
        database.store_sample(result_with_iocs)
        results = database.search_iocs("evil-c2")
        assert len(results) >= 1
        assert any("evil-c2" in r["value"] for r in results)
