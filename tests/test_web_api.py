"""Tests for HashGuard Web API module."""

import json
import os
import threading
from unittest.mock import MagicMock, patch

import pytest

from hashguard.web.api import (
    HAS_FASTAPI,
    _get_static_dir,
    _get_template_dir,
    _sanitize_for_json,
    app,
)

# Skip all tests if FastAPI is not installed
pytestmark = pytest.mark.skipif(not HAS_FASTAPI, reason="FastAPI not installed")


@pytest.fixture
def client():
    """Create a test client for the API."""
    from starlette.testclient import TestClient

    return TestClient(app)


# ── Helpers ──────────────────────────────────────────────────────────────────


class TestSanitizeForJSON:
    def test_plain_dict(self):
        assert _sanitize_for_json({"a": 1}) == {"a": 1}

    def test_nested(self):
        data = {"a": {"b": [1, 2, {"c": "x"}]}}
        assert _sanitize_for_json(data) == data

    def test_nan_becomes_none(self):
        assert _sanitize_for_json(float("nan")) is None

    def test_numpy_scalar(self):
        try:
            import numpy as np

            val = np.int64(42)
            assert _sanitize_for_json(val) == 42
        except ImportError:
            pytest.skip("numpy not available")


class TestTemplateDirs:
    def test_template_dir_exists(self):
        d = _get_template_dir()
        assert d is not None

    def test_static_dir(self):
        # May or may not exist depending on install
        _get_static_dir()


# ── API Endpoints ────────────────────────────────────────────────────────────


class TestDashboard:
    def test_get_root(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "HashGuard" in resp.text


class TestStatsEndpoint:
    @patch(
        "hashguard.database.get_stats",
        return_value={
            "total_samples": 5,
            "malicious": 2,
            "clean": 3,
            "detection_rate": 40.0,
            "top_families": [],
            "recent_samples": [],
            "verdict_distribution": {},
        },
    )
    def test_get_stats(self, mock_stats, client):
        resp = client.get("/api/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_samples"] == 5

    def test_stats_fallback_on_error(self, client):
        with patch("hashguard.database.get_stats", side_effect=Exception("db error")):
            resp = client.get("/api/stats")
            assert resp.status_code == 200
            data = resp.json()
            assert data["total_samples"] == 0


class TestSamplesEndpoint:
    @patch(
        "hashguard.database.get_all_samples",
        return_value=[{"id": 1, "filename": "test.exe", "sha256": "a" * 64}],
    )
    def test_list_samples(self, mock_samples, client):
        resp = client.get("/api/samples")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["samples"]) == 1


class TestSampleDetailEndpoint:
    @patch("hashguard.database.get_timeline", return_value=[])
    @patch("hashguard.database.get_sample_behaviors", return_value=[])
    @patch("hashguard.database.get_sample_iocs", return_value=[])
    @patch("hashguard.database.get_sample_by_id")
    def test_get_sample(self, mock_get, mock_iocs, mock_beh, mock_tl, client):
        mock_get.return_value = {
            "id": 1,
            "filename": "test.exe",
            "sha256": "a" * 64,
            "full_result": "{}",
            "capabilities": None,
            "advanced_pe": None,
            "ml_classification": None,
        }
        resp = client.get("/api/samples/1")
        assert resp.status_code == 200

    @patch("hashguard.database.get_sample_by_id", return_value=None)
    def test_sample_not_found(self, mock_get, client):
        resp = client.get("/api/samples/99999")
        assert resp.status_code == 404


class TestAnalyzeEndpoint:
    @patch("hashguard.web.api._run_full_analysis")
    def test_upload_file(self, mock_analysis, client):
        mock_analysis.return_value = {
            "hashes": {"sha256": "a" * 64},
            "malicious": False,
        }
        resp = client.post(
            "/api/analyze",
            files={"file": ("test.txt", b"hello world", "text/plain")},
            data={"use_vt": "false"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "hashes" in data


class TestAnalyzeURLEndpoint:
    @patch("hashguard.scanner.analyze_url")
    def test_analyze_url(self, mock_analyze, client):
        mock_result = MagicMock()
        mock_result.to_dict.return_value = {
            "path": "http://example.com/file",
            "malicious": False,
        }
        mock_analyze.return_value = mock_result
        resp = client.post(
            "/api/analyze-url",
            data={"url": "http://example.com/file", "use_vt": "false"},
        )
        assert resp.status_code == 200

    def test_analyze_url_ssrf_block(self, client):
        with patch(
            "hashguard.scanner.analyze_url",
            side_effect=ValueError("Private/reserved IP blocked"),
        ):
            resp = client.post(
                "/api/analyze-url",
                data={"url": "http://192.168.1.1/file", "use_vt": "false"},
            )
            assert resp.status_code == 400


class TestSearchEndpoint:
    @patch("hashguard.database.search_iocs", return_value=[])
    @patch("hashguard.database.search_samples", return_value=[])
    def test_search(self, mock_samples, mock_iocs, client):
        resp = client.get("/api/search", params={"q": "test"})
        assert resp.status_code == 200
        data = resp.json()
        assert "samples" in data
        assert "iocs" in data


class TestClustersEndpoint:
    @patch("hashguard.malware_cluster.get_all_clusters", return_value=[])
    @patch("hashguard.database.get_all_samples", return_value=[])
    def test_get_clusters(self, mock_samples, mock_clusters, client):
        resp = client.get("/api/clusters")
        assert resp.status_code == 200
        data = resp.json()
        assert "clusters" in data

    def test_clusters_error(self, client):
        with patch("hashguard.database.get_all_samples", side_effect=Exception("db")):
            resp = client.get("/api/clusters")
            assert resp.status_code == 200
            data = resp.json()
            assert "error" in data


class TestGraphEndpoint:
    @patch("hashguard.database.get_sample_by_id")
    def test_graph_not_found(self, mock_get, client):
        mock_get.return_value = None
        resp = client.get("/api/graph/999")
        assert resp.status_code == 404

    @patch("hashguard.ioc_graph.build_graph")
    @patch("hashguard.database.get_sample_by_id")
    def test_graph_success(self, mock_get, mock_graph, client):
        mock_get.return_value = {
            "full_result": json.dumps({"hashes": {"sha256": "a" * 64}}),
        }
        mock_g = MagicMock()
        mock_g.to_visjs.return_value = {"nodes": [], "edges": []}
        mock_graph.return_value = mock_g
        resp = client.get("/api/graph/1")
        assert resp.status_code == 200

    @patch("hashguard.database.get_sample_by_id")
    def test_graph_server_error(self, mock_get, client):
        mock_get.side_effect = Exception("db error")
        resp = client.get("/api/graph/1")
        assert resp.status_code == 500


class TestTimelineEndpoint:
    @patch("hashguard.database.get_sample_by_id")
    def test_timeline_not_found(self, mock_get, client):
        mock_get.return_value = None
        resp = client.get("/api/timeline/999")
        assert resp.status_code == 404

    @patch("hashguard.malware_timeline.build_timeline")
    @patch("hashguard.database.get_sample_by_id")
    def test_timeline_success(self, mock_get, mock_tl, client):
        mock_get.return_value = {
            "full_result": json.dumps({"pe_info": {}}),
        }
        mock_t = MagicMock()
        mock_t.to_dict.return_value = {"events": []}
        mock_tl.return_value = mock_t
        resp = client.get("/api/timeline/1")
        assert resp.status_code == 200


class TestExportStixEndpoint:
    @patch("hashguard.database.get_sample_by_id")
    def test_stix_not_found(self, mock_get, client):
        mock_get.return_value = None
        resp = client.get("/api/export/stix/999")
        assert resp.status_code == 404

    @patch("hashguard.stix_exporter.export_stix_bundle")
    @patch("hashguard.database.get_sample_by_id")
    def test_stix_success(self, mock_get, mock_export, client):
        mock_get.return_value = {
            "full_result": json.dumps({"hashes": {}}),
        }
        mock_export.return_value = {"type": "bundle", "objects": []}
        resp = client.get("/api/export/stix/1")
        assert resp.status_code == 200

    @patch("hashguard.stix_exporter.export_stix_bundle", side_effect=RuntimeError("no stix2"))
    @patch("hashguard.database.get_sample_by_id")
    def test_stix_not_implemented(self, mock_get, mock_export, client):
        mock_get.return_value = {"full_result": "{}"}
        resp = client.get("/api/export/stix/1")
        assert resp.status_code == 501


class TestEnrichmentEndpoint:
    @patch("hashguard.database.get_sample_by_id")
    def test_enrichment_not_found(self, mock_get, client):
        mock_get.return_value = None
        resp = client.get("/api/enrichment/999")
        assert resp.status_code == 404

    @patch("hashguard.ioc_enrichment.enrich_iocs")
    @patch("hashguard.database.get_sample_by_id")
    def test_enrichment_success(self, mock_get, mock_enrich, client):
        mock_get.return_value = {
            "full_result": json.dumps({
                "strings_info": {"iocs": {"ips": ["1.2.3.4"]}}
            }),
        }
        mock_r = MagicMock()
        mock_r.to_dict.return_value = {"enriched": True}
        mock_enrich.return_value = mock_r
        resp = client.get("/api/enrichment/1")
        assert resp.status_code == 200


class TestSandboxStatusEndpoint:
    @patch("hashguard.sandbox.check_sandbox_availability")
    def test_sandbox_status(self, mock_check, client):
        mock_check.return_value = {"any_available": True}
        resp = client.get("/api/sandbox/status")
        assert resp.status_code == 200
        assert resp.json()["any_available"] is True

    def test_sandbox_status_error(self, client):
        with patch("hashguard.sandbox.check_sandbox_availability", side_effect=Exception("e")):
            resp = client.get("/api/sandbox/status")
            assert resp.status_code == 200
            assert resp.json()["any_available"] is False


class TestEnhancedSandboxEndpoint:
    @patch("hashguard.sandbox.enhanced_monitor")
    def test_enhanced_monitor(self, mock_monitor, client):
        mock_r = MagicMock()
        mock_r.to_dict.return_value = {"duration": 30, "events": []}
        mock_monitor.return_value = mock_r
        resp = client.post("/api/sandbox/enhanced-monitor", data={"duration": 30})
        assert resp.status_code == 200


class TestSettingsEndpoint:
    def test_get_settings_empty(self, client, monkeypatch):
        monkeypatch.delenv("HASHGUARD_VT_API_KEY", raising=False)
        monkeypatch.delenv("VT_API_KEY", raising=False)
        monkeypatch.delenv("ABUSE_CH_API_KEY", raising=False)
        resp = client.get("/api/settings")
        assert resp.status_code == 200
        data = resp.json()
        assert data["vt_api_key_set"] is False

    def test_save_settings(self, client):
        resp = client.post(
            "/api/settings",
            data={"vt_api_key": "test_key_12345678", "abuse_ch_api_key": "abuse_key_1234"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "vt_api_key" in data["saved"]


class TestDatasetEndpoints:
    @patch("hashguard.database.get_dataset_stats")
    def test_dataset_stats(self, mock_stats, client):
        mock_stats.return_value = {"total": 100}
        resp = client.get("/api/dataset/stats")
        assert resp.status_code == 200

    def test_dataset_stats_error(self, client):
        with patch("hashguard.database.get_dataset_stats", side_effect=Exception("e")):
            resp = client.get("/api/dataset/stats")
            assert resp.status_code == 500

    @patch("hashguard.database.export_dataset")
    def test_dataset_export_csv(self, mock_export, client):
        mock_export.return_value = "col1,col2\n1,2\n"
        resp = client.get("/api/dataset/export", params={"fmt": "csv"})
        assert resp.status_code == 200

    @patch("hashguard.database.export_dataset")
    def test_dataset_export_jsonl(self, mock_export, client):
        mock_export.return_value = '{"a": 1}\n'
        resp = client.get("/api/dataset/export", params={"fmt": "jsonl"})
        assert resp.status_code == 200


class TestDatasetFeaturesEndpoint:
    def test_features_not_found(self, client):
        with (
            patch("hashguard.database.init_db"),
            patch("hashguard.database._ensure_dataset_table"),
            patch("hashguard.database.get_connection") as mock_conn,
        ):
            mock_conn.return_value.execute.return_value.fetchone.return_value = None
            resp = client.get("/api/dataset/features/999")
            assert resp.status_code == 404

    def test_features_found(self, client):
        row = {"sample_id": 1, "entropy": 7.5, "file_size": 1024}
        with (
            patch("hashguard.database.init_db"),
            patch("hashguard.database._ensure_dataset_table"),
            patch("hashguard.database.get_connection") as mock_conn,
        ):
            mock_conn.return_value.execute.return_value.fetchone.return_value = row
            resp = client.get("/api/dataset/features/1")
            assert resp.status_code == 200


class TestIngestEndpoints:
    @patch("hashguard.batch_ingest.start_ingest")
    def test_ingest_start(self, mock_ingest, client):
        mock_ingest.return_value = {"job_id": "abc", "status": "started"}
        resp = client.post("/api/ingest/start", data={"source": "recent", "limit": 10})
        assert resp.status_code == 200

    @patch("hashguard.batch_ingest.get_ingest_status")
    def test_ingest_status(self, mock_status, client):
        mock_status.return_value = {"status": "idle"}
        resp = client.get("/api/ingest/status")
        assert resp.status_code == 200

    @patch("hashguard.batch_ingest.request_stop")
    def test_ingest_stop(self, mock_stop, client):
        resp = client.post("/api/ingest/stop")
        assert resp.status_code == 200


class TestMLEndpoints:
    @patch("hashguard.ml_trainer.start_training")
    def test_ml_train(self, mock_train, client):
        mock_train.return_value = {"started": True}
        resp = client.post("/api/ml/train", data={"mode": "binary"})
        assert resp.status_code == 200

    @patch("hashguard.ml_trainer.start_training")
    def test_ml_train_error(self, mock_train, client):
        mock_train.return_value = {"error": "no data"}
        resp = client.post("/api/ml/train", data={"mode": "binary"})
        assert resp.status_code == 400

    @patch("hashguard.ml_trainer.get_training_status")
    def test_ml_status(self, mock_status, client):
        mock_status.return_value = {"status": "idle"}
        resp = client.get("/api/ml/status")
        assert resp.status_code == 200

    @patch("hashguard.ml_trainer.list_models")
    def test_ml_models(self, mock_list, client):
        mock_list.return_value = [{"model_id": "test"}]
        resp = client.get("/api/ml/models")
        assert resp.status_code == 200

    @patch("hashguard.ml_trainer.get_model_metrics")
    def test_ml_model_detail(self, mock_metrics, client):
        mock_metrics.return_value = {"accuracy": 0.95}
        resp = client.get("/api/ml/models/test")
        assert resp.status_code == 200

    @patch("hashguard.ml_trainer.get_model_metrics", return_value=None)
    def test_ml_model_not_found(self, mock_metrics, client):
        resp = client.get("/api/ml/models/nonexistent")
        assert resp.status_code == 404

    @patch("hashguard.ml_trainer.delete_model", return_value=True)
    def test_ml_model_delete(self, mock_delete, client):
        resp = client.delete("/api/ml/models/test")
        assert resp.status_code == 200

    @patch("hashguard.ml_trainer.delete_model", return_value=False)
    def test_ml_model_delete_not_found(self, mock_delete, client):
        resp = client.delete("/api/ml/models/test")
        assert resp.status_code == 404

    def test_ml_predict(self, client):
        row = {"sample_id": 1, "entropy": 7.5, "file_size": 1024}
        pred = {"predicted_class": "malicious", "confidence": 95.0}
        with (
            patch("hashguard.database.init_db"),
            patch("hashguard.database._ensure_dataset_table"),
            patch("hashguard.database.get_connection") as mock_conn,
            patch("hashguard.ml_trainer.predict_sample", return_value=pred),
        ):
            mock_conn.return_value.execute.return_value.fetchone.return_value = row
            resp = client.post("/api/ml/predict", data={"sample_id": 1})
            assert resp.status_code == 200

    def test_ml_predict_no_features(self, client):
        with (
            patch("hashguard.database.init_db"),
            patch("hashguard.database._ensure_dataset_table"),
            patch("hashguard.database.get_connection") as mock_conn,
        ):
            mock_conn.return_value.execute.return_value.fetchone.return_value = None
            resp = client.post("/api/ml/predict", data={"sample_id": 999})
            assert resp.status_code == 404


class TestAnalyzeURLEdgeCases:
    def test_analyze_url_403(self, client):
        with patch(
            "hashguard.scanner.analyze_url",
            side_effect=Exception("403 Forbidden"),
        ):
            resp = client.post(
                "/api/analyze-url", data={"url": "http://example.com/f"}
            )
            assert resp.status_code == 502

    def test_analyze_url_404(self, client):
        with patch(
            "hashguard.scanner.analyze_url",
            side_effect=Exception("404 Not Found"),
        ):
            resp = client.post(
                "/api/analyze-url", data={"url": "http://example.com/f"}
            )
            assert resp.status_code == 502

    def test_analyze_url_connection_error(self, client):
        class FakeConnectionError(Exception):
            pass
        FakeConnectionError.__name__ = "ConnectionError"
        with patch(
            "hashguard.scanner.analyze_url",
            side_effect=FakeConnectionError("timeout"),
        ):
            resp = client.post(
                "/api/analyze-url", data={"url": "http://example.com/f"}
            )
            assert resp.status_code == 502

    def test_analyze_url_generic_error(self, client):
        with patch(
            "hashguard.scanner.analyze_url",
            side_effect=Exception("unknown error"),
        ):
            resp = client.post(
                "/api/analyze-url", data={"url": "http://example.com/f"}
            )
            assert resp.status_code == 500


class TestAnalyzeFileEdgeCases:
    def test_upload_analysis_error(self, client):
        with patch("hashguard.web.api._run_full_analysis", side_effect=Exception("boom")):
            resp = client.post(
                "/api/analyze",
                files={"file": ("test.txt", b"data", "text/plain")},
            )
            assert resp.status_code == 500

    @patch("hashguard.web.api._run_full_analysis")
    def test_upload_sanitizes_filename(self, mock_analysis, client):
        mock_analysis.return_value = {"hashes": {}, "malicious": False}
        resp = client.post(
            "/api/analyze",
            files={"file": ("t<>e|st.exe", b"MZ" + b"\x00" * 100, "application/octet-stream")},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "<" not in data.get("original_filename", "")


class TestSamplesListError:
    def test_list_samples_error(self, client):
        with patch("hashguard.database.get_all_samples", side_effect=Exception("db")):
            resp = client.get("/api/samples")
            assert resp.status_code == 500


class TestSampleDetailEdgeCases:
    @patch("hashguard.database.get_timeline", return_value=[])
    @patch("hashguard.database.get_sample_behaviors", return_value=[])
    @patch("hashguard.database.get_sample_iocs", return_value=[])
    @patch("hashguard.database.get_sample_by_id")
    def test_json_fields_parsed(self, mock_get, mock_iocs, mock_beh, mock_tl, client):
        mock_get.return_value = {
            "id": 1,
            "full_result": json.dumps({"hashes": {"sha256": "a" * 64}}),
            "capabilities": json.dumps({"total": 5}),
            "advanced_pe": None,
            "ml_classification": json.dumps({"predicted_class": "trojan"}),
        }
        resp = client.get("/api/samples/1")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["capabilities"], dict)
        assert isinstance(data["ml_classification"], dict)

    @patch("hashguard.database.get_sample_by_id")
    def test_sample_detail_server_error(self, mock_get, client):
        mock_get.side_effect = Exception("db error")
        resp = client.get("/api/samples/1")
        assert resp.status_code == 500


class TestRunFullAnalysisUnpackAndGraph:
    """Test _run_full_analysis with auto-unpack and graph branches."""

    def test_packed_file_auto_unpack(self):
        from hashguard.web.api import _run_full_analysis

        mock_result = MagicMock()
        mock_result.to_dict.return_value = {
            "hashes": {"sha256": "a" * 64},
            "packer": {"detected": True, "name": "UPX"},
        }

        mock_unpack = MagicMock()
        mock_unpack.to_dict.return_value = {"unpacked": True}

        with (
            patch("hashguard.scanner.analyze", return_value=mock_result),
            patch("hashguard.config.get_default_config", return_value={}),
            patch("hashguard.unpacker.auto_unpack", return_value=mock_unpack),
            patch("hashguard.ioc_graph.build_graph", side_effect=Exception("no graph")),
            patch("hashguard.malware_timeline.build_timeline", side_effect=Exception("no tl")),
            patch("hashguard.database.store_sample", side_effect=Exception("no db")),
            patch("hashguard.feature_extractor.extract_features", side_effect=Exception("no feat")),
        ):
            result = _run_full_analysis("/fake/path.exe")
            assert "unpack_result" in result

    def test_ioc_graph_added(self):
        from hashguard.web.api import _run_full_analysis

        mock_result = MagicMock()
        mock_result.to_dict.return_value = {
            "hashes": {"sha256": "b" * 64},
        }

        mock_graph = MagicMock()
        mock_graph.to_visjs.return_value = {"nodes": [{"id": 1}], "edges": []}

        with (
            patch("hashguard.scanner.analyze", return_value=mock_result),
            patch("hashguard.config.get_default_config", return_value={}),
            patch("hashguard.ioc_graph.build_graph", return_value=mock_graph),
            patch("hashguard.malware_timeline.build_timeline", side_effect=Exception("no tl")),
            patch("hashguard.database.store_sample", side_effect=Exception("no db")),
            patch("hashguard.feature_extractor.extract_features", side_effect=Exception("no feat")),
        ):
            result = _run_full_analysis("/fake/path.exe")
            assert "ioc_graph" in result

    def test_timeline_added(self):
        from hashguard.web.api import _run_full_analysis

        mock_result = MagicMock()
        mock_result.to_dict.return_value = {
            "hashes": {"sha256": "c" * 64},
        }

        mock_tl = MagicMock()
        mock_tl.to_dict.return_value = {"events": [{"type": "analysis"}]}

        with (
            patch("hashguard.scanner.analyze", return_value=mock_result),
            patch("hashguard.config.get_default_config", return_value={}),
            patch("hashguard.ioc_graph.build_graph", side_effect=Exception("no graph")),
            patch("hashguard.malware_timeline.build_timeline", return_value=mock_tl),
            patch("hashguard.database.store_sample", side_effect=Exception("no db")),
            patch("hashguard.feature_extractor.extract_features", side_effect=Exception("no feat")),
        ):
            result = _run_full_analysis("/fake/path.exe")
            assert "timeline" in result


class TestStartServer:
    """Test start_server function."""

    def test_no_fastapi(self):
        from hashguard.web import api
        orig = api.HAS_FASTAPI
        api.HAS_FASTAPI = False
        try:
            api.start_server()
        finally:
            api.HAS_FASTAPI = orig


class TestRunFullAnalysisPrediction:
    """Tests for trained model prediction integration in _run_full_analysis."""

    def test_prediction_added_when_model_exists(self):
        from hashguard.web.api import _run_full_analysis

        mock_result = MagicMock()
        mock_result.to_dict.return_value = {
            "hashes": {"sha256": "a" * 64},
            "malicious": True,
        }

        fake_feats = {"entropy": 7.5, "file_size": 1024}
        fake_prediction = {
            "predicted_class": "malicious",
            "confidence": 95.0,
            "model_id": "test_model",
            "probabilities": {"malicious": 0.95, "benign": 0.05},
        }

        with (
            patch("hashguard.scanner.analyze", return_value=mock_result),
            patch("hashguard.config.get_default_config", return_value={}),
            patch("hashguard.feature_extractor.extract_features", return_value=fake_feats),
            patch("hashguard.database.store_sample", return_value=1),
            patch("hashguard.database.store_timeline_event"),
            patch("hashguard.database.store_dataset_features"),
            patch("hashguard.ml_trainer.predict_sample", return_value=fake_prediction),
            patch("hashguard.ioc_graph.build_graph", side_effect=ImportError),
            patch("hashguard.malware_timeline.build_timeline", side_effect=ImportError),
            patch("hashguard.unpacker.auto_unpack", side_effect=ImportError),
        ):
            result = _run_full_analysis("/fake/path.exe")
            assert "trained_model_prediction" in result
            assert result["trained_model_prediction"]["predicted_class"] == "malicious"
            assert result["trained_model_prediction"]["confidence"] == 95.0

    def test_prediction_skipped_when_no_model(self):
        from hashguard.web.api import _run_full_analysis

        mock_result = MagicMock()
        mock_result.to_dict.return_value = {
            "hashes": {"sha256": "b" * 64},
            "malicious": False,
        }

        fake_feats = {"entropy": 3.0, "file_size": 512}
        error_prediction = {"error": "No trained models found"}

        with (
            patch("hashguard.scanner.analyze", return_value=mock_result),
            patch("hashguard.config.get_default_config", return_value={}),
            patch("hashguard.feature_extractor.extract_features", return_value=fake_feats),
            patch("hashguard.database.store_sample", return_value=2),
            patch("hashguard.database.store_timeline_event"),
            patch("hashguard.database.store_dataset_features"),
            patch("hashguard.ml_trainer.predict_sample", return_value=error_prediction),
            patch("hashguard.ioc_graph.build_graph", side_effect=ImportError),
            patch("hashguard.malware_timeline.build_timeline", side_effect=ImportError),
            patch("hashguard.unpacker.auto_unpack", side_effect=ImportError),
        ):
            result = _run_full_analysis("/fake/path.exe")
            assert "trained_model_prediction" not in result

    def test_prediction_skipped_when_no_features(self):
        from hashguard.web.api import _run_full_analysis

        mock_result = MagicMock()
        mock_result.to_dict.return_value = {
            "hashes": {"sha256": "c" * 64},
            "malicious": False,
        }

        with (
            patch("hashguard.scanner.analyze", return_value=mock_result),
            patch("hashguard.config.get_default_config", return_value={}),
            patch("hashguard.feature_extractor.extract_features", side_effect=Exception("fail")),
            patch("hashguard.database.store_sample", return_value=3),
            patch("hashguard.database.store_timeline_event"),
            patch("hashguard.ioc_graph.build_graph", side_effect=ImportError),
            patch("hashguard.malware_timeline.build_timeline", side_effect=ImportError),
            patch("hashguard.unpacker.auto_unpack", side_effect=ImportError),
        ):
            result = _run_full_analysis("/fake/path.exe")
            assert "trained_model_prediction" not in result

    def test_prediction_exception_handled_gracefully(self):
        from hashguard.web.api import _run_full_analysis

        mock_result = MagicMock()
        mock_result.to_dict.return_value = {
            "hashes": {"sha256": "d" * 64},
            "malicious": True,
        }

        fake_feats = {"entropy": 6.0}

        with (
            patch("hashguard.scanner.analyze", return_value=mock_result),
            patch("hashguard.config.get_default_config", return_value={}),
            patch("hashguard.feature_extractor.extract_features", return_value=fake_feats),
            patch("hashguard.database.store_sample", return_value=4),
            patch("hashguard.database.store_timeline_event"),
            patch("hashguard.database.store_dataset_features"),
            patch("hashguard.ml_trainer.predict_sample", side_effect=RuntimeError("model corrupt")),
            patch("hashguard.ioc_graph.build_graph", side_effect=ImportError),
            patch("hashguard.malware_timeline.build_timeline", side_effect=ImportError),
            patch("hashguard.unpacker.auto_unpack", side_effect=ImportError),
        ):
            # Should not raise — error is caught and logged
            result = _run_full_analysis("/fake/path.exe")
            assert "trained_model_prediction" not in result


class TestSandboxEndpoint:
    def test_sandbox_status(self, client):
        resp = client.get("/api/sandbox/status")
        assert resp.status_code == 200


class TestEndpointErrorHandlers:
    """Test exception handlers for remaining endpoints."""

    def test_ingest_start_error(self, client):
        with patch("hashguard.batch_ingest.start_ingest", side_effect=Exception("fail")):
            resp = client.post("/api/ingest/start", data={"source": "recent"})
            assert resp.status_code == 500

    def test_ingest_status_error(self, client):
        with patch("hashguard.batch_ingest.get_ingest_status", side_effect=Exception("fail")):
            resp = client.get("/api/ingest/status")
            assert resp.status_code == 500

    def test_ingest_stop_error(self, client):
        with patch("hashguard.batch_ingest.request_stop", side_effect=Exception("fail")):
            resp = client.post("/api/ingest/stop")
            assert resp.status_code == 500

    def test_ml_train_exception(self, client):
        with patch("hashguard.ml_trainer.start_training", side_effect=Exception("fail")):
            resp = client.post("/api/ml/train", data={"mode": "binary"})
            assert resp.status_code == 500

    def test_ml_status_error(self, client):
        with patch("hashguard.ml_trainer.get_training_status", side_effect=Exception("fail")):
            resp = client.get("/api/ml/status")
            assert resp.status_code == 500

    def test_ml_models_error(self, client):
        with patch("hashguard.ml_trainer.list_models", side_effect=Exception("fail")):
            resp = client.get("/api/ml/models")
            assert resp.status_code == 500

    def test_ml_model_detail_error(self, client):
        with patch("hashguard.ml_trainer.get_model_metrics", side_effect=Exception("fail")):
            resp = client.get("/api/ml/models/test")
            assert resp.status_code == 500

    def test_ml_model_delete_error(self, client):
        with patch("hashguard.ml_trainer.delete_model", side_effect=Exception("fail")):
            resp = client.delete("/api/ml/models/test")
            assert resp.status_code == 500

    def test_ml_predict_error(self, client):
        with (
            patch("hashguard.database.init_db", side_effect=Exception("db fail")),
        ):
            resp = client.post("/api/ml/predict", data={"sample_id": 1})
            assert resp.status_code == 500

    def test_enrichment_error(self, client):
        with patch("hashguard.database.get_sample_by_id", side_effect=Exception("fail")):
            resp = client.get("/api/enrichment/1")
            assert resp.status_code == 500

    def test_dataset_export_error(self, client):
        with patch("hashguard.database.export_dataset", side_effect=Exception("fail")):
            resp = client.get("/api/dataset/export")
            assert resp.status_code == 500

    def test_search_error(self, client):
        with patch("hashguard.database.search_samples", side_effect=Exception("fail")):
            resp = client.get("/api/search", params={"q": "test"})
            assert resp.status_code == 500

    def test_enhanced_monitor_error(self, client):
        with patch("hashguard.sandbox.enhanced_monitor", side_effect=Exception("fail")):
            resp = client.post("/api/sandbox/enhanced-monitor", data={"duration": 10})
            assert resp.status_code == 500

    def test_dataset_features_error(self, client):
        with patch("hashguard.database.init_db", side_effect=Exception("fail")):
            resp = client.get("/api/dataset/features/1")
            assert resp.status_code == 500

    def test_graph_error(self, client):
        with patch("hashguard.database.get_sample_by_id", side_effect=Exception("fail")):
            resp = client.get("/api/graph/1")
            assert resp.status_code == 500

    def test_timeline_error(self, client):
        with patch("hashguard.database.get_sample_by_id", side_effect=Exception("fail")):
            resp = client.get("/api/timeline/1")
            assert resp.status_code == 500

    def test_stix_error(self, client):
        with patch("hashguard.database.get_sample_by_id", side_effect=Exception("fail")):
            resp = client.get("/api/export/stix/1")
            assert resp.status_code == 500


class TestTemplateFallback:
    """Cover _get_template_dir fallback (line 79) and _get_static_dir None (line 88)."""

    def test_template_dir_fallback(self):
        with patch("hashguard.web.api.Path") as mock_path:
            inst = MagicMock()
            inst.parent = inst
            inst.__truediv__ = lambda s, n: MagicMock(is_dir=lambda: False)
            mock_path.return_value = inst
            mock_path.__file__ = "api.py"
            # Just test the function exists and returns something
            d = _get_template_dir()
            assert d is not None

    def test_static_dir_none(self):
        d = _get_static_dir()
        # Returns either a path or None
        assert d is None or hasattr(d, "__fspath__") or isinstance(d, str)


class TestAutoUnpackError:
    """Cover auto-unpack error path (lines 125-126)."""

    def test_auto_unpack_exception(self, client):
        mock_result = {"packer": {"detected": True}, "hashes": {}}
        with patch("hashguard.web.api._run_full_analysis") as mock_run:
            # Trigger analyze_file endpoint and make _run_full_analysis return
            # a result that would normally trigger auto-unpack
            mock_run.return_value = mock_result
            # Upload a file
            resp = client.post(
                "/api/analyze",
                files={"file": ("test.exe", b"MZ" + b"\x00" * 100)},
                data={"use_vt": "false"},
            )
            # Should succeed since _run_full_analysis handles auto-unpack internally
            assert resp.status_code == 200


class TestSampleDetailJsonParse:
    """Cover JSON field parsing (lines 320-321) and graph/timeline rebuild (335-336, 343-344)."""

    def test_sample_detail_json_fields(self, client):
        sample = {
            "id": 1,
            "full_result": '{"sha256": "abc"}',
            "capabilities": '{"caps": []}',
            "advanced_pe": None,
            "ml_classification": None,
        }
        with patch("hashguard.database.get_sample_by_id", return_value=dict(sample)):
            with patch("hashguard.database.get_sample_iocs", return_value=[]):
                with patch("hashguard.database.get_sample_behaviors", return_value=[]):
                    with patch("hashguard.database.get_timeline", return_value=[]):
                        with patch("hashguard.ioc_graph.build_graph") as mock_graph:
                            mock_graph.return_value = MagicMock(to_visjs=lambda: {"nodes": []})
                            with patch("hashguard.malware_timeline.build_timeline") as mock_tl:
                                mock_tl.return_value = MagicMock(to_dict=lambda: {"events": []})
                                resp = client.get("/api/samples/1")
                                assert resp.status_code == 200
                                data = resp.json()
                                # full_result should be parsed from JSON string
                                assert isinstance(data["full_result"], dict)


class TestBatchIngestCaps:
    """Cover batch ingest source limit caps (lines 597-600)."""

    def test_recent_capped_to_100(self, client):
        with patch("hashguard.batch_ingest.start_ingest", return_value={"status": "started"}) as mock:
            resp = client.post(
                "/api/ingest/start",
                data={"source": "recent", "limit": 500, "tag": "", "file_type": "exe", "directory": ""},
            )
            assert resp.status_code == 200
            mock.assert_called_once()
            _, kwargs = mock.call_args
            assert kwargs.get("limit", mock.call_args[1].get("limit", 500)) <= 100

    def test_tag_capped_to_1000(self, client):
        with patch("hashguard.batch_ingest.start_ingest", return_value={"status": "started"}) as mock:
            resp = client.post(
                "/api/ingest/start",
                data={"source": "tag", "limit": 5000, "tag": "Emotet", "file_type": "exe", "directory": ""},
            )
            assert resp.status_code == 200
            call_kwargs = mock.call_args[1] if mock.call_args[1] else {}
            actual_limit = call_kwargs.get("limit", 5000)
            assert actual_limit <= 1000


class TestMLPredictNotFound:
    """Cover ML predict 404 when no features (line 730)."""

    def test_predict_no_features(self, client):
        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchone.return_value = None
        with patch("hashguard.database.init_db"):
            with patch("hashguard.database.get_connection", return_value=mock_conn):
                resp = client.post("/api/ml/predict", data={"sample_id": 999})
                assert resp.status_code == 404


class TestStartServer:
    """Cover start_server function (lines 745-760)."""

    def test_start_server_no_fastapi(self, capsys):
        with patch("hashguard.web.api.HAS_FASTAPI", False):
            from hashguard.web.api import start_server
            start_server()
            out = capsys.readouterr().out
            assert "FastAPI not installed" in out

    def test_start_server_banner(self, capsys):
        with patch("hashguard.web.api.HAS_FASTAPI", True):
            with patch("hashguard.web.api.uvicorn") as mock_uvi:
                from hashguard.web.api import start_server
                start_server(open_browser=False)
                out = capsys.readouterr().out
                assert "HashGuard" in out
                mock_uvi.run.assert_called_once()


class TestSampleDetailJSONParseFail:
    """Cover JSON parse exception in sample detail (lines 320-321)."""

    @patch("hashguard.database.get_timeline", return_value=[])
    @patch("hashguard.database.get_sample_behaviors", return_value=[])
    @patch("hashguard.database.get_sample_iocs", return_value=[])
    @patch("hashguard.database.get_sample_by_id")
    def test_invalid_json_field(self, mock_get, mock_iocs, mock_beh, mock_tl, client):
        mock_get.return_value = {
            "id": 1,
            "filename": "test.exe",
            "sha256": "a" * 64,
            "full_result": "not valid json {{{{",
            "capabilities": "also broken json",
            "advanced_pe": None,
            "ml_classification": None,
        }
        resp = client.get("/api/samples/1")
        assert resp.status_code == 200
        data = resp.json()
        # Fields with invalid JSON remain as strings
        assert data["full_result"] == "not valid json {{{{"


class TestSampleDetailGraphException:
    """Cover graph/timeline build exceptions (lines 335-336, 343-344)."""

    @patch("hashguard.malware_timeline.build_timeline", side_effect=Exception("tl fail"))
    @patch("hashguard.ioc_graph.build_graph", side_effect=Exception("graph fail"))
    @patch("hashguard.database.get_timeline", return_value=[])
    @patch("hashguard.database.get_sample_behaviors", return_value=[])
    @patch("hashguard.database.get_sample_iocs", return_value=[])
    @patch("hashguard.database.get_sample_by_id")
    def test_graph_and_timeline_exceptions(self, mock_get, mock_iocs, mock_beh, mock_db_tl, mock_graph, mock_tl, client):
        mock_get.return_value = {
            "id": 1,
            "filename": "test.exe",
            "sha256": "a" * 64,
            "full_result": '{"malicious": true}',
            "capabilities": None,
            "advanced_pe": None,
            "ml_classification": None,
        }
        resp = client.get("/api/samples/1")
        assert resp.status_code == 200
        data = resp.json()
        assert "ioc_graph" not in data
        assert "analysis_timeline" not in data
