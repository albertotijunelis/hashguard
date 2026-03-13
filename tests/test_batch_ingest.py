"""Tests for the batch ingest pipeline."""

import os
import tempfile
import threading
import time
import zipfile

import pytest
from unittest.mock import patch, MagicMock

from hashguard import batch_ingest
from hashguard.batch_ingest import (
    IngestJob,
    _get_abuse_ch_key,
    _mb_get_recent,
    _mb_get_by_tag,
    _mb_get_by_filetype,
    _mb_download_sample,
    _already_in_dataset,
    _run_local_ingest,
    get_ingest_status,
    request_stop,
    start_ingest,
)


# ── IngestJob ───────────────────────────────────────────────────────────────


class TestIngestJob:
    def test_default_state(self):
        job = IngestJob()
        assert job.status == "idle"
        assert job.total_candidates == 0
        assert job.analysed == 0

    def test_to_dict(self):
        job = IngestJob(source="recent", status="running", started_at=time.time() - 5.0)
        d = job.to_dict()
        assert d["source"] == "recent"
        assert d["status"] == "running"
        assert d["elapsed_seconds"] >= 4.0
        assert isinstance(d["errors"], list)

    def test_to_dict_idle_no_elapsed(self):
        job = IngestJob()
        d = job.to_dict()
        assert d["elapsed_seconds"] == 0.0

    def test_errors_capped_at_20(self):
        job = IngestJob(errors=[f"err_{i}" for i in range(50)])
        d = job.to_dict()
        assert len(d["errors"]) == 20


# ── MalwareBazaar helpers ──────────────────────────────────────────────────


class TestMBGetRecent:
    @patch("hashguard.batch_ingest._mb_post")
    def test_returns_samples(self, mock_post):
        mock_post.return_value = {
            "query_status": "ok",
            "data": [{"sha256_hash": f"{'a' * 64}"}, {"sha256_hash": f"{'b' * 64}"}],
        }
        result = _mb_get_recent(limit=10)
        assert len(result) == 2
        mock_post.assert_called_once()

    @patch("hashguard.batch_ingest._mb_post")
    def test_empty_on_error(self, mock_post):
        mock_post.return_value = None
        assert _mb_get_recent() == []

    @patch("hashguard.batch_ingest._mb_post")
    def test_empty_on_not_found(self, mock_post):
        mock_post.return_value = {"query_status": "no_results"}
        assert _mb_get_recent() == []

    @patch("hashguard.batch_ingest._mb_post")
    def test_respects_limit(self, mock_post):
        mock_post.return_value = {
            "query_status": "ok",
            "data": [{"sha256_hash": f"{i:064x}"} for i in range(50)],
        }
        result = _mb_get_recent(limit=5)
        assert len(result) == 5


class TestMBGetByTag:
    @patch("hashguard.batch_ingest._mb_post")
    def test_returns_samples(self, mock_post):
        mock_post.return_value = {
            "query_status": "ok",
            "data": [{"sha256_hash": "a" * 64, "tags": ["Emotet"]}],
        }
        result = _mb_get_by_tag("Emotet", limit=10)
        assert len(result) == 1

    @patch("hashguard.batch_ingest._mb_post")
    def test_empty_on_none(self, mock_post):
        mock_post.return_value = None
        assert _mb_get_by_tag("nope") == []


class TestMBGetByFiletype:
    @patch("hashguard.batch_ingest._mb_post")
    def test_returns_samples(self, mock_post):
        mock_post.return_value = {
            "query_status": "ok",
            "data": [{"sha256_hash": "c" * 64, "file_type": "exe"}],
        }
        result = _mb_get_by_filetype("exe", limit=5)
        assert len(result) == 1

    @patch("hashguard.batch_ingest._mb_post")
    def test_returns_empty_on_not_ok(self, mock_post):
        """Cover return [] when query_status != 'ok' (line 200)."""
        mock_post.return_value = {"query_status": "no_results"}
        result = _mb_get_by_filetype("dll", limit=5)
        assert result == []


# ── Download helper ────────────────────────────────────────────────────────


class TestMBDownloadSample:
    def _make_zip_bytes(self, filename: str, content: bytes, password: bytes = b"infected") -> bytes:
        """Create an in-memory ZIP with a password-protected file."""
        import io
        import pyzipper

        buf = io.BytesIO()
        with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
            zf.setpassword(password)
            zf.writestr(filename, content)
        return buf.getvalue()

    @patch("hashguard.batch_ingest._mb_post")
    def test_download_failure_returns_none(self, mock_post):
        """If the HTTP response can't be fetched, return None."""
        # We mock at a higher level since download uses requests directly
        with patch("requests.post", side_effect=Exception("network error")):
            result = _mb_download_sample("a" * 64, tempfile.mkdtemp())
            assert result is None

    def test_bad_zip_returns_none(self):
        """Non-ZIP content should return None gracefully."""
        with patch("requests.post") as mock_req:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.content = b"this is not a zip file at all, definitely more than 100 bytes long " * 3
            mock_req.return_value = mock_resp

            dest = tempfile.mkdtemp()
            try:
                result = _mb_download_sample("a" * 64, dest)
                assert result is None
            finally:
                import shutil
                shutil.rmtree(dest, ignore_errors=True)


# ── Dedup helper ───────────────────────────────────────────────────────────


class TestAlreadyInDataset:
    @patch("hashguard.database.get_sample")
    def test_exists(self, mock_get):
        mock_get.return_value = {"id": 1}
        assert _already_in_dataset("a" * 64) is True

    @patch("hashguard.database.get_sample")
    def test_not_exists(self, mock_get):
        mock_get.return_value = None
        assert _already_in_dataset("b" * 64) is False

    def test_exception_returns_false(self):
        with patch("hashguard.database.get_sample", side_effect=Exception("db error")):
            assert _already_in_dataset("c" * 64) is False


# ── get_ingest_status / request_stop ───────────────────────────────────────


class TestStatusAndStop:
    def test_get_ingest_status_returns_dict(self):
        status = get_ingest_status()
        assert isinstance(status, dict)
        assert "status" in status

    def test_request_stop_sets_event(self):
        batch_ingest._stop_event.clear()
        request_stop()
        assert batch_ingest._stop_event.is_set()
        batch_ingest._stop_event.clear()


# ── start_ingest ───────────────────────────────────────────────────────────


class TestStartIngest:
    def setup_method(self):
        """Reset global state before each test."""
        batch_ingest._current_job = IngestJob()
        batch_ingest._stop_event.clear()

    @patch("hashguard.batch_ingest._mb_get_recent")
    def test_no_candidates_returns_not_started(self, mock_recent):
        mock_recent.return_value = []
        result = start_ingest(source="recent", limit=10)
        assert result["started"] is True
        # Candidate fetching now happens in background thread; wait for it
        for _ in range(50):
            if get_ingest_status()["status"] != "running":
                break
            time.sleep(0.1)
        status = get_ingest_status()
        assert status["status"] == "error"
        assert any("No candidates" in e for e in status.get("errors", []))

    @patch("hashguard.batch_ingest._mb_get_recent")
    @patch("hashguard.batch_ingest._run_ingest")
    def test_starts_thread_on_candidates(self, mock_run, mock_recent):
        mock_recent.return_value = [{"sha256_hash": "a" * 64}]
        # _run_ingest will be called in a background thread; mock it to prevent real work
        result = start_ingest(source="recent", limit=1)
        assert result["started"] is True
        # candidates starts at 0; background thread fetches them
        assert result["candidates"] == 0
        # Wait for background thread to call _run_ingest
        for _ in range(50):
            if mock_run.called:
                break
            time.sleep(0.1)
        mock_run.assert_called_once()

    @patch("hashguard.batch_ingest._mb_get_recent")
    def test_rejects_concurrent_job(self, mock_recent):
        batch_ingest._current_job = IngestJob(status="running")
        result = start_ingest(source="recent", limit=10)
        assert result["started"] is False
        assert "already running" in result["reason"]
        batch_ingest._current_job = IngestJob()

    @patch("hashguard.batch_ingest._mb_get_by_tag")
    @patch("hashguard.batch_ingest._run_ingest")
    def test_tag_source(self, mock_run, mock_tag):
        mock_tag.return_value = [{"sha256_hash": "b" * 64}]
        result = start_ingest(source="tag", tag="Emotet", limit=5)
        assert result["started"] is True
        # Wait for background thread to call the mock
        for _ in range(50):
            if mock_tag.called:
                break
            time.sleep(0.1)
        mock_tag.assert_called_once_with("Emotet", 5)

    @patch("hashguard.batch_ingest._mb_get_by_filetype")
    @patch("hashguard.batch_ingest._run_ingest")
    def test_filetype_source(self, mock_run, mock_ft):
        mock_ft.return_value = [{"sha256_hash": "c" * 64}]
        result = start_ingest(source="filetype", file_type="dll", limit=5)
        assert result["started"] is True
        # Wait for background thread to call the mock
        for _ in range(50):
            if mock_ft.called:
                break
            time.sleep(0.1)
        mock_ft.assert_called_once_with("dll", 5)


# ── _run_ingest integration ───────────────────────────────────────────────


class TestRunIngest:
    def setup_method(self):
        batch_ingest._current_job = IngestJob(status="running", started_at=time.time())
        batch_ingest._stop_event.clear()

    def teardown_method(self):
        batch_ingest._current_job = IngestJob()
        batch_ingest._stop_event.clear()

    @patch("hashguard.batch_ingest._analyse_file_batch")
    @patch("hashguard.batch_ingest._mb_download_sample")
    @patch("hashguard.batch_ingest._already_in_dataset")
    def test_skips_existing(self, mock_exists, mock_dl, mock_analyse):
        mock_exists.return_value = True
        candidates = [{"sha256_hash": "a" * 64}]
        batch_ingest._run_ingest(candidates, delay=0)
        assert batch_ingest._current_job.skipped_existing == 1
        mock_dl.assert_not_called()
        mock_analyse.assert_not_called()

    @patch("hashguard.batch_ingest._analyse_file_batch")
    @patch("hashguard.batch_ingest._mb_download_sample")
    @patch("hashguard.batch_ingest._already_in_dataset")
    def test_download_failure(self, mock_exists, mock_dl, mock_analyse):
        mock_exists.return_value = False
        mock_dl.return_value = None
        candidates = [{"sha256_hash": "a" * 64}]
        batch_ingest._run_ingest(candidates, delay=0)
        assert batch_ingest._current_job.failed == 1
        mock_analyse.assert_not_called()

    @patch("hashguard.batch_ingest._analyse_file_batch")
    @patch("hashguard.batch_ingest._mb_download_sample")
    @patch("hashguard.batch_ingest._already_in_dataset")
    def test_successful_analysis(self, mock_exists, mock_dl, mock_analyse):
        mock_exists.return_value = False
        # Create a real temp file for download
        fd, tmp = tempfile.mkstemp()
        os.write(fd, b"\x00" * 100)
        os.close(fd)
        mock_dl.return_value = tmp
        mock_analyse.return_value = {"hashes": {"sha256": "a" * 64}, "risk_score": {"score": 50}}
        candidates = [{"sha256_hash": "a" * 64}]
        batch_ingest._run_ingest(candidates, delay=0)
        assert batch_ingest._current_job.downloaded == 1
        assert batch_ingest._current_job.analysed == 1
        assert batch_ingest._current_job.status == "done"

    @patch("hashguard.batch_ingest._analyse_file_batch")
    @patch("hashguard.batch_ingest._mb_download_sample")
    @patch("hashguard.batch_ingest._already_in_dataset")
    def test_analysis_failure(self, mock_exists, mock_dl, mock_analyse):
        mock_exists.return_value = False
        fd, tmp = tempfile.mkstemp()
        os.write(fd, b"\x00" * 100)
        os.close(fd)
        mock_dl.return_value = tmp
        mock_analyse.return_value = None  # analysis failed
        candidates = [{"sha256_hash": "a" * 64}]
        batch_ingest._run_ingest(candidates, delay=0)
        assert batch_ingest._current_job.downloaded == 1
        assert batch_ingest._current_job.failed == 1

    @patch("hashguard.batch_ingest._analyse_file_batch")
    @patch("hashguard.batch_ingest._mb_download_sample")
    @patch("hashguard.batch_ingest._already_in_dataset")
    def test_stop_event_halts_processing(self, mock_exists, mock_dl, mock_analyse):
        mock_exists.return_value = False
        batch_ingest._stop_event.set()
        candidates = [{"sha256_hash": f"{i:064x}"} for i in range(10)]
        batch_ingest._run_ingest(candidates, delay=0)
        assert batch_ingest._current_job.downloaded == 0
        assert batch_ingest._current_job.status == "done"

    @patch("hashguard.batch_ingest._analyse_file_batch")
    @patch("hashguard.batch_ingest._mb_download_sample")
    @patch("hashguard.batch_ingest._already_in_dataset")
    def test_multiple_candidates(self, mock_exists, mock_dl, mock_analyse):
        mock_exists.return_value = False
        fd, tmp = tempfile.mkstemp()
        os.write(fd, b"\x00" * 100)
        os.close(fd)
        mock_dl.return_value = tmp
        mock_analyse.return_value = {"ok": True}
        candidates = [{"sha256_hash": f"{i:064x}"} for i in range(3)]
        batch_ingest._run_ingest(candidates, delay=0)
        assert batch_ingest._current_job.analysed == 3
        assert batch_ingest._current_job.status == "done"
        assert batch_ingest._current_job.finished_at > 0

    def test_empty_sha_skipped(self):
        candidates = [{"sha256_hash": ""}, {}]
        batch_ingest._run_ingest(candidates, delay=0)
        assert batch_ingest._current_job.analysed == 0
        assert batch_ingest._current_job.failed == 0


# ── Auth-Key support ───────────────────────────────────────────────────────


class TestGetAbuseCHKey:
    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("ABUSE_CH_API_KEY", "test-key-123")
        assert _get_abuse_ch_key() == "test-key-123"

    def test_none_when_missing(self, monkeypatch):
        monkeypatch.delenv("ABUSE_CH_API_KEY", raising=False)
        with patch("hashguard.config.get_default_config") as mock_cfg:
            mock_cfg.return_value.abuse_ch_api_key = None
            assert _get_abuse_ch_key() is None

    def test_from_config(self, monkeypatch):
        monkeypatch.delenv("ABUSE_CH_API_KEY", raising=False)
        with patch("hashguard.config.get_default_config") as mock_cfg:
            mock_cfg.return_value.abuse_ch_api_key = "cfg-key-456"
            assert _get_abuse_ch_key() == "cfg-key-456"


class TestMBPostAuthKey:
    @patch("hashguard.batch_ingest._get_abuse_ch_key")
    def test_sends_auth_header(self, mock_key):
        mock_key.return_value = "my-secret-key"
        with patch("requests.post") as mock_req:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"query_status": "ok"}
            mock_req.return_value = mock_resp
            from hashguard.batch_ingest import _mb_post
            _mb_post({"query": "get_recent", "selector": "10"})
            call_kwargs = mock_req.call_args
            assert call_kwargs.kwargs.get("headers", {}).get("Auth-Key") == "my-secret-key"

    @patch("hashguard.batch_ingest._get_abuse_ch_key")
    def test_no_header_without_key(self, mock_key):
        mock_key.return_value = None
        with patch("requests.post") as mock_req:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"query_status": "ok"}
            mock_req.return_value = mock_resp
            from hashguard.batch_ingest import _mb_post
            _mb_post({"query": "get_recent", "selector": "10"})
            call_kwargs = mock_req.call_args
            assert "Auth-Key" not in call_kwargs.kwargs.get("headers", {})


# ── Local directory ingest ─────────────────────────────────────────────────


class TestStartIngestLocal:
    def setup_method(self):
        batch_ingest._current_job = IngestJob()
        batch_ingest._stop_event.clear()

    def teardown_method(self):
        batch_ingest._current_job = IngestJob()
        batch_ingest._stop_event.clear()

    def test_invalid_directory(self):
        result = start_ingest(source="local", directory="/nonexistent/path/xyz")
        assert result["started"] is False
        assert "Invalid" in result["reason"]

    def test_empty_directory(self):
        result = start_ingest(source="local", directory="")
        assert result["started"] is False
        assert "Invalid" in result["reason"]

    @patch("hashguard.batch_ingest._analyse_file_batch")
    @patch("hashguard.batch_ingest._already_in_dataset")
    def test_local_ingest_analyses_files(self, mock_exists, mock_analyse):
        mock_exists.return_value = False
        mock_analyse.return_value = {"hashes": {"sha256": "a" * 64}}
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create sample files
            for i in range(3):
                path = os.path.join(tmpdir, f"sample_{i}.bin")
                with open(path, "wb") as f:
                    f.write(os.urandom(256))
            result = start_ingest(source="local", directory=tmpdir, limit=10)
            assert result["started"] is True
            # Wait for background thread to finish before tmpdir cleanup
            for _ in range(50):
                if get_ingest_status()["status"] != "running":
                    break
                time.sleep(0.1)


# ── Additional coverage tests ──────────────────────────────────────────────


class TestGetAbuseCHKeyException:
    """Cover _get_abuse_ch_key exception fallback (lines 107-108)."""

    def test_config_exception_returns_none(self, monkeypatch):
        monkeypatch.delenv("ABUSE_CH_API_KEY", raising=False)
        with patch("hashguard.config.get_default_config", side_effect=RuntimeError("broken")):
            assert _get_abuse_ch_key() is None


class TestMBPostEdge:
    """Cover _mb_post ImportError and retry paths (lines 119-120, 139-151)."""

    def test_import_error_returns_none(self):
        import sys
        import importlib
        with patch.dict("sys.modules", {"requests": None}):
            # Force reimport
            from hashguard.batch_ingest import _mb_post
            result = _mb_post({"query": "test"})
            assert result is None

    @patch("hashguard.batch_ingest._get_abuse_ch_key", return_value=None)
    def test_non_200_returns_none(self, mock_key):
        """Non-200 response returns None (line 139-140)."""
        import requests
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        with patch.object(requests, "post", return_value=mock_resp):
            from hashguard.batch_ingest import _mb_post
            result = _mb_post({"query": "test"})
            assert result is None

    @patch("hashguard.batch_ingest._get_abuse_ch_key", return_value=None)
    def test_timeout_retries(self, mock_key):
        """Timeout retries up to max then returns None (lines 141-151)."""
        import requests
        with patch.object(requests, "post", side_effect=requests.exceptions.Timeout("timed out")):
            with patch("hashguard.batch_ingest.time.sleep"):
                from hashguard.batch_ingest import _mb_post
                result = _mb_post({"query": "test"}, retries=2)
                assert result is None

    @patch("hashguard.batch_ingest._get_abuse_ch_key", return_value=None)
    def test_unexpected_exception_returns_none(self, mock_key):
        """Non-retriable exception returns None (lines 146-148)."""
        import requests
        with patch.object(requests, "post", side_effect=ValueError("bad")):
            from hashguard.batch_ingest import _mb_post
            result = _mb_post({"query": "test"})
            assert result is None


class TestMBGetByTagEdge:
    """Cover empty tag (line 173)."""

    def test_empty_tag_returns_empty(self):
        assert _mb_get_by_tag("") == []
        assert _mb_get_by_tag("   ") == []


class TestMBGetByFiletypeEdge:
    """Cover empty filetype (line 190)."""

    def test_empty_filetype_returns_empty(self):
        assert _mb_get_by_filetype("") == []
        assert _mb_get_by_filetype("   ") == []


class TestMBDownloadSampleEdge:
    """Cover auth header, HTTP check, pyzipper, and stdlib fallback (lines 214, 223, 231-251)."""

    @patch("hashguard.batch_ingest._get_abuse_ch_key", return_value="testkey")
    def test_auth_header_sent(self, mock_key):
        """Auth header sent when API key exists (line 214)."""
        import requests
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        # Create a valid zip content
        import io
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("sample.bin", b"MZ" + b"\x00" * 200)
        zip_bytes = buf.getvalue()
        mock_resp.content = zip_bytes

        with patch.object(requests, "post", return_value=mock_resp) as mock_post:
            with tempfile.TemporaryDirectory() as tmpdir:
                _mb_download_sample("a" * 64, tmpdir)
                call_kwargs = mock_post.call_args
                assert call_kwargs.kwargs.get("headers", {}).get("Auth-Key") == "testkey"

    def test_http_failure_returns_none(self):
        """Non-200 or small response returns None (line 223)."""
        import requests
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.content = b""
        with patch.object(requests, "post", return_value=mock_resp):
            result = _mb_download_sample("a" * 64, tempfile.mkdtemp())
            assert result is None

    def test_stdlib_zip_fallback(self):
        """When pyzipper unavailable, falls back to stdlib zipfile (lines 240-248)."""
        import io
        import requests

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("sample.bin", b"MZ" + b"\x00" * 200)
        zip_bytes = buf.getvalue()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = zip_bytes

        with patch.object(requests, "post", return_value=mock_resp):
            with patch.dict("sys.modules", {"pyzipper": None}):
                with tempfile.TemporaryDirectory() as tmpdir:
                    result = _mb_download_sample("a" * 64, tmpdir)
                    # stdlib zipfile should work for non-encrypted zips
                    assert result is not None
                    assert os.path.exists(result)

    def test_stdlib_zip_empty_names(self):
        """Empty zip returns None in stdlib fallback (line 243-244)."""
        import io
        import requests

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            pass  # empty zip
        zip_bytes = buf.getvalue()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        # Make content large enough (>100 bytes)
        mock_resp.content = zip_bytes + b"\x00" * 200

        with patch.object(requests, "post", return_value=mock_resp):
            with patch.dict("sys.modules", {"pyzipper": None}):
                with tempfile.TemporaryDirectory() as tmpdir:
                    result = _mb_download_sample("a" * 64, tmpdir)
                    assert result is None

    def test_pyzipper_empty_zip_returns_none(self):
        """Pyzipper with empty namelist returns None (line 232-233)."""
        import io
        import requests

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"\x00" * 200

        mock_pyzipper = MagicMock()
        mock_zf = MagicMock()
        mock_zf.__enter__ = MagicMock(return_value=mock_zf)
        mock_zf.__exit__ = MagicMock(return_value=False)
        mock_zf.namelist.return_value = []
        mock_pyzipper.AESZipFile.return_value = mock_zf

        with patch.object(requests, "post", return_value=mock_resp):
            with patch.dict("sys.modules", {"pyzipper": mock_pyzipper}):
                with tempfile.TemporaryDirectory() as tmpdir:
                    result = _mb_download_sample("a" * 64, tmpdir)
                    assert result is None


class TestAnalyseFile:
    """Cover _analyse_file (lines 269-273)."""

    def test_analyse_success(self):
        from hashguard.batch_ingest import _analyse_file
        with patch("hashguard.web.api._run_full_analysis", return_value={"ok": True}):
            result = _analyse_file("/fake/path")
            assert result == {"ok": True}

    def test_analyse_failure(self):
        from hashguard.batch_ingest import _analyse_file
        with patch("hashguard.web.api._run_full_analysis", side_effect=Exception("fail")):
            result = _analyse_file("/fake/path")
            assert result is None


class TestRunLocalIngestEdge:
    """Cover local ingest error paths (lines 391-394, 408-409)."""

    def setup_method(self):
        batch_ingest._current_job = IngestJob(status="running", started_at=time.time())
        batch_ingest._stop_event.clear()

    def teardown_method(self):
        batch_ingest._current_job = IngestJob()
        batch_ingest._stop_event.clear()

    @patch("hashguard.batch_ingest._analyse_file_batch")
    @patch("hashguard.batch_ingest._already_in_dataset")
    def test_unreadable_file(self, mock_exists, mock_analyse):
        """OSError during SHA-256 computation (lines 391-394)."""
        mock_exists.return_value = False
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "bad.bin")
            with open(path, "wb") as f:
                f.write(b"\x00" * 100)
            orig_open = open
            def patched_open(p, *a, **kw):
                if str(p) == path and "rb" in a:
                    raise OSError("permission denied")
                return orig_open(p, *a, **kw)
            with patch("builtins.open", side_effect=patched_open):
                _run_local_ingest(tmpdir, use_vt=False, delay=0)
            assert batch_ingest._current_job.failed == 1

    @patch("hashguard.batch_ingest._analyse_file_batch", return_value=None)
    @patch("hashguard.batch_ingest._already_in_dataset", return_value=False)
    def test_analysis_failure_in_local(self, mock_exists, mock_analyse):
        """Analysis failure bumps failed counter (lines 408-409)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "sample.bin")
            with open(path, "wb") as f:
                f.write(b"\x00" * 100)
            _run_local_ingest(tmpdir, use_vt=False, delay=0)
        assert batch_ingest._current_job.failed == 1


class TestMBGetMulti:
    """Cover _mb_get_multi (lines 436-464)."""

    @patch("hashguard.batch_ingest._mb_get_by_filetype")
    @patch("hashguard.batch_ingest.time.sleep")
    def test_collects_from_multiple_types(self, mock_sleep, mock_ft):
        """Combines samples from multiple file types."""
        from hashguard.batch_ingest import _mb_get_multi
        # Return different samples per type
        call_count = [0]
        def side_effect(ftype, limit):
            call_count[0] += 1
            return [{"sha256_hash": f"{call_count[0]:064x}"}]
        mock_ft.side_effect = side_effect

        result = _mb_get_multi(3)
        assert len(result) >= 1
        assert mock_ft.call_count >= 1

    @patch("hashguard.batch_ingest._mb_get_by_filetype")
    @patch("hashguard.batch_ingest.time.sleep")
    def test_deduplicates_samples(self, mock_sleep, mock_ft):
        """Duplicate sha256 hashes are removed."""
        from hashguard.batch_ingest import _mb_get_multi
        mock_ft.return_value = [{"sha256_hash": "a" * 64}]
        result = _mb_get_multi(100)
        # All types return same hash, should only appear once
        assert len(result) == 1

    @patch("hashguard.batch_ingest._mb_get_by_filetype")
    @patch("hashguard.batch_ingest.time.sleep")
    def test_stops_at_limit(self, mock_sleep, mock_ft):
        """Stops collecting when limit reached."""
        from hashguard.batch_ingest import _mb_get_multi
        counter = [0]
        def side_effect(ftype, limit):
            counter[0] += 1
            return [{"sha256_hash": f"{counter[0]:064x}"}]
        mock_ft.side_effect = side_effect
        result = _mb_get_multi(2)
        assert len(result) <= 2


class TestStartIngestMixed:
    """Cover mixed source dispatch (line 546)."""

    def setup_method(self):
        batch_ingest._current_job = IngestJob()
        batch_ingest._stop_event.clear()

    def teardown_method(self):
        batch_ingest._current_job = IngestJob()
        batch_ingest._stop_event.clear()

    @patch("hashguard.batch_ingest._run_ingest")
    @patch("hashguard.batch_ingest._mb_get_multi")
    def test_mixed_source(self, mock_multi, mock_run):
        """Mixed source calls _mb_get_multi."""
        mock_multi.return_value = [{"sha256_hash": "a" * 64}]
        result = start_ingest(source="mixed", limit=5)
        assert result["started"] is True
        # Wait for background thread to call the mock
        for _ in range(50):
            if mock_multi.called:
                break
            time.sleep(0.1)
        mock_multi.assert_called_once_with(5)

    @patch("hashguard.batch_ingest._analyse_file_batch")
    @patch("hashguard.batch_ingest._already_in_dataset")
    def test_local_skips_existing(self, mock_exists, mock_analyse):
        mock_exists.return_value = True
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "sample.bin")
            with open(path, "wb") as f:
                f.write(b"\x00" * 100)
            result = start_ingest(source="local", directory=tmpdir, limit=10)
            assert result["started"] is True
            for _ in range(50):
                if get_ingest_status()["status"] != "running":
                    break
                time.sleep(0.1)
            job = get_ingest_status()
            assert job["skipped_existing"] == 1
            mock_analyse.assert_not_called()


class TestRunLocalIngest:
    def setup_method(self):
        batch_ingest._current_job = IngestJob(status="running", started_at=time.time())
        batch_ingest._stop_event.clear()

    def teardown_method(self):
        batch_ingest._current_job = IngestJob()
        batch_ingest._stop_event.clear()

    @patch("hashguard.batch_ingest._analyse_file_batch")
    @patch("hashguard.batch_ingest._already_in_dataset")
    def test_processes_files(self, mock_exists, mock_analyse):
        mock_exists.return_value = False
        mock_analyse.return_value = {"ok": True}
        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(2):
                with open(os.path.join(tmpdir, f"f{i}"), "wb") as f:
                    f.write(os.urandom(64))
            _run_local_ingest(tmpdir, limit=10, delay=0)
        assert batch_ingest._current_job.analysed == 2
        assert batch_ingest._current_job.status == "done"

    @patch("hashguard.batch_ingest._analyse_file_batch")
    @patch("hashguard.batch_ingest._already_in_dataset")
    def test_respects_limit(self, mock_exists, mock_analyse):
        mock_exists.return_value = False
        mock_analyse.return_value = {"ok": True}
        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(10):
                with open(os.path.join(tmpdir, f"f{i}"), "wb") as f:
                    f.write(os.urandom(64))
            _run_local_ingest(tmpdir, limit=3, delay=0)
        assert batch_ingest._current_job.total_candidates == 3

    @patch("hashguard.batch_ingest._analyse_file_batch")
    @patch("hashguard.batch_ingest._already_in_dataset")
    def test_stop_event_halts(self, mock_exists, mock_analyse):
        mock_exists.return_value = False
        batch_ingest._stop_event.set()
        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(5):
                with open(os.path.join(tmpdir, f"f{i}"), "wb") as f:
                    f.write(os.urandom(64))
            _run_local_ingest(tmpdir, limit=100, delay=0)
        assert batch_ingest._current_job.analysed == 0
        assert batch_ingest._current_job.status == "done"

    @patch("hashguard.batch_ingest._analyse_file_batch")
    @patch("hashguard.batch_ingest._already_in_dataset")
    def test_ignores_subdirectories(self, mock_exists, mock_analyse):
        mock_exists.return_value = False
        mock_analyse.return_value = {"ok": True}
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "sample"), "wb") as f:
                f.write(os.urandom(64))
            os.makedirs(os.path.join(tmpdir, "subdir"))
            _run_local_ingest(tmpdir, limit=100, delay=0)
        assert batch_ingest._current_job.total_candidates == 1
