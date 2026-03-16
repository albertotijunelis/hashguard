"""Tests for HashGuard dataset hub router (HuggingFace + Kaggle publishing)."""

import os
import pytest
from unittest.mock import patch, MagicMock


@pytest.fixture(autouse=True)
def _disable_auth():
    old = os.environ.get("HASHGUARD_AUTH")
    os.environ["HASHGUARD_AUTH"] = "0"
    yield
    if old is None:
        os.environ.pop("HASHGUARD_AUTH", None)
    else:
        os.environ["HASHGUARD_AUTH"] = old


@pytest.fixture(autouse=True)
def _clear_hub_env():
    keys = ["HF_TOKEN", "KAGGLE_USERNAME", "KAGGLE_KEY"]
    old = {k: os.environ.get(k) for k in keys}
    for k in keys:
        os.environ.pop(k, None)
    yield
    for k, v in old.items():
        if v is not None:
            os.environ[k] = v
        else:
            os.environ.pop(k, None)


@pytest.fixture
def client():
    with patch("hashguard.web.routers.dataset_hub_router.get_current_user",
               return_value=lambda: {"sub": "admin@test.com", "role": "admin"}):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from hashguard.web.routers.dataset_hub_router import router

        app = FastAPI()
        app.include_router(router)
        with TestClient(app) as tc:
            yield tc


# ── Hub Status ──────────────────────────────────────────────────────────────


class TestHubStatus:
    def test_no_hubs_configured(self, client):
        r = client.get("/api/dataset/hub/status")
        assert r.status_code == 200
        data = r.json()
        assert data["huggingface"] is False
        assert data["kaggle"] is False

    def test_huggingface_configured(self, client):
        os.environ["HF_TOKEN"] = "hf_test_token"
        r = client.get("/api/dataset/hub/status")
        assert r.json()["huggingface"] is True
        assert r.json()["kaggle"] is False

    def test_kaggle_configured(self, client):
        os.environ["KAGGLE_USERNAME"] = "testuser"
        os.environ["KAGGLE_KEY"] = "testkey"
        r = client.get("/api/dataset/hub/status")
        assert r.json()["kaggle"] is True
        assert r.json()["huggingface"] is False

    def test_both_configured(self, client):
        os.environ["HF_TOKEN"] = "hf_test"
        os.environ["KAGGLE_USERNAME"] = "user"
        os.environ["KAGGLE_KEY"] = "key"
        r = client.get("/api/dataset/hub/status")
        assert r.json()["huggingface"] is True
        assert r.json()["kaggle"] is True

    def test_kaggle_partial_not_configured(self, client):
        os.environ["KAGGLE_USERNAME"] = "user"
        r = client.get("/api/dataset/hub/status")
        assert r.json()["kaggle"] is False


# ── HuggingFace Publish ─────────────────────────────────────────────────────


class TestHuggingFacePublish:
    def test_no_token_returns_400(self, client):
        r = client.post("/api/dataset/hub/huggingface/publish?version=1.0.0")
        assert r.status_code == 400
        assert "HF_TOKEN" in r.json()["detail"]

    def test_invalid_version_format(self, client):
        os.environ["HF_TOKEN"] = "hf_test"
        r = client.post("/api/dataset/hub/huggingface/publish?version=invalid")
        assert r.status_code == 422

    def test_version_not_found(self, client):
        os.environ["HF_TOKEN"] = "hf_test"
        with patch("hashguard.database.get_dataset_version_path", return_value=None):
            r = client.post("/api/dataset/hub/huggingface/publish?version=1.0.0")
            assert r.status_code == 404

    def test_successful_publish(self, client):
        os.environ["HF_TOKEN"] = "hf_test"
        mock_api = MagicMock()
        with patch("hashguard.database.get_dataset_version_path", return_value="/tmp/test.parquet"), \
             patch("hashguard.database.list_dataset_versions", return_value=[{"version": "1.0.0", "sample_count": 100, "format": "parquet"}]), \
             patch("huggingface_hub.HfApi", return_value=mock_api):
            r = client.post("/api/dataset/hub/huggingface/publish?version=1.0.0")
            assert r.status_code == 200
            assert r.json()["status"] == "published"
            assert r.json()["hub"] == "huggingface"

    def test_api_error(self, client):
        os.environ["HF_TOKEN"] = "hf_test"
        with patch("hashguard.database.get_dataset_version_path", return_value="/tmp/test.parquet"), \
             patch("hashguard.database.list_dataset_versions", return_value=[]), \
             patch("huggingface_hub.HfApi", side_effect=Exception("API Error")):
            r = client.post("/api/dataset/hub/huggingface/publish?version=1.0.0")
            assert r.status_code == 500

    def test_custom_repo_id(self, client):
        os.environ["HF_TOKEN"] = "hf_test"
        mock_api = MagicMock()
        with patch("hashguard.database.get_dataset_version_path", return_value="/tmp/test.parquet"), \
             patch("hashguard.database.list_dataset_versions", return_value=[]), \
             patch("huggingface_hub.HfApi", return_value=mock_api):
            r = client.post("/api/dataset/hub/huggingface/publish?version=2.0.0&repo_id=custom/repo")
            assert r.status_code == 200

    def test_private_repo(self, client):
        os.environ["HF_TOKEN"] = "hf_test"
        mock_api = MagicMock()
        with patch("hashguard.database.get_dataset_version_path", return_value="/tmp/test.parquet"), \
             patch("hashguard.database.list_dataset_versions", return_value=[]), \
             patch("huggingface_hub.HfApi", return_value=mock_api):
            r = client.post("/api/dataset/hub/huggingface/publish?version=1.0.0&private=true")
            assert r.status_code == 200


# ── Kaggle Publish ──────────────────────────────────────────────────────────


class TestKagglePublish:
    def test_no_credentials_returns_400(self, client):
        r = client.post("/api/dataset/hub/kaggle/publish?version=1.0.0")
        assert r.status_code == 400
        assert "KAGGLE" in r.json()["detail"]

    def test_partial_credentials_returns_400(self, client):
        os.environ["KAGGLE_USERNAME"] = "testuser"
        r = client.post("/api/dataset/hub/kaggle/publish?version=1.0.0")
        assert r.status_code == 400

    def test_invalid_version(self, client):
        os.environ["KAGGLE_USERNAME"] = "user"
        os.environ["KAGGLE_KEY"] = "key"
        r = client.post("/api/dataset/hub/kaggle/publish?version=bad")
        assert r.status_code == 422

    def test_version_not_found(self, client):
        os.environ["KAGGLE_USERNAME"] = "user"
        os.environ["KAGGLE_KEY"] = "key"
        with patch("hashguard.database.get_dataset_version_path", return_value=None):
            r = client.post("/api/dataset/hub/kaggle/publish?version=1.0.0")
            assert r.status_code == 404

    def test_api_error(self, client):
        os.environ["KAGGLE_USERNAME"] = "user"
        os.environ["KAGGLE_KEY"] = "key"
        try:
            import importlib
            kmod = importlib.import_module("kaggle.api.kaggle_api_extended")
        except (ImportError, AttributeError, ModuleNotFoundError):
            pytest.skip("kaggle.api.kaggle_api_extended not accessible")
        # Build a real path under the expected dataset directory
        app_data = os.environ.get("APPDATA") or os.path.expanduser("~")
        fake_path = os.path.join(app_data, "HashGuard", "datasets", "test.csv")
        with patch("hashguard.database.get_dataset_version_path", return_value=fake_path), \
             patch("os.path.isfile", return_value=True), \
             patch("shutil.copy2"), \
             patch.object(kmod, "KaggleApi", side_effect=Exception("Kaggle Error")):
            r = client.post("/api/dataset/hub/kaggle/publish?version=1.0.0")
            assert r.status_code == 500


# ── HF README Builder ──────────────────────────────────────────────────────


class TestBuildHfReadme:
    def test_builds_readme(self):
        from hashguard.web.routers.dataset_hub_router import _build_hf_readme
        ver_info = {"version": "1.0.0", "sample_count": 5000, "malicious_count": 3000,
                    "benign_count": 2000, "feature_count": 120}
        versions = [
            {"version": "1.0.0", "sample_count": 5000, "format": "parquet", "created_at": "2026-01-01T00:00:00"},
        ]
        readme = _build_hf_readme("test/repo", ver_info, versions)
        assert "HashGuard" in readme
        assert "5,000" in readme
        assert "malware" in readme
        assert "test/repo" in readme

    def test_empty_version_info(self):
        from hashguard.web.routers.dataset_hub_router import _build_hf_readme
        readme = _build_hf_readme("test/repo", {}, [])
        assert "HashGuard" in readme

    def test_multiple_versions(self):
        from hashguard.web.routers.dataset_hub_router import _build_hf_readme
        versions = [
            {"version": "1.0.0", "sample_count": 5000, "format": "parquet", "created_at": "2026-01-01"},
            {"version": "2.0.0", "sample_count": 10000, "format": "parquet", "created_at": "2026-03-01"},
        ]
        readme = _build_hf_readme("test/repo", versions[-1], versions)
        assert "1.0.0" in readme
        assert "2.0.0" in readme
