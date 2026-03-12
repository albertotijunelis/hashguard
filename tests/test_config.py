"""Tests for HashGuard configuration module."""

import json
import os
import sys

import pytest

from hashguard.config import HashGuardConfig, get_default_config, _default_signatures_path


class TestDefaultSignaturesPath:
    def test_returns_string(self):
        path = _default_signatures_path()
        assert isinstance(path, str)
        assert "signatures.json" in path

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("HASHGUARD_SIGNATURES", "/custom/sigs.json")
        assert _default_signatures_path() == "/custom/sigs.json"

    def test_meipass_frozen(self, monkeypatch):
        monkeypatch.delenv("HASHGUARD_SIGNATURES", raising=False)
        monkeypatch.setattr("sys._MEIPASS", "/frozen/app", raising=False)
        result = _default_signatures_path()
        assert "signatures.json" in result

    def test_pkg_data_not_found(self, monkeypatch, tmp_path):
        monkeypatch.delenv("HASHGUARD_SIGNATURES", raising=False)
        if hasattr(sys, "_MEIPASS"):
            monkeypatch.delattr("sys._MEIPASS")
        # When the pkg data path doesn't exist, should fall back to project root
        import hashguard.config as config_mod
        orig = config_mod.__file__
        monkeypatch.setattr(config_mod, "__file__", str(tmp_path / "config.py"))
        result = _default_signatures_path()
        assert "signatures.json" in result
        monkeypatch.setattr(config_mod, "__file__", orig)


class TestHashGuardConfig:
    def test_defaults(self):
        cfg = HashGuardConfig()
        assert cfg.chunk_size == 65536
        assert cfg.max_file_size == 0
        assert cfg.log_level == "INFO"
        assert "md5" in cfg.hash_algorithms
        assert "sha256" in cfg.hash_algorithms

    def test_to_dict_redacts_key(self):
        cfg = HashGuardConfig(vt_api_key="secret123")
        d = cfg.to_dict()
        assert d["vt_api_key"] == "***REDACTED***"

    def test_to_dict_no_key(self):
        cfg = HashGuardConfig(vt_api_key=None)
        d = cfg.to_dict()
        assert d["vt_api_key"] is None

    def test_to_dict_abuse_ch_key_redacted(self):
        cfg = HashGuardConfig(abuse_ch_api_key="secretkey")
        d = cfg.to_dict()
        assert d["abuse_ch_api_key"] == "***REDACTED***"

    def test_to_dict_abuse_ch_key_none(self):
        cfg = HashGuardConfig(abuse_ch_api_key=None)
        d = cfg.to_dict()
        assert d["abuse_ch_api_key"] is None

    def test_from_file_nonexistent(self, tmp_path):
        cfg = HashGuardConfig.from_file(str(tmp_path / "nope.json"))
        assert cfg.chunk_size == 65536  # defaults

    def test_from_file_valid(self, tmp_path):
        path = tmp_path / "config.json"
        path.write_text(json.dumps({"chunk_size": 131072, "log_level": "DEBUG"}))
        cfg = HashGuardConfig.from_file(str(path))
        assert cfg.chunk_size == 131072
        assert cfg.log_level == "DEBUG"

    def test_from_file_ignores_unknown_keys(self, tmp_path):
        path = tmp_path / "config.json"
        path.write_text(json.dumps({"chunk_size": 4096, "unknown_field": True}))
        cfg = HashGuardConfig.from_file(str(path))
        assert cfg.chunk_size == 4096
        assert not hasattr(cfg, "unknown_field")

    def test_from_file_invalid_json(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("not valid json {{{")
        cfg = HashGuardConfig.from_file(str(path))
        assert cfg.chunk_size == 65536  # falls back to defaults

    def test_save_and_load(self, tmp_path):
        path = str(tmp_path / "out.json")
        cfg = HashGuardConfig(chunk_size=1024, log_level="WARNING", vt_api_key="secret")
        cfg.save(path)
        loaded = HashGuardConfig.from_file(path)
        assert loaded.chunk_size == 1024
        assert loaded.log_level == "WARNING"
        # API key must not be persisted
        with open(path) as f:
            data = json.load(f)
        assert "vt_api_key" not in data

    def test_save_creates_directory(self, tmp_path):
        path = str(tmp_path / "sub" / "dir" / "config.json")
        cfg = HashGuardConfig()
        cfg.save(path)
        assert os.path.exists(path)


class TestGetDefaultConfig:
    def test_returns_config(self):
        cfg = get_default_config()
        assert isinstance(cfg, HashGuardConfig)
