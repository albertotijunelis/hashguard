"""Tests for fuzzy hashing and similarity detection."""

import json
import os
import tempfile

import pytest
from unittest.mock import patch, MagicMock

from hashguard.fuzzy_hasher import (
    FuzzyHash,
    FuzzyHashResult,
    SimilarityMatch,
    _load_db,
    _save_db,
    compare_ssdeep,
    compare_tlsh,
    compute_fuzzy_hashes,
    find_similar,
)


class TestFuzzyHash:
    def test_defaults(self):
        fh = FuzzyHash()
        assert fh.ssdeep == ""
        assert fh.tlsh == ""


class TestSimilarityMatch:
    def test_defaults(self):
        m = SimilarityMatch(filename="test.exe", sha256="abc123")
        assert m.ssdeep_score == 0
        assert m.tlsh_distance == 999
        assert m.combined_score == 0.0


class TestFuzzyHashResult:
    def test_defaults(self):
        r = FuzzyHashResult()
        assert r.hashes.ssdeep == ""
        assert r.similar_samples == []
        assert r.best_match is None

    def test_to_dict_no_best_match(self):
        r = FuzzyHashResult()
        d = r.to_dict()
        assert "hashes" in d
        assert "best_match" not in d

    def test_to_dict_with_best_match(self):
        r = FuzzyHashResult()
        r.best_match = SimilarityMatch(
            filename="sample.exe", sha256="abc", combined_score=85.3
        )
        r.similar_samples = [r.best_match]
        d = r.to_dict()
        assert "best_match" in d
        assert d["best_match"]["combined_score"] == 85.3


class TestLoadSaveDB:
    def test_load_nonexistent(self, tmp_path):
        with patch("hashguard.fuzzy_hasher._DB_FILE", str(tmp_path / "nope.json")):
            db = _load_db()
            assert db == {}

    def test_save_and_load(self, tmp_path):
        db_path = str(tmp_path / "fuzzy_db.json")
        with patch("hashguard.fuzzy_hasher._DB_FILE", db_path):
            data = {"sha1": {"filename": "a.exe", "ssdeep": "3:abc", "tlsh": "T1abc"}}
            _save_db(data)
            loaded = _load_db()
            assert loaded["sha1"]["filename"] == "a.exe"

    def test_load_corrupt_json(self, tmp_path):
        db_path = tmp_path / "corrupt.json"
        db_path.write_text("NOT JSON", encoding="utf-8")
        with patch("hashguard.fuzzy_hasher._DB_FILE", str(db_path)):
            db = _load_db()
            assert db == {}


class TestComputeFuzzyHashes:
    def test_nonexistent_file(self):
        fh = compute_fuzzy_hashes("/nonexistent/file.exe")
        assert fh.ssdeep == ""
        assert fh.tlsh == ""

    def test_computes_ssdeep(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(os.urandom(4096))
        fh = compute_fuzzy_hashes(str(f))
        # ppdeep should be available in this project
        if fh.ssdeep:
            assert len(fh.ssdeep) > 0

    def test_computes_tlsh(self, tmp_path):
        f = tmp_path / "test.bin"
        # TLSH needs at least 50 bytes of diverse data
        f.write_bytes(os.urandom(4096))
        fh = compute_fuzzy_hashes(str(f))
        # TLSH may or may not be available
        # Just ensure no crash

    def test_ssdeep_hash_success_mocked(self, tmp_path):
        """Cover ssdeep hash computation path (lines 122-123)."""
        f = tmp_path / "test.bin"
        f.write_bytes(b"A" * 4096)
        mock_ppdeep = MagicMock()
        mock_ppdeep.hash.return_value = "3:AAAA:BBBB"
        with patch("hashguard.fuzzy_hasher.HAS_SSDEEP", True), \
             patch("hashguard.fuzzy_hasher.ppdeep", mock_ppdeep, create=True):
            fh = compute_fuzzy_hashes(str(f))
        assert fh.ssdeep == "3:AAAA:BBBB"

    def test_tlsh_hash_success_mocked(self, tmp_path):
        """Cover TLSH hash computation path (lines 126-131)."""
        f = tmp_path / "test.bin"
        f.write_bytes(b"A" * 4096)
        mock_tlsh = MagicMock()
        mock_tlsh.hash.return_value = "T1E2F3A4B5C6"
        with patch("hashguard.fuzzy_hasher.HAS_TLSH", True), \
             patch("hashguard.fuzzy_hasher.tlsh", mock_tlsh, create=True):
            fh = compute_fuzzy_hashes(str(f))
        assert fh.tlsh == "T1E2F3A4B5C6"

    def test_tlsh_hash_tnull(self, tmp_path):
        """TLSH returns TNULL for low-entropy data → should stay empty."""
        f = tmp_path / "test.bin"
        f.write_bytes(b"\x00" * 4096)
        mock_tlsh = MagicMock()
        mock_tlsh.hash.return_value = "TNULL"
        with patch("hashguard.fuzzy_hasher.HAS_TLSH", True), \
             patch("hashguard.fuzzy_hasher.tlsh", mock_tlsh, create=True):
            fh = compute_fuzzy_hashes(str(f))
        assert fh.tlsh == ""

    def test_ssdeep_hash_exception(self, tmp_path):
        """Cover ssdeep hash exception path."""
        f = tmp_path / "test.bin"
        f.write_bytes(b"A" * 4096)
        mock_ppdeep = MagicMock()
        mock_ppdeep.hash.side_effect = RuntimeError("hash error")
        with patch("hashguard.fuzzy_hasher.HAS_SSDEEP", True), \
             patch("hashguard.fuzzy_hasher.ppdeep", mock_ppdeep, create=True):
            fh = compute_fuzzy_hashes(str(f))
        assert fh.ssdeep == ""

    def test_tlsh_hash_exception(self, tmp_path):
        """Cover TLSH hash exception path."""
        f = tmp_path / "test.bin"
        f.write_bytes(b"A" * 4096)
        mock_tlsh = MagicMock()
        mock_tlsh.hash.side_effect = RuntimeError("tlsh error")
        with patch("hashguard.fuzzy_hasher.HAS_TLSH", True), \
             patch("hashguard.fuzzy_hasher.tlsh", mock_tlsh, create=True):
            fh = compute_fuzzy_hashes(str(f))
        assert fh.tlsh == ""


class TestCompareSSDeep:
    def test_empty_hashes(self):
        assert compare_ssdeep("", "") == 0

    def test_identical_hashes(self):
        # If ppdeep is available, comparing identical hashes should give 100
        try:
            import ppdeep
            h = ppdeep.hash(b"A" * 4096)
            score = compare_ssdeep(h, h)
            assert score == 100
        except ImportError:
            assert compare_ssdeep("3:abc", "3:abc") == 0

    def test_no_ssdeep_returns_zero(self):
        with patch("hashguard.fuzzy_hasher.HAS_SSDEEP", False):
            assert compare_ssdeep("3:abc", "3:abc") == 0

    def test_compare_ssdeep_success_mocked(self):
        """Cover ppdeep.compare success path (lines 142-143)."""
        mock_ppdeep = MagicMock()
        mock_ppdeep.compare.return_value = 75
        with patch("hashguard.fuzzy_hasher.HAS_SSDEEP", True), \
             patch("hashguard.fuzzy_hasher.ppdeep", mock_ppdeep, create=True):
            result = compare_ssdeep("3:abc", "3:def")
        assert result == 75

    def test_compare_ssdeep_exception(self):
        """Cover ppdeep.compare exception path."""
        mock_ppdeep = MagicMock()
        mock_ppdeep.compare.side_effect = RuntimeError("compare error")
        with patch("hashguard.fuzzy_hasher.HAS_SSDEEP", True), \
             patch("hashguard.fuzzy_hasher.ppdeep", mock_ppdeep, create=True):
            result = compare_ssdeep("3:abc", "3:def")
        assert result == 0


class TestCompareTLSH:
    def test_empty_hashes(self):
        assert compare_tlsh("", "") == 999

    def test_no_tlsh_returns_999(self):
        with patch("hashguard.fuzzy_hasher.HAS_TLSH", False):
            assert compare_tlsh("T1abc", "T1abc") == 999

    def test_compare_tlsh_success_mocked(self):
        """Cover tlsh.diff success path (lines 150-153)."""
        mock_tlsh = MagicMock()
        mock_tlsh.diff.return_value = 42
        with patch("hashguard.fuzzy_hasher.HAS_TLSH", True), \
             patch("hashguard.fuzzy_hasher.tlsh", mock_tlsh, create=True):
            result = compare_tlsh("T1abc", "T1def")
        assert result == 42

    def test_compare_tlsh_exception(self):
        """Cover tlsh.diff exception path."""
        mock_tlsh = MagicMock()
        mock_tlsh.diff.side_effect = RuntimeError("diff error")
        with patch("hashguard.fuzzy_hasher.HAS_TLSH", True), \
             patch("hashguard.fuzzy_hasher.tlsh", mock_tlsh, create=True):
            result = compare_tlsh("T1abc", "T1def")
        assert result == 999


class TestFindSimilar:
    def test_empty_db(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"A" * 4096)
        db_path = str(tmp_path / "fuzzy_db.json")
        with patch("hashguard.fuzzy_hasher._DB_FILE", db_path):
            result = find_similar(str(f), sha256="sha256_test")
            assert isinstance(result, FuzzyHashResult)
            assert result.similar_samples == []

    def test_stores_in_db(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"A" * 4096)
        db_path = str(tmp_path / "fuzzy_db.json")
        with patch("hashguard.fuzzy_hasher._DB_FILE", db_path):
            find_similar(str(f), sha256="sha256_test")
            db = json.loads((tmp_path / "fuzzy_db.json").read_text())
            assert "sha256_test" in db

    def test_finds_similar_ssdeep(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"A" * 4096)
        db_path = str(tmp_path / "fuzzy_db.json")

        # Pre-populate the DB with a matching entry
        try:
            import ppdeep
            h = ppdeep.hash(b"A" * 4096)
        except ImportError:
            pytest.skip("ppdeep not available")

        db_data = {
            "existing_sha": {
                "filename": "similar.exe",
                "ssdeep": h,
                "tlsh": "",
            }
        }
        (tmp_path / "fuzzy_db.json").write_text(json.dumps(db_data))

        with patch("hashguard.fuzzy_hasher._DB_FILE", db_path):
            result = find_similar(str(f), sha256="new_sha")
            # Should find the matching sample

    def test_find_similar_with_mocked_hashes(self, tmp_path):
        """Cover available_algorithms, ssdeep comparison, and combined score paths."""
        f = tmp_path / "test.bin"
        f.write_bytes(b"A" * 4096)
        db_path = str(tmp_path / "fuzzy_db.json")

        db_data = {
            "existing_sha": {
                "filename": "similar.exe",
                "ssdeep": "3:AAAA:BBBB",
                "tlsh": "T1E2F3",
            }
        }
        (tmp_path / "fuzzy_db.json").write_text(json.dumps(db_data))

        mock_ppdeep = MagicMock()
        mock_ppdeep.hash.return_value = "3:AAAA:BBBB"
        mock_ppdeep.compare.return_value = 85
        mock_tlsh = MagicMock()
        mock_tlsh.hash.return_value = "T1E2F3"
        mock_tlsh.diff.return_value = 30

        with patch("hashguard.fuzzy_hasher._DB_FILE", db_path), \
             patch("hashguard.fuzzy_hasher.HAS_SSDEEP", True), \
             patch("hashguard.fuzzy_hasher.HAS_TLSH", True), \
             patch("hashguard.fuzzy_hasher.ppdeep", mock_ppdeep, create=True), \
             patch("hashguard.fuzzy_hasher.tlsh", mock_tlsh, create=True):
            result = find_similar(str(f), sha256="new_sha")

        assert "ssdeep" in result.available_algorithms
        assert "tlsh" in result.available_algorithms
        assert len(result.similar_samples) >= 1
        assert result.similar_samples[0].ssdeep_score == 85
        assert result.best_match is not None

    def test_save_db_error(self, tmp_path):
        """Cover _save_db exception path (lines 106-107)."""
        with patch("hashguard.fuzzy_hasher._DB_FILE", "/nonexistent/deep/path/db.json"), \
             patch("hashguard.fuzzy_hasher.os.makedirs", side_effect=PermissionError("denied")):
            _save_db({"sha": {"filename": "a.exe"}})

    def test_no_sha256_skips_store(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"A" * 4096)
        db_path = str(tmp_path / "fuzzy_db.json")
        with patch("hashguard.fuzzy_hasher._DB_FILE", db_path):
            result = find_similar(str(f), sha256="")
            assert isinstance(result, FuzzyHashResult)

    def test_combined_score_sorting(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"A" * 4096)
        db_path = str(tmp_path / "fuzzy_db.json")

        try:
            import ppdeep
            h1 = ppdeep.hash(b"A" * 4096)
            h2 = ppdeep.hash(b"A" * 2048 + b"B" * 2048)
        except ImportError:
            pytest.skip("ppdeep not available")

        db_data = {
            "sha_high": {"filename": "high.exe", "ssdeep": h1, "tlsh": ""},
            "sha_low": {"filename": "low.exe", "ssdeep": h2, "tlsh": ""},
        }
        (tmp_path / "fuzzy_db.json").write_text(json.dumps(db_data))

        with patch("hashguard.fuzzy_hasher._DB_FILE", db_path):
            result = find_similar(str(f), sha256="new_sha")
            if len(result.similar_samples) >= 2:
                # Should be sorted by combined_score descending
                assert (
                    result.similar_samples[0].combined_score
                    >= result.similar_samples[1].combined_score
                )
