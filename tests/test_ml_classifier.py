"""Tests for ML classifier module."""

import math
from unittest.mock import patch, MagicMock, PropertyMock
from dataclasses import fields

import pytest

from hashguard.ml_classifier import (
    MLClassification,
    _entropy,
    CLASSES,
    FEATURE_NAMES,
    CRYPTO_APIS,
    NETWORK_APIS,
    INJECTION_APIS,
    SUSPICIOUS_APIS,
)


# ── Dataclass tests ──────────────────────────────────────────────────────────


class TestMLClassification:
    def test_defaults(self):
        c = MLClassification()
        assert c.predicted_class == "unknown"
        assert c.confidence == 0.0
        assert c.is_anomaly is False
        assert c.features_used == 0

    def test_to_dict(self):
        c = MLClassification(
            predicted_class="trojan",
            confidence=0.85,
            probabilities={"trojan": 0.85, "benign": 0.1},
            anomaly_score=-0.123,
            is_anomaly=False,
            features_used=22,
        )
        d = c.to_dict()
        assert d["predicted_class"] == "trojan"
        assert d["confidence"] == 85.0
        assert d["probabilities"]["trojan"] == 85.0
        assert d["anomaly_score"] == -0.123
        assert d["features_used"] == 22

    def test_to_dict_empty_probabilities(self):
        c = MLClassification()
        d = c.to_dict()
        assert d["probabilities"] == {}


# ── Entropy tests ────────────────────────────────────────────────────────────


class TestEntropy:
    def test_empty(self):
        assert _entropy(b"") == 0.0

    def test_single_byte_repeated(self):
        assert _entropy(b"\x00" * 100) == 0.0

    def test_two_equal_bytes(self):
        val = _entropy(b"\x00\xff" * 50)
        assert abs(val - 1.0) < 0.01

    def test_high_entropy(self):
        data = bytes(range(256)) * 10
        val = _entropy(data)
        assert val > 7.9

    def test_low_entropy(self):
        data = b"\x00" * 90 + b"\x01" * 10
        val = _entropy(data)
        assert val < 1.0


# ── Constants tests ──────────────────────────────────────────────────────────


class TestConstants:
    def test_classes_list(self):
        assert "benign" in CLASSES
        assert "trojan" in CLASSES
        assert "ransomware" in CLASSES
        assert len(CLASSES) == 5

    def test_feature_names_count(self):
        assert len(FEATURE_NAMES) == 22

    def test_suspicious_apis_is_union(self):
        assert CRYPTO_APIS.issubset(SUSPICIOUS_APIS)
        assert NETWORK_APIS.issubset(SUSPICIOUS_APIS)
        assert INJECTION_APIS.issubset(SUSPICIOUS_APIS)


# ── Extract features tests ───────────────────────────────────────────────────


class TestExtractFeatures:
    def test_non_pe_returns_none(self, tmp_path):
        p = tmp_path / "test.txt"
        p.write_bytes(b"Hello, this is not a PE file")
        from hashguard.ml_classifier import extract_features

        assert extract_features(str(p)) is None

    def test_missing_file(self):
        from hashguard.ml_classifier import extract_features

        assert extract_features("/no/such/file.exe") is None


# ── Model building tests ─────────────────────────────────────────────────────


class TestBuildModel:
    """Test synthetic model building (no real dataset needed)."""

    def test_build_correlated_samples_shape(self):
        try:
            import numpy as np
            from hashguard.ml_classifier import _build_correlated_samples
        except ImportError:
            pytest.skip("numpy/sklearn not available")

        rng = np.random.RandomState(42)
        samples = _build_correlated_samples("benign", 100, rng)
        assert samples.shape == (100, 22)

    def test_build_correlated_samples_clamped(self):
        try:
            import numpy as np
            from hashguard.ml_classifier import _build_correlated_samples
        except ImportError:
            pytest.skip("numpy/sklearn not available")

        rng = np.random.RandomState(42)
        for cls_name in CLASSES:
            samples = _build_correlated_samples(cls_name, 200, rng)
            # Entropy features should be in [0, 8]
            for idx in [1, 2, 3, 21]:
                assert samples[:, idx].min() >= 0.0
                assert samples[:, idx].max() <= 8.0
            # Binary features should be 0 or 1
            for idx in [8, 9, 10, 11, 12, 13, 14, 15, 16, 20]:
                uniques = set(samples[:, idx].tolist())
                assert uniques.issubset({0.0, 1.0})
            # Ratio features in [0, 1]
            assert samples[:, 7].min() >= 0.0
            assert samples[:, 7].max() <= 1.0

    def test_build_model_returns_ensemble(self):
        try:
            import numpy as np
            from hashguard.ml_classifier import _build_model
        except ImportError:
            pytest.skip("numpy/sklearn not available")

        with patch("hashguard.ml_classifier._load_real_dataset", return_value=None):
            clf, scaler, iso = _build_model()
            assert clf is not None
            assert scaler is not None
            assert iso is not None


# ── Classify tests ───────────────────────────────────────────────────────────


class TestClassify:
    def test_classify_non_pe(self, tmp_path):
        from hashguard.ml_classifier import classify

        p = tmp_path / "test.txt"
        p.write_bytes(b"Not a PE file")
        result = classify(str(p))
        assert result.predicted_class == "unknown"

    def test_classify_missing_file(self):
        from hashguard.ml_classifier import classify

        result = classify("/no/such/file.exe")
        assert result.predicted_class == "unknown"


# ── HMAC integrity tests ────────────────────────────────────────────────────


class TestModelIntegrity:
    def test_compute_file_hmac(self, tmp_path):
        from hashguard.ml_classifier import _compute_file_hmac

        p = tmp_path / "test.bin"
        p.write_bytes(b"test data")
        h1 = _compute_file_hmac(str(p))
        h2 = _compute_file_hmac(str(p))
        assert h1 == h2
        assert len(h1) == 64  # SHA256 hex

    def test_hmac_changes_with_content(self, tmp_path):
        from hashguard.ml_classifier import _compute_file_hmac

        p = tmp_path / "test.bin"
        p.write_bytes(b"data version 1")
        h1 = _compute_file_hmac(str(p))
        p.write_bytes(b"data version 2")
        h2 = _compute_file_hmac(str(p))
        assert h1 != h2


# ── Dataset loading tests ───────────────────────────────────────────────────


class TestLoadRealDataset:
    def test_no_dataset_returns_none(self, tmp_path, monkeypatch):
        try:
            from hashguard.ml_classifier import _load_real_dataset
        except ImportError:
            pytest.skip("numpy/sklearn not available")

        monkeypatch.setattr("hashguard.ml_classifier.DATASET_DIR", str(tmp_path))
        assert _load_real_dataset() is None

    def test_csv_dataset_loads(self, tmp_path, monkeypatch):
        try:
            import numpy as np
            from hashguard.ml_classifier import _load_real_dataset
        except ImportError:
            pytest.skip("numpy/sklearn not available")

        monkeypatch.setattr("hashguard.ml_classifier.DATASET_DIR", str(tmp_path))

        # Create a CSV with 60 rows (above the 50 minimum)
        header = ",".join(FEATURE_NAMES) + ",label\n"
        rows = []
        for i in range(60):
            vals = [str(float(i % 5 + j * 0.1)) for j in range(22)]
            rows.append(",".join(vals) + f",{CLASSES[i % 5]}\n")

        csv_path = tmp_path / "dataset.csv"
        csv_path.write_text(header + "".join(rows))

        result = _load_real_dataset()
        assert result is not None
        X, y = result
        assert X.shape == (60, 22)
        assert len(y) == 60

    def test_json_dataset_loads(self, tmp_path, monkeypatch):
        try:
            import json
            import numpy as np
            from hashguard.ml_classifier import _load_real_dataset
        except ImportError:
            pytest.skip("numpy/sklearn not available")

        monkeypatch.setattr("hashguard.ml_classifier.DATASET_DIR", str(tmp_path))

        data = []
        for i in range(60):
            row = {name: float(i % 5 + j * 0.1) for j, name in enumerate(FEATURE_NAMES)}
            row["label"] = CLASSES[i % 5]
            data.append(row)

        json_path = tmp_path / "dataset.json"
        json_path.write_text(json.dumps(data))

        result = _load_real_dataset()
        assert result is not None
        X, y = result
        assert X.shape == (60, 22)


# ── _get_or_build_model tests ───────────────────────────────────────────────


class TestGetOrBuildModel:
    def test_builds_when_no_cache(self, tmp_path, monkeypatch):
        try:
            from hashguard.ml_classifier import _get_or_build_model, MODEL_VERSION
        except ImportError:
            pytest.skip("ML deps not available")

        monkeypatch.setattr("hashguard.ml_classifier.MODEL_DIR", str(tmp_path))
        monkeypatch.setattr("hashguard.ml_classifier.MODEL_PATH", str(tmp_path / "model.pkl"))
        monkeypatch.setattr("hashguard.ml_classifier._MODEL_HMAC_PATH", str(tmp_path / "model.pkl.hmac"))
        monkeypatch.setattr("hashguard.ml_classifier.DATASET_DIR", str(tmp_path / "datasets"))

        clf, scaler, iso = _get_or_build_model()
        assert clf is not None
        assert scaler is not None
        assert iso is not None
        # Should have saved to disk
        assert (tmp_path / "model.pkl").exists()
        assert (tmp_path / "model.pkl.hmac").exists()

    def test_loads_from_cache(self, tmp_path, monkeypatch):
        try:
            import pickle
            from hashguard.ml_classifier import (
                _get_or_build_model,
                _build_model,
                _compute_file_hmac,
                MODEL_VERSION,
            )
        except ImportError:
            pytest.skip("ML deps not available")

        model_path = str(tmp_path / "model.pkl")
        hmac_path = model_path + ".hmac"
        monkeypatch.setattr("hashguard.ml_classifier.MODEL_DIR", str(tmp_path))
        monkeypatch.setattr("hashguard.ml_classifier.MODEL_PATH", model_path)
        monkeypatch.setattr("hashguard.ml_classifier._MODEL_HMAC_PATH", hmac_path)
        monkeypatch.setattr("hashguard.ml_classifier.DATASET_DIR", str(tmp_path / "datasets"))

        # Build and save first
        with patch("hashguard.ml_classifier._load_real_dataset", return_value=None):
            clf, scaler, iso = _build_model()
        with open(model_path, "wb") as f:
            pickle.dump({"clf": clf, "scaler": scaler, "iso": iso, "version": MODEL_VERSION}, f)
        from pathlib import Path
        Path(hmac_path).write_text(_compute_file_hmac(model_path))

        # Should load from cache without rebuilding
        clf2, scaler2, iso2 = _get_or_build_model()
        assert clf2 is not None

    def test_integrity_failure_rebuilds(self, tmp_path, monkeypatch):
        try:
            import pickle
            from hashguard.ml_classifier import _get_or_build_model, _build_model, MODEL_VERSION
        except ImportError:
            pytest.skip("ML deps not available")

        model_path = str(tmp_path / "model.pkl")
        hmac_path = model_path + ".hmac"
        monkeypatch.setattr("hashguard.ml_classifier.MODEL_DIR", str(tmp_path))
        monkeypatch.setattr("hashguard.ml_classifier.MODEL_PATH", model_path)
        monkeypatch.setattr("hashguard.ml_classifier._MODEL_HMAC_PATH", hmac_path)
        monkeypatch.setattr("hashguard.ml_classifier.DATASET_DIR", str(tmp_path / "datasets"))

        # Write model with wrong HMAC
        with patch("hashguard.ml_classifier._load_real_dataset", return_value=None):
            clf, scaler, iso = _build_model()
        with open(model_path, "wb") as f:
            pickle.dump({"clf": clf, "scaler": scaler, "iso": iso, "version": MODEL_VERSION}, f)
        from pathlib import Path
        Path(hmac_path).write_text("wrong_hmac_value")

        # Should rebuild due to HMAC mismatch
        clf2, scaler2, iso2 = _get_or_build_model()
        assert clf2 is not None

    def test_no_ml_returns_none(self, monkeypatch):
        from hashguard.ml_classifier import _get_or_build_model
        monkeypatch.setattr("hashguard.ml_classifier.HAS_ML", False)
        clf, scaler, iso = _get_or_build_model()
        assert clf is None
        assert scaler is None
        assert iso is None


# ── classify integration tests ───────────────────────────────────────────────


class TestClassifyIntegration:
    def test_classify_with_no_ml(self, monkeypatch):
        from hashguard.ml_classifier import classify
        monkeypatch.setattr("hashguard.ml_classifier.HAS_ML", False)
        result = classify("test.exe")
        assert result.predicted_class == "unknown"

    def test_classify_with_mocked_model(self, tmp_path, monkeypatch):
        try:
            import numpy as np
            from hashguard.ml_classifier import classify, CLASSES
        except ImportError:
            pytest.skip("ML deps not available")

        mock_features = [1.0] * 22
        monkeypatch.setattr("hashguard.ml_classifier.extract_features",
                            lambda *a, **kw: mock_features)

        # Mock the model
        mock_clf = MagicMock()
        mock_clf.predict_proba.return_value = np.array([[0.05, 0.7, 0.1, 0.1, 0.05]])
        mock_scaler = MagicMock()
        mock_scaler.transform.return_value = np.array([mock_features])
        mock_iso = MagicMock()
        mock_iso.predict.return_value = np.array([1])
        mock_iso.score_samples.return_value = np.array([0.1])

        monkeypatch.setattr("hashguard.ml_classifier._get_or_build_model",
                            lambda: (mock_clf, mock_scaler, mock_iso))

        result = classify("test.exe")
        assert result.predicted_class == "trojan"
        assert result.confidence > 0.5
        assert result.features_used == 22
        assert result.is_anomaly is False


class TestExtractFeaturesWithMockedPE:
    """Tests for extract_features with mocked pefile."""

    def test_no_pefile(self):
        from hashguard import ml_classifier
        with patch.object(ml_classifier, "HAS_PEFILE", False):
            result = ml_classifier.extract_features("/fake/path")
            assert result is None

    def test_pefile_success(self, tmp_path):
        from hashguard import ml_classifier
        try:
            import pefile as pf
        except ImportError:
            pytest.skip("pefile not available")

        # Create a real temp file for os.path.getsize / open to work
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"\x00" * 5000)

        with patch.object(ml_classifier, "HAS_PEFILE", True):
            mock_sec = MagicMock()
            mock_sec.Name = b".text\x00\x00\x00"
            mock_sec.SizeOfRawData = 1000
            mock_sec.Misc_VirtualSize = 1000
            mock_sec.get_data.return_value = b"\x00" * 1000
            mock_sec.get_entropy.return_value = 5.5
            mock_sec.Characteristics = 0xA0000020  # EXEC | WRITE

            mock_imp = MagicMock()
            mock_imp.name = b"CreateFileA"
            mock_entry = MagicMock()
            mock_entry.imports = [mock_imp]

            mock_pe = MagicMock()
            mock_pe.sections = [mock_sec]
            mock_pe.DIRECTORY_ENTRY_IMPORT = [mock_entry]
            mock_pe.get_overlay_data_start_offset.return_value = None
            # Ensure hasattr checks work
            del mock_pe.DIRECTORY_ENTRY_TLS
            del mock_pe.DIRECTORY_ENTRY_COM_DESCRIPTOR
            del mock_pe.DIRECTORY_ENTRY_RESOURCE

            with patch("hashguard.ml_classifier.pefile") as mock_pefile:
                mock_pefile.PE.return_value = mock_pe
                mock_pefile.DIRECTORY_ENTRY = {"IMAGE_DIRECTORY_ENTRY_IMPORT": 1}
                result = ml_classifier.extract_features(str(test_file))
                assert result is not None
                assert len(result) == 22
                assert result[0] > 0  # file_size_log
                assert result[4] == 1  # section_count
                assert result[10] == 1.0  # has_file_imports (CreateFileA)

    def test_pefile_with_resources(self, tmp_path):
        """Test extract_features with resource entries."""
        from hashguard import ml_classifier
        try:
            import pefile as pf
        except ImportError:
            pytest.skip("pefile not available")

        test_file = tmp_path / "test_res.exe"
        test_file.write_bytes(b"\x00" * 2000)

        with patch.object(ml_classifier, "HAS_PEFILE", True):
            mock_sec = MagicMock()
            mock_sec.get_entropy.return_value = 3.0
            mock_sec.Characteristics = 0x40000000  # READ only

            # Build resource tree
            mock_e3 = MagicMock()
            mock_e3.data.struct.OffsetToData = 0x100
            mock_e3.data.struct.Size = 100
            mock_e2 = MagicMock()
            mock_e2.directory.entries = [mock_e3]
            mock_e1 = MagicMock()
            mock_e1.directory.entries = [mock_e2]
            mock_res = MagicMock()
            mock_res.entries = [mock_e1]

            mock_pe = MagicMock()
            mock_pe.sections = [mock_sec]
            mock_pe.DIRECTORY_ENTRY_RESOURCE = mock_res
            mock_pe.get_overlay_data_start_offset.return_value = 1500
            mock_pe.get_data.return_value = b"\xAA" * 100
            del mock_pe.DIRECTORY_ENTRY_TLS
            del mock_pe.DIRECTORY_ENTRY_COM_DESCRIPTOR

            with patch("hashguard.ml_classifier.pefile") as mock_pefile:
                mock_pefile.PE.return_value = mock_pe
                mock_pefile.DIRECTORY_ENTRY = {"IMAGE_DIRECTORY_ENTRY_IMPORT": 1}
                result = ml_classifier.extract_features(str(test_file))
                assert result is not None
                assert result[16] == 1.0  # has_overlay
                assert result[17] > 0  # overlay_ratio

    def test_pefile_with_high_entropy(self, tmp_path):
        """Test packed detection (high entropy + few imports)."""
        from hashguard import ml_classifier

        test_file = tmp_path / "packed.exe"
        # Create high-entropy data
        import os
        test_file.write_bytes(os.urandom(5000))

        with patch.object(ml_classifier, "HAS_PEFILE", True):
            mock_sec = MagicMock()
            mock_sec.get_entropy.return_value = 7.5
            mock_sec.Characteristics = 0x60000020  # EXEC | READ

            mock_pe = MagicMock()
            mock_pe.sections = [mock_sec]
            mock_pe.get_overlay_data_start_offset.return_value = None
            del mock_pe.DIRECTORY_ENTRY_IMPORT
            del mock_pe.DIRECTORY_ENTRY_TLS
            del mock_pe.DIRECTORY_ENTRY_COM_DESCRIPTOR
            del mock_pe.DIRECTORY_ENTRY_RESOURCE

            with patch("hashguard.ml_classifier.pefile") as mock_pefile:
                mock_pefile.PE.return_value = mock_pe
                mock_pefile.DIRECTORY_ENTRY = {"IMAGE_DIRECTORY_ENTRY_IMPORT": 1}
                result = ml_classifier.extract_features(str(test_file))
                assert result is not None
                assert result[19] >= 1  # high_entropy_sections

    def test_pefile_parse_error(self):
        from hashguard import ml_classifier
        with patch.object(ml_classifier, "HAS_PEFILE", True):
            mock_pefile = MagicMock()
            mock_pefile.PE.side_effect = Exception("corrupted PE")
            mock_pefile.PEFormatError = type("PEFormatError", (Exception,), {})
            with patch("hashguard.ml_classifier.pefile", mock_pefile):
                result = ml_classifier.extract_features("/fake/path")
                assert result is None


class TestExtractFeaturesLief:
    """Tests for extract_features_lief."""

    def test_no_lief(self):
        from hashguard import ml_classifier
        with patch.object(ml_classifier, "HAS_LIEF", False):
            result = ml_classifier.extract_features_lief("/fake/path")
            assert result is None

    def test_lief_parse_failure(self):
        from hashguard import ml_classifier
        with patch.object(ml_classifier, "HAS_LIEF", True):
            mock_lief = MagicMock()
            mock_lief.parse.return_value = None
            with patch.dict("sys.modules", {"lief": mock_lief}):
                with patch.object(ml_classifier, "lief", mock_lief, create=True):
                    result = ml_classifier.extract_features_lief("/fake/path")
                    assert result is None

    def test_lief_full_extraction(self, tmp_path):
        """Test extract_features_lief with full mocked LIEF binary."""
        from hashguard import ml_classifier

        test_file = tmp_path / "test_lief.exe"
        test_file.write_bytes(b"\x00" * 3000)

        # Mock section
        mock_sec = MagicMock()
        mock_sec.entropy = 5.5
        mock_sec.characteristics = 0  # No WX

        # Mock import entry
        mock_imp_entry = MagicMock()
        mock_imp_entry.name = "CreateFileA"
        mock_import = MagicMock()
        mock_import.entries = [mock_imp_entry]

        # Mock binary
        mock_binary = MagicMock()
        mock_binary.sections = [mock_sec]
        mock_binary.has_imports = True
        mock_binary.imports = [mock_import]
        mock_binary.has_tls = False
        mock_binary.overlay = b""
        mock_binary.has_configuration = False
        mock_binary.has_resources = False

        mock_lief = MagicMock()
        mock_lief.parse.return_value = mock_binary
        # Make isinstance check pass by making mock_binary an instance of mock_lief.PE.Binary
        mock_lief.PE.Binary = type(mock_binary)

        with (
            patch.object(ml_classifier, "HAS_LIEF", True),
            patch.dict("sys.modules", {"lief": mock_lief}),
            patch.object(ml_classifier, "lief", mock_lief, create=True),
        ):
            result = ml_classifier.extract_features_lief(str(test_file))
            assert result is not None
            assert len(result) == 22
            assert result[0] > 0  # file_size_log
            assert result[10] == 1.0  # has_file_imports (CreateFileA)

    def test_lief_with_overlay_and_resources(self, tmp_path):
        """Test extract_features_lief with overlay and resources."""
        from hashguard import ml_classifier

        test_file = tmp_path / "test_lief_res.exe"
        test_file.write_bytes(b"\x00" * 3000)

        mock_sec = MagicMock()
        mock_sec.entropy = 7.5  # High entropy
        # Set write + execute characteristics
        mock_sec.characteristics = 0x80000000 | 0x20000000  # MEM_WRITE | MEM_EXECUTE

        mock_binary = MagicMock()
        mock_binary.sections = [mock_sec]
        mock_binary.has_imports = False
        mock_binary.imports = []
        mock_binary.has_tls = True
        mock_binary.overlay = b"\xAA" * 500
        mock_binary.has_configuration = True
        mock_binary.has_resources = True

        mock_res_node = MagicMock()
        mock_res_node.content = list(b"\xBB" * 100)
        mock_rm = MagicMock()
        mock_rm.get_node_type.return_value = [mock_res_node]
        mock_binary.resources_manager = mock_rm

        mock_lief = MagicMock()
        mock_lief.parse.return_value = mock_binary
        mock_lief.PE.Binary = type(mock_binary)
        mock_lief.PE.Section.CHARACTERISTICS.MEM_WRITE = 0x80000000
        mock_lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE = 0x20000000

        with (
            patch.object(ml_classifier, "HAS_LIEF", True),
            patch.dict("sys.modules", {"lief": mock_lief}),
            patch.object(ml_classifier, "lief", mock_lief, create=True),
        ):
            result = ml_classifier.extract_features_lief(str(test_file))
            assert result is not None
            assert result[14] == 1.0  # has_tls
            assert result[16] == 1.0  # has_overlay
            assert result[18] >= 1  # wx_section_count
            assert result[19] >= 1  # high_entropy_sections
            assert result[20] == 1.0  # is_dotnet (has_configuration)

    def test_lief_not_pe_binary(self):
        """Test with binary that is not a PE binary (e.g. ELF)."""
        from hashguard import ml_classifier

        with patch.object(ml_classifier, "HAS_LIEF", True):
            mock_binary = MagicMock()
            mock_lief = MagicMock()
            mock_lief.parse.return_value = mock_binary
            mock_lief.PE.Binary = type("FakePEBinary", (), {})

            with patch.dict("sys.modules", {"lief": mock_lief}):
                with patch.object(ml_classifier, "lief", mock_lief, create=True):
                    result = ml_classifier.extract_features_lief("/fake/path")
                    # Should return None since mock_binary is not an instance of FakePEBinary
                    assert result is None


class TestClassifyWithAnomalyDetection:
    """Test classify with anomaly detection enabled."""

    def test_anomaly_detected(self, monkeypatch):
        try:
            import numpy as np
            from hashguard.ml_classifier import classify, CLASSES
        except ImportError:
            pytest.skip("ML deps not available")

        mock_features = [1.0] * 22
        monkeypatch.setattr("hashguard.ml_classifier.extract_features",
                            lambda *a, **kw: mock_features)

        mock_clf = MagicMock()
        mock_clf.predict_proba.return_value = np.array([[0.05, 0.7, 0.1, 0.1, 0.05]])
        mock_scaler = MagicMock()
        mock_scaler.transform.return_value = np.array([mock_features])
        mock_iso = MagicMock()
        mock_iso.predict.return_value = np.array([-1])  # -1 = anomaly
        mock_iso.score_samples.return_value = np.array([-0.5])

        monkeypatch.setattr("hashguard.ml_classifier._get_or_build_model",
                            lambda: (mock_clf, mock_scaler, mock_iso))

        result = classify("test.exe")
        assert result.is_anomaly is True


class TestEntropy:
    """Test _entropy helper."""

    def test_empty_data(self):
        from hashguard.ml_classifier import _entropy
        assert _entropy(b"") == 0.0

    def test_uniform_data(self):
        from hashguard.ml_classifier import _entropy
        # All same byte = 0 entropy
        assert _entropy(b"\x00" * 100) == 0.0

    def test_varied_data(self):
        from hashguard.ml_classifier import _entropy
        data = bytes(range(256))
        ent = _entropy(data)
        assert ent > 7.9  # High entropy for uniform distribution


class TestMLClassificationToDict:
    """Test MLClassification.to_dict with edge cases."""

    def test_confidence_fraction(self):
        from hashguard.ml_classifier import MLClassification
        mc = MLClassification(
            predicted_class="trojan",
            confidence=0.85,
            probabilities={"trojan": 0.85, "benign": 0.15},
        )
        d = mc.to_dict()
        assert d["confidence"] == 85.0
        assert d["probabilities"]["trojan"] == 85.0

    def test_confidence_already_percentage(self):
        from hashguard.ml_classifier import MLClassification
        mc = MLClassification(predicted_class="benign", confidence=95.0)
        d = mc.to_dict()
        assert d["confidence"] == 95.0

    def test_confidence_caps_at_100(self):
        from hashguard.ml_classifier import MLClassification
        mc = MLClassification(predicted_class="benign", confidence=150.0)
        d = mc.to_dict()
        assert d["confidence"] == 100.0


class TestLoadRealDataset:
    """Test _load_real_dataset with CSV and JSON files."""

    def test_no_ml_returns_none(self):
        from hashguard import ml_classifier
        with patch.object(ml_classifier, "HAS_ML", False):
            result = ml_classifier._load_real_dataset()
            assert result is None

    def test_csv_dataset(self, tmp_path):
        try:
            from hashguard.ml_classifier import _load_real_dataset, FEATURE_NAMES, DATASET_DIR
            import numpy as np
        except ImportError:
            pytest.skip("ML deps not available")

        from hashguard import ml_classifier

        csv_file = tmp_path / "dataset.csv"
        header = ",".join(FEATURE_NAMES) + ",label\n"
        rows = []
        for i in range(60):
            vals = ",".join(["1.0"] * len(FEATURE_NAMES))
            label = "benign" if i < 30 else "trojan"
            rows.append(f"{vals},{label}\n")
        csv_file.write_text(header + "".join(rows))

        with patch.object(ml_classifier, "DATASET_DIR", str(tmp_path)):
            result = _load_real_dataset()
            assert result is not None
            X, y = result
            assert len(X) == 60

    def test_json_dataset(self, tmp_path):
        try:
            from hashguard.ml_classifier import _load_real_dataset, FEATURE_NAMES
            import numpy as np
        except ImportError:
            pytest.skip("ML deps not available")

        from hashguard import ml_classifier
        import json

        data = []
        for i in range(60):
            row = {fn: 1.0 for fn in FEATURE_NAMES}
            row["label"] = "ransomware" if i < 30 else "miner"
            data.append(row)

        json_file = tmp_path / "dataset.json"
        json_file.write_text(json.dumps(data))

        with patch.object(ml_classifier, "DATASET_DIR", str(tmp_path)):
            result = _load_real_dataset()
            assert result is not None
            X, y = result
            assert len(X) == 60

    def test_too_few_samples(self, tmp_path):
        try:
            from hashguard.ml_classifier import _load_real_dataset, FEATURE_NAMES
        except ImportError:
            pytest.skip("ML deps not available")

        from hashguard import ml_classifier
        import json

        data = [
            {**{fn: 1.0 for fn in FEATURE_NAMES}, "label": "benign"}
            for _ in range(10)
        ]
        json_file = tmp_path / "small.json"
        json_file.write_text(json.dumps(data))

        with patch.object(ml_classifier, "DATASET_DIR", str(tmp_path)):
            result = _load_real_dataset()
            assert result is None


class TestGetOrBuildModel:
    """Test _get_or_build_model caching and integrity."""

    def test_no_ml_returns_none(self):
        from hashguard import ml_classifier
        with patch.object(ml_classifier, "HAS_ML", False):
            clf, scaler, iso = ml_classifier._get_or_build_model()
            assert clf is None

    def test_hmac_mismatch_rebuilds(self, tmp_path):
        try:
            from hashguard import ml_classifier
            import pickle
        except ImportError:
            pytest.skip("ML deps not available")

        model_file = tmp_path / "ml_model.pkl"
        hmac_file = tmp_path / "ml_model.pkl.hmac"

        model_file.write_bytes(pickle.dumps({"version": -1, "clf": None, "scaler": None, "iso": None}))
        hmac_file.write_text("bad_hmac_value")

        with (
            patch.object(ml_classifier, "MODEL_PATH", str(model_file)),
            patch.object(ml_classifier, "_MODEL_HMAC_PATH", str(hmac_file)),
            patch.object(ml_classifier, "_build_model", return_value=(None, None, None)),
        ):
            clf, scaler, iso = ml_classifier._get_or_build_model()
            assert clf is None


class TestClassifyFull:
    """Test full classify flow with pefile fallback to lief."""

    def test_no_ml(self):
        from hashguard import ml_classifier
        with patch.object(ml_classifier, "HAS_ML", False):
            result = ml_classifier.classify("test.exe")
            assert result.predicted_class == "unknown"

    def test_no_features_returns_unknown(self):
        try:
            from hashguard.ml_classifier import classify
        except ImportError:
            pytest.skip("ML deps not available")

        with (
            patch("hashguard.ml_classifier.extract_features", return_value=None),
            patch("hashguard.ml_classifier.extract_features_lief", return_value=None),
        ):
            result = classify("test.exe")
            assert result.predicted_class == "unknown"

    def test_clf_none_returns_unknown(self):
        try:
            from hashguard.ml_classifier import classify
        except ImportError:
            pytest.skip("ML deps not available")

        with (
            patch("hashguard.ml_classifier.extract_features", return_value=[1.0] * 22),
            patch("hashguard.ml_classifier._get_or_build_model", return_value=(None, None, None)),
        ):
            result = classify("test.exe")
            assert result.predicted_class == "unknown"


class TestBuildModel:
    """Test _build_model function."""

    def test_no_ml(self):
        from hashguard import ml_classifier
        with patch.object(ml_classifier, "HAS_ML", False):
            result = ml_classifier._build_model()
            assert result == (None, None, None)

    def test_with_synthetic_data(self):
        try:
            from hashguard.ml_classifier import _build_model
        except ImportError:
            pytest.skip("ML deps not available")

        with patch("hashguard.ml_classifier._load_real_dataset", return_value=None):
            clf, scaler, iso = _build_model()
            assert clf is not None
            assert scaler is not None
            assert iso is not None


class TestBuildModelWithRealDataset:
    """Test _build_model when real dataset is available."""

    def test_real_dataset_path(self, tmp_path, monkeypatch):
        """_build_model should use real dataset when available."""
        try:
            import numpy as np
            from hashguard.ml_classifier import _build_model, CLASSES, FEATURE_NAMES
        except ImportError:
            pytest.skip("ML deps not available")

        # Create a real dataset with enough samples per class
        n_per_class = 40
        rng = np.random.RandomState(42)
        X = rng.rand(n_per_class * len(CLASSES), len(FEATURE_NAMES)).astype(np.float64)
        y = np.array([i for i in range(len(CLASSES)) for _ in range(n_per_class)])

        monkeypatch.setattr("hashguard.ml_classifier._load_real_dataset",
                            lambda: (X, y))
        clf, scaler, iso = _build_model()
        assert clf is not None
        assert scaler is not None

    def test_real_dataset_with_train_and_evaluate(self, tmp_path, monkeypatch):
        """_train_and_evaluate with 'real' source produces classification report."""
        try:
            import numpy as np
            from hashguard.ml_classifier import _train_and_evaluate, CLASSES
        except ImportError:
            pytest.skip("ML deps not available")

        n_per_class = 30
        rng = np.random.RandomState(42)
        X = rng.rand(n_per_class * len(CLASSES), 22).astype(np.float64)
        y = np.array([i for i in range(len(CLASSES)) for _ in range(n_per_class)])

        clf, scaler, iso = _train_and_evaluate(X, y, source="real")
        assert clf is not None


class TestTrainAndEvaluateSmallDataset:
    """Test _train_and_evaluate with a tiny dataset (no split)."""

    def test_too_few_for_split(self, monkeypatch):
        """If min class count < 2, should skip train/test split."""
        try:
            import numpy as np
            from hashguard.ml_classifier import _train_and_evaluate
        except ImportError:
            pytest.skip("ML deps not available")

        # 5 samples, each a different class → min_class_count = 1
        X = np.random.rand(5, 22)
        y = np.array([0, 1, 2, 3, 4])
        clf, scaler, iso = _train_and_evaluate(X, y, source="synthetic")
        assert clf is not None


class TestGetOrBuildModelHmacVersion:
    """Test _get_or_build_model HMAC and version check paths."""

    def test_version_mismatch_rebuilds(self, tmp_path, monkeypatch):
        try:
            import pickle
            from hashguard.ml_classifier import (
                _get_or_build_model, _build_model, _compute_file_hmac
            )
        except ImportError:
            pytest.skip("ML deps not available")

        model_path = str(tmp_path / "model.pkl")
        hmac_path = model_path + ".hmac"
        monkeypatch.setattr("hashguard.ml_classifier.MODEL_DIR", str(tmp_path))
        monkeypatch.setattr("hashguard.ml_classifier.MODEL_PATH", model_path)
        monkeypatch.setattr("hashguard.ml_classifier._MODEL_HMAC_PATH", hmac_path)
        monkeypatch.setattr("hashguard.ml_classifier.DATASET_DIR", str(tmp_path / "ds"))

        # Save model with wrong version
        with patch("hashguard.ml_classifier._load_real_dataset", return_value=None):
            clf, scaler, iso = _build_model()
        with open(model_path, "wb") as f:
            pickle.dump({"clf": clf, "scaler": scaler, "iso": iso, "version": "old_version"}, f)
        from pathlib import Path
        Path(hmac_path).write_text(_compute_file_hmac(model_path))

        # Should rebuild because version doesn't match
        clf2, scaler2, iso2 = _get_or_build_model()
        assert clf2 is not None

    def test_corrupted_pickle_rebuilds(self, tmp_path, monkeypatch):
        try:
            from hashguard.ml_classifier import (_get_or_build_model, _compute_file_hmac)
        except ImportError:
            pytest.skip("ML deps not available")

        model_path = str(tmp_path / "model.pkl")
        hmac_path = model_path + ".hmac"
        monkeypatch.setattr("hashguard.ml_classifier.MODEL_DIR", str(tmp_path))
        monkeypatch.setattr("hashguard.ml_classifier.MODEL_PATH", model_path)
        monkeypatch.setattr("hashguard.ml_classifier._MODEL_HMAC_PATH", hmac_path)
        monkeypatch.setattr("hashguard.ml_classifier.DATASET_DIR", str(tmp_path / "ds"))

        # Write corrupted pickle
        from pathlib import Path
        Path(model_path).write_bytes(b"corrupted data")
        Path(hmac_path).write_text(_compute_file_hmac(model_path))

        clf, scaler, iso = _get_or_build_model()
        assert clf is not None  # Should rebuild successfully

    def test_build_model_save_failure(self, tmp_path, monkeypatch):
        """_get_or_build_model handles save failure gracefully."""
        try:
            from hashguard.ml_classifier import _get_or_build_model
        except ImportError:
            pytest.skip("ML deps not available")

        monkeypatch.setattr("hashguard.ml_classifier.MODEL_DIR", "/nonexistent/dir")
        monkeypatch.setattr("hashguard.ml_classifier.MODEL_PATH", "/nonexistent/dir/model.pkl")
        monkeypatch.setattr("hashguard.ml_classifier._MODEL_HMAC_PATH", "/nonexistent/dir/model.pkl.hmac")
        monkeypatch.setattr("hashguard.ml_classifier.DATASET_DIR", str(tmp_path / "ds"))

        # Should build but fail to save — still returns model
        clf, scaler, iso = _get_or_build_model()
        assert clf is not None


class TestClassifyExceptionPaths:
    """Test classify error handling."""

    def test_classify_model_none(self, monkeypatch):
        from hashguard.ml_classifier import classify
        monkeypatch.setattr("hashguard.ml_classifier._get_or_build_model",
                            lambda: (None, None, None))
        result = classify("test.exe")
        assert result.predicted_class == "unknown"

    def test_classify_prediction_exception(self, monkeypatch):
        """classify handles exceptions from model prediction."""
        try:
            import numpy as np
            from hashguard.ml_classifier import classify
        except ImportError:
            pytest.skip("ML deps not available")

        monkeypatch.setattr("hashguard.ml_classifier.extract_features",
                            lambda *a, **kw: [1.0] * 22)
        mock_clf = MagicMock()
        mock_clf.predict_proba.side_effect = Exception("model error")
        mock_scaler = MagicMock()
        mock_scaler.transform.return_value = [[1.0] * 22]
        monkeypatch.setattr("hashguard.ml_classifier._get_or_build_model",
                            lambda: (mock_clf, mock_scaler, MagicMock()))
        result = classify("test.exe")
        assert result.predicted_class == "unknown"


class TestExtractFeaturesExceptionPaths:
    """Test specific exception paths in extract_features."""

    def test_section_entropy_exception(self, tmp_path):
        """Section get_entropy raises → should be caught."""
        from hashguard import ml_classifier

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"\x00" * 2000)

        with patch.object(ml_classifier, "HAS_PEFILE", True):
            mock_sec = MagicMock()
            mock_sec.get_entropy.side_effect = Exception("corrupt section")
            mock_sec.Characteristics = 0

            mock_pe = MagicMock()
            mock_pe.sections = [mock_sec]
            mock_pe.get_overlay_data_start_offset.return_value = None
            del mock_pe.DIRECTORY_ENTRY_TLS
            del mock_pe.DIRECTORY_ENTRY_COM_DESCRIPTOR
            del mock_pe.DIRECTORY_ENTRY_RESOURCE

            with patch("hashguard.ml_classifier.pefile") as mock_pefile:
                mock_pefile.PE.return_value = mock_pe
                mock_pefile.DIRECTORY_ENTRY = {"IMAGE_DIRECTORY_ENTRY_IMPORT": 1}
                result = ml_classifier.extract_features(str(test_file))
                assert result is not None

    def test_import_analysis_exception(self, tmp_path):
        """Import parsing raises → should be caught."""
        from hashguard import ml_classifier

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"\x00" * 2000)

        with patch.object(ml_classifier, "HAS_PEFILE", True):
            mock_sec = MagicMock()
            mock_sec.get_entropy.return_value = 4.0
            mock_sec.Characteristics = 0

            mock_pe = MagicMock()
            mock_pe.sections = [mock_sec]
            mock_pe.parse_data_directories.side_effect = Exception("import parse error")
            mock_pe.get_overlay_data_start_offset.return_value = None
            del mock_pe.DIRECTORY_ENTRY_TLS
            del mock_pe.DIRECTORY_ENTRY_COM_DESCRIPTOR
            del mock_pe.DIRECTORY_ENTRY_RESOURCE

            with patch("hashguard.ml_classifier.pefile") as mock_pefile:
                mock_pefile.PE.return_value = mock_pe
                mock_pefile.DIRECTORY_ENTRY = {"IMAGE_DIRECTORY_ENTRY_IMPORT": 1}
                result = ml_classifier.extract_features(str(test_file))
                assert result is not None
                assert result[5] == 0  # no imports

    def test_overlay_exception(self, tmp_path):
        """get_overlay_data_start_offset raises → should be caught."""
        from hashguard import ml_classifier

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"\x00" * 2000)

        with patch.object(ml_classifier, "HAS_PEFILE", True):
            mock_sec = MagicMock()
            mock_sec.get_entropy.return_value = 4.0
            mock_sec.Characteristics = 0

            mock_pe = MagicMock()
            mock_pe.sections = [mock_sec]
            mock_pe.get_overlay_data_start_offset.side_effect = Exception("overlay err")
            del mock_pe.DIRECTORY_ENTRY_TLS
            del mock_pe.DIRECTORY_ENTRY_COM_DESCRIPTOR
            del mock_pe.DIRECTORY_ENTRY_RESOURCE

            with patch("hashguard.ml_classifier.pefile") as mock_pefile:
                mock_pefile.PE.return_value = mock_pe
                mock_pefile.DIRECTORY_ENTRY = {"IMAGE_DIRECTORY_ENTRY_IMPORT": 1}
                result = ml_classifier.extract_features(str(test_file))
                assert result is not None

    def test_resource_parsing_exception(self, tmp_path):
        """Resource entries parsing raises → should be caught."""
        from hashguard import ml_classifier

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"\x00" * 2000)

        with patch.object(ml_classifier, "HAS_PEFILE", True):
            mock_sec = MagicMock()
            mock_sec.get_entropy.return_value = 4.0
            mock_sec.Characteristics = 0

            mock_entry = MagicMock()
            mock_entry.directory.entries = MagicMock(
                __iter__=MagicMock(side_effect=Exception("bad resource")),
                __getitem__=MagicMock(side_effect=Exception("bad resource")),
            )
            mock_res = MagicMock()
            mock_res.entries = [mock_entry]

            mock_pe = MagicMock()
            mock_pe.sections = [mock_sec]
            mock_pe.get_overlay_data_start_offset.return_value = None
            mock_pe.DIRECTORY_ENTRY_RESOURCE = mock_res
            del mock_pe.DIRECTORY_ENTRY_TLS
            del mock_pe.DIRECTORY_ENTRY_COM_DESCRIPTOR

            with patch("hashguard.ml_classifier.pefile") as mock_pefile:
                mock_pefile.PE.return_value = mock_pe
                mock_pefile.DIRECTORY_ENTRY = {"IMAGE_DIRECTORY_ENTRY_IMPORT": 1}
                result = ml_classifier.extract_features(str(test_file))
                assert result is not None


class TestLoadRealDatasetEdge:
    """Edge cases for _load_real_dataset."""

    def test_csv_with_warning(self, tmp_path, monkeypatch):
        """CSV with wrong data format → should log warning and skip."""
        try:
            from hashguard.ml_classifier import _load_real_dataset, FEATURE_NAMES
        except ImportError:
            pytest.skip("ML deps not available")

        monkeypatch.setattr("hashguard.ml_classifier.DATASET_DIR", str(tmp_path))

        # Create a CSV with too few samples -> returns None
        header = ",".join(FEATURE_NAMES) + ",label\n"
        rows = []
        for i in range(10):  # less than 50 minimum
            vals = [str(float(i)) for _ in range(22)]
            rows.append(",".join(vals) + ",benign\n")
        csv_path = tmp_path / "small.csv"
        csv_path.write_text(header + "".join(rows))

        result = _load_real_dataset()
        assert result is None

    def test_csv_with_invalid_label(self, tmp_path, monkeypatch):
        """CSV rows with invalid labels should be skipped."""
        try:
            from hashguard.ml_classifier import _load_real_dataset, FEATURE_NAMES, CLASSES
        except ImportError:
            pytest.skip("ML deps not available")

        monkeypatch.setattr("hashguard.ml_classifier.DATASET_DIR", str(tmp_path))

        header = ",".join(FEATURE_NAMES) + ",label\n"
        rows = []
        for i in range(60):
            vals = [str(float(i % 5)) for _ in range(22)]
            # Use valid label for half, invalid for other half
            label = CLASSES[i % 5] if i < 50 else "invalid_label"
            rows.append(",".join(vals) + f",{label}\n")
        csv_path = tmp_path / "mixed.csv"
        csv_path.write_text(header + "".join(rows))

        result = _load_real_dataset()
        assert result is not None
        X, y = result
        assert X.shape[0] == 50  # invalid labels skipped

    def test_json_dataset(self, tmp_path, monkeypatch):
        """JSON dataset loading path."""
        try:
            import json
            import numpy as np
            from hashguard.ml_classifier import _load_real_dataset, FEATURE_NAMES, CLASSES
        except ImportError:
            pytest.skip("ML deps not available")

        monkeypatch.setattr("hashguard.ml_classifier.DATASET_DIR", str(tmp_path))

        data = []
        for i in range(60):
            row = {name: float(i % 5 + j * 0.1) for j, name in enumerate(FEATURE_NAMES)}
            row["label"] = CLASSES[i % 5]
            data.append(row)

        (tmp_path / "data.json").write_text(json.dumps(data))
        result = _load_real_dataset()
        assert result is not None

    def test_corrupted_file_handled(self, tmp_path, monkeypatch):
        """Corrupted file logs warning, doesn't crash."""
        try:
            from hashguard.ml_classifier import _load_real_dataset
        except ImportError:
            pytest.skip("ML deps not available")

        monkeypatch.setattr("hashguard.ml_classifier.DATASET_DIR", str(tmp_path))
        (tmp_path / "corrupt.csv").write_text("bad\x00data\x01garbage")
        result = _load_real_dataset()
        assert result is None


class TestExtractFeaturesExceptions:
    """Cover extract_features exception paths."""

    def test_extract_features_total_exception(self, tmp_path):
        """Overall extract_features exception returns None (lines 317-320)."""
        try:
            from hashguard.ml_classifier import extract_features
        except ImportError:
            pytest.skip("ML deps not available")

        f = tmp_path / "test.exe"
        f.write_bytes(b"MZ" + b"\x00" * 100)

        with patch("hashguard.ml_classifier.pefile") as mock_pe:
            mock_pe.PE.side_effect = RuntimeError("parse fail")
            result = extract_features(str(f))
            assert result is None

    def test_extract_features_lief_not_pe(self, tmp_path):
        """LIEF returns non-PE binary → None (lines 333-334)."""
        try:
            from hashguard.ml_classifier import extract_features_lief, HAS_LIEF
        except ImportError:
            pytest.skip("ML deps not available")

        if not HAS_LIEF:
            pytest.skip("LIEF not installed")

        f = tmp_path / "test.elf"
        f.write_bytes(b"\x7fELF" + b"\x00" * 100)

        with patch("hashguard.ml_classifier.lief") as mock_lief:
            mock_lief.parse.return_value = MagicMock()  # Not a PE Binary
            mock_lief.PE.Binary = type("Binary", (), {})
            result = extract_features_lief(str(f))
            assert result is None

    def test_extract_features_lief_parse_fail(self, tmp_path):
        """LIEF parse exception returns None (lines 333-334)."""
        try:
            from hashguard.ml_classifier import extract_features_lief, HAS_LIEF
        except ImportError:
            pytest.skip("ML deps not available")

        if not HAS_LIEF:
            pytest.skip("LIEF not installed")

        f = tmp_path / "test.exe"
        f.write_bytes(b"MZ" + b"\x00" * 100)

        with patch("hashguard.ml_classifier.lief") as mock_lief:
            mock_lief.parse.side_effect = RuntimeError("parse error")
            result = extract_features_lief(str(f))
            assert result is None
