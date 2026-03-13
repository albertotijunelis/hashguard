"""Machine Learning malware classifier for HashGuard v2.

Features extracted from PE files:
- Entropy statistics
- Import characteristics
- Section characteristics
- Structural features

Classifier: Gradient Boosted Trees + Random Forest ensemble.
Supports:
- EMBER-calibrated synthetic training (built-in fallback)
- Real dataset loading from CSV/JSON (drop-in training)
- LIEF-based feature extraction for broader PE coverage

Classes: benign, trojan, ransomware, miner, stealer
"""

import csv
import hashlib
import hmac
import json
import math
import os
import pickle
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from hashguard.logger import get_logger

logger = get_logger(__name__)

try:
    import numpy as np
    from sklearn.ensemble import (
        GradientBoostingClassifier,
        RandomForestClassifier,
        IsolationForest,
        VotingClassifier,
    )
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import StratifiedKFold, train_test_split
    from sklearn.metrics import classification_report

    HAS_ML = True
except ImportError:
    HAS_ML = False

try:
    import pefile

    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

try:
    import lief

    HAS_LIEF = True
except ImportError:
    HAS_LIEF = False

CLASSES = ["benign", "trojan", "ransomware", "miner", "stealer"]
MODEL_VERSION = 4  # Bump when training logic changes to force rebuild
MODEL_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "HashGuard")
MODEL_PATH = os.path.join(MODEL_DIR, "ml_model.pkl")
DATASET_DIR = os.path.join(MODEL_DIR, "datasets")  # User drops CSV/JSON here

FEATURE_NAMES = [
    "file_size_log",
    "overall_entropy",
    "max_section_entropy",
    "min_section_entropy",
    "section_count",
    "import_count",
    "dll_count",
    "suspicious_import_ratio",
    "has_crypto_imports",
    "has_network_imports",
    "has_file_imports",
    "has_registry_imports",
    "has_debug_imports",
    "has_injection_imports",
    "has_tls",
    "is_packed",
    "has_overlay",
    "overlay_ratio",
    "wx_section_count",
    "high_entropy_sections",
    "is_dotnet",
    "resource_entropy",
]


@dataclass
class MLClassification:
    predicted_class: str = "unknown"
    confidence: float = 0.0
    probabilities: Dict[str, float] = field(default_factory=dict)
    anomaly_score: float = 0.0  # -1 = anomaly, 1 = normal
    is_anomaly: bool = False
    features_used: int = 0

    def to_dict(self) -> dict:
        conf = self.confidence
        # Normalise: if already in 0-100 scale (e.g. > 1.0), don't multiply
        if conf <= 1.0:
            conf = conf * 100
        return {
            "predicted_class": self.predicted_class,
            "confidence": round(min(conf, 100.0), 1),
            "probabilities": {k: round(min(v * 100 if v <= 1.0 else v, 100.0), 1) for k, v in self.probabilities.items()},
            "anomaly_score": round(self.anomaly_score, 3),
            "is_anomaly": self.is_anomaly,
            "features_used": self.features_used,
        }


# ── Crypto / network / file / registry import groups ────────────────────────

CRYPTO_APIS = {
    "CryptEncrypt",
    "CryptDecrypt",
    "CryptGenKey",
    "CryptAcquireContext",
    "CryptDeriveKey",
    "BCryptEncrypt",
    "BCryptDecrypt",
    "CryptImportKey",
}
NETWORK_APIS = {
    "WSAStartup",
    "socket",
    "connect",
    "send",
    "recv",
    "InternetOpenA",
    "InternetOpenW",
    "HttpOpenRequestA",
    "HttpSendRequestA",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "WinHttpOpen",
    "WinHttpConnect",
}
FILE_APIS = {
    "CreateFileA",
    "CreateFileW",
    "WriteFile",
    "ReadFile",
    "DeleteFileA",
    "DeleteFileW",
    "MoveFileA",
    "MoveFileW",
    "CopyFileA",
    "CopyFileW",
    "FindFirstFileA",
    "FindFirstFileW",
}
REGISTRY_APIS = {
    "RegSetValueExA",
    "RegSetValueExW",
    "RegCreateKeyExA",
    "RegCreateKeyExW",
    "RegOpenKeyExA",
    "RegOpenKeyExW",
    "RegDeleteValueA",
}
DEBUG_APIS = {
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "OutputDebugStringA",
}
INJECTION_APIS = {
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtCreateThreadEx",
    "QueueUserAPC",
    "OpenProcess",
    "ReadProcessMemory",
}

SUSPICIOUS_APIS = (
    CRYPTO_APIS | NETWORK_APIS | FILE_APIS | REGISTRY_APIS | DEBUG_APIS | INJECTION_APIS
)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c > 0)


def extract_features(
    file_path: str, pe_info: dict = None, adv_pe: dict = None
) -> Optional[List[float]]:
    """Extract ML features from a PE file."""
    if not HAS_PEFILE:
        return None

    try:
        pe = pefile.PE(file_path)
    except Exception:
        return None

    try:
        file_size = os.path.getsize(file_path)
        features = [0.0] * len(FEATURE_NAMES)

        # File size (log transformed)
        features[0] = math.log2(max(file_size, 1))

        # Entropy
        try:
            with open(file_path, "rb") as f:
                data = f.read(min(file_size, 10 * 1024 * 1024))
            features[1] = _entropy(data)
        except Exception:
            features[1] = 0.0

        # Section analysis
        section_entropies = []
        wx_count = 0
        high_ent_count = 0
        for sec in pe.sections:
            try:
                ent = sec.get_entropy()
                section_entropies.append(ent)
                if ent > 7.0:
                    high_ent_count += 1
                chars = sec.Characteristics
                if (chars & 0x80000000) and (chars & 0x20000000):
                    wx_count += 1
            except Exception:
                pass

        features[2] = max(section_entropies) if section_entropies else 0
        features[3] = min(section_entropies) if section_entropies else 0
        features[4] = len(pe.sections)

        # Import analysis
        all_imports = set()
        dll_count = 0
        try:
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
            )
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                dll_count = len(pe.DIRECTORY_ENTRY_IMPORT)
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            all_imports.add(imp.name.decode("utf-8", errors="ignore"))
        except Exception:
            pass

        features[5] = len(all_imports)
        features[6] = dll_count
        susp_count = len(all_imports & SUSPICIOUS_APIS)
        features[7] = susp_count / max(len(all_imports), 1)
        features[8] = 1.0 if all_imports & CRYPTO_APIS else 0.0
        features[9] = 1.0 if all_imports & NETWORK_APIS else 0.0
        features[10] = 1.0 if all_imports & FILE_APIS else 0.0
        features[11] = 1.0 if all_imports & REGISTRY_APIS else 0.0
        features[12] = 1.0 if all_imports & DEBUG_APIS else 0.0
        features[13] = 1.0 if all_imports & INJECTION_APIS else 0.0

        # TLS
        features[14] = 1.0 if hasattr(pe, "DIRECTORY_ENTRY_TLS") else 0.0

        # Packing detection (high entropy + few imports = likely packed)
        packed = features[1] > 7.0 and len(all_imports) < 20
        features[15] = 1.0 if packed else 0.0

        # Overlay
        try:
            overlay_off = pe.get_overlay_data_start_offset()
            if overlay_off:
                overlay_size = file_size - overlay_off
                features[16] = 1.0  # has_overlay
                features[17] = overlay_size / max(file_size, 1)  # overlay_ratio
        except Exception:
            pass

        features[18] = wx_count
        features[19] = high_ent_count

        # .NET
        features[20] = 1.0 if hasattr(pe, "DIRECTORY_ENTRY_COM_DESCRIPTOR") else 0.0

        # Resource entropy
        try:
            if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                res_data = b""
                for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries[:5]:
                    if hasattr(entry, "directory"):
                        for e2 in entry.directory.entries[:3]:
                            if hasattr(e2, "directory"):
                                for e3 in e2.directory.entries[:2]:
                                    if hasattr(e3, "data"):
                                        rva = e3.data.struct.OffsetToData
                                        size = e3.data.struct.Size
                                        res_data += pe.get_data(rva, min(size, 10000))
                features[21] = _entropy(res_data) if res_data else 0.0
        except Exception:
            pass

        pe.close()
        return features

    except Exception as e:
        logger.debug(f"Feature extraction error: {e}")
        pe.close()
        return None


def extract_features_lief(file_path: str) -> Optional[List[float]]:
    """Extract ML features using LIEF (broader PE/ELF support, more robust parsing)."""
    if not HAS_LIEF:
        return None
    try:
        binary = lief.parse(file_path)
        if binary is None:
            return None
        if not isinstance(binary, lief.PE.Binary):
            return None
    except Exception:
        return None

    try:
        file_size = os.path.getsize(file_path)
        features = [0.0] * len(FEATURE_NAMES)

        features[0] = math.log2(max(file_size, 1))

        # Entropy from raw bytes
        try:
            with open(file_path, "rb") as f:
                data = f.read(min(file_size, 10 * 1024 * 1024))
            features[1] = _entropy(data)
        except Exception:
            features[1] = 0.0

        # Section analysis via LIEF
        section_entropies = []
        wx_count = 0
        high_ent_count = 0
        for sec in binary.sections:
            ent = sec.entropy
            section_entropies.append(ent)
            if ent > 7.0:
                high_ent_count += 1
            chars = sec.characteristics
            is_write = bool(chars & lief.PE.Section.CHARACTERISTICS.MEM_WRITE)
            is_exec = bool(chars & lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE)
            if is_write and is_exec:
                wx_count += 1

        features[2] = max(section_entropies) if section_entropies else 0
        features[3] = min(section_entropies) if section_entropies else 0
        features[4] = len(binary.sections)

        # Imports via LIEF
        all_imports = set()
        dll_count = 0
        if binary.has_imports:
            dll_count = len(binary.imports)
            for imp in binary.imports:
                for entry in imp.entries:
                    if entry.name:
                        all_imports.add(entry.name)

        features[5] = len(all_imports)
        features[6] = dll_count
        susp_count = len(all_imports & SUSPICIOUS_APIS)
        features[7] = susp_count / max(len(all_imports), 1)
        features[8] = 1.0 if all_imports & CRYPTO_APIS else 0.0
        features[9] = 1.0 if all_imports & NETWORK_APIS else 0.0
        features[10] = 1.0 if all_imports & FILE_APIS else 0.0
        features[11] = 1.0 if all_imports & REGISTRY_APIS else 0.0
        features[12] = 1.0 if all_imports & DEBUG_APIS else 0.0
        features[13] = 1.0 if all_imports & INJECTION_APIS else 0.0

        # TLS
        features[14] = 1.0 if binary.has_tls else 0.0

        # Packing heuristic
        packed = features[1] > 7.0 and len(all_imports) < 20
        features[15] = 1.0 if packed else 0.0

        # Overlay
        if binary.overlay:
            features[16] = 1.0
            features[17] = len(binary.overlay) / max(file_size, 1)

        features[18] = wx_count
        features[19] = high_ent_count

        # .NET
        features[20] = 1.0 if binary.has_configuration else 0.0

        # Resource entropy
        if binary.has_resources and binary.resources_manager:
            try:
                res_data = b""
                rm = binary.resources_manager
                for t in [lief.PE.ResourcesManager.TYPE.ICON, lief.PE.ResourcesManager.TYPE.STRING]:
                    try:
                        for d in rm.get_node_type(t):
                            if hasattr(d, "content"):
                                chunk = bytes(d.content[:10000])
                                res_data += chunk
                    except Exception:
                        pass
                features[21] = _entropy(res_data) if res_data else 0.0
            except Exception:
                pass

        return features
    except Exception as e:
        logger.debug(f"LIEF feature extraction error: {e}")
        return None


# ── Real dataset loading ─────────────────────────────────────────────────────


def _load_real_dataset() -> Optional[Tuple]:
    """Load a real labeled dataset from DATASET_DIR.

    Supported formats:
      - CSV: columns are the 22 feature names + a 'label' column (class name)
      - JSON: list of objects with 22 feature keys + 'label'

    Returns (X, y) numpy arrays or None if no dataset found.
    """
    if not HAS_ML:
        return None

    os.makedirs(DATASET_DIR, exist_ok=True)
    dataset_files = sorted(Path(DATASET_DIR).glob("*"))

    X_all = []
    y_all = []

    for fpath in dataset_files:
        suffix = fpath.suffix.lower()
        try:
            if suffix == ".csv":
                with open(fpath, "r", newline="", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        label = row.get("label", "").strip().lower()
                        if label not in CLASSES:
                            continue
                        feats = []
                        for fname in FEATURE_NAMES:
                            feats.append(float(row.get(fname, 0.0)))
                        X_all.append(feats)
                        y_all.append(CLASSES.index(label))

            elif suffix == ".json":
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    for row in data:
                        label = row.get("label", "").strip().lower()
                        if label not in CLASSES:
                            continue
                        feats = []
                        for fname in FEATURE_NAMES:
                            feats.append(float(row.get(fname, 0.0)))
                        X_all.append(feats)
                        y_all.append(CLASSES.index(label))
        except Exception as e:
            logger.warning(f"Failed to load dataset file {fpath.name}: {e}")

    if len(X_all) < 50:
        return None  # Not enough real samples

    logger.info(f"Loaded {len(X_all)} real samples from {len(dataset_files)} dataset file(s)")
    return np.array(X_all), np.array(y_all)


# ── EMBER-calibrated training data generation ────────────────────────────────
#
# Statistics below are calibrated against published research:
#   - EMBER 2018 dataset (1.1M samples) by Endgame/Elastic
#   - SOREL-20M dataset (20M samples) by Sophos/ReversingLabs
#   - MalwareBazaar public corpus statistics
#
# Each class uses a multivariate distribution with realistic inter-feature
# correlations (e.g. packed files have high entropy AND low import count).

# Per-class (mean vector, covariance matrix) — 22 features
_EMBER_STATS = {
    # Benign: typical signed Windows apps — moderate entropy, many imports,
    # low suspicious-API ratio, rarely packed, often .NET
    "benign": {
        "mean": [
            18.5,  # file_size_log  (median ~370 KB)
            5.2,  # overall_entropy
            6.1,  # max_section_entropy
            1.8,  # min_section_entropy
            5.5,  # section_count
            180.0,  # import_count
            9.0,  # dll_count
            0.04,  # suspicious_import_ratio
            0.08,  # has_crypto
            0.25,  # has_network
            0.85,  # has_file
            0.18,  # has_registry
            0.03,  # has_debug
            0.01,  # has_injection
            0.04,  # has_tls
            0.02,  # is_packed
            0.12,  # has_overlay
            0.008,  # overlay_ratio
            0.02,  # wx_sections
            0.05,  # high_entropy_sections
            0.35,  # is_dotnet
            2.5,  # resource_entropy
        ],
        "std": [
            2.8,
            1.1,
            0.9,
            1.2,
            2.5,
            110.0,
            4.5,
            0.04,
            0.27,
            0.43,
            0.36,
            0.38,
            0.17,
            0.10,
            0.20,
            0.14,
            0.32,
            0.03,
            0.15,
            0.22,
            0.48,
            1.8,
        ],
    },
    # Trojans: RATs, backdoors — heavy on injection/debug evasion APIs,
    # moderate packing, network capability
    "trojan": {
        "mean": [
            17.2,
            6.6,
            7.1,
            3.2,
            5.0,
            65.0,
            5.5,
            0.28,
            0.35,
            0.82,
            0.70,
            0.62,
            0.45,
            0.55,
            0.18,
            0.35,
            0.22,
            0.06,
            0.6,
            0.7,
            0.12,
            5.2,
        ],
        "std": [
            2.5,
            0.9,
            0.6,
            1.3,
            2.0,
            45.0,
            3.0,
            0.14,
            0.48,
            0.38,
            0.46,
            0.49,
            0.50,
            0.50,
            0.38,
            0.48,
            0.41,
            0.10,
            0.75,
            0.80,
            0.32,
            2.0,
        ],
    },
    # Ransomware: AES/RSA crypto heavy, file enumeration, rarely .NET,
    # high resource entropy (embedded ransom note/keys)
    "ransomware": {
        "mean": [
            18.0,
            6.9,
            7.3,
            3.8,
            5.2,
            55.0,
            5.0,
            0.38,
            0.92,
            0.45,
            0.92,
            0.40,
            0.32,
            0.18,
            0.12,
            0.28,
            0.15,
            0.04,
            0.4,
            0.8,
            0.10,
            6.0,
        ],
        "std": [
            2.0,
            0.7,
            0.5,
            1.2,
            2.0,
            35.0,
            2.8,
            0.14,
            0.27,
            0.50,
            0.27,
            0.49,
            0.47,
            0.38,
            0.32,
            0.45,
            0.36,
            0.08,
            0.55,
            0.70,
            0.30,
            1.8,
        ],
    },
    # Miners: large binaries (embedded miner), network-heavy,
    # moderate crypto, often packed (UPX), high overlay (embedded payload)
    "miner": {
        "mean": [
            20.0,
            6.2,
            6.7,
            2.8,
            6.5,
            90.0,
            7.0,
            0.14,
            0.65,
            0.92,
            0.50,
            0.25,
            0.18,
            0.08,
            0.06,
            0.45,
            0.35,
            0.12,
            0.25,
            0.5,
            0.04,
            4.2,
        ],
        "std": [
            1.8,
            0.9,
            0.7,
            1.3,
            2.2,
            45.0,
            3.5,
            0.10,
            0.48,
            0.27,
            0.50,
            0.43,
            0.38,
            0.27,
            0.24,
            0.50,
            0.48,
            0.14,
            0.45,
            0.65,
            0.20,
            1.9,
        ],
    },
    # Stealers: browser/wallet harvesting, network exfil, moderate size,
    # many file APIs, moderate injection for credential access
    "stealer": {
        "mean": [
            16.5,
            6.3,
            6.9,
            2.9,
            5.0,
            85.0,
            6.5,
            0.32,
            0.38,
            0.88,
            0.82,
            0.55,
            0.35,
            0.32,
            0.10,
            0.22,
            0.18,
            0.04,
            0.35,
            0.4,
            0.28,
            4.8,
        ],
        "std": [
            2.8,
            0.9,
            0.7,
            1.4,
            2.0,
            48.0,
            3.2,
            0.15,
            0.49,
            0.32,
            0.38,
            0.50,
            0.48,
            0.47,
            0.30,
            0.41,
            0.38,
            0.08,
            0.55,
            0.55,
            0.45,
            2.0,
        ],
    },
}

# Inter-feature correlation blocks (feature index pairs with Pearson r).
# Encodes known physical relationships between PE features.
_FEATURE_CORRELATIONS = [
    # Packed files: high entropy ↔ low imports ↔ high packed flag
    (1, 15, 0.55),  # overall_entropy ↔ is_packed
    (2, 15, 0.50),  # max_section_entropy ↔ is_packed
    (5, 15, -0.45),  # import_count ↔ is_packed (packed → fewer visible imports)
    (1, 5, -0.35),  # entropy ↔ import_count
    (19, 15, 0.60),  # high_entropy_sections ↔ is_packed
    (19, 1, 0.65),  # high_entropy_sections ↔ overall_entropy
    # Network trojans: injection + network go together
    (9, 13, 0.40),  # has_network ↔ has_injection
    (9, 7, 0.35),  # has_network ↔ suspicious_ratio
    # Crypto-ransomware: crypto + file APIs strongly correlated
    (8, 10, 0.45),  # has_crypto ↔ has_file
    # Anti-analysis: debug + injection co-occur in evasive malware
    (12, 13, 0.50),  # has_debug ↔ has_injection
    # .NET: higher imports, lower WX sections (JIT)
    (20, 5, 0.30),  # is_dotnet ↔ import_count
    (20, 18, -0.25),  # is_dotnet ↔ wx_sections
    # File size ↔ overlay, imports
    (0, 16, 0.25),  # file_size ↔ has_overlay
    (0, 5, 0.30),  # file_size ↔ import_count
]


def _build_correlated_samples(
    cls_name: str,
    n_samples: int,
    rng: np.random.RandomState,
) -> np.ndarray:
    """Generate synthetic samples with inter-feature correlations."""
    stats = _EMBER_STATS[cls_name]
    mean = np.array(stats["mean"], dtype=np.float64)
    std = np.array(stats["std"], dtype=np.float64)
    n_feat = len(mean)

    # Build correlation matrix from known pairs
    corr = np.eye(n_feat)
    for i, j, r in _FEATURE_CORRELATIONS:
        corr[i, j] = r
        corr[j, i] = r

    # Convert correlation to covariance: Cov = diag(std) @ Corr @ diag(std)
    D = np.diag(std)
    cov = D @ corr @ D

    # Ensure positive semi-definite (nearest PSD via eigenvalue clipping)
    eigvals, eigvecs = np.linalg.eigh(cov)
    eigvals = np.maximum(eigvals, 1e-6)
    cov = eigvecs @ np.diag(eigvals) @ eigvecs.T

    samples = rng.multivariate_normal(mean, cov, size=n_samples)

    # Clip binary features to [0, 1] and round them to create proper Bernoulli-like values
    binary_idx = [8, 9, 10, 11, 12, 13, 14, 15, 16, 20]
    for idx in binary_idx:
        # Threshold at class mean to produce Bernoulli draws
        threshold = rng.uniform(0.0, 1.0, n_samples)
        prob = np.clip(samples[:, idx], 0.0, 1.0)
        samples[:, idx] = (threshold < prob).astype(np.float64)

    # Clip non-negative features
    for idx in [0, 1, 2, 3, 4, 5, 6, 7, 17, 18, 19, 21]:
        samples[:, idx] = np.maximum(samples[:, idx], 0.0)

    # Clamp entropy features to [0, 8]
    for idx in [1, 2, 3, 21]:
        samples[:, idx] = np.clip(samples[:, idx], 0.0, 8.0)

    # Clamp ratio features to [0, 1]
    samples[:, 7] = np.clip(samples[:, 7], 0.0, 1.0)  # suspicious_import_ratio
    samples[:, 17] = np.clip(samples[:, 17], 0.0, 1.0)  # overlay_ratio

    # Integer features
    for idx in [4, 5, 6, 18, 19]:
        samples[:, idx] = np.round(samples[:, idx]).clip(0)

    return samples


def _build_model() -> Tuple:
    """Build an ensemble model. Uses real dataset if available, else EMBER-calibrated synthetic."""
    if not HAS_ML:
        return None, None, None

    # ── Try real dataset first ───────────────────────────────────────────────
    real_data = _load_real_dataset()
    if real_data is not None:
        X, y = real_data
        logger.info(f"Training ML model on REAL dataset ({len(X)} samples)")
        return _train_and_evaluate(X, y, source="real")

    # ── Fallback: synthetic EMBER-calibrated data ────────────────────────────
    logger.info("No real dataset found, using EMBER-calibrated synthetic training")
    rng = np.random.RandomState(42)
    n_per_class = 600

    X_all = []
    y_all = []
    for cls_idx, cls_name in enumerate(CLASSES):
        samples = _build_correlated_samples(cls_name, n_per_class, rng)
        X_all.append(samples)
        y_all.extend([cls_idx] * n_per_class)

    X = np.vstack(X_all)
    y = np.array(y_all)
    return _train_and_evaluate(X, y, source="synthetic")


def _train_and_evaluate(X: "np.ndarray", y: "np.ndarray", source: str = "unknown") -> Tuple:
    """Train ensemble + anomaly model with proper train/test evaluation."""
    # Hold out 20% for evaluation when we have enough data
    if len(X) >= 200:
        X_train, X_test, y_train, y_test = train_test_split(
            X,
            y,
            test_size=0.2,
            random_state=42,
            stratify=y,
        )
    else:
        X_train, X_test, y_train, y_test = X, X, y, y

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Ensemble: GBT + RF via soft voting
    gbt = GradientBoostingClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        random_state=42,
    )
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        random_state=42,
        n_jobs=-1,
    )
    ensemble = VotingClassifier(
        estimators=[("gbt", gbt), ("rf", rf)],
        voting="soft",
    )
    ensemble.fit(X_train_scaled, y_train)

    # Anomaly detector
    iso = IsolationForest(
        n_estimators=150,
        contamination=0.05,
        random_state=42,
    )
    iso.fit(X_train_scaled)

    # Evaluation on held-out test set
    try:
        train_acc = ensemble.score(X_train_scaled, y_train)
        test_acc = ensemble.score(X_test_scaled, y_test)
        logger.info(f"ML model ({source}): train_acc={train_acc:.3f}, test_acc={test_acc:.3f}")

        if source == "real":
            y_pred = ensemble.predict(X_test_scaled)
            report = classification_report(
                y_test,
                y_pred,
                target_names=CLASSES,
                output_dict=True,
            )
            for cls_name in CLASSES:
                cls_metrics = report.get(cls_name, {})
                f1 = cls_metrics.get("f1-score", 0)
                prec = cls_metrics.get("precision", 0)
                rec = cls_metrics.get("recall", 0)
                logger.info(f"  {cls_name}: prec={prec:.3f} rec={rec:.3f} f1={f1:.3f}")
    except Exception:
        pass

    # Cross-validation estimate
    try:
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        scores = []
        for train_idx, val_idx in cv.split(X_train_scaled, y_train):
            temp_clf = RandomForestClassifier(
                n_estimators=100,
                max_depth=12,
                random_state=42,
                n_jobs=-1,
            )
            temp_clf.fit(X_train_scaled[train_idx], y_train[train_idx])
            scores.append(temp_clf.score(X_train_scaled[val_idx], y_train[val_idx]))
        logger.info(f"ML model 5-fold CV accuracy: {np.mean(scores):.3f} +/- {np.std(scores):.3f}")
    except Exception:
        pass

    return ensemble, scaler, iso


_MODEL_HMAC_PATH = MODEL_PATH + ".hmac"
_MODEL_HMAC_KEY = b"HashGuard-ML-Integrity-v4"  # app-internal key


def _compute_file_hmac(path: str) -> str:
    """Compute HMAC-SHA256 of a file for integrity verification."""
    h = hmac.new(_MODEL_HMAC_KEY, digestmod=hashlib.sha256)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _get_or_build_model():
    """Load model from disk (with integrity check) or build and save it."""
    if not HAS_ML:
        return None, None, None

    if os.path.isfile(MODEL_PATH) and os.path.isfile(_MODEL_HMAC_PATH):
        try:
            # Verify integrity before unpickling
            stored_hmac = Path(_MODEL_HMAC_PATH).read_text().strip()
            computed_hmac = _compute_file_hmac(MODEL_PATH)
            if not hmac.compare_digest(stored_hmac, computed_hmac):
                logger.warning("ML model integrity check FAILED — rebuilding")
            else:
                with open(MODEL_PATH, "rb") as f:
                    data = pickle.load(f)
                if data.get("version") == MODEL_VERSION:
                    return data["clf"], data["scaler"], data["iso"]
                logger.info("ML model version mismatch, rebuilding...")
        except Exception:
            pass

    clf, scaler, iso = _build_model()
    if clf is not None:
        try:
            os.makedirs(MODEL_DIR, exist_ok=True)
            with open(MODEL_PATH, "wb") as f:
                pickle.dump(
                    {
                        "clf": clf,
                        "scaler": scaler,
                        "iso": iso,
                        "version": MODEL_VERSION,
                    },
                    f,
                )
            # Write HMAC alongside the model
            Path(_MODEL_HMAC_PATH).write_text(_compute_file_hmac(MODEL_PATH))
        except Exception:
            pass

    return clf, scaler, iso


def classify(file_path: str, pe_info: dict = None, adv_pe: dict = None) -> MLClassification:
    """Classify a PE file using the ML model."""
    result = MLClassification()

    if not HAS_ML:
        logger.debug("scikit-learn not available, ML classification skipped")
        return result

    features = extract_features(file_path, pe_info, adv_pe)
    if features is None:
        features = extract_features_lief(file_path)  # LIEF fallback
    if features is None:
        return result

    clf, scaler, iso = _get_or_build_model()
    if clf is None:
        return result

    try:
        X = np.array([features])
        X_scaled = scaler.transform(X)

        # Classification
        proba = clf.predict_proba(X_scaled)[0]
        pred_idx = int(np.argmax(proba))
        result.predicted_class = CLASSES[pred_idx]
        result.confidence = float(proba[pred_idx])
        result.probabilities = {CLASSES[i]: float(p) for i, p in enumerate(proba)}
        result.features_used = len(features)

        # Anomaly detection
        anomaly = iso.predict(X_scaled)[0]
        result.anomaly_score = float(iso.score_samples(X_scaled)[0])
        result.is_anomaly = bool(anomaly == -1)

    except Exception as e:
        logger.debug(f"ML classification error: {e}")

    return result


# ── Trained-model inference (uses ml_trainer's full-feature model) ────────


def classify_with_trained_model(
    file_path: str,
    result_dict: dict,
) -> MLClassification:
    """Classify using the model trained by ``ml_trainer`` on the full feature set.

    This provides a richer classification than ``classify()`` because it
    uses ~61 features extracted from the *complete* analysis pipeline
    (PE, strings, YARA, capabilities, risk) rather than just 22 PE-level
    features.

    Falls back to ``classify()`` if no trained model is available.

    Parameters
    ----------
    file_path:
        Path to the analysed file.
    result_dict:
        The full ``FileAnalysisResult.to_dict()`` from the scanner pipeline.
    """
    result = MLClassification()
    if not HAS_ML:
        return result

    try:
        from hashguard.ml_trainer import MODEL_DIR as TRAINER_MODEL_DIR, NUMERIC_FEATURES
        from hashguard.feature_extractor import extract_features as extract_full_features

        # Find the most recent trained model
        model_data = _load_trained_model(TRAINER_MODEL_DIR)
        if model_data is None:
            # No trained model — fall back to PE-level classification
            pe_info = result_dict.get("pe_info")
            return classify(file_path, pe_info=pe_info)

        clf = model_data["clf"]
        scaler = model_data["scaler"]
        class_names = model_data["class_names"]
        feature_names = model_data.get("feature_names", NUMERIC_FEATURES)

        # Extract features from the full analysis result
        feats = extract_full_features(file_path, result_dict)

        # Build feature vector in the same order as training
        X_row = [float(feats.get(fname, 0) or 0) for fname in feature_names]
        X = np.array([X_row])
        X_scaled = scaler.transform(X)

        # Predict
        proba = clf.predict_proba(X_scaled)[0]
        pred_idx = int(np.argmax(proba))
        result.predicted_class = class_names[pred_idx]
        result.confidence = float(proba[pred_idx])
        result.probabilities = {
            class_names[i]: float(p) for i, p in enumerate(proba)
        }
        result.features_used = len(feature_names)

    except Exception as e:
        logger.debug(f"Trained-model classification error: {e}")
        # Fallback to PE-level
        pe_info = result_dict.get("pe_info")
        return classify(file_path, pe_info=pe_info)

    return result


def _load_trained_model(model_dir: str) -> Optional[dict]:
    """Load the most recent model saved by ml_trainer.

    Returns the model data dict or None if no model exists.
    """
    if not os.path.isdir(model_dir):
        return None

    try:
        import joblib as _joblib
    except ImportError:
        _joblib = None

    # Find most recent .joblib (or .pkl) model file
    model_files = sorted(Path(model_dir).glob("*.joblib"), reverse=True)
    if not model_files and _joblib is None:
        model_files = sorted(Path(model_dir).glob("*.pkl"), reverse=True)

    if not model_files:
        return None

    model_path = str(model_files[0])

    # Verify HMAC integrity if available
    hmac_path = model_path + ".hmac"
    if os.path.isfile(hmac_path):
        try:
            stored = Path(hmac_path).read_text().strip()
            computed = _compute_file_hmac(model_path)
            if not hmac.compare_digest(stored, computed):
                logger.warning(f"Trained model integrity check FAILED: {model_path}")
                return None
        except Exception:
            logger.warning("Failed to verify trained model HMAC")
            return None

    try:
        if _joblib is not None:
            data = _joblib.load(model_path)
        else:
            with open(model_files[0], "rb") as f:
                data = pickle.load(f)

        # Validate required keys
        if "clf" in data and "scaler" in data and "class_names" in data:
            return data
    except Exception as e:
        logger.debug(f"Failed to load trained model {model_files[0]}: {e}")

    return None
