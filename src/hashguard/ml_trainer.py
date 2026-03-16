"""ML Training Pipeline for HashGuard.

Trains supervised classifiers on the dataset_features table.
Supports:
  - Binary classification (malicious vs benign)
  - Multi-family classification (by malware family)
  - Random Forest, Gradient Boosting, or ensemble
  - Train/test split with stratified k-fold cross-validation
  - Metrics: accuracy, precision, recall, F1, ROC-AUC
  - Feature importance ranking
  - Model persistence via joblib
"""

import hashlib
import hmac as _hmac
import json
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from hashguard.logger import get_logger

logger = get_logger(__name__)

try:
    import numpy as np
    from sklearn.ensemble import (
        GradientBoostingClassifier,
        RandomForestClassifier,
        VotingClassifier,
    )
    from sklearn.metrics import (
        accuracy_score,
        classification_report,
        confusion_matrix,
        f1_score,
        precision_score,
        recall_score,
        roc_auc_score,
    )
    from sklearn.model_selection import StratifiedKFold, train_test_split
    from sklearn.preprocessing import LabelEncoder, StandardScaler

    HAS_ML = True
except ImportError:
    HAS_ML = False

try:
    import joblib

    HAS_JOBLIB = True
except ImportError:
    HAS_JOBLIB = False


MODEL_DIR = os.path.join(
    os.environ.get("APPDATA", os.path.expanduser("~")), "HashGuard", "models"
)

_HMAC_KEY = b"HashGuard-ML-Integrity-v4"


def _compute_file_hmac(path: str) -> str:
    """Compute HMAC-SHA256 of a file for integrity verification."""
    h = _hmac.new(_HMAC_KEY, digestmod=hashlib.sha256)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify_model_hmac(model_path: str) -> bool:
    """Verify HMAC of a model file. Returns True if valid or no HMAC exists yet."""
    hmac_path = model_path + ".hmac"
    if not os.path.isfile(hmac_path):
        return True  # Legacy model without HMAC — allow but log
    try:
        stored = Path(hmac_path).read_text().strip()
        computed = _compute_file_hmac(model_path)
        return _hmac.compare_digest(stored, computed)
    except Exception:
        return False

# Numeric feature columns from feature_extractor.FEATURE_COLUMNS
# (excludes label_* text columns)
NUMERIC_FEATURES: List[str] = [
    "file_size", "file_size_log", "byte_entropy", "byte_mean", "byte_std",
    "byte_zero_ratio", "byte_printable_ratio", "byte_high_ratio",
    "pe_is_pe", "pe_section_count", "pe_entropy_mean", "pe_entropy_max",
    "pe_entropy_min", "pe_raw_size_total", "pe_raw_size_max",
    "pe_high_entropy_sections", "pe_import_dll_count", "pe_import_func_count",
    "pe_suspicious_import_count", "pe_packed", "pe_overall_entropy",
    "pe_has_tls", "pe_anti_analysis_count",
    "str_total_count", "str_has_iocs", "str_url_count", "str_ip_count",
    "str_domain_count", "str_email_count", "str_crypto_wallet_count",
    "str_registry_key_count", "str_powershell_count", "str_user_agent_count",
    "str_suspicious_path_count",
    "yara_rules_loaded", "yara_match_count", "yara_max_severity",
    "yara_total_severity", "yara_string_hit_count", "yara_unique_categories",
    "ti_total_sources", "ti_flagged_count", "ti_successful_sources",
    "ti_total_tags", "ti_has_family",
    "cap_total_detected", "cap_ransomware", "cap_reverse_shell",
    "cap_credential_stealing", "cap_persistence", "cap_evasion",
    "cap_keylogger", "cap_data_exfil", "cap_max_severity",
    "cap_avg_confidence", "cap_max_confidence",
    "packer_detected", "shellcode_detected", "shellcode_confidence",
    "risk_score", "risk_factor_count", "risk_max_factor", "risk_total_points",
]

ALGORITHMS = ("random_forest", "gradient_boosting", "ensemble")
MODES = ("binary", "family")


@dataclass
class TrainingMetrics:
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    roc_auc: float = 0.0
    cv_accuracy_mean: float = 0.0
    cv_accuracy_std: float = 0.0
    confusion_matrix: List[List[int]] = field(default_factory=list)
    class_report: Dict[str, Any] = field(default_factory=dict)
    feature_importance: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "accuracy": round(self.accuracy, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "roc_auc": round(self.roc_auc, 4),
            "cv_accuracy_mean": round(self.cv_accuracy_mean, 4),
            "cv_accuracy_std": round(self.cv_accuracy_std, 4),
            "confusion_matrix": self.confusion_matrix,
            "class_report": self.class_report,
            "feature_importance": self.feature_importance[:20],
        }


@dataclass
class TrainedModel:
    model_id: str = ""
    mode: str = "binary"
    algorithm: str = "random_forest"
    created_at: str = ""
    sample_count: int = 0
    feature_count: int = 0
    classes: List[str] = field(default_factory=list)
    metrics: TrainingMetrics = field(default_factory=TrainingMetrics)
    path: str = ""

    def to_dict(self) -> dict:
        return {
            "model_id": self.model_id,
            "mode": self.mode,
            "algorithm": self.algorithm,
            "created_at": self.created_at,
            "sample_count": self.sample_count,
            "feature_count": self.feature_count,
            "classes": self.classes,
            "metrics": self.metrics.to_dict(),
            "path": self.path,
        }


@dataclass
class TrainingJob:
    status: str = "idle"  # idle, running, completed, error
    started_at: str = ""
    finished_at: str = ""
    progress: float = 0.0
    message: str = ""
    model: Optional[TrainedModel] = None
    error: str = ""

    def to_dict(self) -> dict:
        d: Dict[str, Any] = {
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "progress": round(self.progress, 1),
            "message": self.message,
        }
        if self.model:
            d["model"] = self.model.to_dict()
        if self.error:
            d["error"] = self.error
        return d


_current_job = TrainingJob()
_job_lock = threading.Lock()


def get_training_status() -> dict:
    with _job_lock:
        return _current_job.to_dict()


# ── Data loading ─────────────────────────────────────────────────────────────


def _load_dataset_from_db() -> Tuple[Optional[Any], Optional[Any], Optional[List[str]], List[str]]:
    """Load feature matrix and labels from dataset_features table.

    Returns (X, y_binary, families, feature_names) or (None, None, None, []).
    """
    if not HAS_ML:
        return None, None, None, []

    from hashguard.database import get_connection, init_db, _ensure_dataset_table

    init_db()
    _ensure_dataset_table()
    conn = get_connection()

    cols_sql = ", ".join(NUMERIC_FEATURES + ["label_is_malicious", "label_family", "label_source"])
    rows = conn.execute(
        f"SELECT {cols_sql} FROM dataset_features"
    ).fetchall()

    if not rows:
        return None, None, None, []

    X = []
    y_binary = []
    families = []
    skipped = 0
    for row in rows:
        feats = [float(row[col] or 0) for col in NUMERIC_FEATURES]
        # Data validation: skip rows with NaN/inf
        if any(not np.isfinite(v) for v in feats):
            skipped += 1
            continue
        X.append(feats)
        y_binary.append(int(row["label_is_malicious"]))
        families.append(str(row["label_family"] or "unknown"))

    if skipped:
        logger.info(f"Skipped {skipped} rows with NaN/inf values")

    if not X:
        return None, None, None, []

    return np.array(X), np.array(y_binary), families, NUMERIC_FEATURES


def _generate_synthetic_benign(n_samples: int, n_features: int, rng: np.random.Generator) -> np.ndarray:
    """Generate synthetic benign samples with realistic distributions.

    Uses low-risk feature profiles: low entropy, no suspicious imports,
    no YARA matches, no TI hits, low risk scores.
    """
    X = np.zeros((n_samples, n_features))

    for i, name in enumerate(NUMERIC_FEATURES[:n_features]):
        if name == "file_size":
            X[:, i] = rng.lognormal(mean=15, sigma=2, size=n_samples).clip(1000, 500_000_000)
        elif name == "file_size_log":
            X[:, i] = np.log2(X[:, NUMERIC_FEATURES.index("file_size")].clip(1))
        elif name == "byte_entropy":
            X[:, i] = rng.normal(5.5, 1.0, n_samples).clip(0, 8)
        elif name in ("byte_mean", "byte_std"):
            X[:, i] = rng.normal(100, 30, n_samples).clip(0, 255)
        elif name.startswith("byte_") and "ratio" in name:
            X[:, i] = rng.beta(2, 5, n_samples)
        elif name == "pe_is_pe":
            X[:, i] = rng.choice([0, 1], n_samples, p=[0.3, 0.7])
        elif name == "pe_section_count":
            X[:, i] = rng.poisson(5, n_samples).clip(0, 20)
        elif name.startswith("pe_entropy"):
            X[:, i] = rng.normal(5.0, 1.2, n_samples).clip(0, 8)
        elif name in ("pe_import_dll_count",):
            X[:, i] = rng.poisson(8, n_samples)
        elif name in ("pe_import_func_count",):
            X[:, i] = rng.poisson(150, n_samples)
        elif name == "pe_suspicious_import_count":
            X[:, i] = rng.poisson(0.5, n_samples).clip(0, 5)
        elif name in ("pe_packed", "pe_has_tls"):
            X[:, i] = rng.choice([0, 1], n_samples, p=[0.95, 0.05])
        elif name == "pe_anti_analysis_count":
            X[:, i] = rng.poisson(0.1, n_samples).clip(0, 2)
        elif name == "str_total_count":
            X[:, i] = rng.poisson(200, n_samples)
        elif name.startswith("str_") and name != "str_has_iocs":
            X[:, i] = rng.poisson(0.3, n_samples).clip(0, 3)
        elif name == "str_has_iocs":
            X[:, i] = rng.choice([0, 1], n_samples, p=[0.9, 0.1])
        elif name.startswith("yara_") or name.startswith("ti_"):
            X[:, i] = 0  # benign files: no YARA/TI hits
        elif name.startswith("cap_"):
            X[:, i] = 0  # benign files: no malicious capabilities
        elif name in ("packer_detected", "shellcode_detected"):
            X[:, i] = 0
        elif name == "shellcode_confidence":
            X[:, i] = 0
        elif name == "risk_score":
            X[:, i] = rng.uniform(0, 20, n_samples)
        elif name == "risk_factor_count":
            X[:, i] = rng.poisson(1, n_samples).clip(0, 3)
        elif name in ("risk_max_factor", "risk_total_points"):
            X[:, i] = rng.uniform(0, 10, n_samples)
        else:
            X[:, i] = rng.normal(0, 1, n_samples).clip(0)

    return X


# ── Training ─────────────────────────────────────────────────────────────────


def _build_classifier(algorithm: str, n_classes: int):
    """Create a classifier instance based on algorithm name."""
    if algorithm == "random_forest":
        return RandomForestClassifier(
            n_estimators=200, max_depth=12, random_state=42, n_jobs=-1
        )
    elif algorithm == "gradient_boosting":
        return GradientBoostingClassifier(
            n_estimators=200, max_depth=6, learning_rate=0.1,
            subsample=0.8, random_state=42,
        )
    else:  # ensemble
        rf = RandomForestClassifier(
            n_estimators=200, max_depth=12, random_state=42, n_jobs=-1
        )
        gbt = GradientBoostingClassifier(
            n_estimators=200, max_depth=6, learning_rate=0.1,
            subsample=0.8, random_state=42,
        )
        return VotingClassifier(
            estimators=[("rf", rf), ("gbt", gbt)], voting="soft"
        )


def _compute_metrics(
    clf, X_train: np.ndarray, y_train: np.ndarray,
    X_test: np.ndarray, y_test: np.ndarray,
    class_names: List[str], feature_names: List[str],
) -> TrainingMetrics:
    """Compute all training metrics."""
    metrics = TrainingMetrics()

    y_pred = clf.predict(X_test)
    average = "binary" if len(class_names) == 2 else "weighted"

    metrics.accuracy = float(accuracy_score(y_test, y_pred))
    metrics.precision = float(precision_score(y_test, y_pred, average=average, zero_division=0))
    metrics.recall = float(recall_score(y_test, y_pred, average=average, zero_division=0))
    metrics.f1 = float(f1_score(y_test, y_pred, average=average, zero_division=0))

    # ROC-AUC
    try:
        if hasattr(clf, "predict_proba"):
            y_proba = clf.predict_proba(X_test)
            if len(class_names) == 2:
                metrics.roc_auc = float(roc_auc_score(y_test, y_proba[:, 1]))
            else:
                metrics.roc_auc = float(
                    roc_auc_score(y_test, y_proba, multi_class="ovr", average="weighted")
                )
    except (ValueError, IndexError):
        metrics.roc_auc = 0.0

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    metrics.confusion_matrix = cm.tolist()

    # Classification report
    report = classification_report(
        y_test, y_pred, target_names=class_names, output_dict=True, zero_division=0
    )
    # Clean numpy types from report
    clean_report = {}
    for k, v in report.items():
        if isinstance(v, dict):
            clean_report[k] = {kk: round(float(vv), 4) for kk, vv in v.items()}
        else:
            clean_report[k] = round(float(v), 4)
    metrics.class_report = clean_report

    # Cross-validation
    try:
        n_splits = min(5, len(np.unique(y_train)))
        if n_splits >= 2 and len(y_train) >= n_splits * 2:
            cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
            cv_scores = []
            for train_idx, val_idx in cv.split(X_train, y_train):
                temp_clf = RandomForestClassifier(
                    n_estimators=100, max_depth=12, random_state=42, n_jobs=-1
                )
                temp_clf.fit(X_train[train_idx], y_train[train_idx])
                cv_scores.append(temp_clf.score(X_train[val_idx], y_train[val_idx]))
            metrics.cv_accuracy_mean = float(np.mean(cv_scores))
            metrics.cv_accuracy_std = float(np.std(cv_scores))
    except Exception as e:
        logger.debug(f"CV error: {e}")

    # Feature importance
    try:
        if hasattr(clf, "feature_importances_"):
            importances = clf.feature_importances_
        elif hasattr(clf, "estimators_"):
            # VotingClassifier: average importances from sub-estimators
            imp_list = []
            for _, est in clf.estimators_:
                if hasattr(est, "feature_importances_"):
                    imp_list.append(est.feature_importances_)
            if imp_list:
                importances = np.mean(imp_list, axis=0)
            else:
                importances = None
        else:
            importances = None

        if importances is not None:
            pairs = sorted(
                zip(feature_names, importances.tolist()),
                key=lambda x: x[1], reverse=True,
            )
            metrics.feature_importance = [
                {"feature": name, "importance": round(imp, 6)}
                for name, imp in pairs
            ]
    except Exception as e:
        logger.debug(f"Feature importance error: {e}")

    return metrics


def _train_model(
    mode: str = "binary",
    algorithm: str = "random_forest",
    test_size: float = 0.2,
) -> TrainedModel:
    """Core training logic. Runs synchronously."""
    if not HAS_ML:
        raise RuntimeError("scikit-learn is required for ML training")

    with _job_lock:
        _current_job.progress = 5.0
        _current_job.message = "Loading dataset from database..."

    X, y_binary, families, feature_names = _load_dataset_from_db()
    if X is None or len(X) == 0:
        raise ValueError("No samples in dataset. Run batch ingest first.")

    n_real = len(X)
    logger.info(f"Loaded {n_real} samples with {len(feature_names)} features")

    with _job_lock:
        _current_job.progress = 15.0
        _current_job.message = f"Loaded {n_real} samples..."

    # Determine labels and class names
    if mode == "family":
        # Multi-class by family
        unique_families = sorted(set(families))
        if len(unique_families) < 2:
            raise ValueError(
                f"Need at least 2 families for family classification, got {len(unique_families)}"
            )
        le = LabelEncoder()
        y = le.fit_transform(families)
        class_names = le.classes_.tolist()
    else:
        # Binary: malicious vs benign
        y = y_binary.copy()
        class_names = ["benign", "malicious"]

        # If all samples are the same class, augment with synthetic benign
        n_malicious = int(np.sum(y == 1))
        n_benign = int(np.sum(y == 0))

        if n_benign == 0:
            n_synth = max(n_malicious, 50)
            logger.info(f"No benign samples — generating {n_synth} synthetic benign samples")

            with _job_lock:
                _current_job.progress = 20.0
                _current_job.message = f"Generating {n_synth} synthetic benign samples..."

            rng = np.random.default_rng(42)
            X_benign = _generate_synthetic_benign(n_synth, len(feature_names), rng)
            X = np.vstack([X, X_benign])
            y = np.concatenate([y, np.zeros(n_synth, dtype=int)])

    with _job_lock:
        _current_job.progress = 30.0
        _current_job.message = "Splitting train/test sets..."

    # Train/test split
    n_classes = len(np.unique(y))
    min_class_count = min(np.bincount(y))

    if min_class_count >= 2 and len(X) >= 10:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
    else:
        # Not enough data for proper split — log a warning
        logger.warning(
            f"Small dataset ({len(X)} samples, min class={min_class_count}) "
            f"— metrics will be optimistic (no held-out test set)"
        )
        X_train, X_test, y_train, y_test = X, X, y, y

    # Scale features
    scaler = StandardScaler()
    X_train_sc = scaler.fit_transform(X_train)
    X_test_sc = scaler.transform(X_test)

    with _job_lock:
        _current_job.progress = 40.0
        _current_job.message = f"Training {algorithm} classifier..."

    # Train
    clf = _build_classifier(algorithm, n_classes)
    clf.fit(X_train_sc, y_train)

    with _job_lock:
        _current_job.progress = 70.0
        _current_job.message = "Computing metrics..."

    # Metrics
    metrics = _compute_metrics(
        clf, X_train_sc, y_train, X_test_sc, y_test, class_names, feature_names
    )

    logger.info(
        f"Training complete: acc={metrics.accuracy:.3f} f1={metrics.f1:.3f} "
        f"roc_auc={metrics.roc_auc:.3f}"
    )

    with _job_lock:
        _current_job.progress = 85.0
        _current_job.message = "Saving model..."

    # Save model
    model_id = datetime.now().strftime("%Y%m%d_%H%M%S") + f"_{mode}_{algorithm}"
    os.makedirs(MODEL_DIR, exist_ok=True)

    model_data = {
        "clf": clf,
        "scaler": scaler,
        "class_names": class_names,
        "feature_names": feature_names,
        "mode": mode,
        "algorithm": algorithm,
        "model_id": model_id,
        "created_at": datetime.now().isoformat(),
        "sample_count": n_real,
        "metrics": metrics.to_dict(),
    }

    model_path = os.path.join(MODEL_DIR, f"{model_id}.joblib")

    if HAS_JOBLIB:
        joblib.dump(model_data, model_path)
    else:
        import pickle
        with open(model_path, "wb") as f:
            pickle.dump(model_data, f)

    # Write HMAC for integrity verification
    Path(model_path + ".hmac").write_text(_compute_file_hmac(model_path))

    # Save metadata JSON alongside
    meta_path = os.path.join(MODEL_DIR, f"{model_id}.json")
    meta = {
        "model_id": model_id,
        "mode": mode,
        "algorithm": algorithm,
        "created_at": datetime.now().isoformat(),
        "sample_count": n_real,
        "feature_count": len(feature_names),
        "classes": class_names,
        "metrics": metrics.to_dict(),
        "model_file": os.path.basename(model_path),
    }
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    model = TrainedModel(
        model_id=model_id,
        mode=mode,
        algorithm=algorithm,
        created_at=meta["created_at"],
        sample_count=n_real,
        feature_count=len(feature_names),
        classes=class_names,
        metrics=metrics,
        path=model_path,
    )

    return model


# ── Public API ───────────────────────────────────────────────────────────────


def start_training(
    mode: str = "binary",
    algorithm: str = "random_forest",
    test_size: float = 0.2,
) -> dict:
    """Start a training job in a background thread.

    Returns {"started": True} or {"error": "..."}.
    """
    if mode not in MODES:
        return {"error": f"Invalid mode '{mode}', use one of {MODES}"}
    if algorithm not in ALGORITHMS:
        return {"error": f"Invalid algorithm '{algorithm}', use one of {ALGORITHMS}"}
    if not 0.05 <= test_size <= 0.5:
        return {"error": "test_size must be between 0.05 and 0.5"}

    with _job_lock:
        if _current_job.status == "running":
            return {"error": "A training job is already running"}
        _current_job.status = "running"
        _current_job.started_at = datetime.now().isoformat()
        _current_job.finished_at = ""
        _current_job.progress = 0.0
        _current_job.message = "Starting..."
        _current_job.model = None
        _current_job.error = ""

    def _run():
        try:
            model = _train_model(mode=mode, algorithm=algorithm, test_size=test_size)
            with _job_lock:
                _current_job.status = "completed"
                _current_job.finished_at = datetime.now().isoformat()
                _current_job.progress = 100.0
                _current_job.message = "Training complete"
                _current_job.model = model
        except Exception as e:
            logger.error(f"Training error: {e}")
            with _job_lock:
                _current_job.status = "error"
                _current_job.finished_at = datetime.now().isoformat()
                _current_job.error = "Training failed"
                _current_job.message = "Error: training failed"

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return {"started": True, "mode": mode, "algorithm": algorithm}


def list_models() -> List[dict]:
    """List all saved model metadata files."""
    models = []
    if not os.path.isdir(MODEL_DIR):
        return models
    for f in sorted(Path(MODEL_DIR).glob("*.json"), reverse=True):
        try:
            with open(f, "r", encoding="utf-8") as fh:
                meta = json.load(fh)
            models.append(meta)
        except Exception:
            pass
    return models


def _safe_model_path(model_id: str, ext: str) -> str:
    """Sanitize model_id and return a safe absolute path under MODEL_DIR."""
    import re
    safe = re.sub(r'[^a-zA-Z0-9._-]', '', model_id)
    if not safe or safe.startswith('.'):
        raise ValueError(f"Invalid model_id: {model_id!r}")
    path = os.path.join(MODEL_DIR, f"{safe}{ext}")
    real_path = os.path.realpath(path)
    real_model_dir = os.path.realpath(MODEL_DIR)
    if not real_path.startswith(real_model_dir + os.sep) and real_path != real_model_dir:
        raise ValueError(f"Invalid model_id: {model_id!r}")
    return real_path


def get_model_metrics(model_id: str) -> Optional[dict]:
    """Load metrics for a specific model by ID."""
    meta_path = _safe_model_path(model_id, ".json")
    real_meta = os.path.realpath(meta_path)
    real_base = os.path.realpath(MODEL_DIR)
    if not real_meta.startswith(real_base + os.sep):
        return None
    if not os.path.isfile(real_meta):
        return None
    with open(real_meta, "r", encoding="utf-8") as f:
        return json.load(f)


def delete_model(model_id: str) -> bool:
    """Delete a saved model and metadata."""
    deleted = False
    for ext in (".joblib", ".json"):
        p = _safe_model_path(model_id, ext)
        real_p = os.path.realpath(p)
        real_base = os.path.realpath(MODEL_DIR)
        if not real_p.startswith(real_base + os.sep):
            continue
        if os.path.isfile(real_p):
            os.remove(real_p)
            deleted = True
    return deleted


def predict_sample(features: Dict[str, float], model_id: Optional[str] = None) -> dict:
    """Run prediction on a feature dict using a trained model.

    If model_id is None, uses the most recent model.
    """
    if not HAS_ML:
        return {"error": "scikit-learn not available"}

    # Find model file
    if model_id:
        model_path = _safe_model_path(model_id, ".joblib")
    else:
        # Use most recent
        if not os.path.isdir(MODEL_DIR):
            return {"error": "No models found"}
        files = sorted(Path(MODEL_DIR).glob("*.joblib"), reverse=True)
        if not files:
            return {"error": "No models found"}
        model_path = str(files[0])

    if not os.path.isfile(model_path):
        return {"error": "Model file not found"}

    # Inline containment check before loading
    real_model = os.path.realpath(model_path)
    real_model_base = os.path.realpath(MODEL_DIR)
    if not real_model.startswith(real_model_base + os.sep):
        return {"error": "Invalid model path"}

    if not _verify_model_hmac(real_model):
        logger.warning("Model integrity check FAILED")
        return {"error": "Model integrity check failed"}

    try:
        if HAS_JOBLIB:
            data = joblib.load(real_model)
        else:
            import pickle
            with open(real_model, "rb") as f:
                data = pickle.load(f)
    except Exception as e:
        return {"error": "Failed to load model"}

    clf = data["clf"]
    scaler = data["scaler"]
    class_names = data["class_names"]
    feature_names = data["feature_names"]

    # Build feature vector
    X = np.array([[float(features.get(fn, 0)) for fn in feature_names]])
    X_sc = scaler.transform(X)

    pred_idx = int(clf.predict(X_sc)[0])
    proba = clf.predict_proba(X_sc)[0]

    return {
        "predicted_class": class_names[pred_idx],
        "confidence": round(float(proba[pred_idx]) * 100, 1),
        "probabilities": {
            class_names[i]: round(float(p) * 100, 1)
            for i, p in enumerate(proba)
        },
        "model_id": data.get("model_id", ""),
    }
