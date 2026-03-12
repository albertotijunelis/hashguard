"""
HashGuard - Malware Research Platform

Advanced malware analysis platform with static analysis, capability detection,
ML classification, fuzzy hashing, IOC graphing, timeline analysis, and a
modern web dashboard.

Version: 1.1.2
License: Elastic-2.0
Author: Alberto Tijunelis Neto
"""

__version__ = "1.1.2"
__author__ = "Alberto Tijunelis Neto"
__license__ = "Elastic-2.0"

import warnings as _warnings

try:
    from requests import RequestsDependencyWarning as _RDW

    _warnings.filterwarnings("ignore", category=_RDW)
except ImportError:
    pass

from hashguard.scanner import analyze, analyze_url, compute_hashes, is_malware
from hashguard.pe_analyzer import analyze_pe
from hashguard.yara_scanner import scan_file as yara_scan
from hashguard.threat_intel import query_all as query_threat_intel
from hashguard.risk_scorer import compute_risk
from hashguard.string_extractor import extract_strings

# ML & Dataset modules (lazy-safe: import errors caught at call time)
try:
    from hashguard.ml_trainer import start_training, predict_sample, list_models
    from hashguard.feature_extractor import extract_features
    from hashguard.batch_ingest import start_ingest

    _HAS_ML = True
except ImportError:
    _HAS_ML = False

try:
    from hashguard.stix_exporter import export_stix_bundle
except ImportError:
    pass

__all__ = [
    "analyze",
    "analyze_url",
    "compute_hashes",
    "is_malware",
    "analyze_pe",
    "yara_scan",
    "query_threat_intel",
    "compute_risk",
    "extract_strings",
    # ML pipeline
    "start_training",
    "predict_sample",
    "list_models",
    "extract_features",
    "start_ingest",
    # STIX export
    "export_stix_bundle",
    "__version__",
]
