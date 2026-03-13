"""Numerical feature extraction for the HashGuard ML dataset.

Extracts ~80 numeric features from a file and its analysis result,
producing a flat dict suitable for ML training (CSV / Parquet export).

Features are grouped into categories:
- **file**: size, entropy, byte histogram stats
- **pe**: section count, import count, suspicious API count, entropy stats
- **strings**: total count, IOC counts by type
- **yara**: hit count, max severity score
- **ti**: flagged source count, total sources queried
- **capabilities**: count per category, max severity
- **risk**: final score, factor count
"""

from __future__ import annotations

import json
import math
import os
from typing import Any, Dict, List, Optional

from hashguard.logger import get_logger

logger = get_logger(__name__)

# Severity → numeric mapping (used for YARA and capabilities)
_SEVERITY_MAP = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _safe_get(d: Optional[dict], *keys: str, default: Any = 0) -> Any:
    """Walk nested dict keys, returning *default* on any miss."""
    current = d
    for k in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(k, default)
    return current if current is not None else default


# ── Byte-level features ────────────────────────────────────────────────────


def _byte_histogram(path: str) -> List[int]:
    """Return 256-bin histogram of byte values for the file."""
    hist = [0] * 256
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                for b in chunk:
                    hist[b] += 1
    except Exception:
        pass
    return hist


def _histogram_stats(hist: List[int]) -> Dict[str, float]:
    """Compute summary statistics from a byte histogram."""
    total = sum(hist)
    if total == 0:
        return {
            "byte_entropy": 0.0,
            "byte_mean": 0.0,
            "byte_std": 0.0,
            "byte_zero_ratio": 0.0,
            "byte_printable_ratio": 0.0,
            "byte_high_ratio": 0.0,
        }

    # Entropy
    entropy = 0.0
    for count in hist:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)

    # Mean / std
    mean = sum(i * c for i, c in enumerate(hist)) / total
    variance = sum(c * (i - mean) ** 2 for i, c in enumerate(hist)) / total
    std = math.sqrt(variance)

    # Ratios
    zero_ratio = hist[0] / total
    printable = sum(hist[i] for i in range(32, 127)) / total
    high = sum(hist[i] for i in range(128, 256)) / total

    return {
        "byte_entropy": round(entropy, 4),
        "byte_mean": round(mean, 4),
        "byte_std": round(std, 4),
        "byte_zero_ratio": round(zero_ratio, 6),
        "byte_printable_ratio": round(printable, 6),
        "byte_high_ratio": round(high, 6),
    }


# ── Feature extraction ─────────────────────────────────────────────────────


def extract_features(
    file_path: str,
    result_dict: dict,
    mb_metadata: Optional[dict] = None,
) -> Dict[str, Any]:
    """Extract numerical features from a file + its analysis result.

    Parameters
    ----------
    file_path:
        Path to the analysed file on disk.
    result_dict:
        The full analysis result dict (``FileAnalysisResult.to_dict()``).
    mb_metadata:
        Optional MalwareBazaar sample metadata dict.  When provided,
        ground-truth labels (family, tags) are taken from the feed
        instead of the scanner's own verdict.

    Returns
    -------
    Flat dict with ~80 numeric features keyed by descriptive names.
    All values are int / float / str (label fields only).
    """

    features: Dict[str, Any] = {}

    # ── 1. File-level features ──────────────────────────────────────────────

    file_size = result_dict.get("file_size", 0)
    features["file_size"] = file_size
    features["file_size_log"] = round(math.log2(file_size + 1), 4)

    # Byte histogram
    if os.path.isfile(file_path):
        hist = _byte_histogram(file_path)
        features.update(_histogram_stats(hist))
    else:
        features.update({
            "byte_entropy": 0.0,
            "byte_mean": 0.0,
            "byte_std": 0.0,
            "byte_zero_ratio": 0.0,
            "byte_printable_ratio": 0.0,
            "byte_high_ratio": 0.0,
        })

    # ── 2. PE features ──────────────────────────────────────────────────────

    pe = result_dict.get("pe_info") or {}
    features["pe_is_pe"] = 1 if pe.get("is_pe") else 0
    features["pe_section_count"] = len(pe.get("sections", []))

    sections = pe.get("sections", [])
    if sections:
        entropies = [s.get("entropy", 0) for s in sections]
        raw_sizes = [s.get("raw_size", 0) for s in sections]
        features["pe_entropy_mean"] = round(sum(entropies) / len(entropies), 4)
        features["pe_entropy_max"] = round(max(entropies), 4)
        features["pe_entropy_min"] = round(min(entropies), 4)
        features["pe_raw_size_total"] = sum(raw_sizes)
        features["pe_raw_size_max"] = max(raw_sizes)
        features["pe_high_entropy_sections"] = sum(1 for e in entropies if e > 6.5)
    else:
        features["pe_entropy_mean"] = 0.0
        features["pe_entropy_max"] = 0.0
        features["pe_entropy_min"] = 0.0
        features["pe_raw_size_total"] = 0
        features["pe_raw_size_max"] = 0
        features["pe_high_entropy_sections"] = 0

    imports = pe.get("imports", {})
    features["pe_import_dll_count"] = len(imports)
    features["pe_import_func_count"] = sum(len(v) for v in imports.values())
    features["pe_suspicious_import_count"] = len(pe.get("suspicious_imports", []))
    features["pe_packed"] = 1 if pe.get("packed") else 0
    features["pe_overall_entropy"] = pe.get("overall_entropy", 0.0)

    # Advanced PE
    adv = result_dict.get("advanced_pe") or {}
    features["pe_has_tls"] = 1 if _safe_get(adv, "tls", "has_tls") else 0
    features["pe_anti_analysis_count"] = _safe_get(adv, "anti_analysis", "total_detections")

    # ── 3. String features ──────────────────────────────────────────────────

    strings = result_dict.get("strings_info") or {}
    features["str_total_count"] = strings.get("total_strings", 0)
    features["str_has_iocs"] = 1 if strings.get("has_iocs") else 0
    features["str_url_count"] = len(strings.get("urls", []))
    features["str_ip_count"] = len(strings.get("ips", []))
    features["str_domain_count"] = len(strings.get("domains", []))
    features["str_email_count"] = len(strings.get("emails", []))
    features["str_crypto_wallet_count"] = len(strings.get("crypto_wallets", []))
    features["str_registry_key_count"] = len(strings.get("registry_keys", []))
    features["str_powershell_count"] = len(strings.get("powershell_commands", []))
    features["str_user_agent_count"] = len(strings.get("user_agents", []))
    features["str_suspicious_path_count"] = len(strings.get("suspicious_paths", []))

    # ── 4. YARA features ────────────────────────────────────────────────────

    yara = result_dict.get("yara_matches") or {}
    matches = yara.get("matches", [])
    features["yara_rules_loaded"] = yara.get("rules_loaded", 0)
    features["yara_match_count"] = len(matches)

    if matches:
        severities = [_SEVERITY_MAP.get(m.get("meta", {}).get("severity", ""), 0) for m in matches]
        features["yara_max_severity"] = max(severities)
        features["yara_total_severity"] = sum(severities)
        features["yara_string_hit_count"] = sum(len(m.get("strings", [])) for m in matches)
        # Category counts
        cats: Dict[str, int] = {}
        for m in matches:
            cat = m.get("meta", {}).get("category", "unknown")
            cats[cat] = cats.get(cat, 0) + 1
        features["yara_unique_categories"] = len(cats)
    else:
        features["yara_max_severity"] = 0
        features["yara_total_severity"] = 0
        features["yara_string_hit_count"] = 0
        features["yara_unique_categories"] = 0

    # ── 5. Threat Intel features ────────────────────────────────────────────
    #
    # In batch_mode the scanner skips HTTP threat-intel queries, so
    # result_dict["threat_intel"] is None.  When MalwareBazaar metadata
    # is available we derive the TI features from it — MalwareBazaar IS
    # a threat-intel source and the sample IS flagged there.

    ti = result_dict.get("threat_intel") or {}
    if ti:
        # Full pipeline ran — use real TI data
        features["ti_total_sources"] = ti.get("total_sources", 0)
        features["ti_flagged_count"] = ti.get("flagged_count", 0)
        features["ti_successful_sources"] = ti.get("successful_sources", 0)
        hits = ti.get("hits", [])
        features["ti_total_tags"] = sum(len(h.get("tags", [])) for h in hits)
        features["ti_has_family"] = 1 if any(h.get("malware_family") for h in hits) else 0
    elif mb_metadata:
        # Batch mode — derive from MalwareBazaar metadata (no extra HTTP)
        mb_tags = mb_metadata.get("tags") or []
        mb_sig = mb_metadata.get("signature") or ""
        features["ti_total_sources"] = 1       # MalwareBazaar
        features["ti_flagged_count"] = 1       # present in malware feed
        features["ti_successful_sources"] = 1
        features["ti_total_tags"] = len(mb_tags)
        features["ti_has_family"] = 1 if mb_sig else 0
    else:
        features["ti_total_sources"] = 0
        features["ti_flagged_count"] = 0
        features["ti_successful_sources"] = 0
        features["ti_total_tags"] = 0
        features["ti_has_family"] = 0

    # ── 6. Capability features ──────────────────────────────────────────────

    caps = result_dict.get("capabilities") or {}
    cap_list = caps.get("capabilities", [])
    features["cap_total_detected"] = caps.get("total_detected", 0)

    risk_cats = caps.get("risk_categories", {})
    for cat in ["ransomware", "reverse_shell", "credential_stealing", "persistence",
                "evasion", "keylogger", "data_exfil"]:
        features[f"cap_{cat}"] = risk_cats.get(cat, 0)

    cap_max_sev = _SEVERITY_MAP.get(caps.get("max_severity", ""), 0)
    features["cap_max_severity"] = cap_max_sev

    if cap_list:
        confidences = [c.get("confidence", 0) for c in cap_list]
        features["cap_avg_confidence"] = round(sum(confidences) / len(confidences), 4)
        features["cap_max_confidence"] = round(max(confidences), 4)
    else:
        features["cap_avg_confidence"] = 0.0
        features["cap_max_confidence"] = 0.0

    # ── 7. Packer / shellcode features ──────────────────────────────────────

    packer = result_dict.get("packer") or {}
    features["packer_detected"] = 1 if packer.get("detected") else 0

    shellcode = result_dict.get("shellcode") or {}
    features["shellcode_detected"] = 1 if shellcode.get("detected") else 0
    sc_conf = {"high": 3, "medium": 2, "low": 1}.get(shellcode.get("confidence", ""), 0)
    features["shellcode_confidence"] = sc_conf

    # ── 8. Risk score features ──────────────────────────────────────────────

    risk = result_dict.get("risk_score") or {}
    features["risk_score"] = risk.get("score", 0)
    features["risk_factor_count"] = len(risk.get("factors", []))

    if risk.get("factors"):
        points = [f.get("points", 0) for f in risk["factors"]]
        features["risk_max_factor"] = max(points)
        features["risk_total_points"] = sum(points)
    else:
        features["risk_max_factor"] = 0
        features["risk_total_points"] = 0

    # ── 9. Label fields (not features, but needed for training) ─────────────
    #
    # When MalwareBazaar metadata is available we use analyst-verified
    # labels (ground truth).  Otherwise we fall back to the scanner's
    # own verdict — but mark the source so the trainer can filter.

    if mb_metadata:
        features["label_source"] = "malwarebazaar"
        features["label_is_malicious"] = 1  # everything from MB is malicious
        features["label_verdict"] = "malicious"
        features["label_family"] = mb_metadata.get("signature") or ""
        features["label_family_confidence"] = 1.0  # analyst-verified
        tags = mb_metadata.get("tags") or []
        features["label_mb_tags"] = json.dumps(tags) if tags else "[]"
        features["label_mb_signature"] = mb_metadata.get("signature") or ""
    else:
        features["label_source"] = "scanner"
        features["label_verdict"] = risk.get("verdict", "unknown")
        features["label_is_malicious"] = 1 if result_dict.get("malicious") else 0
        family = result_dict.get("family_detection") or {}
        features["label_family"] = family.get("family", "")
        features["label_family_confidence"] = family.get("confidence", 0.0)
        features["label_mb_tags"] = "[]"
        features["label_mb_signature"] = ""

    return features


# ── Column schema (for table creation) ─────────────────────────────────────

# Every key from extract_features() with its SQL type.
# label_* columns are TEXT/REAL, everything else is INTEGER or REAL.
FEATURE_COLUMNS: Dict[str, str] = {
    # File
    "file_size": "INTEGER",
    "file_size_log": "REAL",
    "byte_entropy": "REAL",
    "byte_mean": "REAL",
    "byte_std": "REAL",
    "byte_zero_ratio": "REAL",
    "byte_printable_ratio": "REAL",
    "byte_high_ratio": "REAL",
    # PE
    "pe_is_pe": "INTEGER",
    "pe_section_count": "INTEGER",
    "pe_entropy_mean": "REAL",
    "pe_entropy_max": "REAL",
    "pe_entropy_min": "REAL",
    "pe_raw_size_total": "INTEGER",
    "pe_raw_size_max": "INTEGER",
    "pe_high_entropy_sections": "INTEGER",
    "pe_import_dll_count": "INTEGER",
    "pe_import_func_count": "INTEGER",
    "pe_suspicious_import_count": "INTEGER",
    "pe_packed": "INTEGER",
    "pe_overall_entropy": "REAL",
    "pe_has_tls": "INTEGER",
    "pe_anti_analysis_count": "INTEGER",
    # Strings
    "str_total_count": "INTEGER",
    "str_has_iocs": "INTEGER",
    "str_url_count": "INTEGER",
    "str_ip_count": "INTEGER",
    "str_domain_count": "INTEGER",
    "str_email_count": "INTEGER",
    "str_crypto_wallet_count": "INTEGER",
    "str_registry_key_count": "INTEGER",
    "str_powershell_count": "INTEGER",
    "str_user_agent_count": "INTEGER",
    "str_suspicious_path_count": "INTEGER",
    # YARA
    "yara_rules_loaded": "INTEGER",
    "yara_match_count": "INTEGER",
    "yara_max_severity": "INTEGER",
    "yara_total_severity": "INTEGER",
    "yara_string_hit_count": "INTEGER",
    "yara_unique_categories": "INTEGER",
    # Threat Intel
    "ti_total_sources": "INTEGER",
    "ti_flagged_count": "INTEGER",
    "ti_successful_sources": "INTEGER",
    "ti_total_tags": "INTEGER",
    "ti_has_family": "INTEGER",
    # Capabilities
    "cap_total_detected": "INTEGER",
    "cap_ransomware": "INTEGER",
    "cap_reverse_shell": "INTEGER",
    "cap_credential_stealing": "INTEGER",
    "cap_persistence": "INTEGER",
    "cap_evasion": "INTEGER",
    "cap_keylogger": "INTEGER",
    "cap_data_exfil": "INTEGER",
    "cap_max_severity": "INTEGER",
    "cap_avg_confidence": "REAL",
    "cap_max_confidence": "REAL",
    # Packer / Shellcode
    "packer_detected": "INTEGER",
    "shellcode_detected": "INTEGER",
    "shellcode_confidence": "INTEGER",
    # Risk
    "risk_score": "INTEGER",
    "risk_factor_count": "INTEGER",
    "risk_max_factor": "INTEGER",
    "risk_total_points": "INTEGER",
    # Labels
    "label_verdict": "TEXT",
    "label_is_malicious": "INTEGER",
    "label_family": "TEXT",
    "label_family_confidence": "REAL",
    # Ground truth source metadata
    "label_source": "TEXT",
    "label_mb_tags": "TEXT",
    "label_mb_signature": "TEXT",
}
