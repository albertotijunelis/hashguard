"""Batch sample ingest pipeline for the HashGuard ML dataset.

Downloads samples from public threat-intel feeds, runs the full analysis
pipeline on each, and stores extracted features in the dataset table.

Supported sources:
- **MalwareBazaar** (abuse.ch) — requires ``Auth-Key`` header
    - ``get_recent``: latest samples (up to 1000 per request)
    - ``get_taginfo``: samples by tag (e.g. "Emotet", "AgentTesla")
    - ``get_file_type``: samples by type (e.g. "exe", "dll")
- **URLhaus** (abuse.ch) — no authentication required
    - Recent malicious payloads (URLs + downloadable files)
- **MalShare** — requires ``MALSHARE_API_KEY``
    - Samples added in the last 24 hours
- **Hybrid Analysis** (CrowdStrike) — requires ``HYBRID_ANALYSIS_API_KEY``
    - Sandbox analysis results + downloadable samples
- **Triage** (Hatching / tria.ge) — requires ``TRIAGE_API_KEY``
    - Public sandbox submissions + downloadable samples
- **Local directory** — scan files already on disk (no API key needed)

Design principles:
- SHA-256 dedup: already-analysed samples are skipped automatically.
- Rate limiting: configurable delay between API calls (default 1 req/s).
- Quarantine: downloads are unpacked to a temp dir and deleted after analysis.
- Resilient: individual failures are logged and skipped, never abort the run.
- Thread-safe state: a single ``IngestJob`` tracks progress for the API/UI.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import queue
import shutil
import tempfile
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from hashguard.logger import get_logger

logger = get_logger(__name__)

# MalwareBazaar ZIP password (public knowledge, documented in their API)
_MB_ZIP_PASSWORD = b"infected"


# ── Ingest job state ───────────────────────────────────────────────────────


@dataclass
class IngestJob:
    """Tracks the progress of a batch ingest run (thread-safe reads)."""

    source: str = ""
    status: str = "idle"  # idle | running | stopping | done | error
    total_candidates: int = 0
    skipped_existing: int = 0
    downloaded: int = 0
    analysed: int = 0
    failed: int = 0
    current_sha256: str = ""
    started_at: float = 0.0
    finished_at: float = 0.0
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        elapsed = 0.0
        if self.started_at:
            end = self.finished_at or time.time()
            elapsed = round(end - self.started_at, 1)
        rate = 0.0
        if elapsed > 0 and self.analysed > 0:
            rate = round(self.analysed / (elapsed / 60), 1)  # samples/min
        eta_minutes = 0
        remaining = self.total_candidates - self.analysed - self.skipped_existing - self.failed
        if rate > 0 and remaining > 0:
            eta_minutes = round(remaining / rate)
        return {
            "source": self.source,
            "status": self.status,
            "total_candidates": self.total_candidates,
            "skipped_existing": self.skipped_existing,
            "downloaded": self.downloaded,
            "analysed": self.analysed,
            "failed": self.failed,
            "current_sha256": self.current_sha256,
            "elapsed_seconds": elapsed,
            "rate_per_minute": rate,
            "eta_minutes": eta_minutes,
            "errors": self.errors[-20:],  # last 20 errors
        }


# Global singleton — only one ingest job at a time
_current_job = IngestJob()
_job_lock = threading.Lock()
_stop_event = threading.Event()


def get_ingest_status() -> dict:
    """Return the current ingest job state (safe to call from any thread)."""
    return _current_job.to_dict()


def request_stop() -> None:
    """Signal the running ingest job to stop gracefully."""
    _stop_event.set()


# ── MalwareBazaar helpers ──────────────────────────────────────────────────


def _get_abuse_ch_key() -> Optional[str]:
    """Return the configured abuse.ch API key, or None."""
    key = os.getenv("ABUSE_CH_API_KEY")
    if key:
        return key
    try:
        from hashguard.config import get_default_config
        return get_default_config().abuse_ch_api_key
    except Exception:
        return None


def _mb_post(data: dict, timeout: int = 120, retries: int = 3) -> Optional[dict]:
    """POST to MalwareBazaar API and return parsed JSON, or None.

    Retries up to *retries* times on timeout / connection errors with
    exponential back-off (2s, 4s, 8s…).
    """
    try:
        import requests
    except ImportError:
        return None

    headers: Dict[str, str] = {}
    api_key = _get_abuse_ch_key()
    if api_key:
        headers["Auth-Key"] = api_key

    last_err: Optional[Exception] = None
    for attempt in range(retries):
        try:
            resp = requests.post(
                "https://mb-api.abuse.ch/api/v1/",
                data=data,
                headers=headers,
                timeout=timeout,
                verify=True,
            )
            if resp.status_code == 200:
                return resp.json()
            logger.debug(f"MalwareBazaar API HTTP {resp.status_code}")
            return None  # non-retriable HTTP error
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            last_err = e
            wait = 2 ** (attempt + 1)
            logger.debug(f"MalwareBazaar API attempt {attempt + 1}/{retries} failed: {e} — retrying in {wait}s")
            time.sleep(wait)
        except Exception as e:
            logger.debug(f"MalwareBazaar API error: {e}")
            return None

    logger.warning(f"MalwareBazaar API failed after {retries} retries: {last_err}")
    return None


def _mb_get_recent(limit: int = 100) -> List[dict]:
    """Fetch the most recent samples from MalwareBazaar.

    Returns a list of sample metadata dicts (sha256_hash, file_type, etc.).
    The API only accepts ``selector=100`` — any other value is rejected.
    For ``limit <= 100`` we fetch 100 and truncate.
    For ``limit > 100`` we return the 100 available (API hard limit).
    """
    # MalwareBazaar only accepts selector=100 — all other values are rejected
    data = _mb_post({"query": "get_recent", "selector": "100"})
    if data and data.get("query_status") == "ok":
        return data.get("data", [])[:limit]
    return []


def _mb_get_by_tag(tag: str, limit: int = 100) -> List[dict]:
    """Fetch samples by MalwareBazaar tag (e.g. ``Emotet``)."""
    tag = tag.strip()
    if not tag:
        return []
    fetch = min(max(1, limit), 1000)
    data = _mb_post({"query": "get_taginfo", "tag": tag, "limit": str(fetch)})
    if data and data.get("query_status") == "ok":
        return data.get("data", [])[:limit]
    return []


def _mb_get_by_filetype(file_type: str, limit: int = 100) -> List[dict]:
    """Fetch samples by file type (e.g. ``exe``, ``dll``, ``docx``).

    Strips leading dots so both ``exe`` and ``.exe`` work.
    Uses a longer timeout for slow types like ``exe``.
    """
    # Strip dots → ".exe" becomes "exe"
    file_type = file_type.strip().lstrip(".")
    if not file_type:
        return []
    fetch = min(max(1, limit), 1000)
    # "exe" queries are extremely slow on MalwareBazaar (~25-30s)
    timeout = 180 if file_type.lower() == "exe" else 120
    data = _mb_post(
        {"query": "get_file_type", "file_type": file_type, "limit": str(fetch)},
        timeout=timeout,
    )
    if data and data.get("query_status") == "ok":
        return data.get("data", [])[:limit]
    return []


def _mb_download_sample(sha256: str, dest_dir: str) -> Optional[str]:
    """Download a sample ZIP from MalwareBazaar, extract, return file path.

    The ZIP is password-protected with ``infected``.  The extracted file is
    placed into *dest_dir* named ``<sha256>``.
    """
    try:
        import requests
        headers: Dict[str, str] = {}
        api_key = _get_abuse_ch_key()
        if api_key:
            headers["Auth-Key"] = api_key
        resp = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_file", "sha256_hash": sha256},
            headers=headers,
            timeout=60,
            verify=True,
        )
        if resp.status_code != 200 or len(resp.content) < 100:
            return None

        # MalwareBazaar returns an AES-encrypted ZIP with password "infected"
        buf = io.BytesIO(resp.content)
        try:
            import pyzipper

            with pyzipper.AESZipFile(buf, "r") as zf:
                names = zf.namelist()
                if not names:
                    return None
                dest_path = os.path.join(dest_dir, sha256)
                with zf.open(names[0], pwd=_MB_ZIP_PASSWORD) as src, open(dest_path, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                return dest_path
        except ImportError:
            # Fallback to stdlib zipfile (works for non-AES zips)
            try:
                with zipfile.ZipFile(buf) as zf:
                    names = zf.namelist()
                    if not names:
                        return None
                    dest_path = os.path.join(dest_dir, sha256)
                    with zf.open(names[0], pwd=_MB_ZIP_PASSWORD) as src, open(dest_path, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    return dest_path
            except (zipfile.BadZipFile, RuntimeError) as e:
                logger.debug(f"Failed to extract ZIP for {sha256}: {e}")
                return None
        except (zipfile.BadZipFile, RuntimeError, Exception) as e:
            logger.debug(f"Failed to extract ZIP for {sha256}: {e}")
            return None
    except Exception as e:
        logger.debug(f"Download failed for {sha256}: {e}")
        return None


# ── API key helpers ────────────────────────────────────────────────────────


def _get_malshare_key() -> Optional[str]:
    """Return the configured MalShare API key, or None."""
    key = os.getenv("MALSHARE_API_KEY")
    if key:
        return key
    try:
        from hashguard.config import get_default_config
        return getattr(get_default_config(), "malshare_api_key", None)
    except Exception:
        return None


def _get_hybrid_analysis_key() -> Optional[str]:
    """Return the configured Hybrid Analysis API key, or None."""
    key = os.getenv("HYBRID_ANALYSIS_API_KEY")
    if key:
        return key
    try:
        from hashguard.config import get_default_config
        return getattr(get_default_config(), "hybrid_analysis_api_key", None)
    except Exception:
        return None


def _get_triage_key() -> Optional[str]:
    """Return the configured Triage API key, or None."""
    key = os.getenv("TRIAGE_API_KEY")
    if key:
        return key
    try:
        from hashguard.config import get_default_config
        return getattr(get_default_config(), "triage_api_key", None)
    except Exception:
        return None


# ── URLhaus helpers (abuse.ch) ─────────────────────────────────────────────


def _urlhaus_get_recent(limit: int = 100) -> List[dict]:
    """Fetch recent malicious payloads from URLhaus.

    URLhaus is a free abuse.ch service — no API key required for reads.
    Returns normalized dicts with ``sha256_hash`` and ``_source`` fields.
    """
    try:
        import requests
    except ImportError:
        return []
    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/payloads/recent/",
            data={"limit": str(min(limit, 1000))},
            timeout=60,
            verify=True,
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
        payloads = data.get("payloads", [])
        results: List[dict] = []
        for p in payloads[:limit]:
            sha256 = p.get("sha256_hash", "")
            if not sha256:
                continue
            results.append({
                "sha256_hash": sha256,
                "md5_hash": p.get("md5_hash", ""),
                "file_type": p.get("file_type") or "unknown",
                "file_size": p.get("file_size", 0),
                "signature": p.get("signature"),
                "tags": [t for t in [p.get("signature")] if t],
                "_source": "urlhaus",
            })
        return results
    except Exception as e:
        logger.debug(f"URLhaus API error: {e}")
        return []


def _urlhaus_download_payload(sha256: str, dest_dir: str) -> Optional[str]:
    """Download a payload from URLhaus by SHA-256.

    URLhaus returns a password-protected ZIP (password ``infected``).
    Falls back to writing raw bytes if the response is not a valid ZIP.
    """
    try:
        import requests
        resp = requests.get(
            f"https://urlhaus-api.abuse.ch/v1/download/{sha256}/",
            timeout=60,
            verify=True,
        )
        if resp.status_code != 200 or len(resp.content) < 100:
            return None
        buf = io.BytesIO(resp.content)
        dest_path = os.path.join(dest_dir, sha256)
        try:
            with zipfile.ZipFile(buf) as zf:
                names = zf.namelist()
                if not names:
                    return None
                with zf.open(names[0], pwd=_MB_ZIP_PASSWORD) as src, open(dest_path, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                return dest_path
        except (zipfile.BadZipFile, RuntimeError):
            # Not a ZIP — write raw bytes
            with open(dest_path, "wb") as f:
                f.write(resp.content)
            return dest_path
    except Exception as e:
        logger.debug(f"URLhaus download failed for {sha256}: {e}")
        return None


# ── MalShare helpers ───────────────────────────────────────────────────────


def _malshare_get_recent_24h(limit: int = 100) -> List[dict]:
    """Fetch samples added to MalShare in the last 24 hours.

    Requires ``MALSHARE_API_KEY``.  The list endpoint returns MD5 hashes
    only — SHA-256 is computed after download.  Pre-download dedup is
    skipped for this source.
    """
    api_key = _get_malshare_key()
    if not api_key:
        logger.debug("MalShare API key not configured (set MALSHARE_API_KEY)")
        return []
    try:
        import requests
        resp = requests.get(
            "https://malshare.com/api.php",
            params={"api_key": api_key, "action": "getlistraw"},
            timeout=60,
            verify=True,
        )
        if resp.status_code != 200:
            return []
        hashes = [h.strip() for h in resp.text.strip().splitlines() if h.strip()]
        results: List[dict] = []
        for h in hashes[:limit]:
            results.append({
                "sha256_hash": "",  # only MD5 available from list endpoint
                "md5_hash": h,
                "file_type": "unknown",
                "tags": [],
                "_source": "malshare",
                "_hash_for_download": h,
            })
        return results
    except Exception as e:
        logger.debug(f"MalShare API error: {e}")
        return []


def _malshare_download_sample(hash_val: str, dest_dir: str) -> Optional[str]:
    """Download a sample from MalShare by hash (MD5 or SHA-256).

    Returns the path to the downloaded file, named by its SHA-256.
    """
    api_key = _get_malshare_key()
    if not api_key:
        return None
    try:
        import requests
        resp = requests.get(
            "https://malshare.com/api.php",
            params={"api_key": api_key, "action": "getfile", "hash": hash_val},
            timeout=60,
            verify=True,
        )
        if resp.status_code != 200 or len(resp.content) < 100:
            return None
        sha256 = hashlib.sha256(resp.content).hexdigest()
        dest_path = os.path.join(dest_dir, sha256)
        with open(dest_path, "wb") as f:
            f.write(resp.content)
        return dest_path
    except Exception as e:
        logger.debug(f"MalShare download failed for {hash_val}: {e}")
        return None


# ── Hybrid Analysis helpers ────────────────────────────────────────────────


def _ha_search_recent(limit: int = 100) -> List[dict]:
    """Fetch recent submissions from Hybrid Analysis (CrowdStrike).

    Requires ``HYBRID_ANALYSIS_API_KEY``.  Uses the ``/feed/latest``
    endpoint which returns recently analysed samples with verdicts.
    """
    api_key = _get_hybrid_analysis_key()
    if not api_key:
        logger.debug("Hybrid Analysis API key not configured (set HYBRID_ANALYSIS_API_KEY)")
        return []
    try:
        import requests
        resp = requests.get(
            "https://www.hybrid-analysis.com/api/v2/feed/latest",
            headers={
                "api-key": api_key,
                "User-Agent": "HashGuard",
                "accept": "application/json",
            },
            timeout=60,
            verify=True,
        )
        if resp.status_code != 200:
            logger.debug(f"Hybrid Analysis API HTTP {resp.status_code}")
            return []
        data = resp.json()
        items = data if isinstance(data, list) else data.get("data", [])
        results: List[dict] = []
        for item in items[:limit]:
            sha256 = item.get("sha256", "")
            if not sha256:
                continue
            results.append({
                "sha256_hash": sha256,
                "md5_hash": item.get("md5", ""),
                "file_type": item.get("type_short") or "unknown",
                "file_size": item.get("size", 0),
                "signature": item.get("vx_family", ""),
                "tags": [t for t in [item.get("vx_family")] if t],
                "_source": "hybrid_analysis",
            })
        return results
    except Exception as e:
        logger.debug(f"Hybrid Analysis API error: {e}")
        return []


def _ha_download_sample(sha256: str, dest_dir: str) -> Optional[str]:
    """Download a sample from Hybrid Analysis by SHA-256.

    May return gzip-compressed content which is decompressed transparently.
    """
    api_key = _get_hybrid_analysis_key()
    if not api_key:
        return None
    try:
        import requests
        resp = requests.get(
            f"https://www.hybrid-analysis.com/api/v2/overview/{sha256}/sample",
            headers={
                "api-key": api_key,
                "User-Agent": "HashGuard",
                "accept": "application/octet-stream",
            },
            timeout=120,
            verify=True,
        )
        if resp.status_code != 200 or len(resp.content) < 100:
            return None
        try:
            content = gzip.decompress(resp.content)
        except (gzip.BadGzipFile, OSError):
            content = resp.content
        dest_path = os.path.join(dest_dir, sha256)
        with open(dest_path, "wb") as f:
            f.write(content)
        return dest_path
    except Exception as e:
        logger.debug(f"Hybrid Analysis download failed for {sha256}: {e}")
        return None


# ── Triage helpers (Hatching / tria.ge) ────────────────────────────────────


def _triage_get_recent(limit: int = 100) -> List[dict]:
    """Fetch recent public submissions from Triage.

    Requires ``TRIAGE_API_KEY``.  Uses the search endpoint to find
    recently submitted samples excluding those tagged clean.
    """
    api_key = _get_triage_key()
    if not api_key:
        logger.debug("Triage API key not configured (set TRIAGE_API_KEY)")
        return []
    try:
        import requests
        resp = requests.get(
            "https://tria.ge/api/v0/search",
            params={"query": "NOT tag:clean", "limit": str(min(limit, 200))},
            headers={
                "Authorization": f"Bearer {api_key}",
                "accept": "application/json",
            },
            timeout=60,
            verify=True,
        )
        if resp.status_code != 200:
            logger.debug(f"Triage API HTTP {resp.status_code}")
            return []
        data = resp.json()
        items = data.get("data", [])
        results: List[dict] = []
        for item in items[:limit]:
            sha256 = item.get("sha256", "")
            targets = item.get("targets", [])
            if not sha256 and targets and isinstance(targets[0], dict):
                sha256 = targets[0].get("sha256", "")
            if not sha256:
                continue
            sample_id = item.get("id", "")
            results.append({
                "sha256_hash": sha256,
                "md5_hash": item.get("md5", ""),
                "file_type": item.get("kind") or "unknown",
                "tags": item.get("tags") or [],
                "signature": "",
                "_source": "triage",
                "_triage_sample_id": sample_id,
            })
        return results
    except Exception as e:
        logger.debug(f"Triage API error: {e}")
        return []


def _triage_download_sample(
    sha256: str, dest_dir: str, sample_id: str = "",
) -> Optional[str]:
    """Download a sample from Triage by sample ID or SHA-256."""
    api_key = _get_triage_key()
    if not api_key:
        return None
    try:
        import requests
        dl_id = sample_id or sha256
        resp = requests.get(
            f"https://tria.ge/api/v0/samples/{dl_id}/sample",
            headers={
                "Authorization": f"Bearer {api_key}",
                "accept": "application/octet-stream",
            },
            timeout=120,
            verify=True,
        )
        if resp.status_code != 200 or len(resp.content) < 100:
            return None
        dest_path = os.path.join(dest_dir, sha256)
        with open(dest_path, "wb") as f:
            f.write(resp.content)
        return dest_path
    except Exception as e:
        logger.debug(f"Triage download failed for {sha256}: {e}")
        return None


# ── Generic download dispatcher ───────────────────────────────────────────


def _download_sample(entry: dict, dest_dir: str) -> Optional[str]:
    """Download a sample using the appropriate source-specific downloader.

    Dispatches to the correct API based on the ``_source`` field in metadata.
    Returns the path to the downloaded file, or None on failure.
    """
    source = entry.get("_source", "malwarebazaar")
    sha256 = entry.get("sha256_hash", "")

    if source == "urlhaus":
        return _urlhaus_download_payload(sha256, dest_dir)
    if source == "malshare":
        hash_val = entry.get("_hash_for_download", sha256)
        return _malshare_download_sample(hash_val, dest_dir)
    if source == "hybrid_analysis":
        return _ha_download_sample(sha256, dest_dir)
    if source == "triage":
        sample_id = entry.get("_triage_sample_id", "")
        return _triage_download_sample(sha256, dest_dir, sample_id=sample_id)
    # Default: MalwareBazaar
    return _mb_download_sample(sha256, dest_dir)


# ── Core ingest engine ─────────────────────────────────────────────────────


def _analyse_file(file_path: str, use_vt: bool = False) -> Optional[dict]:
    """Run the full analysis pipeline on a single file.

    Uses the same pipeline as the web dashboard's ``_run_full_analysis``.
    Returns the sanitised result dict, or None on failure.
    """
    try:
        from hashguard.web.api import _run_full_analysis
        return _run_full_analysis(file_path, use_vt=use_vt)
    except Exception as e:
        logger.warning(f"Analysis failed for {file_path}: {e}")
        return None


def _analyse_file_batch(file_path: str, mb_metadata: Optional[dict] = None) -> Optional[dict]:
    """Run a streamlined analysis for batch/continuous ingest.

    Skips expensive post-processing (auto-unpack, IOC graph, timeline)
    that are unnecessary for dataset feature extraction.  The core
    scanner output + feature extraction + DB storage are preserved.

    Parameters
    ----------
    mb_metadata:
        Optional MalwareBazaar entry dict.  When provided, ground-truth
        labels (family, tags) are passed to the feature extractor so the
        dataset uses analyst-verified labels instead of the scanner's
        own verdict.
    """
    try:
        from hashguard.scanner import analyze
        from hashguard.config import get_default_config
        from hashguard.web.api import _sanitize_for_json

        config = get_default_config()
        result = analyze(file_path, vt=False, config=config, batch_mode=True)
        result_dict = result.to_dict()

        # When the sample comes from a malware feed (MalwareBazaar) but the
        # scanner assigned a low risk score, override the verdict.  These samples
        # are analyst-confirmed malware — a "clean" verdict is misleading.
        if mb_metadata is not None:
            risk = result_dict.get("risk_score", {})
            if risk.get("verdict") in ("clean", "unknown", "suspicious"):
                risk["verdict"] = "malicious"
                risk["score"] = max(risk.get("score", 0), 40)
                result_dict["risk_score"] = risk
            if not result_dict.get("malicious"):
                result_dict["malicious"] = True

        # Store in database
        sample_id = None
        try:
            from hashguard.database import store_sample, store_timeline_event
            sample_id = store_sample(result_dict)
            result_dict["sample_id"] = sample_id
        except Exception as e:
            logger.debug(f"Database storage error: {e}")

        # Extract & store ML dataset features (the whole point of batch ingest)
        try:
            from hashguard.feature_extractor import extract_features
            from hashguard.database import store_dataset_features

            feats = extract_features(file_path, result_dict, mb_metadata=mb_metadata)
            sha = result_dict.get("hashes", {}).get("sha256", "")
            if sha and sample_id:
                store_dataset_features(sample_id, sha, feats)
        except Exception as e:
            logger.debug(f"Dataset feature extraction error: {e}")

        return _sanitize_for_json(result_dict)
    except Exception as e:
        logger.warning(f"Batch analysis failed for {file_path}: {e}")
        return None


def _already_in_dataset(sha256: str) -> bool:
    """Check if a SHA-256 is already stored in the samples table."""
    try:
        from hashguard.database import get_sample
        return get_sample(sha256) is not None
    except Exception:
        return False


def _run_ingest(
    candidates: List[dict],
    delay: float = 1.0,
    use_vt: bool = False,
) -> None:
    """Process a list of MalwareBazaar candidate dicts.

    This is the inner loop that runs in a background thread.
    """
    global _current_job
    _current_job.total_candidates = len(candidates)

    quarantine_dir = tempfile.mkdtemp(prefix="hashguard_ingest_")
    try:
        for entry in candidates:
            if _stop_event.is_set():
                _current_job.status = "stopping"
                break

            sha256 = entry.get("sha256_hash", "")
            if not sha256 and not entry.get("_hash_for_download"):
                continue

            _current_job.current_sha256 = sha256 or entry.get("_hash_for_download", "")

            # Dedup (skip if sha256 unknown — will dedup post-download)
            if sha256 and _already_in_dataset(sha256):
                _current_job.skipped_existing += 1
                continue

            # Download via source-specific downloader
            file_path = _download_sample(entry, quarantine_dir)
            if not file_path:
                _current_job.failed += 1
                _current_job.errors.append(f"download_failed:{sha256[:16]}")
                time.sleep(delay)
                continue

            _current_job.downloaded += 1

            # Analyse — batch mode extracts features + stores in dataset
            result = _analyse_file_batch(file_path, mb_metadata=entry)
            if result:
                _current_job.analysed += 1
            else:
                _current_job.failed += 1
                _current_job.errors.append(f"analysis_failed:{sha256[:16]}")

            # Cleanup individual file
            try:
                os.remove(file_path)
            except OSError:
                pass

            # Respect rate limit
            time.sleep(delay)

    finally:
        # Cleanup quarantine directory
        shutil.rmtree(quarantine_dir, ignore_errors=True)
        _current_job.current_sha256 = ""
        _current_job.finished_at = time.time()
        if _current_job.status == "running":
            _current_job.status = "done"
        elif _current_job.status == "stopping":
            _current_job.status = "done"


# ── Public API ─────────────────────────────────────────────────────────────


def _run_local_ingest(
    directory: str,
    limit: int = 100,
    delay: float = 0.1,
    use_vt: bool = False,
) -> None:
    """Ingest files from a local directory (no download step).

    Each file is hashed with SHA-256 for dedup, then analysed in place.
    """
    global _current_job

    files = []
    for name in os.listdir(directory):
        path = os.path.join(directory, name)
        if os.path.isfile(path):
            files.append(path)
        if len(files) >= limit:
            break

    _current_job.total_candidates = len(files)

    for file_path in files:
        if _stop_event.is_set():
            _current_job.status = "stopping"
            break

        # Compute SHA-256 for dedup / progress
        try:
            h = hashlib.sha256()
            with open(file_path, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    h.update(chunk)
            sha256 = h.hexdigest()
        except OSError:
            _current_job.failed += 1
            _current_job.errors.append(f"read_failed:{os.path.basename(file_path)[:16]}")
            continue

        _current_job.current_sha256 = sha256

        if _already_in_dataset(sha256):
            _current_job.skipped_existing += 1
            continue

        _current_job.downloaded += 1  # counts as "loaded" for local

        result = _analyse_file_batch(file_path)
        if result:
            _current_job.analysed += 1
        else:
            _current_job.failed += 1
            _current_job.errors.append(f"analysis_failed:{sha256[:16]}")

        time.sleep(delay)

    _current_job.current_sha256 = ""
    _current_job.finished_at = time.time()
    if _current_job.status in ("running", "stopping"):
        _current_job.status = "done"


# ── Benign sample collection ──────────────────────────────────────────────

# Directories containing known-clean binaries for benign class balance.
_BENIGN_DIRS_WINDOWS = [
    os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32"),
    os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "SysWOW64"),
    os.path.join(os.environ.get("PROGRAMFILES", r"C:\Program Files"), "Common Files"),
    os.environ.get("PROGRAMFILES", r"C:\Program Files"),
]

# Extensions considered for benign collection
_BENIGN_EXTENSIONS = {".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr"}


def _run_benign_ingest(
    limit: int = 5000,
    delay: float = 0.05,
) -> None:
    """Ingest known-clean files from system directories for class balance.

    Scans signed Windows system binaries from System32 / Program Files.
    Labels them as ``label_is_malicious=0``, ``label_source="benign_system"``.
    """
    global _current_job

    files: List[str] = []
    for base_dir in _BENIGN_DIRS_WINDOWS:
        if not os.path.isdir(base_dir):
            continue
        try:
            for root, _dirs, names in os.walk(base_dir):
                for name in names:
                    ext = os.path.splitext(name)[1].lower()
                    if ext not in _BENIGN_EXTENSIONS:
                        continue
                    path = os.path.join(root, name)
                    if os.path.isfile(path):
                        files.append(path)
                    if len(files) >= limit:
                        break
                if len(files) >= limit:
                    break
        except PermissionError:
            continue
        if len(files) >= limit:
            break

    _current_job.total_candidates = len(files)
    if not files:
        _current_job.status = "error"
        _current_job.errors.append("No benign system files found")
        _current_job.finished_at = time.time()
        return

    logger.info(f"Benign ingest: found {len(files)} system files")

    for file_path in files:
        if _stop_event.is_set():
            _current_job.status = "stopping"
            break

        try:
            h = hashlib.sha256()
            with open(file_path, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    h.update(chunk)
            sha256 = h.hexdigest()
        except (OSError, PermissionError):
            _current_job.failed += 1
            continue

        _current_job.current_sha256 = sha256

        if _already_in_dataset(sha256):
            _current_job.skipped_existing += 1
            continue

        _current_job.downloaded += 1

        # Use a synthetic MB-like metadata dict to mark as benign
        benign_meta = {
            "signature": "",
            "tags": [],
            "_benign_source": "system",
        }

        try:
            from hashguard.scanner import analyze
            from hashguard.config import get_default_config
            from hashguard.feature_extractor import extract_features
            from hashguard.database import store_sample, store_dataset_features

            config = get_default_config()
            result = analyze(file_path, vt=False, config=config, batch_mode=True)
            result_dict = result.to_dict()

            sample_id = store_sample(result_dict)

            feats = extract_features(file_path, result_dict)
            # Override labels: these are KNOWN benign
            feats["label_source"] = "benign_system"
            feats["label_is_malicious"] = 0
            feats["label_verdict"] = "clean"
            feats["label_family"] = ""
            feats["label_family_confidence"] = 1.0
            feats["label_mb_tags"] = "[]"
            feats["label_mb_signature"] = ""

            sha = result_dict.get("hashes", {}).get("sha256", "")
            if sha and sample_id:
                store_dataset_features(sample_id, sha, feats)

            _current_job.analysed += 1
        except Exception as e:
            _current_job.failed += 1
            _current_job.errors.append(f"benign_failed:{sha256[:16]}")
            logger.debug(f"Benign analysis failed: {e}")

        time.sleep(delay)

    _current_job.current_sha256 = ""
    _current_job.finished_at = time.time()
    if _current_job.status in ("running", "stopping"):
        _current_job.status = "done"


# ── Multi-source collection for large datasets ────────────────────────────

# File types ordered by availability on MalwareBazaar (most samples first)
_MIXED_FILE_TYPES = [
    "exe", "dll", "docx", "doc", "xls", "xlsx", "pdf", "elf",
    "apk", "jar", "js", "vbs", "ps1", "bat", "msi", "iso",
    "lnk", "rtf", "hta", "wsf",
]

# Popular MalwareBazaar tags for diverse dataset collection
_POPULAR_TAGS = [
    "Emotet", "AgentTesla", "Formbook", "Remcos", "LockBit",
    "RedLine", "AsyncRAT", "NjRAT", "GuLoader", "Qakbot",
    "IcedID", "Cobalt Strike", "Raccoon", "Vidar", "SmokeLoader",
    "TrickBot", "Dridex", "BazarLoader", "Conti", "REvil",
    "DarkSide", "Ryuk", "Maze", "Phobos", "Dharma",
    "Stop", "XMRig", "CoinMiner", "Mirai", "Gafgyt",
    "Gh0stRAT", "PlugX", "ShadowPad", "WannaCry", "Petya",
    "BlackCat", "AvosLocker", "Hive", "Royal", "Play",
    "Medusa", "Akira", "BianLian", "NoEscape", "8Base",
    "Snake", "BlackBasta", "Vice Society", "Cuba", "Clop",
]


def _mb_get_multi(limit: int) -> List[dict]:
    """Fetch samples from multiple MalwareBazaar file types.

    Collects up to *limit* unique samples by querying each file type
    in ``_MIXED_FILE_TYPES`` with up to 1000 per call.  Deduplicates by
    SHA-256 so the same sample is never returned twice.
    """
    seen: set = set()
    combined: List[dict] = []

    # How many to request per type — spread evenly across types, at least 100
    per_type = max(100, min(1000, (limit // len(_MIXED_FILE_TYPES)) + 100))

    for ftype in _MIXED_FILE_TYPES:
        if len(combined) >= limit:
            break
        needed = limit - len(combined)
        fetch = min(per_type, 1000, needed + 200)  # over-fetch to account for dupes

        logger.info(f"Mixed ingest: fetching {fetch} samples of type '{ftype}'")
        batch = _mb_get_by_filetype(ftype, fetch)

        for entry in batch:
            sha = entry.get("sha256_hash", "")
            if sha and sha not in seen:
                seen.add(sha)
                combined.append(entry)
                if len(combined) >= limit:
                    break

        # Rate-limit between API calls
        if len(combined) < limit:
            time.sleep(2)

    logger.info(f"Mixed ingest: collected {len(combined)} unique candidates from {len(_MIXED_FILE_TYPES)} types")
    return combined


def start_ingest(
    source: str = "recent",
    limit: int = 100,
    tag: str = "",
    file_type: str = "exe",
    delay: float = 1.0,
    use_vt: bool = False,
    directory: str = "",
) -> dict:
    """Start a batch ingest job in the background.

    Parameters
    ----------
    source : str
        ``"recent"`` — most recent samples from MalwareBazaar (max 100).
        ``"tag"`` — samples matching *tag* (max 1000 per call).
        ``"filetype"`` — samples matching *file_type* (max 1000 per call).
        ``"mixed"`` — combines multiple file types to reach higher limits
        (supports 5 000+ by aggregating exe, dll, docx, pdf, elf, apk…).
        ``"continuous"`` — loops through tags + file types continuously
        until *limit* samples are analysed or stopped manually.  Designed
        for building large datasets (200k+).
        ``"urlhaus"`` — recent malicious payloads from URLhaus (abuse.ch).
        No API key required.
        ``"malshare"`` — samples added in the last 24 h from MalShare.
        Requires ``MALSHARE_API_KEY``.
        ``"hybrid_analysis"`` — recent sandbox submissions from Hybrid
        Analysis (CrowdStrike).  Requires ``HYBRID_ANALYSIS_API_KEY``.
        ``"triage"`` — recent public samples from Triage (tria.ge).
        Requires ``TRIAGE_API_KEY``.
        ``"benign"`` — scans known-clean system binaries (System32, Program
        Files) to collect benign samples for class balance.
        ``"local"`` — scan files from a local *directory*.
    limit : int
        Maximum number of candidates to fetch.
        - ``recent``: capped at 100 (MalwareBazaar hard limit).
        - ``tag`` / ``filetype``: capped at 1000 per API call.
        - ``mixed``: no cap — fetches across multiple file types.
        - ``continuous``: target total samples to analyse.
        - ``local``: no cap.
    tag : str
        MalwareBazaar tag (only used when source="tag").
    file_type : str
        File type filter (only used when source="filetype"), e.g. "exe", "dll".
    delay : float
        Seconds between API calls (rate limiting).
    use_vt : bool
        Whether to query VirusTotal during analysis.
    directory : str
        Path to directory containing samples (only used when source="local").

    Returns
    -------
    dict with ``{"started": True, ...}`` or ``{"started": False, "reason": ...}``.
    """
    global _current_job

    with _job_lock:
        if _current_job.status == "running":
            return {"started": False, "reason": "A job is already running"}

        # Reset state
        _stop_event.clear()
        _current_job = IngestJob(
            source=source,
            status="running",
            started_at=time.time(),
        )

    # ── Local directory mode ──────────────────────────────────────────
    if source == "local":
        if not directory:
            _current_job.status = "error"
            _current_job.errors.append("Invalid or missing directory path")
            _current_job.finished_at = time.time()
            return {"started": False, "reason": "Invalid or missing directory path"}

        # Resolve and validate to prevent path traversal
        if ".." in directory:
            _current_job.status = "error"
            _current_job.errors.append("Invalid directory path (traversal blocked)")
            _current_job.finished_at = time.time()
            return {"started": False, "reason": "Invalid directory path"}

        from pathlib import Path
        resolved_path = Path(directory).resolve()
        if not resolved_path.is_dir():
            _current_job.status = "error"
            _current_job.errors.append("Invalid directory path")
            _current_job.finished_at = time.time()
            return {"started": False, "reason": "Invalid directory path"}

        # Containment: only allow paths under user home or common data dirs
        _allowed_roots = [
            Path(os.path.expanduser("~")).resolve(),
            Path(os.environ.get("APPDATA", os.path.expanduser("~"))).resolve(),
            Path(os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))).resolve(),
            Path("/tmp").resolve(),
        ]
        if not any(resolved_path.is_relative_to(r) for r in _allowed_roots):
            _current_job.status = "error"
            _current_job.errors.append("Directory outside allowed paths")
            _current_job.finished_at = time.time()
            return {"started": False, "reason": "Directory outside allowed paths"}

        safe_dir = str(resolved_path)
        candidates = os.listdir(safe_dir)
        t = threading.Thread(
            target=_run_local_ingest,
            args=(safe_dir, limit, delay, use_vt),
            daemon=True,
            name="hashguard-ingest",
        )
        t.start()
        return {"started": True, "source": "local", "candidates": min(limit, len(candidates))}

    # ── Benign system files mode ──────────────────────────────────────
    if source == "benign":
        t = threading.Thread(
            target=_run_benign_ingest,
            args=(limit, delay),
            daemon=True,
            name="hashguard-ingest",
        )
        t.start()
        return {"started": True, "source": "benign", "candidates": 0}

    # ── Feed-based mode (MalwareBazaar / URLhaus / MalShare / HA / Triage) ──
    # Launch candidate fetching + analysis in a background thread so the
    # HTTP response returns immediately and the UI can poll progress.
    t = threading.Thread(
        target=_fetch_and_ingest,
        args=(source, limit, tag, file_type, delay, use_vt),
        daemon=True,
        name="hashguard-ingest",
    )
    t.start()
    return {"started": True, "source": source, "candidates": 0}


def _fetch_and_ingest(
    source: str, limit: int, tag: str, file_type: str, delay: float, use_vt: bool,
) -> None:
    """Fetch candidates from threat-intel feeds, then run the ingest pipeline.

    Runs entirely in a background thread so the API can respond instantly.
    Dispatches to the correct source API based on the *source* parameter.
    """
    global _current_job

    # ── Continuous mode ───────────────────────────────────────────────
    if source == "continuous":
        _run_continuous_ingest(limit, delay, use_vt)
        return

    _current_job.current_sha256 = "Fetching candidates..."

    logger.info(f"Fetching candidates: source={source} limit={limit} tag={tag} file_type={file_type}")

    candidates: List[dict] = []

    if source == "mixed":
        candidates = _mb_get_multi(limit)
    elif source == "tag" and tag:
        candidates = _mb_get_by_tag(tag, min(limit, 1000))
    elif source == "filetype":
        candidates = _mb_get_by_filetype(file_type, min(limit, 1000))
    elif source == "urlhaus":
        candidates = _urlhaus_get_recent(limit)
    elif source == "malshare":
        candidates = _malshare_get_recent_24h(limit)
    elif source == "hybrid_analysis":
        candidates = _ha_search_recent(limit)
    elif source == "triage":
        candidates = _triage_get_recent(limit)
    else:
        candidates = _mb_get_recent(min(limit, 100))

    if _stop_event.is_set():
        _current_job.status = "stopped"
        _current_job.finished_at = time.time()
        return

    if not candidates:
        reason = f"No candidates returned from {source} feed"
        if source in ("recent", "tag", "filetype", "mixed") and not _get_abuse_ch_key():
            reason += " (no ABUSE_CH_API_KEY configured)"
        elif source == "malshare" and not _get_malshare_key():
            reason += " (no MALSHARE_API_KEY configured)"
        elif source == "hybrid_analysis" and not _get_hybrid_analysis_key():
            reason += " (no HYBRID_ANALYSIS_API_KEY configured)"
        elif source == "triage" and not _get_triage_key():
            reason += " (no TRIAGE_API_KEY configured)"
        _current_job.status = "error"
        _current_job.errors.append(reason)
        _current_job.finished_at = time.time()
        return

    _current_job.total_candidates = len(candidates)
    _current_job.current_sha256 = ""
    _run_ingest(candidates, delay, use_vt)


def _run_continuous_ingest(
    target: int,
    delay: float = 0.5,
    use_vt: bool = False,
) -> None:
    """Continuously fetch and analyse samples until *target* is reached.

    Cycles through:
    1. MalwareBazaar recent samples (every cycle)
    2. URLhaus recent payloads
    3. MalShare recent 24h (if API key configured)
    4. Hybrid Analysis recent (if API key configured)
    5. Triage recent (if API key configured)
    6. Each popular MalwareBazaar tag (1000 per tag)
    7. Each MalwareBazaar file type (1000 per type)

    Automatically deduplicates via the database.  Crash-resilient: on
    restart, ``_already_in_dataset`` skips previously analysed samples.
    Progress is tracked via ``_current_job`` and visible in the dashboard.
    """
    global _current_job

    _current_job.total_candidates = target
    cycle = 0

    quarantine_dir = tempfile.mkdtemp(prefix="hashguard_continuous_")
    try:
        while _current_job.analysed < target:
            if _stop_event.is_set():
                _current_job.status = "stopping"
                break

            cycle += 1
            logger.info(
                f"Continuous ingest cycle {cycle}: "
                f"{_current_job.analysed}/{target} analysed, "
                f"{_current_job.skipped_existing} skipped"
            )

            # -- 1. MalwareBazaar recent samples --
            _current_job.current_sha256 = "Fetching MalwareBazaar recent..."
            recent = _mb_get_recent(100)
            _process_candidates(recent, quarantine_dir, delay, use_vt, target)
            if _stop_event.is_set() or _current_job.analysed >= target:
                break

            # -- 2. URLhaus recent payloads (no API key needed) --
            _current_job.current_sha256 = "Fetching URLhaus recent..."
            urlhaus = _urlhaus_get_recent(500)
            _process_candidates(urlhaus, quarantine_dir, delay, use_vt, target)
            if _stop_event.is_set() or _current_job.analysed >= target:
                break

            # -- 3. MalShare recent 24h (if configured) --
            if _get_malshare_key():
                _current_job.current_sha256 = "Fetching MalShare recent..."
                malshare = _malshare_get_recent_24h(500)
                _process_candidates(malshare, quarantine_dir, delay, use_vt, target)
                if _stop_event.is_set() or _current_job.analysed >= target:
                    break

            # -- 4. Hybrid Analysis recent (if configured) --
            if _get_hybrid_analysis_key():
                _current_job.current_sha256 = "Fetching Hybrid Analysis recent..."
                ha = _ha_search_recent(100)
                _process_candidates(ha, quarantine_dir, delay, use_vt, target)
                if _stop_event.is_set() or _current_job.analysed >= target:
                    break

            # -- 5. Triage recent (if configured) --
            if _get_triage_key():
                _current_job.current_sha256 = "Fetching Triage recent..."
                triage = _triage_get_recent(200)
                _process_candidates(triage, quarantine_dir, delay, use_vt, target)
                if _stop_event.is_set() or _current_job.analysed >= target:
                    break

            # -- 6. Popular tags --
            for tag in _POPULAR_TAGS:
                if _stop_event.is_set() or _current_job.analysed >= target:
                    break
                _current_job.current_sha256 = f"Fetching tag: {tag}..."
                batch = _mb_get_by_tag(tag, 1000)
                _process_candidates(batch, quarantine_dir, delay, use_vt, target)
                time.sleep(0.5)  # rate-limit between API calls

            if _stop_event.is_set() or _current_job.analysed >= target:
                break

            # -- 7. File types --
            for ftype in _MIXED_FILE_TYPES:
                if _stop_event.is_set() or _current_job.analysed >= target:
                    break
                _current_job.current_sha256 = f"Fetching type: {ftype}..."
                batch = _mb_get_by_filetype(ftype, 1000)
                _process_candidates(batch, quarantine_dir, delay, use_vt, target)
                time.sleep(0.5)

            # Wait before next cycle (APIs may have new data)
            if _current_job.analysed < target and not _stop_event.is_set():
                _current_job.current_sha256 = f"Cycle {cycle} done — waiting 30s for new data..."
                logger.info(f"Cycle {cycle} complete. Waiting 30s before next cycle.")
                for _ in range(30):
                    if _stop_event.is_set():
                        break
                    time.sleep(1)
    finally:
        shutil.rmtree(quarantine_dir, ignore_errors=True)
        _current_job.current_sha256 = ""
        _current_job.finished_at = time.time()
        if _current_job.status in ("running", "stopping"):
            _current_job.status = "done"


def _process_candidates(
    candidates: List[dict],
    quarantine_dir: str,
    delay: float,
    use_vt: bool,
    target: int,
) -> None:
    """Download and analyse a batch of candidates using parallel workers.

    Uses a thread pool to overlap network I/O (downloads) with CPU-bound
    analysis.  Each worker handles one sample end-to-end to avoid shared
    state issues with file paths.
    """
    global _current_job

    # Pre-filter already-known samples in bulk
    fresh: List[dict] = []
    for entry in candidates:
        sha256 = entry.get("sha256_hash", "")
        if not sha256 and not entry.get("_hash_for_download"):
            continue
        if sha256 and _already_in_dataset(sha256):
            _current_job.skipped_existing += 1
        else:
            fresh.append(entry)

    if not fresh:
        return

    logger.info(f"Processing {len(fresh)} new candidates ({len(candidates) - len(fresh)} skipped, analysed={_current_job.analysed}, target={target})")

    # Determine worker count — balance between API rate limits and throughput
    workers = min(4, len(fresh))

    def _process_one(entry: dict) -> Optional[str]:
        """Download + analyse a single sample. Returns sha256 on success."""
        if _stop_event.is_set() or _current_job.analysed >= target:
            return None
        sha256 = entry.get("sha256_hash", "") or entry.get("_hash_for_download", "")
        _current_job.current_sha256 = sha256

        file_path = _download_sample(entry, quarantine_dir)
        if not file_path:
            _current_job.failed += 1
            _current_job.errors.append(f"download_failed:{sha256[:16]}")
            return None

        _current_job.downloaded += 1

        result = _analyse_file_batch(file_path, mb_metadata=entry)
        if result:
            _current_job.analysed += 1
        else:
            _current_job.failed += 1
            _current_job.errors.append(f"analysis_failed:{sha256[:16]}")

        try:
            os.remove(file_path)
        except OSError:
            pass

        # Log progress periodically
        if _current_job.analysed % 100 == 0 and _current_job.analysed > 0:
            logger.info(
                f"Progress: {_current_job.analysed}/{target} analysed, "
                f"{_current_job.failed} failed, "
                f"{_current_job.skipped_existing} skipped"
            )
        return sha256

    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ingest") as pool:
        futures = {}
        for entry in fresh:
            if _stop_event.is_set() or _current_job.analysed >= target:
                break
            f = pool.submit(_process_one, entry)
            futures[f] = entry
            # Small stagger to avoid overwhelming the API
            time.sleep(delay)

        for f in as_completed(futures):
            try:
                f.result()
            except Exception as e:
                logger.debug(f"Worker error: {e}")
