"""Core scanning functionality for HashGuard.

This module provides cryptographic hash computation, malware signature detection,
threat intelligence integration via VirusTotal, and comprehensive file analysis.
"""

import hashlib
import json
import os
import time
from typing import Dict, List, Optional, Tuple
from datetime import datetime

from hashguard.logger import get_logger
from hashguard.config import HashGuardConfig, get_default_config

logger = get_logger(__name__)


class SignatureDatabase:
    """Manager for malware signature database."""

    def __init__(self, config: Optional[HashGuardConfig] = None):
        """Initialize signature database manager."""
        self.config = config or get_default_config()
        self._signatures: Dict[str, str] = {}
        self._load_time: float = 0
        self.load()

    def load(self) -> None:
        """Load or reload signature database from configured file."""
        self._signatures = {}
        if not os.path.exists(self.config.signatures_file):
            logger.warning(f"Signatures file not found: {self.config.signatures_file}")
            return

        try:
            with open(self.config.signatures_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    # Convert all keys to lowercase for case-insensitive lookup
                    self._signatures = {k.lower(): v for k, v in data.items()}
                    self._load_time = time.time()
                    logger.info(f"Loaded {len(self._signatures)} malware signatures")
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in signatures file: {e}")
        except Exception as e:
            logger.error(f"Failed to load signatures: {e}")

    def get(self, hash_value: str) -> Optional[str]:
        """Get description for a hash, case-insensitive."""
        return self._signatures.get(hash_value.lower())

    def contains(self, hash_value: str) -> bool:
        """Check if hash is in database."""
        return hash_value.lower() in self._signatures

    def count(self) -> int:
        """Get total signatures in database."""
        return len(self._signatures)


# Global signature database instance (lazy singleton)
_global_signatures: Optional[SignatureDatabase] = None


def _get_global_signatures() -> SignatureDatabase:
    """Return the cached global signature database."""
    global _global_signatures
    if _global_signatures is None:
        _global_signatures = SignatureDatabase()
    return _global_signatures


class FileAnalysisResult:
    """Structured result from file analysis."""

    def __init__(
        self,
        path: str,
        hashes: Dict[str, str],
        malicious: bool = False,
        description: str = "Unknown",
        vt_result: Optional[dict] = None,
        file_size: int = 0,
        analysis_time: float = 0,
        pe_info: Optional[dict] = None,
        yara_matches: Optional[dict] = None,
        threat_intel: Optional[dict] = None,
        risk_score: Optional[dict] = None,
        strings_info: Optional[dict] = None,
        # v2 fields
        capabilities: Optional[dict] = None,
        advanced_pe: Optional[dict] = None,
        fuzzy_hashes: Optional[dict] = None,
        ml_classification: Optional[dict] = None,
        family_detection: Optional[dict] = None,
        ioc_graph: Optional[dict] = None,
        timeline: Optional[dict] = None,
        packer: Optional[dict] = None,
        shellcode: Optional[dict] = None,
        script_deobfuscation: Optional[dict] = None,
    ):
        self.path = path
        self.hashes = hashes
        self.malicious = malicious
        self.description = description
        self.vt_result = vt_result
        self.file_size = file_size
        self.analysis_time = analysis_time
        self.pe_info = pe_info
        self.yara_matches = yara_matches
        self.threat_intel = threat_intel
        self.risk_score = risk_score
        self.strings_info = strings_info
        self.capabilities = capabilities
        self.advanced_pe = advanced_pe
        self.fuzzy_hashes = fuzzy_hashes
        self.ml_classification = ml_classification
        self.family_detection = family_detection
        self.ioc_graph = ioc_graph
        self.timeline = timeline
        self.packer = packer
        self.shellcode = shellcode
        self.script_deobfuscation = script_deobfuscation
        self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> dict:
        """Convert result to dictionary."""
        d = {
            "path": self.path,
            "hashes": self.hashes,
            "malicious": self.malicious,
            "description": self.description,
            "file_size": self.file_size,
            "analysis_time_ms": round(self.analysis_time * 1000, 2),
            "timestamp": self.timestamp,
            "vt_result": self.vt_result,
        }
        if self.pe_info:
            d["pe_info"] = self.pe_info
        if self.yara_matches:
            d["yara_matches"] = self.yara_matches
        if self.threat_intel:
            d["threat_intel"] = self.threat_intel
        if self.risk_score:
            d["risk_score"] = self.risk_score
        if self.strings_info:
            d["strings_info"] = self.strings_info
        if self.capabilities:
            d["capabilities"] = self.capabilities
        if self.advanced_pe:
            d["advanced_pe"] = self.advanced_pe
        if self.fuzzy_hashes:
            d["fuzzy_hashes"] = self.fuzzy_hashes
        if self.ml_classification:
            d["ml_classification"] = self.ml_classification
        if self.family_detection:
            d["family_detection"] = self.family_detection
        if self.ioc_graph:
            d["ioc_graph"] = self.ioc_graph
        if self.timeline:
            d["timeline"] = self.timeline
        if self.packer:
            d["packer"] = self.packer
        if self.shellcode:
            d["shellcode"] = self.shellcode
        if self.script_deobfuscation:
            d["script_deobfuscation"] = self.script_deobfuscation
        return d

    def to_json(self) -> str:
        """Convert result to JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)


def compute_hashes(
    path: str,
    algorithms: Optional[List[str]] = None,
    config: Optional[HashGuardConfig] = None,
) -> Dict[str, str]:
    """
    Compute cryptographic hashes for a file.

    Args:
        path: Path to file to hash
        algorithms: List of hash algorithms (md5, sha1, sha256)
        config: Configuration object

    Returns:
        Dictionary of {algorithm: hex_digest}

    Raises:
        FileNotFoundError: If file doesn't exist
        PermissionError: If file can't be read
        IOError: If read error occurs
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"File not found: {path}")

    if algorithms is None:
        config = config or get_default_config()
        algorithms = config.hash_algorithms

    results: Dict[str, str] = {}
    config = config or get_default_config()

    try:
        with open(path, "rb") as f:
            # Validate file size if limit is configured
            if config.max_file_size > 0:
                f.seek(0, 2)  # Seek to end
                file_size = f.tell()
                f.seek(0)  # Seek back to start
                if file_size > config.max_file_size:
                    raise ValueError(f"File exceeds maximum size of {config.max_file_size} bytes")

            # Compute all requested hashes in single pass
            hashers = {algo: hashlib.new(algo) for algo in algorithms}

            while True:
                chunk = f.read(config.chunk_size)
                if not chunk:
                    break
                for hasher in hashers.values():
                    hasher.update(chunk)

            results = {algo: h.hexdigest() for algo, h in hashers.items()}

    except PermissionError:
        raise PermissionError(f"Permission denied reading file: {path}")
    except Exception as e:
        logger.error(f"Error computing hashes for {path}: {e}")
        raise

    return results


def is_malware(
    path: str,
    signatures: Optional[SignatureDatabase] = None,
    config: Optional[HashGuardConfig] = None,
) -> bool:
    """
    Check if file matches known malware signatures.

    Args:
        path: Path to file
        signatures: Signature database (uses global if not provided)
        config: Configuration object

    Returns:
        True if file matches any signature
    """
    config = config or get_default_config()
    signatures = signatures or _get_global_signatures()

    try:
        hashes = compute_hashes(path, config=config)
        return any(signatures.contains(h) for h in hashes.values())
    except Exception as e:
        logger.error(f"Error checking malware status: {e}")
        return False


def query_virustotal(
    path: str,
    api_key: Optional[str] = None,
    config: Optional[HashGuardConfig] = None,
) -> Optional[dict]:
    """
    Query VirusTotal threat intelligence API.

    Args:
        path: Path to file
        api_key: VirusTotal API key (uses config if not provided)
        config: Configuration object

    Returns:
        VirusTotal API response or None if unavailable
    """
    config = config or get_default_config()
    api_key = api_key or config.vt_api_key

    if not api_key:
        logger.debug("No VirusTotal API key configured")
        return None

    try:
        import requests
    except ImportError:
        logger.error("requests library not available for VirusTotal queries")
        return None

    try:
        # Get SHA256 hash
        hashes = compute_hashes(path, ["sha256"], config=config)
        sha256 = hashes.get("sha256")
        if not sha256:
            return None

        # Query VirusTotal API v3
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        headers = {"x-apikey": api_key}

        logger.debug(f"Querying VirusTotal for {sha256}")
        resp = requests.get(url, headers=headers, timeout=10, verify=True)

        if resp.status_code == 200:
            logger.info("VirusTotal query successful")
            return resp.json()
        elif resp.status_code == 404:
            logger.debug("File not found in VirusTotal")
            return None
        else:
            logger.warning(f"VirusTotal API error: {resp.status_code}")
            return None

    except requests.RequestException as e:
        logger.error(f"VirusTotal query failed: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error in VirusTotal query: {e}")
        return None


def query_virustotal_url(
    url: str,
    api_key: Optional[str] = None,
    config: Optional[HashGuardConfig] = None,
) -> Optional[dict]:
    """Query VirusTotal URL scan API."""
    config = config or get_default_config()
    api_key = api_key or config.vt_api_key
    if not api_key:
        return None
    try:
        import requests as req
    except ImportError:
        return None
    try:
        import base64

        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": api_key}
        resp = req.get(endpoint, headers=headers, timeout=15)
        if resp.status_code == 200:
            return resp.json()
        return None
    except Exception as e:
        logger.error(f"VirusTotal URL query failed: {e}")
        return None


def _run_extended_analysis(
    file_path: str,
    hashes: Dict[str, str],
    is_malicious: bool,
    description: str,
    config: HashGuardConfig,
    *,
    batch_mode: bool = False,
) -> tuple:
    """Run PE analysis, YARA scan, threat intel, string extraction, and risk scoring.

    Returns (is_malicious, description, pe_info, yara_info, threat_intel_info,
             risk_score_info, strings_info).
    """
    # Track whether the file matched the local hash signature DB separately
    # from detections added by other modules during analysis.
    hash_signature_match = is_malicious

    # Accumulate all findings instead of first-writer-wins.
    findings: list[str] = []
    if is_malicious and description != "Clean":
        findings.append(description)

    pe_info = None
    try:
        from hashguard.pe_analyzer import analyze_pe, is_pe_file

        if is_pe_file(file_path):
            pe_result = analyze_pe(file_path)
            if pe_result.is_pe:
                pe_info = pe_result.to_dict()
                if pe_result.packed:
                    findings.append(f"Packed executable ({pe_result.packer_hint})")
                elif pe_result.suspicious_imports:
                    findings.append("Suspicious API imports detected")
    except Exception as e:
        logger.debug(f"PE analysis skipped: {e}")

    yara_info = None
    try:
        from hashguard.yara_scanner import scan_file as yara_scan

        yara_result = yara_scan(file_path)
        if yara_result.rules_loaded > 0 or yara_result.matches:
            yara_info = yara_result.to_dict()
            if yara_result.matches:
                rule_names = ", ".join(m.rule for m in yara_result.matches[:3])
                findings.append(f"YARA: {rule_names}")
    except Exception as e:
        logger.debug(f"YARA scan skipped: {e}")

    threat_intel_info = None
    if not batch_mode:
        try:
            from hashguard.threat_intel import query_all

            sha256 = hashes.get("sha256", "")
            if sha256:
                ti_result = query_all(sha256)
                threat_intel_info = ti_result.to_dict()
                if ti_result.flagged_count > 0:
                    flagged = [h.source for h in ti_result.hits if h.found]
                    findings.append(f"Flagged by: {', '.join(flagged)}")
        except Exception as e:
            logger.debug(f"Threat intel query skipped: {e}")

    # String extraction
    strings_info = None
    try:
        from hashguard.string_extractor import extract_strings

        str_result = extract_strings(file_path)
        strings_info = str_result.to_dict()
    except Exception as e:
        logger.debug(f"String extraction skipped: {e}")

    # Risk scoring
    risk_score_info = None
    try:
        from hashguard.risk_scorer import compute_risk

        risk = compute_risk(
            signature_match=hash_signature_match,
            signature_name=description if hash_signature_match else "",
            pe_info=pe_info,
            yara_matches=yara_info,
            threat_intel=threat_intel_info,
            strings_info=strings_info,
        )
        risk_score_info = risk.to_dict()
        # Set malicious flag based on risk verdict
        if risk.verdict == "malicious":
            is_malicious = True
    except Exception as e:
        logger.debug(f"Risk scoring skipped: {e}")

    # ── v2 Extended Analysis ────────────────────────────────────────────────

    # Capability detection
    capabilities_info = None
    try:
        from hashguard.capability_detector import detect_capabilities

        caps = detect_capabilities(file_path, pe_info=pe_info)
        if caps.total_detected > 0:
            capabilities_info = caps.to_dict()
    except Exception as e:
        logger.debug(f"Capability detection skipped: {e}")

    # Advanced PE analysis
    advanced_pe_info = None
    try:
        from hashguard.advanced_pe import analyze_advanced_pe
        from hashguard.pe_analyzer import is_pe_file

        if is_pe_file(file_path):
            adv = analyze_advanced_pe(file_path)
            if (
                adv.imphash
                or (adv.tls and adv.tls.has_tls)
                or (adv.anti_analysis and adv.anti_analysis.total_detections > 0)
            ):
                advanced_pe_info = adv.to_dict()
    except Exception as e:
        logger.debug(f"Advanced PE skipped: {e}")

    # Fuzzy hashing — skip in batch mode (DB lookups grow expensive)
    fuzzy_info = None
    if not batch_mode:
        try:
            from hashguard.fuzzy_hasher import find_similar

            sha256 = hashes.get("sha256", "")
            fuzzy = find_similar(file_path, sha256=sha256)
            fuzzy_info = fuzzy.to_dict()
        except Exception as e:
            logger.debug(f"Fuzzy hashing skipped: {e}")

    # ML classification
    ml_info = None
    try:
        from hashguard.ml_classifier import classify

        ml = classify(file_path, pe_info=pe_info)
        if ml.predicted_class != "unknown":
            ml_info = ml.to_dict()
            # ML with high confidence for non-benign => flag malicious
            if ml.predicted_class != "benign" and ml.confidence >= 0.75 and not is_malicious:
                is_malicious = True
                findings.append(f"ML: {ml.predicted_class} ({ml.confidence:.0%})")
            # Anomaly detection
            if ml.is_anomaly and not is_malicious:
                findings.append("ML anomaly detected")
    except Exception as e:
        logger.debug(f"ML classification skipped: {e}")

    # Family detection
    family_info = None
    try:
        from hashguard.family_detector import detect_family

        family = detect_family(
            file_path,
            pe_info=pe_info,
            yara_matches=yara_info,
            threat_intel=threat_intel_info,
            ml_result=ml_info,
            strings_info=strings_info,
        )
        if family.family:
            family_info = family.to_dict()
    except Exception as e:
        logger.debug(f"Family detection skipped: {e}")

    # Packer / shellcode detection
    packer_info = None
    shellcode_info = None
    try:
        from hashguard.unpacker import detect_packer, detect_shellcode

        packed, packer_name = detect_packer(file_path)
        if packed:
            packer_info = {"detected": True, "name": packer_name}
        sc = detect_shellcode(file_path)
        if sc.detected:
            shellcode_info = sc.to_dict()
            if sc.confidence in ("high", "medium") and not is_malicious:
                is_malicious = True
                findings.append(f"Shellcode detected ({sc.confidence})")
    except Exception as e:
        logger.debug(f"Unpacker/shellcode skipped: {e}")

    # Script deobfuscation (for scripts: .ps1, .vbs, .js, .bat, .hta, etc.)
    deobfuscation_info = None
    try:
        ext = os.path.splitext(file_path)[1].lower()
        script_exts = {
            ".ps1",
            ".psm1",
            ".vbs",
            ".vbe",
            ".js",
            ".jse",
            ".wsf",
            ".bat",
            ".cmd",
            ".hta",
        }
        if ext in script_exts:
            from hashguard.deobfuscator import analyze_script

            deob = analyze_script(file_path)
            if deob.obfuscation_detected or deob.iocs_extracted or deob.risk_indicators:
                deobfuscation_info = deob.to_dict()
            # Flag as malicious if high-risk indicators found
            high_risk_keywords = {
                "AMSI bypass",
                "Credential theft",
                "Memory manipulation",
                "shellcode injection",
                "Firewall manipulation",
            }
            if any(
                r
                for r in deob.risk_indicators
                if any(k.lower() in r.lower() for k in high_risk_keywords)
            ):
                if not is_malicious:
                    is_malicious = True
                    findings.append(f"Malicious script: {deob.risk_indicators[0]}")
    except Exception as e:
        logger.debug(f"Script deobfuscation skipped: {e}")

    # ── Second-pass risk scoring with ALL signals ───────────────────────────
    # The initial risk score was computed before capabilities, ML, etc.
    # Recompute it now with the full picture.
    try:
        from hashguard.risk_scorer import compute_risk

        risk = compute_risk(
            signature_match=hash_signature_match,
            signature_name=description if hash_signature_match else "",
            pe_info=pe_info,
            yara_matches=yara_info,
            threat_intel=threat_intel_info,
            strings_info=strings_info,
            capabilities=capabilities_info,
            ml_result=ml_info,
        )
        risk_score_info = risk.to_dict()
        if risk.verdict == "malicious" and not is_malicious:
            is_malicious = True
            findings.append(f"Risk score {risk.score}/100")
    except Exception as e:
        logger.debug(f"Second-pass risk scoring skipped: {e}")

    # Assemble final description from accumulated findings.
    description = "; ".join(findings) if findings else "Clean"

    return (
        is_malicious,
        description,
        pe_info,
        yara_info,
        threat_intel_info,
        risk_score_info,
        strings_info,
        capabilities_info,
        advanced_pe_info,
        fuzzy_info,
        ml_info,
        family_info,
        packer_info,
        shellcode_info,
        deobfuscation_info,
    )


def analyze(
    path: str,
    vt: bool = False,
    config: Optional[HashGuardConfig] = None,
    *,
    batch_mode: bool = False,
) -> FileAnalysisResult:
    """
    Perform comprehensive file analysis.

    Args:
        path: Path to file to analyze
        vt: Whether to query VirusTotal
        config: Configuration object
        batch_mode: If True, skip expensive network queries (threat intel)
            and post-processing (IOC graph, timeline) for faster batch ingest.

    Returns:
        FileAnalysisResult with detailed analysis

    Raises:
        FileNotFoundError: If file doesn't exist
    """
    config = config or get_default_config()
    start_time = time.time()

    if not os.path.isfile(path):
        raise FileNotFoundError(f"File not found: {path}")

    try:
        # Compute hashes
        hashes = compute_hashes(path, config=config)

        # Check against signature database (use config-specific database)
        sig_db = SignatureDatabase(config)
        matching_sigs = [(h, sig_db.get(h)) for h in hashes.values() if sig_db.contains(h)]

        is_malicious = bool(matching_sigs)
        description = matching_sigs[0][1] if matching_sigs else "Clean"

        # Get file size
        file_size = os.path.getsize(path)

        # Extended analysis: PE, YARA, threat intel, strings, risk + v2 modules
        (
            is_malicious,
            description,
            pe_info,
            yara_info,
            threat_intel_info,
            risk_score_info,
            strings_info,
            capabilities_info,
            advanced_pe_info,
            fuzzy_info,
            ml_info,
            family_info,
            packer_info,
            shellcode_info,
            deobfuscation_info,
        ) = _run_extended_analysis(path, hashes, is_malicious, description, config, batch_mode=batch_mode)

        # IOC graph (needs full result context) — skip in batch mode
        ioc_graph_info = None
        if not batch_mode:
            try:
                from hashguard.ioc_graph import build_graph

                partial = {
                    "strings_info": strings_info,
                    "threat_intel": threat_intel_info,
                    "pe_info": pe_info,
                    "family_detection": family_info,
                }
                graph = build_graph(partial)
                if graph.nodes:
                    ioc_graph_info = graph.to_visjs()
            except Exception:
                pass

        # Timeline — skip in batch mode
        timeline_info = None
        if not batch_mode:
            try:
                from hashguard.malware_timeline import build_timeline

                partial = {
                    "capabilities": capabilities_info,
                    "pe_info": pe_info,
                    "yara_matches": yara_info,
                    "threat_intel": threat_intel_info,
                    "packer": packer_info,
                    "shellcode": shellcode_info,
                    "family_detection": family_info,
                }
                tl = build_timeline(partial)
                if tl.events:
                    timeline_info = tl.to_dict()
            except Exception:
                pass

        # Optional VirusTotal query
        vt_result = None
        if vt:
            vt_result = query_virustotal(path, config=config)

        analysis_time = time.time() - start_time

        logger.info(f"Analysis complete for {path} ({file_size} bytes) in {analysis_time:.2f}s")

        return FileAnalysisResult(
            path=path,
            hashes=hashes,
            malicious=is_malicious,
            description=description,
            vt_result=vt_result,
            file_size=file_size,
            analysis_time=analysis_time,
            pe_info=pe_info,
            yara_matches=yara_info,
            threat_intel=threat_intel_info,
            risk_score=risk_score_info,
            strings_info=strings_info,
            capabilities=capabilities_info,
            advanced_pe=advanced_pe_info,
            fuzzy_hashes=fuzzy_info,
            ml_classification=ml_info,
            family_detection=family_info,
            ioc_graph=ioc_graph_info,
            timeline=timeline_info,
            packer=packer_info,
            shellcode=shellcode_info,
            script_deobfuscation=deobfuscation_info,
        )

    except Exception as e:
        logger.error(f"Analysis failed for {path}: {e}")
        raise


def _is_private_ip(hostname: str) -> bool:
    """Resolve *hostname* and return True if any address is private/reserved.

    Covers RFC 1918, RFC 6598 (CGN), RFC 5737 (doc), loopback, link-local,
    and IPv6 equivalents.  Resolves DNS so that crafted hostnames pointing
    to internal IPs are caught.
    """
    import ipaddress
    import socket

    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        # Unresolvable hostname — not an SSRF risk, let requests handle the error
        return False

    for family, _type, _proto, _canon, sockaddr in infos:
        ip_str = sockaddr[0]
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            return True
    return False


def analyze_url(
    url: str,
    vt: bool = False,
    config: Optional[HashGuardConfig] = None,
) -> FileAnalysisResult:
    """Download a URL to a temp file, analyze it, and optionally query VirusTotal URL scan."""
    import tempfile
    from urllib.parse import urlparse

    try:
        import requests as req
    except ImportError:
        raise RuntimeError("requests library is required for URL analysis")

    # Validate URL scheme to prevent SSRF
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme!r}")
    if not parsed.hostname:
        raise ValueError("Invalid URL: no hostname")
    # Resolve hostname and block all private / reserved IP ranges
    if _is_private_ip(parsed.hostname):
        raise ValueError("URL points to a local/private address")

    config = config or get_default_config()
    start_time = time.time()

    # Disable automatic redirects and validate each hop against SSRF
    max_redirects = 10
    current_url = url
    resp = None
    for _ in range(max_redirects):
        resp = req.get(current_url, timeout=30, stream=True, allow_redirects=False, verify=True)
        if resp.is_redirect or resp.is_permanent_redirect:
            redirect_url = resp.headers.get("Location", "")
            parsed_redir = urlparse(redirect_url)
            if parsed_redir.scheme and parsed_redir.scheme not in ("http", "https"):
                raise ValueError(f"Redirect uses unsupported scheme: {parsed_redir.scheme!r}")
            if parsed_redir.hostname and _is_private_ip(parsed_redir.hostname):
                raise ValueError("Redirect points to a local/private address")
            current_url = redirect_url
            continue
        break
    else:
        raise ValueError("Too many redirects")
    resp.raise_for_status()

    # Stream to temp file with a 200 MB safety limit
    max_download = 200 * 1024 * 1024
    downloaded = 0
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".download")
    try:
        for chunk in resp.iter_content(chunk_size=config.chunk_size):
            downloaded += len(chunk)
            if downloaded > max_download:
                tmp.close()
                os.unlink(tmp.name)
                raise ValueError("Download exceeds 200 MB limit")
            tmp.write(chunk)
        tmp.close()

        # Analyze the downloaded file
        hashes = compute_hashes(tmp.name, config=config)
        sig_db = SignatureDatabase(config)
        matching_sigs = [(h, sig_db.get(h)) for h in hashes.values() if sig_db.contains(h)]
        is_malicious = bool(matching_sigs)
        description = matching_sigs[0][1] if matching_sigs else "Clean"
        file_size = os.path.getsize(tmp.name)

        # Extended analysis: PE, YARA, threat intel, strings, risk + v2 modules
        (
            is_malicious,
            description,
            pe_info,
            yara_info,
            threat_intel_info,
            risk_score_info,
            strings_info,
            capabilities_info,
            advanced_pe_info,
            fuzzy_info,
            ml_info,
            family_info,
            packer_info,
            shellcode_info,
            deobfuscation_info,
        ) = _run_extended_analysis(tmp.name, hashes, is_malicious, description, config)

        # IOC graph
        ioc_graph_info = None
        try:
            from hashguard.ioc_graph import build_graph

            partial = {
                "strings_info": strings_info,
                "threat_intel": threat_intel_info,
                "pe_info": pe_info,
                "family_detection": family_info,
            }
            graph = build_graph(partial)
            if graph.nodes:
                ioc_graph_info = graph.to_visjs()
        except Exception:
            pass

        # Timeline
        timeline_info = None
        try:
            from hashguard.malware_timeline import build_timeline

            partial = {
                "capabilities": capabilities_info,
                "pe_info": pe_info,
                "yara_matches": yara_info,
                "threat_intel": threat_intel_info,
                "packer": packer_info,
                "shellcode": shellcode_info,
                "family_detection": family_info,
            }
            tl = build_timeline(partial)
            if tl.events:
                timeline_info = tl.to_dict()
        except Exception:
            pass

        # VirusTotal: query both file hash and URL
        vt_result = None
        if vt:
            vt_result = query_virustotal(tmp.name, config=config)
            url_vt = query_virustotal_url(url, config=config)
            if url_vt and not vt_result:
                vt_result = url_vt
            elif url_vt and vt_result:
                vt_result["url_scan"] = url_vt

        analysis_time = time.time() - start_time
        return FileAnalysisResult(
            path=url,
            hashes=hashes,
            malicious=is_malicious,
            description=description,
            vt_result=vt_result,
            file_size=file_size,
            analysis_time=analysis_time,
            pe_info=pe_info,
            yara_matches=yara_info,
            threat_intel=threat_intel_info,
            risk_score=risk_score_info,
            strings_info=strings_info,
            capabilities=capabilities_info,
            advanced_pe=advanced_pe_info,
            fuzzy_hashes=fuzzy_info,
            ml_classification=ml_info,
            family_detection=family_info,
            ioc_graph=ioc_graph_info,
            timeline=timeline_info,
            packer=packer_info,
            shellcode=shellcode_info,
            script_deobfuscation=deobfuscation_info,
        )
    finally:
        if os.path.exists(tmp.name):
            os.unlink(tmp.name)
