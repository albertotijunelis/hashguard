"""SOC Integration router — SIEM/SOAR connectors.

Provides endpoints and utilities for integrating HashGuard with
Security Operations Center tooling:

- Syslog/CEF forwarding configuration
- Splunk HEC (HTTP Event Collector) forwarding
- Elastic/OpenSearch bulk index
- Microsoft Sentinel webhook connector
- Generic alert forwarding (any HTTP endpoint)

All connectors use a stored configuration and can be tested on-demand.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api/soc", tags=["soc"])
logger = logging.getLogger("hashguard.soc")


def _soc_dep():
    """Plan dependency — SOC integrations require Team+ plan."""
    from hashguard.web.billing import require_feature
    return require_feature("soc")

# ---------------------------------------------------------------------------
# Config persistence
# ---------------------------------------------------------------------------

def _config_path() -> Path:
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    return Path(base) / "HashGuard" / "soc_integrations.json"


def _load_integrations() -> List[Dict[str, Any]]:
    path = _config_path()
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return []


def _save_integrations(items: List[Dict[str, Any]]):
    path = _config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(items, f, indent=2, default=str)


_VALID_TYPES = {"syslog", "splunk_hec", "elastic", "sentinel", "generic_http"}


# ---------------------------------------------------------------------------
# Format converters
# ---------------------------------------------------------------------------

def to_cef(sample: dict) -> str:
    """Convert a sample record to CEF (Common Event Format) string."""
    severity = "10" if sample.get("verdict") == "malicious" else (
        "5" if sample.get("verdict") == "suspicious" else "1"
    )
    sha = sample.get("sha256", "")
    name = sample.get("filename", sha[:16])
    score = sample.get("risk_score", 0)
    return (
        f"CEF:0|HashGuard|MalwareAnalysis|1.1.4|{sample.get('verdict', 'unknown')}|"
        f"{name}|{severity}|"
        f"fileHash={sha} "
        f"fname={name} "
        f"cn1={score} cn1Label=RiskScore "
        f"cs1={sample.get('family', '')} cs1Label=MalwareFamily "
        f"rt={sample.get('analysis_date', '')}"
    )


def to_ecs(sample: dict) -> dict:
    """Convert a sample record to Elastic Common Schema (ECS) format."""
    return {
        "@timestamp": sample.get("analysis_date") or datetime.now(timezone.utc).isoformat(),
        "event": {
            "kind": "alert",
            "category": ["malware"],
            "type": ["indicator"],
            "severity": sample.get("risk_score", 0),
            "outcome": sample.get("verdict", "unknown"),
        },
        "file": {
            "name": sample.get("filename", ""),
            "size": sample.get("file_size", 0),
            "hash": {
                "sha256": sample.get("sha256", ""),
                "md5": sample.get("md5", ""),
                "sha1": sample.get("sha1", ""),
            },
        },
        "threat": {
            "indicator": {
                "type": "file",
                "description": sample.get("description", ""),
                "confidence": "High" if sample.get("verdict") == "malicious" else "Medium",
            },
            "software": {
                "name": sample.get("family", "") or "unknown",
            },
        },
        "hashguard": {
            "risk_score": sample.get("risk_score", 0),
            "verdict": sample.get("verdict", "unknown"),
            "family": sample.get("family", ""),
        },
    }


def to_sentinel(sample: dict) -> dict:
    """Convert a sample to Microsoft Sentinel Threat Intelligence format."""
    return {
        "action": "alert",
        "targetProduct": "Azure Sentinel",
        "description": sample.get("description", ""),
        "title": f"HashGuard: {sample.get('filename', 'Unknown')}",
        "severity": (
            "high" if sample.get("verdict") == "malicious"
            else "medium" if sample.get("verdict") == "suspicious"
            else "informational"
        ),
        "tlpLevel": "amber",
        "fileHashType": "sha256",
        "fileHashValue": sample.get("sha256", ""),
        "malwareFamilyNames": [sample.get("family")] if sample.get("family") else [],
        "confidence": sample.get("risk_score", 0),
        "additionalInformation": json.dumps({
            "risk_score": sample.get("risk_score", 0),
            "verdict": sample.get("verdict", "unknown"),
        }),
    }


# ---------------------------------------------------------------------------
# Forwarding engine
# ---------------------------------------------------------------------------

def _forward_to_syslog(integration: dict, sample: dict) -> dict:
    """Send CEF-formatted event to a syslog server."""
    host = integration.get("host", "127.0.0.1")
    port = int(integration.get("port", 514))
    protocol = integration.get("protocol", "udp")
    msg = to_cef(sample)

    try:
        if protocol == "tcp":
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((host, port))
            s.sendall((msg + "\n").encode("utf-8"))
            s.close()
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(msg.encode("utf-8"), (host, port))
            s.close()
        return {"ok": True, "format": "cef"}
    except Exception:
        return {"ok": False, "error": "Syslog delivery failed"}


def _forward_to_splunk(integration: dict, sample: dict) -> dict:
    """Send event to Splunk HTTP Event Collector."""
    try:
        import httpx
    except ImportError:
        return {"ok": False, "error": "httpx not installed"}

    url = integration.get("url", "")
    token = integration.get("token", "")
    if not url or not token:
        return {"ok": False, "error": "url and token required"}

    payload = {
        "event": to_ecs(sample),
        "sourcetype": "hashguard:analysis",
        "source": "hashguard",
        "index": integration.get("index", "main"),
    }
    try:
        r = httpx.post(
            url, json=payload,
            headers={"Authorization": f"Splunk {token}"},
            timeout=15, verify=False,
        )
        return {"ok": r.status_code < 300, "status_code": r.status_code}
    except Exception:
        return {"ok": False, "error": "Splunk delivery failed"}


def _forward_to_elastic(integration: dict, sample: dict) -> dict:
    """Send event to Elastic/OpenSearch index."""
    try:
        import httpx
    except ImportError:
        return {"ok": False, "error": "httpx not installed"}

    url = integration.get("url", "")
    index = integration.get("index", "hashguard-alerts")
    api_key = integration.get("api_key", "")
    if not url:
        return {"ok": False, "error": "url required"}

    doc = to_ecs(sample)
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"

    try:
        r = httpx.post(
            f"{url.rstrip('/')}/{index}/_doc",
            json=doc, headers=headers, timeout=15, verify=False,
        )
        return {"ok": r.status_code < 300, "status_code": r.status_code}
    except Exception:
        return {"ok": False, "error": "Elastic delivery failed"}


def _forward_to_sentinel(integration: dict, sample: dict) -> dict:
    """Send event to Microsoft Sentinel via Log Analytics API."""
    try:
        import httpx
    except ImportError:
        return {"ok": False, "error": "httpx not installed"}

    url = integration.get("url", "")
    shared_key = integration.get("shared_key", "")
    if not url:
        return {"ok": False, "error": "url required"}

    payload = to_sentinel(sample)
    headers = {"Content-Type": "application/json"}
    if shared_key:
        headers["Authorization"] = f"SharedKey {shared_key}"

    try:
        r = httpx.post(url, json=payload, headers=headers, timeout=15)
        return {"ok": r.status_code < 300, "status_code": r.status_code}
    except Exception:
        return {"ok": False, "error": "Sentinel delivery failed"}


def _forward_to_generic(integration: dict, sample: dict) -> dict:
    """Send JSON event to any HTTP endpoint."""
    try:
        import httpx
    except ImportError:
        return {"ok": False, "error": "httpx not installed"}

    url = integration.get("url", "")
    if not url:
        return {"ok": False, "error": "url required"}

    headers = {"Content-Type": "application/json"}
    for k, v in (integration.get("headers") or {}).items():
        headers[k] = v

    try:
        r = httpx.post(url, json=to_ecs(sample), headers=headers, timeout=15)
        return {"ok": r.status_code < 300, "status_code": r.status_code}
    except Exception:
        return {"ok": False, "error": "HTTP delivery failed"}


_FORWARDERS = {
    "syslog": _forward_to_syslog,
    "splunk_hec": _forward_to_splunk,
    "elastic": _forward_to_elastic,
    "sentinel": _forward_to_sentinel,
    "generic_http": _forward_to_generic,
}


def forward_alert(sample: dict):
    """Forward an analysis result to all enabled SOC integrations."""
    integrations = _load_integrations()
    for integ in integrations:
        if not integ.get("enabled", True):
            continue
        min_score = integ.get("min_risk_score", 0)
        if sample.get("risk_score", 0) < min_score:
            continue
        forwarder = _FORWARDERS.get(integ.get("type"))
        if forwarder:
            try:
                forwarder(integ, sample)
            except Exception as e:
                logger.debug(f"SOC forward error ({integ.get('type')}): {e}")


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

@router.get("/integrations")
async def list_integrations(user: dict = Depends(_soc_dep())):
    """List all configured SOC integrations."""
    items = _load_integrations()
    # Mask sensitive fields
    safe = []
    for it in items:
        entry = dict(it)
        for secret_key in ("token", "api_key", "shared_key"):
            if entry.get(secret_key):
                val = entry[secret_key]
                entry[secret_key] = val[:4] + "***" if len(val) >= 4 else "***"
        safe.append(entry)
    return {"integrations": safe}


@router.post("/integrations")
async def create_integration(payload: Dict[str, Any] = Body(...), user: dict = Depends(_soc_dep())):
    """Create a new SOC integration connector."""
    itype = payload.get("type", "")
    if itype not in _VALID_TYPES:
        raise HTTPException(400, f"Invalid type. Must be one of: {', '.join(sorted(_VALID_TYPES))}")

    name = payload.get("name", itype)
    integration = {
        "id": f"soc_{int(time.time())}_{name[:10]}",
        "name": name,
        "type": itype,
        "enabled": payload.get("enabled", True),
        "min_risk_score": int(payload.get("min_risk_score", 0)),
        "created": datetime.now(timezone.utc).isoformat(),
    }
    # Type-specific config
    for key in ("host", "port", "protocol", "url", "token", "api_key",
                "shared_key", "index", "headers"):
        if key in payload:
            integration[key] = payload[key]

    items = _load_integrations()
    items.append(integration)
    _save_integrations(items)
    return {"ok": True, "integration": integration}


@router.put("/integrations/{integration_id}")
async def update_integration(integration_id: str, payload: Dict[str, Any] = Body(...), user: dict = Depends(_soc_dep())):
    """Update an existing SOC integration."""
    items = _load_integrations()
    for i, it in enumerate(items):
        if it.get("id") == integration_id:
            for key in ("name", "enabled", "min_risk_score", "host", "port",
                        "protocol", "url", "token", "api_key", "shared_key",
                        "index", "headers"):
                if key in payload:
                    items[i][key] = payload[key]
            _save_integrations(items)
            return {"ok": True, "integration": items[i]}
    raise HTTPException(404, "Integration not found")


@router.delete("/integrations/{integration_id}")
async def delete_integration(integration_id: str, user: dict = Depends(_soc_dep())):
    """Delete a SOC integration."""
    items = _load_integrations()
    new_items = [it for it in items if it.get("id") != integration_id]
    if len(new_items) == len(items):
        raise HTTPException(404, "Integration not found")
    _save_integrations(new_items)
    return {"ok": True}


@router.post("/integrations/{integration_id}/test")
async def test_integration(integration_id: str, user: dict = Depends(_soc_dep())):
    """Send a test event to a specific integration."""
    items = _load_integrations()
    integration = next((it for it in items if it.get("id") == integration_id), None)
    if not integration:
        raise HTTPException(404, "Integration not found")

    test_sample = {
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
        "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "filename": "test_event.exe",
        "file_size": 12345,
        "risk_score": 85,
        "verdict": "malicious",
        "family": "TestFamily",
        "description": "HashGuard SOC integration test event",
        "analysis_date": datetime.now(timezone.utc).isoformat(),
    }

    forwarder = _FORWARDERS.get(integration.get("type"))
    if not forwarder:
        raise HTTPException(400, f"Unknown type: {integration.get('type')}")

    result = forwarder(integration, test_sample)
    return {"ok": result.get("ok", False), "result": result}


@router.get("/formats/cef")
async def sample_cef():
    """Return a sample CEF-formatted event for documentation."""
    sample = {
        "sha256": "a" * 64,
        "filename": "sample.exe",
        "risk_score": 85,
        "verdict": "malicious",
        "family": "Emotet",
        "analysis_date": datetime.now(timezone.utc).isoformat(),
    }
    return {"format": "cef", "example": to_cef(sample)}


@router.get("/formats/ecs")
async def sample_ecs():
    """Return a sample ECS-formatted event for documentation."""
    sample = {
        "sha256": "a" * 64,
        "md5": "c" * 32,
        "sha1": "b" * 40,
        "filename": "sample.exe",
        "file_size": 12345,
        "risk_score": 85,
        "verdict": "malicious",
        "family": "Emotet",
        "description": "Trojan detected",
        "analysis_date": datetime.now(timezone.utc).isoformat(),
    }
    return {"format": "ecs", "example": to_ecs(sample)}


@router.get("/formats/sentinel")
async def sample_sentinel():
    """Return a sample Sentinel-formatted event for documentation."""
    sample = {
        "sha256": "a" * 64,
        "filename": "sample.exe",
        "risk_score": 85,
        "verdict": "malicious",
        "family": "Emotet",
        "description": "Trojan detected",
    }
    return {"format": "sentinel", "example": to_sentinel(sample)}
