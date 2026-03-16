"""Webhook & notification system for HashGuard.

Sends real-time alerts when:
- High-risk malware is detected (configurable threshold)
- New malware family is discovered
- Anomalies are detected

Supports:
- HTTP webhooks (POST JSON payloads)
- Configurable per-hook filters (min risk score, verdicts, families)
"""

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from hashguard.logger import get_logger

logger = get_logger(__name__)

# ── Webhook storage ─────────────────────────────────────────────────────────


def _get_webhooks_dir() -> Path:
    """Return the directory for webhook configuration."""
    app_data = os.environ.get("APPDATA") or os.path.expanduser("~")
    d = Path(app_data) / "HashGuard" / "webhooks"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _load_webhooks() -> dict:
    path = _get_webhooks_dir() / "webhooks.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save_webhooks(hooks: dict) -> None:
    path = _get_webhooks_dir() / "webhooks.json"
    path.write_text(json.dumps(hooks, indent=2), encoding="utf-8")


# ── CRUD ────────────────────────────────────────────────────────────────────

VALID_EVENTS = {
    "analysis.completed",
    "analysis.high_risk",
    "analysis.malicious",
    "family.new",
    "anomaly.detected",
    "ingest.completed",
}


def create_webhook(
    name: str,
    url: str,
    events: List[str],
    min_risk_score: int = 0,
    secret: str = "",
    active: bool = True,
) -> dict:
    """Register a new webhook endpoint.

    Args:
        name: Human-readable name
        url: Target URL (must be HTTPS in production)
        events: List of event types to subscribe to
        min_risk_score: Only fire for samples above this risk score (0-100)
        secret: Optional secret for HMAC-SHA256 signature verification
        active: Whether the webhook is initially active

    Returns:
        dict with hook_id, name, url, events, secret (the raw secret, shown once)
    """
    # Validate events
    invalid = set(events) - VALID_EVENTS
    if invalid:
        raise ValueError(f"Invalid events: {invalid}. Valid: {VALID_EVENTS}")

    if not url:
        raise ValueError("URL is required")

    hook_id = secrets.token_hex(8)
    hook_secret = secret or secrets.token_hex(16)

    hooks = _load_webhooks()
    hooks[hook_id] = {
        "name": name,
        "url": url,
        "events": list(events),
        "min_risk_score": min_risk_score,
        "secret_hash": hashlib.sha256(hook_secret.encode()).hexdigest(),
        "active": active,
        "created_at": time.time(),
        "last_triggered": 0.0,
        "trigger_count": 0,
        "last_error": "",
    }
    _save_webhooks(hooks)

    logger.info("Created webhook (id=%s, events=%s)", hook_id, events)
    return {
        "hook_id": hook_id,
        "name": name,
        "url": url,
        "events": list(events),
        "secret": hook_secret,
    }


def update_webhook(hook_id: str, **kwargs) -> bool:
    """Update webhook configuration fields."""
    hooks = _load_webhooks()
    if hook_id not in hooks:
        return False

    allowed_fields = {"name", "url", "events", "min_risk_score", "active"}
    for k, v in kwargs.items():
        if k in allowed_fields:
            if k == "events":
                invalid = set(v) - VALID_EVENTS
                if invalid:
                    raise ValueError(f"Invalid events: {invalid}")
            hooks[hook_id][k] = v

    _save_webhooks(hooks)
    return True


def delete_webhook(hook_id: str) -> bool:
    """Delete a webhook."""
    hooks = _load_webhooks()
    if hook_id not in hooks:
        return False
    del hooks[hook_id]
    _save_webhooks(hooks)
    logger.info("Webhook deleted")
    return True


def list_webhooks() -> list:
    """List all webhooks (without secrets)."""
    hooks = _load_webhooks()
    return [
        {
            "hook_id": hid,
            "name": h["name"],
            "url": h["url"],
            "events": h["events"],
            "min_risk_score": h.get("min_risk_score", 0),
            "active": h["active"],
            "created_at": h["created_at"],
            "last_triggered": h.get("last_triggered", 0),
            "trigger_count": h.get("trigger_count", 0),
            "last_error": h.get("last_error", ""),
        }
        for hid, h in hooks.items()
    ]


def get_webhook(hook_id: str) -> Optional[dict]:
    """Get a single webhook by ID."""
    hooks = _load_webhooks()
    if hook_id not in hooks:
        return None
    h = hooks[hook_id]
    return {
        "hook_id": hook_id,
        "name": h["name"],
        "url": h["url"],
        "events": h["events"],
        "min_risk_score": h.get("min_risk_score", 0),
        "active": h["active"],
        "created_at": h["created_at"],
        "last_triggered": h.get("last_triggered", 0),
        "trigger_count": h.get("trigger_count", 0),
        "last_error": h.get("last_error", ""),
    }


def send_test(hook_id: str) -> dict:
    """Send a test payload to a webhook."""
    hooks = _load_webhooks()
    if hook_id not in hooks:
        return {"success": False, "error": "Webhook not found"}

    test_payload = {
        "event": "test",
        "timestamp": time.time(),
        "data": {
            "message": "This is a test notification from HashGuard",
            "hook_id": hook_id,
        },
    }
    return _deliver(hook_id, hooks[hook_id], test_payload)


# ── Delivery ────────────────────────────────────────────────────────────────


def _sign_payload(payload_bytes: bytes, secret_hash: str) -> str:
    """Create HMAC-SHA256 signature for payload verification."""
    return hmac.new(
        secret_hash.encode("utf-8"),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()


def _deliver(hook_id: str, hook: dict, payload: dict) -> dict:
    """Deliver a webhook payload via HTTP POST."""
    import urllib.request
    import urllib.error

    payload_bytes = json.dumps(payload, default=str).encode("utf-8")
    signature = _sign_payload(payload_bytes, hook.get("secret_hash", ""))

    req = urllib.request.Request(
        hook["url"],
        data=payload_bytes,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "HashGuard-Webhook/1.0",
            "X-HashGuard-Signature": f"sha256={signature}",
            "X-HashGuard-Event": payload.get("event", "unknown"),
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.status
            body = resp.read().decode("utf-8", errors="replace")[:500]

        # Update stats
        hooks = _load_webhooks()
        if hook_id in hooks:
            hooks[hook_id]["last_triggered"] = time.time()
            hooks[hook_id]["trigger_count"] = hooks[hook_id].get("trigger_count", 0) + 1
            hooks[hook_id]["last_error"] = ""
            _save_webhooks(hooks)

        return {"success": True, "status_code": status, "response": body}

    except urllib.error.HTTPError as e:
        error_msg = f"HTTP {e.code}"
        _record_error(hook_id, error_msg)
        return {"success": False, "error": error_msg}
    except urllib.error.URLError:
        error_msg = "Connection error"
        _record_error(hook_id, error_msg)
        return {"success": False, "error": error_msg}
    except Exception:
        error_msg = "Delivery failed"
        _record_error(hook_id, error_msg)
        return {"success": False, "error": error_msg}


def _record_error(hook_id: str, error_msg: str) -> None:
    hooks = _load_webhooks()
    if hook_id in hooks:
        hooks[hook_id]["last_error"] = error_msg
        _save_webhooks(hooks)
    logger.warning("Webhook delivery failed")


# ── Event dispatch ──────────────────────────────────────────────────────────


def fire_event(event: str, data: dict) -> int:
    """Fire a webhook event to all matching hooks.

    Deliveries happen in background threads so this returns immediately.

    Args:
        event: Event type (e.g., "analysis.high_risk")
        data: Event payload data

    Returns:
        Number of hooks that matched the event
    """
    hooks = _load_webhooks()
    matched = 0

    for hook_id, hook in hooks.items():
        if not hook.get("active", True):
            continue
        if event not in hook.get("events", []):
            continue

        # Risk score filter
        min_score = hook.get("min_risk_score", 0)
        if min_score > 0:
            sample_score = data.get("risk_score", 0)
            if sample_score < min_score:
                continue

        payload = {
            "event": event,
            "timestamp": time.time(),
            "data": data,
        }

        # Fire in background thread
        t = threading.Thread(
            target=_deliver,
            args=(hook_id, hook, payload),
            daemon=True,
        )
        t.start()
        matched += 1

    return matched


# ── Convenience helpers for scanner integration ─────────────────────────────


def notify_analysis_complete(result: dict) -> int:
    """Fire notifications after a file analysis completes.

    Automatically determines which events to fire based on the result.
    """
    risk_score = 0
    if isinstance(result.get("risk_score"), dict):
        risk_score = result["risk_score"].get("score", 0)
    elif isinstance(result.get("risk_score"), (int, float)):
        risk_score = int(result["risk_score"])

    verdict = ""
    if isinstance(result.get("risk_score"), dict):
        verdict = result["risk_score"].get("verdict", "")

    sha256 = result.get("hashes", {}).get("sha256", "")
    family = ""
    fd = result.get("family_detection", {})
    if isinstance(fd, dict):
        family = fd.get("family", "")

    base_data = {
        "sha256": sha256,
        "filename": os.path.basename(result.get("path", "")),
        "risk_score": risk_score,
        "verdict": verdict,
        "family": family,
        "sample_id": result.get("sample_id"),
    }

    total = 0

    # Always fire analysis.completed
    total += fire_event("analysis.completed", base_data)

    # Fire analysis.malicious for malicious verdicts
    if result.get("malicious") or verdict == "malicious":
        total += fire_event("analysis.malicious", base_data)

    # Fire analysis.high_risk for high scores (>= 70)
    if risk_score >= 70:
        total += fire_event("analysis.high_risk", base_data)

    return total
