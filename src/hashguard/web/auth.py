"""Authentication & authorization for the HashGuard API.

Provides:
- JWT token generation and validation
- API key management (hashed storage)
- FastAPI dependency for protecting endpoints
- Role-based access (admin, analyst, viewer)
"""

import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from hashguard.logger import get_logger

logger = get_logger(__name__)

try:
    import jwt as pyjwt

    HAS_JWT = True
except ImportError:
    HAS_JWT = False

try:
    import bcrypt

    HAS_BCRYPT = True
except ImportError:
    HAS_BCRYPT = False


# ── Configuration ───────────────────────────────────────────────────────────

_DEFAULT_TOKEN_EXPIRY = 86400  # 24 hours
_ALGORITHM = "HS256"

ROLES = {"admin", "analyst", "viewer"}

# Permissions per role
ROLE_PERMISSIONS = {
    "admin": {
        "analyze", "read", "search", "export",
        "ingest", "train", "settings", "manage_keys",
    },
    "analyst": {
        "analyze", "read", "search", "export", "ingest", "train",
    },
    "viewer": {
        "read", "search",
    },
}


def _get_auth_dir() -> Path:
    """Return the directory for auth data files."""
    app_data = os.environ.get("APPDATA") or os.path.expanduser("~")
    auth_dir = Path(app_data) / "HashGuard" / "auth"
    auth_dir.mkdir(parents=True, exist_ok=True)
    return auth_dir


def _get_secret_key() -> str:
    """Get or create the JWT signing key.

    Stored on disk so tokens survive server restarts.
    """
    key_file = _get_auth_dir() / ".jwt_secret"
    if key_file.exists():
        return key_file.read_text(encoding="utf-8").strip()

    secret = secrets.token_hex(32)
    # Store derived key using PBKDF2 (not cleartext secret)
    derived = hashlib.pbkdf2_hmac("sha256", secret.encode(), b"hashguard-jwt-v1", 1).hex()
    key_file.write_text(derived, encoding="utf-8")
    # Restrict permissions: owner-only read/write
    try:
        os.chmod(key_file, 0o600)
    except OSError:
        pass
    logger.info("Generated new JWT secret key (stored with restricted permissions)")
    return derived


# ── API Key Store ───────────────────────────────────────────────────────────

@dataclass
class APIKeyRecord:
    key_id: str
    key_hash: str
    name: str
    role: str
    created_at: float
    last_used: float = 0.0
    active: bool = True


def _load_keys() -> dict:
    """Load API key records from disk."""
    path = _get_auth_dir() / "api_keys.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data
    except (json.JSONDecodeError, OSError):
        return {}


def _save_keys(keys: dict) -> None:
    """Save API key records to disk."""
    path = _get_auth_dir() / "api_keys.json"
    path.write_text(json.dumps(keys, indent=2), encoding="utf-8")


def _hash_api_key(raw_key: str) -> str:
    """Hash an API key for secure storage using PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        raw_key.encode("utf-8"),
        b"hashguard-api-key-v1",
        iterations=100_000,
    ).hex()


def create_api_key(name: str, role: str = "analyst") -> dict:
    """Create a new API key.

    Returns dict with key_id, raw_key (shown once), name, role.
    """
    if role not in ROLES:
        raise ValueError(f"Invalid role: {role}. Must be one of {ROLES}")

    raw_key = f"hg_{secrets.token_hex(24)}"
    key_id = secrets.token_hex(8)
    key_hash = _hash_api_key(raw_key)

    keys = _load_keys()
    keys[key_id] = {
        "key_hash": key_hash,
        "name": name,
        "role": role,
        "created_at": time.time(),
        "last_used": 0.0,
        "active": True,
    }
    _save_keys(keys)

    logger.info("Created API key (role=%s, id=%s)", role, key_id)
    return {
        "key_id": key_id,
        "api_key": raw_key,
        "name": name,
        "role": role,
    }


def revoke_api_key(key_id: str) -> bool:
    """Revoke an API key."""
    keys = _load_keys()
    if key_id not in keys:
        return False
    keys[key_id]["active"] = False
    _save_keys(keys)
    logger.info("Revoked API key")
    return True


def list_api_keys() -> list:
    """List all API keys (without hashes)."""
    keys = _load_keys()
    return [
        {
            "key_id": kid,
            "name": kdata["name"],
            "role": kdata["role"],
            "active": kdata["active"],
            "created_at": kdata["created_at"],
            "last_used": kdata.get("last_used", 0),
        }
        for kid, kdata in keys.items()
    ]


def validate_api_key(raw_key: str) -> Optional[dict]:
    """Validate an API key. Returns key record or None."""
    key_hash = _hash_api_key(raw_key)
    keys = _load_keys()
    for kid, kdata in keys.items():
        if hmac.compare_digest(kdata["key_hash"], key_hash):
            if not kdata.get("active", True):
                return None
            # Update last_used
            kdata["last_used"] = time.time()
            _save_keys(keys)
            return {"key_id": kid, "role": kdata["role"], "name": kdata["name"]}
    return None


# ── JWT Tokens ──────────────────────────────────────────────────────────────

def create_token(
    subject: str,
    role: str = "analyst",
    expiry_seconds: int = _DEFAULT_TOKEN_EXPIRY,
) -> str:
    """Create a JWT token."""
    if not HAS_JWT:
        raise RuntimeError("PyJWT not installed. Run: pip install PyJWT")

    now = time.time()
    payload = {
        "sub": subject,
        "role": role,
        "iat": int(now),
        "exp": int(now + expiry_seconds),
    }
    return pyjwt.encode(payload, _get_secret_key(), algorithm=_ALGORITHM)


def verify_token(token: str) -> dict:
    """Verify and decode a JWT token.

    Returns the payload dict.
    Raises jwt.InvalidTokenError on failure.
    """
    if not HAS_JWT:
        raise RuntimeError("PyJWT not installed")

    return pyjwt.decode(token, _get_secret_key(), algorithms=[_ALGORITHM])


# ── FastAPI Dependencies ────────────────────────────────────────────────────

def _is_auth_enabled() -> bool:
    """Check if authentication is enabled.

    Auth is DISABLED by default for local development (127.0.0.1).
    Set HASHGUARD_AUTH=1 to force-enable, or HASHGUARD_AUTH=0 to force-disable.
    """
    env = os.environ.get("HASHGUARD_AUTH", "").strip().lower()
    if env in ("1", "true", "yes"):
        return True
    if env in ("0", "false", "no"):
        return False
    # Default: disabled (local dev mode)
    return False


def _extract_identity(request) -> Optional[dict]:
    """Extract identity from a FastAPI Request synchronously.

    Returns a dict with at least 'sub' and 'role' keys, or None on failure.
    Used by admin_router and other code that needs identity outside of Depends().
    """
    if not _is_auth_enabled():
        plan = os.environ.get("HASHGUARD_DEFAULT_PLAN", "free")
        return {"sub": "local", "role": "viewer", "plan": plan}

    auth_header = getattr(request, "headers", {}).get("authorization", "")
    if not auth_header:
        return None

    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None

    token = parts[1]
    if token.startswith("hg_"):
        key_info = validate_api_key(token)
        if not key_info:
            return None
        return {"sub": key_info["name"], "role": key_info["role"]}

    try:
        payload = verify_token(token)
        return payload
    except Exception:
        return None


def get_current_user():
    """FastAPI dependency that validates auth if enabled.

    Usage:
        @app.get("/api/protected")
        async def protected(user=Depends(get_current_user)):
            ...
    """
    try:
        from fastapi import Depends, Security, Request
        from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    except ImportError:
        return None

    security = HTTPBearer(auto_error=False)

    async def _authenticate(
        request: Request,
        credentials: Optional[HTTPAuthorizationCredentials] = Security(security),
    ) -> Optional[dict]:
        if not _is_auth_enabled():
            plan = os.environ.get("HASHGUARD_DEFAULT_PLAN", "free")
            return {"sub": "local", "role": "admin", "plan": plan}

        # Try Bearer token first
        if credentials and credentials.credentials:
            token = credentials.credentials
            # Check if it looks like an API key (hg_...)
            if token.startswith("hg_"):
                key_info = validate_api_key(token)
                if not key_info:
                    from fastapi import HTTPException

                    raise HTTPException(status_code=401, detail="Invalid API key")
                return {"sub": key_info["name"], "role": key_info["role"]}
            # Otherwise treat as JWT
            try:
                payload = verify_token(token)
                return payload
            except Exception:
                from fastapi import HTTPException

                raise HTTPException(status_code=401, detail="Invalid or expired token")

        # No credentials provided
        from fastapi import HTTPException

        raise HTTPException(
            status_code=401,
            detail="Authentication required. Provide Bearer token or API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return _authenticate


def require_permission(permission: str):
    """FastAPI dependency that checks role-based permission.

    Usage:
        @app.post("/api/settings")
        async def save_settings(user=Depends(require_permission("settings"))):
            ...
    """
    try:
        from fastapi import Depends, HTTPException
    except ImportError:
        return None

    auth_dep = get_current_user()

    async def _check_permission(user: dict = Depends(auth_dep)) -> dict:
        role = user.get("role", "viewer")
        allowed = ROLE_PERMISSIONS.get(role, set())
        if permission not in allowed:
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient permissions. Required: {permission}",
            )
        return user

    return _check_permission
