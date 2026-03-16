"""HashGuard v2 Web API — FastAPI-based malware research platform.

Endpoints:
- POST /api/analyze       Upload and analyze a file
- POST /api/analyze-url   Analyze a URL
- GET  /api/samples       List all analyzed samples
- GET  /api/samples/{id}  Get sample detail with full results
- GET  /api/stats         Dashboard statistics
- GET  /api/graph/{id}    IOC graph for a sample
- GET  /api/timeline/{id} Malware timeline for a sample
- GET  /api/clusters      Malware clusters
- GET  /api/search        Search samples and IOCs
- GET  /                  Web dashboard
"""

import json
import os
import sys
import tempfile
import time
import warnings
import webbrowser
import threading
from pathlib import Path
from typing import Optional

# Suppress RequestsDependencyWarning that causes PowerShell to treat stderr output as error
warnings.filterwarnings("ignore", message=".*urllib3.*charset.*", category=Warning)

from hashguard.logger import get_logger

logger = get_logger(__name__)

try:
    from fastapi import FastAPI, File, UploadFile, Form, Query, HTTPException, Depends, Request
    from fastapi.responses import HTMLResponse, JSONResponse as _JSONResponse, Response
    from fastapi.staticfiles import StaticFiles
    from fastapi.middleware.cors import CORSMiddleware
    import uvicorn

    HAS_FASTAPI = True

    class SafeJSONResponse(_JSONResponse):
        """JSONResponse that handles numpy types and other non-serializable objects."""

        def render(self, content) -> bytes:
            import json

            return json.dumps(
                content,
                ensure_ascii=False,
                allow_nan=False,
                default=str,
            ).encode("utf-8")

    # Use SafeJSONResponse everywhere
    JSONResponse = SafeJSONResponse

except ImportError:
    HAS_FASTAPI = False

# ── Rate limiting ────────────────────────────────────────────────────────────

try:
    from slowapi import Limiter
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded

    HAS_SLOWAPI = True
except ImportError:
    HAS_SLOWAPI = False

# Plan-based rate limits: {plan: {endpoint_group: "limit_string"}}
PLAN_RATE_LIMITS = {
    "free":       {"analyze": "10/minute",  "search": "15/minute", "ingest": "0/minute",  "ml": "1/minute"},
    "pro":        {"analyze": "60/minute",  "search": "60/minute", "ingest": "0/minute",  "ml": "5/minute"},
    "team":       {"analyze": "120/minute", "search": "120/minute", "ingest": "10/minute", "ml": "10/minute"},
    "enterprise": {"analyze": "600/minute", "search": "600/minute", "ingest": "60/minute", "ml": "60/minute"},
}


def _get_plan_for_request(request) -> str:
    """Extract user plan from request for dynamic rate limiting."""
    try:
        from hashguard.web.auth import _is_auth_enabled
        if not _is_auth_enabled():
            return "free"  # No auth = free plan limits
        # Try to get plan from JWT/API key identity
        from hashguard.web.auth import verify_token, validate_api_key
        token = None
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
        if token:
            payload = None
            if token.startswith("hg_"):
                key_info = validate_api_key(token)
                if key_info:
                    payload = {"tenant_id": key_info.get("tenant_id")}
            else:
                try:
                    payload = verify_token(token)
                except Exception:
                    pass
            if payload and payload.get("tenant_id"):
                from hashguard.models import get_orm_session
                from hashguard.web.usage_metering import get_tenant_plan
                db = get_orm_session()
                try:
                    return get_tenant_plan(db, payload["tenant_id"])
                finally:
                    db.close()
    except Exception:
        pass
    return "free"


def _dynamic_limit(endpoint_group: str, fallback: str):
    """Return a callable for slowapi that resolves limit based on user plan."""
    def _resolver() -> str:
        # Check if auth is enabled; if not, use enterprise limits
        try:
            from hashguard.web.auth import _is_auth_enabled
            if not _is_auth_enabled():
                return PLAN_RATE_LIMITS["enterprise"].get(endpoint_group, fallback)
        except Exception:
            pass
        plan = getattr(_dynamic_limit, "_current_plan", "free")
        return PLAN_RATE_LIMITS.get(plan, PLAN_RATE_LIMITS["free"]).get(endpoint_group, fallback)
    return _resolver


def _plan_aware_key(request) -> str:
    """Key function that also caches the current plan for the limit resolver."""
    plan = _get_plan_for_request(request)
    _dynamic_limit._current_plan = plan
    return get_remote_address(request) if HAS_SLOWAPI else "unknown"


def _rate_limit(limit_string: str, endpoint_group: str = ""):
    """Return a slowapi rate-limit decorator with plan-based dynamic limits."""
    if HAS_SLOWAPI and "limiter" in globals() and limiter is not None:
        if endpoint_group:
            return limiter.limit(
                _dynamic_limit(endpoint_group, limit_string),
                key_func=_plan_aware_key,
            )
        return limiter.limit(limit_string)

    def _noop(func):
        return func

    return _noop

app = FastAPI(
    title="HashGuard",
    version="1.1.4",
    docs_url="/api/docs",
    description="""
# HashGuard — Malware Research Platform API

Full-featured malware analysis REST API with 18 analysis engines, ML classification,
YARA scanning, threat intelligence integration, and real-time webhook notifications.

## Authentication

Authentication is **optional** (disabled by default). Enable it by setting the
`HASHGUARD_AUTH=1` environment variable.

When enabled, two auth methods are supported:

### API Key Authentication
Pass your API key via the `X-API-Key` header:
```
X-API-Key: your-api-key-here
```

### JWT Bearer Token
1. Exchange an API key for a JWT token via `POST /api/auth/token`
2. Pass the token via the `Authorization` header:
```
Authorization: Bearer eyJhbG...
```

### Roles
- **admin**: Full access (manage keys, train models, configure settings)
- **analyst**: Analyze files, search samples, export data
- **viewer**: Read-only access to stats, samples, and search

## Rate Limiting
Expensive endpoints are rate-limited per IP:
- Analysis: 30/min &bull; URL analysis: 10/min
- ML training: 2/min &bull; Ingest: 5/min
""",
    openapi_tags=[
        {"name": "Auth", "description": "Authentication — API keys and JWT tokens"},
        {"name": "Analysis", "description": "File and URL analysis"},
        {"name": "Samples", "description": "Sample management and search"},
        {"name": "Intelligence", "description": "IOC graphs, timeline, enrichment, STIX export"},
        {"name": "ML", "description": "Machine learning model training and prediction"},
        {"name": "Dataset", "description": "Dataset management for ML training"},
        {"name": "Ingest", "description": "Automated sample ingestion from feeds"},
        {"name": "Webhooks", "description": "Real-time webhook notifications"},
        {"name": "Settings", "description": "Platform configuration"},
    ],
) if HAS_FASTAPI else None

# Build CORS origins — support custom domain via DOMAIN env var
_cors_origins = ["http://127.0.0.1:8000", "http://localhost:8000", "https://hashguard.org"]
_custom_domain = os.environ.get("DOMAIN")
if _custom_domain and _custom_domain != "localhost":
    _cors_origins.append(f"https://{_custom_domain}")

if app:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_methods=["GET", "POST", "DELETE", "PUT"],
        allow_headers=["Content-Type", "Accept", "Authorization", "X-CSRF-Token"],
        expose_headers=["X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset", "Retry-After"],
    )

    # CSRF protection (enabled in production)
    if os.environ.get("HASHGUARD_ENV", "").lower() == "production":
        from hashguard.web.csrf import CSRFMiddleware
        app.add_middleware(CSRFMiddleware)

    # Rate limiter setup
    if HAS_SLOWAPI:
        limiter = Limiter(key_func=get_remote_address)
        app.state.limiter = limiter

        @app.exception_handler(RateLimitExceeded)
        async def _rate_limit_handler(request: "Request", exc: RateLimitExceeded):
            retry_after = getattr(exc, "retry_after", 60)
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Rate limit exceeded. Try again later.",
                    "retry_after": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )
    else:
        limiter = None

    # ── ORM initialization ──────────────────────────────────────────────────
    try:
        from hashguard.models import init_orm_db
        init_orm_db()
    except Exception as _orm_err:
        logger.warning("ORM init deferred: %s", _orm_err)

    # ── Prometheus metrics middleware ───────────────────────────────────────
    try:
        from hashguard.web.metrics import get_metrics_response, track_request
        import time as _time

        @app.middleware("http")
        async def _metrics_middleware(request: Request, call_next):
            start = _time.perf_counter()
            response = await call_next(request)
            duration = _time.perf_counter() - start
            track_request(
                request.method,
                request.url.path,
                response.status_code,
                duration,
            )
            return response

        @app.get("/metrics", include_in_schema=False)
        async def _prometheus_metrics():
            body, content_type = get_metrics_response()
            if body is None:
                return Response(content="prometheus_client not installed", status_code=501)
            return Response(content=body, media_type=content_type)
    except ImportError:
        pass

    # ── Routers ─────────────────────────────────────────────────────────────
    _router_modules = [
        ("hashguard.web.routers.auth_router", "router"),
        ("hashguard.web.routers.billing_router", "router"),
        ("hashguard.web.routers.admin_router", "router"),
        ("hashguard.web.routers.feeds_router", "router"),
        ("hashguard.web.routers.branding_router", "router"),
        ("hashguard.web.routers.team_router", "router"),
        ("hashguard.web.routers.soc_router", "router"),
        ("hashguard.web.routers.oauth_router", "router"),
        ("hashguard.web.routers.dataset_hub_router", "router"),
    ]
    for _mod_name, _attr in _router_modules:
        try:
            _mod = __import__(_mod_name, fromlist=[_attr])
            app.include_router(getattr(_mod, _attr))
        except Exception as _router_err:
            logger.warning("Router %s unavailable: %s", _mod_name.rsplit('.', 1)[-1], _router_err)


def _get_template_dir():
    """Locate the templates directory (supports PyInstaller frozen builds)."""
    # In PyInstaller frozen builds, data files live under sys._MEIPASS (onefile)
    # or next to the exe directory (onedir / COLLECT mode)
    if getattr(sys, 'frozen', False):
        bases = []
        if hasattr(sys, '_MEIPASS'):
            bases.append(Path(sys._MEIPASS))
        # onedir: files sit next to the exe
        bases.append(Path(sys.executable).parent)
        for base in bases:
            for candidate in (
                base / "hashguard" / "web" / "templates",
                base / "templates",
            ):
                if candidate.is_dir():
                    return candidate
    pkg_dir = Path(__file__).parent
    tmpl = pkg_dir / "templates"
    if tmpl.is_dir():
        return tmpl
    return pkg_dir


def _get_static_dir():
    """Locate the static assets directory (supports PyInstaller frozen builds)."""
    if getattr(sys, 'frozen', False):
        bases = []
        if hasattr(sys, '_MEIPASS'):
            bases.append(Path(sys._MEIPASS))
        bases.append(Path(sys.executable).parent)
        for base in bases:
            for candidate in (
                base / "hashguard" / "web" / "static",
                base / "static",
            ):
                if candidate.is_dir():
                    return candidate
    pkg_dir = Path(__file__).parent
    static = pkg_dir / "static"
    if static.is_dir():
        return static
    return None


def _sanitize_for_json(obj):
    """Recursively convert numpy/non-standard types to JSON-safe Python types."""
    if isinstance(obj, dict):
        return {k: _sanitize_for_json(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_sanitize_for_json(i) for i in obj]
    # numpy scalar types
    if hasattr(obj, "item"):
        return obj.item()
    if isinstance(obj, float) and (obj != obj):  # NaN
        return None
    return obj


def _run_full_analysis(file_path: str, use_vt: bool = False) -> dict:
    """Run complete v2 analysis pipeline on a file."""
    from hashguard.scanner import analyze
    from hashguard.config import get_default_config

    config = get_default_config()
    result = analyze(file_path, vt=use_vt, config=config)
    result_dict = result.to_dict()

    # analyze() already runs all v2 modules (capabilities, advanced PE,
    # fuzzy hashing, ML, family detection, unpacker, shellcode, deobfuscation).
    # Only add web-specific post-processing below.

    # Auto-unpack packed files (UPX + Unicorn emulation)
    try:
        if result_dict.get("packer", {}).get("detected"):
            from hashguard.unpacker import auto_unpack

            unpack_result = auto_unpack(file_path)
            result_dict["unpack_result"] = unpack_result.to_dict()
    except Exception:
        logger.debug("Auto-unpack error")

    # IOC Graph
    try:
        from hashguard.ioc_graph import build_graph

        graph = build_graph(result_dict)
        result_dict["ioc_graph"] = graph.to_visjs()
    except Exception:
        logger.debug("IOC graph error")

    # Timeline
    try:
        from hashguard.malware_timeline import build_timeline

        timeline = build_timeline(result_dict)
        result_dict["timeline"] = timeline.to_dict()
    except Exception:
        logger.debug("Timeline error")

    # Store in database
    try:
        from hashguard.database import store_sample, store_timeline_event

        sample_id = store_sample(result_dict)
        result_dict["sample_id"] = sample_id
        store_timeline_event(sample_id, "analysis", "Full v2 analysis completed")
    except Exception:
        logger.debug("Database storage error")

    # Extract & store ML dataset features
    feats = None
    try:
        from hashguard.feature_extractor import extract_features
        from hashguard.database import store_dataset_features

        feats = extract_features(file_path, result_dict)
        sha = result_dict.get("hashes", {}).get("sha256", "")
        if sha and sample_id:
            store_dataset_features(sample_id, sha, feats)
    except Exception:
        logger.debug("Dataset feature extraction error")

    # Real-time prediction using trained ML model
    try:
        if feats:
            from hashguard.ml_trainer import predict_sample

            prediction = predict_sample(feats)
            if "error" not in prediction:
                result_dict["trained_model_prediction"] = prediction
    except Exception:
        logger.debug("Trained model prediction error")

    # Fire webhook notifications
    try:
        from hashguard.web.webhooks import notify_analysis_complete

        notify_analysis_complete(result_dict)
    except Exception:
        logger.debug("Webhook notification error")

    # Forward to SOC integrations
    try:
        from hashguard.web.routers.soc_router import forward_alert

        forward_alert(result_dict)
    except Exception:
        logger.debug("SOC forwarding error")

    return _sanitize_for_json(result_dict)


# ── Static Files ─────────────────────────────────────────────────────────────

if app:
    _static = _get_static_dir()
    if _static:
        app.mount("/static", StaticFiles(directory=str(_static)), name="static")

# ── API Endpoints ────────────────────────────────────────────────────────────

if app:

    # ── Auth helpers ─────────────────────────────────────────────────────
    from hashguard.web.auth import get_current_user, require_permission
    from hashguard.web.billing import require_feature

    _auth_read = Depends(get_current_user())
    _auth_analyze = Depends(require_permission("analyze"))
    _auth_ingest = Depends(require_permission("ingest"))
    _auth_train = Depends(require_permission("train"))
    _auth_settings = Depends(require_permission("settings"))
    _auth_manage = Depends(require_permission("manage_keys"))
    _auth_export = Depends(require_permission("export"))

    # ── Auth endpoints ───────────────────────────────────────────────────

    @app.post("/api/auth/token", tags=["Auth"])
    async def auth_token(
        api_key: str = Form(...),
        expiry: int = Form(86400),
    ):
        """Exchange an API key for a JWT token."""
        from hashguard.web.auth import validate_api_key, create_token

        key_info = validate_api_key(api_key)
        if not key_info:
            raise HTTPException(status_code=401, detail="Invalid API key")
        safe_expiry = min(max(expiry, 300), 604800)  # 5min..7days
        token = create_token(
            subject=key_info["name"],
            role=key_info["role"],
            expiry_seconds=safe_expiry,
        )
        return JSONResponse(content={
            "access_token": token,
            "token_type": "bearer",
            "expires_in": safe_expiry,
            "role": key_info["role"],
        })

    @app.post("/api/auth/keys", tags=["Auth"])
    async def auth_create_key(
        name: str = Form(...),
        role: str = Form("analyst"),
        user: dict = Depends(require_feature("api_access")),
    ):
        """Create a new API key (admin only)."""
        from hashguard.web.auth import create_api_key

        try:
            result = create_api_key(name=name, role=role)
            return JSONResponse(content=result)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid role")

    @app.get("/api/auth/keys", tags=["Auth"])
    async def auth_list_keys(user: dict = _auth_manage):
        """List all API keys (admin only)."""
        from hashguard.web.auth import list_api_keys

        return JSONResponse(content={"keys": list_api_keys()})

    @app.delete("/api/auth/keys/{key_id}", tags=["Auth"])
    async def auth_revoke_key(key_id: str, user: dict = _auth_manage):
        """Revoke an API key (admin only)."""
        from hashguard.web.auth import revoke_api_key

        if revoke_api_key(key_id):
            return JSONResponse(content={"revoked": True})
        raise HTTPException(status_code=404, detail="Key not found")

    # ── Public endpoints ─────────────────────────────────────────────────

    @app.get("/", response_class=HTMLResponse)
    async def dashboard():
        """Serve the main dashboard."""
        tmpl_dir = _get_template_dir()
        index = tmpl_dir / "index.html"
        if index.is_file():
            return HTMLResponse(content=index.read_text(encoding="utf-8"))
        return HTMLResponse(content="<h1>HashGuard v2</h1><p>Template not found</p>")

    @app.get("/landing", response_class=HTMLResponse)
    async def landing_page():
        """Serve the marketing landing page or coming-soon page."""
        tmpl_dir = _get_template_dir()
        # When HASHGUARD_COMING_SOON=1, serve the "Em Breve" page instead
        if os.environ.get("HASHGUARD_COMING_SOON", "0") == "1":
            coming = tmpl_dir / "coming_soon.html"
            if coming.is_file():
                return HTMLResponse(
                    content=coming.read_text(encoding="utf-8"),
                    headers={"Cache-Control": "no-cache, no-store, must-revalidate", "Pragma": "no-cache"},
                )
        landing = tmpl_dir / "landing.html"
        if landing.is_file():
            return HTMLResponse(
                content=landing.read_text(encoding="utf-8"),
                headers={"Cache-Control": "no-cache, no-store, must-revalidate", "Pragma": "no-cache"},
            )
        return HTMLResponse(content="<h1>HashGuard</h1><p>Landing template not found</p>")

    @app.post("/api/waitlist", tags=["Marketing"])
    async def waitlist_signup(request: Request):
        """Collect email for launch waitlist."""
        import json as _json
        body = await request.json()
        email = body.get("email", "").strip()
        if not email or "@" not in email:
            return JSONResponse({"error": "Invalid email"}, status_code=400)
        # Append to a simple waitlist file (no DB dependency needed at launch)
        waitlist_path = Path(os.environ.get("HASHGUARD_DATA_DIR", "data")) / "waitlist.jsonl"
        waitlist_path.parent.mkdir(parents=True, exist_ok=True)
        from datetime import datetime, timezone
        entry = _json.dumps({"email": email, "ts": datetime.now(timezone.utc).isoformat()})
        with open(waitlist_path, "a", encoding="utf-8") as f:
            f.write(entry + "\n")
        logger.info("waitlist signup: %s", email)
        return JSONResponse({"status": "ok"})

    @app.post("/api/analyze", tags=["Analysis"])
    @_rate_limit("30/minute", endpoint_group="analyze")
    async def analyze_file(
        request: Request,
        file: UploadFile = File(...),
        use_vt: bool = Form(False),
        user: dict = _auth_analyze,
    ):
        """Upload and analyze a file."""
        import re

        # Check usage quota (always enforced)
        try:
            from hashguard.web.usage_metering import check_quota, record_analysis
            from hashguard.models import get_session_factory
            _Ses = get_session_factory()
            _db = _Ses()
            try:
                tenant = user.get("tenant_id", "default") if isinstance(user, dict) else "default"
                quota = check_quota(_db, tenant)
                if not quota["allowed"]:
                    raise HTTPException(status_code=429, detail=f"Daily analysis limit reached ({quota['limit']}/day). Upgrade your plan for more.")
            finally:
                _db.close()
        except HTTPException:
            raise
        except Exception:
            pass  # Don't block analysis if metering fails

        # Sanitize filename: strip path components, keep only safe chars
        raw_name = Path(file.filename).name if file.filename else ""
        safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", raw_name)
        suffix = Path(safe_name).suffix if safe_name else ".bin"
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix, prefix="hg_")
        try:
            content = await file.read()
            if len(content) > 200 * 1024 * 1024:
                raise HTTPException(status_code=413, detail="File too large (max 200MB)")
            tmp.write(content)
            tmp.close()

            result = _run_full_analysis(tmp.name, use_vt=use_vt)
            result["original_filename"] = safe_name or file.filename

            # Record usage after successful analysis
            try:
                _db2 = _Ses()
                try:
                    record_analysis(_db2, tenant)
                finally:
                    _db2.close()
            except Exception:
                pass

            return JSONResponse(content=result)
        except HTTPException:
            raise
        except Exception:
            logger.error("Analysis error")
            raise HTTPException(status_code=500, detail="Internal server error")
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

    @app.post("/api/analyze-url", tags=["Analysis"])
    @_rate_limit("10/minute", endpoint_group="analyze")
    async def analyze_url(request: Request, url: str = Form(...), use_vt: bool = Form(False), user: dict = _auth_analyze):
        """Analyze a URL."""
        try:
            from hashguard.scanner import analyze_url as scan_url

            result = scan_url(url, vt=use_vt)
            result_dict = _sanitize_for_json(result.to_dict())
            return JSONResponse(content=result_dict)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid or blocked URL")
        except Exception as e:
            ename = type(e).__name__
            emsg = str(e).lower()
            # Friendly messages for common HTTP errors
            if "HTTPError" in ename and hasattr(e, "response"):
                code = getattr(getattr(e, "response", None), "status_code", 0)
                if code == 403:
                    raise HTTPException(
                        status_code=502, detail="Remote server denied access (403 Forbidden)"
                    )
                if code == 404:
                    raise HTTPException(
                        status_code=502, detail="File not found on remote server (404)"
                    )
            # Also detect HTTP error codes from string messages
            if "403" in emsg and "forbidden" in emsg:
                raise HTTPException(
                    status_code=502, detail="Remote server denied access (403 Forbidden)"
                )
            if "404" in emsg and ("not found" in emsg):
                raise HTTPException(
                    status_code=502, detail="File not found on remote server (404)"
                )
            if "ConnectionError" in ename or "Timeout" in ename:
                raise HTTPException(
                    status_code=502, detail="Could not connect to remote server"
                )
            logger.error("URL analysis error")
            raise HTTPException(status_code=500, detail="Internal server error")

    @app.post("/api/analyze/async", tags=["Analysis"])
    @_rate_limit("30/minute", endpoint_group="analyze")
    async def analyze_file_async(
        request: Request,
        file: UploadFile = File(...),
        use_vt: bool = Form(False),
        user: dict = _auth_analyze,
    ):
        """Upload a file for background analysis via Celery.

        Returns a task_id immediately. Poll GET /api/tasks/{task_id} for result.
        Falls back to sync analysis if Celery/Redis is unavailable.
        """
        import re

        raw_name = Path(file.filename).name if file.filename else ""
        safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", raw_name)
        suffix = Path(safe_name).suffix if safe_name else ".bin"
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix, prefix="hg_async_")
        try:
            content = await file.read()
            if len(content) > 200 * 1024 * 1024:
                raise HTTPException(status_code=413, detail="File too large (max 200MB)")
            tmp.write(content)
            tmp.close()

            try:
                from hashguard.tasks import analyze_file_task
                task = analyze_file_task.delay(tmp.name, use_vt)
                return JSONResponse(content={
                    "task_id": task.id,
                    "status": "queued",
                    "detail": "Analysis queued. Poll /api/tasks/{task_id} for result.",
                })
            except Exception:
                # Celery/Redis not available — fall back to sync
                result = _run_full_analysis(tmp.name, use_vt=use_vt)
                result["original_filename"] = safe_name or file.filename
                return JSONResponse(content=result)
        except HTTPException:
            raise
        except Exception:
            logger.error("Async analysis error")
            raise HTTPException(status_code=500, detail="Internal server error")

    @app.get("/api/tasks/{task_id}", tags=["Analysis"])
    async def get_task_status(task_id: str, user: dict = _auth_read):
        """Get the status of a background analysis task."""
        try:
            from hashguard.tasks import celery_app
            result = celery_app.AsyncResult(task_id)
            response = {
                "task_id": task_id,
                "status": result.status,
            }
            if result.ready():
                response["result"] = result.result
            return JSONResponse(content=response)
        except Exception:
            return JSONResponse(content={
                "task_id": task_id,
                "status": "UNKNOWN",
                "detail": "Celery not available",
            })

    @app.get("/api/health", tags=["Health"])
    async def health_check():
        """Unauthenticated health check for Docker/load balancer probes."""
        return JSONResponse({"status": "ok", "version": "1.1.4"})

    @app.get("/api/stats", tags=["Samples"])
    async def get_stats(user: dict = _auth_read):
        """Get dashboard statistics."""
        try:
            from hashguard.database import get_stats

            return JSONResponse(content=get_stats())
        except Exception as e:
            logger.warning(f"Stats query failed: {e}")
            return JSONResponse(
                content={
                    "total_samples": 0,
                    "malicious": 0,
                    "clean": 0,
                    "detection_rate": 0,
                    "top_families": [],
                    "recent_samples": [],
                    "verdict_distribution": {},
                    "error": "Database unavailable",
                }
            )

    @app.get("/api/samples", tags=["Samples"])
    async def list_samples(limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0), user: dict = _auth_read):
        """List analyzed samples."""
        try:
            from hashguard.database import get_all_samples

            samples = get_all_samples(limit=limit, offset=offset)
            return JSONResponse(content={"samples": samples})
        except Exception as e:
            raise HTTPException(status_code=500, detail="Internal server error")

    @app.get("/api/samples/{sample_id}", tags=["Samples"])
    async def get_sample_detail(sample_id: int, user: dict = _auth_read):
        """Get full sample detail."""
        try:
            from hashguard.database import (
                get_sample_by_id,
                get_sample_iocs,
                get_sample_behaviors,
                get_timeline,
            )

            sample = get_sample_by_id(sample_id)
            if not sample:
                raise HTTPException(status_code=404, detail="Sample not found")

            # Parse stored JSON fields
            for field_name in ["full_result", "capabilities", "advanced_pe", "ml_classification"]:
                val = sample.get(field_name)
                if isinstance(val, str):
                    try:
                        sample[field_name] = json.loads(val)
                    except (json.JSONDecodeError, TypeError):
                        pass

            sample["iocs"] = get_sample_iocs(sample_id)
            sample["behaviors"] = get_sample_behaviors(sample_id)
            sample["timeline"] = get_timeline(sample_id)

            # Rebuild graph if we have full result
            full = sample.get("full_result", {})
            if isinstance(full, dict):
                try:
                    from hashguard.ioc_graph import build_graph

                    graph = build_graph(full)
                    sample["ioc_graph"] = graph.to_visjs()
                except Exception:
                    pass

                try:
                    from hashguard.malware_timeline import build_timeline

                    tl = build_timeline(full)
                    sample["analysis_timeline"] = tl.to_dict()
                except Exception:
                    pass

            return JSONResponse(content=sample)
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail="Internal server error")

    @app.get("/api/graph/{sample_id}", tags=["Intelligence"])
    async def get_graph(sample_id: int, user: dict = _auth_read):
        """Get IOC graph for a sample."""
        try:
            from hashguard.database import get_sample_by_id

            sample = get_sample_by_id(sample_id)
            if not sample:
                raise HTTPException(status_code=404, detail="Sample not found")

            full = sample.get("full_result", "{}")
            if isinstance(full, str):
                full = json.loads(full)

            from hashguard.ioc_graph import build_graph

            graph = build_graph(full)
            return JSONResponse(content=graph.to_visjs())
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail="Internal server error")

    @app.get("/api/timeline/{sample_id}", tags=["Intelligence"])
    async def get_sample_timeline(sample_id: int, user: dict = _auth_read):
        """Get malware timeline for a sample."""
        try:
            from hashguard.database import get_sample_by_id

            sample = get_sample_by_id(sample_id)
            if not sample:
                raise HTTPException(status_code=404, detail="Sample not found")

            full = sample.get("full_result", "{}")
            if isinstance(full, str):
                full = json.loads(full)

            from hashguard.malware_timeline import build_timeline

            timeline = build_timeline(full)
            return JSONResponse(content=timeline.to_dict())
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail="Internal server error")

    @app.get("/api/export/stix/{sample_id}", tags=["Intelligence"])
    async def export_stix(sample_id: int, user: dict = Depends(require_feature("stix_export"))):
        """Export a sample's analysis results as a STIX 2.1 Bundle."""
        try:
            from hashguard.database import get_sample_by_id

            sample = get_sample_by_id(sample_id)
            if not sample:
                raise HTTPException(status_code=404, detail="Sample not found")

            full = sample.get("full_result", "{}")
            if isinstance(full, str):
                full = json.loads(full)

            from hashguard.stix_exporter import export_stix_bundle

            bundle = export_stix_bundle(full)
            return SafeJSONResponse(content=bundle)
        except HTTPException:
            raise
        except RuntimeError:
            raise HTTPException(status_code=501, detail="STIX export not available")
        except Exception as e:
            logger.debug(f"STIX export error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    @app.get("/api/clusters", tags=["Intelligence"])
    async def get_clusters(user: dict = _auth_read):
        """Get malware clusters."""
        try:
            from hashguard.database import get_all_samples
            from hashguard.malware_cluster import get_all_clusters

            samples = get_all_samples(limit=1000)
            clusters = get_all_clusters(samples)
            return JSONResponse(content={"clusters": clusters})
        except Exception as e:
            logger.warning(f"Cluster query failed: {e}")
            return JSONResponse(content={"clusters": [], "error": "Cluster analysis unavailable"})

    @app.get("/api/search", tags=["Samples"])
    @_rate_limit("30/minute", endpoint_group="search")
    async def search(request: Request, q: str = Query(..., min_length=1), user: dict = _auth_read):
        """Search samples and IOCs."""
        try:
            from hashguard.database import search_samples, search_iocs

            samples = search_samples(q)
            iocs = search_iocs(q)
            return JSONResponse(content={"samples": samples, "iocs": iocs})
        except Exception as e:
            raise HTTPException(status_code=500, detail="Internal server error")

    @app.get("/api/sandbox/status")
    async def sandbox_status(user: dict = _auth_read):
        """Check sandbox availability."""
        try:
            from hashguard.sandbox import check_sandbox_availability

            return JSONResponse(content=check_sandbox_availability())
        except Exception as e:
            logger.warning(f"Sandbox status check failed: {e}")
            return JSONResponse(content={"any_available": False, "error": "Sandbox check failed"})

    @app.post("/api/sandbox/enhanced-monitor")
    @_rate_limit("5/minute")
    async def enhanced_sandbox_monitor(request: Request, duration: int = 30, user: dict = _auth_analyze):
        """Run enhanced monitoring (snapshot diffs + ETW + registry checks)."""
        try:
            from hashguard.sandbox import enhanced_monitor

            duration = min(max(duration, 5), 120)  # 5-120 seconds
            result = enhanced_monitor(duration_seconds=duration)
            return JSONResponse(content=result.to_dict())
        except Exception as e:
            raise HTTPException(status_code=500, detail="Internal server error")

    @app.get("/api/enrichment/{sample_id}", tags=["Intelligence"])
    async def enrich_sample(sample_id: int, user: dict = _auth_read):
        """Enrich IOCs for a sample."""
        try:
            from hashguard.database import get_sample_by_id

            sample = get_sample_by_id(sample_id)
            if not sample:
                raise HTTPException(status_code=404, detail="Sample not found")

            full = sample.get("full_result", "{}")
            if isinstance(full, str):
                full = json.loads(full)

            strings_info = full.get("strings_info") or full.get("strings", {})
            iocs = strings_info.get("iocs", {}) if strings_info else {}

            from hashguard.ioc_enrichment import enrich_iocs

            result = enrich_iocs(iocs)
            return JSONResponse(content=result.to_dict())
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail="Internal server error")

    # ── Dataset endpoints ────────────────────────────────────────────────

    @app.get("/api/dataset/stats", tags=["Dataset"])
    async def dataset_stats(user: dict = _auth_read):
        """Return dataset summary statistics."""
        try:
            from hashguard.database import get_dataset_stats

            return JSONResponse(content=get_dataset_stats())
        except Exception as e:
            logger.warning(f"Dataset stats error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    @app.get("/api/dataset/export", tags=["Dataset"])
    async def dataset_export(fmt: str = Query("csv", pattern="^(csv|jsonl|parquet)$"), user: dict = _auth_export):
        """Export the full ML dataset as CSV, JSONL, or Parquet."""
        try:
            from hashguard.database import export_dataset

            data = export_dataset(fmt=fmt)
            if fmt == "parquet":
                return Response(
                    content=data,
                    media_type="application/octet-stream",
                    headers={"Content-Disposition": "attachment; filename=hashguard_dataset.parquet"},
                )
            media = "text/csv" if fmt == "csv" else "application/x-ndjson"
            ext = "csv" if fmt == "csv" else "jsonl"
            return Response(
                content=data,
                media_type=media,
                headers={"Content-Disposition": f"attachment; filename=hashguard_dataset.{ext}"},
            )
        except Exception as e:
            logger.warning(f"Dataset export error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    @app.get("/api/dataset/export/anonymized", tags=["Dataset"])
    async def dataset_export_anonymized(
        fmt: str = Query("csv", pattern="^(csv|jsonl|parquet)$"),
        user: dict = _auth_export,
    ):
        """Export the ML dataset with PII removed (anonymized)."""
        try:
            from hashguard.database import export_dataset_anonymized

            data = export_dataset_anonymized(fmt=fmt)
            suffix = "_anonymized"
            if fmt == "parquet":
                return Response(
                    content=data,
                    media_type="application/octet-stream",
                    headers={"Content-Disposition": f"attachment; filename=hashguard_dataset{suffix}.parquet"},
                )
            media = "text/csv" if fmt == "csv" else "application/x-ndjson"
            ext = "csv" if fmt == "csv" else "jsonl"
            return Response(
                content=data,
                media_type=media,
                headers={"Content-Disposition": f"attachment; filename=hashguard_dataset{suffix}.{ext}"},
            )
        except Exception as e:
            logger.warning(f"Anonymized export error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    @app.get("/api/dataset/features/{sample_id}", tags=["Dataset"])
    async def dataset_sample_features(sample_id: int, user: dict = _auth_read):
        """Return extracted features for a single sample."""
        try:
            from hashguard.database import get_connection, init_db, _ensure_dataset_table

            init_db()
            _ensure_dataset_table()
            conn = get_connection()
            row = conn.execute(
                "SELECT * FROM dataset_features WHERE sample_id = ?", (sample_id,)
            ).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="No features for this sample")
            return JSONResponse(content=dict(row))
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail="Internal server error")

    # ── Dataset versioning endpoints ─────────────────────────────────────

    @app.get("/api/dataset/versions", tags=["Dataset"])
    async def dataset_versions(user: dict = _auth_read):
        """List all dataset versions."""
        try:
            from hashguard.database import list_dataset_versions
            return JSONResponse(content=list_dataset_versions())
        except Exception as e:
            logger.warning(f"Dataset versions list error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    @app.post("/api/dataset/versions", tags=["Dataset"])
    async def create_dataset_version_endpoint(
        version: str = Query(..., pattern=r"^\d+\.\d+\.\d+$"),
        fmt: str = Query("parquet", pattern="^(parquet|csv|jsonl)$"),
        notes: str = Query(None),
        user: dict = _auth_export,
    ):
        """Create a versioned snapshot of the current dataset."""
        try:
            from hashguard.database import create_dataset_version
            result = create_dataset_version(
                version=version, fmt=fmt, notes=notes,
                created_by=user.get("sub", "unknown"),
            )
            return JSONResponse(content=result)
        except Exception as e:
            if "UNIQUE constraint" in str(e):
                raise HTTPException(status_code=409, detail=f"Version {version} already exists")
            logger.warning(f"Dataset version create error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    @app.get("/api/dataset/versions/{version}/download", tags=["Dataset"])
    async def download_dataset_version(version: str, user: dict = _auth_export):
        """Download a specific dataset version file."""
        try:
            from hashguard.database import get_dataset_version_path
            path = get_dataset_version_path(version)
            if not path:
                raise HTTPException(status_code=404, detail=f"Version {version} not found")
            ext = path.rsplit(".", 1)[-1]
            media_map = {"parquet": "application/octet-stream", "csv": "text/csv", "jsonl": "application/x-ndjson"}
            with open(path, "rb") as f:
                data = f.read()
            return Response(
                content=data,
                media_type=media_map.get(ext, "application/octet-stream"),
                headers={"Content-Disposition": f"attachment; filename=hashguard_dataset_v{version}.{ext}"},
            )
        except HTTPException:
            raise
        except Exception as e:
            logger.warning(f"Dataset version download error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    # ── Settings endpoints ───────────────────────────────────────────────

    @app.get("/api/settings", tags=["Settings"])
    async def get_settings(user: dict = _auth_settings):
        """Return current API-key status (masked) so the UI can show state."""
        def _mask(val: str) -> str:
            return (val[:4] + "***" + val[-4:]) if len(val) >= 8 else ("***" if val else "")

        vt = os.environ.get("HASHGUARD_VT_API_KEY") or os.environ.get("VT_API_KEY") or ""
        ab = os.environ.get("ABUSE_CH_API_KEY") or ""
        ms = os.environ.get("MALSHARE_API_KEY") or ""
        ha = os.environ.get("HYBRID_ANALYSIS_API_KEY") or ""
        tr = os.environ.get("TRIAGE_API_KEY") or ""
        return JSONResponse(content={
            "vt_api_key_set": bool(vt),
            "vt_api_key_masked": _mask(vt),
            "abuse_ch_api_key_set": bool(ab),
            "abuse_ch_api_key_masked": _mask(ab),
            "malshare_api_key_set": bool(ms),
            "malshare_api_key_masked": _mask(ms),
            "hybrid_analysis_api_key_set": bool(ha),
            "hybrid_analysis_api_key_masked": _mask(ha),
            "triage_api_key_set": bool(tr),
            "triage_api_key_masked": _mask(tr),
        })

    @app.post("/api/settings", tags=["Settings"])
    async def save_settings(
        vt_api_key: str = Form(""),
        abuse_ch_api_key: str = Form(""),
        malshare_api_key: str = Form(""),
        hybrid_analysis_api_key: str = Form(""),
        triage_api_key: str = Form(""),
        user: dict = _auth_settings,
    ):
        """Save API keys into the process environment for the running session."""
        saved = []
        if vt_api_key.strip():
            os.environ["VT_API_KEY"] = vt_api_key.strip()
            os.environ["HASHGUARD_VT_API_KEY"] = vt_api_key.strip()
            saved.append("vt_api_key")
        if abuse_ch_api_key.strip():
            os.environ["ABUSE_CH_API_KEY"] = abuse_ch_api_key.strip()
            saved.append("abuse_ch_api_key")
        if malshare_api_key.strip():
            os.environ["MALSHARE_API_KEY"] = malshare_api_key.strip()
            saved.append("malshare_api_key")
        if hybrid_analysis_api_key.strip():
            os.environ["HYBRID_ANALYSIS_API_KEY"] = hybrid_analysis_api_key.strip()
            saved.append("hybrid_analysis_api_key")
        if triage_api_key.strip():
            os.environ["TRIAGE_API_KEY"] = triage_api_key.strip()
            saved.append("triage_api_key")
        return JSONResponse(content={"saved": saved, "ok": True})

    # ── Batch ingest endpoints ───────────────────────────────────────────

    @app.post("/api/ingest/start", tags=["Ingest"])
    @_rate_limit("5/minute", endpoint_group="ingest")
    async def ingest_start(
        request: Request,
        source: str = Form("recent"),
        limit: int = Form(100),
        tag: str = Form(""),
        file_type: str = Form("exe"),
        directory: str = Form(""),
        user: dict = Depends(require_feature("batch_ingest")),
    ):
        """Start a batch ingest job from public feeds or local directory."""
        try:
            from hashguard.batch_ingest import start_ingest

            # Validate source against whitelist
            valid_sources = {"recent", "tag", "filetype", "mixed", "local", "continuous", "benign"}
            if source not in valid_sources:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid source. Must be one of: {', '.join(sorted(valid_sources))}",
                )

            # Validate directory to prevent path traversal
            if directory:
                if ".." in directory:
                    raise HTTPException(status_code=400, detail="Invalid directory path")
                from pathlib import Path as _Path
                resolved_dir = _Path(directory).resolve()
                if not resolved_dir.is_dir():
                    raise HTTPException(status_code=400, detail="Invalid directory path")
                # Containment: only allow paths under user home or common data dirs
                _home = _Path(os.path.expanduser("~")).resolve()
                _appdata = _Path(os.environ.get("APPDATA", str(_home))).resolve()
                _allowed = [_home, _appdata, _Path("/tmp").resolve()]
                if not any(resolved_dir.is_relative_to(r) for r in _allowed):
                    raise HTTPException(status_code=400, detail="Directory outside allowed paths")
                directory = str(resolved_dir)

            # Cap per source: recent=100, tag/filetype=1000, mixed/local/continuous=unlimited
            if source == "recent":
                safe_limit = min(limit, 100)
            elif source in ("tag", "filetype"):
                safe_limit = min(limit, 1000)
            else:
                safe_limit = limit  # mixed, local, continuous have no hard cap

            if source == "benign":
                ingest_delay = 0.05
            elif source == "continuous":
                ingest_delay = 2.0
            else:
                ingest_delay = 1.0

            result = start_ingest(
                source=source,
                limit=safe_limit,
                tag=tag,
                file_type=file_type,
                delay=ingest_delay,
                directory=directory,
            )
            return JSONResponse(content=result)
        except Exception as e:
            logger.warning(f"Ingest start error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    @app.get("/api/ingest/status", tags=["Ingest"])
    async def ingest_status(user: dict = _auth_read):
        """Return the current ingest job status."""
        try:
            from hashguard.batch_ingest import get_ingest_status

            return JSONResponse(content=get_ingest_status())
        except Exception as e:
            logger.warning(f"Ingest status error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    @app.post("/api/ingest/stop", tags=["Ingest"])
    async def ingest_stop(user: dict = _auth_ingest):
        """Signal the running ingest job to stop."""
        try:
            from hashguard.batch_ingest import request_stop

            request_stop()
            return JSONResponse(content={"stopped": True})
        except Exception as e:
            logger.warning(f"Ingest stop error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    # ── ML Training endpoints ────────────────────────────────────────────

    @app.post("/api/ml/train", tags=["ML"])
    @_rate_limit("2/minute", endpoint_group="ml")
    async def ml_train(
        request: Request,
        mode: str = Form("binary"),
        algorithm: str = Form("random_forest"),
        test_size: float = Form(0.2),
        user: dict = _auth_train,
    ):
        """Start an ML training job."""
        try:
            from hashguard.ml_trainer import start_training

            result = start_training(mode=mode, algorithm=algorithm, test_size=test_size)
            if "error" in result:
                raise HTTPException(status_code=400, detail=result["error"])
            return JSONResponse(content=result)
        except HTTPException:
            raise
        except Exception as e:
            logger.warning(f"ML train error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    @app.get("/api/ml/status", tags=["ML"])
    async def ml_status(user: dict = _auth_read):
        """Return the current training job status."""
        try:
            from hashguard.ml_trainer import get_training_status

            return JSONResponse(content=get_training_status())
        except Exception as e:
            logger.warning(f"ML status error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    @app.get("/api/ml/models", tags=["ML"])
    async def ml_models(user: dict = _auth_read):
        """List all trained models."""
        try:
            from hashguard.ml_trainer import list_models

            return JSONResponse(content=list_models())
        except Exception as e:
            logger.warning(f"ML models error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    @app.get("/api/ml/models/{model_id}", tags=["ML"])
    async def ml_model_detail(model_id: str, user: dict = _auth_read):
        """Get metrics for a specific model."""
        try:
            from hashguard.ml_trainer import get_model_metrics

            result = get_model_metrics(model_id)
            if result is None:
                raise HTTPException(status_code=404, detail="Model not found")
            return JSONResponse(content=result)
        except HTTPException:
            raise
        except Exception as e:
            logger.warning(f"ML model detail error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    @app.delete("/api/ml/models/{model_id}", tags=["ML"])
    async def ml_model_delete(model_id: str, user: dict = _auth_train):
        """Delete a trained model."""
        try:
            from hashguard.ml_trainer import delete_model

            if delete_model(model_id):
                return JSONResponse(content={"deleted": True})
            raise HTTPException(status_code=404, detail="Model not found")
        except HTTPException:
            raise
        except Exception as e:
            logger.warning(f"ML model delete error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    @app.post("/api/ml/predict", tags=["ML"])
    async def ml_predict(sample_id: int = Form(...), user: dict = _auth_analyze):
        """Predict using a trained model on a dataset sample's features."""
        try:
            from hashguard.ml_trainer import predict_sample
            from hashguard.database import get_connection, init_db, _ensure_dataset_table

            init_db()
            _ensure_dataset_table()
            conn = get_connection()
            row = conn.execute(
                "SELECT * FROM dataset_features WHERE sample_id = ?", (sample_id,)
            ).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="No features for this sample")
            features = dict(row)
            result = predict_sample(features)
            if "error" in result:
                raise HTTPException(status_code=400, detail="Prediction failed")
            return JSONResponse(content=result)
        except HTTPException:
            raise
        except Exception as e:
            logger.warning("ML predict error")
            raise HTTPException(status_code=500, detail="Internal server error")

    # ── Anomaly detection endpoints ──────────────────────────────────────

    @app.post("/api/anomaly/train", tags=["ML"])
    @_rate_limit("2/minute", endpoint_group="ml")
    async def anomaly_train(
        request: Request,
        contamination: float = Form(0.05),
        min_samples: int = Form(200),
        user: dict = _auth_train,
    ):
        """Train the anomaly detection model from the dataset."""
        try:
            from hashguard.anomaly_detector import train_anomaly_model

            result = train_anomaly_model(
                contamination=contamination,
                min_samples=min_samples,
            )
            return JSONResponse(content=result)
        except Exception as e:
            logger.warning(f"Anomaly train error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    @app.post("/api/anomaly/detect", tags=["ML"])
    async def anomaly_detect(sample_id: int = Form(...), user: dict = _auth_analyze):
        """Run anomaly detection on a dataset sample by ID."""
        try:
            from hashguard.anomaly_detector import detect_anomaly
            from hashguard.ml_trainer import NUMERIC_FEATURES
            from hashguard.database import get_connection, init_db, _ensure_dataset_table

            init_db()
            _ensure_dataset_table()
            conn = get_connection()
            cols = ", ".join(NUMERIC_FEATURES)
            row = conn.execute(
                f"SELECT {cols} FROM dataset_features WHERE sample_id = ?",
                (sample_id,),
            ).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Sample not found")

            features = {NUMERIC_FEATURES[i]: row[i] for i in range(len(NUMERIC_FEATURES))}
            result = detect_anomaly(features)
            return JSONResponse(content=result.to_dict())
        except HTTPException:
            raise
        except Exception as e:
            logger.warning(f"Anomaly detect error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    # ── Memory analysis endpoints ────────────────────────────────────────

    @app.post("/api/memory/analyze", tags=["Analysis"])
    async def memory_analyze(sample_id: int = Form(...), user: dict = _auth_analyze):
        """Run memory/injection analysis on a stored sample by ID."""
        try:
            from hashguard.memory_analyzer import analyze_memory
            from hashguard.database import get_connection, init_db

            init_db()
            conn = get_connection()
            row = conn.execute(
                "SELECT file_path FROM samples WHERE id = ?",
                (sample_id,),
            ).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Sample not found")

            file_path = row[0]
            if not file_path or not os.path.isfile(file_path):
                raise HTTPException(status_code=404, detail="Sample file not on disk")

            result = analyze_memory(file_path)
            return JSONResponse(content=result.to_dict())
        except HTTPException:
            raise
        except Exception as e:
            logger.warning("Memory analysis error")
            raise HTTPException(status_code=500, detail="Internal server error")

    # ── Webhook endpoints ────────────────────────────────────────────────

    @app.post("/api/webhooks", tags=["Webhooks"])
    async def webhook_create(
        name: str = Form(...),
        url: str = Form(...),
        events: str = Form("analysis.high_risk,analysis.malicious"),
        min_risk_score: int = Form(0),
        user: dict = Depends(require_feature("webhooks")),
    ):
        """Create a new webhook notification endpoint."""
        from hashguard.web.webhooks import create_webhook

        try:
            event_list = [e.strip() for e in events.split(",") if e.strip()]
            result = create_webhook(
                name=name,
                url=url,
                events=event_list,
                min_risk_score=min_risk_score,
            )
            return JSONResponse(content=result)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid webhook configuration")

    @app.get("/api/webhooks", tags=["Webhooks"])
    async def webhook_list(user: dict = _auth_settings):
        """List all configured webhooks."""
        from hashguard.web.webhooks import list_webhooks

        return JSONResponse(content={"webhooks": list_webhooks()})

    @app.delete("/api/webhooks/{hook_id}", tags=["Webhooks"])
    async def webhook_delete(hook_id: str, user: dict = _auth_settings):
        """Delete a webhook."""
        from hashguard.web.webhooks import delete_webhook

        if delete_webhook(hook_id):
            return JSONResponse(content={"deleted": True})
        raise HTTPException(status_code=404, detail="Webhook not found")

    @app.put("/api/webhooks/{hook_id}", tags=["Webhooks"])
    async def webhook_update(
        hook_id: str,
        name: str = Form(None),
        url: str = Form(None),
        events: str = Form(None),
        min_risk_score: int = Form(None),
        active: bool = Form(None),
        user: dict = _auth_settings,
    ):
        """Update a webhook configuration."""
        from hashguard.web.webhooks import update_webhook

        kwargs = {}
        if name is not None:
            kwargs["name"] = name
        if url is not None:
            kwargs["url"] = url
        if events is not None:
            kwargs["events"] = [e.strip() for e in events.split(",") if e.strip()]
        if min_risk_score is not None:
            kwargs["min_risk_score"] = min_risk_score
        if active is not None:
            kwargs["active"] = active

        try:
            if update_webhook(hook_id, **kwargs):
                return JSONResponse(content={"updated": True})
            raise HTTPException(status_code=404, detail="Webhook not found")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid webhook configuration")

    @app.post("/api/webhooks/{hook_id}/test", tags=["Webhooks"])
    async def webhook_test(hook_id: str, user: dict = _auth_settings):
        """Send a test payload to a webhook."""
        from hashguard.web.webhooks import send_test

        result = send_test(hook_id)
        if not result.get("success") and result.get("error") == "Webhook not found":
            raise HTTPException(status_code=404, detail="Webhook not found")
        return JSONResponse(content=result)


def start_server(host: str = "127.0.0.1", port: int = 8000, open_browser: bool = True):
    """Start the HashGuard web dashboard."""
    if not HAS_FASTAPI:
        print("ERROR: FastAPI not installed. Run: pip install fastapi uvicorn python-multipart")
        return

    url = f"http://{host}:{port}"
    banner = (
        "\n"
        "    +------------------------------------------------------+\n"
        "    |    HashGuard v1.1.4 - Malware Research Platform       |\n"
        "    |                                                       |\n"
        f"    |     Dashboard: {url:<39s}|\n"
        f"    |     API Docs:  {url + '/api/docs':<39s}|\n"
        "    +------------------------------------------------------+\n"
    )
    print(banner)

    if open_browser:
        threading.Timer(1.5, lambda: webbrowser.open(f"http://{host}:{port}")).start()

    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    start_server()
