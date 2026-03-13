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
    from fastapi import FastAPI, File, UploadFile, Form, Query, HTTPException
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

app = FastAPI(title="HashGuard", version="1.1.3", docs_url="/api/docs") if HAS_FASTAPI else None

if app:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Content-Type", "Accept"],
    )


def _get_template_dir():
    """Locate the templates directory."""
    pkg_dir = Path(__file__).parent
    tmpl = pkg_dir / "templates"
    if tmpl.is_dir():
        return tmpl
    return pkg_dir


def _get_static_dir():
    """Locate the static assets directory."""
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
    except Exception as e:
        logger.debug(f"Auto-unpack error: {e}")

    # IOC Graph
    try:
        from hashguard.ioc_graph import build_graph

        graph = build_graph(result_dict)
        result_dict["ioc_graph"] = graph.to_visjs()
    except Exception as e:
        logger.debug(f"IOC graph error: {e}")

    # Timeline
    try:
        from hashguard.malware_timeline import build_timeline

        timeline = build_timeline(result_dict)
        result_dict["timeline"] = timeline.to_dict()
    except Exception as e:
        logger.debug(f"Timeline error: {e}")

    # Store in database
    try:
        from hashguard.database import store_sample, store_timeline_event

        sample_id = store_sample(result_dict)
        result_dict["sample_id"] = sample_id
        store_timeline_event(sample_id, "analysis", "Full v2 analysis completed")
    except Exception as e:
        logger.debug(f"Database storage error: {e}")

    # Extract & store ML dataset features
    feats = None
    try:
        from hashguard.feature_extractor import extract_features
        from hashguard.database import store_dataset_features

        feats = extract_features(file_path, result_dict)
        sha = result_dict.get("hashes", {}).get("sha256", "")
        if sha and sample_id:
            store_dataset_features(sample_id, sha, feats)
    except Exception as e:
        logger.debug(f"Dataset feature extraction error: {e}")

    # Real-time prediction using trained ML model
    try:
        if feats:
            from hashguard.ml_trainer import predict_sample

            prediction = predict_sample(feats)
            if "error" not in prediction:
                result_dict["trained_model_prediction"] = prediction
    except Exception as e:
        logger.debug(f"Trained model prediction error: {e}")

    return _sanitize_for_json(result_dict)


# ── Static Files ─────────────────────────────────────────────────────────────

if app:
    _static = _get_static_dir()
    if _static:
        app.mount("/static", StaticFiles(directory=str(_static)), name="static")

# ── API Endpoints ────────────────────────────────────────────────────────────

if app:

    @app.get("/", response_class=HTMLResponse)
    async def dashboard():
        """Serve the main dashboard."""
        tmpl_dir = _get_template_dir()
        index = tmpl_dir / "index.html"
        if index.is_file():
            return HTMLResponse(content=index.read_text(encoding="utf-8"))
        return HTMLResponse(content="<h1>HashGuard v2</h1><p>Template not found</p>")

    @app.post("/api/analyze")
    async def analyze_file(
        file: UploadFile = File(...),
        use_vt: bool = Form(False),
    ):
        """Upload and analyze a file."""
        import re

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
            return JSONResponse(content=result)
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Analysis error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

    @app.post("/api/analyze-url")
    async def analyze_url(url: str = Form(...), use_vt: bool = Form(False)):
        """Analyze a URL."""
        try:
            from hashguard.scanner import analyze_url as scan_url

            result = scan_url(url, vt=use_vt)
            result_dict = _sanitize_for_json(result.to_dict())
            return JSONResponse(content=result_dict)
        except ValueError as e:
            # SSRF block, bad scheme, private IP, download too large
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            err = str(e)
            # Friendly messages for common HTTP errors
            if "403" in err:
                raise HTTPException(
                    status_code=502, detail=f"Remote server denied access (403 Forbidden): {url}"
                )
            if "404" in err:
                raise HTTPException(
                    status_code=502, detail=f"File not found on remote server (404): {url}"
                )
            if "ConnectionError" in type(e).__name__ or "Timeout" in type(e).__name__:
                raise HTTPException(
                    status_code=502, detail=f"Could not connect to remote server: {url}"
                )
            raise HTTPException(status_code=500, detail=err)

    @app.get("/api/stats")
    async def get_stats():
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

    @app.get("/api/samples")
    async def list_samples(limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
        """List analyzed samples."""
        try:
            from hashguard.database import get_all_samples

            samples = get_all_samples(limit=limit, offset=offset)
            return JSONResponse(content={"samples": samples})
        except Exception as e:
            raise HTTPException(status_code=500, detail="Internal server error")

    @app.get("/api/samples/{sample_id}")
    async def get_sample_detail(sample_id: int):
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

    @app.get("/api/graph/{sample_id}")
    async def get_graph(sample_id: int):
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

    @app.get("/api/timeline/{sample_id}")
    async def get_sample_timeline(sample_id: int):
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

    @app.get("/api/export/stix/{sample_id}")
    async def export_stix(sample_id: int):
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
        except RuntimeError as e:
            raise HTTPException(status_code=501, detail=str(e))
        except Exception as e:
            logger.debug(f"STIX export error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    @app.get("/api/clusters")
    async def get_clusters():
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

    @app.get("/api/search")
    async def search(q: str = Query(..., min_length=1)):
        """Search samples and IOCs."""
        try:
            from hashguard.database import search_samples, search_iocs

            samples = search_samples(q)
            iocs = search_iocs(q)
            return JSONResponse(content={"samples": samples, "iocs": iocs})
        except Exception as e:
            raise HTTPException(status_code=500, detail="Internal server error")

    @app.get("/api/sandbox/status")
    async def sandbox_status():
        """Check sandbox availability."""
        try:
            from hashguard.sandbox import check_sandbox_availability

            return JSONResponse(content=check_sandbox_availability())
        except Exception as e:
            logger.warning(f"Sandbox status check failed: {e}")
            return JSONResponse(content={"any_available": False, "error": "Sandbox check failed"})

    @app.post("/api/sandbox/enhanced-monitor")
    async def enhanced_sandbox_monitor(duration: int = 30):
        """Run enhanced monitoring (snapshot diffs + ETW + registry checks)."""
        try:
            from hashguard.sandbox import enhanced_monitor

            duration = min(max(duration, 5), 120)  # 5-120 seconds
            result = enhanced_monitor(duration_seconds=duration)
            return JSONResponse(content=result.to_dict())
        except Exception as e:
            raise HTTPException(status_code=500, detail="Internal server error")

    @app.get("/api/enrichment/{sample_id}")
    async def enrich_sample(sample_id: int):
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

    @app.get("/api/dataset/stats")
    async def dataset_stats():
        """Return dataset summary statistics."""
        try:
            from hashguard.database import get_dataset_stats

            return JSONResponse(content=get_dataset_stats())
        except Exception as e:
            logger.warning(f"Dataset stats error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    @app.get("/api/dataset/export")
    async def dataset_export(fmt: str = Query("csv", pattern="^(csv|jsonl)$")):
        """Export the full ML dataset as CSV or JSONL."""
        try:
            from hashguard.database import export_dataset

            data = export_dataset(fmt=fmt)
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

    @app.get("/api/dataset/features/{sample_id}")
    async def dataset_sample_features(sample_id: int):
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

    # ── Settings endpoints ───────────────────────────────────────────────

    @app.get("/api/settings")
    async def get_settings():
        """Return current API-key status (masked) so the UI can show state."""
        vt = os.environ.get("HASHGUARD_VT_API_KEY") or os.environ.get("VT_API_KEY") or ""
        ab = os.environ.get("ABUSE_CH_API_KEY") or ""
        return JSONResponse(content={
            "vt_api_key_set": bool(vt),
            "vt_api_key_masked": (vt[:4] + "***" + vt[-4:]) if len(vt) >= 8 else ("***" if vt else ""),
            "abuse_ch_api_key_set": bool(ab),
            "abuse_ch_api_key_masked": (ab[:4] + "***" + ab[-4:]) if len(ab) >= 8 else ("***" if ab else ""),
        })

    @app.post("/api/settings")
    async def save_settings(
        vt_api_key: str = Form(""),
        abuse_ch_api_key: str = Form(""),
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
        return JSONResponse(content={"saved": saved, "ok": True})

    # ── Batch ingest endpoints ───────────────────────────────────────────

    @app.post("/api/ingest/start")
    async def ingest_start(
        source: str = Form("recent"),
        limit: int = Form(100),
        tag: str = Form(""),
        file_type: str = Form("exe"),
        directory: str = Form(""),
    ):
        """Start a batch ingest job from public feeds or local directory."""
        try:
            from hashguard.batch_ingest import start_ingest

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
                ingest_delay = 0.3
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

    @app.get("/api/ingest/status")
    async def ingest_status():
        """Return the current ingest job status."""
        try:
            from hashguard.batch_ingest import get_ingest_status

            return JSONResponse(content=get_ingest_status())
        except Exception as e:
            logger.warning(f"Ingest status error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    @app.post("/api/ingest/stop")
    async def ingest_stop():
        """Signal the running ingest job to stop."""
        try:
            from hashguard.batch_ingest import request_stop

            request_stop()
            return JSONResponse(content={"stopped": True})
        except Exception as e:
            logger.warning(f"Ingest stop error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    # ── ML Training endpoints ────────────────────────────────────────────

    @app.post("/api/ml/train")
    async def ml_train(
        mode: str = Form("binary"),
        algorithm: str = Form("random_forest"),
        test_size: float = Form(0.2),
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

    @app.get("/api/ml/status")
    async def ml_status():
        """Return the current training job status."""
        try:
            from hashguard.ml_trainer import get_training_status

            return JSONResponse(content=get_training_status())
        except Exception as e:
            logger.warning(f"ML status error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    @app.get("/api/ml/models")
    async def ml_models():
        """List all trained models."""
        try:
            from hashguard.ml_trainer import list_models

            return JSONResponse(content=list_models())
        except Exception as e:
            logger.warning(f"ML models error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    @app.get("/api/ml/models/{model_id}")
    async def ml_model_detail(model_id: str):
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

    @app.delete("/api/ml/models/{model_id}")
    async def ml_model_delete(model_id: str):
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

    @app.post("/api/ml/predict")
    async def ml_predict(sample_id: int = Form(...)):
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
                raise HTTPException(status_code=400, detail=result["error"])
            return JSONResponse(content=result)
        except HTTPException:
            raise
        except Exception as e:
            logger.warning(f"ML predict error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")


def start_server(host: str = "127.0.0.1", port: int = 8000, open_browser: bool = True):
    """Start the HashGuard web dashboard."""
    if not HAS_FASTAPI:
        print("ERROR: FastAPI not installed. Run: pip install fastapi uvicorn python-multipart")
        return

    url = f"http://{host}:{port}"
    banner = (
        "\n"
        "    +------------------------------------------------------+\n"
        "    |    HashGuard v1.1.3 - Malware Research Platform       |\n"
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
