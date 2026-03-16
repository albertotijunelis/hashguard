"""HashGuard database layer — unified ORM-backed access.

All queries go through the SQLAlchemy engine from models.py, eliminating
the dual-connection issue (raw sqlite3 vs ORM) that caused data
inconsistency between dashboard, dataset, and admin pages.

For callers that still need a raw DBAPI connection (dataset_features
dynamic schema, legacy scripts), ``get_connection()`` returns one from
the shared engine so it shares the same database file/connection pool.
"""

import json
import os
import threading
from datetime import datetime
from typing import Dict, List, Optional, Union

from sqlalchemy import text

from hashguard.logger import get_logger

logger = get_logger(__name__)

# Thread-local cache for raw DBAPI connections from the engine
_local = threading.local()

# Legacy constants kept for backward-compat (scripts reference _DB_PATH)
_DB_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "HashGuard")
_DB_PATH = os.path.join(_DB_DIR, "hashguard.db")

# Dynamic schema for dataset_features table (built from feature_extractor)
_DATASET_SCHEMA_APPLIED = False

def _get_engine():
    """Import and return the shared engine from models (avoids circular import)."""
    from hashguard.models import get_engine, init_orm_db
    engine = get_engine()
    init_orm_db()
    return engine


def _ensure_dataset_table() -> None:
    """Create the dataset_features table if it doesn't exist.

    Also handles schema migration: if the table was created with an older
    version of FEATURE_COLUMNS, any new columns are added via ALTER TABLE.
    """
    global _DATASET_SCHEMA_APPLIED
    if _DATASET_SCHEMA_APPLIED:
        return
    try:
        from hashguard.feature_extractor import FEATURE_COLUMNS
    except ImportError:
        return

    conn = get_connection()
    is_sqlite = _is_sqlite()

    cols = [
        "id INTEGER PRIMARY KEY AUTOINCREMENT" if is_sqlite else "id SERIAL PRIMARY KEY",
        "sample_id INTEGER UNIQUE REFERENCES samples(id) ON DELETE CASCADE",
        "sha256 TEXT UNIQUE",
        "created_at TEXT",
    ]
    for col_name, col_type in FEATURE_COLUMNS.items():
        cols.append(f"{col_name} {col_type}")
    ddl = f"CREATE TABLE IF NOT EXISTS dataset_features (\n    {', '.join(cols)}\n);"

    if is_sqlite:
        conn.executescript(ddl)
    else:
        conn.execute(ddl)
        conn.commit()

    # Migrate: add any columns missing from older schema versions
    if is_sqlite:
        existing = {row[1] for row in conn.execute("PRAGMA table_info(dataset_features)").fetchall()}
    else:
        existing = {row[0] for row in conn.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_name='dataset_features'"
        ).fetchall()}

    for col_name, col_type in FEATURE_COLUMNS.items():
        if col_name not in existing:
            try:
                conn.execute(f"ALTER TABLE dataset_features ADD COLUMN {col_name} {col_type}")
            except Exception:
                pass

    # Indexes for ML queries
    for idx_sql in [
        "CREATE INDEX IF NOT EXISTS idx_dataset_sha256 ON dataset_features(sha256)",
        "CREATE INDEX IF NOT EXISTS idx_dataset_verdict ON dataset_features(label_verdict)",
        "CREATE INDEX IF NOT EXISTS idx_dataset_family ON dataset_features(label_family)",
        "CREATE INDEX IF NOT EXISTS idx_dataset_source ON dataset_features(label_source)",
        "CREATE INDEX IF NOT EXISTS idx_dataset_malicious ON dataset_features(label_is_malicious)",
    ]:
        try:
            conn.execute(idx_sql)
        except Exception:
            pass
    conn.commit()
    _DATASET_SCHEMA_APPLIED = True


def _is_sqlite() -> bool:
    """Check if the current engine is SQLite."""
    return str(_get_engine().url).startswith("sqlite")


def get_connection():
    """Get a thread-local raw DBAPI connection from the shared engine.

    This ensures ``database.py`` and ``models.py`` use the same database
    file/connection pool, eliminating the dual-path inconsistency.
    """
    if not hasattr(_local, "conn") or _local.conn is None:
        engine = _get_engine()
        pool_conn = engine.raw_connection()
        # Unwrap the pool proxy to get the actual DBAPI connection
        raw = getattr(pool_conn, "dbapi_connection", None) or getattr(pool_conn, "connection", pool_conn)
        # Enable dict-like row access for sqlite3
        if _is_sqlite():
            import sqlite3
            raw.row_factory = sqlite3.Row
        _local.conn = raw
    return _local.conn


def get_db_path() -> str:
    """Return the database file path (for legacy callers like anomaly_detector)."""
    return _DB_PATH


def init_db() -> None:
    """Initialize the database schema via the ORM engine.

    This is now a thin wrapper — the actual schema creation happens in
    ``models.init_orm_db()`` called by ``_get_engine()``.
    """
    _get_engine()  # triggers init_orm_db()


def store_sample(result_dict: dict) -> int:
    """Store a complete analysis result. Returns sample ID."""
    init_db()
    conn = get_connection()

    hashes = result_dict.get("hashes", {})
    risk = result_dict.get("risk_score", {})
    caps = result_dict.get("capabilities")
    adv_pe = result_dict.get("advanced_pe")
    ml = result_dict.get("ml_classification")
    family = result_dict.get("family_detection", {})

    sha256 = hashes.get("sha256", "")

    # Check if already exists
    row = conn.execute("SELECT id FROM samples WHERE sha256 = ?", (sha256,)).fetchone()
    if row:
        sample_id = row["id"]
        conn.execute(
            """
            UPDATE samples SET
                risk_score=?, verdict=?, is_malicious=?, description=?,
                full_result=?, capabilities=?, advanced_pe=?, ml_classification=?,
                family=?, family_confidence=?, analysis_date=?
            WHERE id=?
        """,
            (
                risk.get("score", 0),
                risk.get("verdict", "unknown"),
                1 if result_dict.get("malicious") else 0,
                result_dict.get("description", ""),
                json.dumps(result_dict, default=str),
                json.dumps(caps, default=str) if caps else None,
                json.dumps(adv_pe, default=str) if adv_pe else None,
                json.dumps(ml, default=str) if ml else None,
                family.get("family", ""),
                family.get("confidence", 0.0),
                datetime.now().isoformat(),
                sample_id,
            ),
        )
    else:
        fuzzy = result_dict.get("fuzzy_hashes", {}).get("hashes", {})
        cursor = conn.execute(
            """
            INSERT INTO samples (
                filename, file_path, sha256, sha1, md5, ssdeep, tlsh, imphash,
                file_size, analysis_date, risk_score, verdict, is_malicious,
                description, full_result, capabilities, advanced_pe,
                ml_classification, family, family_confidence
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                os.path.basename(result_dict.get("path", "")),
                result_dict.get("path", ""),
                sha256,
                hashes.get("sha1", ""),
                hashes.get("md5", ""),
                fuzzy.get("ssdeep", ""),
                fuzzy.get("tlsh", ""),
                (adv_pe or {}).get("imphash", ""),
                result_dict.get("file_size", 0),
                datetime.now().isoformat(),
                risk.get("score", 0),
                risk.get("verdict", "unknown"),
                1 if result_dict.get("malicious") else 0,
                result_dict.get("description", ""),
                json.dumps(result_dict, default=str),
                json.dumps(caps, default=str) if caps else None,
                json.dumps(adv_pe, default=str) if adv_pe else None,
                json.dumps(ml, default=str) if ml else None,
                family.get("family", "") if family else "",
                family.get("confidence", 0.0) if family else 0.0,
            ),
        )
        sample_id = cursor.lastrowid

    # Store IOCs
    strings_info = result_dict.get("strings_info") or result_dict.get("strings", {})
    if strings_info:
        conn.execute("DELETE FROM iocs WHERE sample_id = ?", (sample_id,))
        # Support both nested {"iocs": {type: [...]}} and flat {type: [...]} formats
        iocs = strings_info.get("iocs", {})
        if not iocs:
            # Fallback: IOCs might be flattened into strings_info directly
            skip = {"total_strings", "has_iocs", "iocs"}
            iocs = {k: v for k, v in strings_info.items()
                    if k not in skip and isinstance(v, list)}
        for ioc_type, values in iocs.items():
            if isinstance(values, list):
                for val in values[:50]:
                    conn.execute(
                        "INSERT INTO iocs (sample_id, ioc_type, value) VALUES (?, ?, ?)",
                        (sample_id, ioc_type, str(val)),
                    )

    # Store behaviors from capabilities
    if caps:
        conn.execute("DELETE FROM behaviors WHERE sample_id = ?", (sample_id,))
        for cap in caps.get("capabilities", []):
            conn.execute(
                "INSERT INTO behaviors (sample_id, category, description, severity, mitre_attack) VALUES (?, ?, ?, ?, ?)",
                (
                    sample_id,
                    cap.get("category", ""),
                    cap.get("name", ""),
                    cap.get("severity", "medium"),
                    cap.get("mitre_attack", ""),
                ),
            )

    conn.commit()
    return sample_id


def get_sample(sha256: str) -> Optional[dict]:
    """Get sample by SHA256 hash."""
    init_db()
    conn = get_connection()
    row = conn.execute("SELECT * FROM samples WHERE sha256 = ?", (sha256,)).fetchone()
    if row:
        return dict(row)
    return None


def get_sample_by_id(sample_id: int) -> Optional[dict]:
    """Get sample by ID."""
    init_db()
    conn = get_connection()
    row = conn.execute("SELECT * FROM samples WHERE id = ?", (sample_id,)).fetchone()
    if row:
        return dict(row)
    return None


def get_all_samples(limit: int = 100, offset: int = 0, tenant_id: str = None) -> List[dict]:
    """Get all samples, most recent first. Optionally filtered by tenant."""
    init_db()
    conn = get_connection()
    if tenant_id:
        rows = conn.execute(
            "SELECT * FROM samples WHERE tenant_id = ? ORDER BY analysis_date DESC LIMIT ? OFFSET ?",
            (tenant_id, limit, offset),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM samples ORDER BY analysis_date DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    return [dict(r) for r in rows]


def get_sample_iocs(sample_id: int) -> List[dict]:
    """Get IOCs for a sample."""
    init_db()
    conn = get_connection()
    rows = conn.execute("SELECT * FROM iocs WHERE sample_id = ?", (sample_id,)).fetchall()
    return [dict(r) for r in rows]


def get_sample_behaviors(sample_id: int) -> List[dict]:
    """Get behaviors for a sample."""
    init_db()
    conn = get_connection()
    rows = conn.execute("SELECT * FROM behaviors WHERE sample_id = ?", (sample_id,)).fetchall()
    return [dict(r) for r in rows]


def get_stats(tenant_id: str = None) -> dict:
    """Get dashboard statistics. Optionally filtered by tenant."""
    init_db()
    conn = get_connection()
    where = "WHERE tenant_id = ?" if tenant_id else ""
    params: tuple = (tenant_id,) if tenant_id else ()

    total = conn.execute(f"SELECT COUNT(*) FROM samples {where}", params).fetchone()[0]

    # Derive all counts from the verdict column (single source of truth)
    if tenant_id:
        verdicts = conn.execute(
            "SELECT verdict, COUNT(*) as cnt FROM samples WHERE tenant_id = ? GROUP BY verdict",
            (tenant_id,),
        ).fetchall()
        families = conn.execute(
            "SELECT family, COUNT(*) as cnt FROM samples WHERE tenant_id = ? AND family != '' GROUP BY family ORDER BY cnt DESC LIMIT 10",
            (tenant_id,),
        ).fetchall()
        recent = conn.execute(
            "SELECT id, filename, sha256, risk_score, verdict, is_malicious, analysis_date, family "
            "FROM samples WHERE tenant_id = ? ORDER BY analysis_date DESC LIMIT 20",
            (tenant_id,),
        ).fetchall()
    else:
        verdicts = conn.execute(
            "SELECT verdict, COUNT(*) as cnt FROM samples GROUP BY verdict"
        ).fetchall()
        families = conn.execute(
            "SELECT family, COUNT(*) as cnt FROM samples WHERE family != '' GROUP BY family ORDER BY cnt DESC LIMIT 10"
        ).fetchall()
        recent = conn.execute(
            "SELECT id, filename, sha256, risk_score, verdict, is_malicious, analysis_date, family "
            "FROM samples ORDER BY analysis_date DESC LIMIT 20"
        ).fetchall()

    verdict_distribution = {v["verdict"]: v["cnt"] for v in verdicts}
    malicious = verdict_distribution.get("malicious", 0)
    suspicious = verdict_distribution.get("suspicious", 0)
    clean = verdict_distribution.get("clean", 0)

    return {
        "total_samples": total,
        "malicious": malicious,
        "suspicious": suspicious,
        "clean": clean,
        "detection_rate": round(malicious / total * 100, 1) if total > 0 else 0,
        "top_families": [{"name": f["family"], "count": f["cnt"]} for f in families],
        "recent_samples": [dict(r) for r in recent],
        "verdict_distribution": verdict_distribution,
    }


def search_samples(query: str, tenant_id: str = None) -> List[dict]:
    """Search samples by filename, hash, or family. Optionally filtered by tenant."""
    init_db()
    conn = get_connection()
    like = f"%{query}%"
    if tenant_id:
        rows = conn.execute(
            """
            SELECT * FROM samples
            WHERE tenant_id = ? AND (filename LIKE ? OR sha256 LIKE ? OR md5 LIKE ? OR family LIKE ? OR description LIKE ?)
            ORDER BY analysis_date DESC LIMIT 50
        """,
            (tenant_id, like, like, like, like, like),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT * FROM samples
            WHERE filename LIKE ? OR sha256 LIKE ? OR md5 LIKE ? OR family LIKE ? OR description LIKE ?
            ORDER BY analysis_date DESC LIMIT 50
        """,
            (like, like, like, like, like),
        ).fetchall()
    return [dict(r) for r in rows]


def search_iocs(query: str) -> List[dict]:
    """Search IOCs across all samples."""
    init_db()
    conn = get_connection()
    like = f"%{query}%"
    rows = conn.execute(
        """
        SELECT i.*, s.filename, s.sha256 FROM iocs i
        JOIN samples s ON i.sample_id = s.id
        WHERE i.value LIKE ?
        ORDER BY i.id DESC LIMIT 100
    """,
        (like,),
    ).fetchall()
    return [dict(r) for r in rows]


def store_cluster(
    name: str, members: List[dict], shared_iocs: List[str] = None, algorithm: str = "fuzzy"
) -> int:
    """Store a malware cluster."""
    init_db()
    conn = get_connection()
    cursor = conn.execute(
        """
        INSERT INTO clusters (name, algorithm, created_date, sample_count, shared_iocs)
        VALUES (?, ?, ?, ?, ?)
    """,
        (name, algorithm, datetime.now().isoformat(), len(members), json.dumps(shared_iocs or [])),
    )
    cluster_id = cursor.lastrowid

    for member in members:
        conn.execute(
            """
            INSERT INTO cluster_members (cluster_id, sample_id, similarity)
            VALUES (?, ?, ?)
        """,
            (cluster_id, member["sample_id"], member.get("similarity", 0)),
        )

    conn.commit()
    return cluster_id


def get_clusters() -> List[dict]:
    """Get all clusters."""
    init_db()
    conn = get_connection()
    rows = conn.execute("SELECT * FROM clusters ORDER BY created_date DESC").fetchall()
    return [dict(r) for r in rows]


def store_timeline_event(
    sample_id: int, event_type: str, description: str, details: str = ""
) -> None:
    """Store a timeline event for a sample."""
    conn = get_connection()
    conn.execute(
        """
        INSERT INTO timeline_events (sample_id, timestamp, event_type, description, details)
        VALUES (?, ?, ?, ?, ?)
    """,
        (sample_id, datetime.now().isoformat(), event_type, description, details),
    )
    conn.commit()


def get_timeline(sample_id: int) -> List[dict]:
    """Get timeline events for a sample."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM timeline_events WHERE sample_id = ? ORDER BY timestamp",
        (sample_id,),
    ).fetchall()
    return [dict(r) for r in rows]


# ── Dataset feature store ──────────────────────────────────────────────────


def store_dataset_features(sample_id: int, sha256: str, features: Dict) -> None:
    """Insert or replace a feature row for a sample."""
    init_db()
    _ensure_dataset_table()
    from hashguard.feature_extractor import FEATURE_COLUMNS

    conn = get_connection()
    col_names = ["sample_id", "sha256", "created_at"] + list(FEATURE_COLUMNS.keys())
    placeholders = ", ".join(["?"] * len(col_names))
    values = [sample_id, sha256, datetime.now().isoformat()]
    for col in FEATURE_COLUMNS:
        values.append(features.get(col, 0))

    conn.execute(
        f"INSERT OR REPLACE INTO dataset_features ({', '.join(col_names)}) VALUES ({placeholders})",
        values,
    )
    conn.commit()


def get_dataset_stats() -> Dict:
    """Return summary statistics for the dataset.

    Uses the *samples* table as source of truth for verdict/malicious labels
    so dashboard and dataset pages report consistent numbers.
    """
    init_db()
    _ensure_dataset_table()
    from hashguard.feature_extractor import FEATURE_COLUMNS
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) FROM dataset_features").fetchone()[0]

    # Join against samples for current verdicts (source of truth)
    verdicts = conn.execute(
        "SELECT s.verdict, COUNT(*) as cnt "
        "FROM dataset_features df JOIN samples s ON df.sample_id = s.id "
        "GROUP BY s.verdict"
    ).fetchall()
    verdict_map = {r["verdict"]: r["cnt"] for r in verdicts}
    malicious = verdict_map.get("malicious", 0)
    suspicious = verdict_map.get("suspicious", 0)
    clean = verdict_map.get("clean", 0)

    families = conn.execute(
        "SELECT s.family, COUNT(*) as cnt "
        "FROM dataset_features df JOIN samples s ON df.sample_id = s.id "
        "WHERE s.family != '' AND s.family IS NOT NULL "
        "GROUP BY s.family ORDER BY cnt DESC LIMIT 20"
    ).fetchall()
    return {
        "total": total,
        "malicious": malicious,
        "suspicious": suspicious,
        "clean": clean,
        "feature_count": len(FEATURE_COLUMNS),
        "verdict_distribution": [{"verdict": v, "count": c} for v, c in verdict_map.items()],
        "top_families": [{"family": r["family"], "count": r["cnt"]} for r in families],
    }


def export_dataset(fmt: str = "csv") -> Union[str, bytes]:
    """Export the full dataset_features table as CSV, JSONL, or Parquet."""
    init_db()
    _ensure_dataset_table()
    from hashguard.feature_extractor import FEATURE_COLUMNS

    conn = get_connection()
    rows = conn.execute("SELECT * FROM dataset_features ORDER BY created_at DESC").fetchall()

    if fmt == "jsonl":
        import json as _json
        lines = []
        for r in rows:
            lines.append(_json.dumps(dict(r), default=str))
        return "\n".join(lines)

    if fmt == "parquet":
        import pyarrow as pa
        import pyarrow.parquet as pq
        import io as _io

        cols = ["sha256", "created_at"] + list(FEATURE_COLUMNS.keys())
        data = {c: [] for c in cols}
        for r in rows:
            rd = dict(r)
            for c in cols:
                data[c].append(rd.get(c))
        table = pa.table(data)
        buf = _io.BytesIO()
        pq.write_table(table, buf, compression="snappy")
        return buf.getvalue()

    # CSV (default)
    import csv
    import io
    output = io.StringIO()
    cols = ["sha256", "created_at"] + list(FEATURE_COLUMNS.keys())
    writer = csv.DictWriter(output, fieldnames=cols, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        writer.writerow({c: dict(r).get(c, "") for c in cols})
    return output.getvalue()


def export_dataset_anonymized(fmt: str = "csv") -> Union[str, bytes]:
    """Export the dataset with PII removed (anonymized).

    Wraps ``export_dataset`` and applies the anonymization pipeline.
    """
    from hashguard.anonymizer import anonymize_dataset

    raw = export_dataset(fmt=fmt)
    return anonymize_dataset(raw, fmt=fmt)


# ── Dataset versioning ────────────────────────────────────────────────

def create_dataset_version(version: str, fmt: str = "parquet",
                           notes: Optional[str] = None,
                           created_by: Optional[str] = None) -> dict:
    """Snapshot the current dataset_features into a versioned release.

    Returns version metadata dict with file path.
    """
    import hashlib
    from hashguard.models import DatasetVersion, get_orm_session

    data = export_dataset(fmt=fmt)
    data_bytes = data if isinstance(data, bytes) else data.encode("utf-8")

    checksum = hashlib.sha256(data_bytes).hexdigest()

    # Count stats
    stats = get_dataset_stats()

    # Save file
    import re as _re
    app_data = os.environ.get("APPDATA") or os.path.expanduser("~")
    dataset_dir = os.path.join(app_data, "HashGuard", "datasets")
    os.makedirs(dataset_dir, exist_ok=True)
    # Sanitize version and format to prevent path traversal
    safe_version = _re.sub(r'[^a-zA-Z0-9._-]', '', str(version))
    safe_ext = _re.sub(r'[^a-zA-Z0-9]', '', str(fmt))
    if not safe_version or not safe_ext:
        raise ValueError("Invalid version or format")
    filename = f"hashguard_dataset_v{safe_version}.{safe_ext}"
    filepath = os.path.join(dataset_dir, filename)
    # Ensure path stays within dataset_dir
    from pathlib import Path
    resolved_filepath = Path(filepath).resolve()
    resolved_dataset_dir = Path(dataset_dir).resolve()
    if not resolved_filepath.is_relative_to(resolved_dataset_dir):
        raise ValueError("Invalid version or format")
    with open(str(resolved_filepath), "wb") as f:
        f.write(data_bytes)

    # Store version record
    session = get_orm_session()
    try:
        dv = DatasetVersion(
            version=version,
            sample_count=stats["total"],
            malicious_count=stats["malicious"],
            benign_count=stats["clean"],
            feature_count=stats["feature_count"],
            file_size_bytes=len(data_bytes),
            sha256_checksum=checksum,
            format=fmt,
            notes=notes,
            created_by=created_by,
        )
        session.add(dv)
        session.commit()
        result = {
            "version": dv.version,
            "sample_count": dv.sample_count,
            "malicious_count": dv.malicious_count,
            "benign_count": dv.benign_count,
            "feature_count": dv.feature_count,
            "file_size_bytes": dv.file_size_bytes,
            "sha256_checksum": dv.sha256_checksum,
            "format": dv.format,
            "notes": dv.notes,
            "created_at": dv.created_at.isoformat() if dv.created_at else None,
            "file_path": filepath,
        }
        session.close()
        return result
    except Exception:
        session.rollback()
        session.close()
        raise


def list_dataset_versions() -> list[dict]:
    """List all dataset versions ordered by created_at desc."""
    from hashguard.models import DatasetVersion, get_orm_session
    session = get_orm_session()
    try:
        versions = session.query(DatasetVersion).order_by(
            DatasetVersion.created_at.desc()
        ).all()
        result = []
        for v in versions:
            result.append({
                "id": v.id,
                "version": v.version,
                "sample_count": v.sample_count,
                "malicious_count": v.malicious_count,
                "benign_count": v.benign_count,
                "feature_count": v.feature_count,
                "file_size_bytes": v.file_size_bytes,
                "sha256_checksum": v.sha256_checksum,
                "format": v.format,
                "notes": v.notes,
                "created_at": v.created_at.isoformat() if v.created_at else None,
            })
        return result
    finally:
        session.close()


def get_dataset_version_path(version: str) -> Optional[str]:
    """Get the file path for a specific dataset version."""
    from hashguard.models import DatasetVersion, get_orm_session
    session = get_orm_session()
    try:
        dv = session.query(DatasetVersion).filter_by(version=version).first()
        if not dv:
            return None
        app_data = os.environ.get("APPDATA") or os.path.expanduser("~")
        path = os.path.join(app_data, "HashGuard", "datasets",
                            f"hashguard_dataset_v{dv.version}.{dv.format}")
        return path if os.path.exists(path) else None
    finally:
        session.close()
