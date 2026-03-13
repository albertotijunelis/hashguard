"""SQLite sample database for HashGuard v2.

Persists all analysis results, IOCs, behaviors, families, and clusters
for investigation and historical lookups.
"""

import json
import os
import sqlite3
import threading
from datetime import datetime
from typing import Dict, List, Optional

from hashguard.logger import get_logger

logger = get_logger(__name__)

_DB_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "HashGuard")
_DB_PATH = os.path.join(_DB_DIR, "hashguard.db")
_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    file_path TEXT,
    sha256 TEXT UNIQUE,
    sha1 TEXT,
    md5 TEXT,
    ssdeep TEXT,
    tlsh TEXT,
    imphash TEXT,
    file_size INTEGER DEFAULT 0,
    analysis_date TEXT,
    risk_score INTEGER DEFAULT 0,
    verdict TEXT DEFAULT 'unknown',
    is_malicious INTEGER DEFAULT 0,
    description TEXT,
    full_result TEXT,
    capabilities TEXT,
    advanced_pe TEXT,
    ml_classification TEXT,
    family TEXT,
    family_confidence REAL DEFAULT 0.0
);

CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id INTEGER REFERENCES samples(id) ON DELETE CASCADE,
    ioc_type TEXT NOT NULL,
    value TEXT NOT NULL,
    context TEXT
);

CREATE TABLE IF NOT EXISTS behaviors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id INTEGER REFERENCES samples(id) ON DELETE CASCADE,
    category TEXT NOT NULL,
    description TEXT,
    severity TEXT DEFAULT 'medium',
    mitre_attack TEXT
);

CREATE TABLE IF NOT EXISTS families (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    first_seen TEXT,
    sample_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS clusters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    centroid_sha256 TEXT,
    algorithm TEXT,
    created_date TEXT,
    sample_count INTEGER DEFAULT 0,
    shared_iocs TEXT
);

CREATE TABLE IF NOT EXISTS cluster_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cluster_id INTEGER REFERENCES clusters(id) ON DELETE CASCADE,
    sample_id INTEGER REFERENCES samples(id) ON DELETE CASCADE,
    similarity REAL DEFAULT 0.0
);

CREATE TABLE IF NOT EXISTS timeline_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id INTEGER REFERENCES samples(id) ON DELETE CASCADE,
    timestamp TEXT,
    event_type TEXT,
    description TEXT,
    details TEXT
);

CREATE INDEX IF NOT EXISTS idx_samples_sha256 ON samples(sha256);
CREATE INDEX IF NOT EXISTS idx_samples_md5 ON samples(md5);
CREATE INDEX IF NOT EXISTS idx_samples_family ON samples(family);
CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
CREATE INDEX IF NOT EXISTS idx_behaviors_category ON behaviors(category);
"""

# Dynamic schema for dataset_features table (built from feature_extractor)
_DATASET_SCHEMA_APPLIED = False


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
    cols = ["id INTEGER PRIMARY KEY AUTOINCREMENT", "sample_id INTEGER UNIQUE REFERENCES samples(id) ON DELETE CASCADE", "sha256 TEXT UNIQUE", "created_at TEXT"]
    for col_name, col_type in FEATURE_COLUMNS.items():
        cols.append(f"{col_name} {col_type}")
    ddl = f"CREATE TABLE IF NOT EXISTS dataset_features (\n    {', '.join(cols)}\n);"
    conn = get_connection()
    conn.executescript(ddl)

    # Migrate: add any columns missing from older schema versions
    existing = {row[1] for row in conn.execute("PRAGMA table_info(dataset_features)").fetchall()}
    for col_name, col_type in FEATURE_COLUMNS.items():
        if col_name not in existing:
            try:
                conn.execute(f"ALTER TABLE dataset_features ADD COLUMN {col_name} {col_type}")
            except Exception:
                pass  # column already exists or other benign error

    # Indexes for ML queries
    conn.executescript("""
        CREATE INDEX IF NOT EXISTS idx_dataset_sha256 ON dataset_features(sha256);
        CREATE INDEX IF NOT EXISTS idx_dataset_verdict ON dataset_features(label_verdict);
        CREATE INDEX IF NOT EXISTS idx_dataset_family ON dataset_features(label_family);
        CREATE INDEX IF NOT EXISTS idx_dataset_source ON dataset_features(label_source);
        CREATE INDEX IF NOT EXISTS idx_dataset_malicious ON dataset_features(label_is_malicious);
    """)
    conn.commit()
    _DATASET_SCHEMA_APPLIED = True


def get_connection() -> sqlite3.Connection:
    """Get a thread-local database connection."""
    if not hasattr(_local, "conn") or _local.conn is None:
        os.makedirs(_DB_DIR, exist_ok=True)
        _local.conn = sqlite3.connect(_DB_PATH)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA foreign_keys=ON")
    return _local.conn


def init_db() -> None:
    """Initialize the database schema."""
    conn = get_connection()
    conn.executescript(SCHEMA)
    conn.commit()


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
        iocs = strings_info.get("iocs", {})
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


def get_all_samples(limit: int = 100, offset: int = 0) -> List[dict]:
    """Get all samples, most recent first."""
    init_db()
    conn = get_connection()
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


def get_stats() -> dict:
    """Get dashboard statistics."""
    init_db()
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) FROM samples").fetchone()[0]
    malicious = conn.execute("SELECT COUNT(*) FROM samples WHERE is_malicious = 1").fetchone()[0]
    clean = total - malicious

    families = conn.execute(
        "SELECT family, COUNT(*) as cnt FROM samples WHERE family != '' GROUP BY family ORDER BY cnt DESC LIMIT 10"
    ).fetchall()

    recent = conn.execute(
        "SELECT id, filename, sha256, risk_score, verdict, is_malicious, analysis_date, family "
        "FROM samples ORDER BY analysis_date DESC LIMIT 20"
    ).fetchall()

    verdicts = conn.execute(
        "SELECT verdict, COUNT(*) as cnt FROM samples GROUP BY verdict"
    ).fetchall()

    return {
        "total_samples": total,
        "malicious": malicious,
        "clean": clean,
        "detection_rate": round(malicious / total * 100, 1) if total > 0 else 0,
        "top_families": [{"name": f["family"], "count": f["cnt"]} for f in families],
        "recent_samples": [dict(r) for r in recent],
        "verdict_distribution": {v["verdict"]: v["cnt"] for v in verdicts},
    }


def search_samples(query: str) -> List[dict]:
    """Search samples by filename, hash, or family."""
    init_db()
    conn = get_connection()
    like = f"%{query}%"
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
    """Return summary statistics for the dataset."""
    init_db()
    _ensure_dataset_table()
    from hashguard.feature_extractor import FEATURE_COLUMNS
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) FROM dataset_features").fetchone()[0]
    malicious = conn.execute("SELECT COUNT(*) FROM dataset_features WHERE label_is_malicious = 1").fetchone()[0]
    clean = total - malicious
    verdicts = conn.execute("SELECT label_verdict, COUNT(*) as cnt FROM dataset_features GROUP BY label_verdict").fetchall()
    families = conn.execute(
        "SELECT label_family, COUNT(*) as cnt FROM dataset_features WHERE label_family != '' GROUP BY label_family ORDER BY cnt DESC LIMIT 20"
    ).fetchall()
    return {
        "total": total,
        "malicious": malicious,
        "clean": clean,
        "feature_count": len(FEATURE_COLUMNS),
        "verdict_distribution": [{"verdict": r["label_verdict"], "count": r["cnt"]} for r in verdicts],
        "top_families": [{"family": r["label_family"], "count": r["cnt"]} for r in families],
    }


def export_dataset(fmt: str = "csv") -> str:
    """Export the full dataset_features table as CSV string."""
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
