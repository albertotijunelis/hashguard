#!/usr/bin/env python3
"""Fix MalwareBazaar samples that were given score=20/verdict=suspicious.

These are confirmed malware from MalwareBazaar but the batch_ingest floor
was too low (20 → suspicious range).  Correct them to score=40 / verdict=malicious.
"""

import json
import os
import sqlite3
import sys

DB_PATH = os.path.join(
    os.environ.get("APPDATA", os.path.expanduser("~")),
    "HashGuard",
    "hashguard.db",
)


def main():
    if not os.path.exists(DB_PATH):
        print(f"Database not found: {DB_PATH}")
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")

    # Find samples with score=20 and verdict=suspicious (the old floor)
    rows = conn.execute(
        "SELECT id, full_result FROM samples "
        "WHERE risk_score = 20 AND verdict = 'suspicious'"
    ).fetchall()

    print(f"Found {len(rows)} samples with score=20 / verdict=suspicious")

    updated = 0
    for row in rows:
        sid = row["id"]
        # Update samples table
        conn.execute(
            "UPDATE samples SET risk_score = 40, verdict = 'malicious', "
            "is_malicious = 1 WHERE id = ?",
            (sid,),
        )
        # Update full_result JSON if present
        fr = row["full_result"]
        if fr:
            try:
                data = json.loads(fr)
                rs = data.get("risk_score", {})
                if isinstance(rs, dict):
                    rs["score"] = max(rs.get("score", 0), 40)
                    rs["verdict"] = "malicious"
                    data["risk_score"] = rs
                    conn.execute(
                        "UPDATE samples SET full_result = ? WHERE id = ?",
                        (json.dumps(data, default=str), sid),
                    )
            except (json.JSONDecodeError, TypeError):
                pass
        updated += 1

    # Also sync dataset_features labels
    conn.execute(
        "UPDATE dataset_features SET label_is_malicious = 1, label_verdict = 'malicious' "
        "WHERE sample_id IN ("
        "  SELECT id FROM samples WHERE risk_score = 40 AND verdict = 'malicious'"
        "  AND label_verdict != 'malicious'"
        ")"
    )
    synced = conn.execute("SELECT changes()").fetchone()[0]

    conn.commit()
    conn.close()
    print(f"Updated {updated} samples: score 20→40, verdict suspicious→malicious")
    print(f"Synced {synced} dataset_features labels")


if __name__ == "__main__":
    main()
