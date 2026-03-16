#!/usr/bin/env python3
"""One-time data repair: fix is_malicious/verdict mismatches in the DB.

Fixes:
1. Samples with is_malicious=1 but verdict='clean' → set is_malicious=0
   (verdict is the source of truth; these had score <= 15)
2. Batch-ingested samples (filename looks like SHA256 hash) with
   risk_score=0 and verdict='clean' → set verdict='suspicious', score=20
   (MalwareBazaar samples that the scanner couldn't fingerprint)
"""

import os
import re
import sqlite3
import sys

DB_PATH = os.path.join(
    os.environ.get("APPDATA", os.path.expanduser("~")),
    "HashGuard",
    "hashguard.db",
)

SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}(\.\w+)?$")


def main():
    if not os.path.exists(DB_PATH):
        print(f"Database not found: {DB_PATH}")
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    # --- Fix 1: is_malicious=1 but verdict='clean' -------------------------
    rows = conn.execute(
        "SELECT id FROM samples WHERE is_malicious = 1 AND verdict = 'clean'"
    ).fetchall()
    fix1_count = len(rows)
    if fix1_count:
        conn.execute(
            "UPDATE samples SET is_malicious = 0 "
            "WHERE is_malicious = 1 AND verdict = 'clean'"
        )
    print(f"Fix 1: {fix1_count} samples had is_malicious=1 + verdict=clean → set is_malicious=0")

    # --- Fix 2: Batch-ingested malware with score=0, verdict='clean' --------
    candidates = conn.execute(
        "SELECT id, filename FROM samples "
        "WHERE risk_score = 0 AND verdict = 'clean'"
    ).fetchall()
    batch_ids = [r["id"] for r in candidates if SHA256_RE.match(r["filename"] or "")]
    fix2_count = len(batch_ids)
    if fix2_count:
        placeholders = ",".join("?" * fix2_count)
        conn.execute(
            f"UPDATE samples SET verdict = 'suspicious', risk_score = 20 "
            f"WHERE id IN ({placeholders})",
            batch_ids,
        )
    print(f"Fix 2: {fix2_count} batch-ingested samples (score=0, verdict=clean) → suspicious/20")

    conn.commit()
    conn.close()

    # Verification
    conn2 = sqlite3.connect(DB_PATH)
    conn2.row_factory = sqlite3.Row
    verdicts = conn2.execute(
        "SELECT verdict, COUNT(*) as cnt FROM samples GROUP BY verdict"
    ).fetchall()
    total = conn2.execute("SELECT COUNT(*) FROM samples").fetchone()[0]
    print(f"\nPost-repair verdict distribution (total={total}):")
    for v in verdicts:
        print(f"  {v['verdict']}: {v['cnt']}")
    mismatches = conn2.execute(
        "SELECT COUNT(*) FROM samples WHERE is_malicious = 1 AND verdict = 'clean'"
    ).fetchone()[0]
    print(f"  Remaining is_malicious/verdict mismatches: {mismatches}")
    conn2.close()


if __name__ == "__main__":
    main()
