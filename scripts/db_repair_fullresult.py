"""Repair full_result JSON for batch-ingested samples where DB risk_score
was updated to 20 but full_result still has score=0/verdict=clean.

Also ensures future viewSample() calls show the correct score.
"""
import os, sqlite3, json, re

DB = os.path.join(os.environ.get("APPDATA", ""), "HashGuard", "hashguard.db")
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}(\.\w+)?$")

conn = sqlite3.connect(DB)
conn.row_factory = sqlite3.Row

rows = conn.execute(
    "SELECT id, filename, full_result FROM samples "
    "WHERE risk_score = 20 AND full_result IS NOT NULL AND full_result != '' "
    "AND json_extract(full_result, '$.risk_score.score') != 20"
).fetchall()

updated = 0
for r in rows:
    try:
        d = json.loads(r["full_result"])
    except (json.JSONDecodeError, TypeError):
        continue

    rs = d.get("risk_score")
    if isinstance(rs, dict) and rs.get("score", -1) != 20:
        rs["score"] = 20
        rs["verdict"] = "suspicious"
        if not rs.get("factors"):
            rs["factors"] = [
                {"name": "MalwareBazaar sample", "points": 20,
                 "detail": "Known malware sample from MalwareBazaar (minimum risk applied)"}
            ]
        d["risk_score"] = rs

    # Also fix top-level malicious flag if present
    d["malicious"] = True

    conn.execute(
        "UPDATE samples SET full_result = ? WHERE id = ?",
        (json.dumps(d, default=str), r["id"]),
    )
    updated += 1

conn.commit()

# Verify
still_mismatched = conn.execute(
    "SELECT COUNT(*) FROM samples "
    "WHERE risk_score = 20 AND full_result IS NOT NULL AND full_result != '' "
    "AND json_extract(full_result, '$.risk_score.score') != 20"
).fetchone()[0]

print(f"Updated full_result JSON for {updated} samples")
print(f"Remaining mismatches: {still_mismatched}")
conn.close()
