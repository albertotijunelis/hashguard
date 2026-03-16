"""Backfill IOCs from stored full_result JSON into the iocs table.

The StringExtractionResult.to_dict() bug caused IOCs to be stored flat
in full_result->strings_info but never persisted to the iocs table.
This script recovers them.
"""
import sqlite3
import os
import json
import sys

DB = os.path.join(os.environ.get("APPDATA", ""), "HashGuard", "hashguard.db")
conn = sqlite3.connect(DB, timeout=60)
conn.row_factory = sqlite3.Row
conn.execute("PRAGMA journal_mode=WAL")

SKIP_KEYS = {"total_strings", "has_iocs", "iocs"}
IOC_TYPES = {
    "urls", "ips", "domains", "emails", "powershell_commands",
    "suspicious_paths", "crypto_wallets", "user_agents", "registry_keys",
}

# Get all samples with IOC data in full_result
rows = conn.execute(
    "SELECT id, full_result FROM samples WHERE full_result LIKE '%\"has_iocs\": true%'"
).fetchall()
print(f"Found {len(rows)} samples with IOC data to backfill")

total_iocs = 0
samples_updated = 0
batch_size = 500
batch_count = 0

for r in rows:
    try:
        data = json.loads(r["full_result"])
        si = data.get("strings_info", {})
        if not si:
            continue

        # Extract IOCs (flattened format from old to_dict)
        iocs = si.get("iocs", {})
        if not iocs:
            iocs = {k: v for k, v in si.items()
                    if k not in SKIP_KEYS and isinstance(v, list) and k in IOC_TYPES}

        if not iocs:
            continue

        sample_id = r["id"]
        # Clear existing (should be empty, but safe)
        conn.execute("DELETE FROM iocs WHERE sample_id = ?", (sample_id,))

        count = 0
        for ioc_type, values in iocs.items():
            if isinstance(values, list):
                for val in values[:50]:
                    conn.execute(
                        "INSERT INTO iocs (sample_id, ioc_type, value) VALUES (?, ?, ?)",
                        (sample_id, ioc_type, str(val)),
                    )
                    count += 1

        if count > 0:
            total_iocs += count
            samples_updated += 1

        batch_count += 1
        if batch_count >= batch_size:
            conn.commit()
            batch_count = 0
            print(f"  ...{samples_updated} samples, {total_iocs} IOCs so far")

    except (json.JSONDecodeError, Exception) as e:
        print(f"  Warning: sample id={r['id']}: {e}", file=sys.stderr)
        continue

conn.commit()
print(f"\nDone! Updated {samples_updated} samples with {total_iocs} IOCs total")

# Verify
final_count = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
type_breakdown = conn.execute(
    "SELECT ioc_type, COUNT(*) as cnt FROM iocs GROUP BY ioc_type ORDER BY cnt DESC"
).fetchall()
print(f"\nFinal IOC count: {final_count}")
print("By type:")
for t in type_breakdown:
    print(f"  {t['ioc_type']}: {t['cnt']}")

conn.close()
