"""Check if full_result contains IOC data for backfill."""
import sqlite3, os, json

DB = os.path.join(os.environ.get("APPDATA", ""), "HashGuard", "hashguard.db")
conn = sqlite3.connect(DB, timeout=30)
conn.row_factory = sqlite3.Row

rows = conn.execute(
    "SELECT id, full_result FROM samples WHERE full_result IS NOT NULL LIMIT 5"
).fetchall()

for r in rows:
    try:
        data = json.loads(r["full_result"])
        si = data.get("strings_info", {})
        keys = list(si.keys()) if si else []
        ioc_types = [k for k in keys if k not in ("total_strings", "has_iocs")]
        # Check if there are actual IOC values
        ioc_count = sum(len(si.get(k, [])) for k in ioc_types if isinstance(si.get(k), list))
        print(f"id={r['id']}: strings_info_keys={keys}, flat_ioc_types={ioc_types}, ioc_values={ioc_count}")
    except Exception as e:
        print(f"id={r['id']}: error={e}")

# Count how many samples have IOC data in full_result
has_iocs = conn.execute("""
    SELECT COUNT(*) FROM samples 
    WHERE full_result LIKE '%"has_iocs": true%'
""").fetchone()[0]
no_iocs = conn.execute("""
    SELECT COUNT(*) FROM samples 
    WHERE full_result LIKE '%"has_iocs": false%'
""").fetchone()[0]
no_strings = conn.execute("""
    SELECT COUNT(*) FROM samples 
    WHERE full_result NOT LIKE '%strings_info%' OR full_result IS NULL
""").fetchone()[0]

print(f"\nSamples with has_iocs=true in full_result: {has_iocs}")
print(f"Samples with has_iocs=false in full_result: {no_iocs}")
print(f"Samples without strings_info in full_result: {no_strings}")

conn.close()
