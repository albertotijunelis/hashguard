"""Check if full_result JSON matches DB risk_score for repaired samples."""
import os, sqlite3, json

DB = os.path.join(os.environ.get("APPDATA", ""), "HashGuard", "hashguard.db")
conn = sqlite3.connect(DB)
conn.row_factory = sqlite3.Row

# Check a few samples with risk_score=20
rows = conn.execute(
    "SELECT id, filename, risk_score, verdict, full_result "
    "FROM samples WHERE risk_score = 20 LIMIT 5"
).fetchall()

print("=== Samples with risk_score=20 (first 5) ===")
for r in rows:
    fr = r["full_result"]
    if fr:
        try:
            d = json.loads(fr)
            rs = d.get("risk_score", "N/A")
            print(f"  ID={r['id']} | DB_risk={r['risk_score']} | full_result.risk_score={rs}")
        except Exception as e:
            print(f"  ID={r['id']} | DB_risk={r['risk_score']} | parse error: {e}")
    else:
        print(f"  ID={r['id']} | DB_risk={r['risk_score']} | NO full_result")

# Count mismatches using json_extract
cur = conn.execute(
    "SELECT COUNT(*) FROM samples "
    "WHERE risk_score = 20 AND full_result IS NOT NULL "
    "AND full_result != '' "
    "AND json_extract(full_result, '$.risk_score.score') != 20"
)
mismatch = cur.fetchone()[0]

total_20 = conn.execute("SELECT COUNT(*) FROM samples WHERE risk_score = 20").fetchone()[0]
no_fr = conn.execute(
    "SELECT COUNT(*) FROM samples WHERE risk_score = 20 "
    "AND (full_result IS NULL OR full_result = '')"
).fetchone()[0]

print(f"\nTotal with risk_score=20: {total_20}")
print(f"  With no full_result: {no_fr}")
print(f"  With full_result.risk_score.score != 20: {mismatch}")

# Also check samples with score=0
zero_total = conn.execute("SELECT COUNT(*) FROM samples WHERE risk_score = 0").fetchone()[0]
zero_clean = conn.execute(
    "SELECT COUNT(*) FROM samples WHERE risk_score = 0 AND verdict = 'clean'"
).fetchone()[0]
print(f"\nTotal with risk_score=0: {zero_total}")
print(f"  Of those, verdict=clean: {zero_clean}")

conn.close()
