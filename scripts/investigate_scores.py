"""Investigate risk score mismatches in the database."""
import json
import sys
sys.path.insert(0, "src")

from hashguard.database import get_connection, init_db

init_db()
conn = get_connection()

# 1) Score distribution
print("=== Risk Score Distribution ===")
rows = conn.execute("SELECT risk_score, COUNT(*) as cnt FROM samples GROUP BY risk_score ORDER BY risk_score").fetchall()
for r in rows:
    print(f"  Score {r[0]:3d}: {r[1]:5d} samples")

# 2) Check score=40 samples
print("\n=== Samples with score=40 (first 5) ===")
rows = conn.execute("SELECT id, filename, risk_score, verdict FROM samples WHERE risk_score=40 LIMIT 5").fetchall()
for r in rows:
    print(f"  id={r[0]} file={r[1][:50]} score={r[2]} verdict={r[3]}")

# 3) Breakdown for score=40 samples
print("\n=== Breakdown for score=40 samples (first 3) ===")
rows = conn.execute("SELECT id, filename, full_result FROM samples WHERE risk_score=40 LIMIT 3").fetchall()
for row in rows:
    fr = json.loads(row[2]) if row[2] else {}
    rs = fr.get("risk_score", {})
    total_points = sum(f.get("points", 0) for f in rs.get("factors", []))
    print(f"\n  Sample id={row[0]} file={row[1][:50]}")
    print(f"  Stored score={rs.get('score')}, breakdown sum={total_points}")
    for f in rs.get("factors", []):
        print(f"    {f.get('name','?'):35s} +{f.get('points',0):3d}  {f.get('detail','')[:60]}")

# 4) Check mismatches across all samples
print("\n=== Score vs Breakdown Mismatch Analysis ===")
rows = conn.execute("SELECT id, risk_score, full_result FROM samples WHERE full_result IS NOT NULL").fetchall()
mismatch_count = 0
match_count = 0
no_factors = 0
for row in rows:
    fr = json.loads(row[2]) if row[2] else {}
    rs = fr.get("risk_score", {})
    stored_score = rs.get("score", row[1])
    factors = rs.get("factors", [])
    if not factors:
        no_factors += 1
        continue
    total_points = sum(f.get("points", 0) for f in factors)
    if stored_score != total_points:
        mismatch_count += 1
    else:
        match_count += 1

print(f"  Matches: {match_count}")
print(f"  Mismatches: {mismatch_count}")
print(f"  No factors: {no_factors}")
print(f"  Total with full_result: {len(rows)}")

# 5) Show a few mismatch examples
print("\n=== Mismatch Examples ===")
shown = 0
for row in rows:
    fr = json.loads(row[2]) if row[2] else {}
    rs = fr.get("risk_score", {})
    stored_score = rs.get("score", row[1])
    factors = rs.get("factors", [])
    if not factors:
        continue
    total_points = sum(f.get("points", 0) for f in factors)
    if stored_score != total_points and shown < 5:
        print(f"\n  id={row[0]} stored_score={stored_score} breakdown_sum={total_points} diff={stored_score - total_points}")
        for f in factors:
            print(f"    {f.get('name','?'):35s} +{f.get('points',0):3d}")
        shown += 1
