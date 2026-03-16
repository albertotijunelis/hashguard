"""Quick verification of re-scored data."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from hashguard.database import get_connection, init_db

init_db()
conn = get_connection()

# Verify score=40 samples
print("=== Score=40 samples (first 5) ===")
rows = conn.execute(
    "SELECT id, risk_score, full_result FROM samples WHERE risk_score=40 LIMIT 5"
).fetchall()
for r in rows:
    fr = json.loads(r[2])
    rs = fr.get("risk_score", {})
    factors_sum = sum(f.get("points", 0) for f in rs.get("factors", []))
    json_score = rs.get("score", -1)
    print(f"  id={r[0]} DB={r[1]} JSON={json_score} sum={factors_sum}")
    for f in rs.get("factors", []):
        print(f"    {f['name']:35s} +{f['points']:3d}")

# Stats
print()
total = conn.execute("SELECT COUNT(*) FROM samples").fetchone()[0]
mal = conn.execute("SELECT COUNT(*) FROM samples WHERE is_malicious=1").fetchone()[0]
clean = conn.execute("SELECT COUNT(*) FROM samples WHERE is_malicious=0").fetchone()[0]
print(f"Total: {total}, Malicious: {mal} ({mal/total*100:.1f}%), Clean: {clean}")

# Verdict distribution
print("\n=== Verdict Distribution ===")
rows = conn.execute("SELECT verdict, COUNT(*) FROM samples GROUP BY verdict").fetchall()
for r in rows:
    print(f"  {r[0]:12s}: {r[1]:5d}")

# Previously mismatched score=40/breakdown=20 samples
print("\n=== Former score=40 samples (now score=20) ===")
rows = conn.execute(
    "SELECT id, risk_score, full_result FROM samples WHERE risk_score=20 LIMIT 3"
).fetchall()
for r in rows:
    fr = json.loads(r[2])
    rs = fr.get("risk_score", {})
    factors_sum = sum(f.get("points", 0) for f in rs.get("factors", []))
    print(f"  id={r[0]} DB={r[1]} JSON={rs.get('score')} sum={factors_sum} verdict={rs.get('verdict')}")
    for f in rs.get("factors", []):
        print(f"    {f['name']:35s} +{f['points']:3d}")

# Detection rate
print(f"\nDetection rate: {mal/total*100:.1f}%")
