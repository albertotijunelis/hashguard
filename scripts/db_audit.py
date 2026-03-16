"""Quick DB audit script to check stats inconsistencies."""
import sqlite3
import os

db_path = os.path.join(os.environ.get("APPDATA", ""), "HashGuard", "hashguard.db")
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

# 1. Total and is_malicious counts
total = conn.execute("SELECT COUNT(*) FROM samples").fetchone()[0]
mal = conn.execute("SELECT COUNT(*) FROM samples WHERE is_malicious = 1").fetchone()[0]
clean_card = total - mal
print(f"Total: {total}")
print(f"is_malicious=1: {mal}")
print(f"Clean card (total - malicious): {clean_card}")
print()

# 2. Verdict distribution (chart data)
verdicts = conn.execute(
    "SELECT verdict, COUNT(*) as cnt FROM samples GROUP BY verdict ORDER BY cnt DESC"
).fetchall()
print("Verdict Distribution (chart):")
for v in verdicts:
    print(f"  {v['verdict']}: {v['cnt']}")
print()

# 3. Mismatch analysis
breakdown = conn.execute(
    "SELECT verdict, COUNT(*) as cnt FROM samples WHERE is_malicious = 0 GROUP BY verdict ORDER BY cnt DESC"
).fetchall()
print("is_malicious=0 samples by verdict:")
for b in breakdown:
    print(f"  {b['verdict']}: {b['cnt']}")
print()

# 4. Recent "clean" samples that might be suspicious
recent_clean = conn.execute(
    "SELECT id, filename, sha256, risk_score, verdict, is_malicious, analysis_date "
    "FROM samples WHERE verdict = 'clean' ORDER BY analysis_date DESC LIMIT 20"
).fetchall()
print("Recent 20 'clean' verdict samples:")
for s in recent_clean:
    print(f"  id={s['id']} score={s['risk_score']} verdict={s['verdict']} "
          f"mal={s['is_malicious']} file={s['filename']} date={s['analysis_date']}")
print()

# 5. Samples with risk_score > 15 but verdict = 'clean' 
suspicious_clean = conn.execute(
    "SELECT COUNT(*) FROM samples WHERE verdict = 'clean' AND risk_score > 15"
).fetchone()[0]
print(f"Samples with verdict='clean' but risk_score > 15: {suspicious_clean}")

# 6. Samples with risk_score 0 and verdict = 'clean'
zero_score = conn.execute(
    "SELECT COUNT(*) FROM samples WHERE verdict = 'clean' AND risk_score = 0"
).fetchone()[0]
print(f"Samples with verdict='clean' AND risk_score=0: {zero_score}")

# 7. Samples with verdict = 'unknown'
unknown = conn.execute(
    "SELECT COUNT(*) FROM samples WHERE verdict = 'unknown'"
).fetchone()[0]
print(f"Samples with verdict='unknown': {unknown}")

# 8. Check if is_malicious matches verdict properly
wrong_mal = conn.execute(
    "SELECT COUNT(*) FROM samples WHERE is_malicious = 1 AND verdict = 'clean'"
).fetchone()[0]
wrong_clean = conn.execute(
    "SELECT COUNT(*) FROM samples WHERE is_malicious = 0 AND verdict = 'malicious'"
).fetchone()[0]
print(f"\nMismatches:")
print(f"  is_malicious=1 but verdict=clean: {wrong_mal}")
print(f"  is_malicious=0 but verdict=malicious: {wrong_clean}")

conn.close()

# Further analysis
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

# 9. The 34 where is_malicious=1 but verdict=clean
rows = conn.execute(
    'SELECT id, filename, risk_score, verdict, is_malicious '
    'FROM samples WHERE is_malicious=1 AND verdict="clean" LIMIT 10'
).fetchall()
print("\nis_malicious=1 but verdict=clean (first 10):")
for r in rows:
    print(f"  id={r['id']} score={r['risk_score']} file={r['filename'][:50]}")

# 10. Risk score distribution of clean verdict
rows2 = conn.execute(
    'SELECT risk_score, COUNT(*) as c FROM samples '
    'WHERE verdict="clean" GROUP BY risk_score ORDER BY c DESC LIMIT 10'
).fetchall()
print("\nRisk score distribution of verdict=clean:")
for r in rows2:
    print(f"  score={r['risk_score']}: {r['c']}")

# 11. filename=sha256 pattern for zero-score
zero = conn.execute(
    'SELECT COUNT(*) FROM samples WHERE risk_score=0 AND verdict="clean" AND length(filename)=64'
).fetchone()[0]
print(f"\nrisk_score=0, verdict=clean, filename is 64-char hash: {zero}")

# 12. How many batch-ingested (score=0, filename=sha256 hash)
batch = conn.execute(
    'SELECT COUNT(*) FROM samples WHERE risk_score=0 AND length(filename)=64'
).fetchone()[0]
print(f"Total batch-ingested (score=0, hash filename): {batch}")

conn.close()
