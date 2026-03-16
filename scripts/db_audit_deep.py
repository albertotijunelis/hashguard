"""Deep data audit."""
import os, sqlite3
DB = os.path.join(os.environ.get("APPDATA", ""), "HashGuard", "hashguard.db")
c = sqlite3.connect(DB)
c.row_factory = sqlite3.Row

# Dataset features
ds = c.execute(
    "SELECT COUNT(*) as total, "
    "SUM(CASE WHEN label_is_malicious=1 THEN 1 ELSE 0 END) as mal, "
    "SUM(CASE WHEN label_is_malicious=0 THEN 1 ELSE 0 END) as clean "
    "FROM dataset_features"
).fetchone()
print(f"Dataset features: total={ds['total']} malicious={ds['mal']} clean={ds['clean']}")

# Dataset features gap (15582 samples - 15512 features = 70 missing)
gap = c.execute(
    "SELECT COUNT(*) FROM samples s "
    "LEFT JOIN dataset_features df ON s.id = df.sample_id "
    "WHERE df.id IS NULL"
).fetchone()[0]
print(f"Samples without features: {gap}")

# Dataset label_is_malicious vs samples.is_malicious mismatch
mismatch = c.execute(
    "SELECT COUNT(*) FROM samples s "
    "JOIN dataset_features df ON s.id = df.sample_id "
    "WHERE s.is_malicious != df.label_is_malicious"
).fetchone()[0]
print(f"is_malicious vs label_is_malicious mismatches: {mismatch}")

# What does dataset use for malicious label?
print("\n--- Dataset label_is_malicious distribution ---")
for r in c.execute("SELECT label_is_malicious, COUNT(*) as cnt FROM dataset_features GROUP BY label_is_malicious").fetchall():
    print(f"  label_is_malicious={r['label_is_malicious']}: {r['cnt']}")

# What does dataset use for verdict?
print("\n--- Dataset label_verdict distribution ---")
for r in c.execute("SELECT label_verdict, COUNT(*) as cnt FROM dataset_features GROUP BY label_verdict ORDER BY cnt DESC").fetchall():
    print(f"  label_verdict={r['label_verdict']}: {r['cnt']}")

print("\n--- Samples verdict distribution ---")
for r in c.execute("SELECT verdict, COUNT(*) as cnt FROM samples GROUP BY verdict ORDER BY cnt DESC").fetchall():
    print(f"  verdict={r['verdict']}: {r['cnt']}")

print("\n--- Risk score distribution (top 20) ---")
for r in c.execute("SELECT risk_score, COUNT(*) as cnt FROM samples GROUP BY risk_score ORDER BY cnt DESC LIMIT 20").fetchall():
    print(f"  risk_score={r['risk_score']}: {r['cnt']}")

print("\n--- Score=20 breakdown ---")
for r in c.execute("SELECT verdict, family, COUNT(*) as cnt FROM samples WHERE risk_score=20 GROUP BY verdict, family ORDER BY cnt DESC LIMIT 10").fetchall():
    print(f"  verdict={r['verdict']} family={r['family'] or 'N/A'}: {r['cnt']}")

print("\n--- Score=40 breakdown ---")
for r in c.execute("SELECT verdict, family, COUNT(*) as cnt FROM samples WHERE risk_score=40 GROUP BY verdict, family ORDER BY cnt DESC LIMIT 10").fetchall():
    print(f"  verdict={r['verdict']} family={r['family'] or 'N/A'}: {r['cnt']}")

# Check what generates score 20/40
print("\n--- Score=20 typical factors ---")
for r in c.execute(
    "SELECT full_result FROM samples WHERE risk_score=20 AND full_result IS NOT NULL LIMIT 3"
).fetchall():
    import json
    try:
        d = json.loads(r["full_result"])
        rs = d.get("risk_score", {})
        if isinstance(rs, dict):
            print(f"  factors: {rs.get('factors', [])}")
    except: pass

print("\n--- Score=40 typical factors ---")
for r in c.execute(
    "SELECT full_result FROM samples WHERE risk_score=40 AND full_result IS NOT NULL LIMIT 3"
).fetchall():
    import json
    try:
        d = json.loads(r["full_result"])
        rs = d.get("risk_score", {})
        if isinstance(rs, dict):
            print(f"  factors: {rs.get('factors', [])}")
    except: pass

# IOC table check
print(f"\n--- IOCs table ---")
print(f"Total IOCs: {c.execute('SELECT COUNT(*) FROM iocs').fetchone()[0]}")
# Check if IOCs are stored somewhere else
tables = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
print(f"All tables: {tables}")

c.close()
