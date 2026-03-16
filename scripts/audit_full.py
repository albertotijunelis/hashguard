"""Full system audit for HashGuard."""
import sqlite3
import os

DB = os.path.join(os.environ.get("APPDATA", ""), "HashGuard", "hashguard.db")
conn = sqlite3.connect(DB, timeout=30)
conn.row_factory = sqlite3.Row
conn.execute("PRAGMA journal_mode=WAL")

print("=" * 60)
print("HASHGUARD DATABASE AUDIT")
print("=" * 60)

# 1. Tables
tables = [r[0] for r in conn.execute(
    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
).fetchall()]
print(f"\nTables ({len(tables)}): {tables}")

# 2. Sample counts
total = conn.execute("SELECT COUNT(*) FROM samples").fetchone()[0]
print(f"\nTotal samples: {total}")

# 3. Verdict distribution
verdicts = conn.execute(
    "SELECT verdict, COUNT(*) as cnt FROM samples GROUP BY verdict ORDER BY cnt DESC"
).fetchall()
print("\nVerdict distribution (samples):")
for v in verdicts:
    print(f"  {v['verdict']}: {v['cnt']}")

# 4. Score distribution
scores = conn.execute("""
    SELECT 
        CASE 
            WHEN risk_score BETWEEN 0 AND 15 THEN 'clean(0-15)'
            WHEN risk_score BETWEEN 16 AND 35 THEN 'suspicious(16-35)'
            WHEN risk_score BETWEEN 36 AND 100 THEN 'malicious(36-100)'
            ELSE 'other'
        END as range_label, 
        COUNT(*) as cnt 
    FROM samples 
    GROUP BY range_label 
    ORDER BY range_label
""").fetchall()
print("\nScore ranges:")
for s in scores:
    print(f"  {s['range_label']}: {s['cnt']}")

# 5. Score vs verdict consistency
mismatches = conn.execute("""
    SELECT COUNT(*) FROM samples 
    WHERE (risk_score <= 15 AND verdict != 'clean')
       OR (risk_score BETWEEN 16 AND 35 AND verdict != 'suspicious')
       OR (risk_score >= 36 AND verdict != 'malicious')
""").fetchone()[0]
print(f"\nScore/verdict mismatches: {mismatches}")

if mismatches > 0:
    examples = conn.execute("""
        SELECT id, risk_score, verdict FROM samples 
        WHERE (risk_score <= 15 AND verdict != 'clean')
           OR (risk_score BETWEEN 16 AND 35 AND verdict != 'suspicious')
           OR (risk_score >= 36 AND verdict != 'malicious')
        LIMIT 10
    """).fetchall()
    for e in examples:
        print(f"  id={e['id']} score={e['risk_score']} verdict={e['verdict']}")

# 6. Dataset features
try:
    ds_total = conn.execute("SELECT COUNT(*) FROM dataset_features").fetchone()[0]
    print(f"\nDataset features rows: {ds_total}")
    
    ds_verdicts = conn.execute("""
        SELECT s.verdict, COUNT(*) as cnt 
        FROM dataset_features df 
        JOIN samples s ON df.sample_id = s.id 
        GROUP BY s.verdict
    """).fetchall()
    print("Dataset verdict distribution (JOIN samples):")
    for v in ds_verdicts:
        print(f"  {v['verdict']}: {v['cnt']}")
    
    label_mismatches = conn.execute("""
        SELECT COUNT(*) FROM dataset_features df
        JOIN samples s ON df.sample_id = s.id
        WHERE df.label_verdict != s.verdict
    """).fetchone()[0]
    print(f"Dataset label_verdict vs sample verdict mismatches: {label_mismatches}")

    score_mismatches = conn.execute("""
        SELECT COUNT(*) FROM dataset_features df
        JOIN samples s ON df.sample_id = s.id
        WHERE df.label_is_malicious != s.is_malicious
    """).fetchone()[0]
    print(f"Dataset label_is_malicious vs sample is_malicious mismatches: {score_mismatches}")
except Exception as e:
    print(f"Dataset error: {e}")

# 7. Users
try:
    users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    roles = conn.execute(
        "SELECT role, COUNT(*) as cnt FROM users GROUP BY role"
    ).fetchall()
    print(f"\nUsers: {users}")
    for r in roles:
        print(f"  {r['role']}: {r['cnt']}")
except Exception:
    print("\nUsers table: not found")

# 8. Families
families = conn.execute("""
    SELECT family, COUNT(*) as cnt FROM samples 
    WHERE family != '' AND family IS NOT NULL 
    GROUP BY family ORDER BY cnt DESC LIMIT 15
""").fetchall()
print(f"\nTop families ({len(families)}):")
for f in families:
    print(f"  {f['family']}: {f['cnt']}")

# 9. IOCs and behaviors
ioc_count = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
beh_count = conn.execute("SELECT COUNT(*) FROM behaviors").fetchone()[0]
print(f"\nIOCs: {ioc_count}")
print(f"Behaviors: {beh_count}")

# 10. IOC type breakdown
ioc_types = conn.execute(
    "SELECT ioc_type, COUNT(*) as cnt FROM iocs GROUP BY ioc_type ORDER BY cnt DESC"
).fetchall()
print("IOC types:")
for t in ioc_types:
    print(f"  {t['ioc_type']}: {t['cnt']}")

# 11. Orphaned data
orphans = conn.execute(
    "SELECT COUNT(*) FROM dataset_features df LEFT JOIN samples s ON df.sample_id = s.id WHERE s.id IS NULL"
).fetchone()[0]
print(f"\nOrphaned dataset rows (no sample): {orphans}")

no_features = conn.execute(
    "SELECT COUNT(*) FROM samples s LEFT JOIN dataset_features df ON s.id = df.sample_id WHERE df.id IS NULL"
).fetchone()[0]
print(f"Samples without dataset features: {no_features}")

# 12. Clusters
try:
    clusters = conn.execute("SELECT COUNT(*) FROM clusters").fetchone()[0]
    print(f"Clusters: {clusters}")
except Exception:
    pass

# 13. DB file size
db_size = os.path.getsize(DB)
print(f"\nDatabase file size: {db_size / (1024*1024):.1f} MB")

# 14. Subcriptions/billing
try:
    subs = conn.execute("SELECT plan, COUNT(*) as cnt FROM subscriptions GROUP BY plan").fetchall()
    print("\nSubscriptions:")
    for s in subs:
        print(f"  {s['plan']}: {s['cnt']}")
except Exception:
    print("\nSubscriptions table: not populated or missing")

# 15. API keys
try:
    keys = conn.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0]
    print(f"API keys: {keys}")
except Exception:
    pass

# 16. Webhooks
try:
    wh = conn.execute("SELECT COUNT(*) FROM webhooks").fetchone()[0]
    print(f"Webhooks: {wh}")
except Exception:
    pass

conn.close()
print("\n" + "=" * 60)
print("AUDIT COMPLETE")
print("=" * 60)
