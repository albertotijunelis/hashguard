"""Sync dataset_features labels with current samples verdicts.

Fixes stale label_is_malicious and label_verdict in dataset_features
that were captured before the db_repair changed verdicts.
"""
import os, sqlite3

DB = os.path.join(os.environ.get("APPDATA", ""), "HashGuard", "hashguard.db")
conn = sqlite3.connect(DB)
conn.row_factory = sqlite3.Row

# Count mismatches before
before = conn.execute(
    "SELECT COUNT(*) FROM dataset_features df "
    "JOIN samples s ON df.sample_id = s.id "
    "WHERE df.label_verdict != s.verdict "
    "OR df.label_is_malicious != s.is_malicious"
).fetchone()[0]
print(f"Mismatched labels before sync: {before}")

# Sync label_verdict from samples.verdict
conn.execute(
    "UPDATE dataset_features SET label_verdict = ("
    "  SELECT s.verdict FROM samples s WHERE s.id = dataset_features.sample_id"
    ") WHERE EXISTS ("
    "  SELECT 1 FROM samples s WHERE s.id = dataset_features.sample_id "
    "  AND s.verdict != dataset_features.label_verdict"
    ")"
)
v_updated = conn.total_changes

# Sync label_is_malicious from samples.is_malicious
conn.execute(
    "UPDATE dataset_features SET label_is_malicious = ("
    "  SELECT s.is_malicious FROM samples s WHERE s.id = dataset_features.sample_id"
    ") WHERE EXISTS ("
    "  SELECT 1 FROM samples s WHERE s.id = dataset_features.sample_id "
    "  AND s.is_malicious != dataset_features.label_is_malicious"
    ")"
)

# Sync label_family
conn.execute(
    "UPDATE dataset_features SET label_family = ("
    "  SELECT COALESCE(s.family, '') FROM samples s WHERE s.id = dataset_features.sample_id"
    ") WHERE EXISTS ("
    "  SELECT 1 FROM samples s WHERE s.id = dataset_features.sample_id "
    "  AND COALESCE(s.family, '') != COALESCE(dataset_features.label_family, '')"
    ")"
)

conn.commit()

# Verify
after = conn.execute(
    "SELECT COUNT(*) FROM dataset_features df "
    "JOIN samples s ON df.sample_id = s.id "
    "WHERE df.label_verdict != s.verdict "
    "OR df.label_is_malicious != s.is_malicious"
).fetchone()[0]

print(f"Mismatched labels after sync: {after}")

# Show new distribution
print("\nDataset label distribution (post-sync):")
for r in conn.execute("SELECT label_verdict, COUNT(*) as cnt FROM dataset_features GROUP BY label_verdict ORDER BY cnt DESC").fetchall():
    print(f"  {r['label_verdict']}: {r['cnt']}")

conn.close()
