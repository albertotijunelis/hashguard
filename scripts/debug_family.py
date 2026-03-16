"""Debug dataset stats family issue."""
import os
import threading

os.environ["DATABASE_URL"] = "sqlite:///test_debug.db"

from hashguard import database, models
models.reset_engine()
database._local = threading.local()
database._DATASET_SCHEMA_APPLIED = False
database.init_db()

result = {
    "path": "/tmp/test.exe",
    "hashes": {"sha256": "a" * 64, "sha1": "", "md5": ""},
    "risk_score": {"score": 95, "verdict": "malicious"},
    "malicious": True,
    "file_size": 100,
    "family_detection": {"family": "Emotet", "confidence": 0.9},
}
sid = database.store_sample(result)
print(f"stored sample {sid}")

conn = database.get_connection()
row = conn.execute("SELECT family FROM samples WHERE id = ?", (sid,)).fetchone()
print(f"family in DB: {repr(dict(row)['family'])}")

database.store_dataset_features(sid, "a" * 64, {
    "label_is_malicious": 1, "label_verdict": "malicious", "label_family": "Emotet"
})

stats = database.get_dataset_stats()
print(f"top_families: {stats['top_families']}")
print(f"total: {stats['total']}, malicious: {stats['malicious']}")

os.remove("test_debug.db")
