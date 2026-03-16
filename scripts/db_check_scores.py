"""Check score=20 and score=40 legitimacy."""
import os, sqlite3, re
DB = os.path.join(os.environ.get("APPDATA", ""), "HashGuard", "hashguard.db")
c = sqlite3.connect(DB)
c.row_factory = sqlite3.Row

SHA_RE = re.compile(r"^[0-9a-fA-F]{64}")

# Score=20 breakdown
rows_20 = c.execute("SELECT filename FROM samples WHERE risk_score = 20").fetchall()
batch_20 = sum(1 for r in rows_20 if SHA_RE.match(r["filename"] or ""))
genuine_20 = len(rows_20) - batch_20
print(f"Score=20: total={len(rows_20)}, batch-ingested={batch_20}, genuine={genuine_20}")

# Score=40 breakdown
rows_40 = c.execute("SELECT filename FROM samples WHERE risk_score = 40").fetchall()
batch_40 = sum(1 for r in rows_40 if SHA_RE.match(r["filename"] or ""))
genuine_40 = len(rows_40) - batch_40
print(f"Score=40: total={len(rows_40)}, batch-ingested={batch_40}, genuine={genuine_40}")

# The 709 db-repaired samples — what scores do they really have?
# These were set to 20 by db_repair. How many had legitimate analysis giving 20?
import json
repaired_with_factors = 0
repaired_bazaar_only = 0
for r in c.execute(
    "SELECT full_result FROM samples WHERE risk_score = 20 AND full_result IS NOT NULL"
).fetchall():
    try:
        d = json.loads(r["full_result"])
        rs = d.get("risk_score", {})
        if isinstance(rs, dict):
            factors = rs.get("factors", [])
            if len(factors) == 1 and factors[0].get("name") == "MalwareBazaar sample":
                repaired_bazaar_only += 1
            elif factors:
                repaired_with_factors += 1
    except:
        pass

print(f"\nScore=20 factor analysis:")
print(f"  Genuine detection factors (YARA/capability): {repaired_with_factors}")
print(f"  Minimum score from MalwareBazaar repair: {repaired_bazaar_only}")
print(f"  (total with factors: {repaired_with_factors + repaired_bazaar_only})")

c.close()
