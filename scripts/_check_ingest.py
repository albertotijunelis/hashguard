"""Check ingest status."""
import requests
r = requests.get("http://127.0.0.1:8000/api/ingest/status", timeout=10)
d = r.json()
for k in ["status", "source", "downloaded", "analysed", "skipped_existing", "failed", "current_tag", "current_sha256"]:
    v = d.get(k, "")
    if k == "current_sha256" and v:
        v = v[:16] + "..."
    print(f"  {k}: {v}")
errs = d.get("errors", [])
if errs:
    print(f"  Last errors: {errs[-3:]}")
