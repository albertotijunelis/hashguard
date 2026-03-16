"""Re-score all samples in the database using stored analysis data.

Reads each sample's full_result JSON, extracts all available signals,
and re-computes the risk score using the current compute_risk() logic.
Updates both the risk_score column and the risk_score dict in full_result.
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from hashguard.database import get_connection, init_db
from hashguard.risk_scorer import compute_risk
from hashguard.scanner import SignatureDatabase
from hashguard.config import get_default_config


def rescore_all():
    init_db()
    conn = get_connection()
    config = get_default_config()
    sig_db = SignatureDatabase(config)

    total = conn.execute("SELECT COUNT(*) FROM samples").fetchone()[0]
    print(f"Total samples to re-score: {total}")

    # Fetch all samples
    rows = conn.execute(
        "SELECT id, sha256, full_result FROM samples WHERE full_result IS NOT NULL"
    ).fetchall()

    updated = 0
    errors = 0
    start = time.time()
    batch_size = 500
    batch_updates = []

    for i, row in enumerate(rows):
        sample_id = row["id"]
        sha256 = row["sha256"]

        try:
            fr = json.loads(row["full_result"])

            # Determine if this hash matches the local signature DB
            hashes = fr.get("hashes", {})
            signature_match = False
            signature_name = ""
            for h_val in hashes.values():
                if h_val and sig_db.contains(h_val):
                    signature_match = True
                    signature_name = sig_db.get(h_val) or ""
                    break

            # Extract all available analysis signals
            pe_info = fr.get("pe_info")
            yara_matches = fr.get("yara_matches")
            threat_intel = fr.get("threat_intel")
            strings_info = fr.get("strings_info")
            capabilities = fr.get("capabilities")
            ml_result = fr.get("ml_classification")

            # Re-compute risk score
            risk = compute_risk(
                signature_match=signature_match,
                signature_name=signature_name,
                pe_info=pe_info,
                yara_matches=yara_matches,
                threat_intel=threat_intel,
                strings_info=strings_info,
                capabilities=capabilities,
                ml_result=ml_result,
            )

            new_score_dict = risk.to_dict()

            # Update is_malicious based on new verdict
            is_malicious = 1 if risk.verdict == "malicious" else 0

            # Update risk_score inside full_result JSON
            fr["risk_score"] = new_score_dict
            fr["malicious"] = bool(is_malicious)

            # Rebuild description from factors
            if risk.factors:
                descriptions = []
                for f in risk.factors:
                    descriptions.append(f.name)
                desc = "; ".join(descriptions[:5])
                if len(descriptions) > 5:
                    desc += f" (+{len(descriptions) - 5} more)"
            else:
                desc = "Clean"

            fr["description"] = desc

            batch_updates.append((
                risk.score,
                risk.verdict,
                is_malicious,
                desc,
                json.dumps(fr, default=str),
                sample_id,
            ))
            updated += 1

        except Exception as e:
            errors += 1
            if errors <= 5:
                print(f"  Error on sample {sample_id}: {e}")

        # Batch commit
        if len(batch_updates) >= batch_size:
            conn.executemany(
                """UPDATE samples SET risk_score=?, verdict=?, is_malicious=?,
                   description=?, full_result=? WHERE id=?""",
                batch_updates,
            )
            conn.commit()
            batch_updates = []
            elapsed = time.time() - start
            pct = (i + 1) / len(rows) * 100
            rate = (i + 1) / elapsed if elapsed > 0 else 0
            print(f"  [{pct:5.1f}%] {i+1}/{len(rows)} samples | {rate:.0f} samples/s")

    # Final batch
    if batch_updates:
        conn.executemany(
            """UPDATE samples SET risk_score=?, verdict=?, is_malicious=?,
               description=?, full_result=? WHERE id=?""",
            batch_updates,
        )
        conn.commit()

    elapsed = time.time() - start
    print(f"\nDone! Re-scored {updated} samples in {elapsed:.1f}s ({errors} errors)")

    # Verify
    print("\n=== Post-rescore Distribution ===")
    dist = conn.execute(
        "SELECT risk_score, COUNT(*) FROM samples GROUP BY risk_score ORDER BY risk_score"
    ).fetchall()
    for r in dist:
        print(f"  Score {r[0]:3d}: {r[1]:5d}")

    # Verify no more mismatches
    print("\n=== Mismatch Check ===")
    rows2 = conn.execute("SELECT id, risk_score, full_result FROM samples WHERE full_result IS NOT NULL").fetchall()
    mismatches = 0
    for r in rows2:
        fr2 = json.loads(r[2]) if r[2] else {}
        rs2 = fr2.get("risk_score", {})
        db_score = r[1]
        json_score = rs2.get("score", -1)
        factor_sum = sum(f.get("points", 0) for f in rs2.get("factors", []))
        clamped_sum = max(0, min(100, factor_sum))
        if db_score != json_score or db_score != clamped_sum:
            mismatches += 1
    print(f"  Remaining mismatches: {mismatches}")


if __name__ == "__main__":
    rescore_all()
