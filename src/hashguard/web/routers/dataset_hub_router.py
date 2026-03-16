"""
HuggingFace Hub and Kaggle dataset publishing endpoints.

Allows publishing versioned dataset snapshots to:
- HuggingFace Datasets Hub
- Kaggle Datasets

Environment variables:
- HF_TOKEN: HuggingFace API token (write access)
- KAGGLE_USERNAME: Kaggle username
- KAGGLE_KEY: Kaggle API key
"""

import logging
import os
import tempfile
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse

from hashguard.web.auth import get_current_user

logger = logging.getLogger("hashguard.dataset_hub")

router = APIRouter(prefix="/api/dataset/hub", tags=["Dataset Hub"])

_auth = Depends(get_current_user())


@router.get("/status")
async def hub_status(user: dict = _auth):
    """Check which hubs are configured."""
    return JSONResponse(content={
        "huggingface": bool(os.environ.get("HF_TOKEN")),
        "kaggle": bool(os.environ.get("KAGGLE_USERNAME") and os.environ.get("KAGGLE_KEY")),
    })


@router.post("/huggingface/publish")
async def publish_to_huggingface(
    version: str = Query(..., pattern=r"^\d+\.\d+\.\d+$"),
    repo_id: str = Query("albertotijunelis/hashguard-malware-dataset"),
    private: bool = Query(False),
    user: dict = _auth,
):
    """Publish a dataset version to HuggingFace Hub."""
    hf_token = os.environ.get("HF_TOKEN")
    if not hf_token:
        raise HTTPException(status_code=400, detail="HF_TOKEN environment variable not set")

    from hashguard.database import get_dataset_version_path, list_dataset_versions
    path = get_dataset_version_path(version)
    if not path:
        raise HTTPException(status_code=404, detail=f"Version {version} not found locally")

    try:
        from huggingface_hub import HfApi

        api = HfApi(token=hf_token)

        # Create repo if needed
        api.create_repo(repo_id=repo_id, repo_type="dataset", private=private, exist_ok=True)

        # Upload the dataset file
        ext = path.rsplit(".", 1)[-1]
        filename = f"hashguard_dataset_v{version}.{ext}"
        api.upload_file(
            path_or_fileobj=path,
            path_in_repo=f"data/{filename}",
            repo_id=repo_id,
            repo_type="dataset",
            commit_message=f"HashGuard dataset v{version}",
        )

        # Create/update README with dataset card
        versions = list_dataset_versions()
        ver_info = next((v for v in versions if v["version"] == version), {})
        readme = _build_hf_readme(repo_id, ver_info, versions)
        api.upload_file(
            path_or_fileobj=readme.encode("utf-8"),
            path_in_repo="README.md",
            repo_id=repo_id,
            repo_type="dataset",
            commit_message=f"Update dataset card for v{version}",
        )

        return JSONResponse(content={
            "status": "published",
            "hub": "huggingface",
            "repo_id": repo_id,
            "version": version,
            "url": f"https://huggingface.co/datasets/{repo_id}",
        })
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"HuggingFace publish error: {e}")
        raise HTTPException(status_code=500, detail=f"HuggingFace publish failed: {str(e)}")


@router.post("/kaggle/publish")
async def publish_to_kaggle(
    version: str = Query(..., pattern=r"^\d+\.\d+\.\d+$"),
    slug: str = Query("hashguard-malware-dataset"),
    title: str = Query("HashGuard Open Malware Dataset"),
    user: dict = _auth,
):
    """Publish a dataset version to Kaggle Datasets."""
    kaggle_user = os.environ.get("KAGGLE_USERNAME")
    kaggle_key = os.environ.get("KAGGLE_KEY")
    if not kaggle_user or not kaggle_key:
        raise HTTPException(status_code=400, detail="KAGGLE_USERNAME and KAGGLE_KEY not set")

    from hashguard.database import get_dataset_version_path
    path = get_dataset_version_path(version)
    if not path:
        raise HTTPException(status_code=404, detail=f"Version {version} not found locally")

    # Validate source path: must exist and be within the dataset directory
    from pathlib import Path
    resolved_path = Path(path).resolve()
    app_data = os.environ.get("APPDATA") or os.path.expanduser("~")
    dataset_base_dir = Path(os.path.join(app_data, "HashGuard", "datasets")).resolve()
    if not resolved_path.is_relative_to(dataset_base_dir):
        raise HTTPException(status_code=400, detail="Invalid dataset path")
    real_path = str(resolved_path)

    try:
        import json
        import re as _re
        # Kaggle API uses a temp dir with dataset-metadata.json
        with tempfile.TemporaryDirectory() as tmpdir:
            # Copy dataset file (sanitize version to prevent path traversal)
            ext = real_path.rsplit(".", 1)[-1]
            safe_version = _re.sub(r'[^a-zA-Z0-9._-]', '', str(version))
            safe_ext = _re.sub(r'[^a-zA-Z0-9]', '', ext)
            if not safe_version or not safe_ext:
                raise HTTPException(status_code=400, detail="Invalid version")
            import shutil
            dest_name = f"hashguard_dataset_v{safe_version}.{safe_ext}"
            dest = os.path.join(tmpdir, dest_name)
            # Verify path stays within tmpdir
            if not os.path.realpath(dest).startswith(os.path.realpath(tmpdir)):
                raise HTTPException(status_code=400, detail="Invalid version")
            shutil.copy2(real_path, dest)

            # Create metadata
            metadata = {
                "title": title,
                "id": f"{kaggle_user}/{slug}",
                "licenses": [{"name": "other", "nameNullable": "other"}],
                "keywords": ["malware", "cybersecurity", "threat-intelligence", "pe-analysis"],
                "resources": [
                    {
                        "path": f"hashguard_dataset_v{version}.{ext}",
                        "description": f"HashGuard malware analysis dataset v{version}",
                    }
                ],
            }
            meta_path = os.path.join(tmpdir, "dataset-metadata.json")
            with open(meta_path, "w") as f:
                json.dump(metadata, f, indent=2)

            # Use kaggle API
            os.environ["KAGGLE_CONFIG_DIR"] = tmpdir
            # Write kaggle.json credentials
            kaggle_cred = {"username": kaggle_user, "key": kaggle_key}
            with open(os.path.join(tmpdir, "kaggle.json"), "w") as f:
                json.dump(kaggle_cred, f)

            from kaggle.api.kaggle_api_extended import KaggleApi
            kapi = KaggleApi()
            kapi.authenticate()

            try:
                kapi.dataset_create_version(tmpdir, f"v{version}", dir_mode="zip")
                action = "version_created"
            except Exception:
                kapi.dataset_create_new(tmpdir, dir_mode="zip")
                action = "created"

        return JSONResponse(content={
            "status": "published",
            "hub": "kaggle",
            "action": action,
            "slug": f"{kaggle_user}/{slug}",
            "version": version,
            "url": f"https://www.kaggle.com/datasets/{kaggle_user}/{slug}",
        })
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Kaggle publish error: {e}")
        raise HTTPException(status_code=500, detail=f"Kaggle publish failed: {str(e)}")


def _build_hf_readme(repo_id: str, ver_info: dict, all_versions: list) -> str:
    """Build a HuggingFace dataset card README."""
    sample_count = ver_info.get("sample_count", 0)
    malicious = ver_info.get("malicious_count", 0)
    benign = ver_info.get("benign_count", 0)
    features = ver_info.get("feature_count", 0)

    versions_table = "\n".join(
        f"| {v['version']} | {v['sample_count']:,} | {v['format']} | {v.get('created_at', 'N/A')[:10]} |"
        for v in all_versions
    )

    return f"""---
license: other
task_categories:
  - tabular-classification
tags:
  - malware
  - cybersecurity
  - threat-intelligence
  - pe-analysis
  - security
size_categories:
  - 10K<n<100K
---

# HashGuard Open Malware Dataset

A comprehensive, labeled malware analysis dataset generated by [HashGuard](https://github.com/albertotijunelis/hashguard) — an open-source malware research platform.

## Dataset Description

This dataset contains **{sample_count:,}** analyzed file samples with **{features}** extracted features per sample, including:

- **Byte-level statistics**: entropy, mean, standard deviation, zero/printable/high ratios
- **PE analysis**: section count, entropy, imports, suspicious APIs, packing detection
- **String analysis**: URLs, IPs, domains, emails, crypto wallets, PowerShell commands
- **YARA rules**: match count, severity scores, categories
- **Threat intelligence**: multi-source flagging, tags, family attribution
- **Capability detection**: ransomware, reverse shell, credential stealing, persistence, evasion
- **Risk scoring**: composite score, factor breakdown

### Labels

| Label | Description |
|-------|-------------|
| `label_verdict` | Classification: malicious, suspicious, clean, unknown |
| `label_is_malicious` | Binary: 1 = malicious, 0 = not |
| `label_family` | Malware family name (when identified) |
| `label_family_confidence` | Family attribution confidence (0.0 - 1.0) |
| `label_source` | Ground truth source (e.g., MalwareBazaar) |

### Statistics

- **Total samples**: {sample_count:,}
- **Malicious**: {malicious:,}
- **Clean/Benign**: {benign:,}
- **Features per sample**: {features}

## Version History

| Version | Samples | Format | Date |
|---------|---------|--------|------|
{versions_table}

## Usage

```python
from datasets import load_dataset

ds = load_dataset("{repo_id}")
print(ds)
```

```python
import pyarrow.parquet as pq
import pandas as pd

df = pd.read_parquet("hf://datasets/{repo_id}/data/hashguard_dataset_v{ver_info.get('version', 'latest')}.parquet")
print(f"Samples: {{len(df)}}, Features: {{len(df.columns)}}")
```

## License

This dataset is provided under the [Elastic License 2.0](https://www.elastic.co/licensing/elastic-license).

## Citation

```bibtex
@misc{{hashguard_dataset,
  title={{HashGuard Open Malware Dataset}},
  author={{Alberto Tijunelis Neto}},
  year={{2025}},
  url={{https://github.com/albertotijunelis/hashguard}}
}}
```
"""
