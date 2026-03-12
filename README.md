<p align="center">
  <img src="https://raw.githubusercontent.com/albertotijunelis/hashguard/main/assets/branding/icon%2Btexto.png" alt="HashGuard" height="160">
</p>

<p align="center">
  <strong>Malware Research & Threat Intelligence Platform</strong>
</p>

<p align="center">
  <a href="https://github.com/albertotijunelis/hashguard/releases/latest"><img src="https://img.shields.io/badge/%E2%AC%87%EF%B8%8F_Download-v1.1.2-FF6600?style=for-the-badge" alt="Download"></a>
  <a href="https://pypi.org/project/hashguard/"><img src="https://img.shields.io/badge/%F0%9F%93%A6_PyPI-hashguard-FF6600?style=for-the-badge" alt="PyPI"></a>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Elastic--2.0-003366.svg" alt="Elastic License 2.0"></a>
  <a href="https://pypi.org/project/hashguard/"><img src="https://img.shields.io/pypi/v/hashguard?color=FF6600&label=pypi" alt="PyPI version"></a>
  <a href="https://github.com/albertotijunelis/hashguard/actions/workflows/ci.yml"><img src="https://github.com/albertotijunelis/hashguard/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://codecov.io/gh/albertotijunelis/hashguard"><img src="https://codecov.io/gh/albertotijunelis/hashguard/branch/main/graph/badge.svg" alt="Coverage"></a>
  <img src="https://img.shields.io/badge/python-3.9%2B-FF6600.svg" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-informational" alt="Platform">
</p>

---

HashGuard is a professional malware research platform that combines static analysis, ML classification, behavioral detection, script deobfuscation, sandbox monitoring, 167 YARA rules, multi-source threat intelligence, fuzzy hashing, IOC graphing, and a web dashboard — accessible via CLI, web browser, or Python API.

## What's new in v1.1.2

- **STIX 2.1 Export** — one-click export of analysis results as a STIX 2.1 Bundle; compatible with MISP, OpenCTI, TheHive, Splunk SOAR
- **CI/CD Pipeline** — GitHub Actions: test matrix (3.9–3.13 × Ubuntu/Windows), CodeQL security scanning, automated release builds
- **ML Training Pipeline** — train your own models (Random Forest, Gradient Boosting, Ensemble) on 63 rich features extracted from analysis results; real-time classification on every upload
- **Batch Ingest** — bulk sample ingestion from MalwareBazaar (abuse.ch Auth-Key + selectors) and local directories; automatic feature extraction and dataset building
- **Dual ML Classification** — built-in 5-class classifier (22 PE features) + custom trained model (63 features) with class probabilities and model management
- **Web Dashboard** — FastAPI + Alpine.js dark-themed SPA with file upload, IOC graphs, timelines, cluster visualization, ML training controls, and model management
- **ML Classification** — Gradient Boosted Trees + Random Forest ensemble (benign / trojan / ransomware / miner / stealer)
- **Script Deobfuscation** — PowerShell, VBScript, JavaScript, Batch, HTA deobfuscation via pattern matching
- **Behavioral Sandbox** — Windows Sandbox integration with ETW-based process monitoring and system snapshot diffing
- **Unpacker** — UPX auto-unpacking, packer/protector detection, Unicorn CPU emulation (experimental)
- **158 YARA Rules** — expanded from 28 to 158 rules across 14 categories (C2, evasion, persistence, exploits, stealers, ransomware, rootkits, documents, miners, destructive...)
- **Threat Intelligence** — added ThreatFox + Shodan InternetDB (now 7 sources total)
- **IOC Enrichment** — passive DNS, IP geolocation, WHOIS, domain age analysis
- **IOC Graphs** — visual relationship mapping (file → domain → IP → family) with vis.js
- **Malware Clustering** — DBSCAN on ML feature vectors + fuzzy hash similarity + imphash grouping
- **Family Detection** — YARA metadata, threat intel, imphash patterns, string signatures
- **Timeline Analysis** — delivery → execution → persistence → C2 → action phase sequencing
- **SQLite Database** — persistent storage for all analysis results, IOCs, behaviors, clusters, and ML datasets

## Features

### Analysis Engine

| Category | Feature | Details |
|----------|---------|---------|
| **Hashing** | Cryptographic | SHA-256, SHA-1, MD5 in a single streaming pass |
| **Fuzzy Hashing** | Similarity | ssdeep (CTPH) + TLSH for variant detection |
| **Signatures** | Known-bad | 21 malware hash signatures in `signatures.json` |
| **Risk Score** | Composite | 0–100 score → clean / suspicious / malicious verdict |
| **PE Analysis** | Deep inspection | Sections, imports, entropy, packer detection, TLS callbacks, anti-debug/anti-VM, rich headers, overlay analysis |
| **YARA** | Rule engine | **158 rules** across 14 categories, auto-loads custom `.yar` files |
| **Capabilities** | CAPA-inspired | Ransomware, keylogger, reverse shell, credential theft, persistence, evasion technique detection |
| **ML** | Classification | Built-in 5-class ensemble (GBT + RF) + custom trained models (RF, GBT, Ensemble) |
| **ML Training** | Pipeline | 63-feature extraction, dataset management, model training, real-time prediction |
| **Batch Ingest** | Dataset | MalwareBazaar bulk ingestion (Auth-Key + selectors) and local directory scanning |
| **Deobfuscation** | Script analysis | PowerShell, VBScript, JavaScript, Batch, HTA pattern-based deobfuscation |
| **Unpacker** | Packing | UPX auto-unpack, MPRESS/Themida/VMProtect detection, Unicorn emulation |
| **Sandbox** | Behavioral | Windows Sandbox + ETW monitoring, system snapshot diffing |
| **IOC Extraction** | Strings | URLs, IPs, domains, emails, PowerShell commands, crypto wallets, registry keys |
| **Family Detection** | Attribution | YARA metadata + threat intel + imphash + string signature matching |
| **Clustering** | Grouping | DBSCAN on ML features, fuzzy hash similarity, shared IOC analysis |
| **STIX Export** | Interop | STIX 2.1 Bundle (File, Malware, Indicator, AttackPattern, SCOs, Notes) |
| **Timeline** | Sequencing | Delivery → execution → persistence → C2 → action phase mapping |

### Threat Intelligence (7 sources)

| Source | Type | Key Required |
|--------|------|:---:|
| MalwareBazaar | Hash reputation | No |
| URLhaus | Payload database | No |
| ThreatFox | IOC database | No |
| AlienVault OTX | Hash reputation | No |
| Shodan InternetDB | IP intelligence | No |
| AbuseIPDB | IP reputation | Yes (free tier) |
| VirusTotal | Multi-engine scan | Yes (opt-in `--vt`) |

### Interfaces

| Interface | Description |
|-----------|-------------|
| **CLI** | Single-file, URL, and batch modes with JSON / CSV / HTML reports |
| **Web Dashboard** | FastAPI SPA with file upload, IOC graphs, timelines, clustering, and search |
| **REST API** | Full programmatic access at `http://127.0.0.1:8000/api/docs` |
| **ML API** | Train models, manage datasets, predict samples via REST endpoints |
| **Python API** | `from hashguard import analyze` — embeddable in your own scripts |

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                           HashGuard v1.1.2                           │
├───────────────┬──────────────┬───────────┬───────────────────────────┤
│     CLI       │ Web Dashboard│  REST API │       Python API          │
│   cli.py      │ web/api.py   │  /api/*   │ from hashguard import ...│
├───────────────┴──────────────┴───────────┴───────────────────────────┤
│                         scanner.py                                    │
│      compute_hashes() → analyze() → analyze_url()                    │
├──────────┬──────────┬──────────┬──────────┬──────────┬───────────────┤
│ PE       │ YARA     │ Threat   │ ML       │ Sandbox  │ Deobfuscator │
│ Analyzer │ Scanner  │ Intel    │ Classify │ Monitor  │ Unpacker     │
│ advanced │ 167 rules│ 7 sources│ GBT + RF │ ETW/Snap │ UPX/Unicorn  │
│ _pe.py   │ 15 files │ + cache  │ 5 class  │ diff     │              │
├──────────┼──────────┼──────────┼──────────┼──────────┼───────────────┤
│ ML Train │ Feature  │ Batch    │ Family   │ Cluster  │ IOC Enricher │
│ Pipeline │ Extract  │ Ingest   │ Detector │ Engine   │ DNS/Geo/WHOIS│
│ RF/GBT/E │ 63 feats │ abuse.ch │ fuzzy    │ DBSCAN   │              │
├──────────┼──────────┼──────────┼──────────┼──────────┼───────────────┤
│ IOC      │ Timeline │ Risk     │ STIX     │          │              │
│ Graph    │ Builder  │ Scorer   │ Export   │          │              │
│ vis.js   │ phases   │ 0-100    │ 2.1      │          │              │
├──────────┴──────────┴──────────┴──────────┴──────────┴───────────────┤
│  database.py (SQLite)  │  reports.py (JSON/CSV/HTML)  │  config.py  │
└────────────────────────┴──────────────────────────────┴──────────────┘
```

## Quick start

### Install from PyPI

```bash
pip install hashguard
```

### Install from source

```bash
git clone https://github.com/albertotijunelis/hashguard.git
cd hashguard
pip install -e ".[full]"    # includes lief, tlsh, networkx
```

### CLI

```bash
hashguard file.exe                            # full analysis pipeline
hashguard file.exe --vt --json                # + VirusTotal (requires VT_API_KEY)
hashguard --url https://example.com/file.exe  # download & analyze
hashguard --batch ./samples -o report.html    # batch scan → HTML report
hashguard --web                               # launch web dashboard
```

### Web Dashboard

```bash
hashguard-web                                 # opens http://127.0.0.1:8000
```

The web dashboard features dark theme, file upload with drag-and-drop, real-time analysis progress, IOC relationship graphs (vis.js), behavior timelines, malware clustering visualization, sample search, and full analysis history.

### Python API

```python
from hashguard import analyze, analyze_url, compute_hashes, is_malware
from hashguard import analyze_pe, yara_scan, query_threat_intel

# Full analysis (hashes + PE + YARA + ML + capabilities + threat intel + risk)
result = analyze("file.exe")

print(result["hashes"]["sha256"])
print(result["risk_score"])          # {"score": 82, "verdict": "malicious", "factors": [...]}
print(result["yara_matches"])        # YARA rule hits
print(result["strings"])             # extracted URLs, IPs, domains, wallets
print(result["threat_intel"])        # MalwareBazaar + URLhaus + ThreatFox + OTX
print(result["ml_classification"])   # {"label": "trojan", "confidence": 0.87}
print(result["capabilities"])        # detected behaviors
print(result["family_detection"])    # {"family": "AgentTesla", "confidence": 0.9}

# Also query VirusTotal (requires VT_API_KEY env var)
result = analyze("file.exe", vt=True)

# Standalone PE analysis
pe_info = analyze_pe("file.exe")

# ML Training Pipeline
from hashguard.ml_trainer import start_training, predict_sample, list_models
from hashguard.batch_ingest import start_ingest

# Train a model on your dataset
training = start_training(mode="binary", algorithm="ensemble", test_size=0.2)

# Predict with trained model
prediction = predict_sample(features_dict)
# → {"predicted_class": "malicious", "confidence": 95.0, "probabilities": {...}}

# Bulk ingest from MalwareBazaar
start_ingest(source="recent", limit=100)
```

## YARA Rules

HashGuard ships with **158 rules** across **14 categories**. Custom `.yar` / `.yara` files placed in the `yara_rules/` directory are loaded automatically.

| File | Rules | Covers |
|------|:-----:|--------|
| `c2_frameworks.yar` | 15 | Cobalt Strike, Metasploit, Sliver, Brute Ratel, Mythic, Havoc, HTTP/DNS/IRC C2, Telegram/Discord C2, ICMP tunneling |
| `evasion.yar` | 17 | Anti-debug, anti-VM, anti-sandbox, AMSI bypass, ETW patching, process hollowing, direct syscalls, DLL unhooking, sleep obfuscation, APC injection |
| `persistence.yar` | 16 | Registry run keys, scheduled tasks, WMI events, services, COM hijacking, bootkit, AppInit DLLs, DLL search order, lateral movement (PsExec, DCSync, pass-the-hash) |
| `destructive.yar` | 15 | MBR/disk/file wipers, HermeticWiper, CaddyWiper, USB/network/email worms, RATs (njRAT, DarkComet, Quasar, Remcos) |
| `exploits.yar` | 13 | CVE-2017-11882, CVE-2021-44228 (Log4Shell), CVE-2021-34527 (PrintNightmare), Follina, EternalBlue, ZeroLogon, shellcode patterns |
| `stealers.yar` | 12 | Browser credentials, crypto wallets, Discord tokens, Telegram sessions, Steam, FTP, email, VPN, clipboard monitoring |
| `documents.yar` | 12 | OLE macros, DDE attacks, template injection, PDF exploits, RTF exploits, OneNote embedded files, ISO/IMG/LNK droppers |
| `trojans.yar` | 12 | Reverse shells, data exfiltration, downloaders, droppers, firewall/security disabling, UAC bypass, LSASS dumping |
| `ransomware.yar` | 11 | LockBit, Conti, BlackCat/ALPHV, Hive, REvil, WannaCry, Dharma, ransom notes, shadow copy deletion |
| `rootkits.yar` | 10 | Driver loading, SSDT/IDT hooking, process/file hiding, bootkit MBR/UEFI, vulnerable driver exploitation |
| `miners.yar` | 10 | XMRig, Stratum protocol, mining pools, Coinhive, hidden mining, crypto algorithm detection |
| `packers.yar` | 6 | UPX, MPRESS, ASPack, Themida/VMProtect, Enigma, PECompact |
| `default.yar` | 5 | PowerShell encoding, process injection, anti-debug, crypto usage, keylogger |
| `scripts.yar` | 4 | VBA macro droppers, batch payloads, JS droppers, HTA payloads |

## Configuration

| Variable | Description |
|---|---|
| `VT_API_KEY` | VirusTotal API key (enables VT lookups with `--vt` flag) |
| `ABUSE_CH_API_KEY` | abuse.ch Auth-Key for MalwareBazaar bulk ingest (free at bazaar.abuse.ch) |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key (free at abuseipdb.com) |
| `HASHGUARD_SIGNATURES` | Path to custom signatures database |

Settings can also be configured via the **Web Dashboard**, persisted to `%APPDATA%/HashGuard/config.json`.

## Comparison

| Feature | HashGuard | VirusTotal (web) | ClamAV |
|---------|:----------:|:----------------:|:------:|
| Offline analysis | **Yes** | No | Yes |
| Risk scoring | **Yes** | Partial | No |
| ML classification | **Yes** | No | No |
| ML training pipeline | **Yes** | No | No |
| Batch sample ingest | **Yes** | No | No |
| Script deobfuscation | **Yes** | No | No |
| Behavioral sandbox | **Yes** | No | No |
| IOC extraction + graphing | **Yes** | No | No |
| PE analysis (deep) | **Yes** | Partial | No |
| YARA rules (158) | **Yes** | No | Yes |
| STIX 2.1 export | **Yes** | No | No |
| Malware clustering | **Yes** | No | No |
| Family detection | **Yes** | **Yes** | Yes |
| Threat intel (7 sources) | **Yes** | **Yes** | No |
| Web dashboard | **Yes** | **Yes** | No |
| CLI + Web API | **Yes** | Web only | CLI only |
| SQLite persistence | **Yes** | N/A | No |
| CI/CD pipeline | **Yes** | N/A | No |
| Windows installer | **Yes** | N/A | Yes |
| License | **Elastic-2.0** | Proprietary | **GPL** |

## Building

```bash
cd scripts
py -3.12 -m PyInstaller hashguard-cli.spec    # CLI + Web executable
```

Releases are automated via GitHub Actions — push a `v*` tag and the workflow publishes executables, a portable ZIP, and a Windows installer.
Every push and PR runs the CI pipeline (pytest matrix, linting) and the security workflow (pip-audit + CodeQL).

## Project structure

```
src/hashguard/
  scanner.py             core analysis engine
  risk_scorer.py         composite 0–100 risk scoring
  string_extractor.py    automated IOC / string extraction
  pe_analyzer.py         PE executable inspection
  advanced_pe.py         extended PE analysis (TLS, anti-debug, rich headers)
  yara_scanner.py        YARA rules engine (158 rules, 14 categories)
  threat_intel.py        7-source threat intelligence with TTL cache
  ioc_enrichment.py      passive DNS, geolocation, WHOIS, domain age
  ioc_graph.py           IOC relationship graphs (vis.js)
  capability_detector.py CAPA-inspired behavioral detection
  family_detector.py     malware family identification
  fuzzy_hasher.py        ssdeep + TLSH fuzzy hashing
  ml_classifier.py       built-in ML ensemble classifier (GBT + RF, 5 classes)
  ml_trainer.py          ML training pipeline (RF, GBT, Ensemble) with model persistence
  feature_extractor.py   63-feature vector extraction for ML training and prediction
  batch_ingest.py        MalwareBazaar bulk ingestion and local directory scanning
  malware_cluster.py     DBSCAN clustering engine
  malware_timeline.py    attack phase timeline builder
  deobfuscator.py        script deobfuscation (PS, VBS, JS, BAT, HTA)
  unpacker.py            UPX unpacker + packer detection + Unicorn emulation
  sandbox.py             behavioral sandbox (Windows Sandbox + ETW)
  database.py            SQLite persistence layer
  stix_exporter.py       STIX 2.1 bundle export (Malware, Indicators, ATT&CK, IOC SCOs)
  cli.py                 command-line interface
  config.py              configuration management
  reports.py             JSON / CSV / HTML reports
  logger.py              logging utilities
  web/
    api.py               FastAPI web dashboard + REST API
    templates/            Alpine.js + Tailwind CSS SPA
  yara_rules/            14 YARA rule files (158 rules)
  data/                  signatures.json, pe_indicators.json
tests/                   721 pytest tests (78% coverage)
assets/branding/         logo and icon files
scripts/                 PyInstaller specs, NSIS installer, build tooling
.github/workflows/       CI (test + lint), Release (build + publish), Security (audit + CodeQL)
```

## License

Copyright (c) 2026 Alberto Tijunelis Neto. [Elastic License 2.0 (ELv2)](LICENSE)

