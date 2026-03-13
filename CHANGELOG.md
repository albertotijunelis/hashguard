# Changelog

## 1.1.3 — 2026-03-12

### ML Training & Classification
- Trained binary classification model (Random Forest, 12,728 samples, 63 features): 99.18% accuracy, F1 99.32%, ROC AUC 99.97%.
- Trained family classification model (Random Forest, 68 classes): 98.65% accuracy, F1 98.50%, ROC AUC 99.99%.
- Real-time classification active: every analyzed file gets an ML prediction injected into results.

### Dataset & Ingest
- Batch ingest of 12,728 samples (7,752 malicious from MalwareBazaar + 4,976 benign system files).
- Feature extractor now accepts `mb_metadata` for ground-truth labels from MalwareBazaar.
- Threat-intel features derived from MalwareBazaar metadata during ingest.
- Benign ingest uses `os.walk` recursion across SysWOW64 + Program Files directories.

### Security
- HMAC-SHA256 integrity verification on serialized ML models (save and load).
- `.gitignore` hardened: `*.db`, `*.sqlite*`, `*.joblib`, `*.pkl`, `*.hmac`, `models/` excluded from version control.
- Database and model files confirmed never pushed to GitHub.

### Web Dashboard
- IOC listing rewritten: expandable detail lists for 9 IOC categories (URLs, IPs, domains, emails, crypto wallets, PowerShell commands, suspicious paths, user agents, registry keys).
- Each IOC item has a copy-to-clipboard button with hover reveal.
- Color-coded IOC categories with count badges.

### Bug Fixes
- Fixed IOC graph not showing IOC nodes: `build_graph()` now handles flat `to_dict()` structure with fallback, and uses correct `ips` key instead of `ip_addresses`.
- Added benign source option to dashboard ingest dropdown.

### Testing & Quality
- 1,212 tests passing, 93% coverage (6,247 statements, 468 missed).
- Updated batch ingest test mocks from `_analyse_file` to `_analyse_file_batch`.
- Database schema migration with new indexes for `label_family`, `label_source`, `label_is_malicious`.

### Maintenance
- Version bump to 1.1.3 across all components.

---

## 1.1.2 — 2026-03-11

### Web Dashboard
- Batch ingest now runs candidate fetching in a background thread — the UI responds immediately instead of blocking for minutes on large requests.
- Added "Mixed (Multi-type)" ingest source to download samples across 20 file types (up to 10,000 candidates).
- Dynamic limit field adapts max value per source (100/1,000/10,000).
- Immediate visual feedback with spinner and "Fetching candidates..." message while background fetch runs.
- Fixed Start Ingest button alignment in the batch ingest form.

### Bug Fixes
- Replaced deprecated `datetime.utcnow()` and `datetime.utcfromtimestamp()` calls with timezone-aware alternatives (`ioc_enrichment.py`, `pe_analyzer.py`).

### Testing & Quality
- Updated batch ingest tests to match async background-thread architecture (5 tests fixed).
- 97% test coverage maintained (1,212 tests, 5,887 statements, 176 missed).

### Maintenance
- Version bump to 1.1.2 across all components.

---

## 1.1.1 — 2026-03-11

### Testing & Quality
- 97% test coverage (1212 tests, 5879 statements, 173 missed).
- New tests for capability detector, family detector, threat intel cache paths, IOC extraction edge cases, malware timeline, reports, database search, risk scorer, CLI, web API, batch ingest, and string extractor covering previously uncovered branches.
- Fixed dead-code paths in string extractor URL parsing identified during coverage analysis.

### Web Dashboard
- Updated YARA rule count to 167 (15 rule files).
- Corrected threat intelligence feed count to 7 sources (MalwareBazaar, URLhaus, ThreatFox, AlienVault OTX, Shodan InternetDB, AbuseIPDB, VirusTotal).
- Updated analysis engine count to 18.

### Maintenance
- Version bump to 1.1.1 across all components (pyproject.toml, __init__.py, web API, NSIS installer, manifest, CLI version info, README).

---

## 1.1.0 — 2026-03-10

### STIX 2.1 Export
- `stix_exporter.py` — converts full analysis results into a STIX 2.1 Bundle (File, Malware, Indicator, AttackPattern, URL, IPv4, Domain, Email, Note, Relationships).
- REST API endpoint `GET /api/export/stix/{sample_id}` — downloads STIX bundle JSON for any analyzed sample.
- "Export STIX" button on the web dashboard — one-click download alongside the existing JSON export.
- Maps YARA matches → Indicator SDOs, capabilities → ATT&CK patterns, family detection → Malware SDO, IOCs → SCOs.
- Compatible with MISP, OpenCTI, TheHive, Splunk SOAR, and any STIX 2.1-compatible platform.

### CI/CD & Security
- GitHub Actions CI: test matrix (Python 3.9–3.13 × Ubuntu + Windows), pip caching, coverage upload to Codecov.
- GitHub Actions Release: automated Windows installer + portable ZIP on `v*` tags, with pip caching.
- Security workflow: weekly `pip-audit` dependency scanning + GitHub CodeQL static analysis.
- Added `--port` CLI argument for `hashguard --web --port <N>`.
- Added `__main__.py` for `python -m hashguard` support.
- Suppressed `RequestsDependencyWarning` stderr noise on Windows.

### ML Training Pipeline & Real-time Classification
- `feature_extractor.py` — 63 numeric features + 4 labels extracted from analysis results (file, PE, strings, YARA, threat intel, capabilities).
- `ml_trainer.py` — full ML training pipeline with Random Forest, Gradient Boosting, and Ensemble algorithms.
- `batch_ingest.py` — MalwareBazaar bulk sample ingestion (Auth-Key + selectors) and local directory scanning.
- Dataset database (`dataset_features` table) — SQLite storage for ML training data.
- Real-time classification — every uploaded file is automatically classified by the trained model (63 features).
- Model management API — train, list, inspect, delete models; predict individual samples.
- Web dashboard ML page — training controls, progress bar, metrics display, feature importance charts, model history.
- Dual classifier display — both built-in (22 PE features) and trained model (63 rich features) shown in results.
- REST API endpoints: `POST /api/ml/train`, `GET /api/ml/status`, `GET /api/ml/models`, `GET /api/ml/models/{id}`, `DELETE /api/ml/models/{id}`, `POST /api/ml/predict`.
- REST API endpoints: `POST /api/dataset/ingest`, `GET /api/dataset/stats`, `GET /api/dataset/export`.

### Web Dashboard
- FastAPI + Alpine.js + Tailwind CSS dark-themed single-page application.
- File upload & URL analysis with real-time progress.
- IOC relationship graphs (vis.js network visualization).
- Malware behavior timelines and clustering visualization.
- Sample search, analysis history, and dashboard statistics.
- REST API: `/api/analyze`, `/api/samples`, `/api/stats`, `/api/graph/{id}`, `/api/timeline/{id}`, `/api/clusters`, `/api/search`.

### Machine Learning
- Gradient Boosted Trees + Random Forest ensemble classifier.
- 5-class classification: benign, trojan, ransomware, miner, stealer.
- EMBER-calibrated synthetic training data generation.
- HMAC integrity verification on serialized models.

### Script Deobfuscation
- PowerShell: Base64 decoding, char concatenation, string reversal, Invoke-Expression unwrapping.
- VBScript/VBA, JavaScript, Batch, and HTA deobfuscation.
- Pattern-based analysis — no code execution.

### Behavioral Sandbox
- Windows Sandbox integration with configurable timeout.
- ETW-based process monitoring.
- System snapshot diffing (processes, files, registry, network).
- File system change monitors.

### Unpacker
- UPX auto-detection and unpacking.
- MPRESS, Themida, VMProtect, ASPack, Enigma, PECompact detection.
- Entropy-based generic packing detection.
- Unicorn CPU emulation for shellcode analysis (experimental).

### YARA Rules (28 → 158)
- Expanded from 5 to 14 category files.
- New categories: C2 frameworks (15), evasion (17), persistence (16), destructive (15), exploits (13), stealers (12), documents (12), rootkits (10), miners (10).
- Existing categories updated: ransomware (3 → 11), trojans (4 → 12), default (11 → 5, split into specialized files).

### Threat Intelligence
- Added ThreatFox IOC database (abuse.ch).
- Added Shodan InternetDB for IP intelligence.
- Thread-safe TTL-based cache for all sources.
- Now 7 sources total (up from 5).

### New Modules
- `advanced_pe.py` — TLS callbacks, anti-debug/anti-VM detection, rich header analysis, overlay analysis.
- `capability_detector.py` — CAPA-inspired behavioral detection (ransomware, keylogger, reverse shell, credential theft).
- `family_detector.py` — malware family identification via YARA metadata, threat intel, imphash, string signatures.
- `fuzzy_hasher.py` — ssdeep (CTPH) + TLSH fuzzy hashing for similarity matching.
- `ioc_enrichment.py` — passive DNS, IP geolocation, WHOIS, domain age analysis.
- `ioc_graph.py` — file → domain → IP → family relationship graphs (vis.js).
- `malware_cluster.py` — DBSCAN clustering on ML features, fuzzy hash similarity, imphash grouping.
- `malware_timeline.py` — delivery → execution → persistence → C2 → action phase timeline builder.
- `database.py` — SQLite persistence for all analysis results, IOCs, behaviors, families, and clusters.

### Security Fixes
- HMAC integrity verification before loading pickled ML models.
- CORS origin lockdown on web API.
- Filename sanitization in sandbox module.
- Error details hidden from API responses in production.
- Thread-safe threat intelligence cache.
- 10 MB file size guard on deobfuscator input.

### GUI
- 3 new tabs: Packer/Unpack, Deobfuscation, Threat Intel.
- Version display corrected to v1.1.0.

---

## 1.0.4 — 2026-03-08

Initial public release.

### Core Analysis
- Streaming SHA-256, SHA-1, and MD5 hash computation in a single pass.
- Malware signature matching via `signatures.json` (21 known-bad hashes).
- Composite risk scoring engine (0–100) with clean / suspicious / malicious verdicts.
- Automated IOC and string extraction (URLs, IPs, domains, emails, PowerShell commands, crypto wallets, registry keys).

### PE Executable Analysis
- Section-level entropy, packer detection, suspicious API import flagging.
- W+X section warnings, compile-time metadata, entry-point display.

### YARA
- 28+ YARA rules across 5 category files: general, ransomware, trojans, packers, and scripts.
- Auto-loads all `.yar` / `.yara` files from the `yara_rules/` directory.

### Threat Intelligence
- MalwareBazaar hash reputation (abuse.ch) — free, runs automatically.
- URLhaus payload database (abuse.ch) — free, runs automatically.
- AlienVault OTX hash reputation (v2 API) — free, runs automatically.
- AbuseIPDB IP reputation — free tier, requires `ABUSEIPDB_API_KEY`.
- VirusTotal API v3 integration — requires `VT_API_KEY`, activated with `--vt`.

### Security
- SSRF redirect validation: each hop checked against private/reserved IPs.
- API keys read from environment variables only — never persisted to disk.
- Config field whitelisting during deserialization.
- Explicit `verify=True` on all HTTP requests (TLS enforcement).
- Symlink-safe batch directory scanning.

### GUI
- Modern dark-themed Tkinter interface with drag-and-drop file support.
- Visual risk score bar with color-coded verdict display.
- Windows taskbar icon via `AppUserModelID` and BMP-encoded ICO.
- Threat indicator checklist with point breakdown.
- Extracted IOC display categorized by type.
- Real-time progress indicators and URL analysis support.
- Persistent settings via GUI Settings tab (`%APPDATA%/HashGuard/config.json`).

### CLI
- Single-file, URL, and batch analysis modes.
- Risk score and IOC summary in console output.
- JSON, CSV, and HTML report export.
- `--gui` flag to launch the graphical interface.

### Distribution
- PyInstaller spec files for standalone Windows executables (CLI + GUI).
- NSIS Windows installer with Start Menu, Desktop shortcut, and optional PATH registration.
- Portable ZIP package.
- GitHub Actions CI (Python 3.9–3.12 matrix) and automated release workflow.
