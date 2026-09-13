# cnvd-skill

**A portable toolkit for batch discovery of generic unauthenticated vulnerabilities (CNVD submissions).**

Niche product lines × prebuilt endpoint dictionaries × batch read-only verification — 10+ confirmed instances make one generic vulnerability finding.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](#requirements)

中文文档：[README.md](README.md)

---

## What is this

A workflow toolkit for discovering **generic unauthenticated vulnerabilities** at scale, designed for [CNVD](https://www.cnvd.org.cn/) (China National Vulnerability Database) submissions:

- **A skill definition** (`skills/cnvd/SKILL.md`) — full workflow, principles, detection criteria, and compliance rules. Usable as a standalone playbook even without Claude Code.
- **9 Python scripts** — standard library only, zero pip dependencies. Covering recon → detection → dedup & re-verification.
- **28 endpoint dictionary rules** (8 files) — battle-tested unauthenticated endpoints, transferable across vendors. The core asset of this package.
- **Sanitized samples + one-click self-check** — `示例产出/` shows all intermediate artifact formats; `校验.bat` runs an environment self-check and smoke test (Windows).

The core idea: **horizontal coverage at the endpoint level, not firmware-level deep dives.** Pick a niche product line, batch-verify similar devices with prebuilt dictionaries — 10+ hits give you enough instances for one generic vulnerability report.

**Run semantics (v2.1)**: **no stopping without output** — the only legal stop condition is having landed at least one submission-ready finding (10+ hits + no duplicate + re-verified + report on disk). Switching product lines is not stopping; keep cycling until a finding lands or the user says stop. Compliance rules stay fully enforced during continuous operation.

## Workflow

```
Prep (10 min) → Recon → Batch check → Dedup + re-verify → Report → Next line
```

| Phase | Tool | Output |
|-------|------|--------|
| 0 Recon | `cnvd_recon.py` | Asset CSV (multi-channel FOFA queries) |
| 1 Check | `cnvd_check.py` | `findings.csv` (triple false-positive guards) |
| 1.5 Dedup + verify | `verify_*.py` | `verify_report.json` |
| 2 Report | SKILL.md §1.4 | Submission + reproduction reports |

## Features

- **Three read-only protocol probes**: HTTP (GET/POST with double-diff), RTSP (strict SDP criteria), FTP (anonymous 230)
- **Double-diff anti-false-positive**: HTTP hits are re-requested without cookies; non-reproducible hits are discarded
- **Honeypot filtering**: built-in ip-api lookups; cloud-provider IP ranges flagged as `cloud_suspect` for manual review
- **Strict RTSP criteria**: requires `DESCRIBE 200` with SDP containing `v=0` + `m=video/audio`; OPTIONS-only responses are always discarded
- **Multi-channel FOFA support**: any number of channels (official or relay format), automatic failover
- **Resumable scans**: `--resume` skips completed targets
- **Compliance built in**: per-IP serial requests with ≥1s interval enforced in code; everything is read-only
- **Zero dependencies**: Python 3.8+, no third-party packages

## Quick start

### Requirements

- **Python 3.8+** (3.12 recommended) — the only hard dependency
- Windows / Linux / macOS (the `校验.bat` self-check is Windows-only)

### Three steps

**1. Install Python** — from https://python.org, check "Add python.exe to PATH". Verify with `python --version`.

**2. Fill in your FOFA key** — `api_keys.json` is a placeholder template (all keys are `REPLACE_ME`). Edit the `channels` array:

```json
{
  "channels": [
    {
      "name": "primary",
      "enabled": true,
      "base_url": "https://your-fofa-proxy",
      "search_path": "/api/v1/search/all",
      "key_param": "key",
      "query_param": "qbase64",
      "key": "YOUR_KEY"
    }
  ]
}
```

- `query_param`: `qbase64` for official format (query base64-encoded), `query` for plain relay APIs
- Multiple channels are tried in order with automatic failover

**3. Self-check** — run `校验.bat` (Windows) or invoke each script with `--help`.

### Shortest path

```bat
cd tools\scripts

:: 1) Recon: pull assets for a product line (nvr/printer/industrial/network/access/nas/conference)
python cnvd_recon.py --preset nvr --out stage0_nvr.csv

:: 2) Prepare targets.csv (header: ip,port) and batch-check
python cnvd_check.py --targets targets.csv --rules ..\rules\rules_boa.json --geo --out findings.csv

:: 3) 10+ hits → dedup + re-verify per SKILL.md §1.3
```

## Endpoint dictionaries

| File | Product line | Endpoints |
|------|--------------|-----------|
| `rules_boa.json` | NVR/DVR (Boa firmware) | Config.json (UID) / ONVIF / RTSP / anonymous FTP |
| `rules_newfe.json` | New-frontend NVR/IPC | Config.json (UID) / super-password code / recovery API / RTSP / ONVIF |
| `rules_access_*.json` | Access control (3 vendors) | Firmware fingerprints / pre-filled default credentials / exposed consoles |
| `rules_ews_printer.json` | EWS printers | VNC panel / account mgmt / backup password / firmware update / config export |
| `rules_superpw_only.json` | Super-password single rule | Unauthenticated recovery-code disclosure |
| `rules_generic.json` | Generic starter | Config export / backup / path traversal / sensitive API fields / RTSP |

See [docs/规则编写指南.md](docs/规则编写指南.md) (Chinese) for writing custom rules.

## Compliance (non-negotiable)

```
DO:     read-only GET/OPTIONS/DESCRIBE/LIST | ≥1s per-IP interval | full operation logs | CNVD submissions only
DON'T:  modify configs / delete data | download sensitive files | brute-force / lateral movement |
        public disclosure before submission | scan government/military/critical infrastructure without authorization
```

- This toolkit **only verifies unauthenticated access** (proving what can be read). It provides no write, exploit, or persistence capabilities.
- Only test assets you are **authorized** to test.
- Vulnerability details must not be publicly disclosed before platform disclosure.

## Disclaimer

This toolkit is provided for **authorized security testing** and **legitimate vulnerability submissions** (e.g., CNVD) only. Users are responsible for complying with applicable laws and regulations. The authors assume no liability for misuse.

## Documentation

| Document | Content |
|----------|---------|
| [README.md](README.md) | Full documentation (Chinese) |
| [README-移植说明.md](README-移植说明.md) | Portable deployment guide (Chinese) |
| [docs/使用教程.md](docs/使用教程.md) | End-to-end walkthrough (Chinese) |
| [docs/规则编写指南.md](docs/规则编写指南.md) | Rule authoring guide (Chinese) |
| [docs/FAQ.md](docs/FAQ.md) | FAQ (Chinese) |
| [CHANGELOG.md](CHANGELOG.md) | Version history |

---

*All sample data is sanitized (RFC 5737 reserved ranges); no real assets or personal information included. FOFA keys are placeholders — fill in your own locally.*
