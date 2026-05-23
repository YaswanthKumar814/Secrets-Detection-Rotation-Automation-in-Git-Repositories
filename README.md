<div align="center">

# GitGuard

**Defensive secret detection for Git repositories**

Find leaked API keys, tokens, and credentials hiding in your code and commit history — before attackers do.

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?logo=data:image/svg+xml;base64,)](https://attack.mitre.org/)

[Quick Start](#quick-start) · [Features](#features) · [Architecture](#architecture) · [CLI Reference](#cli-reference) · [Dashboard](#dashboard--reports) · [Configuration](#configuration) · [Project Guide](docs/PROJECT_GUIDE.md)

</div>

---

## Quick Start

```bash
# 1. Clone & install
git clone https://github.com/your-org/gitguard.git
cd gitguard
pip install -r requirements.txt

# 2. Run the full demo (scan + history + report)
python main.py demo

# 3. Launch the web dashboard
python main.py dashboard
# → Open http://127.0.0.1:5000
```

> **No cloud account required.** GitGuard runs entirely on your machine. AWS/LocalStack integration is optional and disabled by default.

---

## Features

| Capability | Description |
|:---|:---|
| **File Scanning** | Walks repo trees, matches 25+ secret patterns (AWS keys, GitHub tokens, Stripe keys, JWTs, PEM blocks, DB URLs, and more) |
| **Git History Scanning** | Inspects commit diffs to uncover secrets that were "deleted" but live on in history |
| **Risk Scoring** | Three-dimensional scoring: *severity* (how dangerous), *confidence* (how likely it's real), *exposure* (how accessible the file is) |
| **MITRE ATT&CK Mapping** | Every finding linked to an ATT&CK technique (T1552, T1552.001, T1552.004, etc.) with dashboard hyperlinks |
| **Duplicate Grouping** | Same secret across multiple files → one row with `occurrence_count` and an expandable file list |
| **Web Dashboard** | Flask + Bootstrap 5 + Chart.js — overview, findings table, analytics charts, history, rotations, monitoring, reports |
| **HTML Reports** | Executive-ready, printable reports with risk banners, ATT&CK tables, remediation checklists |
| **Real-Time Monitoring** | Watchdog-based file watcher that re-scans on changes |
| **Mock Credential Rotation** | Simulates rotation workflows with an audit log (does not revoke real keys) |
| **Cloud Export (optional)** | Push reports to S3, alerts to SNS, summaries to DynamoDB via AWS or LocalStack |

---

## Architecture

```
┌─────────────────────────────────────────────┐
│  PRESENTATION                               │
│  main.py  ·  dashboard/  ·  reports/        │
└─────────────────────┬───────────────────────┘
                      │
┌─────────────────────▼───────────────────────┐
│  INTELLIGENCE                               │
│  risk_intel/ (scores, ATT&CK, grouping)     │
└─────────────────────┬───────────────────────┘
                      │
┌─────────────────────▼───────────────────────┐
│  DETECTION + STORAGE                        │
│  scanner/  ·  git_history/  ·  regex_engine/│
│  entropy/  ·  database/ (SQLite)            │
└─────────────────────────────────────────────┘

Optional: cloud_export/ → S3, SNS, DynamoDB
```

### Detection Pipeline

```
Repository
  → ① Pick files (skip node_modules, .git, venv; allowed extensions only; <512 KB)
  → ② Read lines (4-thread parallel)
  → ③ Regex match (25+ secret patterns)
  → ④ Shannon entropy scoring (filters placeholders like "changeme")
  → ⑤ Risk enrichment (severity, confidence, exposure, ATT&CK, remediation)
  → ⑥ Group duplicates (merge same secret across files)
  → ⑦ Save to SQLite
  → ⑧ Display: CLI table / Web dashboard / HTML report
```

---

## CLI Reference

```bash
python main.py <command> [arguments]
```

| Command | Description |
|:---|:---|
| `scan <path>` | Scan a local repository for secrets |
| `scan-remote <url>` | Clone a remote repo and scan (allowlist required) |
| `scan-targets <file.yaml>` | Batch scan multiple repos from a YAML manifest |
| `history-scan <path>` | Scan Git commit history for buried secrets |
| `monitor <path>` | Watch a directory for file changes and re-scan in real time |
| `report` | Generate an HTML + JSON executive report |
| `dashboard` | Start the web dashboard at `:5000` |
| `demo` | End-to-end demo: generate test repo → scan → history scan → report |
| `generate-test-repo` | Create `test_repo/` populated with fake secrets for testing |
| `aws-check` | Verify AWS / LocalStack connectivity |

### Example Workflow

```bash
# Scan a local project
python main.py scan ./my-project

# Scan git history (last N commits)
python main.py history-scan ./my-project

# Generate an executive report
python main.py report
# → reports_output/gitguard_report_<timestamp>.html
```

---

## Dashboard & Reports

### Web Dashboard — `http://127.0.0.1:5000`

| Page | What You'll See |
|:---|:---|
| **Overview** | Risk pill, executive summary, charts, last scan info, top repos, ATT&CK coverage |
| **Findings** | Full findings table with severity, confidence, exposure, ATT&CK links, grouped/expandable rows |
| **Analytics** | Severity & confidence distributions, top secret types, trend over time |
| **History** | Commit-level secret leaks with author, date, and diff context |
| **Rotations** | Mock remediation audit log |
| **Monitoring** | Live file change events |
| **Reports** | Trigger and download HTML reports |
| **Logs / Repos** | Audit trail and scan history |

**Tech stack:** Flask · Jinja2 · Bootstrap 5 · Chart.js

### HTML Reports

Standalone, printable reports that include a risk banner, executive statistics, ATT&CK mapping table, grouped findings, remediation checklist, and MITRE defensive recommendations. Drop them into a Slack thread or email them to stakeholders.

---

## Project Structure

```
gitguard/
├── main.py                ← CLI entry point
├── config.py              ← Settings + env vars
├── allowlist.yaml         ← Approved scan targets
├── targets.yaml           ← Batch scan manifest
├── gitguard.db            ← SQLite database (auto-created)
│
├── scanner/               ← File scanning + repo clone + allowlist
├── regex_engine/          ← 25+ secret detection patterns
├── entropy/               ← Shannon entropy scoring
├── risk_intel/            ← Severity, ATT&CK mapping, grouping
├── git_history/           ← Commit history scanning
├── database/              ← Schema, queries, migrations
├── dashboard/             ← Flask web application
├── reports/               ← HTML report generator (Jinja2)
├── rotation/              ← Mock credential rotation
├── monitor/               ← File watcher (Watchdog)
├── cloud_export/          ← Optional S3 / SNS / DynamoDB
├── templates/             ← Dashboard HTML templates
├── utils/                 ← Masking, logging helpers
├── test_repo/             ← Demo repo with fake secrets
├── test_repo_gen.py       ← Generates test_repo
├── reports_output/        ← Generated report files
└── docs/                  ← PROJECT_GUIDE.md and docs
```

---

## Security & Safety

- **Secrets are never stored in full.** Only masked previews (`ghp_abc…` → `ghp_********…`) are saved to the database, displayed on the dashboard, and included in reports.
- **Allowlists** prevent scanning arbitrary external repositories. Required for `scan-remote` and `scan-targets`.
- **Cloud failures are non-blocking** — scans complete even if AWS/LocalStack is unreachable.

---

## Configuration

Settings live in `config.py` and can be overridden with environment variables or a `.env` file.

| Variable | Default | Effect |
|:---|:---|:---|
| `GITGUARD_AWS_ENABLED` | `false` | Enable cloud export (S3, SNS, DynamoDB) |
| `GITGUARD_AWS_ENDPOINT_URL` | — | LocalStack endpoint (e.g. `http://localhost:4566`) |
| `GITGUARD_ENFORCE_ALLOWLIST` | `false` | Require allowlist even for local scans |
| `ENTROPY_THRESHOLD` | `4.5` | Minimum entropy to flag a match as a real secret |
| `FLASK_PORT` | `5000` | Dashboard server port |

---

## Database

GitGuard uses a local SQLite database (`gitguard.db`, auto-created on first run).

**Core tables:** `repositories`, `scans`, `findings`, `history_findings`, `rotation_actions`, `monitor_events`, `logs`

**Key finding fields:** `secret_type`, `masked_preview`, `severity`, `severity_score`, `confidence_label`, `confidence_score`, `attack_technique`, `attack_name`, `attack_tactic`, `exposure_level`, `exposure_reason`, `occurrence_count`, `remediation`

---

## MITRE ATT&CK Coverage

| Technique ID | Name | Typical Trigger |
|:---|:---|:---|
| T1552 | Unsecured Credentials | Default mapping for detected secrets |
| T1552.001 | Credentials in Files | API keys, tokens, passwords found in source code |
| T1552.004 | Private Keys | PEM / RSA private key blocks |

Every finding on the dashboard links directly to the corresponding [MITRE ATT&CK](https://attack.mitre.org/) page.

---

## Demo Walkthrough (5 Minutes)

1. **Terminal** — Run `python main.py demo` and walk through the findings table
2. **Browser** — Open the dashboard: Overview → Findings → Analytics
3. **Report** — Open `reports_output/gitguard_report_*.html` in a browser
4. **Architecture** — Mention the allowlist system and optional LocalStack cloud integration

---

## Limitations

- Does **not** revoke or rotate real credentials — rotation is simulated for demo purposes
- Does **not** rewrite Git history — only detects secrets, does not remove them
- Does **not** scan all of GitHub — only allowlisted URLs are accepted
- Does **not** use ML — detection is regex + rules + Shannon entropy

---

## Glossary

| Term | Definition |
|:---|:---|
| **Finding** | A detected (possibly grouped) secret |
| **Masked preview** | Partially redacted secret shown for safe display |
| **Allowlist** | Set of approved repositories and paths for scanning |
| **SOC** | Security Operations Center — the team monitoring threats |
| **MITRE ATT&CK** | Industry-standard catalog of adversary techniques |
| **LocalStack** | Local AWS emulator for cloud feature demos |
| **Grouped finding** | Duplicate secrets merged into a single database row |
| **Shallow clone** | `git clone --depth 1` used for faster remote scanning |

---

## Further Reading

- **[Project Guide](docs/PROJECT_GUIDE.md)** — Deep-dive into every module, data flow, and design decision
- **[MITRE ATT&CK](https://attack.mitre.org/)** — The framework behind our threat mapping
- **[LocalStack](https://localstack.cloud/)** — Run cloud features without an AWS account

---

<div align="center">

**GitGuard** — Defensive secrets detection for secure development.

*Built with Python · Flask · SQLite · Rich · Chart.js*

</div>
