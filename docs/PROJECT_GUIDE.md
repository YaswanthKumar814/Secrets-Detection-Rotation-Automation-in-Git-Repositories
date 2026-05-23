# GitGuard — Complete Project Guide

A beginner-friendly guide to the entire project: what it does, how it is built, and how data flows from a Git repo to the dashboard.

**Audience:** New team members, hackathon judges, or anyone running the demo for the first time.

---

## Table of Contents

1. [What is GitGuard?](#1-what-is-gitguard)
2. [The Problem](#2-the-problem)
3. [Architecture (Simple View)](#3-architecture-simple-view)
4. [Detection Pipeline](#4-detection-pipeline)
5. [Folder Structure](#5-folder-structure)
6. [Modules at a Glance](#6-modules-at-a-glance)
7. [Database](#7-database)
8. [CLI Commands](#8-cli-commands)
9. [Dashboard & Reports](#9-dashboard--reports)
10. [Hybrid Ingestion & Allowlist](#10-hybrid-ingestion--allowlist)
11. [Risk Intelligence & ATT&CK](#11-risk-intelligence--attack)
12. [Rotation, Monitor, Cloud](#12-rotation-monitor-cloud)
13. [Configuration & Demo](#13-configuration--demo)
14. [Limitations & Glossary](#14-limitations--glossary)

---

## 1. What is GitGuard?

GitGuard is a **defensive** tool that finds secrets accidentally committed to Git repositories.

It can:

- Scan **current files** in a repo (`.env`, source code, configs).
- Scan **Git history** (old commits where secrets were added then “removed”).
- **Score** findings (severity, confidence, exposure).
- Map findings to **MITRE ATT&CK** techniques.
- **Group** duplicate secrets into one row.
- Show results in a **terminal CLI**, a **web dashboard**, and **HTML reports**.
- Optionally export to **AWS / LocalStack** (disabled by default).

Runs locally. No cloud account required for core features.

---

## 2. The Problem

Secrets in Git are dangerous because:

1. They appear in **working files** anyone with repo access can read.
2. They often remain in **commit history** forever unless rewritten.
3. Attackers use stolen credentials for access (MITRE **T1552 — Unsecured Credentials**).

GitGuard automates discovery and presents results in a SOC-friendly format.

---

## 3. Architecture (Simple View)

### Three layers

```
┌─────────────────────────────────────────┐
│  PRESENTATION                           │
│  main.py · dashboard/ · reports/        │
└──────────────────┬──────────────────────┘
                   │
┌──────────────────▼──────────────────────┐
│  INTELLIGENCE                           │
│  risk_intel/ (scores, ATT&CK, grouping) │
└──────────────────┬──────────────────────┘
                   │
┌──────────────────▼──────────────────────┐
│  DETECTION + STORAGE                    │
│  scanner/ · git_history/ · regex_engine/│
│  entropy/ · database/ (SQLite)          │
└─────────────────────────────────────────┘

Optional: cloud_export/ → S3, SNS, DynamoDB
```

### System diagram

```
  [You] ──► main.py (CLI)
                │
       ┌────────┼────────┐
       ▼        ▼        ▼
   scanner  git_history  monitor
       │        │        │
       └────┬───┴────────┘
            ▼
      risk_intel (enrich + group)
            ▼
      database (gitguard.db)
            │
    ┌───────┼───────┐
    ▼       ▼       ▼
  CLI   dashboard  report.html
```

### Entry point

**`main.py`** parses commands (`scan`, `demo`, `dashboard`, …) and calls the right module. It does not contain detection logic itself.

---

## 4. Detection Pipeline

This is the core flow for `python main.py scan ./test_repo`.

### Pipeline (8 steps)

```
Repository
  → ① Pick files to scan
  → ② Read each line
  → ③ Regex match (25+ secret types)
  → ④ Entropy score
  → ⑤ Risk enrichment
  → ⑥ Group duplicates
  → ⑦ Save to SQLite
  → ⑧ CLI / Dashboard / Report
```

### ① Pick files

`scanner/__init__.py` walks the tree, skips `node_modules`, `.git`, `venv`, etc.  
Scans only allowed extensions (`.py`, `.env`, `.yml`, …) or names (`Dockerfile`).  
Skips files larger than **512 KB**.

### ② Read lines

Files are read as text. Each line is checked. Multiple files scan in parallel (**4 threads**).

### ③ Regex match

`regex_engine/` holds patterns for AWS keys, GitHub tokens, Stripe keys, JWTs, private keys, database URLs, and more.  
Each match returns: `secret_type`, `matched_text`, base severity.

### ④ Entropy

`entropy/shannon_entropy()` measures how random the matched string looks.  
Real keys tend to score high; placeholders like `changeme` score low.

### ⑤ Risk enrichment

`risk_intel/analyze_finding()` adds:

| Output | Meaning |
|--------|---------|
| `severity` / `severity_score` | Critical → Low (0–100) |
| `confidence_label` | How sure we are it's real |
| `exposure_level` | How risky the *file location* is |
| `attack_technique` | MITRE ID (e.g. T1552.001) |
| `remediation` | What to do next |
| `context_flags` | e.g. likely example text |

Obvious fake placeholders may be **dropped** (low confidence + low score).

### ⑥ Group duplicates

`risk_intel/group_findings()` merges the same secret found in multiple files.  
Sets `occurrence_count` and `affected_files` so the UI stays clean.

### ⑦ Save

Rows go into SQLite `findings` table, linked to `scans` and `repositories`.

### ⑧ Display

- Terminal: Rich tables via `main.py`
- Web: Flask reads DB
- Report: Jinja2 HTML in `reports_output/`

### History scan (parallel pipeline)

`git_history/scan_history()`:

1. Uses **GitPython** on last N commits.
2. Reads **diff patches** (what changed in each commit).
3. Runs regex + entropy + risk on new lines.
4. Stores in `history_findings` (includes commit, author, date).

---

## 5. Folder Structure

```
gitguard/
├── main.py              ← CLI entry point
├── config.py            ← Settings + AWS env vars
├── allowlist.yaml       ← Approved scan targets
├── targets.yaml         ← Batch scan list
├── gitguard.db          ← SQLite (created on first run)
│
├── scanner/             ← File scan + repo clone/allowlist
├── regex_engine/        ← Secret patterns
├── entropy/             ← Randomness scoring
├── risk_intel/          ← Severity, ATT&CK, grouping
├── git_history/         ← Commit history scan
├── database/            ← DB schema + queries
├── dashboard/           ← Flask web app
├── reports/             ← HTML report generator
├── rotation/            ← Mock validate/rotate
├── monitor/             ← File watcher
├── cloud_export/        ← Optional S3/SNS/DynamoDB
├── templates/           ← Dashboard HTML (Jinja2)
├── utils/               ← Masking, logging
├── test_repo/           ← Demo repo (fake secrets)
├── test_repo_gen.py     ← Builds test_repo
├── reports_output/      ← Generated reports
└── docs/                ← This guide
```

---

## 6. Modules at a Glance

| Module | Role |
|--------|------|
| **main.py** | Commands, banners, tables; orchestrates everything |
| **scanner/** | `scan_repository()` — walk files, thread pool, save findings |
| **repo_ingestion.py** | Clone remote repos, enforce allowlist, batch YAML scans |
| **regex_engine/** | Pattern library for secret types |
| **entropy/** | Shannon entropy helper |
| **risk_intel/** | `analyze_finding()`, `group_findings()`, ATT&CK map, remediation text |
| **git_history/** | Scan commits/diffs for buried secrets |
| **database/** | SQLite CRUD, stats, executive summary, schema migration |
| **dashboard/** | Flask routes + API JSON for charts/tables |
| **reports/** | Single HTML template → executive report |
| **rotation/** | Mock credential rotation with audit log |
| **monitor/** | Watchdog (or polling) on file changes |
| **cloud_export/** | Post-scan/report S3, SNS, DynamoDB (safe, optional) |
| **utils/masking.py** | `ghp_abc…` → `ghp_********…` — never show full secrets |

### Safety rule

Full secrets are **never** stored for display. Only **masked previews** go to the DB, dashboard, and reports.

---

## 7. Database

**File:** `gitguard.db` (SQLite, local file).

### Main tables

| Table | Purpose |
|-------|---------|
| `repositories` | Scanned repo paths |
| `scans` | Each scan run (file or history) |
| `findings` | Detected secrets (current tree) |
| `history_findings` | Secrets in old commits |
| `rotation_actions` | Mock rotation audit |
| `monitor_events` | File change events |
| `logs` | App audit log |

### Key finding fields

```
secret_type, masked_preview, severity, severity_score,
confidence_label, confidence_score,
attack_technique, attack_name, attack_tactic,
exposure_level, exposure_reason,
occurrence_count, remediation
```

### Relationships

```
repository → many scans → many findings
finding → many rotation_actions
repository → many history_findings
```

`get_stats()` and `get_executive_summary()` power the dashboard home page and reports.

---

## 8. CLI Commands

```text
python main.py <command> [arguments]
```

| Command | Purpose |
|---------|---------|
| `scan <path>` | Scan local repository |
| `scan-remote <url>` | Clone + scan (allowlist required) |
| `scan-targets <file.yaml>` | Batch scan |
| `history-scan <path>` | Scan Git commits |
| `monitor <path>` | Real-time file watch |
| `report` | Generate HTML + JSON report |
| `dashboard` | Start web UI at :5000 |
| `demo` | Full demo: scan + history + report |
| `generate-test-repo` | Create test_repo with fake secrets |
| `aws-check` | Test AWS / LocalStack |

After scan, CLI prints a **summary line**: counts by severity, grouped rows, timing.

---

## 9. Dashboard & Reports

### Dashboard (http://127.0.0.1:5000)

| Page | What you see |
|------|----------------|
| **Overview** | Risk pill, executive summary, charts, last scan, top repos, ATT&CK table |
| **Findings** | Full table: severity, confidence, exposure, ATT&CK links, grouped expand |
| **Analytics** | Severity/confidence charts, top types, time trend |
| **History** | Commit-level leaks |
| **Rotations** | Mock remediation log |
| **Monitoring** | Live file events |
| **Reports** | Download trigger |
| **Logs / Repos** | Audit trail and scan history |

**Stack:** Flask + Jinja2 + Bootstrap 5 + Chart.js (no React).

### HTML reports

`python main.py report` → `reports_output/gitguard_report_<timestamp>.html`

Includes risk banner, executive stats, ATT&CK table, grouped findings, remediation checklist, MITRE defensive notes. Printable for stakeholders.

---

## 10. Hybrid Ingestion & Allowlist

GitGuard accepts two **sources**:

```
Local path ──────────────────► scan_repository()
                                    ▲
Remote URL ──► allowlist check ──► git clone (temp)
                                    │
                                    └──► cleanup delete
```

### Why allowlist?

Prevents scanning arbitrary GitHub repos. Required for `scan-remote` and `scan-targets`.

### allowlist.yaml

| Key | Allows |
|-----|--------|
| `allowed_local_paths` | Folders like `./test_repo` |
| `allowed_repositories` | Exact Git URLs |
| `allowed_github_users` | All repos under a user/org |

### targets.yaml

Lists multiple local paths and remote URLs for one `scan-targets` command.

---

## 11. Risk Intelligence & ATT&CK

### Three scores judges care about

1. **Severity** — How dangerous is this secret *type* and *context*?
2. **Confidence** — How sure are we it's real (not a placeholder)?
3. **Exposure** — How bad is the *location* (`.env` vs `README.md`)?

### ATT&CK mapping (examples)

| ID | Name | Typical secret |
|----|------|----------------|
| T1552 | Unsecured Credentials | Default |
| T1552.001 | Credentials in Files | API keys, tokens in code |
| T1552.004 | Private Keys | PEM blocks |

Dashboard links each technique to [attack.mitre.org](https://attack.mitre.org/) for presentations.

### Grouping

Same token in `.env` and `docker-compose.yml` → **one row**, `occurrence_count = 2`, expandable file list.

---

## 12. Rotation, Monitor, Cloud

### Mock rotation (`rotation/`)

When Critical secrets are found during scan, GitGuard can **simulate** rotation:

- Logs old/new masked values in `rotation_actions`
- Does **not** revoke real keys

### Monitor (`monitor/`)

Watches a folder for file changes (Watchdog, polling fallback). Re-scans changed files and logs to `monitor_events`.

### Cloud export (`cloud_export/`) — optional

Off unless `GITGUARD_AWS_ENABLED=true`.

| Service | When | What |
|---------|------|------|
| S3 | After `report` | HTML report + JSON findings |
| SNS | After scan with Critical | Alert message (masked only) |
| DynamoDB | After scan | Finding summaries |

**LocalStack:** Set endpoint to `http://localhost:4566` to demo cloud without real AWS.  
Failures are **non-blocking** — scans never crash if cloud is down.

---

## 13. Configuration & Demo

### Important settings (`config.py` / `.env`)

| Variable | Default | Effect |
|----------|---------|--------|
| `GITGUARD_AWS_ENABLED` | false | Cloud export |
| `GITGUARD_AWS_ENDPOINT_URL` | empty | LocalStack URL |
| `GITGUARD_ENFORCE_ALLOWLIST` | false | Require allowlist for local scan |
| `ENTROPY_THRESHOLD` | 4.5 | Entropy cutoff |
| `FLASK_PORT` | 5000 | Dashboard port |

### Fastest demo

```powershell
pip install -r requirements.txt
python main.py demo
python main.py dashboard
```

`demo` sets `GITGUARD_DEMO_MODE` (shows banner in UI), creates/uses `test_repo`, scans, history-scans, generates report, prints dashboard URL.

### Judge walkthrough (5 min)

1. Terminal: `python main.py demo` — show findings table  
2. Browser: Overview → Findings → Analytics  
3. Open latest `reports_output/*.html`  
4. Mention allowlist + optional LocalStack architecture  

---

## 14. Limitations & Glossary

### What GitGuard does NOT do

- Revoke or rotate **real** credentials
- Remove secrets from Git history (only **detects** them)
- Scan all of GitHub (only **allowlisted** URLs)
- Use machine learning (regex + rules + entropy only)

### Glossary

| Term | Definition |
|------|------------|
| **Finding** | One detected (possibly grouped) secret |
| **Masked preview** | Partially redacted secret for safe display |
| **Allowlist** | Approved repos/paths for scanning |
| **SOC** | Security team monitoring threats |
| **MITRE ATT&CK** | Catalog of attacker techniques |
| **LocalStack** | Local AWS emulator for demos |
| **Grouped finding** | Duplicates merged into one DB row |
| **Shallow clone** | `git clone --depth 1` for fast remote scans |

---

## End-to-End Cheat Sheet

```
python main.py scan ./test_repo
         │
         ▼
    scanner.scan_repository()
         │
    regex + entropy + risk_intel
         │
    group_findings() → database
         │
    ┌────┴────┬────────┐
    ▼         ▼        ▼
  CLI     dashboard  report
```

For commands and LocalStack setup, see [README.md](../README.md).  
For screenshots, see [screenshots/README.md](screenshots/README.md).

---

*GitGuard — defensive secrets detection for hackathon demos and learning.*
