# 🛡️ GitGuard

**Hybrid Git secret detection pipeline with controlled repository ingestion, risk intelligence, and SOC-style visibility.**

A defensive cybersecurity tool that scans Git repositories for leaked secrets, maps findings to MITRE ATT&CK, groups duplicates, performs mock credential rotation, and presents executive-ready analytics through a Flask dashboard and HTML reports.

> Built for a cybersecurity hackathon — local-first, presentation-ready, with optional LocalStack cloud export.

---

## Problem Statement

Developers accidentally commit API keys, tokens, and passwords into Git repositories. Once pushed, secrets remain in **current files** and often in **commit history**, enabling credential theft (MITRE ATT&CK T1552). Manual review does not scale; enterprise tools are heavy for demos and labs.

**GitGuard** provides a lightweight, judge-friendly pipeline: detect → classify → map to ATT&CK → group → remediate (mock) → report → visualize.

---

## Threat Model

| Threat | Mitigation in GitGuard |
|--------|------------------------|
| Secrets in working tree | Regex + entropy scanner |
| Secrets in Git history | `history-scan` on commits/diffs |
| Re-commit after rotation | Real-time `monitor` (watchdog) |
| Unauthorized repo scanning | `allowlist.yaml` enforcement |
| Mass GitHub crawling | Only explicit URLs in allowlist/targets |
| Credential exposure in UI | Masked previews only; no full secrets stored |
| Cloud dependency for demos | Local SQLite + optional LocalStack |

**Out of scope:** Real credential validation/rotation, production IAM, CI/CD plugins (future work).

---

## Features

- **Secret Detection** — 25+ regex patterns for AWS keys, GitHub tokens, Slack tokens, Stripe keys, SSH keys, JWTs, database URLs, and more
- **Entropy Analysis** — Shannon entropy scoring to reduce false positives
- **Git History Scanning** — Detect secrets buried in old commits and diffs
- **Severity Scoring** — 0–100 severity score mapped to Critical/High/Medium/Low
- **Mock Credential Validation** — Simulated ACTIVE/EXPIRED/TEST/INVALID/UNKNOWN checks
- **Mock Rotation Workflow** — Automated remediation with audit trail and retry logic
- **Real-Time Monitoring** — Watchdog-based file change detection with polling fallback
- **SOC-Style Dashboard** — Dark theme Flask dashboard with 9 pages and Chart.js visualizations
- **HTML Report Generator** — Executive summary with findings, remediation history, and MITRE ATT&CK mapping
- **Rich CLI** — Beautiful terminal output with progress bars and tables
- **Demo Repository Generator** — Creates a test repo with realistic fake secrets
- **One-Command Demo** — `python main.py demo` runs scan + history + report end-to-end
- **Executive Summary** — Risk posture on dashboard home and HTML reports
- **Hybrid Repository Ingestion** — Scan local paths or allowlisted GitHub URLs
- **Mandatory Allowlist** — Remote and batch scans require explicit approval in `allowlist.yaml`
- **Batch Target Scanning** — Scan multiple repos from `targets.yaml`

---

## 5-Minute Hackathon Demo

**Fastest path** — one command prepares all demo data:

```powershell
pip install -r requirements.txt
python main.py demo
python main.py dashboard
```

Open **http://127.0.0.1:5000** and walk judges through this order:

| Step | Action | What to say |
|------|--------|-------------|
| 1 | **Overview** (`/`) | Executive summary, risk level, ATT&CK coverage, last scan |
| 2 | **Findings** (`/findings`) | Severity, confidence, exposure, grouped duplicates, remediation |
| 3 | **Analytics** (`/analytics`) | Severity/confidence charts, top secret types, ATT&CK distribution |
| 4 | Open `reports_output/gitguard_report_*.html` | Printable executive report for stakeholders |
| 5 | **History** (`/history`) | Secrets buried in old commits |
| 6 | *(Optional)* `python main.py aws-check` | LocalStack-safe cloud export story |

**Manual equivalent** (if you prefer step-by-step):

```powershell
python main.py generate-test-repo
python main.py scan ./test_repo
python main.py history-scan ./test_repo
python main.py report
python main.py dashboard
```

---

> **Full beginner guide:** See [docs/PROJECT_GUIDE.md](docs/PROJECT_GUIDE.md) for architecture, pipeline, and module-by-module explanation.

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run full demo (recommended)
python main.py demo

# 2b. Or generate a demo test repo manually
python main.py generate-test-repo

# 3. Scan for secrets (local)
python main.py scan ./test_repo

# 3b. Scan a remote repo (must be in allowlist.yaml)
python main.py scan-remote https://github.com/octocat/Hello-World.git

# 3c. Batch scan configured targets
python main.py scan-targets targets.yaml

# 4. Scan commit history
python main.py history-scan ./test_repo

# 5. Generate a report
python main.py report

# 6. Launch the dashboard
python main.py dashboard
# Open http://127.0.0.1:5000 in your browser
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `python main.py scan <path>` | Scan a local repository for secrets |
| `python main.py scan-remote <repo_url>` | Clone and scan an allowlisted remote repo (`--history` optional) |
| `python main.py scan-targets <targets.yaml>` | Batch scan targets from YAML (`--history` optional) |
| `python main.py history-scan <path>` | Scan Git commit history for leaks |
| `python main.py monitor <path>` | Watch a repo for real-time changes |
| `python main.py report` | Generate an HTML executive report (optional S3 export) |
| `python main.py aws-check` | Test AWS / LocalStack connectivity |
| `python main.py dashboard` | Launch the web dashboard |
| `python main.py demo` | Full demo: test repo → scan → history → report |
| `python main.py generate-test-repo` | Create a demo test repository |

## Dashboard Pages

| Page | Description |
|------|-------------|
| Overview | Executive summary, risk pill, ATT&CK table, top repos, recent scans |
| Findings | Filterable table of all detected secrets |
| Analytics | Severity distribution, trends, entropy histogram |
| History | Secrets found in Git commit history |
| Rotations | Mock credential rotation actions |
| Monitoring | Real-time file change events |
| Reports | Generate and download HTML reports |
| Logs | Structured audit log viewer |
| Repositories | Repository stats and scan history |

## Dashboard Screenshots

Capture screenshots after running `python main.py demo` and `python main.py dashboard`.

See **[docs/screenshots/README.md](docs/screenshots/README.md)** for exact filenames and capture steps.

Suggested files: `01-overview.png`, `02-findings.png`, `03-analytics.png`, `04-report.png`

---

## ATT&CK Mapping

| Technique | Name | When applied |
|-----------|------|--------------|
| T1552 | Unsecured Credentials | Default credential-in-repo finding |
| T1552.001 | Credentials in Files | API keys, tokens in source/config |
| T1552.004 | Private Keys | PEM / private key blocks |
| T1078 | Valid Accounts | High-impact cloud tokens (contextual) |

Findings display technique ID with links to [MITRE ATT&CK](https://attack.mitre.org/) in the dashboard and reports.

---

## Detection Pipeline

```
Repository (local or cloned)
    → Allowlist check (remote/batch)
    → File walk + extension filter
    → Regex pattern matching (25+ types)
    → Shannon entropy scoring
    → Risk intelligence enrichment
        • Severity score (0–100)
        • Confidence label (High/Medium/Low)
        • Exposure level + reason
        • ATT&CK technique mapping
        • Duplicate grouping
    → SQLite persistence
    → Dashboard / Report / Optional AWS export
```

---

## Risk Intelligence

Phase 4 enrichment adds judge-friendly context without ML:

- **Confidence** — pattern strength + entropy + context flags
- **Exposure** — file sensitivity (e.g. `.env`, `docker-compose`, committed history)
- **Grouping** — collapses duplicate secrets across files (`occurrence_count`)
- **Remediation** — actionable text per finding type
- **Executive summary** — estimated risk, top secret type, cloud credential count

---

## Example Findings (Demo Repo)

After `python main.py scan ./test_repo`, expect entries such as:

| Severity | Type | Location |
|----------|------|----------|
| Critical | GitHub Token (classic) | `.env` |
| Critical | OpenAI API Key | `.env` |
| Critical | Private Key Block | `service_account.json` |
| High | AWS Access Key | `.env` |
| High | JWT Token | `notes.txt` |

All values are **fake** and masked in output (e.g. `ghp_********…`).

---

## Hybrid Ingestion Architecture

```
Git Source
  ├── Local repository path          (e.g. ./test_repo)
  └── GitHub repository URL          (e.g. https://github.com/user/repo.git)
        ↓
Mandatory Allowlist Validation       (allowlist.yaml / targets.yaml)
        ↓
Temporary Clone Workspace            (remote only — shallow git clone)
        ↓
Existing Scanner + Git History       (reused — no duplicate logic)
        ↓
Cleanup Temporary Repository         (always removed after remote scan)
```

### Allowlist Enforcement

Remote scans **always** require allowlist approval before cloning. Batch scans skip disallowed targets and continue with the rest.

| Allowlist key | Controls |
|---------------|----------|
| `allowed_local_paths` | Directories that may be scanned locally or via batch |
| `allowed_repositories` | Exact GitHub/Git remote URLs (normalized) |
| `allowed_github_users` | Any repo owned by these GitHub users/orgs |

Edit `allowlist.yaml` (or set `GITGUARD_ALLOWLIST_PATH`) before using `scan-remote` or `scan-targets`.

Optional: set `GITGUARD_ENFORCE_ALLOWLIST=true` to require allowlist approval for `python main.py scan <path>` as well.

### Example `targets.yaml`

```yaml
allowed_local_paths:
  - ./test_repo

allowed_repositories:
  - https://github.com/octocat/Hello-World.git

allowed_github_users:
  - octocat

scan_targets:
  local:
    - ./test_repo
  repositories:
    - https://github.com/octocat/Hello-World.git
```

Copy `targets.yaml.example` to customize. See `allowlist.yaml` for the default allowlist used by `scan-remote`.

## Optional AWS / LocalStack Integration

AWS is **fully optional**. With `GITGUARD_AWS_ENABLED=false` (default), GitGuard runs 100% locally with no cloud calls.

When enabled, the optional export layer provides:

| Feature | Trigger | Config required |
|---------|---------|-----------------|
| **S3 report export** | After `python main.py report` | `GITGUARD_S3_BUCKET` |
| **S3 findings JSON** | Same as above | `GITGUARD_S3_BUCKET` |
| **SNS Critical alerts** | After any scan with Critical findings | `GITGUARD_SNS_TOPIC_ARN` |
| **DynamoDB finding sync** | After any scan | `GITGUARD_DYNAMODB_TABLE` |

Object keys use the structure:

```
s3://<bucket>/reports/<timestamp>/report.html
s3://<bucket>/reports/<timestamp>/findings.json
```

SNS messages include repository name, secret type, severity, and **masked preview only** — never full secrets.

### Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `GITGUARD_AWS_ENABLED` | `false` | Master switch |
| `GITGUARD_AWS_REGION` | `ap-south-1` | AWS region |
| `GITGUARD_AWS_ENDPOINT_URL` | *(empty)* | LocalStack URL e.g. `http://localhost:4566` |
| `GITGUARD_S3_BUCKET` | *(empty)* | S3 bucket for reports |
| `GITGUARD_DYNAMODB_TABLE` | *(empty)* | DynamoDB table for findings |
| `GITGUARD_SNS_TOPIC_ARN` | *(empty)* | SNS topic for Critical alerts |
| `GITGUARD_ALLOW_REAL_AWS_VALIDATION` | `false` | Allow STS check against real AWS |

### LocalStack Setup (Windows Beginner-Friendly)

AWS export is **optional**. Scans and reports always work locally even if LocalStack is off.

#### Prerequisites

1. **Docker Desktop** must be installed and running (whale icon in system tray).
2. Python dependencies installed: `pip install -r requirements.txt`

#### Step 1 — Start LocalStack (Docker)

**PowerShell:**

```powershell
docker run -d -p 4566:4566 --name gitguard-localstack localstack/localstack
```

**CMD:**

```cmd
docker run -d -p 4566:4566 --name gitguard-localstack localstack/localstack
```

> LocalStack may still be starting. Wait **~15–30 seconds** after `docker run`, then continue.

#### Step 2 — Verify LocalStack is healthy

**PowerShell / CMD:**

```powershell
curl http://localhost:4566/_localstack/health
```

Or use GitGuard:

```powershell
python main.py aws-check
```

You should see `LocalStack is reachable` when healthy.

#### Step 3 — Set environment variables

**PowerShell (current session):**

```powershell
$env:GITGUARD_AWS_ENABLED = "true"
$env:GITGUARD_AWS_ENDPOINT_URL = "http://localhost:4566"
$env:GITGUARD_AWS_REGION = "ap-south-1"
$env:GITGUARD_S3_BUCKET = "gitguard-reports"
$env:GITGUARD_DYNAMODB_TABLE = "gitguard-findings"
$env:GITGUARD_SNS_TOPIC_ARN = "arn:aws:sns:ap-south-1:000000000000:gitguard-alerts"
```

**CMD (current session):**

```cmd
set GITGUARD_AWS_ENABLED=true
set GITGUARD_AWS_ENDPOINT_URL=http://localhost:4566
set GITGUARD_AWS_REGION=ap-south-1
set GITGUARD_S3_BUCKET=gitguard-reports
set GITGUARD_DYNAMODB_TABLE=gitguard-findings
set GITGUARD_SNS_TOPIC_ARN=arn:aws:sns:ap-south-1:000000000000:gitguard-alerts
```

Alternatively, copy `.env.example` → `.env` and edit values (loaded automatically).

#### Step 4 — Create SNS topic (optional, for alerts)

**PowerShell / CMD:**

```powershell
aws --endpoint-url=http://localhost:4566 sns create-topic --name gitguard-alerts --region ap-south-1
```

#### Step 5 — Test GitGuard with AWS enabled

```powershell
python main.py aws-check
python main.py scan ./test_repo
python main.py report
python main.py dashboard
```

If LocalStack is **not running**, scans and reports still succeed — you'll see warnings like:

```
[WARNING] Could not connect to LocalStack. Skipping AWS exports.
```

#### Step 6 — Stop / remove LocalStack

**PowerShell / CMD:**

```powershell
docker stop gitguard-localstack
docker rm gitguard-localstack
```

### LocalStack quick setup (summary)

```bash
docker run -d -p 4566:4566 --name gitguard-localstack localstack/localstack
# wait ~15-30 seconds
python main.py aws-check
```

When `GITGUARD_AWS_ENDPOINT_URL` is set, GitGuard treats the environment as **LocalStack** and may auto-create the S3 bucket and DynamoDB table if they do not exist. Real AWS validation via STS requires `GITGUARD_ALLOW_REAL_AWS_VALIDATION=true`.

### Cloud-Native flow (optional)

```
Scanner / Findings
       ↓
Optional AWS Export Layer
   ├── S3  — HTML report + findings JSON
   ├── SNS — Critical finding alerts
   └── DynamoDB — finding summaries
```

## Architecture Overview

GitGuard follows a **hybrid / cloud-native-ready** layout: the core detection pipeline runs locally today, with optional AWS hooks prepared for future phases.

```
┌─────────────────────────────────────────────────────────────────┐
│                     Local execution (default)                   │
│  CLI ─► Ingestion ─► Scanner ─► SQLite ─► Dashboard             │
│         │                              │                        │
│         └── Git History / Monitor ─────┘                        │
│         └── Mock Rotation / Reports ───┘                        │
└─────────────────────────────────────────────────────────────────┘
                              │
              optional (GITGUARD_AWS_ENABLED=true)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              cloud_export/ — S3 · SNS · DynamoDB                │
│  Report upload · Critical alerts · Finding sync · LocalStack    │
└─────────────────────────────────────────────────────────────────┘
```

### Hybrid / Cloud-Native Design

| Layer | Role |
|-------|------|
| **CLI & Dashboard** | Primary interface — unchanged whether AWS is on or off |
| **Scanner / Rotation / Monitor** | Local detection and mock remediation (always available) |
| **SQLite** | Default persistence — no cloud dependency |
| **cloud_export/** | Optional S3, SNS, DynamoDB integrations |

### AWS Optionality

AWS is **off by default**. Set `GITGUARD_AWS_ENABLED=true` only when you are ready to wire cloud resources. If `boto3` is missing or credentials are unset, GitGuard continues in local mode with logged warnings — no crashes.

| Variable | Default | Purpose |
|----------|---------|---------|
| `GITGUARD_AWS_ENABLED` | `false` | Master switch for AWS features |
| `GITGUARD_AWS_REGION` | `ap-south-1` | AWS region |
| `GITGUARD_AWS_ENDPOINT_URL` | *(empty)* | Custom endpoint (e.g. LocalStack) |
| `GITGUARD_S3_BUCKET` | *(empty)* | Future report export target |
| `GITGUARD_DYNAMODB_TABLE` | *(empty)* | Future findings sync target |
| `GITGUARD_SNS_TOPIC_ARN` | *(empty)* | Future alert notifications |
| `GITGUARD_ALLOW_REAL_AWS_VALIDATION` | `false` | Allow STS connectivity checks |

Copy `.env.example` to `.env` to override defaults locally. Existing constants in `config.py` (paths, scanner thresholds, Flask settings) are unchanged.

## Project Structure

```
gitguard/
├── main.py                 # CLI entry point
├── config.py               # Local + optional AWS configuration
├── requirements.txt        # Python dependencies
├── cloud_export/           # Optional AWS export (S3, SNS, DynamoDB)
│   ├── aws_client.py       # boto3 client + LocalStack support
│   └── export.py           # Post-scan / post-report orchestration
├── scanner/                # Multi-threaded file scanner
│   └── repo_ingestion.py   # Hybrid ingestion + allowlist enforcement
├── allowlist.yaml          # Default scan allowlist
├── targets.yaml.example    # Batch scan template
├── regex_engine/           # 25+ secret detection patterns
├── entropy/                # Shannon entropy analysis
├── git_history/            # Git commit history scanner
├── rotation/               # Mock validation & rotation
├── monitor/                # Watchdog + polling file monitor
├── dashboard/              # Flask web application
├── reports/                # HTML report generator
├── database/               # SQLite persistence layer
├── templates/              # Jinja2 dashboard templates
├── utils/                  # Masking & logging utilities
└── test_repo_gen.py        # Demo repository generator
```

## Tech Stack

- **Python 3.11+** — core language
- **Flask** — web dashboard
- **GitPython** — Git history analysis
- **watchdog** — filesystem monitoring
- **Rich** — terminal UI
- **SQLite** — local database (default persistence)
- **Chart.js** — dashboard visualizations
- **Bootstrap 5** — responsive dark theme
- **python-dotenv** — optional `.env` loading
- **PyYAML** — allowlist and batch target configuration
- **boto3** — optional AWS SDK (unused when AWS disabled)

## Limitations

This is a **defensive-only** hackathon project:

- All credential validation is **mock/simulated** by default
- All rotation is **simulated** — no actual secrets are changed
- Runs **locally by default** — remote scanning requires explicit allowlist entries
- **No mass GitHub crawling** — only configured targets are cloned and scanned
- Regex/entropy can produce false positives — confidence scoring helps prioritize
- Designed for **demonstration purposes** at a hackathon
- Secrets in the test repo are **intentionally fake**

## Future Improvements

- Pre-commit hook integration and CI pipeline plugins
- Git history secret removal guidance (BFG/git-filter-repo workflows)
- Policy-as-code allowlist in organization settings
- Slack/Teams notification webhooks (beyond SNS)
- Fine-tuned false-positive suppression rules per repo
- Role-based dashboard access for multi-user SOC use

## Team

Built by Team at Amrita School of Engineering, Bengaluru.

## License

MIT — built for educational and hackathon purposes.
