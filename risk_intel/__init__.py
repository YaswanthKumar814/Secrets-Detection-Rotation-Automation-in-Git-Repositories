"""Lightweight risk intelligence — scoring, ATT&CK, context, grouping."""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Optional

# --- ATT&CK mapping (dictionary-driven) ---
ATTACK_MAP: dict[str, dict] = {
    "AWS Access Key": {"id": "T1552.001", "name": "Credentials In Files", "tactic": "Credential Access"},
    "AWS Secret Key": {"id": "T1552.001", "name": "Credentials In Files", "tactic": "Credential Access"},
    "GitHub Token (classic)": {"id": "T1552.001", "name": "Credentials In Files", "tactic": "Credential Access"},
    "GitHub Token (fine-grained)": {"id": "T1552.001", "name": "Credentials In Files", "tactic": "Credential Access"},
    "GitHub OAuth": {"id": "T1552.001", "name": "Credentials In Files", "tactic": "Credential Access"},
    "GitLab Token": {"id": "T1552.001", "name": "Credentials In Files", "tactic": "Credential Access"},
    "Google API Key": {"id": "T1552.001", "name": "Credentials In Files", "tactic": "Credential Access"},
    "Private Key Block": {"id": "T1552.004", "name": "Private Keys", "tactic": "Credential Access"},
    "Database URL": {"id": "T1552.001", "name": "Credentials In Files", "tactic": "Credential Access"},
    "Stripe Secret Key": {"id": "T1552.001", "name": "Credentials In Files", "tactic": "Credential Access"},
    "JWT Token": {"id": "T1552.001", "name": "Credentials In Files", "tactic": "Credential Access"},
    "Bearer Token": {"id": "T1552.001", "name": "Credentials In Files", "tactic": "Credential Access"},
    "Basic Auth": {"id": "T1552.001", "name": "Credentials In Files", "tactic": "Credential Access"},
}
DEFAULT_ATTACK = {"id": "T1552", "name": "Unsecured Credentials", "tactic": "Credential Access"}

CLOUD_CREDENTIAL_TYPES = {
    "AWS Access Key", "AWS Secret Key", "Google API Key", "Stripe Secret Key",
    "GitHub Token (classic)", "GitHub Token (fine-grained)", "GitHub OAuth",
    "GitLab Token", "OpenAI API Key", "Slack Bot Token", "Slack User Token",
}

SENSITIVE_FILES = {
    ".env", ".env.local", ".env.production", "credentials", "secrets",
    "docker-compose.yml", "terraform.tfvars", "kubeconfig", "id_rsa",
}
SENSITIVE_EXTENSIONS = {".env", ".pem", ".key", ".pfx", ".p12", ".tfvars"}
SENSITIVE_PATH_PARTS = {"/config/", "/deploy/", "/secrets/", "/.aws/", "/infra/"}

EXAMPLE_MARKERS = re.compile(
    r"(?i)(example|placeholder|sample|fake|dummy|test_|_test|demo_|not_a_real|"
    r"your[_-]?key|changeme|xxx+|replace[_-]?me|lorem|ipsum|todo|fixme|"
    r"insert[_-]?here|redacted|<your|<api[_-]?key>)"
)
FAKE_VALUE_MARKERS = re.compile(
    r"(?i)(fake|test|demo|sample|example|xxxx|000000|111111|password123|"
    r"sk-test|AKIAFAKE|notreal|changeme)"
)

REMEDIATION: dict[str, str] = {
    "AWS Access Key": "Rotate the IAM access key in AWS Console, revoke the exposed key, and move secrets to AWS Secrets Manager.",
    "AWS Secret Key": "Rotate IAM secret key immediately, audit CloudTrail for misuse, and use Secrets Manager or SSM Parameter Store.",
    "GitHub Token (classic)": "Revoke the token in GitHub Settings → Developer settings, rotate, and use GitHub Actions secrets or OIDC.",
    "GitHub Token (fine-grained)": "Revoke the fine-grained PAT, audit repository access logs, and prefer short-lived tokens.",
    "Private Key Block": "Revoke the key pair, generate new keys, and never commit private keys — use a secrets vault.",
    "Database URL": "Change database credentials, rotate passwords, and use environment variables or a vault for connection strings.",
    "Stripe Secret Key": "Roll the live key in Stripe Dashboard, review payment logs for abuse, and restrict API key scope.",
    "OpenAI API Key": "Regenerate the API key, review usage billing, and store keys in environment variables only.",
    "Slack Bot Token": "Rotate the bot token in Slack app settings and audit workspace access.",
    "JWT Token": "Invalidate active sessions, rotate signing secrets, and shorten token lifetimes.",
    "Generic API Key": "Rotate the API key, remove from source control, and use environment variables or a secrets manager.",
    "Generic Secret": "Rotate the credential, remove from the repository, and enable pre-commit secret scanning.",
}
DEFAULT_REMEDIATION = "Remove the secret from Git history (e.g. git filter-repo), rotate the credential, and enable pre-commit scanning with GitGuard or gitleaks."


def get_attack_mapping(secret_type: str) -> dict:
    return ATTACK_MAP.get(secret_type, DEFAULT_ATTACK)


def get_remediation(secret_type: str, severity: str) -> str:
    for key, tip in REMEDIATION.items():
        if key.lower() in secret_type.lower():
            return tip
    if severity in ("Critical", "High"):
        return "Rotate this credential immediately, remove from Git history, and enable pre-commit secret scanning."
    return DEFAULT_REMEDIATION


def _file_sensitivity(file_path: str) -> tuple[int, str]:
    """Return sensitivity boost 0-25 and reason."""
    base = os.path.basename(file_path).lower()
    path_lower = file_path.replace("\\", "/").lower()
    if base in SENSITIVE_FILES or any(base.endswith(ext) for ext in SENSITIVE_EXTENSIONS):
        return 20, f"Sensitive file: {base}"
    if any(part in path_lower for part in SENSITIVE_PATH_PARTS):
        return 15, "Sensitive directory path"
    if base in ("docker-compose.yml", "dockerfile", "terraform.tf", "main.tf"):
        return 12, "Infrastructure/config file"
    if base.endswith((".md", ".rst", ".txt")) and "readme" in path_lower:
        return -10, "Documentation file"
    if "/docs/" in path_lower or "/examples/" in path_lower:
        return -8, "Documentation/examples path"
    if "/test" in path_lower or base.startswith("test_"):
        return -5, "Test path"
    return 0, ""


def _context_analysis(line: str, matched_text: str, file_path: str) -> dict:
    """Detect likely false-positive context."""
    flags: list[str] = []
    penalty = 0

    if EXAMPLE_MARKERS.search(line):
        flags.append("example_placeholder")
        penalty += 25
    if FAKE_VALUE_MARKERS.search(matched_text):
        flags.append("fake_test_value")
        penalty += 20
    stripped = line.strip()
    if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
        flags.append("commented_line")
        penalty += 15
    if re.search(r'["\']?(example|sample|demo|test)["\']?\s*[:=]', line, re.I):
        flags.append("labeled_example")
        penalty += 15

    base = os.path.basename(file_path).lower()
    if base.endswith(".md") or "readme" in file_path.lower():
        flags.append("markdown_doc")
        penalty += 10

    return {"context_flags": flags, "context_penalty": penalty, "is_likely_example": penalty >= 20}


def compute_confidence(
    secret_type: str,
    matched_text: str,
    file_path: str,
    entropy: float,
    context: dict,
) -> tuple[int, str, float]:
    """Return (score 0-100, label High/Medium/Low, numeric 0-1)."""
    score = 45
    if entropy >= 4.5:
        score += 15
    if entropy >= 5.5:
        score += 10
    if secret_type in CLOUD_CREDENTIAL_TYPES:
        score += 15
    sens_boost, _ = _file_sensitivity(file_path)
    if sens_boost > 0:
        score += min(15, sens_boost)
    if len(matched_text) >= 20:
        score += 5

    score -= context.get("context_penalty", 0)
    if context.get("is_likely_example"):
        score -= 15

    score = max(5, min(98, score))

    if score >= 75:
        label = "High"
    elif score >= 45:
        label = "Medium"
    else:
        label = "Low"

    return score, label, round(score / 100, 2)


def compute_severity(
    secret_type: str,
    severity_base: int,
    entropy: float,
    file_path: str,
    context: dict,
    in_history: bool = False,
) -> tuple[int, str]:
    """Improved deterministic severity 0-100."""
    score = severity_base
    sens_boost, _ = _file_sensitivity(file_path)
    score += max(0, sens_boost) // 2

    if entropy >= 5.5:
        score = min(100, score + 8)
    elif entropy >= 4.5:
        score = min(100, score + 4)
    elif entropy < 3.0:
        score = max(0, score - 12)

    if secret_type in CLOUD_CREDENTIAL_TYPES:
        score = min(100, score + 5)

    score -= context.get("context_penalty", 0) // 2

    if in_history:
        score = min(100, score + 8)

    score = max(0, min(100, score))

    if score >= 85:
        return score, "Critical"
    if score >= 65:
        return score, "High"
    if score >= 40:
        return score, "Medium"
    return score, "Low"


def compute_exposure(
    secret_type: str,
    file_path: str,
    occurrence_count: int = 1,
    in_history: bool = False,
    is_remote_scan: bool = False,
) -> tuple[int, str, str]:
    """Return (exposure_score 0-100, level, reason)."""
    score = 30
    reasons: list[str] = []

    if in_history:
        score += 25
        reasons.append("exposed in Git history")
    sens_boost, sens_reason = _file_sensitivity(file_path)
    if sens_boost >= 15:
        score += 20
        reasons.append(sens_reason)
    elif sens_boost > 0:
        score += 10
        if sens_reason:
            reasons.append(sens_reason)

    if secret_type in CLOUD_CREDENTIAL_TYPES:
        score += 15
        reasons.append("cloud credential type")

    if occurrence_count > 3:
        score += min(20, occurrence_count * 2)
        reasons.append(f"repeated {occurrence_count} times")

    if is_remote_scan:
        score += 5
        reasons.append("remote repository source")

    if file_path.endswith((".env", ".pem", ".key")) or ".env" in file_path:
        score += 10
        reasons.append("plaintext credential storage")

    score = max(0, min(100, score))
    if score >= 80:
        level = "Critical"
    elif score >= 60:
        level = "High"
    elif score >= 35:
        level = "Medium"
    else:
        level = "Low"

    reason = "; ".join(reasons[:4]) if reasons else "standard repository exposure"
    return score, level, reason


def analyze_finding(
    *,
    secret_type: str,
    matched_text: str,
    file_path: str,
    line_number: int,
    line_content: str = "",
    entropy: float,
    severity_base: int,
    in_history: bool = False,
    is_remote_scan: bool = False,
) -> dict:
    """Enrich a raw match with risk intelligence fields."""
    context = _context_analysis(line_content or matched_text, matched_text, file_path)
    sev_score, severity = compute_severity(
        secret_type, severity_base, entropy, file_path, context, in_history
    )
    conf_score, conf_label, conf_numeric = compute_confidence(
        secret_type, matched_text, file_path, entropy, context
    )
    attack = get_attack_mapping(secret_type)
    exp_score, exp_level, exp_reason = compute_exposure(
        secret_type, file_path, 1, in_history, is_remote_scan
    )

    return {
        "severity": severity,
        "severity_score": sev_score,
        "confidence": conf_numeric,
        "confidence_score": conf_score,
        "confidence_label": conf_label,
        "attack_technique": attack["id"],
        "attack_name": attack["name"],
        "attack_tactic": attack["tactic"],
        "exposure_score": exp_score,
        "exposure_level": exp_level,
        "exposure_reason": exp_reason,
        "remediation": get_remediation(secret_type, severity),
        "context_flags": ",".join(context["context_flags"]) if context["context_flags"] else "",
        "is_likely_example": context["is_likely_example"],
    }


def _fingerprint(finding: dict) -> str:
    """Stable key for grouping duplicate secrets."""
    material = "|".join([
        finding.get("secret_type", ""),
        finding.get("masked_preview", "")[:24],
        finding.get("matched_text", "")[:16],
    ])
    return hashlib.sha256(material.encode()).hexdigest()[:16]


def group_findings(findings: list[dict]) -> list[dict]:
    """Group duplicate findings; preserve visibility with occurrence counts."""
    groups: dict[str, dict] = {}

    for f in findings:
        key = _fingerprint(f)
        if key not in groups:
            groups[key] = {
                **f,
                "occurrence_count": 1,
                "affected_files": [f.get("file_path", "")],
                "line_numbers": [f.get("line_number")],
                "group_key": key,
            }
        else:
            g = groups[key]
            g["occurrence_count"] += 1
            fp = f.get("file_path", "")
            if fp and fp not in g["affected_files"]:
                g["affected_files"].append(fp)
            g["line_numbers"].append(f.get("line_number"))
            if f.get("severity_score", 0) > g.get("severity_score", 0):
                g["severity_score"] = f["severity_score"]
                g["severity"] = f["severity"]
            if f.get("confidence_score", 0) > g.get("confidence_score", 0):
                g["confidence_score"] = f["confidence_score"]
                g["confidence_label"] = f["confidence_label"]
                g["confidence"] = f["confidence"]

    result = []
    for g in groups.values():
        exp_score, exp_level, exp_reason = compute_exposure(
            g.get("secret_type", ""),
            g["affected_files"][0] if g["affected_files"] else "",
            g["occurrence_count"],
        )
        g["exposure_score"] = exp_score
        g["exposure_level"] = exp_level
        g["exposure_reason"] = exp_reason
        g["affected_files_json"] = json.dumps(g["affected_files"][:50])
        if g["occurrence_count"] > 1:
            g["file_path"] = f"{g['affected_files'][0]} (+{len(g['affected_files']) - 1} files)"
        result.append(g)

    result.sort(key=lambda x: (-x.get("severity_score", 0), -x.get("confidence_score", 0)))
    return result


def enrich_and_group(raw_findings: list[dict], **analyze_kwargs) -> list[dict]:
    """Analyze each finding then group duplicates."""
    enriched = []
    for f in raw_findings:
        meta = analyze_finding(
            secret_type=f.get("secret_type", ""),
            matched_text=f.get("matched_text", ""),
            file_path=f.get("file_path", ""),
            line_number=f.get("line_number", 0),
            line_content=f.get("line_content", ""),
            entropy=f.get("entropy", 0),
            severity_base=f.get("severity_base", 50),
            **analyze_kwargs,
        )
        enriched.append({**f, **meta})
    return group_findings(enriched)
