"""Regex-based secret detection patterns."""

import re
from dataclasses import dataclass

@dataclass
class SecretPattern:
    name: str
    pattern: re.Pattern
    severity_base: int  # 0-100
    description: str

PATTERNS: list[SecretPattern] = [
    SecretPattern("AWS Access Key", re.compile(r'(?:AKIA[0-9A-Z]{16})'), 95,
                  "AWS IAM access key — grants cloud access"),
    SecretPattern("AWS Secret Key", re.compile(r'(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'), 98,
                  "AWS secret access key — full cloud control"),
    SecretPattern("GitHub Token (classic)", re.compile(r'ghp_[A-Za-z0-9_]{36,}'), 90,
                  "GitHub personal access token"),
    SecretPattern("GitHub Token (fine-grained)", re.compile(r'github_pat_[A-Za-z0-9_]{22,}'), 90,
                  "GitHub fine-grained PAT"),
    SecretPattern("GitHub OAuth", re.compile(r'gho_[A-Za-z0-9]{36,}'), 85,
                  "GitHub OAuth access token"),
    SecretPattern("GitLab Token", re.compile(r'glpat-[A-Za-z0-9\-_]{20,}'), 88,
                  "GitLab personal access token"),
    SecretPattern("Google API Key", re.compile(r'AIza[0-9A-Za-z\-_]{35}'), 80,
                  "Google Cloud / Maps API key"),
    SecretPattern("Slack Bot Token", re.compile(r'xoxb-[0-9]{10,}-[0-9A-Za-z]{20,}'), 85,
                  "Slack bot token"),
    SecretPattern("Slack User Token", re.compile(r'xoxp-[0-9]{10,}-[0-9A-Za-z]{20,}'), 85,
                  "Slack user OAuth token"),
    SecretPattern("Slack Webhook", re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'), 75,
                  "Slack incoming webhook URL"),
    SecretPattern("Stripe Secret Key", re.compile(r'sk_live_[0-9a-zA-Z]{24,}'), 95,
                  "Stripe live secret key — payment access"),
    SecretPattern("Stripe Publishable Key", re.compile(r'pk_live_[0-9a-zA-Z]{24,}'), 40,
                  "Stripe publishable key — low risk"),
    SecretPattern("OpenAI API Key", re.compile(r'sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}'), 88,
                  "OpenAI API key"),
    SecretPattern("Twilio API Key", re.compile(r'SK[0-9a-fA-F]{32}'), 82,
                  "Twilio API key"),
    SecretPattern("Twilio Account SID", re.compile(r'AC[0-9a-fA-F]{32}'), 60,
                  "Twilio Account SID"),
    SecretPattern("SendGrid Key", re.compile(r'SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{22,}'), 85,
                  "SendGrid API key"),
    SecretPattern("JWT Token", re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'), 70,
                  "JSON Web Token — may contain claims"),
    SecretPattern("Private Key Block", re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'), 95,
                  "Private key file — critical credential"),
    SecretPattern("Bearer Token", re.compile(r'[Bb]earer\s+[A-Za-z0-9\-_.~+/]{20,}'), 75,
                  "Bearer authorization token"),
    SecretPattern("Basic Auth", re.compile(r'[Bb]asic\s+[A-Za-z0-9+/=]{20,}'), 70,
                  "HTTP Basic auth credential"),
    SecretPattern("Database URL", re.compile(r'(?:mysql|postgres|postgresql|mongodb|redis|mssql)://[^\s"\']+:[^\s"\']+@[^\s"\']+'), 92,
                  "Database connection string with credentials"),
    SecretPattern("Generic API Key", re.compile(r'(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["\']?([A-Za-z0-9\-_]{16,})["\']?', re.IGNORECASE), 65,
                  "Generic API key assignment"),
    SecretPattern("Generic Secret", re.compile(r'(?:secret|password|passwd|token|auth_token|access_token)\s*[=:]\s*["\']?([A-Za-z0-9\-_!@#$%^&*]{8,})["\']?', re.IGNORECASE), 60,
                  "Generic secret/password assignment"),
    SecretPattern("Heroku API Key", re.compile(r'[hH]eroku.*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'), 80,
                  "Heroku API key"),
    SecretPattern("Mailgun Key", re.compile(r'key-[0-9a-zA-Z]{32}'), 78,
                  "Mailgun API key"),
]


def scan_line(line: str) -> list[dict]:
    """Scan a single line for secret patterns. Returns list of match dicts."""
    results = []
    for pat in PATTERNS:
        for match in pat.pattern.finditer(line):
            matched_text = match.group(0)
            results.append({
                "secret_type": pat.name,
                "matched_text": matched_text,
                "severity_base": pat.severity_base,
                "description": pat.description,
                "start": match.start(),
                "end": match.end(),
            })
    return results
