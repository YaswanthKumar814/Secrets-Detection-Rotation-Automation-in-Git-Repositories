"""GitGuard configuration constants and optional AWS-aware settings."""

import os

# Load .env when present (optional — project runs without it)
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "gitguard.db")
LOG_DIR = os.path.join(BASE_DIR, "logs")
REPORT_DIR = os.path.join(BASE_DIR, "reports_output")

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

# Scanner settings
MAX_FILE_SIZE_KB = 512
SCAN_THREADS = 4
ENTROPY_THRESHOLD = 4.5

IGNORED_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".idea", ".vscode", "dist", "build"}
SCAN_EXTENSIONS = {
    ".env", ".yml", ".yaml", ".json", ".ini", ".txt", ".py", ".js", ".ts",
    ".jsx", ".tsx", ".rb", ".go", ".java", ".sh", ".bash", ".cfg", ".conf",
    ".properties", ".pem", ".key", ".toml", ".xml", ".tf", ".tfvars",
    ".dockerfile", ".dockerignore", ".md",
}
SCAN_FILENAMES = {"Dockerfile", ".env", ".env.local", ".env.production", "docker-compose.yml"}

# Dashboard
FLASK_HOST = "127.0.0.1"
FLASK_PORT = 5000
FLASK_DEBUG = False

# Monitoring
MONITOR_POLL_INTERVAL = 3  # seconds for polling fallback

# Repository ingestion & allowlist
ALLOWLIST_PATH = os.getenv(
    "GITGUARD_ALLOWLIST_PATH",
    os.path.join(BASE_DIR, "allowlist.yaml"),
)
CLONE_DEPTH = int(os.getenv("GITGUARD_CLONE_DEPTH", "1"))
CLONE_TIMEOUT_SEC = int(os.getenv("GITGUARD_CLONE_TIMEOUT_SEC", "120"))


def _env_bool(name: str, default: bool = False) -> bool:
    """Parse a boolean environment variable."""
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


ENFORCE_ALLOWLIST_ON_LOCAL_SCAN = _env_bool("GITGUARD_ENFORCE_ALLOWLIST", default=False)


# --- Optional AWS configuration (disabled by default) ---
AWS_ENABLED = _env_bool("GITGUARD_AWS_ENABLED", default=False)
AWS_REGION = os.getenv("GITGUARD_AWS_REGION", "ap-south-1")
AWS_ENDPOINT_URL = os.getenv("GITGUARD_AWS_ENDPOINT_URL", "").strip() or None
S3_BUCKET = os.getenv("GITGUARD_S3_BUCKET", "").strip() or None
DYNAMODB_TABLE = os.getenv("GITGUARD_DYNAMODB_TABLE", "").strip() or None
SNS_TOPIC_ARN = os.getenv("GITGUARD_SNS_TOPIC_ARN", "").strip() or None
ALLOW_REAL_AWS_VALIDATION = _env_bool("GITGUARD_ALLOW_REAL_AWS_VALIDATION", default=False)


def get_aws_config() -> dict:
    """Return AWS-related settings as a plain dict (for logging and future hooks)."""
    return {
        "enabled": AWS_ENABLED,
        "region": AWS_REGION,
        "endpoint_url": AWS_ENDPOINT_URL,
        "s3_bucket": S3_BUCKET,
        "dynamodb_table": DYNAMODB_TABLE,
        "sns_topic_arn": SNS_TOPIC_ARN,
        "allow_real_aws_validation": ALLOW_REAL_AWS_VALIDATION,
    }
