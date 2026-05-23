"""Hybrid repository ingestion with mandatory allowlist enforcement."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Generator, Optional
from urllib.parse import urlparse

import yaml

from config import ALLOWLIST_PATH, BASE_DIR, CLONE_DEPTH, CLONE_TIMEOUT_SEC
from git_history import scan_history
from scanner import scan_repository
from utils.logger import log


class SourceType(str, Enum):
    LOCAL = "local"
    REMOTE = "remote"


class AllowlistError(Exception):
    """Raised when a target fails allowlist validation."""


class CloneError(Exception):
    """Raised when git clone fails."""


@dataclass
class IngestionMetadata:
    source_type: str
    source_target: str
    repository_url: Optional[str] = None
    workspace_path: Optional[str] = None
    allowlist_passed: bool = False
    allowlist_reason: str = ""
    clone_status: str = "not_required"
    scan_started_at: str = field(default_factory=lambda: _utc_now())
    scan_finished_at: Optional[str] = None
    cleanup_status: str = "pending"
    file_findings: int = 0
    history_findings: int = 0
    error: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_remote_target(target: str) -> bool:
    """Return True when the target looks like a remote Git URL."""
    target = target.strip()
    return target.startswith(("http://", "https://", "git@", "ssh://"))


def normalize_repo_url(url: str) -> str:
    """Normalize a GitHub/Git remote URL for allowlist comparison."""
    url = url.strip().rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]

    if url.startswith("git@"):
        # git@github.com:owner/repo -> https://github.com/owner/repo
        match = re.match(r"git@([^:]+):(.+)", url)
        if match:
            host, path = match.groups()
            return f"https://{host}/{path}".lower()

    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = (parsed.netloc or parsed.path.split("/")[0]).lower()
    path = parsed.path.strip("/")
    if not path and parsed.netloc:
        path = parsed.netloc.split("/", 1)[-1] if "/" in parsed.netloc else ""
    return f"https://{host}/{path}".lower().rstrip("/")


def parse_github_owner(url: str) -> Optional[str]:
    """Extract the repository owner from a GitHub-style URL."""
    normalized = normalize_repo_url(url)
    match = re.match(r"https://[^/]+/([^/]+)/", normalized + "/")
    return match.group(1).lower() if match else None


def normalize_local_path(path: str) -> str:
    """Resolve a local path relative to project root when needed."""
    path = os.path.expanduser(path.strip())
    if not os.path.isabs(path):
        path = os.path.join(BASE_DIR, path)
    return os.path.normpath(os.path.abspath(path))


class Allowlist:
    """Configuration-driven allowlist for local and remote scan targets."""

    def __init__(
        self,
        allowed_local_paths: Optional[list[str]] = None,
        allowed_repositories: Optional[list[str]] = None,
        allowed_github_users: Optional[list[str]] = None,
    ):
        self.allowed_local_paths = {
            normalize_local_path(p) for p in (allowed_local_paths or [])
        }
        self.allowed_repositories = {
            normalize_repo_url(u) for u in (allowed_repositories or [])
        }
        self.allowed_github_users = {u.lower() for u in (allowed_github_users or [])}

    @classmethod
    def from_file(cls, path: str) -> Allowlist:
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Allowlist file not found: {path}")
        with open(path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict) -> Allowlist:
        return cls(
            allowed_local_paths=data.get("allowed_local_paths", []),
            allowed_repositories=data.get("allowed_repositories", []),
            allowed_github_users=data.get("allowed_github_users", []),
        )

    @classmethod
    def load_default(cls) -> Allowlist:
        if os.path.isfile(ALLOWLIST_PATH):
            return cls.from_file(ALLOWLIST_PATH)
        return cls()

    def validate_local(self, path: str) -> tuple[bool, str]:
        resolved = normalize_local_path(path)
        if not self.allowed_local_paths:
            return False, "No local paths configured in allowlist"

        for allowed in self.allowed_local_paths:
            if resolved == allowed:
                return True, f"Exact match: {allowed}"
            try:
                if os.path.commonpath([resolved, allowed]) == allowed:
                    return True, f"Under allowed path: {allowed}"
            except ValueError:
                continue

        return False, f"Local path not allowlisted: {resolved}"

    def validate_remote(self, url: str) -> tuple[bool, str]:
        normalized = normalize_repo_url(url)
        if not self.allowed_repositories and not self.allowed_github_users:
            return False, "No remote repositories or GitHub users configured in allowlist"

        if normalized in self.allowed_repositories:
            return True, f"Repository allowlisted: {normalized}"

        owner = parse_github_owner(url)
        if owner and owner in self.allowed_github_users:
            return True, f"GitHub user/org allowlisted: {owner}"

        return False, f"Remote repository not allowlisted: {normalized}"

    def validate_target(self, target: str) -> tuple[bool, str]:
        if is_remote_target(target):
            return self.validate_remote(target)
        return self.validate_local(target)


def _remove_workspace(path: str) -> str:
    """Remove a temporary workspace and return cleanup status."""
    import stat
    import time

    def _on_rm_error(func, file_path, _exc_info):
        try:
            os.chmod(file_path, stat.S_IWRITE)
            func(file_path)
        except Exception:
            pass

    if not path or not os.path.exists(path):
        return "success"

    for attempt in range(3):
        try:
            shutil.rmtree(path, onerror=_on_rm_error)
        except Exception:
            pass
        if not os.path.exists(path):
            return "success"
        if attempt < 2:
            time.sleep(0.3 * (attempt + 1))
    return "partial"


def log_ingestion(db, metadata: IngestionMetadata, level: str = "INFO") -> None:
    """Write ingestion metadata to structured logs."""
    source = metadata.repository_url or metadata.source_target
    message = (
        f"Ingestion {metadata.source_type}: {source} | "
        f"allowlist={'pass' if metadata.allowlist_passed else 'fail'} | "
        f"clone={metadata.clone_status} | cleanup={metadata.cleanup_status}"
    )
    log(level.lower(), "ingestion", message, metadata.to_json())
    if db:
        db.add_log(level, "ingestion", message, metadata.to_json())


def clone_repository(url: str, dest: str, shallow: bool = True) -> None:
    """Clone a remote repository into dest using git CLI."""
    cmd = ["git", "clone"]
    if shallow:
        cmd.extend(["--depth", str(CLONE_DEPTH)])
    cmd.extend([url, dest])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=CLONE_TIMEOUT_SEC,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CloneError(f"Git clone timed out after {CLONE_TIMEOUT_SEC}s") from exc
    except FileNotFoundError as exc:
        raise CloneError("git executable not found — install Git to scan remote repositories") from exc

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "unknown error").strip()
        raise CloneError(f"Git clone failed: {detail}")


@contextmanager
def temporary_workspace(prefix: str = "gitguard_") -> Generator[str, None, None]:
    """Create and always remove a temporary workspace directory."""
    workspace = tempfile.mkdtemp(prefix=prefix)
    try:
        yield workspace
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


@contextmanager
def ingest_target(
    target: str,
    allowlist: Allowlist,
    *,
    enforce_allowlist: bool = True,
) -> Generator[tuple[str, IngestionMetadata], None, None]:
    """Validate, optionally clone, and yield a scannable workspace path."""
    metadata = IngestionMetadata(
        source_type=SourceType.REMOTE.value if is_remote_target(target) else SourceType.LOCAL.value,
        source_target=target.strip(),
    )
    workspace: Optional[str] = None
    cleanup_needed = False

    try:
        if enforce_allowlist:
            passed, reason = allowlist.validate_target(target)
            metadata.allowlist_passed = passed
            metadata.allowlist_reason = reason
            if not passed:
                raise AllowlistError(reason)
        else:
            metadata.allowlist_passed = True
            metadata.allowlist_reason = "Allowlist enforcement disabled"

        if is_remote_target(target):
            metadata.repository_url = normalize_repo_url(target)
            workspace = tempfile.mkdtemp(prefix="gitguard_clone_")
            cleanup_needed = True
            metadata.workspace_path = workspace
            log("info", "ingestion", f"Cloning {target} -> {workspace}")
            clone_repository(target, workspace)
            metadata.clone_status = "success"
            yield workspace, metadata
        else:
            workspace = normalize_local_path(target)
            metadata.workspace_path = workspace
            metadata.clone_status = "not_required"
            if not os.path.isdir(workspace):
                raise FileNotFoundError(f"Local repository path not found: {workspace}")
            yield workspace, metadata

    except Exception as exc:
        metadata.error = str(exc)
        if metadata.clone_status == "not_required" and is_remote_target(target):
            metadata.clone_status = "failed"
        elif metadata.clone_status not in ("success", "not_required"):
            metadata.clone_status = "failed"
        raise
    finally:
        if cleanup_needed and workspace:
            metadata.cleanup_status = _remove_workspace(workspace)
            log("info", "ingestion", f"Cleaned up temporary workspace: {workspace} ({metadata.cleanup_status})")
        elif not cleanup_needed:
            metadata.cleanup_status = "not_required"


def run_ingestion_scan(
    target: str,
    db,
    allowlist: Optional[Allowlist] = None,
    *,
    enforce_allowlist: bool = True,
    run_history: bool = False,
    show_progress: bool = True,
) -> dict:
    """Validate, ingest, scan, optionally history-scan, and cleanup a target."""
    allowlist = allowlist or Allowlist.load_default()
    metadata = IngestionMetadata(
        source_type=SourceType.REMOTE.value if is_remote_target(target) else SourceType.LOCAL.value,
        source_target=target.strip(),
    )

    scan_result: dict = {"metadata": metadata, "file_scan": None, "history_scan": None, "success": False}

    try:
        with ingest_target(target, allowlist, enforce_allowlist=enforce_allowlist) as (workspace, meta):
            metadata = meta
            metadata.workspace_path = workspace

            file_result = scan_repository(workspace, db, show_progress=show_progress)
            metadata.file_findings = len(file_result.get("findings", []))
            scan_result["file_scan"] = file_result

            if run_history:
                history_result = scan_history(workspace, db, show_progress=show_progress)
                if "error" in history_result:
                    metadata.error = history_result["error"]
                else:
                    metadata.history_findings = len(history_result.get("findings", []))
                scan_result["history_scan"] = history_result

            scan_result["success"] = True

            try:
                from cloud_export.export import post_scan_exports
                scan_result["aws_export"] = post_scan_exports(
                    workspace,
                    file_result.get("findings", []),
                    scan_id=file_result.get("scan_id"),
                    db=db,
                )
            except Exception:
                scan_result["aws_export"] = {"skipped": True}

    except (AllowlistError, CloneError, FileNotFoundError) as exc:
        metadata.error = str(exc)
        scan_result["error"] = str(exc)
    except Exception as exc:
        metadata.error = str(exc)
        scan_result["error"] = str(exc)
        log("error", "ingestion", f"Ingestion failed for {target}: {exc}")
    finally:
        metadata.scan_finished_at = _utc_now()
        log_ingestion(db, metadata, level="ERROR" if metadata.error else "INFO")

    scan_result["metadata"] = metadata
    return scan_result


def load_targets_file(path: str) -> tuple[Allowlist, dict]:
    """Load allowlist rules and scan targets from a YAML file."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Targets file not found: {path}")

    with open(path, encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}

    allowlist = Allowlist.from_dict(data)
    targets = data.get("scan_targets", {}) or {}
    return allowlist, targets


def scan_targets_batch(
    targets_path: str,
    db,
    *,
    run_history: bool = False,
    show_progress: bool = True,
) -> dict:
    """Scan all configured targets, continuing on partial failures."""
    allowlist, targets = load_targets_file(targets_path)
    local_targets = targets.get("local", []) or []
    remote_targets = targets.get("repositories", []) or []
    all_targets = [(t, SourceType.LOCAL) for t in local_targets] + [
        (t, SourceType.REMOTE) for t in remote_targets
    ]

    results: list[dict] = []
    summary = {
        "total": len(all_targets),
        "succeeded": 0,
        "failed": 0,
        "skipped": 0,
        "file_findings": 0,
        "history_findings": 0,
    }

    for target, source_type in all_targets:
        passed, reason = allowlist.validate_target(target)
        if not passed:
            meta = IngestionMetadata(
                source_type=source_type.value,
                source_target=target,
                allowlist_passed=False,
                allowlist_reason=reason,
                clone_status="skipped",
                cleanup_status="not_required",
                error=reason,
                scan_finished_at=_utc_now(),
            )
            log_ingestion(db, meta, level="WARNING")
            results.append({"target": target, "success": False, "skipped": True, "error": reason, "metadata": meta})
            summary["skipped"] += 1
            continue

        result = run_ingestion_scan(
            target,
            db,
            allowlist=allowlist,
            enforce_allowlist=True,
            run_history=run_history,
            show_progress=show_progress,
        )
        result["target"] = target
        results.append(result)

        if result.get("success"):
            summary["succeeded"] += 1
            summary["file_findings"] += result["metadata"].file_findings
            summary["history_findings"] += result["metadata"].history_findings
        else:
            summary["failed"] += 1

    return {"summary": summary, "results": results}
