"""Scan Git commit history for leaked secrets."""

import os
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from regex_engine import scan_line
from entropy import shannon_entropy
from utils.masking import mask_secret
from utils.logger import log
from database import Database
from risk_intel import analyze_finding, get_attack_mapping


def scan_history(repo_path: str, db: Database, max_commits: int = 100, show_progress: bool = True) -> dict:
    """Scan commit diffs for secrets. Returns summary."""
    try:
        import git
    except ImportError:
        log("error", "history", "GitPython not installed")
        return {"error": "GitPython required"}

    repo_path = os.path.abspath(repo_path)
    try:
        repo = git.Repo(repo_path)
    except git.InvalidGitRepositoryError:
        log("error", "history", f"{repo_path} is not a git repository")
        return {"error": "Not a git repository"}

    repo_name = os.path.basename(repo_path)
    repo_id = db.add_repo(repo_path, repo_name)
    scan_id = db.start_scan(repo_id, "history_scan")
    log("info", "history", f"Scanning commit history for {repo_path}")

    commits = list(repo.iter_commits("HEAD", max_count=max_commits))
    findings = []

    def _process_commit(commit):
        results = []
        try:
            if commit.parents:
                diffs = commit.parents[0].diff(commit, create_patch=True)
            else:
                diffs = commit.diff(git.NULL_TREE, create_patch=True)
        except Exception:
            return results

        for diff in diffs:
            try:
                patch = diff.diff.decode("utf-8", errors="ignore")
            except Exception:
                continue
            fpath = str(diff.b_path or diff.a_path or "unknown")
            for lineno, line in enumerate(patch.splitlines(), 1):
                if not line.startswith("+"):
                    continue
                content = line[1:]
                for m in scan_line(content):
                    ent = shannon_entropy(m["matched_text"])
                    meta = analyze_finding(
                        secret_type=m["secret_type"],
                        matched_text=m["matched_text"],
                        file_path=fpath,
                        line_number=lineno,
                        line_content=content,
                        entropy=ent,
                        severity_base=m["severity_base"],
                        in_history=True,
                    )
                    attack = get_attack_mapping(m["secret_type"])
                    results.append({
                        "commit_hash": commit.hexsha[:8],
                        "author": str(commit.author),
                        "commit_date": commit.committed_datetime.isoformat(),
                        "file_path": fpath,
                        "secret_type": m["secret_type"],
                        "masked_preview": mask_secret(m["matched_text"]),
                        "severity": meta["severity"],
                        "attack_technique": attack["id"],
                        "confidence_label": meta["confidence_label"],
                        "exposure_level": meta["exposure_level"],
                    })
        return results

    if show_progress:
        with Progress(
            SpinnerColumn(), TextColumn("[bold magenta]{task.description}"),
            BarColumn(), TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
        ) as progress:
            task = progress.add_task("Scanning commits", total=len(commits))
            for commit in commits:
                findings.extend(_process_commit(commit))
                progress.advance(task)
    else:
        for commit in commits:
            findings.extend(_process_commit(commit))

    for f in findings:
        db.add_history_finding(repo_id=repo_id, **f)

    db.finish_scan(scan_id, len(commits), len(findings))
    log("info", "history", f"History scan complete: {len(commits)} commits, {len(findings)} leaks found")

    return {
        "commits_scanned": len(commits),
        "leaks_found": len(findings),
        "findings": findings,
    }
