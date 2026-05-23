"""Repository file scanner with multi-threaded support."""

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

from config import MAX_FILE_SIZE_KB, SCAN_THREADS, IGNORED_DIRS, SCAN_EXTENSIONS, SCAN_FILENAMES, ENTROPY_THRESHOLD
from regex_engine import scan_line
from entropy import shannon_entropy
from utils.masking import mask_secret
from utils.logger import log
from database import Database
from risk_intel import analyze_finding, group_findings


def _should_scan(filepath: str) -> bool:
    """Decide whether to scan a file based on extension, name, and size."""
    basename = os.path.basename(filepath)
    if basename in SCAN_FILENAMES:
        return True
    _, ext = os.path.splitext(filepath)
    if ext.lower() not in SCAN_EXTENSIONS:
        return False
    try:
        if os.path.getsize(filepath) > MAX_FILE_SIZE_KB * 1024:
            return False
    except OSError:
        return False
    return True


def _collect_files(repo_path: str) -> list[str]:
    """Walk the repo and collect scannable files."""
    files = []
    for root, dirs, filenames in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
        for fname in filenames:
            fpath = os.path.join(root, fname)
            if _should_scan(fpath):
                files.append(fpath)
    return files


def _scan_file(filepath: str, repo_path: str) -> list[dict]:
    """Scan a single file and return raw findings (enriched later)."""
    findings = []
    try:
        with open(filepath, "r", errors="ignore") as f:
            for lineno, line in enumerate(f, 1):
                matches = scan_line(line)
                for m in matches:
                    ent = shannon_entropy(m["matched_text"])
                    rel_path = os.path.relpath(filepath, repo_path)
                    meta = analyze_finding(
                        secret_type=m["secret_type"],
                        matched_text=m["matched_text"],
                        file_path=rel_path,
                        line_number=lineno,
                        line_content=line,
                        entropy=ent,
                        severity_base=m["severity_base"],
                    )
                    if meta.get("is_likely_example") and meta["confidence_label"] == "Low" and meta["severity_score"] < 50:
                        continue
                    findings.append({
                        "file_path": rel_path,
                        "line_number": lineno,
                        "secret_type": m["secret_type"],
                        "matched_text": m["matched_text"],
                        "masked_preview": mask_secret(m["matched_text"]),
                        "entropy": round(ent, 3),
                        "severity_base": m["severity_base"],
                        "line_content": line,
                        **meta,
                    })
    except Exception as e:
        log("warning", "scanner", f"Could not read {filepath}: {e}")
    return findings


def scan_repository(repo_path: str, db: Database, show_progress: bool = True) -> dict:
    """Scan a local repository for secrets. Returns summary dict."""
    repo_path = os.path.abspath(repo_path)
    if not os.path.isdir(repo_path):
        raise FileNotFoundError(f"Repository path not found: {repo_path}")

    repo_name = os.path.basename(repo_path)
    repo_id = db.add_repo(repo_path, repo_name)
    scan_id = db.start_scan(repo_id, "file_scan")
    log("info", "scanner", f"Starting scan of {repo_path}")

    files = _collect_files(repo_path)
    raw_findings: list[dict] = []

    if show_progress:
        with Progress(
            SpinnerColumn(), TextColumn("[bold cyan]{task.description}"),
            BarColumn(), TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
        ) as progress:
            task = progress.add_task("Scanning files", total=len(files))
            with ThreadPoolExecutor(max_workers=SCAN_THREADS) as pool:
                futures = {pool.submit(_scan_file, f, repo_path): f for f in files}
                for future in as_completed(futures):
                    raw_findings.extend(future.result())
                    progress.advance(task)
    else:
        with ThreadPoolExecutor(max_workers=SCAN_THREADS) as pool:
            futures = {pool.submit(_scan_file, f, repo_path): f for f in files}
            for future in as_completed(futures):
                raw_findings.extend(future.result())

    all_findings = group_findings(raw_findings)

    for f in all_findings:
        line_no = f.get("line_number")
        if isinstance(f.get("line_numbers"), list) and f["line_numbers"]:
            line_no = f["line_numbers"][0]
        db.add_finding(
            scan_id=scan_id, repo_id=repo_id,
            file_path=f["file_path"], line_number=line_no,
            secret_type=f["secret_type"], masked_preview=f["masked_preview"],
            confidence=f["confidence"], severity=f["severity"],
            severity_score=f["severity_score"], entropy=f["entropy"],
            remediation=f["remediation"],
            confidence_score=f.get("confidence_score"),
            confidence_label=f.get("confidence_label"),
            attack_technique=f.get("attack_technique"),
            attack_name=f.get("attack_name"),
            attack_tactic=f.get("attack_tactic"),
            exposure_score=f.get("exposure_score"),
            exposure_level=f.get("exposure_level"),
            exposure_reason=f.get("exposure_reason"),
            occurrence_count=f.get("occurrence_count", 1),
            affected_files=f.get("affected_files_json", "[]"),
            context_flags=f.get("context_flags", ""),
        )

    db.finish_scan(scan_id, len(files), len(all_findings))
    log("info", "scanner", f"Scan complete: {len(files)} files, {len(all_findings)} grouped findings ({len(raw_findings)} raw)")

    return {
        "repo_path": repo_path,
        "files_scanned": len(files),
        "secrets_found": len(all_findings),
        "raw_findings": len(raw_findings),
        "findings": all_findings,
        "scan_id": scan_id,
    }
