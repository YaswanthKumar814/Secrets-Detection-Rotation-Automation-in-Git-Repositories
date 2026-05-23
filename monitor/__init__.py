"""Real-time repository monitoring using watchdog with polling fallback."""

import os
import time
import threading
from typing import Optional

from utils.logger import log
from database import Database
from scanner import _should_scan, _scan_file
from config import MONITOR_POLL_INTERVAL


def _on_file_change(filepath: str, repo_path: str, db: Database, repo_id: int):
    """Handle a detected file change."""
    if not _should_scan(filepath):
        return
    findings = _scan_file(filepath, repo_path)
    rel = os.path.relpath(filepath, repo_path)
    if findings:
        for f in findings:
            db.add_finding(
                scan_id=0, repo_id=repo_id,
                file_path=f["file_path"], line_number=f["line_number"],
                secret_type=f["secret_type"], masked_preview=f["masked_preview"],
                confidence=f["confidence"], severity=f["severity"],
                severity_score=f["severity_score"], entropy=f["entropy"],
                remediation=f["remediation"],
            )
        detail = f"{len(findings)} secret(s) detected"
        db.add_monitor_event(repo_id, "secret_detected", rel, detail)
        log("warning", "monitor", f"New secrets in {rel}: {detail}")
    else:
        db.add_monitor_event(repo_id, "file_changed", rel, "No secrets found")


class WatchdogMonitor:
    """Monitor using watchdog library."""

    def __init__(self, repo_path: str, db: Database):
        self.repo_path = os.path.abspath(repo_path)
        self.db = db
        repo_name = os.path.basename(self.repo_path)
        self.repo_id = db.add_repo(self.repo_path, repo_name)
        self._observer = None

    def start(self):
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler

            monitor_ref = self

            class Handler(FileSystemEventHandler):
                def on_modified(self, event):
                    if not event.is_directory:
                        _on_file_change(event.src_path, monitor_ref.repo_path, monitor_ref.db, monitor_ref.repo_id)

                def on_created(self, event):
                    if not event.is_directory:
                        _on_file_change(event.src_path, monitor_ref.repo_path, monitor_ref.db, monitor_ref.repo_id)

            self._observer = Observer()
            self._observer.schedule(Handler(), self.repo_path, recursive=True)
            self._observer.start()
            log("info", "monitor", f"Watchdog monitoring started for {self.repo_path}")
            return True
        except Exception as e:
            log("warning", "monitor", f"Watchdog failed, will use polling: {e}")
            return False

    def stop(self):
        if self._observer:
            self._observer.stop()
            self._observer.join()
            log("info", "monitor", "Watchdog monitoring stopped")


class PollingMonitor:
    """Fallback polling-based monitor."""

    def __init__(self, repo_path: str, db: Database):
        self.repo_path = os.path.abspath(repo_path)
        self.db = db
        repo_name = os.path.basename(self.repo_path)
        self.repo_id = db.add_repo(self.repo_path, repo_name)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._file_mtimes: dict[str, float] = {}

    def _snapshot(self) -> dict[str, float]:
        snap = {}
        for root, dirs, files in os.walk(self.repo_path):
            dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__"}]
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    snap[fpath] = os.path.getmtime(fpath)
                except OSError:
                    pass
        return snap

    def _poll_loop(self):
        self._file_mtimes = self._snapshot()
        while self._running:
            time.sleep(MONITOR_POLL_INTERVAL)
            new_snap = self._snapshot()
            for fpath, mtime in new_snap.items():
                old = self._file_mtimes.get(fpath)
                if old is None or mtime > old:
                    _on_file_change(fpath, self.repo_path, self.db, self.repo_id)
            self._file_mtimes = new_snap

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()
        log("info", "monitor", f"Polling monitor started for {self.repo_path}")

    def stop(self):
        self._running = False
        log("info", "monitor", "Polling monitor stopped")


def start_monitor(repo_path: str, db: Database):
    """Start monitoring — tries watchdog, falls back to polling."""
    wm = WatchdogMonitor(repo_path, db)
    if wm.start():
        return wm
    pm = PollingMonitor(repo_path, db)
    pm.start()
    return pm
