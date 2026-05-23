"""SQLite database layer for GitGuard."""

import sqlite3
import json
from datetime import datetime
from typing import Optional
from config import DB_PATH


class Database:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_schema()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_schema(self):
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS repositories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    path TEXT UNIQUE NOT NULL,
                    name TEXT,
                    added_at TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repo_id INTEGER REFERENCES repositories(id),
                    scan_type TEXT NOT NULL,
                    started_at TEXT DEFAULT (datetime('now')),
                    finished_at TEXT,
                    files_scanned INTEGER DEFAULT 0,
                    secrets_found INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'running'
                );
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER REFERENCES scans(id),
                    repo_id INTEGER REFERENCES repositories(id),
                    file_path TEXT,
                    line_number INTEGER,
                    secret_type TEXT,
                    masked_preview TEXT,
                    confidence REAL,
                    severity TEXT,
                    severity_score INTEGER,
                    entropy REAL,
                    remediation TEXT,
                    validation_status TEXT DEFAULT 'UNKNOWN',
                    rotation_status TEXT DEFAULT 'pending',
                    found_at TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS history_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repo_id INTEGER REFERENCES repositories(id),
                    commit_hash TEXT,
                    author TEXT,
                    commit_date TEXT,
                    file_path TEXT,
                    secret_type TEXT,
                    masked_preview TEXT,
                    severity TEXT,
                    found_at TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS monitor_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repo_id INTEGER REFERENCES repositories(id),
                    event_type TEXT,
                    file_path TEXT,
                    detail TEXT,
                    created_at TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS rotation_actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id INTEGER REFERENCES findings(id),
                    old_masked TEXT,
                    new_masked TEXT,
                    status TEXT DEFAULT 'initiated',
                    retries INTEGER DEFAULT 0,
                    initiated_at TEXT DEFAULT (datetime('now')),
                    completed_at TEXT
                );
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    level TEXT,
                    category TEXT,
                    message TEXT,
                    detail TEXT,
                    created_at TEXT DEFAULT (datetime('now'))
                );
            """)

            self._migrate_schema(conn)

    def _migrate_schema(self, conn: sqlite3.Connection):
        """Add Phase 4 risk intelligence columns if missing."""
        new_cols = [
            ("confidence_score", "INTEGER"),
            ("confidence_label", "TEXT"),
            ("attack_technique", "TEXT"),
            ("attack_name", "TEXT"),
            ("attack_tactic", "TEXT"),
            ("exposure_score", "INTEGER"),
            ("exposure_level", "TEXT"),
            ("exposure_reason", "TEXT"),
            ("occurrence_count", "INTEGER DEFAULT 1"),
            ("affected_files", "TEXT"),
            ("context_flags", "TEXT"),
        ]
        existing = {row[1] for row in conn.execute("PRAGMA table_info(findings)").fetchall()}
        for col, typedef in new_cols:
            if col not in existing:
                conn.execute(f"ALTER TABLE findings ADD COLUMN {col} {typedef}")

        hist_cols = [
            ("attack_technique", "TEXT"),
            ("confidence_label", "TEXT"),
            ("exposure_level", "TEXT"),
        ]
        hist_existing = {row[1] for row in conn.execute("PRAGMA table_info(history_findings)").fetchall()}
        for col, typedef in hist_cols:
            if col not in hist_existing:
                conn.execute(f"ALTER TABLE history_findings ADD COLUMN {col} {typedef}")

    # --- Repositories ---
    def add_repo(self, path: str, name: str) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT OR IGNORE INTO repositories (path, name) VALUES (?, ?)", (path, name)
            )
            if cur.lastrowid:
                return cur.lastrowid
            row = conn.execute("SELECT id FROM repositories WHERE path = ?", (path,)).fetchone()
            return row["id"]

    def get_repos(self) -> list[dict]:
        with self._conn() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM repositories ORDER BY added_at DESC").fetchall()]

    # --- Scans ---
    def start_scan(self, repo_id: int, scan_type: str) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO scans (repo_id, scan_type) VALUES (?, ?)", (repo_id, scan_type)
            )
            return cur.lastrowid

    def finish_scan(self, scan_id: int, files_scanned: int, secrets_found: int):
        with self._conn() as conn:
            conn.execute(
                "UPDATE scans SET finished_at = datetime('now'), files_scanned = ?, secrets_found = ?, status = 'completed' WHERE id = ?",
                (files_scanned, secrets_found, scan_id),
            )

    def get_scans(self, limit: int = 50) -> list[dict]:
        with self._conn() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)).fetchall()]

    # --- Findings ---
    def add_finding(self, **kwargs) -> int:
        cols = ", ".join(kwargs.keys())
        placeholders = ", ".join(["?"] * len(kwargs))
        with self._conn() as conn:
            cur = conn.execute(f"INSERT INTO findings ({cols}) VALUES ({placeholders})", list(kwargs.values()))
            return cur.lastrowid

    def get_findings(self, limit: int = 500, severity: Optional[str] = None) -> list[dict]:
        query = "SELECT * FROM findings"
        params: list = []
        if severity:
            query += " WHERE severity = ?"
            params.append(severity)
        query += " ORDER BY found_at DESC LIMIT ?"
        params.append(limit)
        with self._conn() as conn:
            return [dict(r) for r in conn.execute(query, params).fetchall()]

    def get_finding(self, finding_id: int) -> Optional[dict]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
            return dict(row) if row else None

    def update_finding(self, finding_id: int, **kwargs):
        sets = ", ".join(f"{k} = ?" for k in kwargs)
        with self._conn() as conn:
            conn.execute(f"UPDATE findings SET {sets} WHERE id = ?", list(kwargs.values()) + [finding_id])

    # --- History ---
    def add_history_finding(self, **kwargs) -> int:
        cols = ", ".join(kwargs.keys())
        placeholders = ", ".join(["?"] * len(kwargs))
        with self._conn() as conn:
            cur = conn.execute(f"INSERT INTO history_findings ({cols}) VALUES ({placeholders})", list(kwargs.values()))
            return cur.lastrowid

    def get_history_findings(self, limit: int = 200) -> list[dict]:
        with self._conn() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM history_findings ORDER BY found_at DESC LIMIT ?", (limit,)).fetchall()]

    # --- Monitor Events ---
    def add_monitor_event(self, repo_id: int, event_type: str, file_path: str, detail: str):
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO monitor_events (repo_id, event_type, file_path, detail) VALUES (?, ?, ?, ?)",
                (repo_id, event_type, file_path, detail),
            )

    def get_monitor_events(self, limit: int = 100) -> list[dict]:
        with self._conn() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM monitor_events ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()]

    # --- Rotation ---
    def add_rotation(self, finding_id: int, old_masked: str, new_masked: str) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO rotation_actions (finding_id, old_masked, new_masked) VALUES (?, ?, ?)",
                (finding_id, old_masked, new_masked),
            )
            return cur.lastrowid

    def update_rotation(self, rotation_id: int, status: str, retries: int = 0):
        with self._conn() as conn:
            completed = datetime.utcnow().isoformat() if status in ("completed", "failed") else None
            conn.execute(
                "UPDATE rotation_actions SET status = ?, retries = ?, completed_at = ? WHERE id = ?",
                (status, retries, completed, rotation_id),
            )

    def get_rotations(self, limit: int = 100) -> list[dict]:
        with self._conn() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT r.*, f.secret_type, f.file_path, f.severity FROM rotation_actions r LEFT JOIN findings f ON r.finding_id = f.id ORDER BY r.initiated_at DESC LIMIT ?",
                (limit,),
            ).fetchall()]

    # --- Logs ---
    def add_log(self, level: str, category: str, message: str, detail: str = ""):
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO logs (level, category, message, detail) VALUES (?, ?, ?, ?)",
                (level, category, message, detail),
            )

    def get_logs(self, limit: int = 200) -> list[dict]:
        with self._conn() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM logs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()]

    # --- Stats ---
    def get_stats(self) -> dict:
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) as c FROM findings").fetchone()["c"]
            critical = conn.execute("SELECT COUNT(*) as c FROM findings WHERE severity = 'Critical'").fetchone()["c"]
            high = conn.execute("SELECT COUNT(*) as c FROM findings WHERE severity = 'High'").fetchone()["c"]
            medium = conn.execute("SELECT COUNT(*) as c FROM findings WHERE severity = 'Medium'").fetchone()["c"]
            low = conn.execute("SELECT COUNT(*) as c FROM findings WHERE severity = 'Low'").fetchone()["c"]
            repos = conn.execute("SELECT COUNT(*) as c FROM repositories").fetchone()["c"]
            scans = conn.execute("SELECT COUNT(*) as c FROM scans").fetchone()["c"]
            rotations = conn.execute("SELECT COUNT(*) as c FROM rotation_actions WHERE status = 'completed'").fetchone()["c"]
            history = conn.execute("SELECT COUNT(*) as c FROM history_findings").fetchone()["c"]
            by_type = [dict(r) for r in conn.execute(
                "SELECT secret_type, COUNT(*) as count FROM findings GROUP BY secret_type ORDER BY count DESC"
            ).fetchall()]
            recent = [dict(r) for r in conn.execute(
                "SELECT * FROM findings ORDER BY found_at DESC LIMIT 10"
            ).fetchall()]
            high_confidence = conn.execute(
                "SELECT COUNT(*) as c FROM findings WHERE confidence_label = 'High'"
            ).fetchone()["c"]
            cloud_creds = conn.execute(
                """SELECT COUNT(*) as c FROM findings WHERE secret_type IN (
                    'AWS Access Key','AWS Secret Key','Google API Key','Stripe Secret Key',
                    'GitHub Token (classic)','GitHub Token (fine-grained)','OpenAI API Key'
                )"""
            ).fetchone()["c"]
            by_attack = [dict(r) for r in conn.execute(
                """SELECT attack_technique, attack_name, COUNT(*) as count FROM findings
                   WHERE attack_technique IS NOT NULL AND attack_technique != ''
                   GROUP BY attack_technique ORDER BY count DESC LIMIT 10"""
            ).fetchall()]
            by_confidence = [dict(r) for r in conn.execute(
                """SELECT confidence_label, COUNT(*) as count FROM findings
                   WHERE confidence_label IS NOT NULL GROUP BY confidence_label"""
            ).fetchall()]
            return {
                "total_findings": total, "critical": critical, "high": high,
                "medium": medium, "low": low, "repos": repos, "scans": scans,
                "rotations_completed": rotations, "history_leaks": history,
                "high_confidence": high_confidence, "cloud_credentials": cloud_creds,
                "by_type": by_type, "by_attack": by_attack, "by_confidence": by_confidence,
                "recent": recent,
            }

    def clear_all(self):
        with self._conn() as conn:
            for table in ["logs", "rotation_actions", "monitor_events", "history_findings", "findings", "scans", "repositories"]:
                conn.execute(f"DELETE FROM {table}")
