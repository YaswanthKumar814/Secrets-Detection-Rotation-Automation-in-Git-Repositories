"""Structured logging that writes to both file and database."""

import logging
import os
from datetime import datetime
from config import LOG_DIR

_file_handler = logging.FileHandler(os.path.join(LOG_DIR, "gitguard.log"))
_file_handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
_logger = logging.getLogger("gitguard")
_logger.setLevel(logging.DEBUG)
_logger.addHandler(_file_handler)

# Lazy db reference — set after import to avoid circular imports
_db = None


def set_db(db):
    global _db
    _db = db


def log(level: str, category: str, message: str, detail: str = ""):
    """Log an event to file and database."""
    getattr(_logger, level.lower(), _logger.info)(f"[{category}] {message}")
    if _db:
        try:
            _db.add_log(level, category, message, detail)
        except Exception:
            pass
