"""
logger.py — TELELINK Centralised Logging Module v5.0
Production-grade: rotating files, structured formatter, deduplication guard,
helper utilities, and clean startup banner.
"""

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# 1. Log directory — absolute path, fail-safe creation
# ---------------------------------------------------------------------------
LOG_DIR = Path(os.getenv("LOG_DIR", "logs")).resolve()
try:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
except OSError as _e:
    print(f"❌ CRITICAL: Could not create log directory '{LOG_DIR}': {_e}", file=sys.stderr)

ACTIVITY_LOG = LOG_DIR / "bot_activity.log"
CRITICAL_LOG  = LOG_DIR / "critical_errors.log"

# ---------------------------------------------------------------------------
# 2. Formatter — ISO-style timestamp, level-padded, function + line
# ---------------------------------------------------------------------------
LOG_FORMAT  = "%(asctime)s | %(levelname)-8s | %(name)s | [%(funcName)s:%(lineno)d] | %(message)s"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"
_formatter  = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)

# ---------------------------------------------------------------------------
# 3. Central logger — guarded against double-registration
# ---------------------------------------------------------------------------
log: logging.Logger = logging.getLogger("anti_scam_bot")
log.setLevel(logging.INFO)
log.propagate = False  # prevent duplicate output through the root logger

if not log.handlers:

    # --- 3a. Console (stdout) ---
    _console = logging.StreamHandler(sys.stdout)
    _console.setLevel(logging.DEBUG)
    _console.setFormatter(_formatter)
    log.addHandler(_console)

    # --- 3b. Activity rotating file ---
    try:
        _file = RotatingFileHandler(
            filename=ACTIVITY_LOG,
            maxBytes=10 * 1024 * 1024,   # 10 MB per shard
            backupCount=10,
            encoding="utf-8-sig",
        )
        _file.setLevel(logging.DEBUG)
        _file.setFormatter(_formatter)
        log.addHandler(_file)
    except OSError as _e:
        print(f"⚠️  Activity log unavailable: {_e}", file=sys.stderr)

    # --- 3c. Critical error rotating file (ERROR+) ---
    try:
        _errfile = RotatingFileHandler(
            filename=CRITICAL_LOG,
            maxBytes=5 * 1024 * 1024,    # 5 MB per shard
            backupCount=5,
            encoding="utf-8-sig",
        )
        _errfile.setLevel(logging.ERROR)
        _errfile.setFormatter(_formatter)
        log.addHandler(_errfile)
    except OSError as _e:
        print(f"⚠️  Critical-error log unavailable: {_e}", file=sys.stderr)

# ---------------------------------------------------------------------------
# 4. Utility helpers
# ---------------------------------------------------------------------------

def log_exception(exc: Exception, context: str = "") -> None:
    """Log an exception with full traceback at ERROR level."""
    label = f"EXCEPTION in {context}" if context else "EXCEPTION"
    log.error("%s: %s", label, exc, exc_info=True)


def log_security_event(user_id: int, action: str, detail: str = "") -> None:
    """Dedicated WARNING log for security-relevant events."""
    extra = f" | {detail}" if detail else ""
    log.warning("SECURITY | user_id=%s | action=%s%s", user_id, action, extra)


def log_admin_action(admin_id: int, action: str, target: str = "") -> None:
    """Audit log for administrator operations."""
    log.info("ADMIN_ACTION | admin=%s | action=%s | target=%s", admin_id, action, target or "—")


def get_logger(name: str) -> logging.Logger:
    """
    Return a child logger that inherits all handlers from the root 'anti_scam_bot' logger.
    Use this in sub-modules that want a distinct name in the log output.
    """
    child = log.getChild(name)
    child.setLevel(logging.DEBUG)
    return child


# ---------------------------------------------------------------------------
# 5. Startup banner
# ---------------------------------------------------------------------------
log.info("=" * 60)
log.info("🚀  ANTI-SCAM SYSTEM LOGGING v5.0 — STARTED")
log.info("📂  Activity log : %s", ACTIVITY_LOG)
log.info("📂  Critical log : %s", CRITICAL_LOG)
log.info("=" * 60)