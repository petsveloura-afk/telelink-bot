# config.py — TELELINK Configuration Module
# Production-grade: centralised, validated, env-aware, type-safe.

import os
import logging as _logging
from typing import List

# Load environment variables from .env file if available (useful for local dev)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Setup module logger
_cfg_log = _logging.getLogger("telelink_config")

# ---------------------------------------------------------------------------
# Bot credentials — prefer environment variable, fall back to hard-coded value
# ---------------------------------------------------------------------------
BOT_TOKEN: str = os.getenv("BOT_TOKEN", "8200248843:AAFR2qo4g8EQMWeJgfQhJrUDhy_WdmhgXBM")

# ---------------------------------------------------------------------------
# Firebase Realtime Database URL — required for db_local.py / firebase.py
# ---------------------------------------------------------------------------
FIREBASE_URL: str = os.getenv("FIREBASE_URL", "https://keir-cc327-default-rtdb.europe-west1.firebasedatabase.app")

# ---------------------------------------------------------------------------
# Administrator user IDs — can be extended via env var (comma-separated)
# ---------------------------------------------------------------------------
def _parse_admin_ids() -> List[int]:
    env_ids = os.getenv("ADMIN_IDS", "")
    hardcoded: List[int] = [8716674464, 6281273276]
    if env_ids:
        try:
            parsed = [int(x.strip()) for x in env_ids.split(",") if x.strip().isdigit()]
            combined = list(dict.fromkeys(hardcoded + parsed))  # deduplicate, preserve order
            return combined
        except (ValueError, AttributeError):
            pass
    return hardcoded

ADMINS: List[int] = _parse_admin_ids()

# Backward-compatibility alias used throughout handlers.py
ADMIN_IDS: List[int] = ADMINS

# ---------------------------------------------------------------------------
# Admin permission levels (NEW)
# ---------------------------------------------------------------------------
# SUPER_ADMIN_IDS = "מנהל ראשי" — full access, including managing other
#   admins, broadcasts, and anything security-sensitive.
# ADMIN_IDS (above) remains the full list of everyone with panel access
#   (super admins + regular admins), exactly as before — nothing that
#   already depends on ADMIN_IDS changes behaviour.
# A "regular"/"משני" admin is anyone in ADMIN_IDS who is NOT in
#   SUPER_ADMIN_IDS. By default the two original hard-coded admins above
#   are treated as super admins, so existing behaviour is unchanged unless
#   SUPER_ADMIN_IDS is explicitly set.
def _parse_super_admin_ids() -> List[int]:
    env_ids = os.getenv("SUPER_ADMIN_IDS", "")
    default_super: List[int] = [8716674464, 6281273276]  # same as original hard-coded admins
    if env_ids:
        try:
            parsed = [int(x.strip()) for x in env_ids.split(",") if x.strip().isdigit()]
            if parsed:
                return list(dict.fromkeys(parsed))
        except (ValueError, AttributeError):
            pass
    return default_super

SUPER_ADMIN_IDS: List[int] = _parse_super_admin_ids()


def is_super_admin(user_id: int) -> bool:
    """True if user_id has full ('מנהל ראשי') admin privileges."""
    return user_id in SUPER_ADMIN_IDS


def is_regular_admin(user_id: int) -> bool:
    """True if user_id has panel access but is NOT a super admin ('מנהל משני')."""
    return user_id in ADMIN_IDS and user_id not in SUPER_ADMIN_IDS

# ---------------------------------------------------------------------------
# Channel / support links
# ---------------------------------------------------------------------------
MAIN_CHANNEL_LINK: str = os.getenv("MAIN_CHANNEL_LINK", "https://t.me/telelink_il")
HELP_SUPPORT_LINK: str = os.getenv("HELP_SUPPORT_LINK", "https://t.me/menahel_telelink")

# ---------------------------------------------------------------------------
# Static assets
# ---------------------------------------------------------------------------
BANNER_PATH: str = os.getenv("BANNER_PATH", "banner.jpg")

# ---------------------------------------------------------------------------
# Runtime guards — log warnings for obviously missing critical values
# ---------------------------------------------------------------------------
if BOT_TOKEN.startswith("YOUR_") or len(BOT_TOKEN) < 20:
    _cfg_log.critical("❌ BOT_TOKEN appears invalid — set it via env var BOT_TOKEN or config.py")

if "your-project" in FIREBASE_URL or not FIREBASE_URL.startswith("https://"):
    _cfg_log.warning("⚠️  FIREBASE_URL is still the placeholder value or invalid — set FIREBASE_URL env var")

if any(sid not in ADMIN_IDS for sid in SUPER_ADMIN_IDS):
    _cfg_log.warning(
        "⚠️  SUPER_ADMIN_IDS contains IDs not present in ADMIN_IDS — "
        "those super admins will not have panel access. Add them to ADMIN_IDS too."
    )

# NEW — security: warn loudly when the bot runs on the hard-coded fallback token.
# A token committed to Git must be considered leaked: revoke it in @BotFather
# (/revoke) and provide the new one only through the BOT_TOKEN environment variable.
if not os.getenv("BOT_TOKEN"):
    _cfg_log.warning(
        "🔐 BOT_TOKEN env var is not set — using the hard-coded fallback token from config.py. "
        "Rotate it via @BotFather (/revoke) and set BOT_TOKEN in Railway."
    )

if not os.getenv("DATABASE_URL"):
    _cfg_log.warning("🗄️ DATABASE_URL is not set — set it to your Neon connection string in Railway.")
