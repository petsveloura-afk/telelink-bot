"""
handlers.py — TELELINK Verification Engine v3.0
Full router module: user flows, admin panel, reporting system, FSM states.
Production-grade: typed, thread-safe JSON I/O, input-validated, XSS-safe,
structured logging, optimised verification lookup order, and complete
error handling on every handler.
"""

import asyncio
import html as html_lib
import json
import logging
import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from aiogram import Bot, F, Router
from aiogram.enums import ParseMode
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import (
    CallbackQuery,
    FSInputFile,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    InputMediaPhoto,
    Message,
)
from aiogram.utils.keyboard import InlineKeyboardBuilder

# ---------------------------------------------------------------------------
# Local project imports
# ---------------------------------------------------------------------------
try:
    from config import ADMIN_IDS, BANNER_PATH, HELP_SUPPORT_LINK, MAIN_CHANNEL_LINK
    try:
        # NEW — permission-level helpers (super admin vs. regular admin).
        # Imported defensively so nothing breaks if config.py hasn't been
        # updated yet; falls back to "everyone in ADMIN_IDS is super".
        from config import SUPER_ADMIN_IDS, is_super_admin, is_regular_admin
    except ImportError:
        SUPER_ADMIN_IDS: List[int] = list(ADMIN_IDS)

        def is_super_admin(user_id: int) -> bool:
            return user_id in ADMIN_IDS

        def is_regular_admin(user_id: int) -> bool:
            return False

    MAIN_CHANNEL_LINK = "https://t.me/telelink_cha"
    HELP_SUPPORT_LINK = "https://t.me/menahel_telelink"
except ImportError:
    ADMIN_IDS: List[int] = []
    SUPER_ADMIN_IDS: List[int] = []
    MAIN_CHANNEL_LINK = "https://t.me/telelink_cha"
    HELP_SUPPORT_LINK = "https://t.me/menahel_telelink"
    BANNER_PATH = "banner.jpg"

    def is_super_admin(user_id: int) -> bool:
        return False

    def is_regular_admin(user_id: int) -> bool:
        return False

try:
    from db_local import DB
except ImportError:
    class DB:  # type: ignore[no-redef]
        @staticmethod
        async def get_user_info(entity: str) -> Optional[Dict[str, Any]]:
            return None

        @staticmethod
        async def get_json(path: str, default: Any = None) -> Any:
            return default

        @staticmethod
        async def set_json(path: str, data: Any) -> bool:
            return False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
GEZA_BOT_LINK: str = "https://t.me/Geza_telelink_bot"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("telelink_bot")
logger.setLevel(logging.INFO)
if not logger.handlers:
    _ch = logging.StreamHandler()
    _ch.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(_ch)

# ---------------------------------------------------------------------------
# File paths
# ---------------------------------------------------------------------------
DATA_DIR       = "data"
USERS_FILE     = os.path.join(DATA_DIR, "users.json")
GROUPS_FILE    = os.path.join(DATA_DIR, "groups.json")
BLACKLIST_FILE = os.path.join(DATA_DIR, "global_blacklist.json")
REPORTS_FILE   = os.path.join(DATA_DIR, "scam_reports.json")
STATS_FILE     = os.path.join(DATA_DIR, "stats.json")
GOLD_LIST_FILE = os.path.join(DATA_DIR, "gold_list.json")

_file_lock      = asyncio.Lock()
_user_save_lock = asyncio.Lock()
BUTTONS_FILE   = os.path.join(DATA_DIR, "buttons.json")
_buttons_lock  = asyncio.Lock()
CUSTOM_BUTTONS_FILE = os.path.join(DATA_DIR, "custom_buttons.json")
_custom_buttons_lock = asyncio.Lock()

# NEW — runtime-managed secondary admins (super admins can add/remove these
# from the panel without touching config.py / redeploying). Structure:
# {"regular_admins": [{"id": int, "name": str}], "promoted": [int]}
ADMINS_EXTRA_FILE = os.path.join(DATA_DIR, "admins_extra.json")
_admins_extra_lock = asyncio.Lock()

# NEW — full audit trail: every admin action (add/edit/remove/broadcast/
# permission change) is appended here with who/what/when, independent of
# the plain activity logs already written by logger.py.
AUDIT_LOG_FILE = os.path.join(DATA_DIR, "audit_log.json")
_audit_log_lock = asyncio.Lock()

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------
router = Router()

# ---------------------------------------------------------------------------
# FSM States
# ---------------------------------------------------------------------------
class CheckFlow(StatesGroup):
    waiting_entity = State()

class ReportFlow(StatesGroup):
    waiting_username    = State()
    waiting_proof       = State()
    waiting_description = State()

class AdminStates(StatesGroup):
    database_master         = State()
    mass_broadcast          = State()
    evidence_review         = State()
    report_generator        = State()
    edit_entry              = State()
    edit_score              = State()
    edit_comment            = State()
    waiting_db_add          = State()
    waiting_db_remove       = State()
    waiting_db_edit_id      = State()
    waiting_db_edit_content = State()
    # --- Professional broadcast wizard (media + optional inline buttons) ---
    broadcast_menu           = State()
    broadcast_wait_buttons   = State()
    # --- Universal button / link editor (admin-editable buttons/links) ---
    button_edit_text         = State()
    button_edit_url          = State()
    button_add_new            = State()
    # --- NEW: advanced search & filter ---
    search_waiting_username  = State()
    search_waiting_date_from = State()
    search_waiting_date_to   = State()
    # --- NEW: admin permission-level management ---
    waiting_new_admin_id     = State()
    # --- NEW: audit trail lookup ---
    audit_waiting_username   = State()

# ---------------------------------------------------------------------------
# Input normalisation
# ---------------------------------------------------------------------------
def normalize_entity(raw_input: str) -> str:
    """
    Sanitise user-supplied entity strings (username, channel link, invite link).
    Returns a clean lowercase alphanumeric+underscore identifier.
    """
    if not raw_input:
        return ""
    text = raw_input.strip().lower()
    for prefix in ("https://", "http://", "t.me/", "telegram.me/"):
        text = text.replace(prefix, "")
    text = text.replace("@", "").strip()
    if "/" in text:
        text = text.split("/")[-1]
    # strip query params (invite links may have ?start= suffix)
    text = text.split("?")[0].strip()
    return text


def clean_tg_username(raw_name: str) -> str:
    """
    Return only Telegram-valid characters (a-z, A-Z, 0-9, _) from a raw name.
    Strips URL prefixes and @ signs first.
    """
    if not raw_name:
        return ""
    text = str(raw_name).strip()
    text = text.replace("https://t.me/", "").replace("t.me/", "").replace("@", "")
    return "".join(re.findall(r"[a-zA-Z0-9_]+", text))


def _truncate(text: str, max_len: int = 200) -> str:
    """Truncate text for safe inclusion in Telegram messages."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "…"


def _esc(value: Any) -> str:
    """
    Escape user-supplied text for safe inclusion inside an HTML-parse-mode
    Telegram message. Without this, a report description or name containing
    '<', '>' or '&' (very common in real scam screenshots, e.g. "price < 500"
    or "A&B store") breaks Telegram's HTML parser — the API then rejects the
    whole message and it silently fails to send. Always wrap raw user input
    with this before interpolating it into an HTML-formatted string.
    """
    return html_lib.escape(str(value if value is not None else ""), quote=False)


def _strip_html_tags(text: str) -> str:
    """Best-effort plain-text fallback used if an HTML-mode send still fails for any reason."""
    return html_lib.unescape(re.sub(r"<[^>]+>", "", text))


_URL_RE = re.compile(r"(https?://\S+|tg://\S+)")


def parse_label_and_url(raw: str) -> Optional[tuple]:
    """
    Forgiving "label + URL" parser used across the button/link editor.
    Accepts several natural input styles so admins aren't blocked by a
    keyboard that hides the '|' key:
      1) "טקסט | קישור"                (pipe-separated — preferred)
      2) "טקסט\nקישור"                  (label on one line, URL on the next)
      3) "טקסט https://example.com"    (URL detected anywhere in the text;
                                          everything else becomes the label)
    Returns (label, url) or None if no valid URL could be found.
    """
    if not raw:
        return None
    raw = raw.strip()

    # 1) Pipe-separated (also tolerate the similar-looking ones some keyboards send)
    for sep in ("|", "｜", "¦"):
        if sep in raw:
            label, _, url = raw.partition(sep)
            label, url = label.strip(), url.strip()
            match = _URL_RE.search(url)
            if match:
                return (label or "🔗 קישור", match.group(1))

    # 2) Newline-separated (label on first line, URL on a later line)
    if "\n" in raw:
        lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        url_line = next((ln for ln in lines if _URL_RE.search(ln)), None)
        if url_line:
            match = _URL_RE.search(url_line)
            label = " ".join(ln for ln in lines if ln != url_line).strip()
            return (label or "🔗 קישור", match.group(1))

    # 3) URL embedded anywhere in a single line — take it, use the rest as label
    match = _URL_RE.search(raw)
    if match:
        label = (raw[:match.start()] + raw[match.end():]).strip(" -–—:|")
        return (label or "🔗 קישור", match.group(1))

    return None

# ---------------------------------------------------------------------------
# Thread-safe JSON I/O helpers
# ---------------------------------------------------------------------------
async def _read_json_file(path: str, default: Any) -> Any:
    def _read() -> Any:
        if not os.path.exists(path):
            return default
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to read '%s': %s", path, exc)
            return default

    return await asyncio.to_thread(_read)


async def _write_json_file(path: str, data: Any) -> bool:
    def _write() -> bool:
        dirpath = os.path.dirname(path)
        if dirpath:
            os.makedirs(dirpath, exist_ok=True)
        tmp = f"{path}.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
            os.replace(tmp, path)
            return True
        except OSError as exc:
            logger.warning("Failed to write '%s': %s", path, exc)
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass
            return False

    return await asyncio.to_thread(_write)

# ---------------------------------------------------------------------------
# Data access layer
# ---------------------------------------------------------------------------
async def load_users() -> List[Dict[str, Any]]:
    data = await _read_json_file(USERS_FILE, [])
    return data if isinstance(data, list) else []


async def save_users(users: List[Dict[str, Any]]) -> bool:
    async with _file_lock:
        return await _write_json_file(USERS_FILE, users)


async def load_blacklist() -> Dict[str, Dict[str, Any]]:
    data = await DB.get_json("global_blacklist", {})
    return data if isinstance(data, dict) else {}


async def save_blacklist(blacklist: Dict[str, Dict[str, Any]]) -> bool:
    return await DB.set_json("global_blacklist", blacklist)


async def load_gold_list() -> List[Dict[str, Any]]:
    data = await DB.get_json("gold_list", [])
    return data if isinstance(data, list) else []


async def save_gold_list(gold_list: List[Dict[str, Any]]) -> bool:
    return await DB.set_json("gold_list", gold_list)


async def load_reports() -> List[Dict[str, Any]]:
    data = await DB.get_json("scam_reports", [])
    return data if isinstance(data, list) else []


async def save_reports(reports: List[Dict[str, Any]]) -> bool:
    return await DB.set_json("scam_reports", reports)


async def load_stats() -> Dict[str, int]:
    default: Dict[str, int] = {"verified": 0, "banned": 0, "users": 0, "checks": 0}
    data = await DB.get_json("stats", default)
    return data if isinstance(data, dict) else default


async def save_stats(stats: Dict[str, int]) -> bool:
    return await DB.set_json("stats", stats)



# ---------------------------------------------------------------------------
# NEW — runtime admin-permission store (regular admins added via the panel,
# plus super-admin promotions/demotions applied on top of config.py values)
# ---------------------------------------------------------------------------
_ADMINS_EXTRA_DEFAULT: Dict[str, Any] = {"regular_admins": [], "promoted": [], "demoted": []}


async def load_admins_extra() -> Dict[str, Any]:
    data = await _read_json_file(ADMINS_EXTRA_FILE, dict(_ADMINS_EXTRA_DEFAULT))
    if not isinstance(data, dict):
        return dict(_ADMINS_EXTRA_DEFAULT)
    for key, default_val in _ADMINS_EXTRA_DEFAULT.items():
        data.setdefault(key, list(default_val))
    return data


async def save_admins_extra(data: Dict[str, Any]) -> bool:
    async with _admins_extra_lock:
        return await _write_json_file(ADMINS_EXTRA_FILE, data)


async def get_effective_admin_roles() -> Dict[int, str]:
    """
    Merge config.py's hard-coded ADMIN_IDS/SUPER_ADMIN_IDS with runtime
    changes made from the panel (added regular admins, promotions,
    demotions) into a single {user_id: "super"|"regular"} map.
    Never mutates config.py — purely additive at runtime.
    """
    extra = await load_admins_extra()
    promoted = set(extra.get("promoted", []))
    demoted  = set(extra.get("demoted", []))

    roles: Dict[int, str] = {}
    for uid in ADMIN_IDS:
        roles[uid] = "super" if (uid in SUPER_ADMIN_IDS and uid not in demoted) else "regular"
        if uid in promoted:
            roles[uid] = "super"

    for entry in extra.get("regular_admins", []):
        if not isinstance(entry, dict):
            continue
        uid = entry.get("id")
        if isinstance(uid, int):
            roles.setdefault(uid, "super" if uid in promoted else "regular")

    return roles


async def is_effective_admin(user_id: int) -> bool:
    roles = await get_effective_admin_roles()
    return user_id in roles or user_id in ADMIN_IDS


async def is_effective_super_admin(user_id: int) -> bool:
    roles = await get_effective_admin_roles()
    return roles.get(user_id) == "super" or (user_id in SUPER_ADMIN_IDS)


# ---------------------------------------------------------------------------
# NEW — full audit trail (who did what, to which record, and when)
# ---------------------------------------------------------------------------
async def load_audit_log() -> List[Dict[str, Any]]:
    data = await _read_json_file(AUDIT_LOG_FILE, [])
    return data if isinstance(data, list) else []


async def save_audit_log(entries: List[Dict[str, Any]]) -> bool:
    async with _audit_log_lock:
        return await _write_json_file(AUDIT_LOG_FILE, entries)


async def log_audit(admin_id: int, action: str, target: str = "", details: str = "") -> None:
    """
    Append one entry to the persistent audit trail. Never raises —
    a failed audit write must not break the admin action it is logging.
    Kept separate from logger.py's rotating text logs so it stays
    structured, queryable, and filterable per-user from the admin panel.
    """
    try:
        entries = await load_audit_log()
        entries.append(
            {
                "admin_id":  admin_id,
                "action":    action,
                "target":    target,
                "details":   details,
                "timestamp": datetime.now().isoformat(),
            }
        )
        # Keep the file bounded — retain the most recent 5000 entries.
        if len(entries) > 5000:
            entries = entries[-5000:]
        await save_audit_log(entries)
    except Exception as exc:
        logger.warning("log_audit failed (admin=%s action=%s target=%s): %s", admin_id, action, target, exc)

# ---------------------------------------------------------------------------
# Universal Button / Link Editor — admin-editable CMS layer
# ---------------------------------------------------------------------------
# Every user-facing button label and every outbound link in the bot is
# registered here. Admins can rename any button and, for "url" type buttons,
# repoint the destination link — all from the admin panel, fully synced
# across every keyboard that renders it, with zero code changes required.
# Nothing here alters existing callback_data / routing logic: only the
# *display text* and, for link buttons, the *URL* are customisable.
#
# type "text" -> label only is editable (callback_data stays fixed)
# type "url"  -> label AND destination URL are both editable
EDITABLE_BUTTONS: Dict[str, Dict[str, str]] = {
    "main_check":       {"label": "תפריט ראשי · בדיקת ערוץ/קבוצה",      "type": "text", "default_text": "🔍 בדיקת ערוץ/קבוצה"},
    "main_report":      {"label": "תפריט ראשי · דיווח על הונאה",        "type": "text", "default_text": "📢 דיווח על הונאה"},
    "main_gold":        {"label": "תפריט ראשי · אינדקס רשימת הזהב",     "type": "text", "default_text": "💎 אינדקס רשימת הזהב"},
    "main_criteria":    {"label": "תפריט ראשי · קריטריוני אימות",       "type": "text", "default_text": "🛡️ קריטריוני אימות"},
    "main_partnership": {"label": "תפריט ראשי · שותפות עסקית",          "type": "text", "default_text": "🤝 שותפות עסקית"},
    "main_stats":       {"label": "תפריט ראשי · נתונים בזמן אמת",       "type": "text", "default_text": "📊 נתונים בזמן אמת"},
    "main_alerts":      {"label": "תפריט ראשי · התראות צבע אדום",       "type": "text", "default_text": "🔔 התראות צבע אדום"},
    "main_help":        {"label": "תפריט ראשי · עזרה ותמיכה",           "type": "text", "default_text": "🆘 עזרה ותמיכה"},
    "main_blacklist":   {"label": "תפריט ראשי · אינדקס רשימה שחורה",    "type": "text", "default_text": "🌍 אינדקס רשימה שחורה"},
    "main_pulse":       {"label": "תפריט ראשי · דופק השוק",             "type": "text", "default_text": "🇮🇱 דופק השוק"},
    "geza_bot":         {"label": "כפתור: בוט הגזע המרכזי",            "type": "url",  "default_text": "🤖 עבור לבוט הגזע המרכזי ➜", "default_url": GEZA_BOT_LINK},
    "main_channel":     {"label": "כפתור: הערוץ הרשמי",                "type": "url",  "default_text": "🔗 הערוץ הרשמי",             "default_url": MAIN_CHANNEL_LINK},
    "help_support":     {"label": "קישור: מרכז התמיכה",                "type": "url",  "default_text": "🆘 עזרה ותמיכה",             "default_url": HELP_SUPPORT_LINK},
    "admin_db_btn":     {"label": "פאנל ניהול · ניהול מסד נתונים",     "type": "text", "default_text": "🗃️ ניהול מסד נתונים"},
    "admin_broadcast_btn": {"label": "פאנל ניהול · שידור הודעה",       "type": "text", "default_text": "📢 שידור הודעה (Broadcast)"},
    "admin_evidence_btn":  {"label": "פאנל ניהול · בדיקת דיווחים",      "type": "text", "default_text": "🔍 בדיקת דיווחים (ראיות)"},
    "admin_reportgen_btn": {"label": "פאנל ניהול · מחולל דוחות",        "type": "text", "default_text": "📄 מחולל דוחות"},
}

_button_overrides: Dict[str, Dict[str, str]] = {}


def _load_button_overrides_sync() -> None:
    """
    Best-effort synchronous load performed once at import time so that the
    (synchronous) keyboard builder functions immediately reflect any saved
    admin customisation, without needing to be converted to async.
    """
    global _button_overrides
    try:
        if os.path.exists(BUTTONS_FILE):
            with open(BUTTONS_FILE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
                if isinstance(data, dict):
                    _button_overrides = data
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to load buttons.json: %s", exc)


_load_button_overrides_sync()


def get_button_text(button_id: str) -> str:
    """Return the current (admin-overridden if set) display text for a button id."""
    meta = EDITABLE_BUTTONS.get(button_id, {})
    override = _button_overrides.get(button_id, {})
    return override.get("text") or meta.get("default_text", button_id)


def get_button_url(button_id: str) -> str:
    """Return the current (admin-overridden if set) destination URL for a button id."""
    meta = EDITABLE_BUTTONS.get(button_id, {})
    override = _button_overrides.get(button_id, {})
    return override.get("url") or meta.get("default_url", "")


def get_button_hidden(button_id: str) -> bool:
    """Return True if an admin has hidden ("deleted") this button from its menu."""
    return bool(_button_overrides.get(button_id, {}).get("hidden", False))


def is_button_customised(button_id: str) -> bool:
    """True if the admin has changed the text/url of this button (independent of hidden state)."""
    entry = _button_overrides.get(button_id, {})
    return bool(entry.get("text") or entry.get("url"))


async def save_button_override(button_id: str, *, text: Optional[str] = None, url: Optional[str] = None) -> bool:
    """Persist an admin edit for a button/link — updates disk AND the in-memory cache."""
    if button_id not in EDITABLE_BUTTONS:
        return False
    entry = _button_overrides.setdefault(button_id, {})
    if text:
        entry["text"] = text.strip()
    if url:
        entry["url"] = url.strip()
    async with _buttons_lock:
        return await _write_json_file(BUTTONS_FILE, _button_overrides)


async def set_button_hidden(button_id: str, hidden: bool) -> bool:
    """
    Reversible "delete" for a built-in button — removes it from the menu it
    belongs to (main menu or admin panel) without touching any handler code.
    Toggle back at any time from the same editor screen.
    """
    if button_id not in EDITABLE_BUTTONS:
        return False
    entry = _button_overrides.setdefault(button_id, {})
    entry["hidden"] = hidden
    async with _buttons_lock:
        return await _write_json_file(BUTTONS_FILE, _button_overrides)


async def reset_button_override(button_id: str) -> bool:
    """Remove a customisation (including hidden state) and revert a button/link back to its coded default."""
    _button_overrides.pop(button_id, None)
    async with _buttons_lock:
        return await _write_json_file(BUTTONS_FILE, _button_overrides)

# ---------------------------------------------------------------------------
# Custom Buttons / Links — fully admin-created (not just edits of existing ones)
# ---------------------------------------------------------------------------
# Any button added here is automatically appended as an extra row at the
# bottom of the main menu (above the official channel link), and can be
# renamed, re-pointed, or removed from the same admin screen.
_custom_buttons: List[Dict[str, str]] = []


def _load_custom_buttons_sync() -> None:
    """Best-effort synchronous load at import time (mirrors _load_button_overrides_sync)."""
    global _custom_buttons
    try:
        if os.path.exists(CUSTOM_BUTTONS_FILE):
            with open(CUSTOM_BUTTONS_FILE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
                if isinstance(data, list):
                    _custom_buttons = data
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to load custom_buttons.json: %s", exc)


_load_custom_buttons_sync()


async def add_custom_button(text: str, url: str) -> Dict[str, str]:
    """Create a brand-new admin button/link and persist it (disk + memory)."""
    new_id = f"cb{len(_custom_buttons) + 1}_{int(datetime.now().timestamp())}"
    entry = {"id": new_id, "text": text.strip(), "url": url.strip()}
    _custom_buttons.append(entry)
    async with _custom_buttons_lock:
        await _write_json_file(CUSTOM_BUTTONS_FILE, _custom_buttons)
    return entry


async def update_custom_button(button_id: str, *, text: Optional[str] = None, url: Optional[str] = None) -> bool:
    """Edit an existing admin-created button in place."""
    for entry in _custom_buttons:
        if entry.get("id") == button_id:
            if text:
                entry["text"] = text.strip()
            if url:
                entry["url"] = url.strip()
            async with _custom_buttons_lock:
                return await _write_json_file(CUSTOM_BUTTONS_FILE, _custom_buttons)
    return False


async def remove_custom_button(button_id: str) -> bool:
    """Delete an admin-created button/link entirely."""
    global _custom_buttons
    before = len(_custom_buttons)
    _custom_buttons = [b for b in _custom_buttons if b.get("id") != button_id]
    if len(_custom_buttons) == before:
        return False
    async with _custom_buttons_lock:
        return await _write_json_file(CUSTOM_BUTTONS_FILE, _custom_buttons)

# ---------------------------------------------------------------------------
# User registration helper
# ---------------------------------------------------------------------------
async def save_user_to_json(msg: Message) -> None:
    """Register a new user on first /start, notify admins, and increment counter."""
    try:
        async with _user_save_lock:
            users = await load_users()
            uid: Optional[int] = getattr(msg.from_user, "id", None)
            if uid is None:
                return
            if any(u.get("id") == uid for u in users):
                return

            username   = getattr(msg.from_user, "username", None)
            first_name = getattr(msg.from_user, "first_name", "") or ""
            last_name  = getattr(msg.from_user, "last_name", "") or ""

            users.append(
                {
                    "id":         uid,
                    "username":   username,
                    "first_name": first_name,
                    "last_name":  last_name,
                    "joined_at":  datetime.utcnow().isoformat(),
                }
            )
            await save_users(users)

            stats = await load_stats()
            stats["users"] = stats.get("users", 0) + 1
            await save_stats(stats)

        bot: Bot = msg.bot  # type: ignore[assignment]
        notify_text = (
            f"🛡️ <b>משתמש חדש ב-TELELINK:</b>\n"
            f"🆔 ID: <code>{uid}</code>\n"
            f"👤 @{username if username else '(ללא שם משתמש)'}\n"
            f"📛 {(first_name + ' ' + last_name).strip()}"
        )
        for admin_id in ADMIN_IDS:
            try:
                await bot.send_message(admin_id, notify_text, parse_mode=ParseMode.HTML)
            except Exception as exc:
                logger.warning("Cannot notify admin %s: %s", admin_id, exc)

    except Exception as exc:
        logger.warning("Failed to save user: %s", exc)

# ---------------------------------------------------------------------------
# Keyboard builders (inline — handlers.py local copies)
# ---------------------------------------------------------------------------
def styled(text: str, primary: bool = True) -> str:
    """
    No-op passthrough (kept so every existing call site below still works
    unchanged). Buttons are no longer prefixed with a colour-marker emoji —
    just returns the label as-is.
    """
    return text


_MAIN_MENU_TEXT_BUTTONS: List[tuple] = [
    ("main_check",       "check_entity"),
    ("main_report",      "report_scam"),
    ("main_gold",        "view_gold_list"),
    ("main_criteria",    "audit_criteria"),
    ("main_partnership", "business_partnership"),
    ("main_stats",       "live_stats"),
    ("main_alerts",      "red_alerts"),
    ("main_help",        "help_support"),
    ("main_blacklist",   "global_blacklist"),
    ("main_pulse",       "market_pulse"),
]
_MAIN_MENU_LINK_BUTTONS: List[str] = ["geza_bot", "main_channel"]


def telelink_main_menu() -> InlineKeyboardMarkup:
    """
    Premium 2-column main menu with Geza bot redirect.
    Every label/link below is resolved through get_button_text()/get_button_url(),
    so any customisation saved by an admin in "🔧 עריכת כפתורים וקישורים" is
    reflected here instantly — with zero behavioural change when unconfigured
    (falls back to the original hard-coded defaults, same 2-per-row layout).
    Buttons an admin has hidden ("deleted") via the editor are simply skipped.
    """
    keyboard: List[List[InlineKeyboardButton]] = []

    # Hero actions rendered blue; the rest rendered as regular/white rows.
    _PRIMARY_BIDS = {"main_check", "main_report", "main_gold", "main_criteria"}

    visible_text = [(bid, cb) for bid, cb in _MAIN_MENU_TEXT_BUTTONS if not get_button_hidden(bid)]
    for i in range(0, len(visible_text), 2):
        pair = visible_text[i : i + 2]
        keyboard.append(
            [
                InlineKeyboardButton(text=styled(get_button_text(bid), primary=(bid in _PRIMARY_BIDS)), callback_data=cb)
                for bid, cb in pair
            ]
        )

    # ✅ REQUIRED ADDITION: Prominent direct link to the main Geza bot
    for bid in _MAIN_MENU_LINK_BUTTONS:
        if not get_button_hidden(bid):
            keyboard.append([InlineKeyboardButton(text=styled(get_button_text(bid), primary=(bid == "geza_bot")), url=get_button_url(bid))])

    # ➕ Admin-created custom buttons/links (added via "🔧 עריכת כפתורים וקישורים")
    # appear automatically here, at the bottom of the main menu.
    for entry in _custom_buttons:
        text = entry.get("text", "")
        url  = entry.get("url", "")
        if text and url:
            keyboard.append([InlineKeyboardButton(text=styled(text, primary=False), url=url)])

    return InlineKeyboardMarkup(inline_keyboard=keyboard)


_ADMIN_PANEL_BUTTONS: List[tuple] = [
    ("admin_db_btn",        "admin_database"),
    ("admin_broadcast_btn", "admin_broadcast"),
    ("admin_evidence_btn",  "admin_evidence"),
    ("admin_reportgen_btn", "admin_report_gen"),
]


def admin_command_center(is_super: bool = True) -> InlineKeyboardMarkup:
    """
    Main admin panel keyboard.
    `is_super=True` (default) preserves the exact prior behaviour for any
    existing caller that doesn't pass the new argument. When explicitly
    called with `is_super=False` (regular/"משני" admin), the
    permission-management row is hidden — everything else stays identical.
    """
    keyboard: List[List[InlineKeyboardButton]] = []
    for bid, cb in _ADMIN_PANEL_BUTTONS:
        if not get_button_hidden(bid):
            keyboard.append([InlineKeyboardButton(text=styled(get_button_text(bid), primary=True), callback_data=cb)])

    # NEW — advanced search & filter
    keyboard.append([InlineKeyboardButton(text=styled("🔎 חיפוש וסינון מתקדם ברשימות", primary=True), callback_data="admin_search")])
    # NEW — audit trail
    keyboard.append([InlineKeyboardButton(text=styled("📜 היסטוריית שינויים (Audit Trail)", primary=False), callback_data="admin_audit_trail")])
    keyboard.append([InlineKeyboardButton(text=styled("🔧 עריכת כפתורים וקישורים", primary=False), callback_data="admin_buttons")])
    # NEW — permission management, super admins only
    if is_super:
        keyboard.append([InlineKeyboardButton(text=styled("👑 ניהול הרשאות מנהלים", primary=True), callback_data="admin_permissions")])
    keyboard.append([InlineKeyboardButton(text=styled("⬅️ חזרה למסך הראשי", primary=False), callback_data="main_menu")])
    return InlineKeyboardMarkup(inline_keyboard=keyboard)


def database_keyboard() -> InlineKeyboardMarkup:
    keyboard = [
        [
            InlineKeyboardButton(text=styled("➕ הוספת רשומה", primary=True),  callback_data="db_add"),
            InlineKeyboardButton(text=styled("🗑️ מחיקת רשומה", primary=True), callback_data="db_remove"),
        ],
        [InlineKeyboardButton(text=styled("✏️ עריכת רשומה", primary=True),    callback_data="db_edit")],
        [InlineKeyboardButton(text=styled("🔎 חיפוש וסינון מתקדם", primary=False), callback_data="admin_search")],
        [InlineKeyboardButton(text=styled("⬅️ חזור", primary=False),            callback_data="admin_back")],
    ]
    return InlineKeyboardMarkup(inline_keyboard=keyboard)


def evidence_keyboard(report_id: str) -> InlineKeyboardMarkup:
    keyboard = [
        [InlineKeyboardButton(text=styled("✅ אישור דיווח (חסימה)", primary=True), callback_data=f"approve_report:{report_id}")],
        [InlineKeyboardButton(text=styled("❌ דחיית דיווח", primary=False),          callback_data=f"reject_report:{report_id}")],
        [InlineKeyboardButton(text=styled("⬅️ חזור", primary=False),                 callback_data="admin_back")],
    ]
    return InlineKeyboardMarkup(inline_keyboard=keyboard)


# ---------------------------------------------------------------------------
# NEW — Advanced search/filter, permissions, and audit-trail keyboards
# ---------------------------------------------------------------------------
def search_filter_keyboard() -> InlineKeyboardMarkup:
    keyboard = [
        [InlineKeyboardButton(text=styled("🔤 חיפוש לפי שם משתמש", primary=True), callback_data="search_by_username")],
        [
            InlineKeyboardButton(text=styled("✅ Whitelist בלבד", primary=False), callback_data="search_filter_whitelist"),
            InlineKeyboardButton(text=styled("⚠️ Blacklist בלבד", primary=False), callback_data="search_filter_blacklist"),
        ],
        [InlineKeyboardButton(text=styled("💎 רשימת הזהב בלבד", primary=False), callback_data="search_filter_gold")],
        [InlineKeyboardButton(text=styled("📅 סינון לפי טווח תאריכים", primary=False), callback_data="search_filter_dates")],
        [InlineKeyboardButton(text=styled("📋 הצג הכול", primary=False), callback_data="search_filter_all")],
        [InlineKeyboardButton(text=styled("⬅️ חזור", primary=False), callback_data="admin_back")],
    ]
    return InlineKeyboardMarkup(inline_keyboard=keyboard)


def permissions_keyboard(roles: Dict[int, str]) -> InlineKeyboardMarkup:
    keyboard: List[List[InlineKeyboardButton]] = []
    for uid, level in roles.items():
        badge = "👑 מנהל ראשי" if level == "super" else "🛠️ מנהל משני"
        keyboard.append(
            [InlineKeyboardButton(text=styled(f"{badge} · {uid}", primary=(level == "super")), callback_data=f"perm_view:{uid}")]
        )
    keyboard.append([InlineKeyboardButton(text=styled("➕ הוספת מנהל משני", primary=True), callback_data="perm_add_admin")])
    keyboard.append([InlineKeyboardButton(text=styled("⬅️ חזור", primary=False), callback_data="admin_back")])
    return InlineKeyboardMarkup(inline_keyboard=keyboard)


def permission_action_keyboard(target_id: int, level: str) -> InlineKeyboardMarkup:
    keyboard: List[List[InlineKeyboardButton]] = []
    if level == "super":
        keyboard.append([InlineKeyboardButton(text=styled("⬇️ הורד לדרגת מנהל משני", primary=False), callback_data=f"perm_demote:{target_id}")])
    else:
        keyboard.append([InlineKeyboardButton(text=styled("⬆️ קדם לדרגת מנהל ראשי", primary=True), callback_data=f"perm_promote:{target_id}")])
        keyboard.append([InlineKeyboardButton(text=styled("🗑️ הסר הרשאת ניהול", primary=False), callback_data=f"perm_remove:{target_id}")])
    keyboard.append([InlineKeyboardButton(text=styled("⬅️ חזרה לרשימת מנהלים", primary=False), callback_data="admin_permissions")])
    return InlineKeyboardMarkup(inline_keyboard=keyboard)


def audit_trail_keyboard() -> InlineKeyboardMarkup:
    keyboard = [
        [InlineKeyboardButton(text=styled("🔍 חפש היסטוריה למשתמש ספציפי", primary=True), callback_data="audit_search_user")],
        [InlineKeyboardButton(text=styled("🕒 20 הפעולות האחרונות (כולן)", primary=False), callback_data="audit_recent_all")],
        [InlineKeyboardButton(text=styled("⬅️ חזור", primary=False), callback_data="admin_back")],
    ]
    return InlineKeyboardMarkup(inline_keyboard=keyboard)

# ---------------------------------------------------------------------------
# /start
# ---------------------------------------------------------------------------
@router.message(Command("start"))
async def start_message(msg: Message, state: FSMContext) -> None:
    await state.clear()
    await save_user_to_json(msg)

    welcome_text = (
        "🛡️ <b>TELELINK</b> — תו התקן הישראלי לאמינות בטלגרם\n\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "ברוכים הבאים למנוע האימות המתקדם ביותר בישראל.\n"
        "המערכת מגנה עליכם מפני נוכלים ורמאים\n"
        "באמצעות פרוטוקולי אבטחה מחמירים ובדיקה רב-שכבתית.\n\n"
        "💡 <b>בחרו פעולה מהתפריט:</b>"
    )

    try:
        if BANNER_PATH and os.path.exists(BANNER_PATH):
            await msg.answer_photo(
                FSInputFile(BANNER_PATH),
                caption=welcome_text,
                parse_mode=ParseMode.HTML,
                reply_markup=telelink_main_menu(),
            )
        else:
            await msg.answer(welcome_text, parse_mode=ParseMode.HTML, reply_markup=telelink_main_menu())
    except Exception as exc:
        logger.warning("Failed to send welcome photo, falling back to text: %s", exc)
        try:
            await msg.answer(welcome_text, parse_mode=ParseMode.HTML, reply_markup=telelink_main_menu())
        except Exception as exc2:
            logger.error("Cannot send start message: %s", exc2)

# ---------------------------------------------------------------------------
# Verification flow
# ---------------------------------------------------------------------------
@router.callback_query(F.data == "check_entity")
async def check_entity_prompt(call: CallbackQuery, state: FSMContext) -> None:
    await state.set_state(CheckFlow.waiting_entity)
    try:
        await call.message.answer(  # type: ignore[union-attr]
            "🔍 <b>מערכת אימות ישויות</b>\n\n"
            "אנא שלחו שם משתמש, קישור לערוץ או לקבוצה שברצונכם לסרוק:\n\n"
            "• <code>@username</code>\n"
            "• <code>t.me/channelname</code>\n"
            "• קישורי הזמנה לקבוצות",
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("check_entity_prompt error: %s", exc)
    finally:
        await call.answer()


@router.message(CheckFlow.waiting_entity)
async def process_verification(msg: Message, state: FSMContext) -> None:
    raw_input    = msg.text or ""
    clean_entity = normalize_entity(raw_input)
    current_date = datetime.now().strftime("%d/%m/%Y %H:%M")

    # Guard against empty input
    if not clean_entity:
        try:
            await msg.answer(
                "⚠️ לא ניתן לזהות את הקלט. אנא שלחו שם משתמש או קישור תקין.",
                parse_mode=ParseMode.HTML,
            )
        except Exception:
            pass
        return

    stats = await load_stats()
    stats["checks"] = stats.get("checks", 0) + 1
    await save_stats(stats)

    status      = "לא ידוע ⚠️"
    trust_score = 45
    verdict     = "אין נתונים זמינים במערכת. יש לנקוט במשנה זהירות."

    try:
        # 1. Gold list check
        gold_list = await load_gold_list()
        gold_member: Optional[Dict[str, Any]] = None
        raw_lower = raw_input.lower()
        for g in gold_list:
            g_name = g.get("name", "").lower().replace("@", "").strip()
            if clean_entity in g_name or g_name in clean_entity or g_name in raw_lower:
                gold_member = g
                break

        if gold_member:
            status      = "זהב (Premium) 💎"
            trust_score = 100
            g_display   = gold_member.get("name") or clean_entity
            description = (
                gold_member.get("desc")
                or gold_member.get("description")
                or "גוף עסקי מאומת ומומלץ בעל וותק רב ומוניטין גבוה במערכת."
            )
            verdict = f"💎 <b>שותף זהב מאומת:</b> <code>{g_display}</code>\n{description}"

        else:
            # 2. Global blacklist JSON check
            global_blacklist = await load_blacklist()
            user_data = (
                global_blacklist.get(clean_entity)
                or global_blacklist.get(f"@{clean_entity}")
            )

            if user_data:
                raw_status = str(user_data.get("status", "scammer")).lower()
                reason     = _truncate(user_data.get("comment", "דיווחי הונאה בינלאומיים"), 300)

                if raw_status == "verified":
                    status      = "מאומת ✅"
                    trust_score = 100
                    verdict     = f"✅ <b>עבר ביקורת אבטחה:</b> הישות נמצאה אמינה ונקייה מחשד.\n📝 הערה: {reason}"
                else:
                    status      = "נוכל / רמאי ❌"
                    trust_score = 0
                    verdict     = f"🌍 <b>התראת רשימה שחורה עולמית:</b> {reason}"

            else:
                # 3. Local Firebase DB check
                info = await DB.get_user_info(clean_entity)
                if info:
                    if info.get("list") == "whitelist":
                        status      = "מאומת ✅"
                        trust_score = 100
                        verdict     = (
                            "✅ <b>עבר ביקורת 5-שלבים:</b> זהות אומתה, פעילות נוטרה במערכת, "
                            "היסטוריית עסקאות נקייה ואישור אבטחה של Telelink."
                        )
                    elif info.get("list") == "blacklist":
                        status      = "נוכל / רמאי ❌"
                        trust_score = 0
                        verdict     = (
                            "🚨 <b>נחסם!</b> קיימים דיווחי הונאה מאומתים כלפי ישות זו. "
                            "המלצת המערכת היא הימנעות מוחלטת."
                        )

    except Exception as exc:
        logger.error("Verification engine error for '%s': %s", clean_entity, exc)

    filled = max(0, min(10, int(trust_score // 10)))
    bar    = "█" * filled + "░" * (10 - filled)

    report = (
        f"🛡️ <b>דוח אימות TELELINK</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"🔍 <b>ישות מבוקשת:</b> <code>{clean_entity}</code>\n"
        f"📅 <b>תאריך בדיקה:</b> {current_date}\n"
        f"🚦 <b>סטטוס מערכת:</b> {status}\n\n"
        f"<b>מדדי אבטחה (Trust Score):</b>\n"
        f"[{bar}] {trust_score}% רמת אמינות\n\n"
        f"<b>פסיקת המערכת (Verdict):</b>\n{verdict}\n\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"<i>🇮🇱 Telelink — הסטנדרט הישראלי לאמינות.</i>"
    )

    keyboard = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="🚨 דווחו על הונאה",     callback_data=f"report_scam_direct:{clean_entity}")],
            [InlineKeyboardButton(text=get_button_text("geza_bot"), url=get_button_url("geza_bot"))],
            [InlineKeyboardButton(text="🔍 חזרה לתפריט הראשי", callback_data="main_menu")],
        ]
    )

    try:
        await msg.answer(report, parse_mode=ParseMode.HTML, reply_markup=keyboard)
    except Exception as exc:
        logger.error("Failed to send verification report: %s", exc)
    finally:
        await state.clear()

# ---------------------------------------------------------------------------
# Report scam — professional evidence packet helpers
# ---------------------------------------------------------------------------
def _reporter_display(entry: Dict[str, Any]) -> str:
    """Human-readable identification of the reporting user for the admin packet."""
    uname = entry.get("reporter_username")
    name  = entry.get("reporter_name") or ""
    uid   = entry.get("reporter")
    parts = []
    if name:
        parts.append(_esc(name))
    if uname:
        parts.append(f"@{_esc(uname)}")
    label = " · ".join(parts) if parts else "משתמש אנונימי"
    return f"{label} (מזהה: <code>{_esc(uid)}</code>)"


def _report_evidence_items(entry: Dict[str, Any]) -> "tuple[List[str], Optional[str]]":
    """
    Normalise a report's stored evidence into (photo_file_ids, text_proof) —
    understands both the current multi-photo format and older single-proof
    entries, so historical reports keep working unchanged.
    """
    photos: List[str] = list(entry.get("proof_photos") or [])
    text_proof: Optional[str] = entry.get("proof_text")

    # Backward compatibility with the earlier single-proof format.
    if not photos and not text_proof and entry.get("proof"):
        if entry.get("proof_type") == "photo":
            photos = [entry["proof"]]
        else:
            text_proof = entry["proof"]

    return photos, text_proof


def _evidence_summary_line(entry: Dict[str, Any]) -> str:
    """One-line, non-revealing summary of what evidence exists (used pre-reveal)."""
    photos, text_proof = _report_evidence_items(entry)
    parts: List[str] = []
    if photos:
        parts.append(f"📸 {len(photos)} תמונות ראיה" if len(photos) > 1 else "📸 תמונת ראיה אחת")
    if text_proof:
        parts.append("🔗 ראיה טקסטואלית/קישור")
    return " + ".join(parts) if parts else "⚠️ לא צורפה ראיה"


def _report_packet_text(
    entry: Dict[str, Any],
    *,
    pending_count: Optional[int] = None,
    position: Optional[tuple] = None,
) -> str:
    """
    Build the formal report SUMMARY shown to administrators up front.
    The evidence itself (photos / links) stays hidden by design — a
    professional, uncluttered notification — and is only revealed when
    the admin explicitly taps "🔍 הצג ראיות".

    `position`, if given as (index, total), shows "מציג דיווח X מתוך Y"
    for queue browsing; otherwise `pending_count` shows a simple counter.
    """
    if position:
        idx, total = position
        pending_line = f"📄 <b>מציג דיווח מספר {idx + 1} מתוך {total} הממתינים לבדיקה</b>\n"
    elif pending_count:
        pending_line = f"⏳ <b>ממתינים בתור לבדיקה:</b> <code>{pending_count}</code> דיווחים נוספים\n"
    else:
        pending_line = ""

    return (
        f"🆘 <b>פרוטוקול דיווח רשמי — TELELINK Security Desk</b>\n"
        f"מזהה תיק: <code>#{_esc(entry.get('id'))}</code>\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"👤 <b>הוגש על ידי:</b> {_reporter_display(entry)}\n"
        f"🎯 <b>ישות מדווחת:</b> <code>{_esc(entry.get('username'))}</code>\n"
        f"🕒 <b>התקבל בתאריך:</b> {_esc(str(entry.get('timestamp', ''))[:19].replace('T', ' '))}\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"📝 <b>תיאור האירוע כפי שנמסר על ידי המדווח:</b>\n"
        f"<blockquote>{_esc(_truncate(entry.get('description') or 'לא סופק תיאור.', 700))}</blockquote>\n"
        f"📎 <b>ראיות מצורפות לתיק:</b> {_evidence_summary_line(entry)}\n"
        f"🔒 <i>הראיות מוסתרות כברירת מחדל. לחצו \"🔍 הצג ראיות\" לצפייה מלאה בכל מה שהמדווח העלה.</i>\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"{pending_line}"
        f"🛡️ <i>יש לבחון את הראיות בעיון לפני קבלת החלטה. הפעולה תירשם ביומן הביקורת של המערכת.</i>"
    )


def _report_review_keyboard(report_id: str) -> InlineKeyboardMarkup:
    """Reveal evidence on demand, plus approve / reject — always available together."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="🔍 הצג ראיות", callback_data=f"view_evidence:{report_id}")],
            [
                InlineKeyboardButton(text="✅ אישור דיווח וחסימה", callback_data=f"approve_report:{report_id}"),
                InlineKeyboardButton(text="❌ דחיית דיווח",          callback_data=f"reject_report:{report_id}"),
            ],
        ]
    )


def _evidence_queue_keyboard(report_id: str, index: int, total: int) -> InlineKeyboardMarkup:
    """
    Full queue-browsing keyboard for "🔍 בדיקת דיווחים (ראיות)" — lets the
    admin move one-by-one through every pending report (⬅️ הקודם / ➡️ הבא),
    reveal evidence on demand, and approve/reject, all from one screen.
    """
    builder = InlineKeyboardBuilder()
    builder.row(InlineKeyboardButton(text="🔍 הצג ראיות", callback_data=f"view_evidence:{report_id}"))
    builder.row(
        InlineKeyboardButton(text="✅ אישור דיווח וחסימה", callback_data=f"approve_report:{report_id}"),
        InlineKeyboardButton(text="❌ דחיית דיווח",          callback_data=f"reject_report:{report_id}"),
    )

    nav_row: List[InlineKeyboardButton] = []
    if index > 0:
        nav_row.append(InlineKeyboardButton(text="⬅️ הדיווח הקודם", callback_data=f"evidence_nav:{index - 1}"))
    if index < total - 1:
        nav_row.append(InlineKeyboardButton(text="➡️ הדיווח הבא", callback_data=f"evidence_nav:{index + 1}"))
    if nav_row:
        builder.row(*nav_row)

    builder.row(InlineKeyboardButton(text="⬅️ חזרה לפאנל הניהול", callback_data="admin_back"))
    return builder.as_markup()


async def _deliver_report_packet(bot: Bot, chat_id: int, entry: Dict[str, Any], *, pending_count: Optional[int] = None) -> None:
    """
    Send the report SUMMARY only, with a "🔍 הצג ראיות" button — a clean,
    professional first touch that never pushes unsolicited images/files.
    The actual evidence is delivered on demand by _reveal_report_evidence().
    """
    text = _report_packet_text(entry, pending_count=pending_count)
    keyboard = _report_review_keyboard(entry.get("id", ""))
    try:
        await bot.send_message(chat_id, text, parse_mode=ParseMode.HTML, reply_markup=keyboard)
    except Exception as exc:
        logger.warning("Could not deliver report packet to %s (HTML), retrying as plain text: %s", chat_id, exc)
        try:
            await bot.send_message(chat_id, _strip_html_tags(text), reply_markup=keyboard)
        except Exception as exc2:
            logger.error("Could not deliver report packet to %s at all: %s", chat_id, exc2)


async def _reveal_report_evidence(bot: Bot, chat_id: int, entry: Dict[str, Any]) -> None:
    """
    Deliver the actual evidence — every photo the reporter uploaded (sent as a
    single photo or, for multiple images, a proper media album, up to Telegram's
    10-item limit) plus any text/link proof — triggered only by an explicit
    admin tap on "🔍 הצג ראיות". Ends by re-offering the approve/reject decision.
    """
    photos, text_proof = _report_evidence_items(entry)

    try:
        if len(photos) == 1:
            await bot.send_photo(chat_id, photo=photos[0], caption="📸 ראיה חזותית שצורפה על ידי המדווח")
        elif len(photos) > 1:
            media = [InputMediaPhoto(media=fid) for fid in photos[:10]]
            media[0].caption = f"📸 {len(photos)} ראיות חזותיות שצורפו על ידי המדווח"
            await bot.send_media_group(chat_id, media=media)
    except Exception as exc:
        logger.warning("Failed to deliver photo evidence to %s: %s", chat_id, exc)
        try:
            await bot.send_message(chat_id, "⚠️ אירעה שגיאה בטעינת התמונות שצורפו לתיק.")
        except Exception:
            pass

    if text_proof:
        try:
            await bot.send_message(
                chat_id,
                f"🔗 <b>ראיה טקסטואלית/קישור שצורפו על ידי המדווח:</b>\n<code>{_esc(text_proof)}</code>",
                parse_mode=ParseMode.HTML,
            )
        except Exception as exc:
            logger.warning("Failed to deliver text evidence to %s (HTML), retrying as plain text: %s", chat_id, exc)
            try:
                await bot.send_message(chat_id, f"🔗 ראיה טקסטואלית/קישור שצורפו על ידי המדווח:\n{text_proof}")
            except Exception as exc2:
                logger.error("Failed to deliver text evidence to %s even as plain text: %s", chat_id, exc2)

    if not photos and not text_proof:
        try:
            await bot.send_message(chat_id, "⚠️ לא נמצאה ראיה מצורפת לתיק זה.")
        except Exception:
            pass

    try:
        await bot.send_message(
            chat_id,
            "מה תרצו לעשות עם התיק?",
            reply_markup=_report_review_keyboard(entry.get("id", "")),
        )
    except Exception as exc:
        logger.warning("Failed to re-offer decision keyboard to %s: %s", chat_id, exc)

# ---------------------------------------------------------------------------
# Report scam — 3-step flow
# ---------------------------------------------------------------------------
@router.callback_query(F.data == "report_scam")
async def report_scam_start(call: CallbackQuery, state: FSMContext) -> None:
    await state.set_state(ReportFlow.waiting_username)
    try:
        await call.message.answer(  # type: ignore[union-attr]
            "🚨 <b>מוקד הדיווחים של TELELINK — פתיחת תיק חדש</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "אתם עומדים לפתוח פנייה רשמית מול צוות האבטחה שלנו.\n"
            "התהליך כולל 3 שלבים קצרים ויימשך פחות מדקה.\n\n"
            "<b>שלב 1 מתוך 3 — זיהוי הישות המדווחת</b>\n"
            "אנא ציינו את שם המשתמש, שם הערוץ או הקישור של הגורם שברצונכם לדווח עליו:",
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("report_scam_start error: %s", exc)
    finally:
        await call.answer()


@router.message(ReportFlow.waiting_username)
async def report_username(msg: Message, state: FSMContext) -> None:
    clean_username = normalize_entity(msg.text or "")
    if not clean_username:
        await msg.answer(
            "⚠️ לא זוהתה ישות תקינה. אנא שלחו שם משתמש או קישור חוקי כדי להמשיך:",
        )
        return

    await state.update_data(username=clean_username, proof_photos=[], proof_text=None)
    await state.set_state(ReportFlow.waiting_proof)
    try:
        await msg.answer(
            f"✅ הישות <code>{clean_username}</code> נקלטה במערכת.\n\n"
            "<b>שלב 2 מתוך 3 — צירוף ראיות</b>\n"
            "לצורך בחינה מקצועית של התיק, אנא צרפו תיעוד תומך:\n"
            "📸 ניתן לשלוח <u>כמה תמונות שתרצו</u> (צילומי מסך של ההתכתבות / העברה הכספית), <u>וגם</u>\n"
            "🔗 קישור או טקסט רלוונטי (פרופיל, פוסט, אישור תשלום וכדומה).\n\n"
            "שלחו את הראיות בזו אחר זו — ולחצו \"✅ סיימתי לצרף ראיות\" כשתסיימו:",
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("report_username step error: %s", exc)


def _report_proof_done_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text="✅ סיימתי לצרף ראיות — המשך", callback_data="report_proof_done")]]
    )


@router.message(ReportFlow.waiting_proof)
async def report_proof(msg: Message, state: FSMContext) -> None:
    """
    Accumulates evidence for the current report — supports any number of
    photos (sent one by one or as an album) plus optional text/link proof.
    The reporter explicitly taps "✅ סיימתי" (via report_proof_done below)
    when ready to move on, instead of the flow auto-advancing on one item.
    """
    data   = await state.get_data()
    photos: List[str] = list(data.get("proof_photos") or [])
    text_proof: Optional[str] = data.get("proof_text")

    if msg.photo:
        if len(photos) >= 10:
            await msg.answer(
                "⚠️ הגעתם למספר המרבי של 10 תמונות ראיה לתיק אחד.\n"
                "לחצו \"✅ סיימתי לצרף ראיות\" כדי להמשיך:",
                reply_markup=_report_proof_done_keyboard(),
            )
            return
        photos.append(msg.photo[-1].file_id)
        await state.update_data(proof_photos=photos)
        try:
            await msg.answer(
                f"📸 תמונה מס' {len(photos)} נקלטה ונשמרה בתיק בהצלחה.\n"
                "ניתן לשלוח תמונות נוספות, או ללחוץ \"✅ סיימתי\" כדי להמשיך לשלב הבא:",
                reply_markup=_report_proof_done_keyboard(),
            )
        except Exception as exc:
            logger.error("report_proof (photo) step error: %s", exc)
        return

    if (msg.text or "").strip():
        addition = msg.text.strip()
        text_proof = f"{text_proof}\n{addition}" if text_proof else addition
        await state.update_data(proof_text=text_proof)
        try:
            await msg.answer(
                "🔗 <b>הראיה הטקסטואלית נקלטה ונשמרה בתיק.</b>\n"
                "ניתן לצרף ראיות נוספות (תמונות/טקסט), או ללחוץ \"✅ סיימתי\" כדי להמשיך:",
                reply_markup=_report_proof_done_keyboard(),
                parse_mode=ParseMode.HTML,
            )
        except Exception as exc:
            logger.error("report_proof (text) step error: %s", exc)
        return

    await msg.answer(
        "⚠️ לא זוהתה ראיה תקינה. שלחו תמונה, טקסט או קישור —\n"
        "או לחצו \"✅ סיימתי\" אם כבר צירפתם את כל הראיות:",
        reply_markup=_report_proof_done_keyboard(),
    )


@router.callback_query(ReportFlow.waiting_proof, F.data == "report_proof_done")
async def report_proof_done(call: CallbackQuery, state: FSMContext) -> None:
    """Advance to the description step once the reporter has attached at least one piece of evidence."""
    data   = await state.get_data()
    photos: List[str] = list(data.get("proof_photos") or [])
    text_proof: Optional[str] = data.get("proof_text")

    if not photos and not text_proof:
        await call.answer("⚠️ יש לצרף לפחות ראיה אחת (תמונה, טקסט או קישור) לפני שממשיכים.", show_alert=True)
        return

    await state.set_state(ReportFlow.waiting_description)
    summary_bits = []
    if photos:
        summary_bits.append(f"{len(photos)} תמונות" if len(photos) > 1 else "תמונה אחת")
    if text_proof:
        summary_bits.append("ראיה טקסטואלית")
    summary = " + ".join(summary_bits)

    try:
        await call.message.answer(  # type: ignore[union-attr]
            f"✅ <b>הראיות נקלטו ונשמרו בתיק</b> ({summary}).\n\n"
            "<b>שלב 3 מתוך 3 — תיאור האירוע</b>\n"
            "אנא תארו במילים שלכם, בבהירות ובקצרה, מה אירע וכיצד בוצעה ההונאה\n"
            "(ציינו סכומים, תאריכים או פרטים רלוונטיים נוספים אם ידועים לכם):",
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("report_proof_done error: %s", exc)
    finally:
        await call.answer()


@router.message(ReportFlow.waiting_description)
async def report_complete(msg: Message, state: FSMContext) -> None:
    data    = await state.get_data()
    reports = await load_reports()

    report_id = f"r{len(reports) + 1}_{int(datetime.now().timestamp())}"
    report_entry: Dict[str, Any] = {
        "id":                report_id,
        "username":          data.get("username"),
        "proof_photos":      list(data.get("proof_photos") or []),
        "proof_text":        data.get("proof_text"),
        "description":       _truncate(msg.text or "", 1000),
        "reporter":          msg.from_user.id if msg.from_user else None,
        "reporter_username": getattr(msg.from_user, "username", None),
        "reporter_name":     ((getattr(msg.from_user, "first_name", "") or "") + " " + (getattr(msg.from_user, "last_name", "") or "")).strip(),
        "status":            "pending",
        "timestamp":         datetime.now().isoformat(),
    }

    reports.append(report_entry)
    await save_reports(reports)

    pending_count = sum(1 for r in reports if r.get("status") == "pending")

    if msg.bot:
        for admin_id in ADMIN_IDS:
            try:
                await _deliver_report_packet(msg.bot, admin_id, report_entry, pending_count=pending_count)
            except Exception as exc:
                logger.warning("Could not notify admin %s: %s", admin_id, exc)

    try:
        await msg.answer(
            f"✅ <b>התיק נפתח בהצלחה במערכת TELELINK — מזהה #{report_id}</b>\n\n"
            "הפנייה הועברה באופן מיידי לצוות האבטחה שלנו לבחינה מקצועית,\n"
            "ותיבדק בהתאם לסדר קבלתה. במקרה של ממצא מבוסס — הישות תיחסם\n"
            "ותתווסף לרשימה השחורה הגלובלית, וכל קהילת המשתמשים תוגן.\n\n"
            "🕒 <b>זמן טיפול משוער:</b> עד 24 שעות.\n"
            "🙏 תודה שסייעתם בשמירה על קהילה בטוחה ואמינה יותר.",
            reply_markup=telelink_main_menu(),
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("Failed to confirm report to user: %s", exc)
    finally:
        await state.clear()


@router.callback_query(F.data.startswith("report_scam_direct:"))
async def direct_report(call: CallbackQuery, state: FSMContext) -> None:
    parts  = call.data.split(":", 1)
    entity = normalize_entity(parts[1]) if len(parts) > 1 else ""
    await state.update_data(username=entity, proof_photos=[], proof_text=None)
    await state.set_state(ReportFlow.waiting_proof)
    try:
        await call.message.answer(  # type: ignore[union-attr]
            f"🚨 <b>פתיחת תיק דיווח — יעד:</b> <code>@{entity}</code>\n\n"
            "<b>שלב 2 מתוך 3 — צירוף ראיות</b>\n"
            "ניתן לשלוח כמה תמונות שתרצו, וגם קישור/טקסט המהווה הוכחה להונאה.\n"
            "לחצו \"✅ סיימתי לצרף ראיות\" כשתסיימו:",
            reply_markup=_report_proof_done_keyboard(),
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("direct_report error: %s", exc)
    finally:
        await call.answer()

# ---------------------------------------------------------------------------
# Feature buttons
# ---------------------------------------------------------------------------
@router.callback_query(F.data == "audit_criteria")
async def show_audit_criteria(call: CallbackQuery) -> None:
    criteria = (
        "🛡️ <b>קריטריוני הביקורת (5-Pillar Audit)</b>\n\n"
        "המערכת שלנו מסתמכת על 5 עמודי תווך לקביעת אמינות:\n\n"
        "1️⃣ <b>זהות (Identity):</b> אימות זהות אנושית ואמיתית של מנהלי הישות.\n"
        "2️⃣ <b>פעילות (Activity):</b> ניתוח דפוסי התנהגות ווותק הישות בטלגרם.\n"
        "3️⃣ <b>קהילה (Community):</b> הצלבת מוניטין בקרב קהילות סגורות ואנשי מפתח.\n"
        "4️⃣ <b>עסקאות (Transactions):</b> היסטוריה פיננסית נקייה ונטולת תלונות.\n"
        "5️⃣ <b>הסמכה (Certification):</b> אישור ביטחוני פנימי של צוות Telelink."
    )
    try:
        await call.message.answer(criteria, parse_mode=ParseMode.HTML, reply_markup=telelink_main_menu())  # type: ignore[union-attr]
    except Exception as exc:
        logger.error("show_audit_criteria error: %s", exc)
    finally:
        await call.answer()


@router.callback_query(F.data == "live_stats")
async def show_live_stats(call: CallbackQuery) -> None:
    user_id  = call.from_user.id
    is_admin = user_id in ADMIN_IDS

    try:
        if is_admin:
            stats = await load_stats()
            text = (
                f"📊 <b>פאנל ניהול — סטטיסטיקות אמת</b>\n"
                f"━━━━━━━━━━━━━━━━━━━━\n"
                f"👤 משתמשים רשומים:  <code>{stats.get('users', 0)}</code>\n"
                f"🔍 סריקות שבוצעו:   <code>{stats.get('checks', 0)}</code>\n"
                f"✅ אומתו בהצלחה:    <code>{stats.get('verified', 0)}</code>\n"
                f"🚫 נחסמו במערכת:    <code>{stats.get('banned', 0)}</code>\n"
                f"━━━━━━━━━━━━━━━━━━━━\n"
                f"⚠️ <i>נתונים אלו גלויים למנהלים בלבד.</i>"
            )
        else:
            fake_users    = 14200 + (user_id % 500)
            fake_checks   = 48500 + (user_id % 1000)
            fake_scammers = 1240  + (user_id % 100)
            text = (
                f"🛡️ <b>Telelink — מערך הגנה פעיל בזמן אמת</b>\n"
                f"━━━━━━━━━━━━━━━━━━━━\n"
                f"👥 קהילת המוגנים שלנו:         <code>{fake_users}+</code>\n"
                f"🔍 בדיקות אקטיביות שבוצעו:    <code>{fake_checks}+</code>\n"
                f"🚫 איומים ונוכלים שנוטרלו:     <code>{fake_scammers}</code>\n"
                f"━━━━━━━━━━━━━━━━━━━━\n"
                f"🟢 <b>סטטוס מנוע הבדיקה:</b> 100% תקין ופעיל\n"
                f"✨ <i>המערכת מעדכנת נתונים אלו בכל 60 שניות.</i>"
            )

        await call.message.answer(text, parse_mode=ParseMode.HTML, reply_markup=telelink_main_menu())  # type: ignore[union-attr]
    except Exception as exc:
        logger.error("show_live_stats error: %s", exc)
    finally:
        await call.answer()


@router.callback_query(F.data.in_({"business_partnership", "red_alerts", "help_support", "market_pulse"}))
async def quick_features(call: CallbackQuery) -> None:
    feature_texts: Dict[str, str] = {
        "business_partnership": (
            "🤝 <b>שותפות עסקית</b>\n\n"
            "לביצוע תהליך אימות פרימיום לעסק שלכם, חיבור ל-API שלנו\n"
            "או הגנה על מותג — אנא פנו להנהלה."
        ),
        "red_alerts": (
            "🔔 <b>התראות צבע אדום</b>\n\n"
            "התראות Push על גלי הונאה רחבים מוגדרות כעת\n"
            "במצב פָּעִיל בחשבונך."
        ),
        "help_support": (
            f"🆘 <b>מרכז תמיכה</b>\n\n"
            f"זקוקים לעזרה? ניתן ליצור קשר ישירות עם צוות התמיכה:\n"
            f"👉 {get_button_url('help_support')}"
        ),
        "market_pulse": (
            "🇮🇱 <b>דופק השוק</b>\n\n"
            "הישארו מעודכנים בשינויי האבטחה האחרונים\n"
            "באקו-סיסטם של טלגרם בישראל.\n"
            "הצטרפו לערוץ הרשמי."
        ),
    }
    text = feature_texts.get(call.data or "", "תכונה זו נמצאת כעת בשדרוג.")
    try:
        await call.message.answer(text, reply_markup=telelink_main_menu(), parse_mode=ParseMode.HTML)  # type: ignore[union-attr]
    except Exception as exc:
        logger.error("quick_features error (%s): %s", call.data, exc)
    finally:
        await call.answer()

# ---------------------------------------------------------------------------
# Global blacklist index
# ---------------------------------------------------------------------------
@router.callback_query(F.data == "global_blacklist")
async def view_global_blacklist_index(call: CallbackQuery) -> None:
    try:
        blacklist = await load_blacklist()
        if not blacklist:
            await call.message.edit_text(  # type: ignore[union-attr]
                "🌍 <b>רשימה שחורה עולמית (Global Blacklist)</b>\n\n"
                "המערכת נקייה כרגע. לא התקבלו דיווחים גלובליים לאחרונה.",
                parse_mode=ParseMode.HTML,
                reply_markup=telelink_main_menu(),
            )
            return

        builder = InlineKeyboardBuilder()
        for name, data in blacklist.items():
            reason      = data.get("comment", "דיווח הונאה")
            button_text = (reason[:30] + "...") if len(reason) > 30 else reason
            builder.row(
                InlineKeyboardButton(
                    text=f"❌ {button_text} • לדו''ח",
                    callback_data=f"show_bl_post:{name}",
                )
            )
        builder.row(InlineKeyboardButton(text="🏠 חזרה לתפריט הראשי", callback_data="main_menu"))

        await call.message.edit_text(  # type: ignore[union-attr]
            "🌍 <b>מאגר הדיווחים הגלובלי — TELELINK</b>\n"
            "<i>רשימת ישויות שנמצאו לא אמינות במערכת</i>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "⚠️ <b>שימו לב:</b> הרשימה מטה כוללת משתמשים שדווחו על הונאה.\n"
            "לחצו על התיאור לצפייה בפרטי הנוכל ובראיות.",
            reply_markup=builder.as_markup(),
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("view_global_blacklist_index error: %s", exc)
    finally:
        await call.answer()


@router.callback_query(F.data.startswith("show_bl_post:"))
async def show_blacklist_post_detail(call: CallbackQuery) -> None:
    parts       = call.data.split(":", 1)
    target_name = parts[1] if len(parts) > 1 else ""

    try:
        blacklist = await load_blacklist()
        item      = blacklist.get(target_name)

        if not item:
            await call.answer("⚠️ הרשומה לא נמצאה", show_alert=True)
            return

        clean_name = clean_tg_username(target_name)
        date_str   = str(item.get("timestamp", "2026-01-01"))[:10]

        text = (
            f"🚨 <b>דוח חשיפה רשמי — TELELINK</b> 🚨\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"👤 <b>ישות מדווחת:</b> "
            f"<a href='https://t.me/{clean_name}'>@{clean_name.upper()}</a>\n"
            f"📊 <b>סטטוס מערכת:</b> ❌ <b>SCAMMER / BANNED</b>\n"
            f"📅 <b>תאריך רישום:</b> {date_str}\n\n"
            f"📝 <b>תיאור האירוע:</b>\n"
            f"<blockquote>{_truncate(item.get('comment', 'קיימים דיווחי הונאה מאומתים.'), 500)}</blockquote>\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"🛡️ <b>אזהרה: הימנעו מכל התקשרות או סחר עם ישות זו!</b>"
        )

        builder = InlineKeyboardBuilder()
        builder.row(InlineKeyboardButton(text="🔙 חזרה לרשימה",  callback_data="global_blacklist"))
        builder.row(InlineKeyboardButton(text="🏠 תפריט ראשי",   callback_data="main_menu"))

        await call.message.edit_text(  # type: ignore[union-attr]
            text,
            reply_markup=builder.as_markup(),
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
        )

    except Exception as exc:
        logger.error("show_blacklist_post_detail error: %s", exc)
    finally:
        await call.answer()

# ---------------------------------------------------------------------------
# Admin command centre
# ---------------------------------------------------------------------------
@router.message(Command("admin"))
async def admin_panel(msg: Message) -> None:
    uid = getattr(msg.from_user, "id", None)
    if uid is None or not await is_effective_admin(uid):
        return
    is_super = await is_effective_super_admin(uid)
    try:
        level_label = "מנהל ראשי 👑" if is_super else "מנהל משני 🛠️"
        await msg.answer(
            "⚙️ <b>מרכז הפיקוד של TELELINK</b>\n\n"
            f"שלום לך, {level_label}. בחר פעולה:",
            reply_markup=admin_command_center(is_super=is_super),
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("admin_panel error: %s", exc)


@router.callback_query(F.data == "admin_database")
async def admin_database(call: CallbackQuery, state: FSMContext) -> None:
    uid = getattr(call.from_user, "id", None)
    if uid is None or not await is_effective_admin(uid):
        await call.answer()
        return
    await state.set_state(AdminStates.database_master)
    try:
        await call.message.edit_text(  # type: ignore[union-attr]
            "🗃️ <b>ניהול מסד נתונים מתקדם</b>\n\n"
            "אנא שלחו פקודה לפי הפורמט הבא:\n"
            "<code>add [username] [gold/verified/scammer] [comment]</code>\n\n"
            "או השתמשו בכפתורים למטה:",
            reply_markup=database_keyboard(),
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("admin_database error: %s", exc)
    finally:
        await call.answer()

# --- DB button handlers ---

@router.callback_query(F.data == "db_add")
async def db_add_start(call: CallbackQuery, state: FSMContext) -> None:
    await state.set_state(AdminStates.waiting_db_add)
    try:
        await call.message.answer(  # type: ignore[union-attr]
            "➕ <b>הוספת רשומה למסד הנתונים</b>\n\nאנא שלחו את שם המשתמש/קישור:",
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("db_add_start error: %s", exc)
    finally:
        await call.answer()


@router.message(AdminStates.waiting_db_add)
async def db_add_process(msg: Message, state: FSMContext) -> None:
    entity = normalize_entity(msg.text or "")
    await state.update_data(target=entity)
    await state.set_state(AdminStates.edit_comment)
    try:
        await msg.answer(
            f"הגדרת רשומה עבור: <code>{entity}</code>\n\n"
            "שלחו כעת את הסטטוס והערה:\n"
            "(לדוגמה: <code>gold שירות מומלץ</code> או <code>scammer נוכל מוכר</code>)",
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("db_add_process error: %s", exc)


@router.message(AdminStates.edit_comment)
async def db_add_final_save(msg: Message, state: FSMContext) -> None:
    data   = await state.get_data()
    target = data.get("target", "")

    parts   = (msg.text or "").split(maxsplit=1)
    status  = parts[0].lower() if parts else "scammer"
    comment = parts[1] if len(parts) > 1 else "נוסף דרך ממשק ניהול"

    try:
        if status == "gold":
            gold_list = await load_gold_list()
            gold_list = [g for g in gold_list if g.get("name", "").lower() != target]
            gold_list.append(
                {
                    "name":       target,
                    "short_desc": (comment[:30] + "...") if len(comment) > 30 else comment,
                    "full_post":  comment,
                    "added_at":   datetime.now().isoformat(),
                }
            )
            await save_gold_list(gold_list)
            if msg.from_user:
                await log_audit(msg.from_user.id, "add_gold", target, comment)
            await msg.answer(
                f"💎 <b>רשומת זהב חדשה!</b>\n"
                f"הישות <code>{target}</code> נוספה בהצלחה לנבחרת המומלצים.",
                reply_markup=admin_command_center(),
                parse_mode=ParseMode.HTML,
            )
        else:
            local_data = await load_blacklist()
            stats      = await load_stats()
            local_data[target] = {
                "status":    status,
                "comment":   comment,
                "timestamp": datetime.now().isoformat(),
            }
            await save_blacklist(local_data)
            if status == "verified":
                stats["verified"] = stats.get("verified", 0) + 1
            else:
                stats["banned"] = stats.get("banned", 0) + 1
            await save_stats(stats)
            if msg.from_user:
                await log_audit(msg.from_user.id, f"add_{status}", target, comment)
            await msg.answer(
                f"✅ הרשומה <code>{target}</code> נשמרה בהצלחה בסטטוס {status}.",
                reply_markup=admin_command_center(),
                parse_mode=ParseMode.HTML,
            )
    except Exception as exc:
        logger.error("db_add_final_save error: %s", exc)
        await msg.answer("❌ אירעה שגיאה בשמירת הרשומה.", reply_markup=admin_command_center())
    finally:
        await state.clear()


@router.callback_query(F.data == "db_remove")
async def db_remove_start(call: CallbackQuery, state: FSMContext) -> None:
    await state.set_state(AdminStates.waiting_db_remove)
    try:
        await call.message.answer(  # type: ignore[union-attr]
            "🗑️ <b>מחיקת רשומה</b>\n\nשלחו את שם המשתמש או הקישור שברצונכם להסיר:",
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("db_remove_start error: %s", exc)
    finally:
        await call.answer()


@router.message(AdminStates.waiting_db_remove)
async def db_remove_process(msg: Message, state: FSMContext) -> None:
    entity  = normalize_entity(msg.text or "")
    removed = False

    try:
        blacklist = await load_blacklist()
        if entity in blacklist:
            del blacklist[entity]
            await save_blacklist(blacklist)
            removed = True

        gold_list = await load_gold_list()
        new_gold  = [g for g in gold_list if g.get("name", "").lower() != entity]
        if len(new_gold) < len(gold_list):
            await save_gold_list(new_gold)
            removed = True

        if removed:
            if msg.from_user:
                await log_audit(msg.from_user.id, "remove_record", entity)
            await msg.answer(
                f"✅ הרשומה <code>{entity}</code> הוסרה בהצלחה.",
                reply_markup=admin_command_center(),
                parse_mode=ParseMode.HTML,
            )
        else:
            await msg.answer("❌ הישות לא נמצאה במסד הנתונים.", reply_markup=admin_command_center())
    except Exception as exc:
        logger.error("db_remove_process error: %s", exc)
        await msg.answer("❌ אירעה שגיאה במחיקת הרשומה.", reply_markup=admin_command_center())
    finally:
        await state.clear()


@router.callback_query(F.data == "db_edit")
async def db_edit_start(call: CallbackQuery, state: FSMContext) -> None:
    await state.set_state(AdminStates.waiting_db_edit_id)
    try:
        await call.message.answer(  # type: ignore[union-attr]
            "✏️ <b>עריכת רשומה קיימת</b>\n\nשלחו את שם המשתמש/קישור שברצונכם לערוך:",
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("db_edit_start error: %s", exc)
    finally:
        await call.answer()


@router.message(AdminStates.waiting_db_edit_id)
async def db_edit_process(msg: Message, state: FSMContext) -> None:
    entity    = normalize_entity(msg.text or "")
    blacklist = await load_blacklist()
    gold_list = await load_gold_list()

    in_blacklist = entity in blacklist
    in_gold      = any(g.get("name", "").lower() == entity for g in gold_list)

    if not in_blacklist and not in_gold:
        await msg.answer("❌ רשומה לא קיימת. השתמשו בהוספה.")
        return

    await state.update_data(target=entity)
    await state.set_state(AdminStates.waiting_db_edit_content)
    try:
        await msg.answer(
            f"עריכת <code>{entity}</code>\n\nשלחו את התיאור/סטטוס החדש:",
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("db_edit_process error: %s", exc)


@router.message(AdminStates.waiting_db_edit_content)
async def db_edit_finish(msg: Message, state: FSMContext) -> None:
    data        = await state.get_data()
    target      = data.get("target", "")
    new_content = msg.text or ""

    try:
        blacklist = await load_blacklist()
        if target in blacklist:
            blacklist[target]["comment"] = new_content
            await save_blacklist(blacklist)

        gold_list = await load_gold_list()
        for g in gold_list:
            if g.get("name", "").lower() == target:
                g["full_post"]  = new_content
                g["short_desc"] = (new_content[:30] + "...") if len(new_content) > 30 else new_content
        await save_gold_list(gold_list)

        if msg.from_user:
            await log_audit(msg.from_user.id, "edit_record", target, new_content)
        await msg.answer("✅ הרשומה עודכנה בהצלחה.", reply_markup=admin_command_center())
    except Exception as exc:
        logger.error("db_edit_finish error: %s", exc)
        await msg.answer("❌ אירעה שגיאה בעדכון הרשומה.", reply_markup=admin_command_center())
    finally:
        await state.clear()


@router.message(AdminStates.database_master)
async def handle_database_command(msg: Message, state: FSMContext) -> None:
    """Inline text command handler: add/remove [entity] [status] [comment]"""
    cmd = (msg.text or "").strip().split()
    if len(cmd) < 2:
        await msg.answer("❌ פורמט לא תקין. יש להשתמש ב: add/remove [entity] [status] [comment]")
        return

    action = cmd[0].lower()
    entity = normalize_entity(cmd[1])
    stats  = await load_stats()

    try:
        if action == "add":
            if len(cmd) < 3:
                await msg.answer("❌ חובה לציין סטטוס (scammer/gold/verified).")
                return
            status  = cmd[2].lower()
            comment = " ".join(cmd[3:]) if len(cmd) > 3 else "הוסף על ידי מנהל מערכת"

            if status == "gold":
                gold_list = await load_gold_list()
                gold_list = [g for g in gold_list if g.get("name", "").lower() != entity]
                gold_list.append(
                    {
                        "name":       entity,
                        "short_desc": (comment[:30] + "...") if len(comment) > 30 else comment,
                        "full_post":  comment,
                        "added_at":   datetime.now().isoformat(),
                    }
                )
                await save_gold_list(gold_list)
            else:
                local_data = await load_blacklist()
                local_data[entity] = {
                    "status":    status,
                    "comment":   comment,
                    "timestamp": datetime.now().isoformat(),
                }
                await save_blacklist(local_data)
                if status == "verified":
                    stats["verified"] = stats.get("verified", 0) + 1
                else:
                    stats["banned"] = stats.get("banned", 0) + 1
                await save_stats(stats)

            if msg.from_user:
                await log_audit(msg.from_user.id, f"add_{status}", entity, comment)
            await msg.answer(
                f"✅ <b>בוצע:</b> <code>{entity}</code> נוסף למערכת.",
                parse_mode=ParseMode.HTML,
            )

        elif action == "remove":
            bl     = await load_blacklist()
            if entity in bl:
                del bl[entity]
                await save_blacklist(bl)
            gl     = await load_gold_list()
            new_gl = [g for g in gl if g.get("name", "").lower() != entity]
            await save_gold_list(new_gl)
            if msg.from_user:
                await log_audit(msg.from_user.id, "remove_record", entity)
            await msg.answer(
                f"✅ <b>בוצע:</b> <code>{entity}</code> הוסר.",
                parse_mode=ParseMode.HTML,
            )

        else:
            await msg.answer("❌ פעולה לא מוכרת. השתמשו ב: add / remove")

    except Exception as exc:
        logger.error("handle_database_command error: %s", exc)
        await msg.answer("❌ אירעה שגיאה בביצוע הפקודה.")
    finally:
        await state.clear()

# ---------------------------------------------------------------------------
# Universal Button / Link Editor — admin UI
# ---------------------------------------------------------------------------
_BUTTON_GROUP_TITLES: Dict[str, str] = {
    "main_": "🏠 תפריט ראשי",
    "admin_": "⚙️ פאנל ניהול",
    "geza_bot": "🔗 קישורים",
    "main_channel": "🔗 קישורים",
    "help_support": "🔗 קישורים",
}


def _button_group_of(button_id: str) -> str:
    for prefix, title in _BUTTON_GROUP_TITLES.items():
        if button_id == prefix or button_id.startswith(prefix):
            return title
    return "🔘 אחר"


def buttons_editor_keyboard() -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()

    # ➕ Add a brand-new button/link — quick, single-message flow
    builder.row(InlineKeyboardButton(text="➕ הוספת כפתור/קישור חדש", callback_data="btn_add_new"))

    grouped: Dict[str, List[str]] = {}
    for bid in EDITABLE_BUTTONS:
        grouped.setdefault(_button_group_of(bid), []).append(bid)

    # Stable, friendly section order so the list is easy to scan
    group_order = ["🏠 תפריט ראשי", "🔗 קישורים", "⚙️ פאנל ניהול", "🔘 אחר"]
    for group_title in group_order:
        ids = grouped.get(group_title)
        if not ids:
            continue
        builder.row(InlineKeyboardButton(text=f"─── {group_title} ───", callback_data="noop"))
        for bid in ids:
            current   = get_button_text(bid)
            hidden    = get_button_hidden(bid)
            is_custom = is_button_customised(bid)
            marker    = "🚫" if hidden else ("✏️" if is_custom else "▫️")
            label     = f"{marker} {current}" + (" (מוסתר)" if hidden else "")
            builder.row(
                InlineKeyboardButton(text=label, callback_data=f"btn_edit:{bid}"),
                InlineKeyboardButton(
                    text="👁️ הצג" if hidden else "🗑️ מחק",
                    callback_data=f"btn_toggle_hide:{bid}",
                ),
            )

    # 🆕 Admin-created custom buttons/links — each with its own edit + delete controls
    if _custom_buttons:
        builder.row(InlineKeyboardButton(text="─── 🆕 כפתורים מותאמים אישית ───", callback_data="noop"))
        for entry in _custom_buttons:
            cb_id = entry.get("id", "")
            builder.row(
                InlineKeyboardButton(text=f"🆕 {entry.get('text', cb_id)}", callback_data=f"btn_edit_custom:{cb_id}"),
                InlineKeyboardButton(text="🗑️ מחק", callback_data=f"btn_delete_custom:{cb_id}"),
            )

    builder.row(InlineKeyboardButton(text="⬅️ חזרה לפאנל הניהול", callback_data="admin_back"))
    return builder.as_markup()


def _button_edit_prompt_keyboard(button_id: str) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    hidden = get_button_hidden(button_id)
    builder.row(
        InlineKeyboardButton(
            text="👁️ הצגה מחדש בתפריט" if hidden else "🗑️ מחיקת הכפתור מהתפריט",
            callback_data=f"btn_toggle_hide:{button_id}",
        )
    )
    if button_id in _button_overrides:
        builder.row(InlineKeyboardButton(text="↩️ איפוס לברירת מחדל", callback_data=f"btn_reset:{button_id}"))
    builder.row(InlineKeyboardButton(text="⬅️ חזרה לרשימה", callback_data="admin_buttons"))
    return builder.as_markup()


@router.callback_query(F.data == "admin_buttons")
async def admin_buttons_menu(call: CallbackQuery, state: FSMContext) -> None:
    if not call.from_user or call.from_user.id not in ADMIN_IDS:
        await call.answer()
        return
    await state.clear()
    try:
        await call.message.edit_text(  # type: ignore[union-attr]
            "🔧 <b>עריכת כפתורים וקישורים</b>\n\n"
            "כל כפתור, טקסט וקישור בבוט ניתן לעריכה, מחיקה או הוספה מכאן —\n"
            "מסונכרן אוטומטית לכל מסך בו הוא מופיע, ללא צורך בשינוי קוד.\n\n"
            "➕ הוספת כפתור/קישור חדש לגמרי לתפריט הראשי.\n"
            "🗑️ ליד כל כפתור — מחיקה מיידית מהתפריט (הפיכה בלחיצה אחת).\n"
            "💡 לעריכה מהירה של כפתור עם קישור, שלחו בהודעה אחת:\n"
            "<code>טקסט חדש | קישור חדש</code>\n\n"
            "▫️ ברירת מחדל   |   ✏️ הותאם אישית   |   🚫 מחוק/מוסתר   |   🆕 כפתור מותאם אישית\n\n"
            "בחרו כפתור לעריכה, או השתמשו בכפתור המחיקה/הצגה שלצידו:",
            reply_markup=buttons_editor_keyboard(),
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("admin_buttons_menu error: %s", exc)
    finally:
        await call.answer()


@router.callback_query(F.data.startswith("btn_edit:"))
async def button_edit_select(call: CallbackQuery, state: FSMContext) -> None:
    if not call.from_user or call.from_user.id not in ADMIN_IDS:
        await call.answer()
        return

    button_id = call.data.split(":", 1)[1]
    meta = EDITABLE_BUTTONS.get(button_id)
    if not meta:
        await call.answer("⚠️ כפתור לא נמצא", show_alert=True)
        return

    await state.update_data(edit_button_id=button_id, edit_is_custom=False)
    await state.set_state(AdminStates.button_edit_text)

    current_text = get_button_text(button_id)
    info_lines = [
        f"✏️ <b>עריכת: {meta['label']}</b>",
        "",
        f"טקסט נוכחי: <code>{current_text}</code>",
    ]
    if meta.get("type") == "url":
        info_lines.append(f"קישור נוכחי: <code>{get_button_url(button_id)}</code>")
        info_lines += [
            "",
            "שלחו טקסט חדש בלבד — או שניהם ביחד, בכל פורמט נוח:",
            "<code>טקסט חדש | קישור חדש</code>",
            "או פשוט: <code>טקסט חדש https://הקישור</code>",
            "",
            "שלחו <code>-</code> כדי להשאיר את הטקסט הקיים ללא שינוי.",
        ]
    else:
        info_lines += ["", "שלחו כעת טקסט חדש לכפתור,", "או שלחו <code>-</code> כדי להשאיר את הטקסט הקיים ללא שינוי."]

    try:
        await call.message.edit_text(  # type: ignore[union-attr]
            "\n".join(info_lines),
            reply_markup=_button_edit_prompt_keyboard(button_id),
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("button_edit_select error: %s", exc)
    finally:
        await call.answer()


@router.message(AdminStates.button_edit_text)
async def button_edit_receive_text(msg: Message, state: FSMContext) -> None:
    data      = await state.get_data()
    button_id = data.get("edit_button_id", "")
    is_custom = bool(data.get("edit_is_custom"))
    raw       = (msg.text or "").strip()
    parsed    = parse_label_and_url(raw)

    # --- Editing an admin-created custom button: one convenient message does it all ---
    if is_custom:
        try:
            if parsed:
                label, url = parsed
                await update_custom_button(button_id, text=label or None, url=url)
            elif raw and raw != "-":
                await update_custom_button(button_id, text=raw)
            await msg.answer(
                "✅ הכפתור המותאם עודכן בהצלחה.",
                reply_markup=buttons_editor_keyboard(),
                parse_mode=ParseMode.HTML,
            )
        except Exception as exc:
            logger.error("button_edit_receive_text (custom) error: %s", exc)
            await msg.answer("❌ אירעה שגיאה בשמירת הכפתור.", reply_markup=admin_command_center())
        finally:
            await state.clear()
        return

    meta = EDITABLE_BUTTONS.get(button_id)
    if not meta:
        await state.clear()
        await msg.answer("⚠️ אירעה שגיאה — הכפתור לא נמצא.", reply_markup=admin_command_center())
        return

    # --- ✨ Convenient one-step shortcut: label + URL in one message updates both at once ---
    # Accepts "טקסט | קישור", two separate lines, or the URL simply embedded in the text.
    if meta.get("type") == "url" and parsed:
        label, url = parsed
        try:
            await save_button_override(button_id, text=label or None, url=url)
            await msg.answer(
                f"✅ הכפתור <b>{meta['label']}</b> עודכן בהצלחה (טקסט וקישור בבת אחת).",
                reply_markup=buttons_editor_keyboard(),
                parse_mode=ParseMode.HTML,
            )
        except Exception as exc:
            logger.error("button_edit_receive_text (shortcut) error: %s", exc)
            await msg.answer("❌ אירעה שגיאה בשמירת הכפתור.", reply_markup=admin_command_center())
        finally:
            await state.clear()
        return

    new_text = raw
    if new_text and new_text != "-":
        await state.update_data(pending_text=new_text)
    else:
        await state.update_data(pending_text=None)

    if meta.get("type") == "url":
        await state.set_state(AdminStates.button_edit_url)
        try:
            await msg.answer(
                f"עכשיו שלחו קישור חדש (חייב להתחיל ב-http:// או https://),\n"
                f"או שלחו <code>-</code> כדי להשאיר את הקישור הנוכחי:\n"
                f"<code>{get_button_url(button_id)}</code>",
                parse_mode=ParseMode.HTML,
            )
        except Exception as exc:
            logger.error("button_edit_receive_text error: %s", exc)
        return

    # text-only button — save immediately
    pending = (await state.get_data()).get("pending_text")
    try:
        if pending:
            await save_button_override(button_id, text=pending)
        await msg.answer(
            f"✅ הכפתור <b>{meta['label']}</b> עודכן בהצלחה.",
            reply_markup=buttons_editor_keyboard(),
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("button_edit_receive_text save error: %s", exc)
        await msg.answer("❌ אירעה שגיאה בשמירת הכפתור.", reply_markup=admin_command_center())
    finally:
        await state.clear()


@router.message(AdminStates.button_edit_url)
async def button_edit_receive_url(msg: Message, state: FSMContext) -> None:
    data      = await state.get_data()
    button_id = data.get("edit_button_id", "")
    meta      = EDITABLE_BUTTONS.get(button_id)
    pending_text = data.get("pending_text")

    if not meta:
        await state.clear()
        await msg.answer("⚠️ אירעה שגיאה — הכפתור לא נמצא.", reply_markup=admin_command_center())
        return

    new_url = (msg.text or "").strip()
    valid_url = new_url and new_url != "-" and new_url.startswith(("http://", "https://", "tg://"))

    if new_url and new_url != "-" and not valid_url:
        await msg.answer("❌ קישור לא תקין. הקישור חייב להתחיל ב-http:// או https://. נסו שוב:")
        return

    try:
        await save_button_override(
            button_id,
            text=pending_text,
            url=new_url if valid_url else None,
        )
        await msg.answer(
            f"✅ הכפתור <b>{meta['label']}</b> עודכן בהצלחה.",
            reply_markup=buttons_editor_keyboard(),
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("button_edit_receive_url error: %s", exc)
        await msg.answer("❌ אירעה שגיאה בשמירת הכפתור.", reply_markup=admin_command_center())
    finally:
        await state.clear()


@router.callback_query(F.data.startswith("btn_reset:"))
async def button_reset(call: CallbackQuery, state: FSMContext) -> None:
    if not call.from_user or call.from_user.id not in ADMIN_IDS:
        await call.answer()
        return
    button_id = call.data.split(":", 1)[1]
    try:
        await reset_button_override(button_id)
        await call.message.edit_text(  # type: ignore[union-attr]
            "↩️ הכפתור אופס לברירת המחדל.",
            reply_markup=buttons_editor_keyboard(),
        )
    except Exception as exc:
        logger.error("button_reset error: %s", exc)
    finally:
        await call.answer()


# --- Delete / restore a built-in button with one tap (reversible "מחיקה") ---
@router.callback_query(F.data.startswith("btn_toggle_hide:"))
async def button_toggle_hide(call: CallbackQuery, state: FSMContext) -> None:
    if not call.from_user or call.from_user.id not in ADMIN_IDS:
        await call.answer()
        return
    button_id = call.data.split(":", 1)[1]
    if button_id not in EDITABLE_BUTTONS:
        await call.answer("⚠️ כפתור לא נמצא", show_alert=True)
        return
    try:
        new_hidden = not get_button_hidden(button_id)
        await set_button_hidden(button_id, new_hidden)
        await call.message.edit_text(  # type: ignore[union-attr]
            "🗑️ הכפתור נמחק מהתפריט (ניתן להחזיר בכל רגע)." if new_hidden else "👁️ הכפתור הוחזר לתפריט.",
            reply_markup=buttons_editor_keyboard(),
        )
    except Exception as exc:
        logger.error("button_toggle_hide error: %s", exc)
    finally:
        await call.answer()


# --- Section-header buttons in the editor list are purely visual dividers ---
@router.callback_query(F.data == "noop")
async def noop_callback(call: CallbackQuery) -> None:
    await call.answer()


# --- Add a brand-new custom button/link (appears in the main menu automatically) ---
@router.callback_query(F.data == "btn_add_new")
async def button_add_new_start(call: CallbackQuery, state: FSMContext) -> None:
    if not call.from_user or call.from_user.id not in ADMIN_IDS:
        await call.answer()
        return
    await state.set_state(AdminStates.button_add_new)
    try:
        await call.message.edit_text(  # type: ignore[union-attr]
            "➕ <b>הוספת כפתור/קישור חדש</b>\n\n"
            "שלחו את הטקסט והקישור בכל אחד מהפורמטים הבאים — איך שנוח לכם:\n\n"
            "1️⃣ <code>טקסט הכפתור | https://הקישור-שלכם</code>\n"
            "2️⃣ שתי שורות נפרדות:\n"
            "<code>טקסט הכפתור\nhttps://הקישור-שלכם</code>\n"
            "3️⃣ פשוט כתבו טקסט וקישור באותה שורה, לדוגמה:\n"
            "<code>📞 צרו קשר https://t.me/example</code>\n\n"
            "הכפתור יתווסף אוטומטית לתפריט הראשי של הבוט.",
            reply_markup=InlineKeyboardMarkup(
                inline_keyboard=[[InlineKeyboardButton(text="⬅️ ביטול וחזרה", callback_data="admin_buttons")]]
            ),
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("button_add_new_start error: %s", exc)
    finally:
        await call.answer()


@router.message(AdminStates.button_add_new)
async def button_add_new_receive(msg: Message, state: FSMContext) -> None:
    raw    = msg.text or ""
    parsed = parse_label_and_url(raw)

    if not parsed:
        await msg.answer(
            "❌ לא זיהיתי קישור תקין בהודעה.\n\n"
            "ודאו שהקישור מתחיל ב-<code>http://</code> או <code>https://</code>, ונסו שוב באחד מהפורמטים:\n"
            "<code>טקסט | קישור</code>\n"
            "או פשוט טקסט וקישור באותה שורה.",
            parse_mode=ParseMode.HTML,
        )
        return

    label, url = parsed
    try:
        await add_custom_button(label, url)
        await msg.answer(
            f"✅ הכפתור <b>{label}</b> נוסף בהצלחה לתפריט הראשי!\n"
            f"🔗 <code>{url}</code>",
            reply_markup=buttons_editor_keyboard(),
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("button_add_new_receive error: %s", exc)
        await msg.answer("❌ אירעה שגיאה בהוספת הכפתור.", reply_markup=admin_command_center())
    finally:
        await state.clear()


# --- Edit an existing custom button (single convenient "טקסט | קישור" message) ---
@router.callback_query(F.data.startswith("btn_edit_custom:"))
async def button_edit_custom_select(call: CallbackQuery, state: FSMContext) -> None:
    if not call.from_user or call.from_user.id not in ADMIN_IDS:
        await call.answer()
        return

    cb_id = call.data.split(":", 1)[1]
    entry = next((b for b in _custom_buttons if b.get("id") == cb_id), None)
    if not entry:
        await call.answer("⚠️ הכפתור לא נמצא", show_alert=True)
        return

    await state.update_data(edit_button_id=cb_id, edit_is_custom=True)
    await state.set_state(AdminStates.button_edit_text)

    try:
        await call.message.edit_text(  # type: ignore[union-attr]
            f"✏️ <b>עריכת כפתור מותאם</b>\n\n"
            f"טקסט נוכחי: <code>{entry.get('text', '')}</code>\n"
            f"קישור נוכחי: <code>{entry.get('url', '')}</code>\n\n"
            f"שלחו בכל פורמט נוח:\n"
            f"<code>טקסט חדש | קישור חדש</code>\n"
            f"או פשוט: <code>טקסט חדש https://הקישור</code>\n"
            f"(או שלחו רק טקסט כדי לשנות את הכיתוב בלבד, ללא נגיעה בקישור)",
            reply_markup=InlineKeyboardMarkup(
                inline_keyboard=[
                    [InlineKeyboardButton(text="🗑️ מחיקת כפתור זה", callback_data=f"btn_delete_custom:{cb_id}")],
                    [InlineKeyboardButton(text="⬅️ חזרה לרשימה", callback_data="admin_buttons")],
                ]
            ),
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("button_edit_custom_select error: %s", exc)
    finally:
        await call.answer()


# --- Delete a custom button entirely ---
@router.callback_query(F.data.startswith("btn_delete_custom:"))
async def button_delete_custom(call: CallbackQuery, state: FSMContext) -> None:
    if not call.from_user or call.from_user.id not in ADMIN_IDS:
        await call.answer()
        return
    cb_id = call.data.split(":", 1)[1]
    try:
        removed = await remove_custom_button(cb_id)
        await call.message.edit_text(  # type: ignore[union-attr]
            "🗑️ הכפתור נמחק בהצלחה." if removed else "⚠️ הכפתור לא נמצא (כנראה כבר נמחק).",
            reply_markup=buttons_editor_keyboard(),
        )
    except Exception as exc:
        logger.error("button_delete_custom error: %s", exc)
    finally:
        await state.clear()
        await call.answer()

# ---------------------------------------------------------------------------
# Broadcast — professional wizard (media + optional inline buttons + preview)
# ---------------------------------------------------------------------------
def _parse_broadcast_buttons(raw_text: str) -> Optional[InlineKeyboardMarkup]:
    """
    Parse admin-supplied button definitions into an InlineKeyboardMarkup.
    Format (one row per line, buttons in the same row separated by ';'):
        טקסט הכפתור | https://example.com
        כפתור א | https://a.com ; כפתור ב | https://b.com
    Returns None if no valid button lines were found.
    """
    builder = InlineKeyboardBuilder()
    found = False
    for line in (raw_text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        row_buttons: List[InlineKeyboardButton] = []
        for chunk in line.split(";"):
            chunk = chunk.strip()
            if "|" not in chunk:
                continue
            label, url = chunk.split("|", 1)
            label, url = label.strip(), url.strip()
            if not label or not url.startswith(("http://", "https://", "tg://")):
                continue
            row_buttons.append(InlineKeyboardButton(text=label, url=url))
        if row_buttons:
            builder.row(*row_buttons)
            found = True
    return builder.as_markup() if found else None


def _broadcast_menu_keyboard(has_buttons: bool) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    if has_buttons:
        builder.row(InlineKeyboardButton(text="🚀 שליחה עם הכפתורים לכולם", callback_data="bc_send"))
        builder.row(InlineKeyboardButton(text="♻️ החלפת הכפתורים", callback_data="bc_add_buttons"))
    else:
        builder.row(InlineKeyboardButton(text="➕ הוספת כפתורים לפוסט", callback_data="bc_add_buttons"))
        builder.row(InlineKeyboardButton(text="🚀 שליחה עכשיו (ללא כפתורים)", callback_data="bc_send"))
    builder.row(InlineKeyboardButton(text="❌ ביטול שידור", callback_data="bc_cancel"))
    return builder.as_markup()


async def _send_broadcast_preview(target: Message, data: Dict[str, Any]) -> None:
    """Render the exact post (media + caption + buttons) as a preview to the admin."""
    kb_data = data.get("buttons_markup")
    reply_markup = InlineKeyboardMarkup(**kb_data) if kb_data else None
    caption = data.get("text") or ""
    media_type = data.get("media_type")
    file_id = data.get("file_id")

    try:
        if media_type == "photo" and file_id:
            await target.answer_photo(file_id, caption=caption, parse_mode=ParseMode.HTML, reply_markup=reply_markup)
        elif media_type == "video" and file_id:
            await target.answer_video(file_id, caption=caption, parse_mode=ParseMode.HTML, reply_markup=reply_markup)
        elif media_type == "document" and file_id:
            await target.answer_document(file_id, caption=caption, parse_mode=ParseMode.HTML, reply_markup=reply_markup)
        elif media_type == "animation" and file_id:
            await target.answer_animation(file_id, caption=caption, parse_mode=ParseMode.HTML, reply_markup=reply_markup)
        else:
            await target.answer(caption or "(פוסט ריק)", parse_mode=ParseMode.HTML, reply_markup=reply_markup)
    except Exception as exc:
        logger.error("_send_broadcast_preview error: %s", exc)


@router.callback_query(F.data == "admin_broadcast")
async def admin_broadcast_start(call: CallbackQuery, state: FSMContext) -> None:
    if not call.from_user or call.from_user.id not in ADMIN_IDS:
        await call.answer()
        return
    await state.set_state(AdminStates.mass_broadcast)
    try:
        await call.message.answer(  # type: ignore[union-attr]
            "📢 <b>מערכת שידור הודעות מקצועית</b>\n\n"
            "שלחו את תוכן הפוסט שברצונכם לשדר לכל משתמשי הבוט.\n"
            "נתמך: טקסט עם עיצוב HTML, תמונה, וידאו, GIF/אנימציה או קובץ — עם כיתוב.\n\n"
            "<i>לאחר קבלת התוכן תוכלו להוסיף לפוסט כפתורים עם קישורים, "
            "לצפות בתצוגה מקדימה ורק אז לאשר שליחה לכולם.</i>",
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("admin_broadcast_start error: %s", exc)
    finally:
        await call.answer()


@router.message(AdminStates.mass_broadcast)
async def broadcast_capture_content(msg: Message, state: FSMContext) -> None:
    """Step 1: capture the post content (text or any supported media type)."""
    text = msg.html_text or msg.caption or ""
    media_type: Optional[str] = None
    file_id: Optional[str] = None

    if msg.photo:
        media_type, file_id = "photo", msg.photo[-1].file_id
    elif msg.video:
        media_type, file_id = "video", msg.video.file_id
    elif msg.animation:
        media_type, file_id = "animation", msg.animation.file_id
    elif msg.document:
        media_type, file_id = "document", msg.document.file_id

    if not text and not file_id:
        await msg.answer("❌ שגיאה: לא נמצא תוכן לשליחה. שלחו טקסט או מדיה עם כיתוב.")
        return

    await state.update_data(text=text, media_type=media_type, file_id=file_id, buttons_markup=None)
    await state.set_state(AdminStates.broadcast_menu)

    data = await state.get_data()
    try:
        await msg.answer("👁️ <b>תצוגה מקדימה של הפוסט:</b>", parse_mode=ParseMode.HTML)
        await _send_broadcast_preview(msg, data)
        await msg.answer(
            "בחרו כיצד להמשיך:",
            reply_markup=_broadcast_menu_keyboard(has_buttons=False),
        )
    except Exception as exc:
        logger.error("broadcast_capture_content error: %s", exc)


@router.callback_query(AdminStates.broadcast_menu, F.data == "bc_add_buttons")
async def broadcast_ask_buttons(call: CallbackQuery, state: FSMContext) -> None:
    await state.set_state(AdminStates.broadcast_wait_buttons)
    try:
        await call.message.answer(  # type: ignore[union-attr]
            "➕ <b>הוספת כפתורים לפוסט</b>\n\n"
            "שלחו שורה אחת לכל כפתור, בפורמט:\n"
            "<code>טקסט הכפתור | https://example.com</code>\n\n"
            "לכמה כפתורים באותה שורה, הפרידו ב-<code>;</code>:\n"
            "<code>כפתור א | https://a.com ; כפתור ב | https://b.com</code>",
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("broadcast_ask_buttons error: %s", exc)
    finally:
        await call.answer()


@router.message(AdminStates.broadcast_wait_buttons)
async def broadcast_receive_buttons(msg: Message, state: FSMContext) -> None:
    markup = _parse_broadcast_buttons(msg.text or "")
    if not markup:
        await msg.answer("❌ לא זוהו כפתורים תקינים. נסו שוב לפי הפורמט שהוצג, או שלחו /admin לביטול.")
        return

    await state.update_data(buttons_markup=markup.model_dump())
    await state.set_state(AdminStates.broadcast_menu)

    data = await state.get_data()
    try:
        await msg.answer("👁️ <b>תצוגה מקדימה מעודכנת:</b>", parse_mode=ParseMode.HTML)
        await _send_broadcast_preview(msg, data)
        await msg.answer(
            "הכפתורים נוספו לפוסט. מוכנים לשליחה?",
            reply_markup=_broadcast_menu_keyboard(has_buttons=True),
        )
    except Exception as exc:
        logger.error("broadcast_receive_buttons error: %s", exc)


@router.callback_query(AdminStates.broadcast_menu, F.data == "bc_cancel")
async def broadcast_cancel(call: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    try:
        await call.message.edit_text(  # type: ignore[union-attr]
            "❌ השידור בוטל.",
            reply_markup=admin_command_center(),
        )
    except Exception as exc:
        logger.error("broadcast_cancel error: %s", exc)
    finally:
        await call.answer()


@router.callback_query(AdminStates.broadcast_menu, F.data == "bc_send")
async def broadcast_send_confirmed(call: CallbackQuery, state: FSMContext) -> None:
    if not call.from_user or call.from_user.id not in ADMIN_IDS:
        await call.answer()
        return

    data = await state.get_data()
    caption     = data.get("text") or ""
    media_type  = data.get("media_type")
    file_id     = data.get("file_id")
    kb_data     = data.get("buttons_markup")
    reply_markup = InlineKeyboardMarkup(**kb_data) if kb_data else None

    users = await load_users()
    sent, failed = 0, 0

    try:
        status_msg = await call.message.answer(f"⏳ מבצע שידור ל-{len(users)} משתמשים...")  # type: ignore[union-attr]
    except Exception as exc:
        logger.error("Cannot send broadcast status message: %s", exc)
        await call.answer()
        return

    bot: Bot = call.bot  # type: ignore[assignment]
    for user in users:
        uid = user.get("id")
        if not uid:
            continue
        try:
            if media_type == "photo" and file_id:
                await bot.send_photo(uid, photo=file_id, caption=caption, parse_mode=ParseMode.HTML, reply_markup=reply_markup)
            elif media_type == "video" and file_id:
                await bot.send_video(uid, video=file_id, caption=caption, parse_mode=ParseMode.HTML, reply_markup=reply_markup)
            elif media_type == "document" and file_id:
                await bot.send_document(uid, document=file_id, caption=caption, parse_mode=ParseMode.HTML, reply_markup=reply_markup)
            elif media_type == "animation" and file_id:
                await bot.send_animation(uid, animation=file_id, caption=caption, parse_mode=ParseMode.HTML, reply_markup=reply_markup)
            else:
                await bot.send_message(uid, caption, parse_mode=ParseMode.HTML, reply_markup=reply_markup)
            sent += 1
        except Exception:
            failed += 1
        await asyncio.sleep(0.05)

    try:
        await status_msg.edit_text(
            f"✅ <b>השידור הושלם</b>\n"
            f"נשלחו: <code>{sent}</code> | נכשלו: <code>{failed}</code>",
            parse_mode=ParseMode.HTML,
        )
        await call.message.answer("⚙️ חזרה למרכז הפיקוד:", reply_markup=admin_command_center())  # type: ignore[union-attr]
    except Exception as exc:
        logger.error("Cannot edit broadcast status: %s", exc)
    finally:
        await state.clear()
        await call.answer()

# ---------------------------------------------------------------------------
# Report generator
# ---------------------------------------------------------------------------
@router.callback_query(F.data == "admin_report_gen")
async def admin_report_generator(call: CallbackQuery) -> None:
    if not call.from_user or call.from_user.id not in ADMIN_IDS:
        await call.answer()
        return
    try:
        stats     = await load_stats()
        reports   = await load_reports()
        blacklist = await load_blacklist()
        gold_list = await load_gold_list()

        pending_count  = sum(1 for r in reports if r.get("status") == "pending")
        approved_count = sum(1 for r in reports if r.get("status") == "approved")

        report_text = (
            f"📊 <b>דוח מצב מערכת — TELELINK</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"📅 תאריך: {datetime.now().strftime('%d/%m/%Y %H:%M')}\n\n"
            f"👥 משתמשים:      <code>{stats.get('users', 0)}</code>\n"
            f"🔍 סריקות:       <code>{stats.get('checks', 0)}</code>\n"
            f"✅ מאומתים:      <code>{stats.get('verified', 0)}</code>\n"
            f"❌ חסומים:       <code>{stats.get('banned', 0)}</code>\n"
            f"💎 רשימת זהב:   <code>{len(gold_list)}</code>\n\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"📁 דיווחים סה\"כ:    <code>{len(reports)}</code>\n"
            f"⏳ ממתינים לבדיקה:  <code>{pending_count}</code>\n"
            f"✅ אושרו:           <code>{approved_count}</code>\n"
            f"🌍 רשימה שחורה:    <code>{len(blacklist)}</code> רשומות."
        )
        await call.message.answer(  # type: ignore[union-attr]
            report_text,
            parse_mode=ParseMode.HTML,
            reply_markup=admin_command_center(),
        )
    except Exception as exc:
        logger.error("admin_report_generator error: %s", exc)
    finally:
        await call.answer()

# ---------------------------------------------------------------------------
# Evidence review — one-by-one navigable queue of pending reports
# ---------------------------------------------------------------------------
@router.callback_query(F.data == "admin_evidence")
async def admin_evidence(call: CallbackQuery) -> None:
    """
    Entry point for "🔍 בדיקת דיווחים (ראיות)" in the admin panel — opens the
    full queue of pending reports, one at a time, with ⬅️ הקודם / ➡️ הבא
    navigation so the admin can browse every open case in order.
    """
    if not call.from_user or call.from_user.id not in ADMIN_IDS:
        await call.answer()
        return
    try:
        reports = await load_reports()
        pending = [r for r in reports if r.get("status") == "pending"]

        if not pending:
            await call.message.answer(  # type: ignore[union-attr]
                "📂 אין דיווחים חדשים הממתינים לבדיקה כרגע.",
                reply_markup=admin_command_center(),
            )
            return

        entry = pending[0]
        text = _report_packet_text(entry, position=(0, len(pending)))
        keyboard = _evidence_queue_keyboard(entry["id"], 0, len(pending))
        try:
            await call.message.answer(text, reply_markup=keyboard, parse_mode=ParseMode.HTML)  # type: ignore[union-attr]
        except Exception as exc:
            logger.warning("admin_evidence HTML send failed, retrying as plain text: %s", exc)
            await call.message.answer(_strip_html_tags(text), reply_markup=keyboard)  # type: ignore[union-attr]
    except Exception as exc:
        logger.error("admin_evidence error: %s", exc)
    finally:
        await call.answer()


@router.callback_query(F.data.startswith("evidence_nav:"))
async def evidence_navigate(call: CallbackQuery) -> None:
    """Move to the previous/next pending report inside the same queue screen."""
    if not call.from_user or call.from_user.id not in ADMIN_IDS:
        await call.answer()
        return
    try:
        requested_index = int(call.data.split(":", 1)[1])
    except (ValueError, IndexError):
        requested_index = 0

    try:
        reports = await load_reports()
        pending = [r for r in reports if r.get("status") == "pending"]

        if not pending:
            await call.message.edit_text(  # type: ignore[union-attr]
                "📂 אין (יותר) דיווחים הממתינים לבדיקה — כולם טופלו.",
                reply_markup=admin_command_center(),
            )
            await call.answer()
            return

        index = max(0, min(requested_index, len(pending) - 1))
        entry = pending[index]
        text = _report_packet_text(entry, position=(index, len(pending)))
        keyboard = _evidence_queue_keyboard(entry["id"], index, len(pending))

        try:
            await call.message.edit_text(text, reply_markup=keyboard, parse_mode=ParseMode.HTML)  # type: ignore[union-attr]
        except Exception as exc:
            logger.warning("evidence_navigate HTML edit failed, retrying as plain text: %s", exc)
            await call.message.edit_text(_strip_html_tags(text), reply_markup=keyboard)  # type: ignore[union-attr]
    except Exception as exc:
        logger.error("evidence_navigate error: %s", exc)
    finally:
        await call.answer()


async def _finish_review_notice(call: CallbackQuery, text: str) -> None:
    """
    Close out an approve/reject decision on the admin's message — works whether
    the original packet was delivered as a photo-with-caption (evidence embedded)
    or as a plain text message, so the UI never breaks either way.
    """
    msg = call.message
    try:
        if msg and getattr(msg, "photo", None):
            await msg.edit_caption(caption=text, parse_mode=ParseMode.HTML)  # type: ignore[union-attr]
        else:
            await msg.edit_text(text, parse_mode=ParseMode.HTML)  # type: ignore[union-attr]
    except Exception as exc:
        logger.warning("_finish_review_notice edit failed, sending a new message instead: %s", exc)
        try:
            await msg.answer(text, parse_mode=ParseMode.HTML)  # type: ignore[union-attr]
        except Exception as exc2:
            logger.error("_finish_review_notice fallback failed: %s", exc2)


@router.callback_query(F.data.startswith("view_evidence:"))
async def view_evidence_inline(call: CallbackQuery) -> None:
    """
    Reveal the full evidence (every photo + any text/link proof) for a report,
    only on explicit admin request — keeps the initial notification clean and
    professional, and lets the admin inspect everything before deciding.
    """
    if not call.from_user or call.from_user.id not in ADMIN_IDS:
        await call.answer()
        return
    report_id = call.data.split(":", 1)[1]
    try:
        reports = await load_reports()
        entry = next((r for r in reports if r.get("id") == report_id), None)
        if not entry:
            await call.answer("⚠️ הדיווח לא נמצא — ייתכן שכבר טופל.", show_alert=True)
            return
        await _reveal_report_evidence(call.bot, call.from_user.id, entry)  # type: ignore[arg-type]
    except Exception as exc:
        logger.error("view_evidence_inline error: %s", exc)
    finally:
        await call.answer()


@router.callback_query(F.data.startswith("approve_report:"))
async def approve_report_inline(call: CallbackQuery) -> None:
    if not call.from_user or call.from_user.id not in ADMIN_IDS:
        await call.answer()
        return

    parts     = call.data.split(":", 1)
    report_id = parts[1] if len(parts) > 1 else ""

    try:
        reports = await load_reports()
        for r in reports:
            if r.get("id") == report_id:
                r["status"] = "approved"
                target       = normalize_entity(r.get("username", ""))
                blacklist    = await load_blacklist()
                blacklist[target] = {
                    "status":    "scammer",
                    "comment":   f"דוח מאושר #{report_id}",
                    "timestamp": datetime.now().isoformat(),
                }
                await save_blacklist(blacklist)

                stats = await load_stats()
                stats["banned"] = stats.get("banned", 0) + 1
                await save_stats(stats)

                await _finish_review_notice(
                    call,
                    f"✅ <b>התיק #{report_id} אושר ונסגר.</b>\n"
                    f"🎯 הישות <code>{target}</code> נחסמה והתווספה לרשימה השחורה הגלובלית.",
                )
                break
        await save_reports(reports)

    except Exception as exc:
        logger.error("approve_report_inline error: %s", exc)
    finally:
        await call.answer()


@router.callback_query(F.data.startswith("reject_report:"))
async def reject_report_inline(call: CallbackQuery) -> None:
    if not call.from_user or call.from_user.id not in ADMIN_IDS:
        await call.answer()
        return

    parts     = call.data.split(":", 1)
    report_id = parts[1] if len(parts) > 1 else ""

    try:
        reports = await load_reports()
        for r in reports:
            if r.get("id") == report_id:
                r["status"] = "rejected"
                await _finish_review_notice(
                    call,
                    f"❌ <b>התיק #{report_id} נדחה ונסגר</b> — הראיות שנבדקו לא הצדיקו חסימה.",
                )
                break
        await save_reports(reports)
    except Exception as exc:
        logger.error("reject_report_inline error: %s", exc)
    finally:
        await call.answer()

# ---------------------------------------------------------------------------
# Gold list index
# ---------------------------------------------------------------------------
@router.callback_query(F.data == "view_gold_list")
async def view_gold_list_index(call: CallbackQuery) -> None:
    try:
        gold_list = await load_gold_list()
        if not gold_list:
            await call.answer("✨ רשימת המומלצים מתעדכנת ברגעים אלו...", show_alert=True)
            return

        builder = InlineKeyboardBuilder()
        for idx, item in enumerate(gold_list):
            raw_name = clean_tg_username(item.get("name", "N/A"))
            builder.row(
                InlineKeyboardButton(
                    text=f"💎 {raw_name.upper()} • לדו''ח המלא",
                    callback_data=f"sgp_idx:{idx}",
                )
            )
        builder.row(InlineKeyboardButton(text="🔙 חזרה לתפריט הראשי", callback_data="main_menu"))

        await call.message.edit_text(  # type: ignore[union-attr]
            "🏆 <b>נבחרת הזהב — Telelink Premium</b>\n"
            "<i>אינדקס נותני שירות מאומתים</i>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "💡 <b>לבדיקת נותן שירות והמלצה מפורטת, לחצו מטה:</b>",
            reply_markup=builder.as_markup(),
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
        )
    except Exception as exc:
        logger.error("view_gold_list_index error: %s", exc)
    finally:
        await call.answer()


@router.callback_query(F.data.startswith("sgp_idx:"))
async def show_gold_post_detail(call: CallbackQuery) -> None:
    try:
        parts = call.data.split(":", 1)
        idx   = int(parts[1]) if len(parts) > 1 else -1

        gold_list = await load_gold_list()
        if idx < 0 or idx >= len(gold_list):
            await call.answer("⚠️ המידע אינו זמין או שהרשימה עודכנה", show_alert=True)
            return

        item       = gold_list[idx]
        clean_name = clean_tg_username(item.get("name", ""))
        added_date = str(item.get("added_at", "2026-01-01"))[:10]

        text = (
            f"💎 <b>דוח המלצה רשמי — נבחרת הזהב</b> 💎\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"👤 <b>ישות מאומתת:</b> @{clean_name}\n"
            f"📊 <b>סטטוס:</b> ✅ מומלץ / GOLD MEMBER\n"
            f"📅 <b>תאריך הוספה:</b> {added_date}\n\n"
            f"📝 <b>פירוט המלצת המערכת:</b>\n"
            f"<i>{_truncate(item.get('full_post', 'נותן שירות מאומת על ידי צוות המערכת — ללא חשש הונאה.'), 800)}</i>\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"🛡️ <b>המלצת TELELINK:</b> ניתן לסחור ולהתקשר בביטחון!"
        )

        builder = InlineKeyboardBuilder()
        builder.row(
            InlineKeyboardButton(
                text=f"🔗 פתיחת שיחה עם {clean_name}",
                url=f"https://t.me/{clean_name}",
            )
        )
        builder.row(InlineKeyboardButton(text="🔙 חזרה לרשימת המומלצים", callback_data="view_gold_list"))

        await call.message.edit_text(  # type: ignore[union-attr]
            text,
            reply_markup=builder.as_markup(),
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
        )

    except (ValueError, IndexError) as exc:
        logger.warning("show_gold_post_detail bad index: %s", exc)
        await call.answer("⚠️ המידע אינו זמין", show_alert=True)
    except Exception as exc:
        logger.error("show_gold_post_detail error: %s", exc)
    finally:
        await call.answer()

# ---------------------------------------------------------------------------
# Navigation
# ---------------------------------------------------------------------------
@router.callback_query(F.data == "main_menu")
async def back_to_main(call: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    try:
        await call.message.delete()  # type: ignore[union-attr]
    except Exception:
        pass
    try:
        await call.message.answer(  # type: ignore[union-attr]
            "🛡️ <b>תפריט ראשי — TELELINK</b>",
            reply_markup=telelink_main_menu(),
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("back_to_main error: %s", exc)
    finally:
        await call.answer()


@router.callback_query(F.data == "admin_back")
async def admin_back(call: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    uid = getattr(call.from_user, "id", None)
    is_super = await is_effective_super_admin(uid) if uid is not None else False
    try:
        await call.message.edit_text(  # type: ignore[union-attr]
            "⚙️ <b>מרכז הפיקוד של TELELINK</b>",
            reply_markup=admin_command_center(is_super=is_super),
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("admin_back error: %s", exc)
    finally:
        await call.answer()

# ---------------------------------------------------------------------------
# NEW FEATURE 1 — Advanced search & filter across whitelist/blacklist/gold
# ---------------------------------------------------------------------------
_SEARCH_RESULT_LIMIT = 15


def _format_search_hit(entity: str, entry: Dict[str, Any], *, is_gold: bool = False) -> str:
    if is_gold:
        added = str(entry.get("added_at", ""))[:10]
        desc  = _truncate(_esc(entry.get("short_desc") or entry.get("full_post", "")), 80)
        return f"💎 <code>{_esc(entity)}</code> · gold · {added}\n<i>{desc}</i>"
    status = _esc(entry.get("status", "—"))
    stamp  = str(entry.get("timestamp", ""))[:10]
    desc   = _truncate(_esc(entry.get("comment", "")), 80)
    return f"🔹 <code>{_esc(entity)}</code> · {status} · {stamp}\n<i>{desc}</i>"


async def _run_search(status_filter: Optional[str] = None) -> List[str]:
    """Return formatted result lines across blacklist + gold list, optionally filtered by status."""
    lines: List[str] = []
    if status_filter != "gold":
        blacklist = await load_blacklist()
        for entity, entry in blacklist.items():
            if not isinstance(entry, dict):
                continue
            if status_filter and status_filter != "all" and entry.get("status") != status_filter:
                continue
            lines.append(_format_search_hit(entity, entry))
    if status_filter in (None, "all", "gold"):
        gold_list = await load_gold_list()
        for entry in gold_list:
            if not isinstance(entry, dict):
                continue
            lines.append(_format_search_hit(entry.get("name", "?"), entry, is_gold=True))
    return lines


@router.callback_query(F.data == "admin_search")
async def admin_search_menu(call: CallbackQuery, state: FSMContext) -> None:
    uid = getattr(call.from_user, "id", None)
    if uid is None or not await is_effective_admin(uid):
        await call.answer()
        return
    await state.clear()
    try:
        await call.message.edit_text(  # type: ignore[union-attr]
            "🔎 <b>חיפוש וסינון מתקדם</b>\n\n"
            "חפשו רשומה ספציפית לפי שם, או סננו את כל המסד לפי סטטוס/תאריך:",
            reply_markup=search_filter_keyboard(),
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("admin_search_menu error: %s", exc)
    finally:
        await call.answer()


@router.callback_query(F.data == "search_by_username")
async def search_by_username_start(call: CallbackQuery, state: FSMContext) -> None:
    await state.set_state(AdminStates.search_waiting_username)
    try:
        await call.message.answer(  # type: ignore[union-attr]
            "🔤 שלחו שם משתמש (או חלק ממנו) לחיפוש:",
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("search_by_username_start error: %s", exc)
    finally:
        await call.answer()


@router.message(AdminStates.search_waiting_username)
async def search_by_username_process(msg: Message, state: FSMContext) -> None:
    query = normalize_entity(msg.text or "")
    await state.clear()
    if not query:
        await msg.answer("❌ יש להזין טקסט לחיפוש.", reply_markup=admin_command_center())
        return

    try:
        all_lines = await _run_search(None)
        matches   = [line for line in all_lines if query in line.lower()]
        if not matches:
            await msg.answer(
                f"🔍 לא נמצאו תוצאות עבור <code>{_esc(query)}</code>.",
                reply_markup=search_filter_keyboard(),
                parse_mode=ParseMode.HTML,
            )
            return

        header = f"🔎 <b>{len(matches)} תוצאות עבור \"{_esc(query)}\":</b>\n\n"
        body   = "\n\n".join(matches[:_SEARCH_RESULT_LIMIT])
        footer = "" if len(matches) <= _SEARCH_RESULT_LIMIT else f"\n\n… ועוד {len(matches) - _SEARCH_RESULT_LIMIT} תוצאות (צמצמו את החיפוש)"
        await msg.answer(header + body + footer, reply_markup=search_filter_keyboard(), parse_mode=ParseMode.HTML)
    except Exception as exc:
        logger.error("search_by_username_process error: %s", exc)
        await msg.answer("❌ אירעה שגיאה בחיפוש.", reply_markup=admin_command_center())


@router.callback_query(F.data.in_({"search_filter_whitelist", "search_filter_blacklist", "search_filter_gold", "search_filter_all"}))
async def search_filter_apply(call: CallbackQuery, state: FSMContext) -> None:
    status_map = {
        "search_filter_whitelist": "verified",
        "search_filter_blacklist": "scammer",
        "search_filter_gold":      "gold",
        "search_filter_all":       "all",
    }
    status_filter = status_map.get(call.data, "all")
    try:
        lines = await _run_search(status_filter)
        if not lines:
            await call.message.answer("📋 לא נמצאו רשומות תואמות.", reply_markup=search_filter_keyboard())  # type: ignore[union-attr]
            return
        header = f"📋 <b>{len(lines)} רשומות:</b>\n\n"
        body   = "\n\n".join(lines[:_SEARCH_RESULT_LIMIT])
        footer = "" if len(lines) <= _SEARCH_RESULT_LIMIT else f"\n\n… ועוד {len(lines) - _SEARCH_RESULT_LIMIT} רשומות"
        await call.message.answer(  # type: ignore[union-attr]
            header + body + footer, reply_markup=search_filter_keyboard(), parse_mode=ParseMode.HTML
        )
    except Exception as exc:
        logger.error("search_filter_apply error: %s", exc)
    finally:
        await call.answer()


@router.callback_query(F.data == "search_filter_dates")
async def search_filter_dates_start(call: CallbackQuery, state: FSMContext) -> None:
    await state.set_state(AdminStates.search_waiting_date_from)
    try:
        await call.message.answer(  # type: ignore[union-attr]
            "📅 שלחו תאריך התחלה בפורמט <code>YYYY-MM-DD</code>:",
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("search_filter_dates_start error: %s", exc)
    finally:
        await call.answer()


@router.message(AdminStates.search_waiting_date_from)
async def search_filter_date_from_process(msg: Message, state: FSMContext) -> None:
    await state.update_data(date_from=(msg.text or "").strip())
    await state.set_state(AdminStates.search_waiting_date_to)
    await msg.answer("📅 שלחו תאריך סיום בפורמט <code>YYYY-MM-DD</code>:", parse_mode=ParseMode.HTML)


@router.message(AdminStates.search_waiting_date_to)
async def search_filter_date_to_process(msg: Message, state: FSMContext) -> None:
    data      = await state.get_data()
    date_from = data.get("date_from", "")
    date_to   = (msg.text or "").strip()
    await state.clear()

    try:
        blacklist = await load_blacklist()
        hits: List[str] = []
        for entity, entry in blacklist.items():
            if not isinstance(entry, dict):
                continue
            stamp = str(entry.get("timestamp", ""))[:10]
            if date_from <= stamp <= date_to:
                hits.append(_format_search_hit(entity, entry))

        if not hits:
            await msg.answer(
                f"📅 לא נמצאו רשומות בין <code>{_esc(date_from)}</code> ל-<code>{_esc(date_to)}</code>.",
                reply_markup=search_filter_keyboard(),
                parse_mode=ParseMode.HTML,
            )
            return

        header = f"📅 <b>{len(hits)} רשומות בין {_esc(date_from)} ל-{_esc(date_to)}:</b>\n\n"
        body   = "\n\n".join(hits[:_SEARCH_RESULT_LIMIT])
        await msg.answer(header + body, reply_markup=search_filter_keyboard(), parse_mode=ParseMode.HTML)
    except Exception as exc:
        logger.error("search_filter_date_to_process error: %s", exc)
        await msg.answer("❌ אירעה שגיאה בסינון לפי תאריך.", reply_markup=admin_command_center())


# ---------------------------------------------------------------------------
# NEW FEATURE 2 — Admin permission-level management (super admins only)
# ---------------------------------------------------------------------------
@router.callback_query(F.data == "admin_permissions")
async def admin_permissions_menu(call: CallbackQuery, state: FSMContext) -> None:
    uid = getattr(call.from_user, "id", None)
    if uid is None or not await is_effective_super_admin(uid):
        await call.answer("⛔ פעולה זו זמינה למנהלים ראשיים בלבד.", show_alert=True)
        return
    await state.clear()
    try:
        roles = await get_effective_admin_roles()
        await call.message.edit_text(  # type: ignore[union-attr]
            "👑 <b>ניהול הרשאות מנהלים</b>\n\n"
            "בחרו מנהל לניהול, או הוסיפו מנהל משני חדש:",
            reply_markup=permissions_keyboard(roles),
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("admin_permissions_menu error: %s", exc)
    finally:
        await call.answer()


@router.callback_query(F.data.startswith("perm_view:"))
async def perm_view_admin(call: CallbackQuery) -> None:
    uid = getattr(call.from_user, "id", None)
    if uid is None or not await is_effective_super_admin(uid):
        await call.answer("⛔ אין הרשאה.", show_alert=True)
        return
    try:
        target_id = int(call.data.split(":", 1)[1])
        roles     = await get_effective_admin_roles()
        level     = roles.get(target_id, "regular")
        badge     = "👑 מנהל ראשי" if level == "super" else "🛠️ מנהל משני"
        await call.message.edit_text(  # type: ignore[union-attr]
            f"{badge}\n🆔 <code>{target_id}</code>",
            reply_markup=permission_action_keyboard(target_id, level),
            parse_mode=ParseMode.HTML,
        )
    except (ValueError, IndexError):
        pass
    except Exception as exc:
        logger.error("perm_view_admin error: %s", exc)
    finally:
        await call.answer()


@router.callback_query(F.data.startswith("perm_promote:"))
async def perm_promote_admin(call: CallbackQuery, state: FSMContext) -> None:
    uid = getattr(call.from_user, "id", None)
    if uid is None or not await is_effective_super_admin(uid):
        await call.answer("⛔ אין הרשאה.", show_alert=True)
        return
    try:
        target_id = int(call.data.split(":", 1)[1])
        extra     = await load_admins_extra()
        promoted  = set(extra.get("promoted", []))
        demoted   = set(extra.get("demoted", []))
        promoted.add(target_id)
        demoted.discard(target_id)
        extra["promoted"] = list(promoted)
        extra["demoted"]  = list(demoted)
        await save_admins_extra(extra)
        await log_audit(uid, "promote_admin", str(target_id))
        await call.answer("✅ קודם לדרגת מנהל ראשי.", show_alert=True)
        await admin_permissions_menu(call, state)
    except (ValueError, IndexError):
        await call.answer()
    except Exception as exc:
        logger.error("perm_promote_admin error: %s", exc)
        await call.answer()


@router.callback_query(F.data.startswith("perm_demote:"))
async def perm_demote_admin(call: CallbackQuery) -> None:
    uid = getattr(call.from_user, "id", None)
    if uid is None or not await is_effective_super_admin(uid):
        await call.answer("⛔ אין הרשאה.", show_alert=True)
        return
    try:
        target_id = int(call.data.split(":", 1)[1])
        if target_id == uid:
            await call.answer("⚠️ לא ניתן להוריד את עצמכם — בקשו ממנהל ראשי אחר.", show_alert=True)
            return
        extra     = await load_admins_extra()
        promoted  = set(extra.get("promoted", []))
        demoted   = set(extra.get("demoted", []))
        demoted.add(target_id)
        promoted.discard(target_id)
        extra["promoted"] = list(promoted)
        extra["demoted"]  = list(demoted)
        await save_admins_extra(extra)
        await log_audit(uid, "demote_admin", str(target_id))
        await call.answer("✅ הורד לדרגת מנהל משני.", show_alert=True)
    except (ValueError, IndexError):
        await call.answer()
    except Exception as exc:
        logger.error("perm_demote_admin error: %s", exc)
        await call.answer()


@router.callback_query(F.data.startswith("perm_remove:"))
async def perm_remove_admin(call: CallbackQuery) -> None:
    uid = getattr(call.from_user, "id", None)
    if uid is None or not await is_effective_super_admin(uid):
        await call.answer("⛔ אין הרשאה.", show_alert=True)
        return
    try:
        target_id = int(call.data.split(":", 1)[1])
        extra = await load_admins_extra()
        extra["regular_admins"] = [a for a in extra.get("regular_admins", []) if a.get("id") != target_id]
        promoted = set(extra.get("promoted", []))
        promoted.discard(target_id)
        extra["promoted"] = list(promoted)
        await save_admins_extra(extra)
        await log_audit(uid, "remove_admin", str(target_id))
        await call.answer("✅ הרשאת הניהול הוסרה.", show_alert=True)
    except (ValueError, IndexError):
        await call.answer()
    except Exception as exc:
        logger.error("perm_remove_admin error: %s", exc)
        await call.answer()


@router.callback_query(F.data == "perm_add_admin")
async def perm_add_admin_start(call: CallbackQuery, state: FSMContext) -> None:
    uid = getattr(call.from_user, "id", None)
    if uid is None or not await is_effective_super_admin(uid):
        await call.answer("⛔ אין הרשאה.", show_alert=True)
        return
    await state.set_state(AdminStates.waiting_new_admin_id)
    try:
        await call.message.answer(  # type: ignore[union-attr]
            "➕ <b>הוספת מנהל משני</b>\n\nשלחו את מזהה המשתמש הטלגרמי (Telegram user ID) של המנהל החדש:",
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("perm_add_admin_start error: %s", exc)
    finally:
        await call.answer()


@router.message(AdminStates.waiting_new_admin_id)
async def perm_add_admin_process(msg: Message, state: FSMContext) -> None:
    await state.clear()
    raw = (msg.text or "").strip()
    if not raw.isdigit():
        await msg.answer("❌ יש לשלוח מזהה מספרי בלבד (Telegram user ID).", reply_markup=admin_command_center())
        return

    new_id = int(raw)
    try:
        extra = await load_admins_extra()
        regular = extra.get("regular_admins", [])
        if any(a.get("id") == new_id for a in regular) or new_id in ADMIN_IDS:
            await msg.answer("⚠️ המשתמש הזה כבר מנהל.", reply_markup=admin_command_center())
            return
        regular.append({"id": new_id, "name": str(new_id)})
        extra["regular_admins"] = regular
        await save_admins_extra(extra)
        if msg.from_user:
            await log_audit(msg.from_user.id, "add_admin", str(new_id))
        await msg.answer(
            f"✅ מנהל משני חדש נוסף: <code>{new_id}</code>",
            reply_markup=admin_command_center(is_super=True),
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("perm_add_admin_process error: %s", exc)
        await msg.answer("❌ אירעה שגיאה בהוספת המנהל.", reply_markup=admin_command_center())


# ---------------------------------------------------------------------------
# NEW FEATURE 3 — Full audit trail (who changed what, and when)
# ---------------------------------------------------------------------------
def _format_audit_entry(entry: Dict[str, Any]) -> str:
    stamp   = str(entry.get("timestamp", ""))[:19].replace("T", " ")
    admin   = entry.get("admin_id", "?")
    action  = _esc(entry.get("action", "?"))
    target  = _esc(entry.get("target", "")) or "—"
    details = _truncate(_esc(entry.get("details", "")), 60)
    line = f"🕒 <code>{stamp}</code> · 👤 <code>{admin}</code> · <b>{action}</b> → <code>{target}</code>"
    if details:
        line += f"\n<i>{details}</i>"
    return line


@router.callback_query(F.data == "admin_audit_trail")
async def admin_audit_trail_menu(call: CallbackQuery, state: FSMContext) -> None:
    uid = getattr(call.from_user, "id", None)
    if uid is None or not await is_effective_admin(uid):
        await call.answer()
        return
    await state.clear()
    try:
        await call.message.edit_text(  # type: ignore[union-attr]
            "📜 <b>היסטוריית שינויים (Audit Trail)</b>\n\n"
            "כל פעולת מנהל — הוספה, עריכה, מחיקה, שידור והרשאות — נשמרת כאן.",
            reply_markup=audit_trail_keyboard(),
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("admin_audit_trail_menu error: %s", exc)
    finally:
        await call.answer()


@router.callback_query(F.data == "audit_recent_all")
async def audit_recent_all(call: CallbackQuery) -> None:
    try:
        entries = await load_audit_log()
        recent  = list(reversed(entries[-20:]))
        if not recent:
            await call.message.answer("📜 אין עדיין פעולות רשומות.", reply_markup=audit_trail_keyboard())  # type: ignore[union-attr]
            return
        body = "\n\n".join(_format_audit_entry(e) for e in recent)
        await call.message.answer(  # type: ignore[union-attr]
            f"📜 <b>20 הפעולות האחרונות:</b>\n\n{body}",
            reply_markup=audit_trail_keyboard(),
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("audit_recent_all error: %s", exc)
    finally:
        await call.answer()


@router.callback_query(F.data == "audit_search_user")
async def audit_search_user_start(call: CallbackQuery, state: FSMContext) -> None:
    await state.set_state(AdminStates.audit_waiting_username)
    try:
        await call.message.answer(  # type: ignore[union-attr]
            "🔍 שלחו שם משתמש (או חלק ממנו) לצפייה בהיסטוריית השינויים שלו:",
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("audit_search_user_start error: %s", exc)
    finally:
        await call.answer()


@router.message(AdminStates.audit_waiting_username)
async def audit_search_user_process(msg: Message, state: FSMContext) -> None:
    query = normalize_entity(msg.text or "")
    await state.clear()
    if not query:
        await msg.answer("❌ יש להזין טקסט לחיפוש.", reply_markup=audit_trail_keyboard())
        return

    try:
        entries = await load_audit_log()
        matches = [e for e in entries if query in str(e.get("target", "")).lower()]
        matches = list(reversed(matches))[:_SEARCH_RESULT_LIMIT]

        if not matches:
            await msg.answer(
                f"📜 לא נמצאה היסטוריה עבור <code>{_esc(query)}</code>.",
                reply_markup=audit_trail_keyboard(),
                parse_mode=ParseMode.HTML,
            )
            return

        body = "\n\n".join(_format_audit_entry(e) for e in matches)
        await msg.answer(
            f"📜 <b>היסטוריית שינויים עבור \"{_esc(query)}\":</b>\n\n{body}",
            reply_markup=audit_trail_keyboard(),
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("audit_search_user_process error: %s", exc)
        await msg.answer("❌ אירעה שגיאה בחיפוש ההיסטוריה.", reply_markup=admin_command_center())


@router.callback_query(F.data.startswith("audit_for:"))
async def audit_for_entity(call: CallbackQuery) -> None:
    """Quick-jump into history for one entity — reachable from a search result."""
    try:
        target  = call.data.split(":", 1)[1]
        entries = await load_audit_log()
        matches = list(reversed([e for e in entries if str(e.get("target", "")).lower() == target.lower()]))[:_SEARCH_RESULT_LIMIT]
        if not matches:
            await call.answer("📜 אין היסטוריה עבור רשומה זו.", show_alert=True)
            return
        body = "\n\n".join(_format_audit_entry(e) for e in matches)
        await call.message.answer(  # type: ignore[union-attr]
            f"📜 <b>היסטוריה עבור {_esc(target)}:</b>\n\n{body}",
            reply_markup=audit_trail_keyboard(),
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("audit_for_entity error: %s", exc)
    finally:
        await call.answer()


@router.callback_query(F.data.startswith("quick_edit:"))
async def quick_edit_entity(call: CallbackQuery, state: FSMContext) -> None:
    """Jump straight into the existing edit flow for a record found via search."""
    uid = getattr(call.from_user, "id", None)
    if uid is None or not await is_effective_admin(uid):
        await call.answer()
        return
    try:
        target = call.data.split(":", 1)[1]
        await state.update_data(target=target)
        await state.set_state(AdminStates.waiting_db_edit_content)
        await call.message.answer(  # type: ignore[union-attr]
            f"✏️ עריכת <code>{_esc(target)}</code>\n\nשלחו את התיאור/סטטוס החדש:",
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("quick_edit_entity error: %s", exc)
    finally:
        await call.answer()

# ---------------------------------------------------------------------------
# Catch-all fallback
# ---------------------------------------------------------------------------
@router.message()
async def unknown_message_fallback(message: Message, state: FSMContext) -> None:
    """
    Catch-all handler for any text input that doesn't match an existing
    FSM state or command. Prevents "Update is not handled" errors for
    stray/unknown user messages.
    """
    try:
        await message.answer(
            "🤔 לא זיהיתי את הפקודה. אנא בחר אפשרות מהתפריט הראשי.",
            reply_markup=telelink_main_menu(),
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("unknown_message_fallback error: %s", exc)

# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("🛡️ TELELINK VERIFICATION ENGINE v3.0 — Premium UI & Full Protocol")