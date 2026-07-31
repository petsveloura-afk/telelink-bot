"""
utils.py — TELELINK Firebase Utility Layer v3.0 (aiohttp-based)
Production-grade: connection-pooled sessions, indexed queries with
scan fallback, full type annotations, and consistent error handling.
"""

import aiohttp
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from config import FIREBASE_URL

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
log = logging.getLogger("anti_scam_bot")

# ---------------------------------------------------------------------------
# Session factory — shared timeout + TCP connector limit
# ---------------------------------------------------------------------------
_DEFAULT_TIMEOUT = aiohttp.ClientTimeout(total=12, connect=5)


def _new_session() -> aiohttp.ClientSession:
    connector = aiohttp.TCPConnector(limit=20, ttl_dns_cache=300)
    return aiohttp.ClientSession(timeout=_DEFAULT_TIMEOUT, connector=connector)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _format_url(path: str) -> str:
    """Return a valid Firebase REST URL (always ends with .json)."""
    base_url   = FIREBASE_URL.rstrip("/")
    clean_path = path.strip("/")
    return f"{base_url}/{clean_path}.json"


def _clean_username(username: str) -> str:
    """Normalise a Telegram username — strip @, whitespace, lowercase."""
    if not username:
        return ""
    return str(username).replace("@", "").strip().lower()


def _safe_int(value: Any) -> Optional[int]:
    """Convert value to int safely, return None on failure."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# 1. Groups
# ---------------------------------------------------------------------------

async def get_groups() -> List[Dict[str, Any]]:
    """Fetch all groups from Firebase with full validation."""
    url = _format_url("groups")
    try:
        async with _new_session() as session:
            async with session.get(url) as res:
                res.raise_for_status()
                data: Any = await res.json()

        if not data or not isinstance(data, dict):
            return []

        groups: List[Dict[str, Any]] = []
        for gid, gdata in data.items():
            if not isinstance(gdata, dict):
                continue
            groups.append(
                {
                    "id":          gid,
                    "name":        gdata.get("name", "קבוצה ללא שם"),
                    "description": gdata.get("description", ""),
                    "link":        gdata.get("link", ""),
                }
            )
        return groups

    except Exception as exc:
        log.error("Error fetching groups: %s", exc)
        return []


# ---------------------------------------------------------------------------
# 2. User lookup (indexed query + linear scan fallback)
# ---------------------------------------------------------------------------

def _build_user_dict(uid: str, udata: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "db_key":   uid,
        "list":     udata.get("list"),
        "details":  udata.get("details") or udata.get("comment") or "אין פירוט נוסף",
        "user_id":  udata.get("user_id"),
        "username": udata.get("username"),
        "added_at": udata.get("timestamp"),
    }


async def get_user_info(username: str) -> Optional[Dict[str, Any]]:
    """
    Fetch user data by username.
    Uses an indexed Firebase query first; falls back to linear scan.
    Requires `.indexOn: ["username"]` in Firebase security rules for the fast path.
    """
    clean_name = _clean_username(username)
    if not clean_name:
        return None

    indexed_url = f'{_format_url("users")}?orderBy="username"&equalTo="{clean_name}"'

    # --- Fast path: indexed query ---
    try:
        async with _new_session() as session:
            async with session.get(indexed_url) as res:
                res.raise_for_status()
                users_data: Any = await res.json()

        if users_data and isinstance(users_data, dict):
            uid, udata = next(iter(users_data.items()))
            if isinstance(udata, dict):
                return _build_user_dict(uid, udata)
    except Exception:
        pass  # fall through to scan

    # --- Fallback: linear scan ---
    try:
        async with _new_session() as session:
            async with session.get(_format_url("users")) as res:
                res.raise_for_status()
                all_users: Any = await res.json()

        if all_users and isinstance(all_users, dict):
            for uid, udata in all_users.items():
                if not isinstance(udata, dict):
                    continue
                if _clean_username(udata.get("username", "")) == clean_name:
                    return _build_user_dict(uid, udata)
    except Exception as exc:
        log.error("Error in user lookup scan for '%s': %s", clean_name, exc)

    return None


# ---------------------------------------------------------------------------
# 3. Unified upsert gateway
# ---------------------------------------------------------------------------

async def set_user_info(username: str, data: Optional[Dict[str, Any]]) -> bool:
    """
    Gateway used by the bot's admin interface.
    data=None  → delete the user.
    data=dict  → create or update.
    """
    if data is None:
        return await remove_user_from_list(username)

    return await add_user_to_list(
        username=username,
        list_type=data.get("list", "blacklist"),
        details=data.get("comment", ""),
        user_id=data.get("user_id"),
    )


async def add_user_to_list(
    username: str,
    list_type: str,
    details: str = "",
    user_id: Any = None,
) -> bool:
    """
    Create or update a user record in Firebase.
    PATCH for existing users (preserves untouched fields).
    POST for new users (Firebase auto-key).
    """
    clean_name = _clean_username(username)
    if not clean_name:
        log.warning("add_user_to_list: empty username")
        return False

    existing_user = await get_user_info(clean_name)

    normalised_uid: Any
    if user_id and str(user_id).isdigit():
        normalised_uid = int(user_id)
    elif user_id:
        normalised_uid = str(user_id)
    else:
        normalised_uid = None

    payload: Dict[str, Any] = {
        "username":   clean_name,
        "list":       list_type,
        "details":    details,
        "user_id":    normalised_uid,
        "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    if not existing_user:
        payload["timestamp"] = {".sv": "timestamp"}

    try:
        async with _new_session() as session:
            if existing_user:
                url = _format_url(f"users/{existing_user['db_key']}")
                async with session.patch(url, json=payload) as res:
                    success = res.status in (200, 201)
            else:
                url = _format_url("users")
                async with session.post(url, json=payload) as res:
                    success = res.status in (200, 201)

        if success:
            log.info("User '%s' saved to list '%s'", clean_name, list_type)
        else:
            log.warning("Unexpected HTTP status saving user '%s'", clean_name)
        return success

    except Exception as exc:
        log.error("Error adding user '%s' to Firebase: %s", clean_name, exc)
        return False


async def remove_user_from_list(username: str) -> bool:
    """Permanently delete a user record by username."""
    user_info = await get_user_info(username)
    if not user_info:
        log.warning("Delete skipped: user '%s' not found", username)
        return False

    try:
        url = _format_url(f"users/{user_info['db_key']}")
        async with _new_session() as session:
            async with session.delete(url) as res:
                success = res.status == 200
        if success:
            log.info("User '%s' deleted from Firebase", username)
        return success
    except Exception as exc:
        log.error("Error removing user '%s': %s", username, exc)
        return False


# ---------------------------------------------------------------------------
# 4. Audit log
# ---------------------------------------------------------------------------

async def log_action(admin_id: int, action: str, target: str = "") -> None:
    """Append an admin action to the Firebase audit log. Never raises."""
    url = _format_url("audit_logs")
    payload: Dict[str, Any] = {
        "admin_id":  admin_id,
        "action":    action,
        "target":    target,
        "timestamp": {".sv": "timestamp"},
    }
    try:
        async with _new_session() as session:
            async with session.post(url, json=payload) as res:
                if res.status not in (200, 201):
                    log.warning("Audit log write returned status %s", res.status)
    except Exception as exc:
        log.error("Error writing audit log (admin=%s, action=%s): %s", admin_id, action, exc)


# ---------------------------------------------------------------------------
# 5. Membership check (whitelist by Telegram user ID)
# ---------------------------------------------------------------------------

async def is_member(user_id: int) -> bool:
    """
    Return True if the given Telegram user_id has an active whitelist entry.
    Requires `.indexOn: ["user_id"]` in Firebase security rules.
    """
    if not user_id:
        return False

    url = f'{_format_url("users")}?orderBy="user_id"&equalTo={int(user_id)}'

    try:
        async with _new_session() as session:
            async with session.get(url) as res:
                res.raise_for_status()
                data: Any = await res.json()

        if not data or not isinstance(data, dict):
            return False

        return any(
            isinstance(record, dict) and record.get("list") == "whitelist"
            for record in data.values()
        )
    except Exception as exc:
        log.error("Error checking membership for user_id=%s: %s", user_id, exc)
        return False


# ---------------------------------------------------------------------------
# Backward-compat reference paths
# ---------------------------------------------------------------------------
ref_users   = f"{FIREBASE_URL.rstrip('/')}/users"
ref_groups  = f"{FIREBASE_URL.rstrip('/')}/groups"
ref_reports = f"{FIREBASE_URL.rstrip('/')}/reports"