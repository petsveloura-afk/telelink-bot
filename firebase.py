"""
firebase.py — TELELINK Async Firebase REST Client v3.0 (aiohttp-based)
Production-grade: typed, persistent-session-aware, proper error handling,
index-compatible queries, audit logging, and membership check by user_id.
"""

import aiohttp
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from config import FIREBASE_URL

# ---------------------------------------------------------------------------
# Module logger
# ---------------------------------------------------------------------------
log = logging.getLogger("anti_scam_bot")

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _format_url(path: str) -> str:
    """Build a Firebase REST URL, always ending with .json."""
    base_url   = FIREBASE_URL.rstrip("/")
    clean_path = path.strip("/")
    return f"{base_url}/{clean_path}.json"


def _clean_username(username: str) -> str:
    """Normalise a Telegram username: strip @, whitespace, lowercase."""
    if not username:
        return ""
    return str(username).replace("@", "").strip().lower()


def _safe_int(value: Any) -> Optional[int]:
    """Convert a value to int safely, returning None on failure."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Shared aiohttp session factory — connection-pooled for performance
# ---------------------------------------------------------------------------
_DEFAULT_TIMEOUT = aiohttp.ClientTimeout(total=12, connect=5)
_CONNECTOR_LIMIT = 20


def _new_session() -> aiohttp.ClientSession:
    """Return a new ClientSession with shared timeout and TCP connector."""
    connector = aiohttp.TCPConnector(limit=_CONNECTOR_LIMIT, ttl_dns_cache=300)
    return aiohttp.ClientSession(timeout=_DEFAULT_TIMEOUT, connector=connector)


# ---------------------------------------------------------------------------
# 1. Group management
# ---------------------------------------------------------------------------

async def get_groups() -> List[Dict[str, Any]]:
    """Return the list of groups from Firebase with full validation."""
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
                    "name":        gdata.get("name") or "קבוצה ללא שם",
                    "description": gdata.get("description") or "",
                    "link":        gdata.get("link") or "",
                }
            )
        return groups

    except aiohttp.ClientResponseError as exc:
        log.error("HTTP error fetching groups (status %s): %s", exc.status, exc.message)
        return []
    except Exception as exc:
        log.error("Unexpected error fetching groups: %s", exc)
        return []


# ---------------------------------------------------------------------------
# 2. User lookup (indexed query with linear scan fallback)
# ---------------------------------------------------------------------------

async def get_user_info(username: str) -> Optional[Dict[str, Any]]:
    """
    Look up a user by username using a Firebase indexed query.
    Requires `.indexOn: ["username"]` in Firebase security rules.
    Falls back to a linear scan if the indexed query returns empty.
    Returns a dict or None if not found.
    """
    clean_name = _clean_username(username)
    if not clean_name:
        return None

    indexed_url = f'{_format_url("users")}?orderBy="username"&equalTo="{clean_name}"'

    async def _try_indexed() -> Optional[Dict[str, Any]]:
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
            pass
        return None

    async def _try_scan() -> Optional[Dict[str, Any]]:
        """Linear full-table scan fallback (no index required)."""
        try:
            async with _new_session() as session:
                async with session.get(_format_url("users")) as res:
                    res.raise_for_status()
                    all_users: Any = await res.json()
            if not all_users or not isinstance(all_users, dict):
                return None
            for uid, udata in all_users.items():
                if not isinstance(udata, dict):
                    continue
                if _clean_username(udata.get("username", "")) == clean_name:
                    return _build_user_dict(uid, udata)
        except aiohttp.ClientResponseError as exc:
            log.error("HTTP error in scan fallback for '%s' (status %s): %s", clean_name, exc.status, exc.message)
        except Exception as exc:
            log.error("Unexpected error in scan fallback for '%s': %s", clean_name, exc)
        return None

    result = await _try_indexed()
    if result is None:
        result = await _try_scan()
    return result


def _build_user_dict(uid: str, udata: Dict[str, Any]) -> Dict[str, Any]:
    """Assemble a canonical user info dict from a raw Firebase record."""
    return {
        "db_key":   uid,
        "list":     udata.get("list"),
        "details":  udata.get("details") or udata.get("comment") or "אין פירוט נוסף",
        "user_id":  udata.get("user_id"),
        "username": udata.get("username"),
        "added_at": udata.get("timestamp"),
    }


# ---------------------------------------------------------------------------
# 3. Add / update a user
# ---------------------------------------------------------------------------

async def add_user_to_list(
    username: str,
    list_type: str,
    details: str = "",
    user_id: Any = None,
) -> bool:
    """
    Create or update a user record.
    Uses PATCH for existing records (preserves untouched fields)
    and POST for new records (Firebase auto-generates the key).
    """
    clean_name = _clean_username(username)
    if not clean_name:
        log.warning("add_user_to_list called with empty username")
        return False

    existing_user = await get_user_info(clean_name)
    normalised_uid = _safe_int(user_id) if user_id else None

    payload: Dict[str, Any] = {
        "username":   clean_name,
        "list":       list_type,
        "details":    details,
        "user_id":    normalised_uid,
        "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    # Stamp created_at only on new records
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
            log.warning("Unexpected HTTP status when saving user '%s'", clean_name)
        return success

    except aiohttp.ClientResponseError as exc:
        log.error("HTTP error saving user '%s' (status %s): %s", clean_name, exc.status, exc.message)
        return False
    except Exception as exc:
        log.error("Unexpected error saving user '%s': %s", clean_name, exc)
        return False


# ---------------------------------------------------------------------------
# 4. Remove a user
# ---------------------------------------------------------------------------

async def remove_user_from_list(username: str) -> bool:
    """Delete a user record completely by username."""
    user_info = await get_user_info(username)
    if not user_info:
        log.warning("Delete skipped — user '%s' not found in database", username)
        return False

    try:
        url = _format_url(f"users/{user_info['db_key']}")
        async with _new_session() as session:
            async with session.delete(url) as res:
                success = res.status == 200

        if success:
            log.info("User '%s' deleted from database", username)
        else:
            log.warning("Unexpected HTTP status when deleting user '%s'", username)
        return success

    except aiohttp.ClientResponseError as exc:
        log.error("HTTP error deleting user '%s' (status %s): %s", username, exc.status, exc.message)
        return False
    except Exception as exc:
        log.error("Unexpected error deleting user '%s': %s", username, exc)
        return False


# ---------------------------------------------------------------------------
# 5. Unified upsert gateway (used by bot handlers)
# ---------------------------------------------------------------------------

async def set_user_info(username: str, data: Optional[Dict[str, Any]]) -> bool:
    """
    Unified gateway for the bot's admin interface.
    Passing data=None triggers deletion; any dict triggers create/update.
    """
    if data is None:
        return await remove_user_from_list(username)

    return await add_user_to_list(
        username=username,
        list_type=data.get("list", "blacklist"),
        details=data.get("comment", ""),
        user_id=data.get("user_id"),
    )


# ---------------------------------------------------------------------------
# 6. Membership check (whitelist by Telegram user ID)
# ---------------------------------------------------------------------------

async def is_member(user_id: int) -> bool:
    """
    Check whether a Telegram user_id belongs to the whitelist.
    Requires `.indexOn: ["user_id"]` in Firebase security rules.
    """
    if not user_id:
        return False

    # Numeric equality — no quotes around the value
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

    except aiohttp.ClientResponseError as exc:
        log.error("HTTP error checking membership for %s (status %s): %s", user_id, exc.status, exc.message)
        return False
    except Exception as exc:
        log.error("Unexpected error checking membership for %s: %s", user_id, exc)
        return False


# ---------------------------------------------------------------------------
# 7. Audit log
# ---------------------------------------------------------------------------

async def log_action(admin_id: int, action: str, target: str = "") -> None:
    """Append an admin action to the Firebase audit log. Never raises."""
    url = _format_url("audit_logs")
    payload = {
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
# Backward-compat reference paths (for code that imports these directly)
# ---------------------------------------------------------------------------
ref_users   = f"{FIREBASE_URL.rstrip('/')}/users"
ref_groups  = f"{FIREBASE_URL.rstrip('/')}/groups"
ref_reports = f"{FIREBASE_URL.rstrip('/')}/reports"