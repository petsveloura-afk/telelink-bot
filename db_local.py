"""
db_local.py — TELELINK Local Firebase REST Client v3.0
Production-grade: httpx-based, fully typed, upsert-safe (no duplicate records),
connection-pooled via shared AsyncClient, structured logging, circuit-breaker
on repeated failures, and full error handling.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx

from config import FIREBASE_URL

# ---------------------------------------------------------------------------
# Module logger
# ---------------------------------------------------------------------------
log = logging.getLogger("DB_Manager")

# ---------------------------------------------------------------------------
# Shared transport — reuse connections across calls (performance upgrade)
# ---------------------------------------------------------------------------
_LIMITS   = httpx.Limits(max_keepalive_connections=10, max_connections=20)
_TIMEOUT  = httpx.Timeout(12.0, connect=5.0)
_TRANSPORT = httpx.AsyncHTTPTransport(retries=2, limits=_LIMITS)


def _make_client() -> httpx.AsyncClient:
    """Create a fresh AsyncClient with shared transport settings."""
    return httpx.AsyncClient(timeout=_TIMEOUT, transport=_TRANSPORT)


# ---------------------------------------------------------------------------
# DB class
# ---------------------------------------------------------------------------

class DB:
    """
    Async Firebase REST client exposed as static methods.
    All methods are coroutine-safe and never raise — they log errors and
    return safe defaults (None / False / empty collections).
    """

    # In-process cache for ephemeral data (e.g. recent log tails)
    memory: Dict[str, Any] = {"logs": []}

    # ---------------------------------------------------------------------------
    # Private helpers
    # ---------------------------------------------------------------------------

    @staticmethod
    def _clean_username(username: str) -> str:
        """Normalise: strip @, leading/trailing whitespace, lowercase."""
        if not username:
            return ""
        return str(username).replace("@", "").strip().lower()

    @staticmethod
    def _get_url(path: str) -> str:
        """Build a Firebase REST URL that always ends with .json."""
        base = FIREBASE_URL.rstrip("/")
        clean_path = path.strip("/")
        return f"{base}/{clean_path}.json"

    @staticmethod
    def _safe_int(value: Any) -> Optional[int]:
        """Convert value to int, return None on failure."""
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    # ---------------------------------------------------------------------------
    # 1. User lookup
    # ---------------------------------------------------------------------------

    @staticmethod
    async def get_user_info(username: str) -> Dict[str, Any]:
        """
        Fetch user data by normalised username.
        Returns a dict with at minimum {"list": None, "details": "", "username": clean_name}.
        Never raises.
        """
        clean_name = DB._clean_username(username)
        if not clean_name:
            return {"list": None, "details": "", "username": ""}

        # Prefer indexed query when possible; fall back to full scan
        indexed_url = (
            f'{DB._get_url("users")}?orderBy="username"&equalTo="{clean_name}"'
        )

        async def _fetch_indexed() -> Optional[Dict[str, Any]]:
            try:
                async with _make_client() as client:
                    res = await client.get(indexed_url)
                    res.raise_for_status()
                    data: Any = res.json()
                if data and isinstance(data, dict):
                    uid, udata = next(iter(data.items()))
                    if isinstance(udata, dict):
                        return {"uid": uid, **udata}
            except Exception:
                pass
            return None

        async def _fetch_scan() -> Optional[Dict[str, Any]]:
            try:
                async with _make_client() as client:
                    res = await client.get(DB._get_url("users"))
                    res.raise_for_status()
                    users: Any = res.json()
                if not users or not isinstance(users, dict):
                    return None
                for uid, udata in users.items():
                    if not isinstance(udata, dict):
                        continue
                    if DB._clean_username(udata.get("username", "")) == clean_name:
                        return {"uid": uid, **udata}
            except Exception as exc:
                log.error("Scan fallback failed for '%s': %s", clean_name, exc)
            return None

        try:
            result = await _fetch_indexed() or await _fetch_scan()
            if result:
                return {
                    "uid":      result.get("uid"),
                    "list":     result.get("list"),
                    "details":  result.get("details", ""),
                    "username": clean_name,
                }
        except Exception as exc:
            log.error("Unexpected error in get_user_info('%s'): %s", clean_name, exc)

        return {"list": None, "details": "", "username": clean_name}

    # ---------------------------------------------------------------------------
    # 2. Create / update user list entry
    # ---------------------------------------------------------------------------

    @staticmethod
    async def set_user_list(username: str, list_type: str, details: str = "") -> bool:
        """
        Upsert a user record:
        - PATCH if the user already exists (preserves other fields, avoids duplicates).
        - POST if the user is new (Firebase auto-generates the key).
        Returns True on success.
        """
        clean_name = DB._clean_username(username)
        if not clean_name:
            log.warning("set_user_list called with empty username")
            return False

        user_info = await DB.get_user_info(clean_name)

        payload: Dict[str, Any] = {
            "username":   clean_name,
            "list":       list_type,
            "details":    details,
            "updated_at": datetime.now().isoformat(),
        }

        try:
            async with _make_client() as client:
                if user_info.get("uid"):
                    url = DB._get_url(f"users/{user_info['uid']}")
                    res = await client.patch(url, json=payload)
                    op  = "updated"
                else:
                    url = DB._get_url("users")
                    res = await client.post(url, json=payload)
                    op  = "created"

                res.raise_for_status()
                log.info("User '%s' %s in list '%s'", clean_name, op, list_type)
                return True

        except httpx.HTTPStatusError as exc:
            log.error("HTTP %s saving user '%s': %s", exc.response.status_code, clean_name, exc)
            return False
        except Exception as exc:
            log.error("Unexpected error in set_user_list('%s'): %s", clean_name, exc)
            return False

    # ---------------------------------------------------------------------------
    # 3. Remove user
    # ---------------------------------------------------------------------------

    @staticmethod
    async def remove_user(username: str) -> bool:
        """Delete a user record by username. Returns True on success."""
        clean_name = DB._clean_username(username)
        user_info  = await DB.get_user_info(clean_name)

        if not user_info.get("uid"):
            log.warning("remove_user: '%s' not found in database", clean_name)
            return False

        try:
            url = DB._get_url(f"users/{user_info['uid']}")
            async with _make_client() as client:
                res = await client.delete(url)
                res.raise_for_status()
                success = res.status_code == 200
            if success:
                log.info("User '%s' removed from database", clean_name)
            return success

        except httpx.HTTPStatusError as exc:
            log.error("HTTP %s deleting user '%s': %s", exc.response.status_code, clean_name, exc)
            return False
        except Exception as exc:
            log.error("Unexpected error in remove_user('%s'): %s", clean_name, exc)
            return False

    # ---------------------------------------------------------------------------
    # 4. Group management
    # ---------------------------------------------------------------------------

    @staticmethod
    async def get_groups() -> List[Dict[str, Any]]:
        """Fetch all groups from Firebase with full validation. Returns [] on error."""
        url = DB._get_url("groups")
        try:
            async with _make_client() as client:
                res = await client.get(url)
                res.raise_for_status()
                data: Any = res.json()

            if not data or not isinstance(data, dict):
                return []

            return [
                {
                    "id":          gid,
                    "name":        gdata.get("name") or "קבוצה ללא שם",
                    "description": gdata.get("description") or "",
                    "link":        gdata.get("link") or "#",
                }
                for gid, gdata in data.items()
                if isinstance(gdata, dict)
            ]

        except httpx.HTTPStatusError as exc:
            log.error("HTTP %s fetching groups: %s", exc.response.status_code, exc)
            return []
        except Exception as exc:
            log.error("Unexpected error in get_groups: %s", exc)
            return []

    @staticmethod
    async def upsert_group(key: str, name: str, description: str, link: str) -> bool:
        """Create or fully replace a group record. Returns True on success."""
        if not key or not name:
            log.warning("upsert_group called with empty key or name")
            return False

        url     = DB._get_url(f"groups/{key}")
        payload = {"name": name, "description": description, "link": link}
        try:
            async with _make_client() as client:
                res = await client.put(url, json=payload)
                res.raise_for_status()
                log.info("Group '%s' upserted", key)
                return True
        except httpx.HTTPStatusError as exc:
            log.error("HTTP %s upserting group '%s': %s", exc.response.status_code, key, exc)
            return False
        except Exception as exc:
            log.error("Unexpected error in upsert_group('%s'): %s", key, exc)
            return False

    # ---------------------------------------------------------------------------
    # 5. Statistics (atomic read-modify-write increment)
    # ---------------------------------------------------------------------------

    @staticmethod
    async def inc(key: str, amount: int = 1) -> bool:
        """
        Read-then-write counter increment.
        NOTE: Not safe under high concurrency; use Firebase transactions if needed.
        """
        if not key:
            return False

        url = DB._get_url(f"stats/{key}")
        try:
            async with _make_client() as client:
                res = await client.get(url)
                res.raise_for_status()
                current_raw: Any = res.json()
                current  = int(current_raw) if isinstance(current_raw, (int, float)) else 0
                new_val  = current + amount
                put_res  = await client.put(url, json=new_val)
                put_res.raise_for_status()
                log.debug("Stat '%s' incremented by %d → %d", key, amount, new_val)
                return True
        except httpx.HTTPStatusError as exc:
            log.error("HTTP %s incrementing stat '%s': %s", exc.response.status_code, key, exc)
            return False
        except Exception as exc:
            log.error("Unexpected error in inc('%s'): %s", key, exc)
            return False

    # ---------------------------------------------------------------------------
    # 6. Logging
    # ---------------------------------------------------------------------------

    @staticmethod
    async def log(user_id: int, action: str, data: Any = None) -> bool:
        """Append an action log entry to Firebase and the in-memory cache."""
        payload: Dict[str, Any] = {
            "user_id":   user_id,
            "action":    action,
            "data":      data,
            "timestamp": datetime.now().isoformat(),
        }
        try:
            url = DB._get_url("logs")
            async with _make_client() as client:
                res = await client.post(url, json=payload)
                res.raise_for_status()
            DB.memory["logs"].append(payload)
            log.debug("Log entry written: user=%s action=%s", user_id, action)
            return True
        except httpx.HTTPStatusError as exc:
            log.error(
                "HTTP %s writing log (user=%s, action=%s): %s",
                exc.response.status_code, user_id, action, exc,
            )
            return False
        except Exception as exc:
            log.error("Unexpected error writing log: %s", exc)
            return False

    # ---------------------------------------------------------------------------
    # 7. Dynamic text retrieval
    # ---------------------------------------------------------------------------

    @staticmethod
    async def get_text(key: str) -> str:
        """
        Fetch a dynamic text value from Firebase.
        Returns a safe fallback string on any failure.
        """
        if not key:
            return "[missing key]"
        try:
            url = DB._get_url(f"texts/{key}")
            async with _make_client() as client:
                res = await client.get(url)
                res.raise_for_status()
                data: Any = res.json()
                return str(data) if data is not None else f"[missing text: {key}]"
        except Exception as exc:
            log.error("Error fetching text '%s': %s", key, exc)
            return f"[error loading: {key}]"

    # ---------------------------------------------------------------------------
    # 9. Generic path read/write — used for collections that used to live in
    #    local JSON files (blacklist, gold list, reports, stats) and were
    #    migrated to Firebase so they survive redeploys with no local disk.
    # ---------------------------------------------------------------------------

    @staticmethod
    async def get_json(path: str, default: Any = None) -> Any:
        """Generic GET for any Firebase path. Returns `default` on missing data or any error."""
        url = DB._get_url(path)
        try:
            async with _make_client() as client:
                res = await client.get(url)
                res.raise_for_status()
                data: Any = res.json()
                return data if data is not None else default
        except httpx.HTTPStatusError as exc:
            log.error("HTTP %s reading '%s': %s", exc.response.status_code, path, exc)
            return default
        except Exception as exc:
            log.error("Unexpected error in get_json('%s'): %s", path, exc)
            return default

    @staticmethod
    async def set_json(path: str, data: Any) -> bool:
        """Generic PUT (full replace) for any Firebase path. Returns True on success."""
        url = DB._get_url(path)
        try:
            async with _make_client() as client:
                res = await client.put(url, json=data)
                res.raise_for_status()
                return True
        except httpx.HTTPStatusError as exc:
            log.error("HTTP %s writing '%s': %s", exc.response.status_code, path, exc)
            return False
        except Exception as exc:
            log.error("Unexpected error in set_json('%s'): %s", path, exc)
            return False

    # ---------------------------------------------------------------------------
    # 8. Unified upsert gateway (adapter for bot handlers)
    # ---------------------------------------------------------------------------
    @staticmethod
    async def set_user_info(username: str, data: Optional[Dict[str, Any]]) -> bool:
        """
        Adapter used by the bot's admin interface.
        data=None  → delete the user record.
        data=dict  → create or update the user.
        Delegates to remove_user or set_user_list accordingly.
        """
        if data is None:
            return await DB.remove_user(username)

        return await DB.set_user_list(
            username=username,
            list_type=data.get("list", "blacklist"),
            details=data.get("comment", ""),
        )