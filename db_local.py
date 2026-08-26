"""
db_local.py — TELELINK Postgres Client v1.0
Drop-in replacement for the Firebase REST version. Same public interface
(get_user_info, set_user_list, remove_user, get_groups, upsert_group, inc,
log, get_text, get_json, set_json, set_user_info) so handlers.py does not
need to change at all.

Requires:
    pip install asyncpg
    DATABASE_URL environment variable set (Railway sets this automatically
    when you add a Postgres plugin — read it from there, never hard-code it).

Schema (created automatically on first use):
    kv_store     — generic key/value store, used for global_blacklist,
                   gold_list, scam_reports, stats, texts/*, chat_lines
                   (anything read/written via DB.get_json / DB.set_json)
    users        — username -> list ("whitelist"/"blacklist") + details
    groups       — key -> name/description/link
    action_logs  — append-only action log (replaces DB.log)
"""

import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import asyncpg

log = logging.getLogger("DB_Manager")

DATABASE_URL: str = os.environ.get("DATABASE_URL", "")

_pool: Optional[asyncpg.Pool] = None
_schema_ready = False


async def _get_pool() -> asyncpg.Pool:
    """Lazily create (once) and return the shared connection pool."""
    global _pool, _schema_ready
    if _pool is None:
        if not DATABASE_URL:
            raise RuntimeError(
                "DATABASE_URL is not set. Add a Postgres plugin on Railway "
                "(or set the env var yourself) before starting the bot."
            )
        _pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=10)
    if not _schema_ready:
        await _ensure_schema(_pool)
        _schema_ready = True
    return _pool


async def _ensure_schema(pool: asyncpg.Pool) -> None:
    async with pool.acquire() as conn:
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS kv_store (
                key         TEXT PRIMARY KEY,
                value       JSONB NOT NULL,
                updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
            );

            CREATE TABLE IF NOT EXISTS users (
                username    TEXT PRIMARY KEY,
                list        TEXT,
                details     TEXT DEFAULT '',
                updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
            );

            CREATE TABLE IF NOT EXISTS groups (
                key         TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                description TEXT DEFAULT '',
                link        TEXT DEFAULT '#'
            );

            CREATE TABLE IF NOT EXISTS action_logs (
                id          BIGSERIAL PRIMARY KEY,
                user_id     BIGINT,
                action      TEXT,
                data        JSONB,
                timestamp   TIMESTAMPTZ NOT NULL DEFAULT now()
            );
            """
        )
        log.info("✅ Postgres schema ensured (kv_store, users, groups, action_logs)")


class DB:
    """Async Postgres client exposed as static methods. Never raises —
    logs errors and returns safe defaults, matching the Firebase version."""

    memory: Dict[str, Any] = {"logs": []}

    # -----------------------------------------------------------------
    @staticmethod
    def _clean_username(username: str) -> str:
        if not username:
            return ""
        return str(username).replace("@", "").strip().lower()

    # -----------------------------------------------------------------
    # 1. User lookup
    # -----------------------------------------------------------------
    @staticmethod
    async def get_user_info(username: str) -> Dict[str, Any]:
        clean_name = DB._clean_username(username)
        if not clean_name:
            return {"list": None, "details": "", "username": ""}
        try:
            pool = await _get_pool()
            async with pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT username, list, details FROM users WHERE username = $1",
                    clean_name,
                )
            if row:
                return {
                    "uid":      row["username"],
                    "list":     row["list"],
                    "details":  row["details"] or "",
                    "username": clean_name,
                }
        except Exception as exc:
            log.error("Unexpected error in get_user_info('%s'): %s", clean_name, exc)
        return {"list": None, "details": "", "username": clean_name}

    # -----------------------------------------------------------------
    # 2. Create / update user list entry
    # -----------------------------------------------------------------
    @staticmethod
    async def set_user_list(username: str, list_type: str, details: str = "") -> bool:
        clean_name = DB._clean_username(username)
        if not clean_name:
            log.warning("set_user_list called with empty username")
            return False
        try:
            pool = await _get_pool()
            async with pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO users (username, list, details, updated_at)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (username) DO UPDATE
                        SET list = EXCLUDED.list,
                            details = EXCLUDED.details,
                            updated_at = EXCLUDED.updated_at
                    """,
                    clean_name, list_type, details, datetime.now(),
                )
            log.info("User '%s' upserted in list '%s'", clean_name, list_type)
            return True
        except Exception as exc:
            log.error("Unexpected error in set_user_list('%s'): %s", clean_name, exc)
            return False

    # -----------------------------------------------------------------
    # 3. Remove user
    # -----------------------------------------------------------------
    @staticmethod
    async def remove_user(username: str) -> bool:
        clean_name = DB._clean_username(username)
        if not clean_name:
            return False
        try:
            pool = await _get_pool()
            async with pool.acquire() as conn:
                result = await conn.execute(
                    "DELETE FROM users WHERE username = $1", clean_name
                )
            deleted = result.endswith("1")
            if deleted:
                log.info("User '%s' removed from database", clean_name)
            else:
                log.warning("remove_user: '%s' not found in database", clean_name)
            return deleted
        except Exception as exc:
            log.error("Unexpected error in remove_user('%s'): %s", clean_name, exc)
            return False

    # -----------------------------------------------------------------
    # 4. Group management
    # -----------------------------------------------------------------
    @staticmethod
    async def get_groups() -> List[Dict[str, Any]]:
        try:
            pool = await _get_pool()
            async with pool.acquire() as conn:
                rows = await conn.fetch("SELECT key, name, description, link FROM groups")
            return [
                {
                    "id":          r["key"],
                    "name":        r["name"] or "קבוצה ללא שם",
                    "description": r["description"] or "",
                    "link":        r["link"] or "#",
                }
                for r in rows
            ]
        except Exception as exc:
            log.error("Unexpected error in get_groups: %s", exc)
            return []

    @staticmethod
    async def upsert_group(key: str, name: str, description: str, link: str) -> bool:
        if not key or not name:
            log.warning("upsert_group called with empty key or name")
            return False
        try:
            pool = await _get_pool()
            async with pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO groups (key, name, description, link)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (key) DO UPDATE
                        SET name = EXCLUDED.name,
                            description = EXCLUDED.description,
                            link = EXCLUDED.link
                    """,
                    key, name, description, link,
                )
            log.info("Group '%s' upserted", key)
            return True
        except Exception as exc:
            log.error("Unexpected error in upsert_group('%s'): %s", key, exc)
            return False

    # -----------------------------------------------------------------
    # 5. Statistics (atomic increment, stored in kv_store under "stats/<key>")
    # -----------------------------------------------------------------
    @staticmethod
    async def inc(key: str, amount: int = 1) -> bool:
        if not key:
            return False
        kv_key = f"stats/{key}"
        try:
            pool = await _get_pool()
            async with pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO kv_store (key, value, updated_at)
                    VALUES ($1, to_jsonb($2::int), now())
                    ON CONFLICT (key) DO UPDATE
                        SET value = to_jsonb(COALESCE((kv_store.value)::text::int, 0) + $2::int),
                            updated_at = now()
                    """,
                    kv_key, amount,
                )
            return True
        except Exception as exc:
            log.error("Unexpected error in inc('%s'): %s", key, exc)
            return False

    # -----------------------------------------------------------------
    # 6. Logging
    # -----------------------------------------------------------------
    @staticmethod
    async def log(user_id: int, action: str, data: Any = None) -> bool:
        payload = {
            "user_id":   user_id,
            "action":    action,
            "data":      data,
            "timestamp": datetime.now().isoformat(),
        }
        try:
            pool = await _get_pool()
            async with pool.acquire() as conn:
                await conn.execute(
                    "INSERT INTO action_logs (user_id, action, data) VALUES ($1, $2, $3::jsonb)",
                    user_id, action, _to_jsonb_safe(data),
                )
            DB.memory["logs"].append(payload)
            return True
        except Exception as exc:
            log.error("Unexpected error writing log: %s", exc)
            return False

    # -----------------------------------------------------------------
    # 7. Dynamic text retrieval (kv_store key "texts/<key>")
    # -----------------------------------------------------------------
    @staticmethod
    async def get_text(key: str) -> str:
        if not key:
            return "[missing key]"
        data = await DB.get_json(f"texts/{key}", None)
        return str(data) if data is not None else f"[missing text: {key}]"

    # -----------------------------------------------------------------
    # 9. Generic path read/write — backs the collections handlers.py reads
    #    via DB.get_json / DB.set_json: "global_blacklist", "gold_list",
    #    "scam_reports", "stats", plus any "texts/<key>" path.
    # -----------------------------------------------------------------
    @staticmethod
    async def get_json(path: str, default: Any = None) -> Any:
        try:
            pool = await _get_pool()
            async with pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT value FROM kv_store WHERE key = $1", path
                )
            if row is None:
                return default
            import json as _json
            value = row["value"]
            # asyncpg returns JSONB as str by default unless a codec is set
            return _json.loads(value) if isinstance(value, str) else value
        except Exception as exc:
            log.error("Unexpected error in get_json('%s'): %s", path, exc)
            return default

    @staticmethod
    async def set_json(path: str, data: Any) -> bool:
        try:
            import json as _json
            pool = await _get_pool()
            async with pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO kv_store (key, value, updated_at)
                    VALUES ($1, $2::jsonb, now())
                    ON CONFLICT (key) DO UPDATE
                        SET value = EXCLUDED.value,
                            updated_at = now()
                    """,
                    path, _json.dumps(data, ensure_ascii=False),
                )
            return True
        except Exception as exc:
            log.error("Unexpected error in set_json('%s'): %s", path, exc)
            return False

    # -----------------------------------------------------------------
    # 8. Unified upsert gateway (adapter for bot handlers)
    # -----------------------------------------------------------------
    @staticmethod
    async def set_user_info(username: str, data: Optional[Dict[str, Any]]) -> bool:
        if data is None:
            return await DB.remove_user(username)
        return await DB.set_user_list(
            username=username,
            list_type=data.get("list", "blacklist"),
            details=data.get("comment", ""),
        )


def _to_jsonb_safe(data: Any) -> str:
    import json as _json
    return _json.dumps(data, ensure_ascii=False)
