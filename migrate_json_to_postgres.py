#!/usr/bin/env python3
"""
migrate_json_to_postgres.py — ONE-TIME migration of the local JSON backup
files into the new Postgres database, matching the exact paths handlers.py
reads/writes via DB.get_json / DB.set_json / DB.get_user_info / DB.get_groups.

What gets migrated and where (confirmed by reading handlers.py directly):
    global_blacklist.json  -> kv_store["global_blacklist"]   (dict)
    gold_list.json         -> kv_store["gold_list"]           (list)
    scam_reports.json      -> kv_store["scam_reports"]        (list)
    stats.json             -> kv_store["stats"]                (dict)
    db.json["users"]       -> users table (one row per username)
    db.json["groups"]      -> groups table
    db.json["texts"]       -> kv_store["texts/<key>"] per key  (for DB.get_text)
    db.json["chat_lines"]  -> kv_store["chat_lines"]           (list)

NOT migrated (handlers.py currently stores these as local files, not via
DB.get_json, so pushing them to Postgres alone would not make the bot use
them — that needs a small handlers.py change too, which this script does
NOT make):
    users.json          (telegram users who joined the bot)
    buttons.json
    custom_buttons.json

Usage:
    pip install asyncpg
    export DATABASE_URL="postgresql://...."      # never hard-code this
    python migrate_json_to_postgres.py /path/to/backup/folder

    If no folder is given, it looks in the current directory for:
    global_blacklist.json, gold_list.json, scam_reports.json, stats.json,
    db.json
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Optional

import asyncpg

DATABASE_URL = os.environ.get("DATABASE_URL", "")


def load_json(path: Path) -> Optional[Any]:
    if not path.exists():
        print(f"⏭️  {path.name} not found, skipping.")
        return None
    with open(path, "r", encoding="utf-8-sig") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError as exc:
            print(f"❌ {path.name} is not valid JSON: {exc}")
            return None


async def ensure_schema(conn: asyncpg.Connection) -> None:
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
    print("✅ Postgres schema ensured (kv_store, users, groups, action_logs)")


async def set_kv(conn: asyncpg.Connection, key: str, value: Any) -> None:
    await conn.execute(
        """
        INSERT INTO kv_store (key, value, updated_at)
        VALUES ($1, $2::jsonb, now())
        ON CONFLICT (key) DO UPDATE
            SET value = EXCLUDED.value, updated_at = now()
        """,
        key, json.dumps(value, ensure_ascii=False),
    )
    count = len(value) if isinstance(value, (list, dict)) else 1
    print(f"✅ kv_store['{key}']  ({count} entries)")


async def migrate_users_from_dbjson(conn: asyncpg.Connection, users: dict) -> None:
    if not isinstance(users, dict):
        print("⏭️  db.json has no valid 'users' dict, skipping users table.")
        return
    n = 0
    for _key, info in users.items():
        if not isinstance(info, dict):
            continue
        username = str(info.get("username") or _key).strip().lower().lstrip("@")
        if not username:
            continue
        list_type = info.get("list")
        details = info.get("details", "") or ""
        await conn.execute(
            """
            INSERT INTO users (username, list, details, updated_at)
            VALUES ($1, $2, $3, now())
            ON CONFLICT (username) DO UPDATE
                SET list = EXCLUDED.list,
                    details = EXCLUDED.details,
                    updated_at = now()
            """,
            username, list_type, details,
        )
        n += 1
    print(f"✅ users table  ({n} entries from db.json)")


async def migrate_groups_from_dbjson(conn: asyncpg.Connection, groups: dict) -> None:
    if not isinstance(groups, dict):
        print("⏭️  db.json has no valid 'groups' dict, skipping groups table.")
        return
    n = 0
    for key, info in groups.items():
        if not isinstance(info, dict):
            continue
        await conn.execute(
            """
            INSERT INTO groups (key, name, description, link)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (key) DO UPDATE
                SET name = EXCLUDED.name,
                    description = EXCLUDED.description,
                    link = EXCLUDED.link
            """,
            key, info.get("name", key), info.get("description", ""), info.get("link", "#"),
        )
        n += 1
    print(f"✅ groups table  ({n} entries from db.json)")


async def main() -> None:
    if not DATABASE_URL:
        print("❌ DATABASE_URL is not set. Set it (Railway → Postgres plugin → "
              "Variables → copy DATABASE_URL) and re-run.")
        sys.exit(1)

    folder = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    print(f"📂 Reading backup files from: {folder.resolve()}\n")

    global_blacklist = load_json(folder / "global_blacklist.json")
    gold_list        = load_json(folder / "gold_list.json")
    scam_reports      = load_json(folder / "scam_reports.json")
    stats             = load_json(folder / "stats.json")
    db_json           = load_json(folder / "db.json")

    conn = await asyncpg.connect(DATABASE_URL)
    try:
        await ensure_schema(conn)
        print()

        if global_blacklist is not None:
            await set_kv(conn, "global_blacklist", global_blacklist)
        if gold_list is not None:
            await set_kv(conn, "gold_list", gold_list)
        if scam_reports is not None:
            await set_kv(conn, "scam_reports", scam_reports)
        if stats is not None:
            await set_kv(conn, "stats", stats)

        if db_json is not None:
            if "users" in db_json:
                await migrate_users_from_dbjson(conn, db_json["users"])
            if "groups" in db_json:
                await migrate_groups_from_dbjson(conn, db_json["groups"])
            if "texts" in db_json and isinstance(db_json["texts"], dict):
                for tkey, tval in db_json["texts"].items():
                    await set_kv(conn, f"texts/{tkey}", tval)
            if "chat_lines" in db_json:
                await set_kv(conn, "chat_lines", db_json["chat_lines"])

        print("\n✅ Migration complete.")
        print(
            "\nℹ️  users.json / buttons.json / custom_buttons.json were NOT "
            "migrated — handlers.py currently reads those from local disk, "
            "not from DB.get_json, so they need a separate code change to "
            "actually persist across redeploys."
        )
    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(main())
