#!/usr/bin/env python3
"""
import_dbjson_to_firebase.py — ONE-TIME import of db.json's content into Firebase.

db.json has a different shape than the data/*.json files (it's a single combined
snapshot with "users", "groups", "texts", "chat_lines", "stats" all together) —
this pushes each top-level key to its OWN Firebase path with a PUT, which only
replaces that specific path and leaves every sibling path (including anything
already migrated by migrate_to_firebase.py) untouched.

"stats" is intentionally NOT auto-imported — see the printed note at the end,
since it's easy to accidentally overwrite more current numbers with stale ones.

Usage:
    pip install httpx python-dotenv   # if not already installed
    python import_dbjson_to_firebase.py path/to/db.json
"""

import asyncio
import json
import os
import re
import sys
from typing import Any, Dict

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import httpx

FIREBASE_URL = os.getenv("FIREBASE_URL", "")

_FORBIDDEN_KEY_CHARS = re.compile(r"[.$#\[\]/]")


def sanitize_key(raw_key: str) -> str:
    key = str(raw_key).strip()
    if "\n" in key:
        key = key.split("\n")[-1].strip()
    if "\r" in key:
        key = key.split("\r")[-1].strip()
    for prefix in ("https://", "http://", "t.me/", "telegram.me/"):
        key = key.replace(prefix, "")
    key = key.replace("@", "")
    key = _FORBIDDEN_KEY_CHARS.sub("_", key)
    key = "".join(ch for ch in key if ch.isprintable())
    key = key.strip("_").strip()
    return key or "_unknown_"


def sanitize_dict_keys(data: Any) -> Any:
    if not isinstance(data, dict):
        return data
    cleaned: Dict[str, Any] = {}
    for k, v in data.items():
        new_key = sanitize_key(k)
        final_key = new_key
        suffix = 2
        while final_key in cleaned:
            final_key = f"{new_key}_{suffix}"
            suffix += 1
        cleaned[final_key] = v
    return cleaned

# top-level db.json key -> firebase path (None = skip, handled manually)
KEY_MAP = {
    "users": "users",
    "groups": "groups",
    "texts": "texts",
    "chat_lines": "chat_lines",
    "stats": None,  # intentionally skipped - see note below
}


async def main():
    if len(sys.argv) < 2:
        print("Usage: python import_dbjson_to_firebase.py path/to/db.json")
        sys.exit(1)

    if not FIREBASE_URL:
        print("❌ FIREBASE_URL is not set. Set it in your environment or a .env file, then re-run.")
        sys.exit(1)

    path = sys.argv[1]
    with open(path, "r", encoding="utf-8") as f:
        db = json.load(f)

    print(f"🔥 Importing {path} into Firebase: {FIREBASE_URL}\n")

    async with httpx.AsyncClient(timeout=30.0) as client:
        for db_key, firebase_path in KEY_MAP.items():
            if firebase_path is None:
                continue
            if db_key not in db:
                print(f"⏭️  '{db_key}' not present in {path}, skipping.")
                continue

            value = db[db_key]
            if isinstance(value, dict):
                value = sanitize_dict_keys(value)
            url = f"{FIREBASE_URL.rstrip('/')}/{firebase_path}.json"
            res = await client.put(url, json=value)
            if res.status_code in (200, 201):
                count = len(value) if isinstance(value, (list, dict)) else 1
                print(f"✅ '{db_key}' → Firebase:/{firebase_path} ({count} entries)")
            else:
                print(f"❌ '{db_key}' → Firebase:/{firebase_path} failed: HTTP {res.status_code} — {res.text[:200]}")

    if "stats" in db:
        print(
            f"\nℹ️  db.json also has a 'stats' block ({db['stats']}) — NOT imported automatically, "
            "since you may already have more current stats in Firebase from the bot running live. "
            "If you want this exact snapshot instead, PUT it manually to "
            f"{FIREBASE_URL.rstrip('/')}/stats.json via the Firebase console."
        )

    print("\n✅ Import complete. Verify in the Firebase console.")


if __name__ == "__main__":
    asyncio.run(main())