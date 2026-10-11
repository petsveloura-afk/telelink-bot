#!/usr/bin/env python3
"""
migrate_to_firebase.py — ONE-TIME migration of existing local data files
into Firebase, matching the paths handlers.py now reads/writes via DB.get_json/set_json.

Run this LOCALLY, once, from the same folder that has your current `data/` directory
with the real accumulated blacklist/gold_list/scam_reports/stats — BEFORE your first
deploy to Render (or any time after, if you find local data you don't want to lose).

Usage:
    pip install httpx python-dotenv   # if not already installed
    python migrate_to_firebase.py

It reads FIREBASE_URL from your environment (or a local .env file), same as the bot does.
Safe to re-run: it overwrites the Firebase path with the local file's content (PUT), so
run it BEFORE the bot has written anything meaningful to those Firebase paths, or you may
overwrite newer Firebase data with older local data.
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
DATA_DIR = "data"

# Firebase Realtime Database keys cannot contain . $ # [ ] / or be empty.
_FORBIDDEN_KEY_CHARS = re.compile(r"[.$#\[\]/]")


def sanitize_key(raw_key: str) -> str:
    """Clean a dict key so Firebase will accept it as a path segment."""
    key = str(raw_key).strip()
    # multi-line "warning label + username" entries (e.g. "🐝 scam warning\nrealuser")
    # -> keep just the last line, matching the convention already used in fix_db.py
    if "\n" in key:
        key = key.split("\n")[-1].strip()
    if "\r" in key:
        key = key.split("\r")[-1].strip()
    for prefix in ("https://", "http://", "t.me/", "telegram.me/"):
        key = key.replace(prefix, "")
    key = key.replace("@", "")
    key = _FORBIDDEN_KEY_CHARS.sub("_", key)
    # strip any remaining control characters (tabs, zero-width marks, etc.)
    key = "".join(ch for ch in key if ch.isprintable())
    key = key.strip("_").strip()
    return key or "_unknown_"


def sanitize_dict_keys(data: Any) -> Any:
    """Recursively sanitize keys of a dict; leaves lists/values untouched."""
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

# (local filename, firebase path, expected type)
MIGRATIONS = [
    ("global_blacklist.json", "global_blacklist", dict),
    ("gold_list.json", "gold_list", list),
    ("scam_reports.json", "scam_reports", list),
    ("stats.json", "stats", dict),
]


async def migrate_one(client: httpx.AsyncClient, filename: str, firebase_path: str, expected_type):
    local_path = os.path.join(DATA_DIR, filename)
    if not os.path.exists(local_path):
        print(f"⏭️  {filename} not found locally, skipping.")
        return

    with open(local_path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as exc:
            print(f"❌ {filename}: invalid JSON ({exc}), skipping.")
            return

    if not isinstance(data, expected_type):
        print(f"⚠️  {filename}: expected {expected_type.__name__}, got {type(data).__name__} — migrating anyway.")

    if isinstance(data, dict):
        data = sanitize_dict_keys(data)

    url = f"{FIREBASE_URL.rstrip('/')}/{firebase_path}.json"
    res = await client.put(url, json=data)
    if res.status_code in (200, 201):
        count = len(data) if isinstance(data, (list, dict)) else 1
        print(f"✅ {filename} → Firebase:/{firebase_path} ({count} entries)")
    else:
        print(f"❌ {filename} → Firebase:/{firebase_path} failed: HTTP {res.status_code} — {res.text[:200]}")


async def main():
    if not FIREBASE_URL:
        print("❌ FIREBASE_URL is not set. Set it in your environment or a .env file, then re-run.")
        sys.exit(1)

    print(f"🔥 Migrating local data/ files to Firebase: {FIREBASE_URL}\n")
    async with httpx.AsyncClient(timeout=30.0) as client:
        for filename, firebase_path, expected_type in MIGRATIONS:
            await migrate_one(client, filename, firebase_path, expected_type)

    print("\n✅ Migration complete. Verify in the Firebase console before deleting local files.")


if __name__ == "__main__":
    asyncio.run(main())