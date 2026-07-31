# TELELINK Bot — Render Deployment Guide

## What changed vs. your local version

1. **`main.py`** — added a tiny health-check HTTP server (`start_health_server()`), started
   right before polling begins. This is required because Render's **free tier only offers
   Web Services**, not Background Workers — and Web Services must bind to `$PORT` and respond
   to HTTP requests to stay alive. It doesn't change any bot behavior; it just keeps the
   container marked "healthy."
2. **`Dockerfile`** — added `EXPOSE 10000` for clarity (Render reads `$PORT` regardless).
3. **`requirements.txt`** — reconstructed from your actual imports (`aiogram`, `aiohttp`, `httpx`,
   `python-dotenv`, `aiosqlite`). **Compare this against your real `requirements.txt` and use
   yours instead if it differs** — this is a best-effort reconstruction since the original
   file wasn't included in what you sent me.

## About your data storage — UPDATED

I initially told you the blacklist/gold list were already Firebase-backed — I was wrong, and
traced the actual code to confirm: `load_blacklist`, `load_gold_list`, `load_reports`, and
`load_stats` were reading/writing **local JSON files** (`data/global_blacklist.json`,
`data/gold_list.json`, `data/scam_reports.json`, `data/stats.json`), which would have been
wiped on every Render redeploy.

**This is now fixed.** Those four functions in `handlers.py` have been rewired to read/write
through Firebase (`db_local.py`'s new `DB.get_json()` / `DB.set_json()` generic helpers),
exactly like `users`/`groups` already were. From now on, anything added to the blacklist,
gold list, or scam reports — through the bot, at any time, including after future
redeploys — is permanently safe in Firebase.

### One-time migration of your EXISTING local data
If you already have real entries accumulated in your current local `data/*.json` files that
you don't want to lose, run **`migrate_to_firebase.py`** once, locally, from the folder that
has your real `data/` directory — **before** your first deploy to Render:

```bash
pip install httpx python-dotenv
python migrate_to_firebase.py
```

It reads `FIREBASE_URL` from your environment/`.env` and pushes `global_blacklist.json`,
`gold_list.json`, `scam_reports.json`, and `stats.json` into the matching Firebase paths.
Safe to skip if you're starting fresh or those files are currently empty.

### What's STILL local-only (lower priority, not migrated in this pass)
Secondary admins added via the panel (`data/admins_extra.json`) and the audit trail
(`data/audit_log.json`) still use local files and will reset on redeploy. Not migrated
this round since you can always re-add admins via the `ADMIN_IDS`/`SUPER_ADMIN_IDS` env
vars — but the same `DB.get_json`/`DB.set_json` pattern can migrate these too if you want
that later; just ask.


## ⚠️ Found a real bug in your requirements.txt

You sent me your actual `requirements.txt`:
```
aiogram==3.2.0
firebase-admin==6.0.1
python-dotenv==1.0.0
psycopg2-binary==2.9.7
```

This doesn't match what the code actually imports. I checked every file:
- **`httpx`** is imported directly by `db_local.py` (and my new `migrate_to_firebase.py`) — **not listed**.
- **`aiohttp`** is imported directly by `firebase.py`, `utils.py`, and `main.py` — **not listed**
  (aiogram pulls in *a* version of aiohttp transitively, but relying on that is fragile).
- **`firebase-admin`** and **`psycopg2-binary`** — grepped the entire codebase, **neither is
  imported anywhere**. Dead weight from an earlier version of the project.

**Why this matters a lot:** `handlers.py` wraps `from db_local import DB` in a
`try/except ImportError`. If `httpx` isn't actually installed, that import silently fails and
`DB` falls back to a stub — meaning `DB.get_json`/`DB.set_json` (the new Firebase-backed
blacklist/gold-list/reports/stats storage we just built) would **silently do nothing**, with
no error, no crash — just data quietly not saving. This is exactly the kind of bug that looks
fine until you check the database days later and it's empty.

**Fixed in this package** — replaced with the actual imports (`aiogram`, `aiohttp`, `httpx`,
`python-dotenv`). Removed `firebase-admin` and `psycopg2-binary` since nothing uses them —
if you have future plans for either, let me know and I'll add them back deliberately instead
of leaving unused deps that only slow down the Docker build.

## About db.json / db.json.bak / fix_db.py

Your local folder also has a root-level `db.json` (and `.bak`) with a `{"users": {...}}`
structure, used by `fix_db.py` — this is separate from everything above (not read by
`handlers.py`, `db_local.py`, or `main.py` at all, as far as the current code shows). It looks
like a standalone one-off maintenance script's data file, not something the live bot reads on
startup. It's excluded from git via `.gitignore` (`*.json` isn't blanket-ignored, but you
should manually confirm `db.json` isn't something you need copied over — I didn't include it
in this package since I don't know its role for certain).

## Deployment steps

### 1. Push this to its own GitHub repo
This is a separate bot from your marketplace project — give it its own repo.

```bash
cd telelink-bot   # wherever you unzip this
git init
git add .
git commit -m "Initial commit - TELELINK bot, Render-ready"
```

Create a new empty repo on GitHub (e.g. `telelink-bot`), then:

```bash
git remote add origin https://github.com/<your-username>/telelink-bot.git
git branch -M main
git push -u origin main
```

### 2. Deploy on Render
- **New → Blueprint**, connect the `telelink-bot` repo. Render will read `render.yaml`
  automatically and create one free Web Service.
- Fill in the environment variables it asks for:
  - `BOT_TOKEN` — from BotFather (this is a **different bot** from your marketplace one —
    make sure you use TELELINK's own token, not GO MARKET's)
  - `ADMIN_IDS` — comma-separated Telegram user IDs
  - `SUPER_ADMIN_IDS` — comma-separated (optional — defaults to the hardcoded values in
    `config.py` if omitted)
  - `FIREBASE_URL` — your Firebase Realtime Database URL
  - `MAIN_CHANNEL_LINK`, `HELP_SUPPORT_LINK` — your channel/support links
- Click **Apply**.

### 3. Keep it awake (same as your other bot)
Free Render Web Services sleep after ~15 minutes of no HTTP traffic, which would pause
Telegram polling too. Set up a free pinger the same way you did for the marketplace bot:
- [cron-job.org](https://cron-job.org) → new cron job → URL = your Render service's URL →
  every 10 minutes.

### 4. Verify
Check the **Logs** tab for `🩺 Health check server listening on port 10000` and
`✅ Bot connected: @yourbotusername`. Then send `/start` to the bot on Telegram.
