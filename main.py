#!/usr/bin/env python3
"""
🛡️ TELELINK VERIFICATION ENGINE v3.0 — Israeli Standard of Trust
Production-grade entry point: rotating logs, graceful shutdown,
lifecycle hooks, preflight validation, and full error handling.
"""

import asyncio
import logging
from logging.handlers import RotatingFileHandler
import sys
import os
import time
from datetime import datetime
from typing import List, Optional

# ---------------------------------------------------------------------------
# Logging — rotating file + stdout, UTF-8 safe
# ---------------------------------------------------------------------------
def _build_logger() -> logging.Logger:
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s (Line: %(lineno)d): %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    handlers: list = []

    try:
        fh = RotatingFileHandler(
            "telelink.log",
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
        fh.setFormatter(fmt)
        handlers.append(fh)
    except OSError as exc:
        print(f"⚠️  Log file unavailable: {exc}", file=sys.stderr)

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    handlers.append(sh)

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in handlers:
        root.addHandler(h)

    return logging.getLogger(__name__)


logger = _build_logger()

# ---------------------------------------------------------------------------
# Dependency guard — aiogram
# ---------------------------------------------------------------------------
try:
    from aiogram import Bot, Dispatcher
    from aiogram.client.default import DefaultBotProperties
    from aiogram.client.session.aiohttp import AiohttpSession
    from aiogram.enums import ParseMode
    from aiogram.types import BotCommand
    from aiogram.fsm.storage.memory import MemoryStorage
    from aiohttp import web

    try:
        from aiogram.fsm.storage.sqlite import SQLiteStorage  # type: ignore
        _SQLITE_AVAILABLE = True
    except ImportError:
        SQLiteStorage = None  # type: ignore
        _SQLITE_AVAILABLE = False

except ImportError as exc:
    logger.critical("❌ Import failure while loading aiogram/aiohttp: %s", exc)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Local imports
# ---------------------------------------------------------------------------
try:
    from config import BOT_TOKEN, ADMIN_IDS, MAIN_CHANNEL_LINK, BANNER_PATH
except ImportError as exc:
    logger.critical("❌ config.py missing or incomplete: %s", exc)
    sys.exit(1)

# NEW — Railway's disk is ephemeral. Bring back users / buttons / admins / audit
# files from their Postgres mirror before handlers.py reads them at import time.
try:
    import db_local as _db_local

    async def _restore_files_once() -> None:
        try:
            restored = await _db_local.restore_files()
            if restored:
                logger.info("♻️ Restored %d local file(s) from Postgres", restored)
        finally:
            # the pool must not outlive this temporary event loop
            await _db_local.close_pool()

    if os.getenv("DATABASE_URL"):
        asyncio.run(_restore_files_once())
except Exception as _restore_exc:  # never block start-up on a restore problem
    logger.warning("⚠️ File restore skipped: %s", _restore_exc)

try:
    from handlers import router as handlers_router
    logger.info("✅ All modules loaded successfully")
except ImportError as exc:
    logger.critical("❌ Import error from handlers.py: %s", exc)
    sys.exit(1)

# NEW — Experience Pack (extra commands, safety center, FAQ, anti-spam).
# Optional by design: if it fails to import, the bot runs exactly as before.
try:
    from extras import router as extras_router, ThrottleMiddleware
    logger.info("✅ Experience Pack loaded")
except Exception as exc:  # noqa: BLE001
    extras_router = None  # type: ignore[assignment]
    ThrottleMiddleware = None  # type: ignore[assignment,misc]
    logger.warning("⚠️ extras.py not loaded: %s", exc)

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
START_TIME: float = time.time()

# ---------------------------------------------------------------------------
# Admin notification helper
# ---------------------------------------------------------------------------
async def notify_admins(bot: Bot, text: str) -> None:
    """Broadcast a system-level message to every configured admin. Never raises."""
    if not ADMIN_IDS:
        return
    for admin_id in ADMIN_IDS:
        try:
            await bot.send_message(chat_id=admin_id, text=text, parse_mode=ParseMode.HTML)
        except Exception as exc:
            logger.error("⚠️ Could not notify admin %s: %s", admin_id, exc)

# ---------------------------------------------------------------------------
# FSM storage factory
# ---------------------------------------------------------------------------
def get_storage() -> MemoryStorage:
    """Return SQLiteStorage for production, MemoryStorage as fallback."""
    if os.getenv("ENV") == "dev" or not _SQLITE_AVAILABLE or SQLiteStorage is None:
        logger.info("ℹ️ Using MemoryStorage (dev mode or SQLite unavailable)")
        return MemoryStorage()

    db_path = os.getenv("FSM_DB_PATH", "telelink_fsm.db")
    try:
        storage = SQLiteStorage(db_path)  # type: ignore[call-arg]
        logger.info("✅ SQLite FSM storage: %s", db_path)
        return storage
    except Exception as exc:
        logger.warning("SQLite storage failed (%s) — falling back to MemoryStorage", exc)
        return MemoryStorage()

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
async def preflight_checks(bot: Bot) -> bool:
    """
    Run startup validations before accepting updates.
    Returns True only when all critical checks pass.
    """
    checks: List[str] = []

    # 1. Verify Telegram connectivity and bot identity
    try:
        me = await bot.get_me()
        logger.info("✅ Bot connected: @%s (ID: %s)", me.username, me.id)
        checks.append("BOT_OK")
    except Exception as exc:
        logger.error("❌ Invalid token or Telegram unreachable: %s", exc)
        return False

    # 2. Register bot command menu
    try:
        commands = [
            BotCommand(command="start",  description="🚀 הפעלת הבוט"),
            BotCommand(command="help",   description="❓ עזרה ומידע"),
            BotCommand(command="check",  description="🔍 בדיקת ישות: /check @username"),
            BotCommand(command="tips",   description="🛡️ מרכז הבטיחות"),
            BotCommand(command="faq",    description="💬 שאלות נפוצות"),
            BotCommand(command="id",     description="🆔 המזהה שלי בטלגרם"),
            BotCommand(command="admin",  description="⚙️ פאנל ניהול (מנהלים בלבד)"),
        ]
        await bot.set_my_commands(commands)
        logger.info("✅ Bot command menu updated (%d commands)", len(commands))
        checks.append("COMMANDS_OK")
    except Exception as exc:
        logger.warning("⚠️ Could not set bot commands: %s", exc)

    # 2b. Database connectivity (NEW — informative, never blocks start-up)
    try:
        from db_local import ping as _ping
        if os.getenv("DATABASE_URL"):
            if await _ping():
                logger.info("✅ Postgres connection OK")
                checks.append("DB_OK")
            else:
                logger.error("❌ Postgres unreachable — check DATABASE_URL (Neon)")
        else:
            logger.warning("⚠️ DATABASE_URL is not set — database-backed features will use safe defaults")
    except Exception as exc:
        logger.warning("⚠️ DB preflight skipped: %s", exc)

    # 3. Ensure data directory exists
    try:
        os.makedirs("data", exist_ok=True)
        checks.append("DIRS_OK")
    except OSError as exc:
        logger.error("❌ Cannot create data directory: %s", exc)
        return False

    # 4. Config sanity
    if not ADMIN_IDS:
        logger.warning("⚠️ ADMIN_IDS is empty — admins will not receive system alerts")
    else:
        checks.append(f"ADMINS_OK ({len(ADMIN_IDS)})")

    if not str(MAIN_CHANNEL_LINK).startswith("http"):
        logger.warning("⚠️ MAIN_CHANNEL_LINK does not look like a valid HTTP URL: %s", MAIN_CHANNEL_LINK)

    logger.info("✅ Preflight passed: %s", ", ".join(checks))
    return True

# ---------------------------------------------------------------------------
# Lifecycle hooks
# ---------------------------------------------------------------------------
async def on_startup(bot: Bot) -> None:
    """Executed automatically when the bot comes online."""
    start_time_str = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    logger.info("🟢 Bot startup at %s", start_time_str)
    await notify_admins(
        bot,
        (
            "🟢 <b>TELELINK מערכת — פעילה!</b>\n\n"
            f"🕒 <b>זמן הפעלה:</b> {start_time_str}\n"
            "🛡️ <b>כל מודולים טעונים ומוכנים.</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "⚙️ <i>פולינג פעיל — הבוט מאזין לעדכונים.</i>"
        ),
    )


async def on_shutdown(bot: Bot, dispatcher: Dispatcher) -> None:
    """Executed automatically when the bot shuts down."""
    uptime_seconds = max(0, int(time.time() - START_TIME))
    hours, remainder = divmod(uptime_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    uptime_str = f"{hours}h {minutes}m {seconds}s"

    logger.info("🔴 Bot shutting down (uptime: %s)", uptime_str)
    await notify_admins(
        bot,
        (
            "🔴 <b>TELELINK מערכת — כיבוי!</b>\n\n"
            f"⏱️ <b>זמן פעילות:</b> {uptime_str}\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "<i>הבוט ירד מהאוויר. בדקו את הלוגים לפרטים.</i>"
        ),
    )

    # Safely close FSM storage
    storage = getattr(dispatcher, "storage", None)
    if storage is not None and hasattr(storage, "close"):
        try:
            logger.info("🔄 Closing FSM storage...")
            await storage.close()
            logger.info("✅ FSM storage closed")
        except Exception as exc:
            logger.error("⚠️ Error closing FSM storage: %s", exc)

# ---------------------------------------------------------------------------
# Health-check server — Render's free tier only offers Web Services (not
# Background Workers), and Web Services must bind to $PORT and respond to
# HTTP requests to stay alive. The bot itself uses long-polling and doesn't
# need a real HTTP API; this tiny server exists purely to satisfy that
# requirement and keep the service from being marked unhealthy.
# ---------------------------------------------------------------------------
async def start_health_server() -> None:
    app = web.Application()

    async def health(_request: web.Request) -> web.Response:
        return web.Response(text="ok")

    app.router.add_get("/", health)

    # NEW — richer probe for uptime monitors / Railway healthchecks
    async def health_json(_request: web.Request) -> web.Response:
        return web.json_response(
            {"status": "ok", "uptime_seconds": int(time.time() - START_TIME), "service": "telelink-bot"}
        )

    app.router.add_get("/health", health_json)
    app.router.add_get("/healthz", health_json)

    runner = web.AppRunner(app)
    await runner.setup()
    port = int(os.getenv("PORT", "10000"))
    site = web.TCPSite(runner, "0.0.0.0", port)
    await site.start()
    logger.info("🩺 Health check server listening on port %d", port)


# ---------------------------------------------------------------------------
# Main coroutine
# ---------------------------------------------------------------------------
async def main() -> None:
    """Full production-grade main coroutine."""

    await start_health_server()

    session = AiohttpSession(timeout=60)

    bot = Bot(
        token=BOT_TOKEN,
        session=session,
        default=DefaultBotProperties(
            parse_mode=ParseMode.HTML,
            allow_sending_without_reply=True,
        ),
    )

    storage = get_storage()
    dp      = Dispatcher(storage=storage)

    # Register lifecycle hooks
    dp.startup.register(on_startup)
    dp.shutdown.register(on_shutdown)

    # NEW — flood protection (admins exempt) + extra commands.
    # extras_router is attached FIRST so its commands win over handlers.py's catch-all.
    if ThrottleMiddleware is not None:
        dp.message.outer_middleware(ThrottleMiddleware(limit=15, window=10.0))
        dp.callback_query.outer_middleware(ThrottleMiddleware(limit=12, window=5.0))
    if extras_router is not None:
        dp.include_router(extras_router)

    # Attach routers
    dp.include_router(handlers_router)

    # Run pre-flight validation
    if not await preflight_checks(bot):
        logger.error("❌ Preflight checks failed — aborting startup")
        await bot.session.close()
        return

    logger.info("🚀 Starting polling...")

    try:
        await bot.delete_webhook(drop_pending_updates=True)

        await dp.start_polling(
            bot,
            handle_signals=True,
            skip_updates=False,
        )
    except KeyboardInterrupt:
        logger.info("⏹️ Manual stop (KeyboardInterrupt)")
    except Exception as exc:
        logger.error("❌ Critical polling error: %s", exc, exc_info=True)
    finally:
        logger.info("🔄 Running cleanup...")

        try:
            await bot.session.close()
        except Exception as exc:
            logger.warning("⚠️ Error closing bot session: %s", exc)

        if hasattr(storage, "close"):
            try:
                await storage.close()
            except Exception:
                pass

        # NEW — let in-flight DB mirror uploads finish, then close the Postgres pool
        try:
            import handlers as _handlers_mod
            _mirrors = list(getattr(_handlers_mod, "_mirror_tasks", {}).values())
            if _mirrors:
                await asyncio.wait(_mirrors, timeout=8)
        except Exception as exc:
            logger.warning("⚠️ Error flushing DB mirrors: %s", exc)
        try:
            from db_local import close_pool as _close_pool
            await _close_pool()
        except Exception as exc:
            logger.warning("⚠️ Error closing DB pool: %s", exc)

        current_task = asyncio.current_task()
        pending = [t for t in asyncio.all_tasks() if t is not current_task]
        if pending:
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

        logger.info("✅ Telelink shut down cleanly")

# ---------------------------------------------------------------------------
# Process-level runner
# ---------------------------------------------------------------------------
def run_bot() -> None:
    """Top-level entry point with full exception coverage."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("⛔ Stopped by user (KeyboardInterrupt)")
    except SystemExit as exc:
        logger.info("⛔ SystemExit: %s", exc)
    except Exception as exc:
        logger.critical("💥 Fatal application-level error: %s", exc, exc_info=True)
        sys.exit(1)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("━" * 60)
    print("  🛡️  TELELINK VERIFICATION ENGINE v3.0")
    print("  🇮🇱  Israeli Standard of Trust — PRODUCTION READY")
    print("━" * 60)
    run_bot()