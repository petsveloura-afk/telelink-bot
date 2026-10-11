"""
extras.py — TELELINK Experience Pack v1.0
Additive module: it does not replace or modify a single existing handler.
It is included in the Dispatcher BEFORE handlers.router (so its commands win over
the catch-all fallback) and adds:

  • /help   — a rich help screen
  • /check  — instant verification:   /check @username   (or interactive when no argument)
  • /id     — shows the user's Telegram ID (handy for admins / support)
  • /tips   — Safety Center (6 practical guides)
  • /faq    — frequently asked questions
  • /status — admin-only health dashboard (DB latency, uptime, queue sizes)
  • ThrottleMiddleware — anti-spam / flood protection (admins exempt)
"""

import logging
import time
from collections import deque
from typing import Any, Awaitable, Callable, Deque, Dict, List, Optional, Tuple

from aiogram import BaseMiddleware, F, Router
from aiogram.dispatcher.event.bases import SkipHandler
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandObject
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Message, TelegramObject

from handlers import (
    ADMIN_IDS,
    CheckFlow,
    _esc,
    get_button_url,
    is_effective_admin,
    load_blacklist,
    load_gold_list,
    load_reports,
    load_users,
    process_verification,
    telelink_main_menu,
)

try:
    from db_local import ping as _db_ping
except ImportError:  # pragma: no cover
    async def _db_ping() -> bool:  # type: ignore[misc]
        return False

logger = logging.getLogger("telelink_extras")

router = Router(name="telelink_extras")

_STARTED_AT: float = time.time()
BOT_VERSION: str = "3.1"

# ---------------------------------------------------------------------------
# Content — Safety Center
# ---------------------------------------------------------------------------
_TIPS: Dict[str, Tuple[str, str]] = {
    "payments": (
        "💸 תשלומים בטוחים",
        "💸 <b>איך משלמים בלי להיעקץ</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "• <b>לא משלמים מראש לגורם שלא אומת.</b> גם אם \"כולם קונים אצלו\".\n"
        "• העדיפו אמצעי תשלום עם הגנת קונה (כרטיס אשראי / מתווך) על פני העברה ישירה.\n"
        "• ודאו ששם מקבל התשלום תואם לשם איש הקשר. פער = דגל אדום.\n"
        "• <b>לעולם אל תשלחו קודי אימות (SMS / טלגרם)</b> — לאף אחד, בשום תירוץ.\n"
        "• לחץ של \"זה נגמר היום\" הוא כלי העבודה של נוכלים. עצרו ובדקו.\n"
        "• שמרו אישורי תשלום וצילומי מסך של ההתכתבות עד שהעסקה הושלמה.\n\n"
        "🔍 לפני כל תשלום: <code>/check @username</code>",
    ),
    "impersonation": (
        "🎭 התחזות והעתקות",
        "🎭 <b>נוכלים מעתיקים שמות — איך מזהים?</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "• בדקו את שם המשתמש אות-אות: <code>l</code> מול <code>1</code>, "
        "<code>o</code> מול <code>0</code>, קו תחתון מיותר או אות כפולה.\n"
        "• מנהלים אמיתיים <b>לא פונים אליכם ראשונים</b> בפרטי עם הצעה \"מיוחדת\".\n"
        "• בקשו הוכחת חיים: הודעה קולית או שיחת וידאו קצרה. מתחזים מתחמקים.\n"
        "• אל תסתמכו על תמונת פרופיל או מספר עוקבים — שניהם קלים להעתקה.\n"
        "• הריצו בדיקה בבוט: אם השם דומה מאוד לשותף זהב, תקבלו <b>אזהרת התחזות</b>.\n\n"
        "🔍 <code>/check @username</code>",
    ),
    "escrow": (
        "🤝 עסקה עם מתווך",
        "🤝 <b>עסקה מאובטחת באמצעות גורם מתווך</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "<b>1.</b> בוחרים מתווך שאומת מראש (בדקו אותו בבוט כמו כל ישות).\n"
        "<b>2.</b> מסכמים בכתב: מה נמכר, מחיר, מועד אספקה ותנאי החזרה.\n"
        "<b>3.</b> הקונה מעביר את הכסף <u>למתווך</u> — לא למוכר.\n"
        "<b>4.</b> המוכר מספק. הקונה בודק ומאשר קבלה.\n"
        "<b>5.</b> רק אז המתווך משחרר את התשלום למוכר.\n\n"
        "⚠️ מוכר שמתנגד לכל מתווך ודורש \"העברה ישירה בלבד\" — חשוד כמעט תמיד.",
    ),
    "redflags": (
        "🚩 דגלים אדומים",
        "🚩 <b>סימנים שמעידים על הונאה</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "🔴 מחיר נמוך משמעותית משוק — \"הזדמנות חד-פעמית\"\n"
        "🔴 לחץ זמן: \"נשארו 2 יחידות\", \"רק היום\"\n"
        "🔴 דרישה למקדמה או \"דמי רצינות\" לפני כל הוכחה\n"
        "🔴 מעבר מהיר לפלטפורמה אחרת (וואטסאפ, אפליקציה לא מוכרת)\n"
        "🔴 סירוב לשיחת וידאו או לתמונה עם תאריך של היום\n"
        "🔴 הרבה צילומי מסך של \"לקוחות מרוצים\" ואפס ביקורות ניתנות לאימות\n"
        "🔴 שגיאות כתיב מוזרות, שפה שמרגישה מתורגמת\n\n"
        "אם זיהיתם שניים או יותר — עצרו, ובדקו בבוט.",
    ),
    "links": (
        "🔗 קישורים והודעות חשודות",
        "🔗 <b>קישורים, קודים והודעות \"רשמיות\"</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "• אל תלחצו על קישורים מקוצרים שהגיעו מגורם לא מוכר.\n"
        "• טלגרם <b>לעולם לא</b> מבקש מכם קוד כניסה בהודעה פרטית.\n"
        "• \"מתנת פרימיום\", \"זכיתם\", \"החשבון ייחסם\" — כמעט תמיד פישינג.\n"
        "• בדקו כתובת אתר לפני הזנת סיסמה: דומיין כמעט-זהה הוא סימן להונאה.\n"
        "• הפעילו אימות דו-שלבי בטלגרם (הגדרות ← פרטיות ואבטחה).\n"
        "• קבוצות/ערוצים: ודאו את קישור ההזמנה מול מקור רשמי לפני שמצטרפים.",
    ),
    "victim": (
        "🆘 נפלתי קורבן — מה עושים?",
        "🆘 <b>נפלתם להונאה? פועלים מהר ובשקט</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "<b>1.</b> הפסיקו כל קשר והעברת כספים נוספת.\n"
        "<b>2.</b> שמרו ראיות: צילומי מסך, שם משתמש, קישורים, אישורי תשלום.\n"
        "<b>3.</b> פנו מיד לבנק / חברת האשראי — בחלק מהמקרים אפשר לעצור או לבטל עסקה.\n"
        "<b>4.</b> הגישו תלונה במשטרה (ניתן גם אונליין), ובמקרי סייבר ניתן לפנות למוקד 105.\n"
        "<b>5.</b> דווחו לנו דרך הבוט כדי שנגן על אחרים — פתיחת תיק לוקחת פחות מדקה.\n\n"
        "💙 זה יכול לקרות לכל אחד. אין בושה — יש פעולה.",
    ),
}

_TIPS_ORDER: List[str] = ["payments", "impersonation", "escrow", "redflags", "links", "victim"]

# ---------------------------------------------------------------------------
# Content — FAQ
# ---------------------------------------------------------------------------
_FAQ: List[Tuple[str, str]] = [
    (
        "🔍 איך עובדת הבדיקה?",
        "הבוט בודק את הישות שלכם מול <b>רשימת הזהב</b>, <b>הרשימה השחורה הגלובלית</b> "
        "ומסד הנתונים הפנימי של TELELINK, ומחזיר דוח עם סטטוס, מדד אמינות ופסיקה.",
    ),
    (
        "📊 מה המשמעות של מדד האמינות?",
        "• <b>100%</b> — ישות מאומתת או שותף זהב.\n"
        "• <b>45%</b> — לא ידוע: אין עליה מידע במערכת. <i>זה לא אישור</i> — נהגו בזהירות.\n"
        "• <b>0%</b> — ישות שנחסמה על סמך דיווחים. הימנעו ממגע.",
    ),
    (
        "🚨 איך מדווחים על נוכל?",
        "מהתפריט הראשי ← \"דיווח על הונאה\", או ישירות מדוח בדיקה. "
        "התהליך כולל 3 שלבים: זיהוי הישות, צירוף ראיות (עד 10 תמונות + טקסט/קישור) ותיאור האירוע.",
    ),
    (
        "⏱️ כמה זמן לוקח לטפל בדיווח?",
        "דיווחים נבדקים לפי סדר קבלתם, בדרך כלל עד 24 שעות. "
        "בסיום הטיפול תקבלו כאן הודעה אם הדיווח אושר או נדחה.",
    ),
    (
        "❓ ישות מסומנת \"לא ידוע\" — האם היא בטוחה?",
        "לא בהכרח. המשמעות היא שעדיין אין לנו מידע. מומלץ לבקש הוכחת חיים, "
        "לעבוד עם מתווך ולא להעביר מקדמה לפני שהצד השני אומת.",
    ),
    (
        "🔒 מי רואה את פרטי המדווח?",
        "פרטי המדווח והראיות מוצגים <b>לצוות האבטחה בלבד</b>, לצורך בחינת התיק. "
        "הם אינם מתפרסמים ברשימות הציבוריות.",
    ),
    (
        "💎 מהי רשימת הזהב?",
        "אינדקס של גופים עסקיים שעברו ביקורת מחמירה ונמצאו אמינים. "
        "ניתן לצפות בו מהתפריט הראשי ← \"אינדקס רשימת הזהב\".",
    ),
    (
        "🤝 איך מצטרפים כשותף מאומת?",
        "פנו אלינו דרך \"שותפות עסקית\" בתפריט הראשי או דרך מרכז התמיכה, והצוות יחזור אליכם.",
    ),
]

# ---------------------------------------------------------------------------
# Keyboards
# ---------------------------------------------------------------------------
def _tips_keyboard() -> InlineKeyboardMarkup:
    rows: List[List[InlineKeyboardButton]] = []
    keys = _TIPS_ORDER
    for i in range(0, len(keys), 2):
        rows.append(
            [InlineKeyboardButton(text=_TIPS[k][0], callback_data=f"tips_page:{k}") for k in keys[i : i + 2]]
        )
    rows.append([InlineKeyboardButton(text="❓ שאלות נפוצות", callback_data="faq_menu")])
    rows.append([InlineKeyboardButton(text="🏠 חזרה לתפריט הראשי", callback_data="main_menu")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def _tips_page_keyboard(current: str) -> InlineKeyboardMarkup:
    idx = _TIPS_ORDER.index(current) if current in _TIPS_ORDER else 0
    nav: List[InlineKeyboardButton] = []
    if idx > 0:
        nav.append(InlineKeyboardButton(text="⬅️ הקודם", callback_data=f"tips_page:{_TIPS_ORDER[idx - 1]}"))
    if idx < len(_TIPS_ORDER) - 1:
        nav.append(InlineKeyboardButton(text="הבא ➡️", callback_data=f"tips_page:{_TIPS_ORDER[idx + 1]}"))
    rows: List[List[InlineKeyboardButton]] = []
    if nav:
        rows.append(nav)
    rows.append([InlineKeyboardButton(text="🔍 בדיקת ישות", callback_data="check_entity")])
    rows.append([InlineKeyboardButton(text="🛡️ מרכז הבטיחות", callback_data="safety_tips")])
    rows.append([InlineKeyboardButton(text="🏠 תפריט ראשי", callback_data="main_menu")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def _faq_keyboard() -> InlineKeyboardMarkup:
    rows = [[InlineKeyboardButton(text=q, callback_data=f"faq:{i}")] for i, (q, _a) in enumerate(_FAQ)]
    rows.append([InlineKeyboardButton(text="🛡️ מרכז הבטיחות", callback_data="safety_tips")])
    rows.append([InlineKeyboardButton(text="🏠 חזרה לתפריט הראשי", callback_data="main_menu")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def _faq_answer_keyboard(idx: int) -> InlineKeyboardMarkup:
    nav: List[InlineKeyboardButton] = []
    if idx > 0:
        nav.append(InlineKeyboardButton(text="⬅️ הקודמת", callback_data=f"faq:{idx - 1}"))
    if idx < len(_FAQ) - 1:
        nav.append(InlineKeyboardButton(text="הבאה ➡️", callback_data=f"faq:{idx + 1}"))
    rows: List[List[InlineKeyboardButton]] = []
    if nav:
        rows.append(nav)
    rows.append([InlineKeyboardButton(text="❓ כל השאלות", callback_data="faq_menu")])
    rows.append([InlineKeyboardButton(text="🏠 תפריט ראשי", callback_data="main_menu")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


async def _show(call: CallbackQuery, text: str, keyboard: InlineKeyboardMarkup) -> None:
    """Edit the current message in place (clean navigation); fall back to a new message."""
    msg = call.message
    try:
        if msg is not None and getattr(msg, "photo", None):
            await msg.edit_caption(caption=text, parse_mode=ParseMode.HTML, reply_markup=keyboard)  # type: ignore[union-attr]
        elif msg is not None:
            await msg.edit_text(text, parse_mode=ParseMode.HTML, reply_markup=keyboard)  # type: ignore[union-attr]
    except Exception as exc:
        # "message is not modified", too old to edit, etc. — send fresh instead.
        logger.debug("edit failed (%s) — sending new message", exc)
        try:
            await msg.answer(text, parse_mode=ParseMode.HTML, reply_markup=keyboard)  # type: ignore[union-attr]
        except Exception as exc2:
            logger.error("_show fallback failed: %s", exc2)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
@router.message(Command("help"))
async def cmd_help(msg: Message, state: FSMContext) -> None:
    await state.clear()
    text = (
        "🛡️ <b>TELELINK — מרכז עזרה</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "הבוט עוזר לכם לבדוק מוכרים, ערוצים וקבוצות <b>לפני</b> שמעבירים כסף.\n\n"
        "<b>⌨️ פקודות מהירות</b>\n"
        "• <code>/check @username</code> — בדיקה מיידית של ישות\n"
        "• <code>/tips</code> — מרכז הבטיחות: 6 מדריכים מעשיים\n"
        "• <code>/faq</code> — שאלות נפוצות\n"
        "• <code>/id</code> — מזהה הטלגרם שלכם\n"
        "• <code>/start</code> — חזרה לתפריט הראשי\n\n"
        "<b>🚦 איך קוראים דוח בדיקה?</b>\n"
        "💎/✅ <b>100%</b> מאומת  ·  ⚠️ <b>45%</b> לא ידוע  ·  ❌ <b>0%</b> נוכל\n\n"
        f"🆘 צריכים עזרה אישית? {_esc(get_button_url('help_support'))}"
    )
    try:
        await msg.answer(text, parse_mode=ParseMode.HTML, reply_markup=telelink_main_menu(), disable_web_page_preview=True)
    except Exception as exc:
        logger.error("cmd_help error: %s", exc)


@router.message(Command("id"))
async def cmd_id(msg: Message) -> None:
    user = msg.from_user
    if user is None:
        return
    uname = f"@{_esc(user.username)}" if user.username else "(אין שם משתמש)"
    text = (
        "🆔 <b>הפרטים שלכם בטלגרם</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"מזהה משתמש: <code>{user.id}</code>\n"
        f"שם משתמש: {uname}\n"
        f"מזהה צ'אט: <code>{msg.chat.id}</code>\n\n"
        "<i>ניתן ללחוץ על המזהה כדי להעתיק אותו.</i>"
    )
    try:
        await msg.answer(text, parse_mode=ParseMode.HTML)
    except Exception as exc:
        logger.error("cmd_id error: %s", exc)


@router.message(Command("check"))
async def cmd_check(msg: Message, state: FSMContext, command: CommandObject) -> None:
    await state.clear()
    arg = (command.args or "").strip()
    if arg:
        try:
            # Re-use the exact same verification engine as the interactive flow.
            await process_verification(msg.model_copy(update={"text": arg}), state)
            return
        except Exception as exc:
            logger.warning("/check inline path failed (%s) — falling back to interactive prompt", exc)
    await state.set_state(CheckFlow.waiting_entity)
    try:
        await msg.answer(
            "🔍 <b>בדיקת ישות</b>\n\n"
            "שלחו שם משתמש, קישור לערוץ או קישור הזמנה לקבוצה:\n"
            "• <code>@username</code>\n"
            "• <code>t.me/channelname</code>\n\n"
            "💡 קיצור: <code>/check @username</code>",
            parse_mode=ParseMode.HTML,
        )
    except Exception as exc:
        logger.error("cmd_check prompt error: %s", exc)


@router.message(Command("tips"))
async def cmd_tips(msg: Message, state: FSMContext) -> None:
    await state.clear()
    try:
        await msg.answer(_tips_intro_text(), parse_mode=ParseMode.HTML, reply_markup=_tips_keyboard())
    except Exception as exc:
        logger.error("cmd_tips error: %s", exc)


@router.message(Command("faq"))
async def cmd_faq(msg: Message, state: FSMContext) -> None:
    await state.clear()
    try:
        await msg.answer(_faq_intro_text(), parse_mode=ParseMode.HTML, reply_markup=_faq_keyboard())
    except Exception as exc:
        logger.error("cmd_faq error: %s", exc)


@router.message(Command("status"))
async def cmd_status(msg: Message) -> None:
    """Admin-only health dashboard. Non-admins fall through to the normal fallback."""
    uid = getattr(msg.from_user, "id", None)
    if uid is None or not (uid in ADMIN_IDS or await is_effective_admin(uid)):
        raise SkipHandler()

    t0 = time.perf_counter()
    db_ok = await _db_ping()
    db_ms = (time.perf_counter() - t0) * 1000

    users = await load_users()
    reports = await load_reports()
    blacklist = await load_blacklist()
    gold = await load_gold_list()
    pending = sum(1 for r in reports if isinstance(r, dict) and r.get("status") == "pending")

    up = max(0, int(time.time() - _STARTED_AT))
    d, rem = divmod(up, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)

    text = (
        f"🩺 <b>TELELINK — לוח בקרה (v{BOT_VERSION})</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"🗄️ מסד נתונים: {'🟢 תקין' if db_ok else '🔴 לא זמין'}"
        f"{f' ({db_ms:.0f}ms)' if db_ok else ''}\n"
        f"⏱️ זמן פעילות: {d}d {h}h {m}m {s}s\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"👤 משתמשים רשומים: <code>{len(users)}</code>\n"
        f"⏳ דיווחים ממתינים: <code>{pending}</code> (מתוך {len(reports)})\n"
        f"🚫 ברשימה השחורה: <code>{len(blacklist)}</code>\n"
        f"💎 ברשימת הזהב: <code>{len(gold)}</code>"
    )
    try:
        await msg.answer(text, parse_mode=ParseMode.HTML)
    except Exception as exc:
        logger.error("cmd_status error: %s", exc)


# ---------------------------------------------------------------------------
# Callbacks — Safety Center / FAQ
# ---------------------------------------------------------------------------
def _tips_intro_text() -> str:
    return (
        "🛡️ <b>מרכז הבטיחות של TELELINK</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "ידע הוא ההגנה הטובה ביותר מפני נוכלים.\n"
        "בחרו מדריך — כל אחד לוקח פחות מדקה לקריאה:"
    )


def _faq_intro_text() -> str:
    return (
        "❓ <b>שאלות נפוצות</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "בחרו שאלה כדי לקבל תשובה מהירה:"
    )


@router.callback_query(F.data == "safety_tips")
async def cb_safety_tips(call: CallbackQuery, state: FSMContext) -> None:
    try:
        await state.clear()
        await _show(call, _tips_intro_text(), _tips_keyboard())
    finally:
        await call.answer()


@router.callback_query(F.data.startswith("tips_page:"))
async def cb_tips_page(call: CallbackQuery) -> None:
    try:
        key = (call.data or "").split(":", 1)[1]
        page = _TIPS.get(key)
        if not page:
            await call.answer("⚠️ המדריך לא נמצא.", show_alert=True)
            return
        await _show(call, page[1], _tips_page_keyboard(key))
    except Exception as exc:
        logger.error("cb_tips_page error: %s", exc)
    finally:
        try:
            await call.answer()
        except Exception:
            pass


@router.callback_query(F.data == "faq_menu")
async def cb_faq_menu(call: CallbackQuery, state: FSMContext) -> None:
    try:
        await state.clear()
        await _show(call, _faq_intro_text(), _faq_keyboard())
    finally:
        await call.answer()


@router.callback_query(F.data.startswith("faq:"))
async def cb_faq_answer(call: CallbackQuery) -> None:
    try:
        raw = (call.data or "").split(":", 1)[1]
        idx = int(raw)
        if not 0 <= idx < len(_FAQ):
            raise ValueError("faq index out of range")
        question, answer = _FAQ[idx]
        await _show(call, f"<b>{question}</b>\n━━━━━━━━━━━━━━━━━━━━\n{answer}", _faq_answer_keyboard(idx))
    except (ValueError, IndexError):
        await call.answer("⚠️ השאלה לא נמצאה.", show_alert=True)
        return
    except Exception as exc:
        logger.error("cb_faq_answer error: %s", exc)
    try:
        await call.answer()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Anti-spam middleware (sliding window, per user, admins exempt)
# ---------------------------------------------------------------------------
class ThrottleMiddleware(BaseMiddleware):
    """
    Drops events from a user who exceeds `limit` events within `window` seconds.
    Defaults are generous on purpose: sending a 10-photo evidence album in the
    report flow must never be blocked, only real flooding is.
    """

    def __init__(self, limit: int = 15, window: float = 10.0, notice: str = "⏳ לאט לאט... נסו שוב בעוד כמה שניות.") -> None:
        self.limit = limit
        self.window = window
        self.notice = notice
        self._hits: Dict[int, Deque[float]] = {}
        self._warned_at: Dict[int, float] = {}

    def _prune(self, now: float) -> None:
        if len(self._hits) < 5000:
            return
        for uid in [u for u, dq in self._hits.items() if not dq or now - dq[-1] > self.window]:
            self._hits.pop(uid, None)
            self._warned_at.pop(uid, None)

    async def __call__(
        self,
        handler: Callable[[TelegramObject, Dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: Dict[str, Any],
    ) -> Any:
        user = data.get("event_from_user") or getattr(event, "from_user", None)
        uid: Optional[int] = getattr(user, "id", None)
        if uid is None or uid in ADMIN_IDS:
            return await handler(event, data)

        now = time.monotonic()
        dq = self._hits.setdefault(uid, deque())
        while dq and now - dq[0] > self.window:
            dq.popleft()
        if len(dq) >= self.limit:
            logger.warning("Throttled user %s (%d events / %.0fs)", uid, len(dq), self.window)
            first_warning = now - self._warned_at.get(uid, 0.0) > self.window
            if first_warning:
                self._warned_at[uid] = now
            try:
                if isinstance(event, CallbackQuery):
                    # always answer: stops the client-side loading spinner on the button
                    await event.answer(self.notice if first_warning else None)
                elif isinstance(event, Message) and first_warning:
                    await event.answer(self.notice)
            except Exception:
                pass
            self._prune(now)
            return None
        dq.append(now)
        self._prune(now)
        return await handler(event, data)
