"""
keyboards.py — TELELINK Keyboard Builder Module v3.0
Production-grade: fully typed, validated, backward-compatible alias,
guards against bad Firebase data, consistent back-navigation,
and improved button grouping / UX copy.
"""

from typing import Any, Dict, List, Optional

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup
from aiogram.utils.keyboard import InlineKeyboardBuilder

from config import MAIN_CHANNEL_LINK

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
GEZA_BOT_LINK: str = "https://t.me/Geza_telelink_bot"

# ---------------------------------------------------------------------------
# Button label helper (kept as passthrough for backward compatibility)
# ---------------------------------------------------------------------------
def styled(text: str, primary: bool = True) -> str:
    """No-op passthrough — returns the label unchanged, no colour marker."""
    return text

# ---------------------------------------------------------------------------
# 1. Main menu
# ---------------------------------------------------------------------------

def main_menu_keyboard() -> InlineKeyboardMarkup:
    """Primary user-facing menu — 2-column layout optimised for mobile."""
    builder = InlineKeyboardBuilder()

    # Hero action — full width — blue (primary)
    builder.row(InlineKeyboardButton(text=styled("📦 קבוצות קנייה/מכירה", primary=True), callback_data="menu_groups"))

    # Primary actions — blue
    builder.row(
        InlineKeyboardButton(text=styled("🔍 בדוק מוכר", primary=True),   callback_data="menu_check_user"),
        InlineKeyboardButton(text=styled("🚨 דווח על נוכל", primary=True), callback_data="menu_report_user"),
    )

    # Secondary actions — regular
    builder.row(InlineKeyboardButton(text=styled("🛡️ טיפים לבטיחות ומניעת הונאות", primary=False), callback_data="menu_tips"))

    # Profile / rating — regular
    builder.row(InlineKeyboardButton(text=styled("💎 הפרופיל שלי ודירוג", primary=False), callback_data="menu_my_profile"))

    # ✅ Direct link to the main Geza bot — prominent, full-width — blue
    builder.row(
        InlineKeyboardButton(
            text=styled("🤖 עבור לבוט הגזע המרכזי ➜", primary=True),
            url=GEZA_BOT_LINK,
        )
    )

    # External channel link — regular
    builder.row(InlineKeyboardButton(text=styled("🔗 מעבר לערוץ הראשי", primary=False), url=MAIN_CHANNEL_LINK))

    return builder.as_markup()


# Backward-compatibility alias used in handlers.py and other modules
telelink_main_menu = main_menu_keyboard


# ---------------------------------------------------------------------------
# 2. Groups list (dynamic, from Firebase)
# ---------------------------------------------------------------------------

def groups_keyboard(groups: Any) -> InlineKeyboardMarkup:
    """
    Build a dynamic groups list keyboard from Firebase data.
    Accepts a dict {gid: {name, description, link}} or any falsy value.
    Invalid / missing links are rendered as non-clickable warning buttons.
    """
    builder = InlineKeyboardBuilder()

    if not groups or not isinstance(groups, dict):
        builder.row(InlineKeyboardButton(text="❌ אין קבוצות זמינות כרגע", callback_data="none"))
    else:
        for gid, info in groups.items():
            if not isinstance(info, dict):
                continue

            name = (info.get("name") or "קבוצה כללית").strip()
            desc = (info.get("description") or "").strip()
            link = (info.get("link") or "").strip()

            btn_text = f"🔹 {name}" + (f" ({desc})" if desc else "")

            if link and str(link).startswith("http"):
                builder.row(InlineKeyboardButton(text=styled(btn_text, primary=True), url=str(link)))
            else:
                builder.row(
                    InlineKeyboardButton(
                        text=f"⚠️ {name} (קישור חסר)",
                        callback_data="link_error",
                    )
                )

    builder.row(InlineKeyboardButton(text=styled("🔙 חזרה לתפריט הראשי", primary=False), callback_data="start"))
    return builder.as_markup()


def members_only_keyboard() -> InlineKeyboardMarkup:
    """Prompt non-members to verify their membership."""
    builder = InlineKeyboardBuilder()
    builder.row(
        InlineKeyboardButton(
            text=styled("✅ אימות חברות ופתיחת קישורים", primary=True),
            callback_data="check_membership",
        )
    )
    builder.row(InlineKeyboardButton(text=styled("🔙 חזרה", primary=False), callback_data="start"))
    return builder.as_markup()


# ---------------------------------------------------------------------------
# 3. Report system
# ---------------------------------------------------------------------------

def confirm_report_keyboard(target_data: str) -> InlineKeyboardMarkup:
    """Confirm / cancel before submitting a scam report."""
    builder = InlineKeyboardBuilder()
    builder.row(
        InlineKeyboardButton(
            text=styled("✅ אישור ושליחה", primary=True),
            callback_data=f"confirm_report:{target_data}",
        ),
        InlineKeyboardButton(text=styled("❌ ביטול", primary=False), callback_data="cancel_report"),
    )
    return builder.as_markup()


def quick_report_keyboard(username: str) -> InlineKeyboardMarkup:
    """Admin quick-action keyboard shown alongside an incoming report."""
    builder = InlineKeyboardBuilder()
    builder.row(
        InlineKeyboardButton(
            text=styled("🚫 חסום והעבר לרשימה שחורה", primary=True),
            callback_data=f"auto_blacklist:{username}",
        )
    )
    builder.row(InlineKeyboardButton(text=styled("🗑️ מחק דיווח", primary=False), callback_data="delete_report"))
    return builder.as_markup()


# ---------------------------------------------------------------------------
# 4. Admin panel
# ---------------------------------------------------------------------------

def admin_main_keyboard(is_super: bool = True) -> InlineKeyboardMarkup:
    """
    Full admin command-centre keyboard — 2-column grid.
    `is_super` gates the permission-management row: only a super admin
    ("מנהל ראשי") can see/open it. Regular ("משני") admins still see and use
    every other row exactly as before — nothing is removed for them.
    """
    builder = InlineKeyboardBuilder()

    builder.row(
        InlineKeyboardButton(text=styled("👥 ניהול רשימות", primary=True),  callback_data="admin_lists"),
        InlineKeyboardButton(text=styled("🔗 ניהול קבוצות", primary=True),  callback_data="admin_groups"),
    )
    # NEW: advanced search/filter across whitelist & blacklist
    builder.row(
        InlineKeyboardButton(text=styled("🔎 חיפוש וסינון מתקדם", primary=True), callback_data="admin_search"),
    )
    builder.row(
        InlineKeyboardButton(text=styled("📝 עריכת טקסטים", primary=False),  callback_data="admin_texts"),
        InlineKeyboardButton(text=styled("📊 סטטיסטיקות", primary=False),    callback_data="admin_stats"),
    )
    builder.row(
        InlineKeyboardButton(
            text=styled("📣 שליחת הודעה גלובלית (Broadcast)", primary=True),
            callback_data="admin_broadcast",
        )
    )
    builder.row(
        InlineKeyboardButton(text=styled("🧾 לוגים", primary=False),             callback_data="admin_logs"),
        InlineKeyboardButton(text=styled("📜 היסטוריית שינויים", primary=False), callback_data="admin_audit_trail"),
    )
    builder.row(
        InlineKeyboardButton(text=styled("🔧 קישורים דינמיים", primary=False), callback_data="admin_dynamic_links"),
    )
    # NEW: permission-level management — super admins only
    if is_super:
        builder.row(
            InlineKeyboardButton(text=styled("👑 ניהול הרשאות מנהלים", primary=True), callback_data="admin_permissions"),
        )
    builder.row(InlineKeyboardButton(text=styled("🏠 חזרה לממשק משתמש", primary=False), callback_data="start"))
    return builder.as_markup()


def lists_keyboard() -> InlineKeyboardMarkup:
    """Choose whitelist or blacklist to manage."""
    builder = InlineKeyboardBuilder()
    builder.row(
        InlineKeyboardButton(text=styled("✅ Whitelist (אמינים)", primary=True),  callback_data="list_whitelist"),
        InlineKeyboardButton(text=styled("⚠️ Blacklist (נוכלים)", primary=True), callback_data="list_blacklist"),
    )
    builder.row(InlineKeyboardButton(text=styled("🔎 חיפוש וסינון מתקדם", primary=False), callback_data="admin_search"))
    builder.row(InlineKeyboardButton(text=styled("🔙 חזרה לתפריט מנהל", primary=False), callback_data="admin_back"))
    return builder.as_markup()


# ---------------------------------------------------------------------------
# 9. NEW — Advanced search & filter (whitelist/blacklist)
# ---------------------------------------------------------------------------

def search_filter_keyboard() -> InlineKeyboardMarkup:
    """Entry point for the advanced search/filter tool."""
    builder = InlineKeyboardBuilder()
    builder.row(InlineKeyboardButton(text=styled("🔤 חיפוש לפי שם משתמש", primary=True), callback_data="search_by_username"))
    builder.row(
        InlineKeyboardButton(text=styled("✅ סנן: Whitelist בלבד", primary=False), callback_data="search_filter_whitelist"),
        InlineKeyboardButton(text=styled("⚠️ סנן: Blacklist בלבד", primary=False), callback_data="search_filter_blacklist"),
    )
    builder.row(InlineKeyboardButton(text=styled("📅 סנן לפי טווח תאריכים", primary=False), callback_data="search_filter_dates"))
    builder.row(InlineKeyboardButton(text=styled("📋 הצג הכול", primary=False), callback_data="search_filter_all"))
    builder.row(InlineKeyboardButton(text=styled("🔙 חזרה לתפריט מנהל", primary=False), callback_data="admin_back"))
    return builder.as_markup()


def search_result_item_keyboard(entity: str) -> InlineKeyboardMarkup:
    """Attached to each search result — jump straight into edit/history for that record."""
    builder = InlineKeyboardBuilder()
    builder.row(
        InlineKeyboardButton(text=styled("✏️ ערוך", primary=True), callback_data=f"quick_edit:{entity}"),
        InlineKeyboardButton(text=styled("📜 היסטוריה", primary=False), callback_data=f"audit_for:{entity}"),
    )
    return builder.as_markup()


# ---------------------------------------------------------------------------
# 10. NEW — Admin permission-level management (super admins only)
# ---------------------------------------------------------------------------

def permissions_keyboard(admins: List[Dict[str, Any]]) -> InlineKeyboardMarkup:
    """
    List current admins with their level, plus controls to promote/demote,
    add a new regular admin, or remove one. `admins` is a list of
    {"id": int, "name": str, "level": "super"|"regular"}.
    """
    builder = InlineKeyboardBuilder()
    for admin in admins:
        if not isinstance(admin, dict):
            continue
        badge = "👑" if admin.get("level") == "super" else "🛠️"
        label = f"{badge} {admin.get('name') or admin.get('id')}"
        builder.row(InlineKeyboardButton(text=styled(label, primary=(admin.get("level") == "super")), callback_data=f"perm_view:{admin.get('id')}"))
    builder.row(InlineKeyboardButton(text=styled("➕ הוספת מנהל משני", primary=True), callback_data="perm_add_admin"))
    builder.row(InlineKeyboardButton(text=styled("🔙 חזרה לתפריט מנהל", primary=False), callback_data="admin_back"))
    return builder.as_markup()


def permission_action_keyboard(target_id: int, is_super: bool) -> InlineKeyboardMarkup:
    """Actions available for one specific admin entry."""
    builder = InlineKeyboardBuilder()
    if is_super:
        builder.row(InlineKeyboardButton(text=styled("⬇️ הורד לדרגת מנהל משני", primary=False), callback_data=f"perm_demote:{target_id}"))
    else:
        builder.row(InlineKeyboardButton(text=styled("⬆️ קדם לדרגת מנהל ראשי", primary=True), callback_data=f"perm_promote:{target_id}"))
        builder.row(InlineKeyboardButton(text=styled("🗑️ הסר הרשאת ניהול", primary=False), callback_data=f"perm_remove:{target_id}"))
    builder.row(InlineKeyboardButton(text=styled("🔙 חזרה לרשימת מנהלים", primary=False), callback_data="admin_permissions"))
    return builder.as_markup()


# ---------------------------------------------------------------------------
# 11. NEW — Audit trail viewer
# ---------------------------------------------------------------------------

def audit_trail_keyboard() -> InlineKeyboardMarkup:
    """Entry point for the audit-trail feature."""
    builder = InlineKeyboardBuilder()
    builder.row(InlineKeyboardButton(text=styled("🔍 חפש היסטוריה למשתמש ספציפי", primary=True), callback_data="audit_search_user"))
    builder.row(InlineKeyboardButton(text=styled("🕒 20 הפעולות האחרונות (כולן)", primary=False), callback_data="audit_recent_all"))
    builder.row(InlineKeyboardButton(text=styled("🔙 חזרה לתפריט מנהל", primary=False), callback_data="admin_back"))
    return builder.as_markup()


def back_to_admin_keyboard() -> InlineKeyboardMarkup:
    """Single back button — used after single-action admin operations."""
    builder = InlineKeyboardBuilder()
    builder.row(InlineKeyboardButton(text=styled("🔙 חזרה לתפריט מנהל", primary=False), callback_data="admin_back"))
    return builder.as_markup()


# ---------------------------------------------------------------------------
# 5. Dynamic links
# ---------------------------------------------------------------------------

def dynamic_links_keyboard(dynamic_links: List[Dict[str, Any]]) -> InlineKeyboardMarkup:
    """
    Build a keyboard from a list of {text, url} dicts.
    Only links with a valid http(s) URL are rendered as clickable buttons.
    """
    builder = InlineKeyboardBuilder()

    for link in dynamic_links:
        if not isinstance(link, dict):
            continue
        text = (link.get("text") or "🔗 קישור חיצוני").strip()
        url  = (link.get("url") or "").strip()
        if str(url).startswith("http"):
            builder.row(InlineKeyboardButton(text=styled(str(text), primary=True), url=str(url)))

    builder.row(InlineKeyboardButton(text=styled("🔙 חזרה", primary=False), callback_data="start"))
    return builder.as_markup()


# ---------------------------------------------------------------------------
# 6. User status (context-aware — report button only for untrusted users)
# ---------------------------------------------------------------------------

def user_status_keyboard(username: str, status: str) -> InlineKeyboardMarkup:
    """
    Post-lookup action keyboard.
    The 'report' button is suppressed when the user is already whitelisted.
    """
    builder = InlineKeyboardBuilder()

    if status != "whitelist":
        builder.row(
            InlineKeyboardButton(
                text=styled("🚨 דווח על משתמש זה למערכת", primary=True),
                callback_data="menu_report_user",
            )
        )

    builder.row(InlineKeyboardButton(text=styled("🔍 בדיקה חדשה", primary=False),        callback_data="menu_check_user"))
    builder.row(InlineKeyboardButton(text=styled("🔙 חזרה לתפריט הראשי", primary=False), callback_data="start"))
    return builder.as_markup()


# ---------------------------------------------------------------------------
# 7. Safety tips
# ---------------------------------------------------------------------------

def safety_tips_keyboard() -> InlineKeyboardMarkup:
    """Interactive safety tips navigation."""
    builder = InlineKeyboardBuilder()
    builder.row(InlineKeyboardButton(text=styled("📖 איך עובדת מערכת האמון?", primary=True),     callback_data="tips_trust_system"))
    builder.row(InlineKeyboardButton(text=styled("💸 איך להימנע מעקיצות בתשלום?", primary=True), callback_data="tips_payments"))
    builder.row(InlineKeyboardButton(text=styled("🔙 חזרה לתפריט הראשי", primary=False),          callback_data="start"))
    return builder.as_markup()


# ---------------------------------------------------------------------------
# 8. Geza bot redirect — reusable standalone button
# ---------------------------------------------------------------------------

def geza_redirect_keyboard() -> InlineKeyboardMarkup:
    """Standalone keyboard for redirecting users to the main Geza bot."""
    builder = InlineKeyboardBuilder()
    builder.row(
        InlineKeyboardButton(
            text=styled("🤖 עבור לבוט הגזע המרכזי ➜", primary=True),
            url=GEZA_BOT_LINK,
        )
    )
    builder.row(InlineKeyboardButton(text=styled("🔙 חזרה לתפריט הראשי", primary=False), callback_data="start"))
    return builder.as_markup()