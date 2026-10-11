# 🛡️ TELELINK — מנוע אימות אמינות לטלגרם

בוט טלגרם (aiogram 3) שבודק מוכרים, ערוצים וקבוצות מול רשימת זהב, רשימה שחורה גלובלית ומסד נתונים פנימי,
ומאפשר לקהילה לדווח על נוכלים עם ראיות. רץ על **Railway** מול **Neon (Postgres)**.

## ✨ יכולות עיקריות
| תחום | מה יש |
|---|---|
| בדיקה | דוח אימות עם מדד אמינות, אזהרת התחזות לשותפי זהב, והמלצות פעולה |
| דיווח | זרימת 3 שלבים, עד 10 תמונות ראיה, עדכון אוטומטי למדווח כשהתיק נסגר |
| ניהול | פאנל מנהלים, הרשאות ראשי/משני, יומן ביקורת, עורך כפתורים וקישורים, Broadcast |
| חוויית משתמש | `/help` `/check` `/tips` `/faq` `/id`, מרכז בטיחות עם 6 מדריכים, שאלות נפוצות |
| יציבות | שיקוף קבצים ל-Postgres (שורד Redeploy), Throttle נגד ספאם, חיבור יציב ל-Neon |

## ⌨️ פקודות
- `/start` — תפריט ראשי
- `/check @username` — בדיקה מיידית (או `/check` לבדיקה אינטראקטיבית)
- `/tips` — מרכז הבטיחות · `/faq` — שאלות נפוצות · `/help` — עזרה
- `/id` — מזהה הטלגרם שלכם
- `/admin` — פאנל ניהול · `/status` — לוח בקרה (מנהלים בלבד)

## 🚀 פריסה ב-Railway + Neon
1. צרו פרויקט ב-Neon והעתיקו את מחרוזת החיבור (Connect) — מומלץ גרסת ה-`pooler`.
2. ב-Railway: *New Project → Deploy from GitHub repo*. הקובץ `railway.json` מגדיר Docker ובדיקת בריאות ב-`/health`.
3. הגדירו Variables (ראו `.env.example`):

| משתנה | חובה | הסבר |
|---|---|---|
| `BOT_TOKEN` | ✅ | הטוקן מ-@BotFather |
| `DATABASE_URL` | ✅ | מחרוזת החיבור של Neon. הפרמטר `channel_binding` מטופל אוטומטית |
| `ADMIN_IDS` | מומלץ | מזהי מנהלים, מופרדים בפסיק |
| `SUPER_ADMIN_IDS` | אופציונלי | מנהלים ראשיים |
| `MAIN_CHANNEL_LINK`, `HELP_SUPPORT_LINK` | אופציונלי | קישורים בתפריט |

4. Deploy. בלוגים תראו `Postgres connection OK`. שלחו `/status` מחשבון מנהל לבדיקה מהירה.

## 💾 שמירת נתונים
רשימות שחורה/זהב, דיווחים וסטטיסטיקות נשמרים ב-Postgres. קבצי `users / buttons / custom_buttons / admins_extra / audit_log`
נכתבים לדיסק המקומי **וגם** משוקפים ל-Postgres (`kv_store`, מפתחות `files/*`), ומשוחזרים אוטומטית בעליית הבוט.
הדיסק ב-Railway זמני — בלי השיקוף הם היו נמחקים בכל פריסה.

## 🔐 אבטחה — חשוב
- בקובץ `config.py` יש טוקן ברירת-מחדל קשיח. **כל טוקן שנכנס ל-Git נחשב חשוף**: בצעו `/revoke` ב-@BotFather,
  והגדירו את החדש רק כמשתנה סביבה `BOT_TOKEN`.
- אל תעלו קבצי `.env` ל-Git (מוגדר ב-`.gitignore`).

## 🧪 בדיקה מקומית
```bash
pip install -r requirements.txt
cp .env.example .env   # ערכו את הערכים
python main.py
```

## 🗂️ מבנה הפרויקט
`main.py` הפעלה ו-lifecycle · `handlers.py` הלוגיקה המרכזית · `extras.py` פקודות, מרכז בטיחות ו-Throttle ·
`db_local.py` שכבת Postgres · `keyboards.py` מקלדות · `config.py` הגדרות · `Dockerfile` / `railway.json` תשתית.
