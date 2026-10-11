import json
import os

def sanitize_database():
    # לפי ה-DIR שלך, זה שם הקובץ הנכון
    target_file = "db.json" 
    
    if not os.path.exists(target_file):
        print(f"❌ הקובץ '{target_file}' לא נמצא בתיקייה הראשית.")
        print("🔍 מנסה לחפש בתוך תיקיית data...")
        target_file = os.path.join("data", "db.json")
        
    if not os.path.exists(target_file):
        print("❌ הקובץ לא נמצא גם בתיקיית data. וודא שזה השם הנכון.")
        return

    print(f"✅ נמצא קובץ: {target_file}. מתחיל ניקוי...")

    try:
        with open(target_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # ב-JSON שלך המידע נמצא תחת המפתח "users"
        users = data.get("users", {})
        cleaned_users = {}

        for key, info in users.items():
            # ניקוי המפתח (הפיכה לאותיות קטנות, הסרת רווחים וזבל)
            new_key = key.strip().lower().replace("https://", "").replace("t.me/", "").replace("@", "")
            if "\n" in new_key:
                new_key = new_key.split("\n")[-1].strip()
            
            cleaned_users[new_key] = info

        data["users"] = cleaned_users

        # יצירת גיבוי
        backup = target_file + ".bak"
        if os.path.exists(backup): os.remove(backup)
        os.rename(target_file, backup)

        with open(target_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        print(f"🚀 סיימתי! {len(cleaned_users)} רשומות נוקו בהצלחה.")
        
    except Exception as e:
        print(f"❌ תקלה בזמן התיקון: {e}")

if __name__ == "__main__":
    sanitize_database()