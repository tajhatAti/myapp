# 🚀 Render Free Tier-এ Data Reset হওয়ার সমাধান

## সমস্যা কী?
Render Free Tier-এ **ephemeral filesystem** আছে — প্রতিবার redeploy/restart-এ `database.db` (SQLite) মুছে যায়।

## ✅ স্থায়ী সমাধান (১০০% ফ্রি, কোনো কার্ড লাগবে না)

### Step 1: Supabase Free Account খুলুন (PostgreSQL Database)
1. https://supabase.com/dashboard/sign-up এ গিয়ে সাইন আপ করুন (GitHub দিয়ে করা সহজ)
2. **New Project** ক্লিক করুন
3. Project name দিন, password তৈরি করুন (এটি সংরক্ষণ করুন!), region পছন্দ করুন (Singapore কাছের, fastest)
4. **Create new project** ক্লিক করুন (1-2 মিনিট লাগবে)

### Step 2: Database Connection URL নিন
1. Project তৈরি হলে: **Project Settings** (left sidebar-এ ⚙️) → **Database**
2. **Connection String** section এ যান
3. **URI** রেডিও বাটন সিলেক্ট করুন
4. Connection string টি কপি করুন — এমন দেখাবে:
   ```
   postgresql://postgres:[YOUR-PASSWORD]@db.xxx.supabase.co:5432/postgres
   ```
5. `[YOUR-PASSWORD]` এর জায়গায় আপনার সেট করা password বসিয়ে দিন

### Step 3: Render-এ Environment Variable সেট করুন
1. আপনার Render Dashboard-এ যান → আপনার service ক্লিক
2. **Environment** ট্যাবে যান
3. **Add Environment Variable** এ ক্লিক করুন
4. Key: `DATABASE_URL`, Value: আপনার Supabase connection string (Step 2 থেকে)
5. **Save Changes**

### Step 4: (Optional) Brevo Email সেটাপ যদি করতে চান
আরো ৩টি ENV var যোগ করুন:
- `BREVO_API_KEY` = Brevo (formerly Sendinblue) free account-এর API key
- `SENDER_EMAIL` = আপনার verified sender email
- `SENDER_NAME` = Ahad Co (বা আপনার নাম)

### Step 5: Redeploy
- Render-এ **Manual Deploy** → **Deploy latest commit** দিন

সবশেষ! 🎉 এখন প্রতিবার deploy-এ data থায়ী থাকবে।

## 🧪 Local-এ কীভাবে চালাবেন?

### SQLite দিয়ে (default):
```bash
pip install -r requirements.txt
uvicorn app:app --reload
```
Database automatically `./database.db` তৈরি হবে।

### PostgreSQL দিয়ে (production-mimic):
```bash
export DATABASE_URL="postgresql://postgres:password@localhost:5432/mydb"
uvicorn app:app --reload
```

## অন্যান্য Free Options (No Card Required)
| Provider | Database | Free Tier | Notes |
|----------|----------|-----------|-------|
| **Supabase** | PostgreSQL | 500 MB | Recommended, easy |
| **Neon.tech** | PostgreSQL | 512 MB, 3 projects | Serverless, fast |
| **Turso** | SQLite-compatible | 9 GB, 1B reads | SQLite-native, fastest |
| **MongoDB Atlas** | MongoDB | 512 MB | SQL-এর জন্য না, NoSQL |
| **Firebase Firestore** | Document DB | 1 GB | NoSQL only |
| **Google Sheets** | Spreadsheet | - | Complex, slow |

## Technical Details (for developers)
- `db.py` automatically detects SQLite vs PostgreSQL via `DATABASE_URL` env var
- All SQL queries use `?` placeholder (sqlite style); db layer auto-translates to `%s` for Postgres
- Tables auto-created on first launch via `CREATE TABLE IF NOT EXISTS`
- Foreign keys + CASCADE deletes work on both backends
