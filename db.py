"""
Database compatibility layer.
- Local dev:  SQLite (default, DB_PATH or ./database.db)
- Production: PostgreSQL via DATABASE_URL env (Supabase / Neon / Render PG / etc.)

Provides a connection + cursor that mimic the sqlite3 API so existing app.py code works
with minimal changes. Placeholders can be written as '?' (sqlite style) everywhere —
this layer auto-translates to '%s' for Postgres.
"""
import os
import sqlite3
import re
from pathlib import Path
from contextlib import contextmanager
from collections import OrderedDict

DB_PATH = Path(os.getenv("DB_PATH", str(Path(__file__).resolve().parent / "database.db")))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

USE_POSTGRES = DATABASE_URL.startswith("postgresql://")

_pg_conn = None


def _get_pg_raw():
    global _pg_conn
    try:
        import psycopg2
        import psycopg2.extras
    except ImportError:
        raise RuntimeError("psycopg2-binary is required for PostgreSQL. pip install psycopg2-binary")
    if _pg_conn is None or _pg_conn.closed:
        _pg_conn = psycopg2.connect(DATABASE_URL)
        _pg_conn.autocommit = False
    return _pg_conn


def _translate_sql(sql: str) -> str:
    """Translate sqlite '?' placeholders to postgres '%s' (only outside string literals)."""
    if not USE_POSTGRES:
        return sql
    out = []
    i = 0
    n = len(sql)
    while i < n:
        ch = sql[i]
        if ch == "'":
            # Skip string literal
            out.append(ch)
            i += 1
            while i < n:
                out.append(sql[i])
                if sql[i] == "'":
                    if i + 1 < n and sql[i+1] == "'":
                        out.append(sql[i+1])
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
        elif ch == "?":
            out.append("%s")
            i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


class _CompatCursor:
    """Wraps a psycopg2 cursor to emulate sqlite3.Cursor (lastrowid, row_factory-like dicts)."""
    def __init__(self, pg_cursor, conn):
        import psycopg2.extras
        if not isinstance(pg_cursor, psycopg2.extras.RealDictCursor):
            # Upgrade to RealDictCursor via a new cursor from conn
            pg_cursor.close()
            pg_cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        self._c = pg_cursor
        self._conn = conn
        self.lastrowid = None
        self.rowcount = -1
        self._results = None
        self._idx = 0

    def execute(self, sql, params=None):
        sql_t = _translate_sql(sql)
        # Detect if this is an INSERT with RETURNING already; if it's a plain INSERT
        # into a table with id serial, append RETURNING id so we can get lastrowid.
        is_insert = False
        if not sql_t.strip().upper().startswith("INSERT"):
            is_insert = False
        elif "RETURNING" not in sql_t.upper():
            # Only add RETURNING id for simple single-table INSERTs that don't already have it
            is_insert = True
            sql_t = sql_t.rstrip().rstrip(";") + " RETURNING id"
        try:
            self._c.execute(sql_t, params or ())
        except Exception:
            self._conn.rollback()
            raise
        self.rowcount = self._c.rowcount
        if is_insert:
            try:
                row = self._c.fetchone()
                self.lastrowid = row["id"] if row else None
                self._results = None
            except Exception:
                self.lastrowid = None
                self._results = None
        else:
            self._results = None
            self.lastrowid = None
        return self

    def executemany(self, sql, params_list):
        sql_t = _translate_sql(sql)
        try:
            self._c.executemany(sql_t, params_list)
        except Exception:
            self._conn.rollback()
            raise
        return self

    def fetchone(self):
        if self._results is None:
            self._results = self._c.fetchall()
            self._idx = 0
        if self._idx >= len(self._results):
            return None
        r = self._results[self._idx]
        self._idx += 1
        return _DictRow(r)

    def fetchall(self):
        if self._results is None:
            self._results = self._c.fetchall()
            self._idx = len(self._results)
        return [_DictRow(r) for r in self._results]

    @property
    def description(self):
        return self._c.description

    @property
    def arraysize(self):
        return self._c.arraysize

    def close(self):
        try: self._c.close()
        except Exception: pass

    def __iter__(self):
        return iter(self.fetchall())


class _DictRow:
    """Emulate sqlite3.Row (indexable by key AND column index)."""
    def __init__(self, d):
        object.__setattr__(self, "_d", dict(d) if d else {})
        object.__setattr__(self, "_keys", list(self._d.keys()))

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._d[self._keys[key]]
        return self._d[key]

    def __setitem__(self, key, val):
        self._d[key] = val

    def __contains__(self, key):
        return key in self._d

    def keys(self):
        return self._keys

    def __getattr__(self, name):
        try:
            return self._d[name]
        except KeyError:
            raise AttributeError(name)

    def __iter__(self):
        return iter(self._keys)

    def __len__(self):
        return len(self._keys)

    def __eq__(self, other):
        if isinstance(other, _DictRow):
            return self._d == other._d
        return self._d == other

    def __bool__(self):
        return True

    def __repr__(self):
        return f"_DictRow({self._d!r})"


class _CompatConnection:
    """Wraps a psycopg2 connection to emulate sqlite3.Connection."""
    def __init__(self, pg_conn):
        self._c = pg_conn
        self.row_factory = None  # accepted for compatibility
        self.autocommit = False

    def cursor(self):
        import psycopg2.extras
        c = self._c.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        return _CompatCursor(c, self._c)

    def execute(self, sql, params=None):
        cur = self.cursor()
        cur.execute(sql, params)
        return cur

    def commit(self):
        try: self._c.commit()
        except Exception: pass

    def rollback(self):
        try: self._c.rollback()
        except Exception: pass

    def close(self):
        try: self._c.close()
        except Exception: pass

    # Context manager support
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            self.commit()
        else:
            self.rollback()
        self.close()
        return False


def is_postgres():
    return USE_POSTGRES


def get_db_connection():
    """Return a sqlite3-compatible connection object for either SQLite or Postgres."""
    if USE_POSTGRES:
        return _CompatConnection(_get_pg_raw())
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def create_tables():
    """Create all tables. Works for both SQLite and Postgres."""
    conn = get_db_connection()
    cur = conn.cursor()

    def auto_pk():
        return "SERIAL PRIMARY KEY" if USE_POSTGRES else "INTEGER PRIMARY KEY AUTOINCREMENT"

    tables = [
        f"""CREATE TABLE IF NOT EXISTS users (
            id {auto_pk()},
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            otp TEXT,
            otp_created_at TEXT,
            is_verified INTEGER NOT NULL DEFAULT 0,
            reset_otp TEXT,
            reset_otp_created_at TEXT,
            reset_verified INTEGER NOT NULL DEFAULT 0,
            role TEXT NOT NULL DEFAULT 'user',
            phone TEXT,
            custom_code TEXT,
            links TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )""",
        f"""CREATE TABLE IF NOT EXISTS sessions (
            id {auto_pk()},
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token TEXT NOT NULL UNIQUE,
            device_info TEXT,
            ip_address TEXT,
            created_at TEXT NOT NULL,
            last_seen TEXT NOT NULL
        )""",
        f"""CREATE TABLE IF NOT EXISTS vault_entries (
            id {auto_pk()},
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            type TEXT NOT NULL,
            label TEXT NOT NULL,
            value TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )""",
        f"""CREATE TABLE IF NOT EXISTS user_2fa (
            id {auto_pk()},
            user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
            secret TEXT,
            is_enabled INTEGER NOT NULL DEFAULT 0,
            backup_codes TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )""",
        f"""CREATE TABLE IF NOT EXISTS login_history (
            id {auto_pk()},
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            ip_address TEXT,
            device_info TEXT,
            location TEXT,
            success INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )""",
        f"""CREATE TABLE IF NOT EXISTS user_preferences (
            id {auto_pk()},
            user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
            theme TEXT DEFAULT 'dark',
            language TEXT DEFAULT 'en',
            timezone TEXT DEFAULT 'UTC',
            notifications_enabled INTEGER DEFAULT 1,
            email_notifications INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )""",
        f"""CREATE TABLE IF NOT EXISTS user_notes (
            id {auto_pk()},
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            color TEXT DEFAULT '#7C6CF6',
            pinned INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )""",
        f"""CREATE TABLE IF NOT EXISTS user_bookmarks (
            id {auto_pk()},
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            url TEXT NOT NULL,
            description TEXT,
            category TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )""",
        f"""CREATE TABLE IF NOT EXISTS user_categories (
            id {auto_pk()},
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            icon TEXT DEFAULT '📁',
            color TEXT DEFAULT '#7C6CF6',
            created_at TEXT NOT NULL
        )""",
        f"""CREATE TABLE IF NOT EXISTS api_keys (
            id {auto_pk()},
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            key_hash TEXT NOT NULL,
            last_used TEXT,
            created_at TEXT NOT NULL
        )""",
        f"""CREATE TABLE IF NOT EXISTS activity_log (
            id {auto_pk()},
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            created_at TEXT NOT NULL
        )""",
        f"""CREATE TABLE IF NOT EXISTS notifications (
            id {auto_pk()},
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            type TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            is_read INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        )""",
    ]

    for stmt in tables:
        try:
            cur.execute(stmt)
        except Exception as e:
            # If table exists / minor schema drift, ignore
            pass

    # Try to add role column (idempotent)
    try:
        cur.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
    except Exception:
        pass

    conn.commit()
    conn.close()


# Initialize DB on import
create_tables()
