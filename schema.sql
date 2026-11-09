-- Esquema SQLite usado pelo main.py (criado automaticamente no arranque)
CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    ukey     TEXT NOT NULL UNIQUE,   -- nome em minúsculas (Ana e ana são a mesma conta)
    pw       TEXT NOT NULL,          -- só o hash scrypt, nunca a palavra-passe
    created  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token   TEXT PRIMARY KEY,        -- hash do token do cookie
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS history (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title     TEXT,
    url       TEXT,
    thumbnail TEXT,
    site      TEXT,
    uploader  TEXT,
    duration  INTEGER,
    kind      TEXT NOT NULL DEFAULT 'video',
    height    INTEGER,
    ext       TEXT,
    created   REAL NOT NULL DEFAULT (strftime('%s','now'))
);
CREATE INDEX IF NOT EXISTS idx_history_user ON history(user_id, created);
