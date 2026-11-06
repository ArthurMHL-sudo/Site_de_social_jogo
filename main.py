"""Servidor do site (FastAPI + SQLite).
Arrancar:  uvicorn main:app --reload
"""
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "toca.db")
SCHEMA = os.path.join(BASE, "schema.sql")
COOKIE = "toca_session"
SESSION_SECONDS = 30 * 24 * 3600

app = FastAPI()


def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con


@app.on_event("startup")
def init_db():
    with open(SCHEMA, encoding="utf-8") as f, db() as con:
        con.executescript(f.read())


def err(msg, status=400):
    return JSONResponse({"error": msg}, status_code=status)


def hash_pw(pw: str) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1)
    return salt.hex() + "$" + h.hex()


def check_pw(pw: str, stored: str) -> bool:
    try:
        salt, h = stored.split("$")
        new = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1)
        return hmac.compare_digest(new.hex(), h)
    except ValueError:
        return False


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def current_user(request: Request):
    token = request.cookies.get(COOKIE)
    if not token:
        return None
    with db() as con:
        return con.execute(
            "SELECT u.id, u.username FROM sessions s JOIN users u ON u.id = s.user_id "
            "WHERE s.token = ? AND s.created > ?",
            (token_hash(token), time.time() - SESSION_SECONDS),
        ).fetchone()


class Creds(BaseModel):
    username: str
    password: str


def start_session(user_id: int, username: str):
    token = secrets.token_urlsafe(32)
    with db() as con:
        con.execute(
            "INSERT INTO sessions (token, user_id, created) VALUES (?, ?, ?)",
            (token_hash(token), user_id, time.time()),
        )
    resp = JSONResponse({"username": username})
    resp.set_cookie(COOKIE, token, max_age=SESSION_SECONDS, httponly=True, samesite="lax")
    return resp


@app.post("/api/register")
def register(c: Creds):
    name = c.username.strip()
    if not re.fullmatch(r"[\w .-]{3,30}", name):
        return err("O nome deve ter 3 a 30 caracteres (letras, números, espaço, . _ -).")
    if len(c.password) < 6:
        return err("A palavra-passe deve ter pelo menos 6 caracteres.")
    try:
        with db() as con:
            cur = con.execute(
                "INSERT INTO users (username, ukey, pw, created) VALUES (?, ?, ?, ?)",
                (name, name.lower(), hash_pw(c.password), time.time()),
            )
            uid = cur.lastrowid
    except sqlite3.IntegrityError:
        return err("Esse nome já está em uso.", 409)
    return start_session(uid, name)


@app.post("/api/login")
def login(c: Creds):
    with db() as con:
        u = con.execute("SELECT * FROM users WHERE ukey = ?", (c.username.strip().lower(),)).fetchone()
    if not u or not check_pw(c.password, u["pw"]):
        return err("Nome ou palavra-passe incorretos.", 401)
    return start_session(u["id"], u["username"])


@app.post("/api/logout")
def logout(request: Request):
    token = request.cookies.get(COOKIE)
    if token:
        with db() as con:
            con.execute("DELETE FROM sessions WHERE token = ?", (token_hash(token),))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE)
    return resp


@app.get("/api/me")
def me(request: Request):
    u = current_user(request)
    return {"username": u["username"] if u else None}


@app.get("/api/museum")
def museum(request: Request):
    u = current_user(request)
    if not u:
        return err("Inicia sessão primeiro.", 401)
    with db() as con:
        rows = con.execute(
            "SELECT id, title, url, thumbnail, site, uploader, duration, kind, height, ext, created "
            "FROM history WHERE user_id = ? ORDER BY created DESC",
            (u["id"],),
        ).fetchall()
    return {"items": [dict(r) for r in rows]}


# Só estes ficheiros são públicos (nunca .git, toca.db, schema.sql...)
@app.get("/")
def index():
    return FileResponse(os.path.join(BASE, "index.html"))


@app.get("/style.css")
def css():
    return FileResponse(os.path.join(BASE, "style.css"), media_type="text/css")
