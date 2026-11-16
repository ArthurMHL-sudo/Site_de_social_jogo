"""
Servidor do site (Flask + SQLite).

Arrancar:  python main.py        (NÃO usar uvicorn: isto é Flask, não FastAPI)
Abrir:     http://127.0.0.1:8765/
"""

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager

from flask import Flask, jsonify, request, send_from_directory, make_response

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "toca.db")
SCHEMA = os.path.join(BASE, "schema.sql")

COOKIE = "toca_session"
SESSION_SECONDS = 30 * 24 * 60 * 60

app = Flask(__name__)


# =========================
# BASE DE DADOS
# =========================

@contextmanager
def db():
    """Abre uma ligação SQLite e garante commit, rollback e fecho."""
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def init_db():
    """Cria as tabelas que faltarem, sem apagar os dados existentes."""
    if not os.path.isfile(SCHEMA):
        raise FileNotFoundError(f"Não encontrei o ficheiro: {SCHEMA}")

    with open(SCHEMA, encoding="utf-8") as f:
        schema_sql = f.read()

    with db() as con:
        con.executescript(schema_sql)
        # Limpa sessões expiradas
        con.execute(
            "DELETE FROM sessions WHERE created < ?",
            (time.time() - SESSION_SECONDS,)
        )


# =========================
# RESPOSTAS E PASSWORDS
# =========================

def err(msg, status=400):
    return jsonify({"error": msg}), status


def hash_pw(pw: str) -> str:
    salt = secrets.token_bytes(16)
    hashed = hashlib.scrypt(
        pw.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1
    )
    return salt.hex() + "$" + hashed.hex()


def check_pw(pw: str, stored: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split("$", 1)
        calculated = hashlib.scrypt(
            pw.encode("utf-8"),
            salt=bytes.fromhex(salt_hex),
            n=2**14,
            r=8,
            p=1
        )
        return hmac.compare_digest(calculated.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# =========================
# SESSÕES
# =========================

def current_user():
    token = request.cookies.get(COOKIE)
    if not token:
        return None

    with db() as con:
        return con.execute(
            """
            SELECT u.id, u.username
            FROM sessions AS s
            JOIN users AS u ON u.id = s.user_id
            WHERE s.token = ? AND s.created > ?
            """,
            (token_hash(token), time.time() - SESSION_SECONDS)
        ).fetchone()


def start_session(user_id: int, username: str):
    token = secrets.token_urlsafe(32)

    with db() as con:
        con.execute(
            """
            INSERT INTO sessions (token, user_id, created)
            VALUES (?, ?, ?)
            """,
            (token_hash(token), user_id, time.time())
        )

    response = make_response(jsonify({"username": username}))
    response.set_cookie(
        COOKIE,
        token,
        max_age=SESSION_SECONDS,
        httponly=True,
        secure=False,  # Para desenvolvimento local em HTTP. Em HTTPS, usar True.
        samesite="Lax",
        path="/"
    )
    return response


def get_creds():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None, None

    username = data.get("username", "")
    password = data.get("password", "")
    if not isinstance(username, str) or not isinstance(password, str):
        return None, None

    return username, password


# =========================
# REGISTO E LOGIN
# =========================

@app.route("/api/register", methods=["POST"])
def register():
    username, password = get_creds()
    if username is None:
        return err("Dados inválidos. Envia username e password em JSON.")

    name = username.strip()
    if not re.fullmatch(r"[\w .-]{3,30}", name):
        return err(
            "O nome deve ter 3 a 30 caracteres "
            "(letras, números, espaço, . _ -)."
        )

    if len(password) < 6:
        return err("A palavra-passe deve ter pelo menos 6 caracteres.")

    try:
        with db() as con:
            cursor = con.execute(
                """
                INSERT INTO users (username, ukey, pw, created)
                VALUES (?, ?, ?, ?)
                """,
                (name, name.lower(), hash_pw(password), time.time())
            )
            user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        return err("Esse nome já está em uso.", 409)

    return start_session(user_id, name)


@app.route("/api/login", methods=["POST"])
def login():
    username, password = get_creds()
    if username is None:
        return err("Dados inválidos. Envia username e password em JSON.")

    with db() as con:
        user = con.execute(
            "SELECT id, username, pw FROM users WHERE ukey = ?",
            (username.strip().lower(),)
        ).fetchone()

    if not user or not check_pw(password, user["pw"]):
        return err("Nome ou palavra-passe incorretos.", 401)

    return start_session(user["id"], user["username"])


# =========================
# LOGOUT E UTILIZADOR ATUAL
# =========================

@app.route("/api/logout", methods=["POST"])
def logout():
    token = request.cookies.get(COOKIE)
    if token:
        with db() as con:
            con.execute(
                "DELETE FROM sessions WHERE token = ?",
                (token_hash(token),)
            )

    response = make_response(jsonify({"ok": True}))
    response.delete_cookie(
        COOKIE,
        path="/",
        httponly=True,
        samesite="Lax"
    )
    return response


@app.route("/api/me", methods=["GET"])
def me():
    user = current_user()
    return jsonify({"username": user["username"] if user else None})


# =========================
# PERFIL E HISTÓRICO
# =========================

@app.route("/api/profile", methods=["GET"])
def profile():
    user = current_user()
    if not user:
        return err("Inicia sessão primeiro.", 401)

    with db() as con:
        rows = con.execute(
            """
            SELECT id, title, url, thumbnail, site, uploader,
                   duration, kind, height, ext, created
            FROM history
            WHERE user_id = ?
            ORDER BY created DESC
            """,
            (user["id"],)
        ).fetchall()

    return jsonify({
        "username": user["username"],
        "items": [dict(row) for row in rows]
    })


# =========================
# ERROS (sempre em JSON, para o site mostrar a mensagem)
# =========================

@app.errorhandler(404)
def not_found(_e):
    return err("Não encontrado.", 404)


@app.errorhandler(405)
def not_allowed(_e):
    return err("Método não permitido.", 405)


@app.errorhandler(500)
def server_error(_e):
    return err("Erro interno do servidor.", 500)


# =========================
# FICHEIROS DO SITE
# =========================

@app.route("/", methods=["GET"])
def index():
    return send_from_directory(BASE, "index.html")


@app.route("/style.css", methods=["GET"])
def css():
    return send_from_directory(BASE, "style.css")


@app.route("/dragao.png", methods=["GET"])
def dragao():
    return send_from_directory(BASE, "dragao.png")


# =========================
# ARRANQUE
# =========================

# Cria as tabelas sempre que o módulo é carregado (python main.py,
# flask run, waitress, gunicorn...), não só quando corre como script.
init_db()

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=8765,
        debug=True
    )
