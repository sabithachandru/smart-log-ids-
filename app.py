import base64
import binascii
import os
import re
import sqlite3
from functools import wraps

from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, abort, jsonify)
from werkzeug.security import generate_password_hash, check_password_hash

import model  # TF-IDF + Logistic Regression classifier

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024  # request limit (file is base64 encoded by the browser)
MAX_LOG_BYTES = 5 * 1024 * 1024  # real log file limit
XOR_KEY = 0x5A  # must match the key in templates/upload.html
XOR_TABLE = bytes(i ^ XOR_KEY for i in range(256))

# ---------------------------------------------------------------------------
# Database layer: MySQL when DB_HOST is set (XAMPP/WAMP or cloud), else SQLite
# ---------------------------------------------------------------------------
USE_MYSQL = bool(os.environ.get("DB_HOST"))
if USE_MYSQL:
    import mysql.connector
PH = "%s" if USE_MYSQL else "?"
SQLITE_PATH = os.environ.get("SQLITE_PATH", "database.db")


def get_db():
    if USE_MYSQL:
        opts = dict(
            host=os.environ["DB_HOST"],
            user=os.environ.get("DB_USER", "root"),
            password=os.environ.get("DB_PASSWORD", ""),
            database=os.environ.get("DB_NAME", "smart_log_ids"),
            port=int(os.environ.get("DB_PORT", "3306")),
            connection_timeout=10,
            charset="utf8mb4",
            collation="utf8mb4_general_ci",  # works on MySQL, MariaDB (XAMPP) and TiDB
        )
        # Cloud MySQL hosts (TiDB Cloud etc.) need SSL: set DB_SSL=true on Render
        if os.environ.get("DB_SSL", "").lower() in ("1", "true", "yes"):
            opts["ssl_ca"] = os.environ.get("DB_SSL_CA", "/etc/ssl/certs/ca-certificates.crt")
        return mysql.connector.connect(**opts)
    conn = sqlite3.connect(SQLITE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def run(sql, params=(), one=False, commit=False):
    """Run one query. Use ? placeholders; they are converted for MySQL."""
    conn = get_db()
    try:
        cur = conn.cursor(dictionary=True) if USE_MYSQL else conn.cursor()
        cur.execute(sql.replace("?", PH), params)
        if commit:
            conn.commit()
            return cur.lastrowid
        rows = [dict(r) for r in cur.fetchall()]
        return (rows[0] if rows else None) if one else rows
    finally:
        conn.close()


def init_db():
    pk = "INT AUTO_INCREMENT PRIMARY KEY" if USE_MYSQL else "INTEGER PRIMARY KEY AUTOINCREMENT"
    # Table design as in project report section 4.4
    run(f"""CREATE TABLE IF NOT EXISTS users (
        id {pk},
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""", commit=True)
    run(f"""CREATE TABLE IF NOT EXISTS logs (
        id {pk},
        filename VARCHAR(200) NULL,
        prediction VARCHAR(100) NULL,
        uploaded_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        username VARCHAR(100) NULL)""", commit=True)
    # Demo account so reviewers / HR can log in without signing up
    if not run("SELECT id FROM users WHERE username = ?", ("demo",), one=True):
        run("INSERT INTO users (username, password) VALUES (?, ?)",
            ("demo", generate_password_hash("demo123")), commit=True)


try:
    init_db()
except Exception as exc:  # keep the app alive so /health still answers
    print("DB init failed:", exc)

# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if "username" not in session:
            flash("Please login first.", "error")
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper


@app.route("/health")
def health():
    return "ok"


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
            flash("Username: 3-30 letters, numbers or underscore.", "error")
        elif len(password) < 6:
            flash("Password must be at least 6 characters.", "error")
        elif run("SELECT id FROM users WHERE username = ?", (username,), one=True):
            flash("Username already taken.", "error")
        else:
            run("INSERT INTO users (username, password) VALUES (?, ?)",
                (username, generate_password_hash(password)), commit=True)
            session.clear()
            session["username"] = username
            return redirect(url_for("dashboard"))
    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = run("SELECT * FROM users WHERE username = ?", (username,), one=True)
        if user and check_password_hash(user["password"], password):
            session.clear()
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/about")
@login_required
def about():
    return render_template("about.html")


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        # The upload page base64-encodes the file in the browser (encoded=1) so that
        # attack strings inside a log (SQL injection, <script> ...) are not mistaken
        # for a real attack by the hosting firewall. Plain uploads still work too.
        mode = request.form.get("encoded", "")
        encoded = mode in ("1", "2")

        def fail(msg):
            if encoded:
                return jsonify(error=msg), 400
            flash(msg, "error")
            return redirect(url_for("upload"))

        f = request.files.get("logfile")
        if not f or not f.filename:
            return fail("Please choose a log file.")
        raw = f.read()
        filename = f.filename
        if encoded:
            try:
                raw = base64.b64decode(raw)
                if mode == "2":  # browser also scrambled the bytes (XOR) and the file name
                    raw = raw.translate(XOR_TABLE)
                    filename = base64.b64decode(request.form.get("orig_name", "")).decode("utf-8", "ignore")
                else:
                    filename = request.form.get("orig_name", "")
            except (binascii.Error, ValueError):
                return fail("Could not read the file. Please try again.")
            filename = filename or "upload.txt"
        if len(raw) > MAX_LOG_BYTES:
            return fail("File too large (max 5 MB).")
        if b"\x00" in raw[:2048]:
            return fail("Invalid file: please upload a text log file.")
        prediction, total, bad = model.classify_text(raw.decode("utf-8", errors="ignore"))
        if prediction is None:
            return fail("The file is empty.")
        run("INSERT INTO logs (filename, prediction, username) VALUES (?, ?, ?)",
            (filename[:200], prediction, session["username"]), commit=True)
        if encoded:
            return jsonify(redirect=url_for("results"))
        return redirect(url_for("results"))
    return render_template("upload.html")


def list_logs(where=""):
    return run(f"SELECT * FROM logs WHERE username = ? {where} ORDER BY id DESC",
               (session["username"],))


@app.route("/results")
@login_required
def results():
    return render_template("table.html", rows=list_logs(), kind="results")


@app.route("/intrusion")
@login_required
def intrusion():
    return render_template("table.html", rows=list_logs("AND prediction = 'Intrusion Detected'"),
                           kind="intrusion")


@app.route("/normal")
@login_required
def normal():
    return render_template("table.html", rows=list_logs("AND prediction = 'Normal File'"),
                           kind="normal")


@app.route("/delete/<int:log_id>", methods=["POST"])
@login_required
def delete(log_id):
    row = run("SELECT id FROM logs WHERE id = ? AND username = ?",
              (log_id, session["username"]), one=True)
    if not row:
        abort(404)
    run("DELETE FROM logs WHERE id = ?", (log_id,), commit=True)
    flash("Record deleted.", "success")
    return redirect(request.referrer or url_for("results"))


@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", code=404, msg="Page not found."), 404


@app.errorhandler(413)
def too_large(_e):
    return render_template("error.html", code=413, msg="File too large (max 5 MB)."), 413


@app.errorhandler(500)
def server_error(_e):
    return render_template("error.html", code=500, msg="Something went wrong. Please try again."), 500


if __name__ == "__main__":
    app.run(debug=True)
