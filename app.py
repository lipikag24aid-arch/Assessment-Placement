"""
Wellness + Placement Portal
---------------------------
Flow for a student:
    login -> Self Assessment (wellness, first page) -> Placement Analysis -> results

Faculty create a class, share the class code, and watch every student's
Self Assessment and Placement results on one live dashboard.
"""
import csv
import io
import os
import random
import secrets
import smtplib
import socket
import sqlite3
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import parseaddr
from functools import wraps

from dotenv import load_dotenv
from flask import (Flask, flash, redirect, render_template, request,
                   send_file, session, url_for, abort)
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from PIL import Image
from reportlab.graphics.barcode import qrencoder
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

from questions_data import (LANGUAGE_QUESTION_BANK, QUESTION_BANK, QUESTION_COUNT,
                            WELLNESS_QUESTIONS)

BASE = os.path.dirname(os.path.abspath(__file__))
load_dotenv(dotenv_path=os.path.join(BASE, ".env"), override=True)
INSTANCE_DIR = os.path.join(BASE, "instance")
REPORT_DIR = os.path.join(BASE, "reports")
os.makedirs(INSTANCE_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)
# Use a persistent path on hosted platforms (e.g. /var/data/portal.db on Render).
DB = os.environ.get("DATABASE_PATH", os.path.join(INSTANCE_DIR, "portal.db"))
os.makedirs(os.path.dirname(os.path.abspath(DB)), exist_ok=True)


def _secret_key():
    """SECRET_KEY from .env, otherwise a random key stored once in instance/."""
    env_key = os.environ.get("SECRET_KEY", "").strip()
    if env_key:
        return env_key
    path = os.path.join(INSTANCE_DIR, "secret.key")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
    with open(path) as f:
        return f.read().strip()


app = Flask(__name__)
app.secret_key = _secret_key()

# ------------------------------------------------------------------ HTTPS settings
def _flag(name, default):
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes", "on")


USE_HTTPS = _flag("USE_HTTPS", "0")          # default: plain http (set USE_HTTPS=1 for HTTPS with a self-signed cert)
BEHIND_PROXY = _flag("BEHIND_PROXY", "0")    # nginx / Caddy / a host terminates HTTPS for you
CERT_DIR = os.path.join(BASE, "certs")
CERT_FILE = os.environ.get("PORTAL_SSL_CERT", os.path.join(CERT_DIR, "cert.pem"))
KEY_FILE = os.environ.get("PORTAL_SSL_KEY", os.path.join(CERT_DIR, "key.pem"))

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=USE_HTTPS or BEHIND_PROXY,   # cookies only travel over HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)
if BEHIND_PROXY:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


@app.before_request
def force_https():
    if BEHIND_PROXY and not request.is_secure:
        return redirect(request.url.replace("http://", "https://", 1), code=301)


@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    # HSTS only with a real certificate (behind a proxy); on a self-signed
    # local cert it can lock you out of the site in your browser.
    if BEHIND_PROXY and request.is_secure:
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    return resp


def _lan_ips():
    ips = set()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            ips.add(s.getsockname()[0])
    except OSError:
        pass
    try:
        ips.update(socket.gethostbyname_ex(socket.gethostname())[2])
    except OSError:
        pass
    return sorted(i for i in ips if not i.startswith("127."))


def ensure_self_signed_cert():
    """Create certs/cert.pem + key.pem (valid for localhost, this PC's LAN IPs and CERT_HOSTS)."""
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return
    import ipaddress
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    os.makedirs(os.path.dirname(CERT_FILE), exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    names = {"localhost", socket.gethostname()}
    names.update(h.strip() for h in os.environ.get("CERT_HOSTS", "").split(",") if h.strip())
    ips = {"127.0.0.1", *_lan_ips()}
    san = []
    for n in sorted(names):
        try:
            san.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            san.append(x509.DNSName(n))
    san += [x509.IPAddress(ipaddress.ip_address(i)) for i in sorted(ips)]
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Wellness Portal (local)")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    with open(KEY_FILE, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))
    try:
        os.chmod(KEY_FILE, 0o600)
    except OSError:
        pass
    with open(CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"Created self-signed certificate: {CERT_FILE}")

WELLNESS_SECONDS = 420
PLACEMENT_SECONDS = 3600
CODING_QUESTIONS_PER_ATTEMPT = 13
FACULTY_SIGNUP_KEY = os.environ.get("FACULTY_SIGNUP_KEY", "faculty-invite")
STAGE_ORDER = ["Aptitude", "Coding", "Technical Interview", "Group Discussion"]
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O/1/I


# --------------------------------------------------------------------------- db
def db():
    con = sqlite3.connect(DB, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con


def init_db():
    con = db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'student',
        class_id INTEGER,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS classes(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        code TEXT UNIQUE NOT NULL,
        faculty_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(faculty_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS wellness_assessments(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        class_id INTEGER,
        total_score INTEGER NOT NULL,
        risk_percent REAL NOT NULL,
        wellness_percent REAL NOT NULL,
        level TEXT NOT NULL,
        safety_flag INTEGER NOT NULL DEFAULT 0,
        time_taken INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS wellness_answers(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        assessment_id INTEGER NOT NULL,
        question_no INTEGER NOT NULL,
        factor TEXT NOT NULL,
        answer TEXT NOT NULL,
        score INTEGER NOT NULL,
        FOREIGN KEY(assessment_id) REFERENCES wellness_assessments(id)
    );
    CREATE TABLE IF NOT EXISTS placement_assessments(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        class_id INTEGER,
        language TEXT NOT NULL,
        total_score INTEGER NOT NULL,
        score_percent REAL NOT NULL,
        level TEXT NOT NULL,
        time_taken INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS placement_answers(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        assessment_id INTEGER NOT NULL,
        question_no INTEGER NOT NULL,
        question TEXT NOT NULL,
        factor TEXT NOT NULL,
        answer TEXT NOT NULL,
        correct_answer TEXT NOT NULL,
        score INTEGER NOT NULL,
        FOREIGN KEY(assessment_id) REFERENCES placement_assessments(id)
    );
    CREATE TABLE IF NOT EXISTS class_sessions(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        class_id INTEGER NOT NULL,
        token TEXT UNIQUE NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        ended INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY(class_id) REFERENCES classes(id)
    );
    CREATE TABLE IF NOT EXISTS session_joins(
        session_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        joined_at TEXT NOT NULL,
        PRIMARY KEY(session_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS checkins(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        mood INTEGER NOT NULL, sleep INTEGER NOT NULL, energy INTEGER NOT NULL,
        stress INTEGER NOT NULL, focus INTEGER NOT NULL,
        note TEXT, created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)
    now = datetime.now().isoformat()
    for name, email, pw, role in [
        ("System Admin", "admin@wellness.local", "admin123", "admin"),
        ("Demo Faculty", "faculty@wellness.local", "faculty123", "faculty"),
    ]:
        if not con.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
            con.execute("INSERT INTO users(name,email,password,role,created_at) VALUES(?,?,?,?,?)",
                        (name, email, generate_password_hash(pw), role, now))
    con.commit()
    con.close()


init_db()


# ----------------------------------------------------------------- auth helpers
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def check_csrf():
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
            flash("Your session expired. Please try again.", "error")
            return redirect(request.referrer or url_for("index"))


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    con = db()
    u = con.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    con.close()
    if u is None:
        session.clear()
        return None
    session["role"] = u["role"]
    return u


def home_for(user):
    if user["role"] == "student":
        return url_for("self_assessment")
    return url_for("faculty_home")


def require(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            u = current_user()
            if not u:
                return redirect(url_for("index"))
            if roles and u["role"] not in roles:
                return redirect(home_for(u))
            return fn(u, *a, **kw)
        return wrapper
    return deco


@app.context_processor
def inject_user():
    return {"me": current_user() if "user_id" in session else None}


def new_class_code(con):
    while True:
        code = "".join(random.choice(CODE_ALPHABET) for _ in range(6))
        if not con.execute("SELECT 1 FROM classes WHERE code=?", (code,)).fetchone():
            return code


def normalise_code(raw):
    return "".join(ch for ch in (raw or "").upper() if ch.isalnum())


# ------------------------------------------------------------------- scoring
def wellness_level(total):
    pct = round(total / (len(WELLNESS_QUESTIONS) * 3) * 100, 1)
    if pct <= 25:
        level = "Low"
    elif pct <= 50:
        level = "Moderate"
    elif pct <= 75:
        level = "High"
    else:
        level = "Very High"
    return pct, round(100 - pct, 1), level


WELLNESS_TIPS = {
    "Irritability": "Short breaks, movement and slow breathing can take the edge off. Notice what usually triggers it.",
    "Companionship": "Reach out to one classmate or friend this week; small, regular contact helps more than one big plan.",
    "Energy": "Check sleep, meals and daylight first. A short daily walk often lifts energy better than extra caffeine.",
    "Self Efficacy": "Set small, finishable goals and note each one you complete to rebuild confidence.",
    "Social Avoidance": "Say yes to one low-pressure invitation a week, such as a short coffee or a study group.",
    "Academic Cynicism": "Link one current subject to a goal you care about, or talk to a mentor about why it matters.",
    "Self Criticism": "Try speaking to yourself the way you would to a friend in the same situation.",
    "Unexpected Stress": "Keep a little slack in your week and write down a first step for when plans change.",
    "Perceived Control": "List what you can influence today and do one thing from that list; park the rest.",
    "Relaxation": "Build a wind-down routine: screens off earlier, light stretching, or a few minutes of slow breathing.",
    "Study Exhaustion": "Use focused blocks with real breaks, and protect at least one study-free half day.",
    "Failure Feelings": "One setback is not a verdict. Talk it over with someone you trust and pick one next step.",
    "Self Harm Thoughts": "Please talk to a trusted person or a qualified professional about this soon.",
}


def wellness_suggestions(factor_scores):
    out = [(f, WELLNESS_TIPS.get(f, "Build a small, consistent routine around this area."))
           for f, s in factor_scores.items() if s >= 2.0]
    if not out:
        out.append(("Overall", "Your responses suggest fairly balanced wellness. Keep up your routines and recheck from time to time."))
    return out


def placement_level(total):
    pct = round(total / QUESTION_COUNT * 100, 1)
    if pct < 40:
        level = "Needs Practice"
    elif pct < 60:
        level = "Developing"
    elif pct < 80:
        level = "Interview Ready"
    else:
        level = "Placement Ready"
    return pct, level


def stage_of(factor):
    """'Python Coding' / 'Java Coding' -> 'Coding' so stages compare across languages."""
    return "Coding" if factor.endswith(" Coding") else factor


STAGE_ADVICE = {
    "Aptitude": "Practise timed quantitative, verbal and logical reasoning sets; review the method behind every missed answer.",
    "Coding": "Write and run small programs daily, tracing edge cases and core language behaviour.",
    "Technical Interview": "Review fundamentals aloud and use concise examples from projects to explain your decisions.",
    "Group Discussion": "Practise structured, respectful contributions, active listening and concise summaries.",
}


def placement_stage_scores(con, assessment_id):
    rows = con.execute("SELECT factor, AVG(score)*100 AS pct FROM placement_answers "
                       "WHERE assessment_id=? GROUP BY factor", (assessment_id,)).fetchall()
    scores = {stage_of(r["factor"]): round(r["pct"], 1) for r in rows}
    return {s: scores[s] for s in STAGE_ORDER if s in scores}


# ----------------------------------------------------------- placement questions
def assessment_question_pool(language):
    common = [q for q in QUESTION_BANK if q[0] != "Java Coding"]
    coding = LANGUAGE_QUESTION_BANK[language]["questions"]
    if language == "java":
        coding = [(q, o, c) for f, q, o, c in QUESTION_BANK if f == "Java Coding"] + coding
    label = f"{LANGUAGE_QUESTION_BANK[language]['name']} Coding"
    return common + [(label, q, o, c) for q, o, c in coding]


COMMON_COUNT = QUESTION_COUNT - sum(1 for f, *_ in QUESTION_BANK if f == "Java Coding")


def build_question_set(language, previous_order=None):
    pool = assessment_question_pool(language)
    coding_idx = list(range(COMMON_COUNT, len(pool)))
    prev_coding = {i for i in previous_order if i in coding_idx} if previous_order else set()
    while True:
        picked = random.sample(coding_idx, CODING_QUESTIONS_PER_ATTEMPT)
        if set(picked) == prev_coding:
            continue
        order = list(range(COMMON_COUNT)) + picked
        random.shuffle(order)
        if order != previous_order:
            return order


# ----------------------------------------------------------------- auth routes
@app.route("/")
def index():
    u = current_user()
    if u:
        return redirect(home_for(u))
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    role = "faculty" if request.args.get("as") == "faculty" else "student"
    if request.method == "POST":
        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        role = "faculty" if request.form.get("role") == "faculty" else "student"
        if not name or "@" not in email:
            flash("Please enter your name and a valid email.", "error")
            return redirect(url_for("register", **({"as": "faculty"} if role == "faculty" else {})))
        if len(password) < 6:
            flash("Password must contain at least 6 characters.", "error")
            return redirect(url_for("register", **({"as": "faculty"} if role == "faculty" else {})))
        if role == "faculty" and not secrets.compare_digest(
                request.form.get("faculty_key", ""), FACULTY_SIGNUP_KEY):
            flash("Incorrect faculty sign-up key.", "error")
            return redirect(url_for("register", **{"as": "faculty"}))
        con = db()
        class_id = None
        if role == "student":
            code = normalise_code(request.form.get("class_code"))
            if code:
                c = con.execute("SELECT id FROM classes WHERE code=?", (code,)).fetchone()
                if not c:
                    con.close()
                    flash("That class code was not found. Check it with your faculty, or leave it blank and join later.", "error")
                    return redirect(url_for("register"))
                class_id = c["id"]
        try:
            con.execute("INSERT INTO users(name,email,password,role,class_id,created_at) VALUES(?,?,?,?,?,?)",
                        (name, email, generate_password_hash(password), role, class_id,
                         datetime.now().isoformat()))
            con.commit()
        except sqlite3.IntegrityError:
            con.close()
            flash("Email already registered.", "error")
            return redirect(url_for("register"))
        con.close()
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("index"))
    return render_template("register.html", role=role)


@app.route("/login", methods=["POST"])
def login():
    email = request.form["email"].strip().lower()
    con = db()
    u = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    con.close()
    if u and check_password_hash(u["password"], request.form["password"]):
        pending = session.get("join_token")
        session.clear()
        session.permanent = True
        session["user_id"] = u["id"]
        session["role"] = u["role"]
        if pending and u["role"] == "student":
            con = db()
            c = apply_join_token(con, u, pending)
            con.close()
            flash(f"You joined {c['name']}." if c else "That QR code has expired. Ask your faculty for the new one.",
                  "success" if c else "error")
        return redirect(home_for(u))
    flash("Invalid email or password.", "error")
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/join", methods=["GET", "POST"])
@require("student")
def join_class(u):
    con = db()
    if request.method == "POST":
        code = normalise_code(request.form.get("class_code"))
        c = con.execute("SELECT * FROM classes WHERE code=?", (code,)).fetchone()
        if not c:
            con.close()
            flash("That class code was not found.", "error")
            return redirect(url_for("join_class"))
        con.execute("UPDATE users SET class_id=? WHERE id=?", (c["id"], u["id"]))
        con.commit()
        con.close()
        flash(f"You joined {c['name']}.", "success")
        return redirect(url_for("self_assessment"))
    current = con.execute("SELECT * FROM classes WHERE id=?", (u["class_id"],)).fetchone() if u["class_id"] else None
    con.close()
    return render_template("join.html", current_class=current)


# ----------------------------------------------------------- student: dashboard
@app.route("/dashboard")
@require("student")
def dashboard(u):
    con = db()
    w = con.execute("SELECT * FROM wellness_assessments WHERE user_id=? ORDER BY id DESC LIMIT 1", (u["id"],)).fetchone()
    p = con.execute("SELECT * FROM placement_assessments WHERE user_id=? ORDER BY id DESC LIMIT 1", (u["id"],)).fetchone()
    cls = con.execute("SELECT * FROM classes WHERE id=?", (u["class_id"],)).fetchone() if u["class_id"] else None
    checkins = con.execute("SELECT * FROM checkins WHERE user_id=? ORDER BY id DESC LIMIT 5", (u["id"],)).fetchall()
    con.close()
    return render_template("dashboard.html", w=w, p=p, cls=cls, checkins=checkins)


# --------------------------------------------------- student: self assessment
@app.route("/self-assessment")
@require("student")
def self_assessment(u):
    con = db()
    cls = con.execute("SELECT * FROM classes WHERE id=?", (u["class_id"],)).fetchone() if u["class_id"] else None
    con.close()
    return render_template("self_assessment.html", questions=WELLNESS_QUESTIONS,
                           seconds=WELLNESS_SECONDS, cls=cls)


@app.route("/self-assessment/submit", methods=["POST"])
@require("student")
def submit_self_assessment(u):
    answers, total, factor_values, missing = [], 0, {}, []
    for i, (factor, _q, opts) in enumerate(WELLNESS_QUESTIONS, 1):
        raw = request.form.get(f"q{i}")
        if raw in (None, ""):
            missing.append(i)
            continue
        try:
            score = int(raw)
        except ValueError:
            score = -1
        if score not in range(4):
            flash("Invalid answer received. Please try again.", "error")
            return redirect(url_for("self_assessment"))
        answers.append((i, factor, opts[score], score))
        total += score
        factor_values.setdefault(factor, []).append(score)
    if missing:
        flash("Please answer all questions. Missing: " + ", ".join(map(str, missing)), "error")
        return redirect(url_for("self_assessment"))
    try:
        time_taken = max(0, min(WELLNESS_SECONDS, int(request.form.get("time_taken", "0") or 0)))
    except ValueError:
        time_taken = 0
    pct, wellness, level = wellness_level(total)
    safety = int(answers[-1][3] > 0)  # question 13
    con = db()
    cur = con.execute(
        "INSERT INTO wellness_assessments(user_id,class_id,total_score,risk_percent,wellness_percent,"
        "level,safety_flag,time_taken,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
        (u["id"], u["class_id"], total, pct, wellness, level, safety, time_taken,
         datetime.now().isoformat()))
    aid = cur.lastrowid
    con.executemany("INSERT INTO wellness_answers(assessment_id,question_no,factor,answer,score) VALUES(?,?,?,?,?)",
                    [(aid, *a) for a in answers])
    con.commit()
    con.close()
    flash("Self assessment saved. Now continue with the placement analysis.", "success")
    return redirect(url_for("placement_home"))


def own_wellness(con, aid, user_id):
    return con.execute("SELECT * FROM wellness_assessments WHERE id=? AND user_id=?", (aid, user_id)).fetchone()


@app.route("/self-assessment/result/<int:aid>")
@require("student")
def self_result(u, aid):
    con = db()
    a = own_wellness(con, aid, u["id"])
    if not a:
        con.close()
        abort(404)
    rows = con.execute("SELECT factor, AVG(score) s FROM wellness_answers WHERE assessment_id=? GROUP BY factor",
                       (aid,)).fetchall()
    answers = con.execute("SELECT * FROM wellness_answers WHERE assessment_id=? ORDER BY question_no", (aid,)).fetchall()
    con.close()
    factors = {r["factor"]: round(r["s"], 2) for r in rows}
    return render_template("self_result.html", a=a, factors=factors, answers=answers,
                           tips=wellness_suggestions(factors))


# --------------------------------------------------------- student: placement
@app.route("/placement")
@require("student")
def placement_home(u):
    con = db()
    has_self = con.execute("SELECT 1 FROM wellness_assessments WHERE user_id=? LIMIT 1", (u["id"],)).fetchone()
    con.close()
    if not has_self:
        flash("Please complete the Self Assessment first.", "error")
        return redirect(url_for("self_assessment"))
    langs = [(slug, v["name"]) for slug, v in LANGUAGE_QUESTION_BANK.items()]
    return render_template("placement_home.html", langs=langs)


@app.route("/placement/quiz")
@require("student")
def placement_quiz(u):
    language = request.args.get("language", "java").lower()
    if language not in LANGUAGE_QUESTION_BANK:
        flash("Choose a supported programming language.", "error")
        return redirect(url_for("placement_home"))
    con = db()
    has_self = con.execute("SELECT 1 FROM wellness_assessments WHERE user_id=? LIMIT 1", (u["id"],)).fetchone()
    con.close()
    if not has_self:
        return redirect(url_for("placement_home"))
    pool = assessment_question_pool(language)
    order = session.get("pl_order")
    valid = (isinstance(order, list) and session.get("pl_lang") == language
             and len(order) == QUESTION_COUNT and len(set(order)) == QUESTION_COUNT
             and all(isinstance(i, int) and 0 <= i < len(pool) for i in order)
             and set(range(COMMON_COUNT)).issubset(order))
    if not valid:
        prev = session.get("pl_prev") if session.get("pl_prev_lang") == language else None
        order = build_question_set(language, prev)
        session["pl_order"], session["pl_lang"] = order, language
    questions = [pool[i] for i in order]
    return render_template("placement_quiz.html", questions=questions,
                           language_name=LANGUAGE_QUESTION_BANK[language]["name"],
                           seconds=PLACEMENT_SECONDS)


@app.route("/placement/submit", methods=["POST"])
@require("student")
def submit_placement(u):
    language = session.get("pl_lang", "java")
    order = session.get("pl_order")
    if language not in LANGUAGE_QUESTION_BANK or not isinstance(order, list):
        flash("Please start a new placement assessment before submitting.", "error")
        return redirect(url_for("placement_home"))
    pool = assessment_question_pool(language)
    if (len(order) != QUESTION_COUNT or len(set(order)) != QUESTION_COUNT
            or any(not isinstance(i, int) or not 0 <= i < len(pool) for i in order)):
        flash("Please start a new placement assessment before submitting.", "error")
        return redirect(url_for("placement_home"))
    rows, total, missing = [], 0, []
    for n, idx in enumerate(order, 1):
        factor, q, opts, correct = pool[idx]
        raw = request.form.get(f"q{n}")
        if raw in (None, ""):
            missing.append(n)
            continue
        try:
            pick = int(raw)
        except ValueError:
            pick = -1
        if pick not in range(len(opts)):
            flash("Invalid answer received. Please try again.", "error")
            return redirect(url_for("placement_quiz", language=language))
        ok = int(pick == correct)
        total += ok
        rows.append((n, q, factor, opts[pick], opts[correct], ok))
    if missing:
        flash("Please answer all questions. Missing: " + ", ".join(map(str, missing)), "error")
        return redirect(url_for("placement_quiz", language=language))
    try:
        time_taken = max(0, min(PLACEMENT_SECONDS, int(request.form.get("time_taken", "0") or 0)))
    except ValueError:
        time_taken = 0
    pct, level = placement_level(total)
    con = db()
    cur = con.execute(
        "INSERT INTO placement_assessments(user_id,class_id,language,total_score,score_percent,level,"
        "time_taken,created_at) VALUES(?,?,?,?,?,?,?,?)",
        (u["id"], u["class_id"], language, total, pct, level, time_taken, datetime.now().isoformat()))
    aid = cur.lastrowid
    con.executemany("INSERT INTO placement_answers(assessment_id,question_no,question,factor,answer,"
                    "correct_answer,score) VALUES(?,?,?,?,?,?,?)", [(aid, *r) for r in rows])
    con.commit()
    con.close()
    session["pl_prev"], session["pl_prev_lang"] = order, language
    session.pop("pl_order", None)
    session.pop("pl_lang", None)
    return redirect(url_for("placement_result", aid=aid))


@app.route("/placement/result/<int:aid>")
@require("student")
def placement_result(u, aid):
    con = db()
    a = con.execute("SELECT * FROM placement_assessments WHERE id=? AND user_id=?", (aid, u["id"])).fetchone()
    if not a:
        con.close()
        abort(404)
    stages = placement_stage_scores(con, aid)
    answers = con.execute("SELECT * FROM placement_answers WHERE assessment_id=? ORDER BY question_no", (aid,)).fetchall()
    w = con.execute("SELECT * FROM wellness_assessments WHERE user_id=? ORDER BY id DESC LIMIT 1", (u["id"],)).fetchone()
    con.close()
    tips = [(s, v, STAGE_ADVICE[s]) for s, v in stages.items()]
    return render_template("placement_result.html", a=a, stages=stages, answers=answers, tips=tips,
                           correct=a["total_score"], total=QUESTION_COUNT, w=w,
                           language_name=LANGUAGE_QUESTION_BANK[a["language"]]["name"])


# ---------------------------------------------------- student: history / checkin
@app.route("/history")
@require("student")
def history(u):
    con = db()
    w = con.execute("SELECT * FROM wellness_assessments WHERE user_id=? ORDER BY id DESC", (u["id"],)).fetchall()
    p = con.execute("SELECT * FROM placement_assessments WHERE user_id=? ORDER BY id DESC", (u["id"],)).fetchall()
    con.close()
    return render_template("history.html", w=w, p=p)


@app.route("/checkin", methods=["GET", "POST"])
@require("student")
def checkin(u):
    if request.method == "POST":
        try:
            vals = [max(1, min(5, int(request.form[k]))) for k in ["mood", "sleep", "energy", "stress", "focus"]]
        except (KeyError, ValueError):
            flash("Please fill in every rating.", "error")
            return redirect(url_for("checkin"))
        con = db()
        con.execute("INSERT INTO checkins(user_id,mood,sleep,energy,stress,focus,note,created_at) VALUES(?,?,?,?,?,?,?,?)",
                    (u["id"], *vals, request.form.get("note", "")[:500], datetime.now().isoformat()))
        con.commit()
        con.close()
        flash("Daily check-in saved.", "success")
        return redirect(url_for("dashboard"))
    return render_template("checkin.html")


# ------------------------------------------------------------ faculty dashboard
def class_for(con, user, class_id):
    c = con.execute("SELECT * FROM classes WHERE id=?", (class_id,)).fetchone()
    if not c or (user["role"] != "admin" and c["faculty_id"] != user["id"]):
        return None
    return c


def class_snapshot(con, class_id):
    """Latest wellness + latest placement result for every student in the class."""
    students = con.execute("SELECT id,name,email FROM users WHERE role='student' AND class_id=? ORDER BY name",
                           (class_id,)).fetchall()
    out = []
    for s in students:
        w = con.execute("SELECT * FROM wellness_assessments WHERE user_id=? ORDER BY id DESC LIMIT 1", (s["id"],)).fetchone()
        p = con.execute("SELECT * FROM placement_assessments WHERE user_id=? ORDER BY id DESC LIMIT 1", (s["id"],)).fetchone()
        out.append({"id": s["id"], "name": s["name"], "email": s["email"], "w": w, "p": p,
                    "stages": placement_stage_scores(con, p["id"]) if p else {}})
    return out


def class_summary(rows):
    done_w = [r for r in rows if r["w"]]
    done_p = [r for r in rows if r["p"]]
    avg = lambda xs: round(sum(xs) / len(xs), 1) if xs else None
    stage_avgs = {}
    for st in STAGE_ORDER:
        vals = [r["stages"][st] for r in done_p if st in r["stages"]]
        if vals:
            stage_avgs[st] = avg(vals)
    count = lambda items, key, order: {k: sum(1 for i in items if i[key] == k) for k in order}
    return {
        "students": len(rows),
        "self_done": len(done_w),
        "placement_done": len(done_p),
        "avg_wellness": avg([r["w"]["wellness_percent"] for r in done_w]),
        "avg_placement": avg([r["p"]["score_percent"] for r in done_p]),
        "stage_avgs": stage_avgs,
        "wellness_levels": count([r["w"] for r in done_w], "level", ["Low", "Moderate", "High", "Very High"]),
        "readiness": count([r["p"] for r in done_p], "level",
                           ["Needs Practice", "Developing", "Interview Ready", "Placement Ready"]),
        "follow_up": sum(1 for r in done_w if r["w"]["safety_flag"] or r["w"]["level"] in ("High", "Very High")),
    }


@app.route("/faculty", methods=["GET", "POST"])
@require("faculty", "admin")
def faculty_home(u):
    con = db()
    if request.method == "POST":
        name = request.form.get("class_name", "").strip()[:80]
        if not name:
            con.close()
            flash("Enter a class name.", "error")
            return redirect(url_for("faculty_home"))
        code = new_class_code(con)
        cur = con.execute("INSERT INTO classes(name,code,faculty_id,created_at) VALUES(?,?,?,?)",
                          (name, code, u["id"], datetime.now().isoformat()))
        con.commit()
        con.close()
        flash(f"Class created. Share the code {code} with your students.", "success")
        return redirect(url_for("faculty_class", class_id=cur.lastrowid))
    if u["role"] == "admin":
        classes = con.execute("SELECT c.*, f.name AS faculty_name FROM classes c JOIN users f ON f.id=c.faculty_id ORDER BY c.id DESC").fetchall()
    else:
        classes = con.execute("SELECT c.*, f.name AS faculty_name FROM classes c JOIN users f ON f.id=c.faculty_id "
                              "WHERE c.faculty_id=? ORDER BY c.id DESC", (u["id"],)).fetchall()
    cards = []
    for c in classes:
        summ = class_summary(class_snapshot(con, c["id"]))
        cards.append({"c": c, "s": summ})
    con.close()
    return render_template("faculty_home.html", cards=cards)


@app.route("/faculty/class/<int:class_id>")
@require("faculty", "admin")
def faculty_class(u, class_id):
    con = db()
    c = class_for(con, u, class_id)
    if not c:
        con.close()
        abort(404)
    rows = class_snapshot(con, class_id)
    live_session = active_session(con, class_id)
    con.close()
    return render_template("faculty_class.html", c=c, rows=rows, s=class_summary(rows),
                           live_session=live_session, stage_order=STAGE_ORDER)


def make_qr_png(text, box=14, border=4):
    """Return PNG bytes of a QR code for `text` (ReportLab encoder + Pillow, no extra service)."""
    q = qrencoder.QRCode(None, qrencoder.QRErrorCorrectLevel.M)
    q.addData(text)
    q.make()
    n = q.getModuleCount()
    size = (n + 2 * border) * box
    img = Image.new("1", (size, size), 1)
    px = img.load()
    for r in range(n):
        for c in range(n):
            if q.isDark(r, c):
                for dy in range(box):
                    for dx in range(box):
                        px[(c + border) * box + dx, (r + border) * box + dy] = 0
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def session_join_url(token):
    return url_for("join_by_token", token=token, _external=True)


def active_session(con, class_id):
    """Latest session of the class that is neither ended nor expired (or None)."""
    row = con.execute("SELECT * FROM class_sessions WHERE class_id=? AND ended=0 "
                      "ORDER BY id DESC LIMIT 1", (class_id,)).fetchone()
    if row and datetime.fromisoformat(row["expires_at"]) > datetime.now():
        return row
    return None


@app.route("/faculty/class/<int:class_id>/session/start", methods=["POST"])
@require("faculty", "admin")
def session_start(u, class_id):
    con = db()
    c = class_for(con, u, class_id)
    if not c:
        con.close()
        abort(404)
    try:
        minutes = min(max(int(request.form.get("minutes", 60)), 5), 480)
    except ValueError:
        minutes = 60
    now = datetime.now()
    con.execute("UPDATE class_sessions SET ended=1 WHERE class_id=?", (class_id,))  # old QR stops working
    token = secrets.token_urlsafe(9)
    cur = con.execute("INSERT INTO class_sessions(class_id,token,created_at,expires_at) VALUES(?,?,?,?)",
                      (class_id, token, now.isoformat(), (now + timedelta(minutes=minutes)).isoformat()))
    con.commit()
    sid = cur.lastrowid
    con.close()
    return redirect(url_for("session_view", class_id=class_id, sid=sid))


def _own_session(con, u, class_id, sid):
    c = class_for(con, u, class_id)
    if not c:
        return None, None
    return c, con.execute("SELECT * FROM class_sessions WHERE id=? AND class_id=?", (sid, class_id)).fetchone()


@app.route("/faculty/class/<int:class_id>/session/<int:sid>")
@require("faculty", "admin")
def session_view(u, class_id, sid):
    con = db()
    c, ss = _own_session(con, u, class_id, sid)
    if not ss:
        con.close()
        abort(404)
    joined = con.execute("SELECT u.name, j.joined_at FROM session_joins j JOIN users u ON u.id=j.user_id "
                         "WHERE j.session_id=? ORDER BY j.joined_at", (sid,)).fetchall()
    con.close()
    live = (not ss["ended"]) and datetime.fromisoformat(ss["expires_at"]) > datetime.now()
    return render_template("faculty_session.html", c=c, ss=ss, live=live, joined=joined,
                           join_url=session_join_url(ss["token"]),
                           expires_ms=int(datetime.fromisoformat(ss["expires_at"]).timestamp() * 1000))


@app.route("/faculty/class/<int:class_id>/session/<int:sid>/qr.png")
@require("faculty", "admin")
def session_qr(u, class_id, sid):
    con = db()
    c, ss = _own_session(con, u, class_id, sid)
    con.close()
    if not ss:
        abort(404)
    return send_file(io.BytesIO(make_qr_png(session_join_url(ss["token"]))), mimetype="image/png",
                     download_name=f"class_session_{sid}.png",
                     as_attachment=request.args.get("download") == "1")


@app.route("/faculty/class/<int:class_id>/session/<int:sid>/end", methods=["POST"])
@require("faculty", "admin")
def session_end(u, class_id, sid):
    con = db()
    c, ss = _own_session(con, u, class_id, sid)
    if not ss:
        con.close()
        abort(404)
    con.execute("UPDATE class_sessions SET ended=1 WHERE id=?", (sid,))
    con.commit()
    con.close()
    flash("Session ended. Its QR code no longer works.", "success")
    return redirect(url_for("faculty_class", class_id=class_id))


def apply_join_token(con, user, token):
    """Put a student into the class of a live session. Returns the class row or None."""
    ss = con.execute("SELECT * FROM class_sessions WHERE token=?", (token,)).fetchone()
    if not ss or ss["ended"] or datetime.fromisoformat(ss["expires_at"]) <= datetime.now():
        return None
    con.execute("UPDATE users SET class_id=? WHERE id=?", (ss["class_id"], user["id"]))
    con.execute("INSERT OR IGNORE INTO session_joins(session_id,user_id,joined_at) VALUES(?,?,?)",
                (ss["id"], user["id"], datetime.now().isoformat()))
    con.commit()
    return con.execute("SELECT * FROM classes WHERE id=?", (ss["class_id"],)).fetchone()


@app.route("/j/<token>")
def join_by_token(token):
    con = db()
    ss = con.execute("SELECT s.*, c.name AS cname FROM class_sessions s JOIN classes c ON c.id=s.class_id "
                     "WHERE s.token=?", (token,)).fetchone()
    live = ss and not ss["ended"] and datetime.fromisoformat(ss["expires_at"]) > datetime.now()
    if not live:
        con.close()
        flash("This QR code has expired. Ask your faculty to show the new one.", "error")
        return redirect(url_for("index"))
    u = current_user() if "user_id" in session else None
    if u and u["role"] == "student":
        c = apply_join_token(con, u, token)
        con.close()
        flash(f"You joined {c['name']}.", "success")
        return redirect(url_for("self_assessment"))
    con.close()
    session["join_token"] = token          # applied right after the student logs in
    flash(f"Log in or create an account to join {ss['cname']}.", "success")
    return redirect(url_for("register") if not u else url_for("index"))


@app.route("/faculty/class/<int:class_id>/student/<int:student_id>")
@require("faculty", "admin")
def faculty_student(u, class_id, student_id):
    con = db()
    c = class_for(con, u, class_id)
    st = con.execute("SELECT id,name,email FROM users WHERE id=? AND class_id=? AND role='student'",
                     (student_id, class_id)).fetchone()
    if not c or not st:
        con.close()
        abort(404)
    w = con.execute("SELECT * FROM wellness_assessments WHERE user_id=? ORDER BY id DESC LIMIT 1", (student_id,)).fetchone()
    p = con.execute("SELECT * FROM placement_assessments WHERE user_id=? ORDER BY id DESC LIMIT 1", (student_id,)).fetchone()
    factors = {}
    if w:
        rows = con.execute("SELECT factor, AVG(score) s FROM wellness_answers WHERE assessment_id=? GROUP BY factor",
                           (w["id"],)).fetchall()
        factors = {r["factor"]: round(r["s"], 2) for r in rows if r["factor"] != "Self Harm Thoughts"}
    stages = placement_stage_scores(con, p["id"]) if p else {}
    con.close()
    return render_template("faculty_student.html", c=c, st=st, w=w, p=p, factors=factors, stages=stages)


@app.route("/faculty/class/<int:class_id>/export.csv")
@require("faculty", "admin")
def faculty_export(u, class_id):
    con = db()
    c = class_for(con, u, class_id)
    if not c:
        con.close()
        abort(404)
    rows = class_snapshot(con, class_id)
    con.close()
    buf = io.StringIO()
    wr = csv.writer(buf)
    wr.writerow(["Name", "Email", "Wellness %", "Wellness level", "Follow-up flag",
                 "Placement %", "Readiness", "Language", *STAGE_ORDER, "Last activity"])
    for r in rows:
        w, p = r["w"], r["p"]
        last = max([x["created_at"] for x in (w, p) if x] or [""])
        wr.writerow([r["name"], r["email"],
                     w["wellness_percent"] if w else "", w["level"] if w else "",
                     ("Yes" if (w["safety_flag"] or w["level"] in ("High", "Very High")) else "No") if w else "",
                     p["score_percent"] if p else "", p["level"] if p else "",
                     LANGUAGE_QUESTION_BANK[p["language"]]["name"] if p else "",
                     *[r["stages"].get(s, "") for s in STAGE_ORDER], last[:16].replace("T", " ")])
    data = io.BytesIO(buf.getvalue().encode("utf-8-sig"))
    return send_file(data, as_attachment=True, mimetype="text/csv",
                     download_name=f"class_{c['code']}_results.csv")


@app.route("/faculty/class/<int:class_id>/delete", methods=["POST"])
@require("faculty", "admin")
def faculty_delete_class(u, class_id):
    con = db()
    c = class_for(con, u, class_id)
    if not c:
        con.close()
        abort(404)
    con.execute("UPDATE users SET class_id=NULL WHERE class_id=?", (class_id,))
    con.execute("DELETE FROM classes WHERE id=?", (class_id,))
    con.commit()
    con.close()
    flash("Class deleted. Students keep their own results but are no longer linked to it.", "success")
    return redirect(url_for("faculty_home"))


# -------------------------------------------------------------- PDF + e-mail
def build_pdf(kind, aid, user_id):
    con = db()
    styles = getSampleStyleSheet()
    title = ParagraphStyle("t", parent=styles["Title"], alignment=TA_CENTER, fontSize=20, spaceAfter=14)
    grid = [("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey), ("GRID", (0, 0), (-1, -1), .5, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 6)]
    story = []
    if kind == "self":
        a = own_wellness(con, aid, user_id)
        if not a:
            con.close()
            return None
        rows = con.execute("SELECT factor, AVG(score) s FROM wellness_answers WHERE assessment_id=? GROUP BY factor", (aid,)).fetchall()
        answers = con.execute("SELECT * FROM wellness_answers WHERE assessment_id=? ORDER BY question_no", (aid,)).fetchall()
        con.close()
        path = os.path.join(REPORT_DIR, f"self_assessment_{aid}.pdf")
        story = [Paragraph("Self Assessment Report", title),
                 Paragraph(f"Generated: {a['created_at'][:19].replace('T', ' ')}", styles["Normal"]), Spacer(1, 12)]
        t = Table([["Metric", "Value"], ["Wellness Score", f"{a['wellness_percent']}%"],
                   ["Screening Indicator", f"{a['risk_percent']}%"], ["Level", a["level"]],
                   ["Time Taken", f"{a['time_taken'] // 60} min {a['time_taken'] % 60} sec"]], colWidths=[210, 210])
        t.setStyle(TableStyle(grid))
        story += [t, Spacer(1, 14), Paragraph("Factor Analysis", styles["Heading2"])]
        t = Table([["Factor", "Average score (0-3)"]] + [[r["factor"], round(r["s"], 2)] for r in rows], colWidths=[260, 160])
        t.setStyle(TableStyle(grid))
        story += [t, Spacer(1, 14), Paragraph("Suggestions", styles["Heading2"])]
        for f, tip in wellness_suggestions({r["factor"]: r["s"] for r in rows}):
            story += [Paragraph(f"<b>{f}:</b> {tip}", styles["BodyText"]), Spacer(1, 5)]
        if a["safety_flag"]:
            story += [Paragraph("Safety Notice", styles["Heading2"]),
                      Paragraph("Question 13 was answered with something other than 'Not at all'. This is not a diagnosis, "
                                "but it is an important signal. If you may be in immediate danger, contact local emergency "
                                "services or a trusted person or qualified professional now.", styles["BodyText"])]
        story += [Spacer(1, 10), Paragraph("This is an educational self-awareness screening tool, not a medical diagnosis.",
                                           styles["BodyText"])]
    else:
        a = con.execute("SELECT * FROM placement_assessments WHERE id=? AND user_id=?", (aid, user_id)).fetchone()
        if not a:
            con.close()
            return None
        stages = placement_stage_scores(con, aid)
        answers = con.execute("SELECT * FROM placement_answers WHERE assessment_id=? ORDER BY question_no", (aid,)).fetchall()
        con.close()
        path = os.path.join(REPORT_DIR, f"placement_report_{aid}.pdf")
        story = [Paragraph("IT Placement Analysis Report", title),
                 Paragraph(f"Generated: {a['created_at'][:19].replace('T', ' ')}", styles["Normal"]), Spacer(1, 12)]
        t = Table([["Metric", "Value"], ["Score", f"{a['score_percent']}% ({a['total_score']}/{QUESTION_COUNT})"],
                   ["Readiness", a["level"]], ["Coding language", LANGUAGE_QUESTION_BANK[a["language"]]["name"]],
                   ["Time Taken", f"{a['time_taken'] // 60} min {a['time_taken'] % 60} sec"]], colWidths=[210, 210])
        t.setStyle(TableStyle(grid))
        story += [t, Spacer(1, 14), Paragraph("Stage Analysis", styles["Heading2"])]
        t = Table([["Stage", "Accuracy"]] + [[s, f"{v}%"] for s, v in stages.items()], colWidths=[260, 160])
        t.setStyle(TableStyle(grid))
        story += [t, Spacer(1, 14), Paragraph("Responses", styles["Heading2"])]
        t = Table([["Q", "Stage", "Question", "Your answer", "Correct answer", "Result"]] + [
            [r["question_no"], r["factor"], Paragraph(r["question"], styles["BodyText"]),
             Paragraph(r["answer"], styles["BodyText"]), Paragraph(r["correct_answer"], styles["BodyText"]),
             "Correct" if r["score"] else "Review"] for r in answers],
            colWidths=[20, 68, 150, 100, 100, 45], repeatRows=1)
        t.setStyle(TableStyle(grid + [("FONTSIZE", (0, 0), (-1, -1), 7)]))
        story += [t, Spacer(1, 14), Paragraph("Recommended practice", styles["Heading2"])]
        for s, v in stages.items():
            story += [Paragraph(f"<b>{s} ({v}%):</b> {STAGE_ADVICE[s]}", styles["BodyText"]), Spacer(1, 5)]
        story += [Spacer(1, 10), Paragraph("This is a practice indicator, not a guarantee of interview or placement outcomes.",
                                           styles["BodyText"])]
    SimpleDocTemplate(path, pagesize=A4, rightMargin=35, leftMargin=35, topMargin=35, bottomMargin=35).build(story)
    return path


@app.route("/download/<kind>/<int:aid>")
@require("student")
def download(u, kind, aid):
    if kind not in ("self", "placement"):
        abort(404)
    path = build_pdf(kind, aid, u["id"])
    if not path:
        abort(404)
    return send_file(path, as_attachment=True)


@app.route("/send-report/<kind>/<int:aid>", methods=["GET", "POST"])
@require("student")
def send_report(u, kind, aid):
    if kind not in ("self", "placement"):
        abort(404)
    label = "Self Assessment" if kind == "self" else "IT Placement Analysis"
    back = url_for("self_result", aid=aid) if kind == "self" else url_for("placement_result", aid=aid)
    if request.method == "GET":
        return render_template("send_report.html", kind=kind, aid=aid, label=label, back=back)
    _, from_addr = parseaddr(request.form.get("from_email", "").strip())
    _, to_addr = parseaddr(request.form.get("to_email", "").strip())
    subject = request.form.get("subject", "").strip() or f"{label} Report #{aid}"
    if "@" not in from_addr or "@" not in to_addr:
        flash("Please enter valid From and To email addresses.", "error")
        return redirect(url_for("send_report", kind=kind, aid=aid))
    host = os.environ.get("SMTP_HOST", "").strip()
    port = int(os.environ.get("SMTP_PORT", "587") or 587)
    user = os.environ.get("SMTP_USERNAME", "").strip()
    pw = os.environ.get("SMTP_PASSWORD", "")
    use_ssl = os.environ.get("SMTP_USE_SSL", "0").lower() in ("1", "true", "yes")
    use_tls = os.environ.get("SMTP_USE_TLS", "1").lower() in ("1", "true", "yes")
    missing = [k for k, v in [("SMTP_HOST", host), ("SMTP_USERNAME", user), ("SMTP_PASSWORD", pw)] if not v]
    if missing:
        flash("Email is not configured. Missing: " + ", ".join(missing) + ". Set them in .env and restart.", "error")
        return redirect(url_for("send_report", kind=kind, aid=aid))
    try:
        pdf = build_pdf(kind, aid, u["id"])
        if not pdf:
            raise RuntimeError("Report could not be generated.")
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = user, to_addr, subject
        if from_addr.lower() != user.lower():
            msg["Reply-To"] = from_addr
        msg.set_content(f"Hello,\n\nPlease find the {label} report attached.\n\nThis is a practice / self-awareness "
                        "tool and not a diagnosis or a guarantee of outcomes.\n")
        with open(pdf, "rb") as f:
            msg.add_attachment(f.read(), maintype="application", subtype="pdf", filename=os.path.basename(pdf))
        if use_ssl:
            with smtplib.SMTP_SSL(host, port, timeout=20) as srv:
                srv.login(user, pw)
                srv.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=20) as srv:
                srv.ehlo()
                if use_tls:
                    srv.starttls()
                    srv.ehlo()
                srv.login(user, pw)
                srv.send_message(msg)
        flash(f"Report sent to {to_addr}.", "success")
    except Exception as exc:  # noqa: BLE001
        app.logger.exception("Report email failed")
        flash(f"Could not send email: {exc}", "error")
    return redirect(back)


# --------------------------------------------------------------------- admin
@app.route("/admin")
@require("admin")
def admin(u):
    con = db()
    stats = {
        "students": con.execute("SELECT COUNT(*) c FROM users WHERE role='student'").fetchone()["c"],
        "faculty": con.execute("SELECT COUNT(*) c FROM users WHERE role='faculty'").fetchone()["c"],
        "classes": con.execute("SELECT COUNT(*) c FROM classes").fetchone()["c"],
        "self": con.execute("SELECT COUNT(*) c FROM wellness_assessments").fetchone()["c"],
        "placement": con.execute("SELECT COUNT(*) c FROM placement_assessments").fetchone()["c"],
    }
    recent = con.execute("SELECT p.*, u.name, u.email FROM placement_assessments p JOIN users u ON u.id=p.user_id "
                         "ORDER BY p.id DESC LIMIT 10").fetchall()
    con.close()
    return render_template("admin.html", stats=stats, recent=recent)


if __name__ == "__main__":
    debug = _flag("FLASK_DEBUG", "0")
    # The Werkzeug debugger allows remote code execution, so debug mode stays on this PC only.
    host = "127.0.0.1" if debug else os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "5000"))
    ssl_ctx = None
    if USE_HTTPS and not BEHIND_PROXY:
        ensure_self_signed_cert()
        ssl_ctx = (CERT_FILE, KEY_FILE)
    scheme = "https" if ssl_ctx else "http"
    print(f"\nOpen on this computer:  {scheme}://localhost:{port}")
    if host == "0.0.0.0":
        for ip in _lan_ips():
            print(f"Students on your network: {scheme}://{ip}:{port}")
    if ssl_ctx and CERT_FILE.startswith(CERT_DIR):
        print("Self-signed certificate: browsers show a one-time warning. Choose Advanced -> Continue.\n")
    app.run(host=host, port=port, debug=debug, ssl_context=ssl_ctx)
