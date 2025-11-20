import os
import hashlib
import sqlite3
import requests
import secrets
import random
from datetime import datetime
from functools import wraps
from typing import List, Tuple
import re
from urllib.parse import urlparse, parse_qs

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
)

# -------------------------
# إعدادات أساسية
# -------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "security-database-demo")

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

DB_PATH = "scanner.db"

DANGEROUS_URLS_ENDPOINT = (
    "https://raw.githubusercontent.com/MutebSA/security-database/refs/heads/main/dangerous_urls.json"
)
MALWARE_SIGNATURES_ENDPOINT = (
    "https://raw.githubusercontent.com/MutebSA/security-database/refs/heads/main/malware_signatures.json"
)


# -------------------------
# دوال مساعدة للداتا بيس
# -------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """إنشاء الجداول في SQLite إذا ما كانت موجودة."""
    conn = get_db()
    cur = conn.cursor()

    # جدول نتائج الفحص
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT,
            target TEXT,
            score INTEGER,
            category TEXT,
            notes TEXT,
            created_at TEXT
        )
        """
    )

    # جدول المستخدمين (مع التفعيل)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            password TEXT,
            is_verified INTEGER DEFAULT 0,
            verification_token TEXT
        )
        """
    )

    # إنشاء أدمن افتراضي إذا ما كان موجود
    cur.execute("SELECT id FROM users WHERE username = ?", (ADMIN_USERNAME,))
    if cur.fetchone() is None:
        cur.execute(
            """
            INSERT INTO users (full_name, username, email, password, is_verified, verification_token)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("Admin", ADMIN_USERNAME, "admin@example.com", ADMIN_PASSWORD, 1, None),
        )

    conn.commit()
    conn.close()


def save_scan(scan_type: str, target: str, score: int, category: str, notes: List[str]):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO scans (scan_type, target, score, category, notes, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            scan_type,
            target,
            score,
            category,
            "; ".join(notes),
            datetime.utcnow().isoformat(),
        ),
    )
    conn.commit()
    conn.close()


# استدعاء إنشاء الداتا بيس عند تشغيل التطبيق
init_db()


# -------------------------
# ديكوريتر حماية الصفحات
# -------------------------
def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    return wrapper


# -------------------------
# دوال مساعدة للفحص
# -------------------------
def fetch_database(url: str, key: str) -> List[str]:
    """جلب بيانات JSON من GitHub وإرجاع القائمة المطلوبة."""
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    payload = response.json()
    return payload.get(key, [])


def calculate_risk_category(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 40:
        return "Elevated"
    if score >= 20:
        return "Medium"
    return "Low"


def analyze_url(target_url: str) -> Tuple[int, List[str]]:
    """
    تحليل رابط باستخدام قواعد متعددة:
    - قائمة الروابط الخطيرة من GitHub
    - كلمات مشبوهة في المسار / الدومين
    - TLD مشبوهة
    - استخدام IP، بورت غريب، HTTP بدون تشفير
    - بارامترات حساسة في الـ query
    - طول الرابط
    """
    raw_url = target_url.strip()
    url = raw_url.lower()
    notes: List[str] = []
    score = 10  # base base

    if not url:
        return 0, ["No URL provided."]

    # نحاول نعمل parse للرابط
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
    except Exception:
        return 50, ["Malformed URL: parsing failed. Needs manual review."]

    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    full_for_match = f"{host}{path}{query}".lower()

    # 1) التطابق مع قاعدة GitHub
    try:
        dangerous_urls = fetch_database(DANGEROUS_URLS_ENDPOINT, "dangerous_urls")
    except Exception:
        dangerous_urls = []

    for dangerous in dangerous_urls:
        if dangerous.lower() in full_for_match:
            score += 70
            notes.append(f"Matches known malicious indicator from feed: '{dangerous}'")

    # 2) كلمات مشبوهة في الرابط
    suspicious_keywords = [
        "login",
        "signin",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "security",
        "bank",
        "payment",
        "paypal",
        "free",
        "gift",
        "bonus",
        "reward",
        "crypto",
        "wallet",
    ]
    keyword_hits = [kw for kw in suspicious_keywords if kw in full_for_match]
    if keyword_hits:
        k_score = min(10 + 5 * len(keyword_hits), 30)  # حد أعلى 30
        score += k_score
        notes.append(
            f"Suspicious keywords in URL ({len(keyword_hits)}): "
            + ", ".join(keyword_hits)
        )

    # 3) TLD مشبوهة
    risky_tlds = [".ru", ".cn", ".tk", ".xyz", ".top", ".zip", ".mov"]
    for tld in risky_tlds:
        if host.endswith(tld):
            score += 15
            notes.append(f"Suspicious TLD detected: {tld}")
            break

    # 4) استخدام IP بدل دومين
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    if re.match(ip_pattern, host):
        score += 25
        notes.append("URL uses raw IP address instead of domain: common in attacks.")

    # 5) بورت غريب
    if parsed.port and parsed.port not in (80, 443):
        score += 10
        notes.append(f"Non-standard port detected: {parsed.port}")

    # 6) HTTP / HTTPS
    scheme = parsed.scheme.lower()
    if scheme == "https":
        score -= 5
        notes.append("HTTPS detected: reduced transport risk (does not guarantee safety).")
    elif scheme == "http":
        score += 10
        notes.append("HTTP detected: no transport security.")
    else:
        score += 5
        notes.append(f"Non-standard or missing scheme '{scheme}': may be obfuscated.")

    # 7) بارامترات حساسة في الـ query
    sensitive_params = ["password", "pass", "token", "session", "bank", "card", "cc", "otp"]
    parsed_qs = parse_qs(query)
    found_params = [p for p in parsed_qs.keys() if any(sp in p.lower() for sp in sensitive_params)]
    if found_params:
        score += 20
        notes.append(
            "Sensitive-looking query parameters detected: " + ", ".join(found_params)
        )

    # 8) طول الرابط
    total_len = len(raw_url)
    if total_len > 200:
        score += 20
        notes.append(f"Very long URL ({total_len} chars): often used in obfuscation.")
    elif total_len > 100:
        score += 10
        notes.append(f"Long URL ({total_len} chars): may include tracking or obfuscation.")

    # ضبط النطاق 0–100
    score = max(0, min(score, 100))

    # لو مافي أي ملاحظات خطيرة
    if score <= 20 and not notes:
        notes.append("No strong indicators found. Still treat unknown URLs with caution.")

    return score, notes



def analyze_file(file_storage) -> Tuple[int, List[str]]:
    """تحليل ملف باستخدام تواقيع برمجيات خبيثة."""
    if file_storage.filename == "":
        return 0, ["No file selected."]

    file_bytes = file_storage.read()
    file_storage.stream.seek(0)

    notes: List[str] = []
    score = 15

    sha256 = hashlib.sha256(file_bytes).hexdigest()
    notes.append(f"SHA-256: {sha256}")

    try:
        content_str = file_bytes.decode("utf-8", errors="ignore")
    except Exception:
        content_str = ""

    malware_signatures = fetch_database(
        MALWARE_SIGNATURES_ENDPOINT, "malware_signatures"
    )

    for signature in malware_signatures:
        if signature.lower() in content_str.lower():
            notes.append(f"Detected malware signature: {signature}")
            score += 70

    if len(file_bytes) > 5 * 1024 * 1024:
        notes.append("Large file (>5MB): flagged for manual review.")
        score += 10

    score = max(0, min(score, 100))
    return score, notes


# -------------------------
# Routes الواجهة
# -------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan/url", methods=["GET", "POST"])
def scan_url():
    if request.method == "GET":
        return render_template("url_scan.html")

    target_url = request.form.get("target_url", "")
    if not target_url:
        flash("Please enter a URL to scan.", "warning")
        return redirect(url_for("scan_url"))

    score, notes = analyze_url(target_url)
    category = calculate_risk_category(score)
    save_scan("URL", target_url, score, category, notes)

    return render_template(
        "result.html",
        subject=target_url,
        score=score,
        category=category,
        notes=notes,
        scan_type="URL Scan",
    )


@app.route("/scan/file", methods=["GET", "POST"])
def scan_file():
    if request.method == "GET":
        return render_template("file_scan.html")

    uploaded_file = request.files.get("file")
    if uploaded_file is None or uploaded_file.filename == "":
        flash("Please choose a file to scan.", "warning")
        return redirect(url_for("scan_file"))

    score, notes = analyze_file(uploaded_file)
    category = calculate_risk_category(score)
    save_scan("File", uploaded_file.filename, score, category, notes)

    return render_template(
        "result.html",
        subject=uploaded_file.filename,
        score=score,
        category=category,
        notes=notes,
        scan_type="File Scan",
    )


# -------------------------
# تسجيل الدخول / التسجيل / التفعيل
# -------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password),
    )
    user = cur.fetchone()
    conn.close()

    if not user:
        flash("بيانات الدخول غير صحيحة.", "danger")
        return redirect(url_for("login"))

    if user["is_verified"] == 0:
        flash("حسابك غير مفعّل. فعّل حسابك من رابط التفعيل أولاً.", "warning")
        return redirect(url_for("login"))

    session["user"] = user["username"]
    flash("تم تسجيل الدخول بنجاح.", "success")
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("تم تسجيل الخروج.", "info")
    return redirect(url_for("index"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if "user" in session:
        return redirect(url_for("dashboard"))

    if request.method == "GET":
        return render_template("register.html")

    full_name = request.form.get("full_name", "").strip()
    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "").strip()
    confirm = request.form.get("confirm", "").strip()

    if not full_name or not username or not email or not password or not confirm:
        flash("جميع الحقول مطلوبة.", "warning")
        return redirect(url_for("register"))

    if password != confirm:
        flash("كلمة المرور غير متطابقة.", "danger")
        return redirect(url_for("register"))

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "SELECT * FROM users WHERE username = ? OR email = ?",
        (username, email),
    )
    existing = cur.fetchone()
    if existing:
        flash("اسم المستخدم أو البريد مستخدم مسبقاً.", "danger")
        conn.close()
        return redirect(url_for("register"))

    token = secrets.token_urlsafe(32)

    cur.execute(
        """
        INSERT INTO users (full_name, username, email, password, is_verified, verification_token)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (full_name, username, email, password, 0, token),
    )
    conn.commit()
    conn.close()

    verify_link = url_for("verify_email", token=token, _external=True)
    flash("تم إنشاء الحساب! اضغط على رابط التفعيل للتحقق من حسابك:", "success")
    flash(verify_link, "info")

    return redirect(url_for("login"))


@app.route("/verify/<token>", methods=["GET", "POST"])
def verify_email(token):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE verification_token = ?", (token,))
    row = cur.fetchone()

    if not row:
        conn.close()
        flash("رابط التفعيل غير صالح أو مستخدم من قبل.", "danger")
        return redirect(url_for("login"))

    user_id = row["id"]

    if request.method == "GET":
        a = random.randint(1, 9)
        b = random.randint(1, 9)
        answer = a + b

        session["verify_answer"] = str(answer)
        session["verify_user_id"] = user_id

        question_text = f"كم حاصل {a} + {b} ؟"
        conn.close()
        return render_template("verify_challenge.html", question=question_text)

    # POST: تحقق من الإجابة
    user_answer = request.form.get("answer", "").strip()
    correct_answer = session.get("verify_answer")
    stored_user_id = session.get("verify_user_id")

    if not correct_answer or not stored_user_id:
        conn.close()
        flash("حدث خطأ في عملية التحقق. حاول مرة أخرى.", "danger")
        return redirect(url_for("login"))

    if user_answer != correct_answer:
        conn.close()
        flash("إجابة التحقق غير صحيحة. حاول مرة أخرى.", "danger")
        return render_template("verify_challenge.html", question="حاول مرة أخرى 👇")

    cur.execute(
        "UPDATE users SET is_verified = 1, verification_token = NULL WHERE id = ?",
        (stored_user_id,),
    )
    conn.commit()
    conn.close()

    session.pop("verify_answer", None)
    session.pop("verify_user_id", None)

    return render_template("verify_success.html")


# -------------------------
# Dashboard + Profile
# -------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, scan_type, target, score, category, notes, created_at "
        "FROM scans ORDER BY id DESC LIMIT 100"
    )
    scans = cur.fetchall()
    conn.close()
    return render_template("dashboard.html", scans=scans)


@app.route("/profile")
@login_required
def profile():
    username = session.get("user")
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT full_name, username, email, is_verified FROM users WHERE username = ?",
        (username,),
    )
    user = cur.fetchone()
    conn.close()

    if not user:
        flash("المستخدم غير موجود.", "danger")
        return redirect(url_for("index"))

    return render_template("profile.html", user=user)


# -------------------------
# أخطاء
# -------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template("index.html"), 404


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
