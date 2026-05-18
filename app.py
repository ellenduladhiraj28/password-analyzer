"""
Password Strength Analyzer
Flask application with SQLite password history database.
Run: python app.py  →  open http://127.0.0.1:5000
"""

import re
import math
import hashlib
import sqlite3
import string
import secrets
from datetime import datetime
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)
DB_PATH = "password_history.db"

# ─── Database Setup ───────────────────────────────────────────────────────────

def init_db():
    """Create the password history table if it doesn't exist."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS password_history (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id   TEXT    NOT NULL DEFAULT 'default_user',
                pw_hash   TEXT    NOT NULL,
                created   TEXT    NOT NULL
            )
        """)
        conn.commit()

def hash_password(password: str) -> str:
    """SHA-256 hash — we NEVER store plain-text passwords."""
    return hashlib.sha256(password.encode()).hexdigest()

def is_password_reused(password: str, user_id: str = "default_user") -> bool:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT 1 FROM password_history WHERE pw_hash=? AND user_id=?",
            (hash_password(password), user_id)
        ).fetchone()
    return row is not None

def save_password(password: str, user_id: str = "default_user"):
    """Store hashed password in history."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO password_history (user_id, pw_hash, created) VALUES (?,?,?)",
            (user_id, hash_password(password), datetime.utcnow().isoformat())
        )
        conn.commit()

def get_history_count(user_id: str = "default_user") -> int:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM password_history WHERE user_id=?", (user_id,)
        ).fetchone()
    return row[0] if row else 0

# ─── Password Analysis ────────────────────────────────────────────────────────

COMMON_PASSWORDS = {
    "password","123456","password123","admin","letmein","welcome",
    "monkey","dragon","master","qwerty","abc123","iloveyou","sunshine",
    "princess","football","superman","batman","trustno1","shadow",
    "michael","jessica","password1","1234567890","passw0rd","hello123",
}

def calc_entropy(password: str) -> float:
    charset = 0
    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'\d',    password): charset += 10
    if re.search(r'[^a-zA-Z0-9]', password): charset += 32
    return len(password) * math.log2(charset) if charset else 0

def analyze_password(password: str):
    """Return a detailed analysis dict."""
    length    = len(password)
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d',    password))
    has_sym   = bool(re.search(r'[^a-zA-Z0-9]', password))
    is_common = password.lower() in COMMON_PASSWORDS
    reused    = is_password_reused(password)
    entropy   = calc_entropy(password)

    # ── Score 0-100 ──
    score = 0
    if length >= 8:  score += 15
    if length >= 12: score += 15
    if length >= 16: score += 10
    if has_lower: score += 10
    if has_upper: score += 10
    if has_digit: score += 10
    if has_sym:   score += 15
    if entropy >= 40:  score += 10
    if entropy >= 60:  score += 5
    if is_common: score = min(score, 10)
    if reused:    score = max(score - 20, 0)

    score = min(score, 100)

    if score < 25:   label, color = "Very Weak",  "#ef4444"
    elif score < 50: label, color = "Weak",        "#f97316"
    elif score < 70: label, color = "Fair",        "#eab308"
    elif score < 85: label, color = "Strong",      "#22c55e"
    else:            label, color = "Very Strong", "#10b981"

    # ── Issues list ──
    issues = []
    if length < 8:   issues.append("Too short — use at least 8 characters")
    if length < 12:  issues.append("Consider using 12+ characters for better security")
    if not has_upper: issues.append("Add uppercase letters (A-Z)")
    if not has_lower: issues.append("Add lowercase letters (a-z)")
    if not has_digit: issues.append("Add numbers (0-9)")
    if not has_sym:   issues.append("Add symbols (!@#$%^&*)")
    if is_common:     issues.append("⚠️  This is one of the most common passwords!")
    if reused:        issues.append("⚠️  You have used this password before!")

    crack_time = estimate_crack_time(entropy)

    return {
        "score": score, "label": label, "color": color,
        "entropy": round(entropy, 1),
        "length": length,
        "checks": {
            "length8": length >= 8,
            "length12": length >= 12,
            "length16": length >= 16,
            "upper": has_upper, "lower": has_lower,
            "digit": has_digit, "symbol": has_sym,
            "not_common": not is_common,
            "not_reused": not reused,
        },
        "issues": issues,
        "crack_time": crack_time,
        "reused": reused,
    }

def estimate_crack_time(entropy: float) -> str:
    guesses_per_sec = 1e10  # modern GPU
    seconds = (2 ** entropy) / guesses_per_sec
    if seconds < 1:      return "Instantly"
    if seconds < 60:     return f"{int(seconds)} seconds"
    if seconds < 3600:   return f"{int(seconds/60)} minutes"
    if seconds < 86400:  return f"{int(seconds/3600)} hours"
    if seconds < 2.6e6:  return f"{int(seconds/86400)} days"
    if seconds < 3.15e7: return f"{int(seconds/2.6e6)} months"
    if seconds < 3.15e9: return f"{int(seconds/3.15e7)} years"
    return "Centuries+"

# ─── Password Generator ───────────────────────────────────────────────────────

def generate_strong_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (re.search(r'[a-z]', pw) and re.search(r'[A-Z]', pw)
                and re.search(r'\d', pw) and re.search(r'[^a-zA-Z0-9]', pw)):
            return pw

def generate_passphrase() -> str:
    words = [
        "Tiger","Maple","Storm","River","Crystal","Phoenix","Velvet","Thunder",
        "Horizon","Silver","Blaze","Shadow","Falcon","Coral","Arctic","Mystic",
        "Ember","Glacier","Cobalt","Prism","Forge","Nomad","Zenith","Atlas",
    ]
    chosen = [secrets.choice(words) for _ in range(4)]
    num    = secrets.randbelow(9000) + 1000
    sym    = secrets.choice("!@#$%&")
    return f"{chosen[0]}{chosen[1]}{num}{chosen[2]}{chosen[3]}{sym}"

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data     = request.get_json(force=True)
    password = data.get("password", "")
    if not password:
        return jsonify({"error": "No password provided"}), 400
    result = analyze_password(password)
    result["history_count"] = get_history_count()
    return jsonify(result)

@app.route("/api/save", methods=["POST"])
def api_save():
    data     = request.get_json(force=True)
    password = data.get("password", "")
    if not password:
        return jsonify({"error": "No password"}), 400
    if is_password_reused(password):
        return jsonify({"saved": False, "message": "Password already in history"})
    save_password(password)
    return jsonify({"saved": True, "message": "Password saved to history",
                    "history_count": get_history_count()})

@app.route("/api/generate", methods=["GET"])
def api_generate():
    return jsonify({
        "random":     generate_strong_password(18),
        "passphrase": generate_passphrase(),
        "short":      generate_strong_password(12),
    })

@app.route("/api/history/count", methods=["GET"])
def api_history_count():
    return jsonify({"count": get_history_count()})

@app.route("/api/history/clear", methods=["POST"])
def api_history_clear():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM password_history WHERE user_id=?", ("default_user",))
        conn.commit()
    return jsonify({"cleared": True, "message": "History cleared"})

# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    print("\n" + "="*55)
    print("  🔐  Password Strength Analyzer")
    print("  Running at: http://127.0.0.1:5000")
    print("  Press Ctrl+C to stop")
    print("="*55 + "\n")
    app.run(debug=True, port=5000)
