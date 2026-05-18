# 🔐 PassGuard — Password Strength Analyzer

A full-stack local web tool built with **Python Flask** + **SQLite**.  
Runs entirely on your machine at `http://127.0.0.1:5000`.

---

## 📁 Project Structure

```
password_analyzer/
├── app.py               ← Flask backend (all logic lives here)
├── requirements.txt     ← Python dependencies (only Flask needed)
├── password_history.db  ← SQLite DB (auto-created on first run)
├── README.md
└── templates/
    └── index.html       ← Full frontend UI (HTML + CSS + JS)
```

---

## ⚙️ Requirements

| Tool | Version | Notes |
|------|---------|-------|
| Python | 3.8+ | `python --version` to check |
| pip | any | comes with Python |
| Flask | 3.x | installed via pip |
| VS Code | any | recommended editor |

> **No database server needed** — SQLite is built into Python.

---

## 🚀 Setup & Run (Step-by-Step)

### Step 1 — Open the project in VS Code

```
File → Open Folder → select the `password_analyzer` folder
```

### Step 2 — Open a terminal in VS Code

```
Terminal → New Terminal   (or press Ctrl + ` )
```

### Step 3 — (Recommended) Create a virtual environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

You'll see `(venv)` appear in your terminal prompt.

### Step 4 — Install dependencies

```bash
pip install -r requirements.txt
```

### Step 5 — Run the app

```bash
python app.py
```

You'll see:

```
=======================================================
  🔐  Password Strength Analyzer
  Running at: http://127.0.0.1:5000
  Press Ctrl+C to stop
=======================================================
```

### Step 6 — Open your browser

Navigate to: **http://127.0.0.1:5000**

---

## 🛑 How to Stop

Press `Ctrl + C` in the VS Code terminal.

---

## ✨ Features

### 🔍 Real-Time Analysis
- Score 0–100 with color-coded strength meter
- Entropy calculation (bits of randomness)
- Estimated time to crack (brute force, GPU speed)

### ✅ Complexity Checklist
- Minimum length (8 / 12 / 16 chars)
- Uppercase, lowercase, numbers, symbols
- Common password detection (top-100 list)
- Password reuse detection (checks SQLite DB)

### 💡 Password Generator
- **Random** — 18-char cryptographically secure string
- **Passphrase** — 4 random words + number + symbol (memorable)
- **Short** — 12-char for less sensitive accounts
- One-click copy to clipboard

### 🗄️ SQLite History (Password Reuse Detection)
- Passwords are **hashed (SHA-256)** before storage — never plain text
- "Save to History" stores current password hash
- Future entries of the same password are flagged as reused
- "Clear History" wipes the DB

---

## 🌐 API Endpoints (for developers / testing)

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/` | Web UI |
| POST | `/api/analyze` | Analyze a password |
| POST | `/api/save` | Save password hash to DB |
| GET | `/api/generate` | Get 3 generated passwords |
| GET | `/api/history/count` | Count saved passwords |
| POST | `/api/history/clear` | Clear all history |

**Example (using curl):**
```bash
curl -X POST http://127.0.0.1:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"password": "MyP@ssw0rd!"}'
```

---

## 🔒 Security Notes

- Passwords are **never logged or stored in plain text**
- SHA-256 hash is a one-way function
- The DB file stays on your local machine only
- `debug=True` is set for development — remove it before deploying

---

## 🐛 Troubleshooting

| Problem | Fix |
|---------|-----|
| `ModuleNotFoundError: flask` | Run `pip install flask` |
| `Address already in use` | Change port in `app.py`: `app.run(port=5001)` |
| Browser shows "can't connect" | Make sure `python app.py` is still running |
| `python` not found on Windows | Use `py app.py` instead |
