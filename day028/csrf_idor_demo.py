"""
Day 028 - CSRF and IDOR Demo
100 Days of Cybersecurity by Sudeep Ravichandran

Demonstrates CSRF and IDOR vulnerabilities alongside
secure implementations.

Run: python3 csrf_idor_demo.py
Requires: pip install flask
Visit: http://127.0.0.1:5000
"""

from flask import Flask, request, jsonify, session
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Mock database
USERS = {
    1: {"username": "alice", "email": "alice@example.com", "balance": 1000},
    2: {"username": "bob",   "email": "bob@example.com",   "balance": 500},
    3: {"username": "carol", "email": "carol@example.com", "balance": 2500},
}

CSRF_TOKENS = {}


# ── Auth helpers ──────────────────────────────────────────────

@app.route("/login", methods=["POST"])
def login():
    user_id = int(request.json.get("user_id", 1))
    if user_id in USERS:
        session["user_id"] = user_id
        token = secrets.token_hex(32)
        CSRF_TOKENS[user_id] = token
        return jsonify({
            "status": "logged in",
            "user": USERS[user_id]["username"],
            "csrf_token": token
        })
    return jsonify({"status": "failed"}), 401


# ── IDOR - Vulnerable ─────────────────────────────────────────

@app.route("/api/users/<int:user_id>")
def get_user_vulnerable(user_id):
    """❌ No authorisation check - any logged-in user gets any profile."""
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    if user_id in USERS:
        return jsonify({
            "user": USERS[user_id],
            "warning": "IDOR: any user_id returns data"
        })
    return jsonify({"error": "Not found"}), 404


# ── IDOR - Secure ─────────────────────────────────────────────

@app.route("/api/users/<int:user_id>/secure")
def get_user_secure(user_id):
    """✅ Users can only access their own profile."""
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    # ✅ Check that the requested ID matches the logged-in user
    if session["user_id"] != user_id:
        return jsonify({"error": "Forbidden - not your profile"}), 403

    return jsonify({"user": USERS[user_id]})


# ── CSRF - Vulnerable Transfer ────────────────────────────────

@app.route("/transfer/vulnerable", methods=["POST"])
def transfer_vulnerable():
    """❌ No CSRF token - any site can trigger this with victim's cookies."""
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    amount = int(request.json.get("amount", 0))
    to_user = int(request.json.get("to", 0))
    from_user = session["user_id"]

    if to_user not in USERS or amount <= 0:
        return jsonify({"error": "Invalid"}), 400

    USERS[from_user]["balance"] -= amount
    USERS[to_user]["balance"] += amount

    return jsonify({
        "status": "transferred",
        "amount": amount,
        "to": USERS[to_user]["username"],
        "warning": "CSRF vulnerable - no token checked"
    })


# ── CSRF - Secure Transfer ────────────────────────────────────

@app.route("/transfer/secure", methods=["POST"])
def transfer_secure():
    """✅ CSRF token required - cross-site requests rejected."""
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    # ✅ Validate CSRF token
    provided_token = request.json.get("csrf_token", "")
    expected_token = CSRF_TOKENS.get(session["user_id"], "")

    if not secrets.compare_digest(provided_token, expected_token):
        return jsonify({"error": "Invalid CSRF token - request rejected"}), 403

    amount = int(request.json.get("amount", 0))
    to_user = int(request.json.get("to", 0))
    from_user = session["user_id"]

    if to_user not in USERS or amount <= 0:
        return jsonify({"error": "Invalid"}), 400

    USERS[from_user]["balance"] -= amount
    USERS[to_user]["balance"] += amount

    return jsonify({
        "status": "transferred",
        "amount": amount,
        "to": USERS[to_user]["username"]
    })


@app.route("/")
def index():
    return """
    <html><body>
    <h1>CSRF + IDOR Demo - Day 028</h1>

    <h3>Step 1: Login as Alice (user_id: 1)</h3>
    <pre>curl -s -c cookies.txt -X POST http://127.0.0.1:5000/login
  -H "Content-Type: application/json"
  -d '{"user_id": 1}'</pre>

    <h3>IDOR Test:</h3>
    <pre>
Vulnerable (returns anyone's data):
  curl -s -b cookies.txt http://127.0.0.1:5000/api/users/2

Secure (returns 403 for other users):
  curl -s -b cookies.txt http://127.0.0.1:5000/api/users/2/secure
    </pre>

    <h3>CSRF Test:</h3>
    <pre>
Vulnerable (no token needed):
  curl -s -b cookies.txt -X POST http://127.0.0.1:5000/transfer/vulnerable
  -H "Content-Type: application/json"
  -d '{"amount": 100, "to": 2}'

Secure (token required - get from login response):
  curl -s -b cookies.txt -X POST http://127.0.0.1:5000/transfer/secure
  -H "Content-Type: application/json"
  -d '{"amount": 100, "to": 2, "csrf_token": "TOKEN_FROM_LOGIN"}'
    </pre>
    </body></html>
    """


if __name__ == "__main__":
    print("=" * 50)
    print("  CSRF + IDOR Demo - Day 028")
    print("  100 Days of Cybersecurity")
    print("=" * 50)
    print("\n  Visit: http://127.0.0.1:5000 for instructions")
    app.run(debug=False)