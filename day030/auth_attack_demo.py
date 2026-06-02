"""
Day 030 - Authentication Attack Demo
100 Days of Cybersecurity by Sudeep Ravichandran

Demonstrates brute force and credential stuffing attacks
alongside defences: rate limiting, account lockout, MFA.

Run: python3 auth_attack_demo.py
Requires: pip install flask
"""

from flask import Flask, request, jsonify, session
import secrets
import time
from collections import defaultdict

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Mock user database
USERS = {
    "admin":  "SuperSecret123!",
    "alice":  "password123",
    "bob":    "letmein",
    "carol":  "Winter2024!",
}

# Track failed attempts
failed_attempts  = defaultdict(int)       # ip → count
lockout_until    = defaultdict(float)     # username → timestamp
request_times    = defaultdict(list)      # ip → [timestamps]

MAX_ATTEMPTS     = 5
LOCKOUT_SECONDS  = 300   # 5 minutes
RATE_LIMIT       = 10    # max requests per minute per IP


def is_rate_limited(ip):
    now = time.time()
    # Keep only attempts in last 60 seconds
    request_times[ip] = [t for t in request_times[ip] if now - t < 60]
    request_times[ip].append(now)
    return len(request_times[ip]) > RATE_LIMIT


def is_locked_out(username):
    if lockout_until[username] > time.time():
        remaining = int(lockout_until[username] - time.time())
        return True, remaining
    return False, 0


# ── Vulnerable - no protections ──────────────────────────────

@app.route("/login/vulnerable", methods=["POST"])
def login_vulnerable():
    """❌ No rate limiting, no lockout, no MFA."""
    data = request.json
    username = data.get("username", "")
    password = data.get("password", "")

    if USERS.get(username) == password:
        return jsonify({"status": "success", "user": username})
    return jsonify({"status": "failed", "message": "Invalid credentials"})


# ── Secure - rate limiting + lockout ─────────────────────────

@app.route("/login/secure", methods=["POST"])
def login_secure():
    """✅ Rate limiting + account lockout + timing-safe comparison."""
    ip = request.remote_addr
    data = request.json
    username = data.get("username", "")
    password = data.get("password", "")

    # ✅ Rate limiting by IP
    if is_rate_limited(ip):
        return jsonify({
            "status": "error",
            "message": "Too many requests - slow down"
        }), 429

    # ✅ Account lockout check
    locked, remaining = is_locked_out(username)
    if locked:
        return jsonify({
            "status": "locked",
            "message": f"Account locked. Try again in {remaining}s"
        }), 423

    # ✅ Timing-safe comparison (prevents timing attacks)
    stored = USERS.get(username, "")
    if stored and secrets.compare_digest(stored, password):
        failed_attempts[username] = 0  # reset on success
        return jsonify({"status": "success", "user": username})

    # ✅ Increment failed attempts
    failed_attempts[username] += 1
    if failed_attempts[username] >= MAX_ATTEMPTS:
        lockout_until[username] = time.time() + LOCKOUT_SECONDS
        return jsonify({
            "status": "locked",
            "message": f"Too many failures. Account locked for {LOCKOUT_SECONDS}s"
        }), 423

    remaining_attempts = MAX_ATTEMPTS - failed_attempts[username]
    return jsonify({
        "status": "failed",
        "message": f"Invalid credentials. {remaining_attempts} attempts remaining"
    })


@app.route("/status")
def status():
    """Show current lockout and attempt status."""
    return jsonify({
        "failed_attempts": dict(failed_attempts),
        "locked_accounts": {
            u: f"locked for {int(t - time.time())}s"
            for u, t in lockout_until.items()
            if t > time.time()
        }
    })


if __name__ == "__main__":
    print("=" * 55)
    print("  Auth Attack Demo - Day 030")
    print("  100 Days of Cybersecurity")
    print("=" * 55)
    print("\nVulnerable: POST /login/vulnerable")
    print("Secure:     POST /login/secure")
    print("Status:     GET  /status")
    print("\nTest brute force on vulnerable:")
    print('  for p in 123456 password letmein password123; do')
    print('    curl -s -X POST http://127.0.0.1:5000/login/vulnerable \\')
    print('    -H "Content-Type: application/json" \\')
    print('    -d \'{"username":"alice","password":"\'$p\'"}\'; echo')
    print('  done')
    print("\nServer: http://127.0.0.1:5000\n")
    app.run(debug=False)