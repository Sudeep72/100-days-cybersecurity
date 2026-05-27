"""
Day 026 - SQL Injection Demo
100 Days of Cybersecurity by Sudeep Ravichandran

Shows a vulnerable login implementation and the
one-line fix that prevents SQL injection entirely.

Run: python3 sqli_demo.py
Requires: pip install flask
"""

from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)
DB = "demo.db"


def init_db():
    """Create demo database with sample users."""
    conn = sqlite3.connect(DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            role TEXT
        )
    """)
    conn.execute("DELETE FROM users")
    conn.executemany(
        "INSERT INTO users VALUES (?, ?, ?, ?)",
        [
            (1, "admin", "supersecret", "admin"),
            (2, "alice", "password123", "user"),
            (3, "bob",   "letmein",     "user"),
        ]
    )
    conn.commit()
    conn.close()


@app.route("/login/vulnerable", methods=["POST"])
def login_vulnerable():
    username = request.json.get("username", "")
    password = request.json.get("password", "")
    conn = sqlite3.connect(DB)

    # ❌ VULNERABLE: direct string concatenation
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    print(f"\n[VULNERABLE] Query: {query}")

    result = conn.execute(query).fetchone()
    conn.close()

    if result:
        return jsonify({"status": "success", "user": result[1], "role": result[3]})
    return jsonify({"status": "failed"})


@app.route("/login/secure", methods=["POST"])
def login_secure():
    username = request.json.get("username", "")
    password = request.json.get("password", "")
    conn = sqlite3.connect(DB)

    # ✅ SECURE: parameterised query
    query = "SELECT * FROM users WHERE username=? AND password=?"
    print(f"\n[SECURE] Query: {query} | Params: ({username}, ***)")

    result = conn.execute(query, (username, password)).fetchone()
    conn.close()

    if result:
        return jsonify({"status": "success", "user": result[1], "role": result[3]})
    return jsonify({"status": "failed"})


if __name__ == "__main__":
    init_db()
    print("=" * 55)
    print("  SQLi Demo - Day 026")
    print("  100 Days of Cybersecurity")
    print("=" * 55)
    print("\nVulnerable endpoint: POST /login/vulnerable")
    print("Secure endpoint:     POST /login/secure")
    print("\nTry this SQLi payload on vulnerable:")
    print('  username: admin\'--')
    print('  password: anything')
    print("\nSame payload on secure endpoint won\'t work.")
    print("\nServer: http://127.0.0.1:5000\n")
    app.run(debug=False)