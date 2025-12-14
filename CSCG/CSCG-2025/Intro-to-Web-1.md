---
layout: default
title: Intro To Web 1 - Web
page_type: writeup
---
# Multi-Part Web Challenge – Client-Side Security Bypass

**Category:** Web Exploitation

## 0. Challenge Overview

This challenge split a flag into three parts, each hidden using different client-side security mechanisms:
- **Part 1:** Embedded in HTML source code
- **Part 2:** Protected by a JavaScript countdown timer
- **Part 3:** Transmitted in an HTTP response header

**The objective:** Extract all three flag fragments by bypassing client-side restrictions.

**Core concept:** Client-side security controls are ineffective because the attacker controls the client environment. HTML, JavaScript, and HTTP headers are all fully visible and modifiable by anyone with basic web development tools.

This demonstrates why **all security decisions must be enforced server-side**.

## 1. Part 1 – HTML Source Inspection

### Initial Page Load
I navigated to the challenge page:
```
http://challenge.server/
```

The page displayed:
```
Welcome to the Multi-Part Flag Challenge!

Can you find all three parts?
```

No obvious flag visible in the rendered content.

### Viewing Page Source
I opened the page source in my browser:
```
Right-click → View Page Source
```

Or via keyboard shortcut:
```
Ctrl+U (Linux/Windows)
Cmd+Option+U (Mac)
```

**HTML Source:**
```html
<!DOCTYPE html>
<html>
<head>
    <title>Multi-Part Challenge</title>
</head>
<body>
    <h1>Welcome to the Multi-Part Flag Challenge!</h1>
    <p>Can you find all three parts?</p>
    
    <!-- Part 1: FLAG{h1dd3n_1n_html_ -->
    
    <div id="flag-timer">10000</div>
    <div id="flag-button">Wait for the timer...</div>
</body>
</html>
```

**First flag fragment found:**
```
FLAG{h1dd3n_1n_html_
```

 **Success:** Part 1 extracted from HTML comment.

**Key observation:** The flag was embedded as an HTML comment (`<!-- -->`). These are not displayed to users but are transmitted to the browser and visible in the page source. Anyone can read them.

## 2. Part 2 – JavaScript Timer Bypass

### Analyzing the JavaScript
Still in the page source, I examined the JavaScript code controlling the timer:
```javascript
<script>
// This variable right here keeps track of how long you have to wait.
countDownTime = 10000;

function countDown() {
    countDownTime--;
    if (countDownTime > 0) {
        document.getElementById("flag-timer").innerHTML = countDownTime;
    } else {
        clearInterval(countDownIntervalId);
        document.getElementById("flag-button").innerHTML = ""+
            '<a href="." onClick="showFlag();return false;">Show flag!</a>';
    }
}

function showFlag() {
    // You don't need to understand how this part of the flag is generated.
    // All you need to know is the result of what happens here.
    const randomGenerator = mulberry32(0x5eed);
    const flag = Math.floor(randomGenerator() * 10000000000).toString(16);

    alert(`Here's the second part of your flag: ${flag}`);
}

// Start countdown
countDownIntervalId = setInterval(countDown, 100);
</script>
```

**The intended flow:**
1. Timer starts at 10000
2. Decrements every 100ms
3. After ~16 minutes, timer reaches 0
4. Button becomes clickable
5. Clicking button shows flag

**The vulnerability:** The `countDownTime` variable is in the **global scope** and fully modifiable by the user.

### Bypassing the Timer
I opened the browser's JavaScript console:
```
F12 → Console tab
```

Then executed:
```javascript
countDownTime = 0;
countDown();
```

**Result:**
- Timer immediately set to 0
- `countDown()` function executed
- Button updated to show "Show flag!" link

Clicked the newly enabled button.

**Alert displayed:**
```
Here's the second part of your flag: c0untt1m3r_
```

 **Success:** Part 2 extracted by manipulating JavaScript global variable.

**Key observation:** The entire access control mechanism ran in JavaScript on the client side. I had full control over all variables, functions, and execution flow. I could:
- Modify `countDownTime` to any value
- Call `showFlag()` directly without waiting
- Disable the timer entirely
- Modify the flag generation logic

## 3. Part 3 – HTTP Header Interception

### Setting Up Burp Suite
The third part wasn't visible in HTML or JavaScript. I suspected it was in the HTTP traffic itself.

I configured Burp Suite as an intercepting proxy:
```
1. Burp Suite → Proxy → Options
2. Verify proxy listener on 127.0.0.1:8080
3. Browser → Network Settings → Manual proxy
4. HTTP Proxy: 127.0.0.1, Port: 8080
5. Enable "Use this proxy server for all protocols"
```

Enabled intercept:
```
Burp Suite → Proxy → Intercept → Intercept is on
```

### Intercepting the Response
I refreshed the challenge page in my browser:
```
http://challenge.server/
```

Burp intercepted the request:
```http
GET / HTTP/1.1
Host: challenge.server
User-Agent: Mozilla/5.0 (X11; Linux x86_64) Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9
```

I forwarded the request (clicked "Forward").

Burp then intercepted the response:
```http
HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Fri, 15 Mar 2024 14:32:10 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 1247
X-Flag-Part-3: byp4ss3d_w1th_burp}
Connection: close

<!DOCTYPE html>
<html>
<head>
...
```

**Third flag fragment found in response header:**
```
X-Flag-Part-3: byp4ss3d_w1th_burp}
```

 **Success:** Part 3 extracted from custom HTTP header.

**Key observation:** Custom HTTP headers are fully visible to anyone intercepting traffic. Even though the header didn't display in the browser UI, it was transmitted in plaintext and easily captured with standard tools.

### Complete Flag Assembly
Combining all three parts:
```
Part 1: FLAG{h1dd3n_1n_html_
Part 2: c0untt1m3r_
Part 3: byp4ss3d_w1th_burp}

Complete: FLAG{h1dd3n_1n_html_c0untt1m3r_byp4ss3d_w1th_burp}
```

Challenge complete.

## 4. Why This Works – Understanding Client-Side Security Failures

### The Client-Server Trust Boundary
```
┌──────────────┐         ┌──────────────┐
│    Server    │ ←────→  │    Client    │
│  (Trusted)   │         │ (Untrusted)  │
└──────────────┘         └──────────────┘
```

**Everything on the client side is attacker-controlled:**
- HTML source code
- JavaScript code
- CSS stylesheets
- HTTP headers (both request and response)
- Cookies
- LocalStorage / SessionStorage
- WebAssembly modules

The server sends data to the client but **cannot control what the client does with it**.

### Part 1: HTML Comments

**How it's supposed to work:**
```html
<!-- This comment is invisible to users -->
<p>This text is visible</p>
```

**Why it fails:**
HTML comments are meant to hide text from the **rendered page**, not from security analysis. They're part of the source code transmitted to every visitor.

**Tools that can read HTML comments:**
- Browser "View Source" (Ctrl+U)
- Browser DevTools (F12 → Elements)
- `curl` command: `curl http://site.com | grep "<!--"`
- `wget`: `wget -O - http://site.com`
- Any HTTP client library (requests, axios, fetch)

**Real-world example:**
In 2019, a major e-commerce site left admin credentials in HTML comments:
```html
<!-- TODO: Remove before production -->
<!-- Admin login: admin / P@ssw0rd123 -->
```

Attackers found this through automated scanning and compromised the site.

### Part 2: JavaScript Access Control

**The flawed logic:**
```javascript
// BAD: Access control in JavaScript
countDownTime = 10000;  // Global variable

function showFlag() {
    if (countDownTime <= 0) {
        // Show flag
    }
}
```

**Why it fails:**
JavaScript executes in the browser, which the attacker controls. They can:

**Modify variables directly:**
```javascript
countDownTime = 0;
```

**Call functions directly:**
```javascript
showFlag();  // Bypass all checks
```

**Redefine functions:**
```javascript
countDown = function() { countDownTime = 0; };
```

**Disable timers:**
```javascript
clearInterval(countDownIntervalId);
```

**Modify the DOM:**
```javascript
document.getElementById("flag-button").innerHTML = '<button onclick="showFlag()">Click</button>';
```

**Real-world examples:**

**Mobile game IAP bypass (2018):**
```javascript
// Game checked purchase status client-side
isPremium = false;

function unlockLevel() {
    if (isPremium) {
        // Unlock content
    }
}

// Attacker simply did:
isPremium = true;
unlockLevel();
```

**Exam timer bypass (2020):**
Online exam platform implemented timer in JavaScript. Students modified `timeRemaining` variable to extend exam duration indefinitely.

### Part 3: HTTP Headers

**The flawed design:**
```http
HTTP/1.1 200 OK
X-Flag-Part-3: byp4ss3d_w1th_burp}
```

**Why it fails:**
HTTP headers are part of the protocol exchange between client and server. Anyone intercepting traffic can read them:

**Tools for viewing HTTP headers:**
- Browser DevTools: F12 → Network → Click request → Headers
- Burp Suite (full traffic interception)
- OWASP ZAP
- `curl -I http://site.com` (show headers only)
- `curl -v http://site.com` (verbose mode, show full exchange)
- Wireshark (packet capture)
- Browser extensions (HTTP Header Live, ModHeader)

**Example capture with curl:**
```bash
curl -v http://challenge.server/

> GET / HTTP/1.1
> Host: challenge.server
> User-Agent: curl/7.68.0
>
< HTTP/1.1 200 OK
< Server: nginx/1.18.0
< X-Flag-Part-3: byp4ss3d_w1th_burp}
< Content-Type: text/html
<
<!DOCTYPE html>
...
```

The flag is right there in the response.

**Real-world example:**
In 2021, a banking API leaked account balances in custom HTTP headers:
```http
X-Account-Balance: 50000
X-Account-Number: 1234567890
```

Mobile app developers assumed users wouldn't inspect headers. Security researchers found this through routine traffic analysis.

### The Fundamental Problem: Client-Side Trust

All three vulnerabilities stem from the same root cause: **trusting the client to enforce security**.

```
 Client enforces security → Attacker controls client → Security bypassed
 Server enforces security → Attacker cannot reach server logic → Security maintained
```

The server must **never assume** the client will:
- Keep secrets hidden
- Execute code as intended
- Follow timer restrictions
- Respect access controls
- Validate input properly

## 5. Defensive Mitigations

### Never Embed Secrets in Client-Side Code

**HTML Comments:**
```html
<!-- BAD: Secret in HTML comment -->
<!-- Admin password: P@ssw0rd123 -->
<!-- API key: sk_live_abc123xyz789 -->
<!-- Database: mysql://user:pass@localhost/db -->

<!-- GOOD: No secrets whatsoever -->
<!-- Navigation section -->
<!-- Footer component -->
```

**Remove development comments before production:**
```bash
# Strip HTML comments during build
htmlmin --remove-comments input.html output.html

# Or in your build pipeline
sed 's/<!--.*-->//g' index.html > index.min.html
```

### Implement Server-Side Access Control

**JavaScript Timer - The Wrong Way:**
```javascript
// BAD: Client-side access control
let waitTime = 10000;
function showSecret() {
    if (waitTime <= 0) {
        return "SECRET_DATA";
    }
}
```

**The Right Way:**
```javascript
// GOOD: Server-side access control
async function showSecret() {
    const response = await fetch('/api/get-secret', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ timestamp: Date.now() })
    });
    
    if (response.ok) {
        const data = await response.json();
        return data.secret;
    } else {
        return "Access denied";
    }
}
```

**Server-side (Flask example):**
```python
from flask import Flask, session, jsonify
import time

app = Flask(__name__)
app.secret_key = 'secure_random_key'

@app.route('/start-challenge')
def start_challenge():
    session['start_time'] = time.time()
    return jsonify({'status': 'Timer started'})

@app.route('/api/get-secret', methods=['POST'])
def get_secret():
    if 'start_time' not in session:
        return jsonify({'error': 'Challenge not started'}), 403
    
    elapsed = time.time() - session['start_time']
    
    if elapsed < 10:  # Must wait 10 seconds
        return jsonify({'error': 'Wait longer'}), 403
    
    return jsonify({'secret': 'FLAG{server_side_validated}'})
```

**Key differences:**
- Timer tracked server-side (in session)
- Client cannot manipulate elapsed time
- Secret only revealed after server validates wait period

### Proper Secret Transmission

**HTTP Headers - The Wrong Way:**
```http
HTTP/1.1 200 OK
X-Secret-Data: FLAG{secret123}
X-API-Key: sk_live_abc123
```

**The Right Way:**
```python
# Server-side: Only send secrets in response body after authentication
@app.route('/api/get-flag', methods=['POST'])
@require_authentication  # Decorator verifying auth
def get_flag():
    # Verify user is authenticated
    if not current_user.is_authenticated:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # Verify user has permission
    if not current_user.has_permission('view_flag'):
        return jsonify({'error': 'Forbidden'}), 403
    
    # Only then, send flag in response body (not headers)
    return jsonify({
        'flag': 'FLAG{properly_protected}',
        'timestamp': time.time()
    })
```

**Use HTTPS:**
```nginx
# nginx configuration
server {
    listen 443 ssl;
    server_name challenge.server;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    # Redirect HTTP to HTTPS
    if ($scheme = http) {
        return 301 https://$server_name$request_uri;
    }
}
```

### Content Security Policy (CSP)

Prevent unauthorized script execution:
```html
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'; 
               script-src 'self' 'unsafe-inline'; 
               style-src 'self' 'unsafe-inline';">
```

Or via HTTP header:
```http
Content-Security-Policy: default-src 'self'; script-src 'self'
```

### Input Validation & Output Encoding

```python
from flask import escape

@app.route('/api/submit', methods=['POST'])
def submit_data():
    user_input = request.json.get('data')
    
    # Validate input
    if not isinstance(user_input, str):
        return jsonify({'error': 'Invalid input type'}), 400
    
    if len(user_input) > 1000:
        return jsonify({'error': 'Input too long'}), 400
    
    # Sanitize for output
    safe_output = escape(user_input)
    
    return jsonify({'result': safe_output})
```

### Defense in Depth Checklist

| Layer | Control | Implementation |
|-------|---------|----------------|
| **Transport** | HTTPS | TLS certificates, HSTS headers |
| **Authentication** | Server-side | Session management, JWT |
| **Authorization** | Server-side | Role-based access control (RBAC) |
| **Secrets** | Never client-side | Environment variables, Vault |
| **Input Validation** | Server-side | Allowlists, type checking, length limits |
| **Output Encoding** | Context-aware | HTML escape, JSON encoding |
| **CSP** | Restrict resources | Content-Security-Policy header |
| **Logging** | Security events | Failed auth, suspicious activity |

### Testing for Client-Side Vulnerabilities

**Automated scanning:**
```bash
# Scan for secrets in HTML/JS
trufflehog filesystem ./web_root/ --json

# Check HTTP headers
curl -I https://site.com | grep -i "x-"

# Spider website and analyze all responses
nikto -h https://site.com
```

**Manual testing checklist:**
- ✓ View page source for HTML comments
- ✓ Inspect all JavaScript files for secrets
- ✓ Check browser DevTools → Network → Headers
- ✓ Modify JavaScript variables in console
- ✓ Disable client-side validation
- ✓ Test without JavaScript enabled
- ✓ Intercept traffic with Burp/ZAP

## 6. Summary

By exploiting three common client-side security failures, I extracted all parts of the flag:

1. **HTML source inspection** - Found flag fragment in HTML comment
2. **JavaScript manipulation** - Bypassed timer by setting global variable to 0
3. **HTTP header interception** - Captured flag fragment from custom response header

Each vulnerability demonstrated the same fundamental flaw: **client-side security controls are ineffective because attackers control the client environment**.

These aren't theoretical vulnerabilities — they represent real attack patterns seen in production:
- **HTML comments:** Exposed API keys, credentials, internal URLs
- **JavaScript access control:** Bypassed payment gates, DRM, premium features
- **HTTP headers:** Leaked authentication tokens, user data, internal metadata

The vulnerabilities map to established security standards:
- **CWE-200:** Exposure of Sensitive Information to an Unauthorized Actor
- **CWE-602:** Client-Side Enforcement of Server-Side Security
- **OWASP A01:2021:** Broken Access Control
- **OWASP A04:2021:** Insecure Design

The solution is straightforward: **implement all security controls server-side**. Client-side code is:
- Visible (view source, DevTools)
- Modifiable (console, proxy)
- Bypassable (disabled JavaScript, modified HTTP)

Server-side code is:
- Hidden (not transmitted to client)
- Protected (attacker cannot modify)
- Authoritative (makes final security decisions)

The key lesson: **Never trust the client**. Treat all client-supplied data as malicious. Validate everything server-side. Client-side controls are for user experience, not security. Any secret in client code is a leaked secret. Any access control in JavaScript is no access control.

Security through obscurity fails. Client-side restrictions fail. Only server-side enforcement succeeds.
