---
layout: default
title: Intro To Web 2 - Web
page_type: writeup
---
# Intro to Web 2 – HTTP Request Manipulation

**Category:** Web Exploitation

## 0. Challenge Overview

This challenge focuses on client-side security bypass techniques through HTTP request manipulation. The goal: retrieve four flag fragments by exploiting weak validation on:
- User-Agent header checks
- POST parameter manipulation
- GET parameter injection
- Authorization query strings

**Core concept:** The server implemented security checks that relied entirely on client-supplied data. By intercepting and modifying HTTP requests, all restrictions could be trivially bypassed.

This demonstrates why **client-side security is not security** — anything the client sends can be modified by an attacker.

## 1. Part 1 – User-Agent Spoofing

### The Restriction
Browsing to the challenge site immediately displayed an error:
```
Error: Insecure Operating System Detected
Please upgrade to Windows 95 or newer to continue.
```

The server was checking the `User-Agent` header and blocking anything that didn't claim to be Windows 95.

### The Bypass
I intercepted the request in Burp Suite and examined the headers:
```http
GET / HTTP/1.1
Host: challenge.server
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36
```

Changed the `User-Agent` to match Windows 95:
```http
GET / HTTP/1.1
Host: challenge.server
User-Agent: Mozilla/4.0 (compatible; MSIE 5.0; Windows 95)
```

Forwarded the request.

**Result:**
```
Welcome! Here's the first part of your flag: FLAG{p4rt1_
```

✔ **Success:** First flag fragment retrieved.

**Key observation:** The server trusted the `User-Agent` header without any server-side validation. This header is trivially spoofed — it's just a string the browser sends that can be set to anything.

## 2. Part 2 – POST Parameter Manipulation

### The Form
The next page contained a form for viewing log files:
```html
<form method="POST" action="/view-file.php">
  <select name="filename">
    <option value="temperature-log.csv">Temperature Log</option>
    <option value="humidity-log.csv">Humidity Log</option>
  </select>
  <input type="submit" value="View File">
</form>
```

Selecting "Temperature Log" sent:
```http
POST /view-file.php HTTP/1.1
Host: challenge.server
Content-Type: application/x-www-form-urlencoded

filename=temperature-log.csv
```

### The Attack
I modified the POST body to request a different file:
```http
POST /view-file.php HTTP/1.1
Host: challenge.server
Content-Type: application/x-www-form-urlencoded

filename=flag.txt
```

**Result:**
```
h34d3r_sp00f1ng_
```

✔ **Success:** Second flag fragment retrieved.

**Key observation:** The server accepted arbitrary filenames without validation. No allowlist, no path sanitization — just direct file access based on user input.

## 3. Part 3 – GET Parameter Injection

### The Endpoint
The challenge hinted that the same functionality could be accessed via GET parameters instead of POST:
```
http://challenge.server/view-file.php?filename=temperature-log.csv
```

### The Attack
Rather than using POST, I simply modified the URL directly:
```
http://challenge.server/view-file.php?filename=flag.txt
```

**Result:**
```
p4r4m_m4n1pul4t10n_
```

✔ **Success:** Third flag fragment retrieved.

**Key observation:** Both GET and POST are equally controllable by the attacker. Switching from POST to GET doesn't provide any additional security — both methods transmit user-supplied data that must be validated server-side.

## 4. Part 4 – Authorization Parameter Bypass

### The Final Gate
The last page linked to a "secure" document viewer:
```
http://challenge.server/enter-security-gate.php
```

This redirected to:
```
http://challenge.server/burn-after-reading.php?authorized=false
```

With `authorized=false`, the response was:
```
Access Denied: File has been burned (deleted).
```

### The Bypass
I intercepted the redirect and changed the parameter before it reached the server:
```
http://challenge.server/burn-after-reading.php?authorized=true
```

**Result:**
```
4nd_qu3ry_tw34k1ng}

Full Flag: FLAG{p4rt1_h34d3r_sp00f1ng_p4r4m_m4n1pul4t10n_4nd_qu3ry_tw34k1ng}
```

✔ **Success:** Final flag fragment retrieved. Challenge complete.

**Key observation:** The authorization decision was made entirely client-side via a URL parameter. The server trusted the `authorized=true` parameter without any server-side session validation or authentication check.

## 5. Why This Works – Understanding Client-Side Security Failures

All four vulnerabilities share the same fundamental flaw: **trusting client-supplied data without server-side validation**.

### The HTTP Request Cycle
```
Client → [Interceptable/Modifiable Request] → Server
```

Every piece of data in an HTTP request can be controlled by an attacker:
- **Headers** (User-Agent, Referer, Cookie, etc.)
- **POST body** (form parameters, JSON, XML)
- **GET parameters** (query strings in the URL)
- **HTTP method** (GET, POST, PUT, DELETE, etc.)

Tools like Burp Suite, OWASP ZAP, or even browser DevTools allow trivial modification of all these components.

### Why Each Bypass Worked

**User-Agent Spoofing:**
- The server checked: `if (User-Agent != "Windows 95") { block(); }`
- The attacker controlled the User-Agent
- Solution: Set User-Agent to whatever the server expected

**POST Parameter Manipulation:**
- The server checked: `if (filename in ['temperature-log.csv', 'humidity-log.csv']) { show(); }`
- But this check was done **client-side** in the HTML form
- The server itself had no validation
- Solution: Send any filename directly

**GET Parameter Injection:**
- Same as POST, but the parameter was visible in the URL
- Browsers don't validate query strings
- Solution: Manually craft the URL with the desired filename

**Authorization Bypass:**
- The server checked: `if (authorized == 'true') { show_flag(); }`
- But the value of `authorized` came from the **client**
- No session tracking, no server-side permission check
- Solution: Set `authorized=true` manually

### Real-World Parallels

These aren't just CTF tricks — they mirror real vulnerabilities:

**Client-Side Validation (CWE-602):**
- JavaScript form validation that can be bypassed by disabling JavaScript
- Hidden form fields that control pricing or permissions
- Client-side access control checks

**Improper Input Validation (CWE-20):**
- Path traversal via filename parameters (`../../../etc/passwd`)
- SQL injection via unsanitized GET/POST parameters
- Command injection via improperly validated input

**Missing Access Control (CWE-285):**
- Authorization decisions based on URL parameters
- Privilege escalation via cookie manipulation
- Direct object reference without permission checks

**Real-world example:** In 2019, a major airline allowed users to view other passengers' boarding passes by simply changing the `bookingReference` parameter in the URL.

## 6. Defensive Mitigations

### Never Trust Client Input
**The Golden Rule:** All client-supplied data is attacker-controlled.

```python
# BAD: Trust client parameters
filename = request.POST.get('filename')
return open(filename).read()

# GOOD: Validate against allowlist
ALLOWED_FILES = ['temperature-log.csv', 'humidity-log.csv']
filename = request.POST.get('filename')
if filename not in ALLOWED_FILES:
    return "Access Denied"
return open(filename).read()
```

### Server-Side Validation
- **Headers:** Don't use User-Agent for security decisions. If OS detection is needed, use server-side fingerprinting or device management certificates.
- **File Access:** Implement strict allowlists, validate paths, and use indirect references (IDs) instead of filenames.
  ```python
  # Instead of: ?filename=flag.txt
  # Use: ?file_id=1 (map IDs to files server-side)
  FILE_MAP = {1: 'temperature-log.csv', 2: 'humidity-log.csv'}
  file_id = int(request.GET.get('file_id'))
  if file_id in FILE_MAP:
      return open(FILE_MAP[file_id]).read()
  ```
- **Authorization:** Implement proper session management and permission checks.

### Authentication & Access Control
```python
# BAD: Authorization via query parameter
authorized = request.GET.get('authorized') == 'true'

# GOOD: Authorization via server-side session
if not session.get('is_authenticated'):
    return redirect('/login')
if not user_has_permission(session['user_id'], resource):
    return "Access Denied"
```

### Defense in Depth

| Layer | Control | Example |
|-------|---------|---------|
| Application | Input validation | Allowlist of filenames |
| Session | Authentication | Verify user session before file access |
| Authorization | Permission checks | Verify user has rights to requested resource |
| Infrastructure | Principle of least privilege | Web server can't read arbitrary files |
| Monitoring | Logging & alerting | Alert on unauthorized file access attempts |

### Secure Development Checklist
- ✓ Validate all input server-side (never rely on client-side checks)
- ✓ Use indirect object references (IDs instead of filenames/paths)
- ✓ Implement proper authentication (sessions, tokens, certificates)
- ✓ Enforce authorization checks on every request
- ✓ Log security-relevant events (failed auth, suspicious parameters)
- ✓ Use security headers (CSP, X-Frame-Options, etc.)
- ✓ Apply principle of least privilege (limit file system access)

## 7. Summary

By intercepting and modifying HTTP requests, I bypassed four separate security controls:
1. User-Agent restriction (header spoofing)
2. File access control (POST parameter injection)
3. Alternative endpoint (GET parameter manipulation)
4. Authorization gate (query parameter modification)

Each vulnerability stemmed from the same root cause: **trusting data supplied by the client**. The server performed no validation, authentication, or authorization checks — it simply accepted whatever the client sent.

The key lesson: **Client-side security is security theater**. Anything rendered in HTML, sent in JavaScript, or transmitted in HTTP requests can be modified by an attacker. All security decisions must be enforced server-side, with proper input validation and access control.

These aren't theoretical vulnerabilities — parameter manipulation and authorization bypass are consistently in the OWASP Top 10 (Broken Access Control, Security Misconfiguration). Production systems with these flaws face data breaches, privilege escalation, and complete system compromise.
