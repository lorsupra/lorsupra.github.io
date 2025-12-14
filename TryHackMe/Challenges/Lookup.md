---
layout: default
title: Lookup
page_type: writeup
---

# THM: Lookup – Web Exploitation & Linux Privilege Escalation

**Category:** Web / Linux Privilege Escalation

---

## Challenge Overview

This challenge demonstrates how multiple low-severity misconfigurations can be chained together to achieve full system compromise.  
The attack progresses from basic web enumeration to remote code execution and ultimately root access through local privilege escalation.

### Core Attack Chain
1. Web application enumeration
2. Username enumeration via login errors
3. Weak credential brute-force
4. Remote code execution through vulnerable file manager
5. Privilege escalation via SUID PATH hijacking
6. Root access through insecure sudo configuration

Each issue alone is minor; together they result in complete system takeover.

---

## Reconnaissance

### Service Enumeration

An initial scan revealed two exposed services:

```bash
nmap -A -Pn 10.64.154.120
````

* **22/tcp** – SSH
* **80/tcp** – Apache HTTPD

The web server was the primary attack surface.

---

## Web Application Enumeration

Directory brute-forcing identified a login page:

```bash
dirb http://10.64.154.120 /usr/share/dirb/wordlists/common.txt
```

The login functionality became the initial foothold.

---

## Username Enumeration

The login form leaked information through inconsistent error messages:

* Invalid username → “wrong username”
* Valid username → “wrong password”

This behavior allowed reliable username enumeration.

A simple script confirmed two valid accounts:

* `admin`
* `jose`

This significantly reduced the search space for credential attacks.

---

## Credential Compromise

With a confirmed username, a password brute-force attack was performed:

```bash
hydra -l jose -P /usr/share/wordlists/rockyou.txt \
  lookup.thm http-post-form \
  "/login.php:username=^USER^&password=^PASS^:Wrong"
```

**Credentials recovered:**

```
jose : password123
```

---

## Initial Access

After authentication, a file manager application was discovered at `files.lookup.thm`.
The service was identified as **elFinder 2.1.47**, a version vulnerable to remote command execution.

---

## Remote Code Execution

The elFinder PHP connector vulnerability was exploited using Metasploit:

```bash
use exploit/unix/webapp/elfinder_php_connector_exiftran_cmd_injection
```

This resulted in a reverse shell as the `www-data` user.

---

## Privilege Escalation (SUID Abuse)

Local enumeration revealed a custom SUID binary:

```
/usr/sbin/pwm
```

The binary executed the `id` command without using an absolute path.
By manipulating the `PATH` environment variable, command execution was hijacked:

```bash
export PATH=/tmp:$PATH
```

This caused the SUID binary to trust attacker-controlled output, leaking another user’s credentials.

---

## Privilege Escalation (Sudo Misconfiguration)

With access as user `think`, sudo permissions were checked:

```bash
sudo -l
```

```
(ALL) NOPASSWD: /usr/bin/look
```

The `look` utility can read files. By supplying an empty prefix, arbitrary file contents could be disclosed:

```bash
sudo /usr/bin/look '' /root/.ssh/id_rsa
```

This exposed the root user’s private SSH key.

---

## Root Access

Using the stolen SSH key:

```bash
ssh -i id_rsa root@lookup.thm
```

Root access was obtained successfully.

### Flags

* **User:** `38375fb4dd8baa2b2039ac03d92b820e`
* **Root:** `5a285a9f257e45c68bb6c9f9f57d18e8`

---

## Attack Summary

### Exploited Weaknesses

* Information disclosure in authentication
* Weak user password
* Outdated web application
* Unsafe SUID binary implementation
* Overly permissive sudo rules

### Key Takeaway

> None of these issues alone were critical, but chaining them together resulted in full system compromise.

This challenge highlights how **basic security hygiene failures** at multiple layers can be combined into a complete takeover.
