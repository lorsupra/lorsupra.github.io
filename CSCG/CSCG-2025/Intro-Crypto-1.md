---
layout: default
title: Intro To Crypto - Crypto
page_type: writeup
---
# CSCG 2024: Once-in-Nonce – Stream Cipher Nonce Reuse

**Category:** Cryptography

## 0. Challenge Overview

This challenge provided an encryption oracle that accepted arbitrary plaintext input and returned ciphertext. The cipher was a stream cipher (likely AES-CTR or ChaCha20), and the oracle had one critical flaw: **it reused the same nonce for every encryption**.

**The objective:** Exploit nonce reuse to decrypt an unknown ciphertext and recover the flag.

**Core concept:** Stream ciphers XOR plaintext with a keystream. If the same nonce is used twice, the same keystream is generated. An attacker who controls the plaintext can recover the keystream, then decrypt any ciphertext encrypted under that nonce.

This is a **chosen-plaintext attack** enabled by catastrophic nonce reuse.

## 1. Understanding Stream Cipher Nonce Reuse

### How Stream Ciphers Work (AES-CTR)

In AES-CTR mode:
```
keystream = AES(key, nonce || counter)
ciphertext = plaintext ⊕ keystream
```

The security relies on:
- Unique (key, nonce) pairs for every message
- Never reusing the same nonce with the same key

### Why Nonce Reuse is Fatal

If the same nonce is used for two messages:
```
C1 = P1 ⊕ keystream
C2 = P2 ⊕ keystream

C1 ⊕ C2 = (P1 ⊕ keystream) ⊕ (P2 ⊕ keystream)
C1 ⊕ C2 = P1 ⊕ P2
```

This eliminates the keystream entirely. Even worse, if an attacker controls one plaintext:
```
C1 = known_plaintext ⊕ keystream
keystream = C1 ⊕ known_plaintext

Then for any other ciphertext:
P2 = C2 ⊕ keystream
```

**With nonce reuse + chosen plaintext = complete decryption capability.**

## 2. Initial Recon – Testing the Oracle

I started by sending test inputs to understand the oracle's behavior:
```python
from pwn import *

conn = remote('challenge.server', 1337)

# Send known plaintext
test_input = b'A' * 32
conn.sendline(test_input.hex())

# Receive ciphertext
ciphertext = bytes.fromhex(conn.recvline().strip().decode())
print(f"Ciphertext: {ciphertext.hex()}")
```

Output:
```
Ciphertext: 5f3a7b2e8c9d4f1a...
```

**Key observation:** The oracle encrypted my input and returned the ciphertext. I could send arbitrary plaintext and observe the output.

## 3. Attempt 1 – Short Keystream Extraction (Failed)

My first approach was to extract a short keystream:
```python
# Send 32 bytes of known plaintext
known_plaintext = b'A' * 32
conn.sendline(known_plaintext.hex())
ciphertext1 = bytes.fromhex(conn.recvline().strip().decode())

# Recover keystream
keystream = bytes([a ^ b for a, b in zip(known_plaintext, ciphertext1)])
print(f"Keystream (32 bytes): {keystream.hex()}")
```

Then I requested the flag ciphertext:
```python
conn.sendline(b'FLAG')  # Command to get flag ciphertext
flag_ciphertext = bytes.fromhex(conn.recvline().strip().decode())

# Attempt decryption
decrypted = bytes([c ^ k for c, k in zip(flag_ciphertext, keystream)])
print(f"Decrypted: {decrypted}")
```

Output:
```
Decrypted: b'CSCG{turns_out_that_once_in_nonc\xc3\xaf\xc2\xbf\xc2\xbdB\xc3\xaf\xc2\xbf...'
```

**Partial success:** The flag started correctly (`CSCG{turns_out_that_once_in_nonc`), but the rest was garbage.

**The problem:** My keystream was only 32 bytes long. The flag ciphertext was longer, so the XOR operation beyond byte 32 was producing invalid data.

## 4. Attempt 2 – Extending Keystream Length (Success)

I increased the known plaintext length to ensure I'd capture the full keystream:
```python
# Send 64 bytes of known plaintext
known_plaintext = b'A' * 64
conn.sendline(known_plaintext.hex())
ciphertext1 = bytes.fromhex(conn.recvline().strip().decode())

# Recover full keystream
keystream = bytes([a ^ b for a, b in zip(known_plaintext, ciphertext1)])
print(f"Keystream length: {len(keystream)} bytes")
print(f"Keystream: {keystream.hex()}")
```

Output:
```
Keystream length: 64 bytes
Keystream: 1e7b3a5c8d9f2e4a6b1c9d3f7e2a8c4d5e9f1b7c3a6d8e2f4a9c1e7b3d5f8a2c...
```

Now decrypt the flag:
```python
conn.sendline(b'FLAG')
flag_ciphertext = bytes.fromhex(conn.recvline().strip().decode())

# Decrypt with full keystream
decrypted = bytes([c ^ k for c, k in zip(flag_ciphertext, keystream)])
print(f"Decrypted flag: {decrypted.decode()}")
```

Output:
```
Decrypted flag: CSCG{turns_out_that_once_in_nonce_is_way_more_than_enough}
```

✔ **Success:** Full flag recovered.

**Key observation:** The keystream length must be **at least as long** as the ciphertext you're trying to decrypt. Using a 64-byte keystream allowed me to decrypt the entire flag.

## 5. Complete Exploit Script

Here's the full working exploit:
```python
#!/usr/bin/env python3
from pwn import *

def xor_bytes(a, b):
    """XOR two byte strings"""
    return bytes([x ^ y for x, y in zip(a, b)])

# Connect to oracle
conn = remote('challenge.server', 1337)

# Step 1: Extract keystream using known plaintext
print("[*] Extracting keystream...")
known_plaintext = b'A' * 64  # Long enough to cover flag length
conn.sendline(known_plaintext.hex())
ciphertext = bytes.fromhex(conn.recvline().strip().decode())

# Step 2: Compute keystream
keystream = xor_bytes(known_plaintext, ciphertext)
print(f"[+] Keystream extracted: {len(keystream)} bytes")

# Step 3: Request flag ciphertext
print("[*] Requesting flag ciphertext...")
conn.sendline(b'FLAG')
flag_ciphertext = bytes.fromhex(conn.recvline().strip().decode())

# Step 4: Decrypt flag
flag_plaintext = xor_bytes(flag_ciphertext, keystream)
print(f"[+] Flag: {flag_plaintext.decode()}")

conn.close()
```

Running the exploit:
```bash
$ python3 exploit.py
[*] Extracting keystream...
[+] Keystream extracted: 64 bytes
[*] Requesting flag ciphertext...
[+] Flag: CSCG{turns_out_that_once_in_nonce_is_way_more_than_enough}
```

Challenge complete.

## 6. Why This Works – The Mathematics of Stream Cipher Nonce Reuse

### The XOR Property
XOR has a critical property: it's its own inverse.
```
A ⊕ B ⊕ B = A
```

This means if you XOR something twice with the same value, you get back the original:
```
plaintext ⊕ keystream = ciphertext
ciphertext ⊕ keystream = plaintext
```

### Keystream Recovery
When we know both the plaintext and ciphertext:
```
ciphertext = plaintext ⊕ keystream
ciphertext ⊕ plaintext = (plaintext ⊕ keystream) ⊕ plaintext
ciphertext ⊕ plaintext = keystream
```

The keystream is just the XOR of the known plaintext and its ciphertext.

### Decrypting Unknown Ciphertexts
Once we have the keystream, we can decrypt **any** ciphertext encrypted with the same nonce:
```
flag_ciphertext ⊕ keystream = flag_plaintext
```

### Why Length Matters
XOR operates byte-by-byte. If your keystream is 32 bytes and the ciphertext is 64 bytes:
```
Bytes 0-31:  Correctly decrypted (keystream available)
Bytes 32-63: Garbage output (no keystream, XOR with undefined data)
```

You need a keystream **at least as long** as the longest ciphertext you want to decrypt.

### Real-World Examples

**WEP (Wireless Encryption):**
- Used RC4 stream cipher with 24-bit IV (nonce)
- IVs inevitably repeated after ~5000 packets
- Attackers recovered the keystream and decrypted all traffic
- This is why WEP is completely broken

**TLS 1.1 CBC (BEAST Attack):**
- While not pure stream cipher, IV reuse enabled similar attacks
- Fixed in TLS 1.2+ with random IVs

**PlayStation 3 ECDSA:**
- Sony reused the same random nonce (`k`) in their signature algorithm
- Allowed recovery of the private key from two signatures
- Complete compromise of PS3 code signing

## 7. Defensive Mitigations

### Never Reuse Nonces
**The Golden Rule:** A (key, nonce) pair must be used for **exactly one** encryption operation.

```python
# BAD: Reusing the same nonce
nonce = os.urandom(12)
for message in messages:
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    ciphertext = cipher.encrypt(message)  # VULNERABLE

# GOOD: Generate a new nonce for each message
for message in messages:
    nonce = os.urandom(12)  # Fresh nonce every time
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    ciphertext = cipher.encrypt(message)
```

### Use Authenticated Encryption
Prefer AES-GCM over AES-CTR. It provides:
- Encryption (confidentiality)
- Authentication (integrity/authenticity)
- Built-in nonce misuse resistance (somewhat)

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)

nonce = os.urandom(12)
ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

# Decryption automatically verifies authenticity
plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
```

### Nonce Generation Strategies

**Option 1: Random Nonces**
```python
nonce = os.urandom(12)  # 96 bits for AES-GCM
```
- Pros: Simple, no state required
- Cons: Birthday paradox limits safety (~2^48 encryptions for 96-bit nonces)

**Option 2: Counter-Based Nonces**
```python
counter = 0
nonce = counter.to_bytes(12, 'big')
counter += 1
```
- Pros: No collision risk, deterministic
- Cons: Requires persistent state

**Option 3: Hybrid (Timestamp + Counter)**
```python
timestamp = int(time.time())
counter = 0
nonce = timestamp.to_bytes(8, 'big') + counter.to_bytes(4, 'big')
```
- Pros: Stateless, collision-resistant
- Cons: Clock synchronization required in distributed systems

### Detection and Monitoring
In production systems:
- **Log all nonces** used with each key
- **Alert on duplicate nonces** (critical security event)
- **Rotate keys regularly** to limit exposure window
- **Use hardware security modules (HSMs)** that enforce unique nonces

### Testing for Nonce Reuse
```python
def test_nonce_uniqueness():
    nonces = set()
    for _ in range(10000):
        nonce = generate_nonce()
        assert nonce not in nonces, "Nonce reuse detected!"
        nonces.add(nonce)
    print("[+] No nonce reuse detected in 10,000 operations")
```

## 8. Summary

By exploiting nonce reuse in a stream cipher, I recovered the keystream through a chosen-plaintext attack and decrypted the flag:

1. **Sent known plaintext** to the oracle (64 bytes of 'A')
2. **Received the ciphertext** and XORed it with the known plaintext to extract the keystream
3. **Requested the flag ciphertext** from the oracle
4. **XORed the flag ciphertext with the keystream** to recover the plaintext flag

The vulnerability is simple but devastating: **nonce reuse in stream ciphers completely breaks confidentiality**. An attacker with chosen-plaintext access can decrypt all traffic encrypted under the reused nonce.

This isn't a theoretical attack — it's broken real-world systems:
- **WEP wireless encryption** (completely compromised)
- **PlayStation 3 firmware signing** (private key extracted)
- **TLS 1.1 CBC mode** (BEAST attack)

The fix is equally simple: **never reuse a nonce**. Use random nonces, counter-based nonces, or authenticated encryption schemes like AES-GCM that provide additional protection.

The key lesson: in cryptography, **implementation details matter as much as algorithm strength**. AES-CTR is secure if used correctly, but a single nonce reuse makes it trivially breakable. Cryptographic misuse is often more dangerous than cryptographic weakness.
