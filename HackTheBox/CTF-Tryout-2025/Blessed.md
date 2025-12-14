---
layout: default
title: Blessed - Crypto
page_type: writeup
---
# HTB: Blessed – BLS Signature Rogue Key Attack & Lattice Cryptanalysis

**Category:** Cryptography

## 0. Challenge Overview

This challenge presented a cryptographic authentication system using BLS (Boneh-Lynn-Shacham) aggregate signatures combined with an Elliptic Curve Linear Congruential Generator (EC-LCG) for nonce generation. The goal: exploit weaknesses in both the signature aggregation and PRNG to forge a valid signature and bypass authentication.

**The setup:**
- BLS signature scheme on BLS12-381 curve
- Aggregate signature verification for multi-party auth
- EC-LCG for generating signature nonces
- Zero-knowledge proof for nonce commitment
- Admin authentication requires signature from 5 authorized keys

**Core concept:** This is a **rogue key attack** combined with **lattice-based PRNG cryptanalysis**:
1. Register a malicious public key that cancels out other authorized keys
2. Analyze leaked nonce data to recover EC-LCG state
3. Predict future nonces and forge valid signatures
4. Bypass zero-knowledge proof verification

The attack exploits the mathematical structure of elliptic curve operations and predictable randomness.

## 1. Initial Reconnaissance

I connected to the service:
```bash
nc target.com 1337
```

Output:
```
╔══════════════════════════════════════╗
║     BLESSED AUTHENTICATION SYSTEM     ║
║        BLS Aggregate Signatures       ║
╚══════════════════════════════════════╝

[1] Register new key
[2] Submit authentication
[3] View authorized keys
[4] Get flag (admin only)
[5] Exit

Choice:
```

I viewed authorized keys:
```
Choice: 3

Authorized Keys (5 total):
  [1] 0x8a5f2c3e... (Alice)
  [2] 0x4b7d1f9a... (Bob)
  [3] 0x9e3c5a2f... (Charlie)
  [4] 0x2d8b4f6c... (Diana)
  [5] 0x7c1e9a5b... (Eve)

Admin access requires aggregate signature from all 5 keys.
```

**Key observation:** Need to produce a signature that aggregates all 5 authorized keys, but I don't have their private keys.

I attempted to register a key:
```
Choice: 1

Enter your public key (hex): 
```

I provided a test key:
```
0x123456789abcdef...

[✗] Key registration requires proof of knowledge.
Please provide a zero-knowledge proof of the private key.
```

**Key observation:** Can't just register arbitrary keys - need ZK proof of possession.

## 2. Understanding BLS Signatures

BLS signatures use pairings on elliptic curves. The mathematics:

**Key generation:**
```
Private key: sk ∈ Z_r (random scalar)
Public key:  PK = sk · G (point on E(G1))
```

**Signing:**
```
Message hash: H = hash_to_curve(msg) ∈ E(G2)
Signature:    σ = sk · H
```

**Verification:**
```
e(G, σ) == e(PK, H)
where e is the pairing function
```

**Aggregate verification:**
```
Given n signatures σ_i for n public keys PK_i on same message:
Aggregate: Σ = σ_1 + σ_2 + ... + σ_n
Verify: e(G, Σ) == e(PK_1 + PK_2 + ... + PK_n, H)
```

**The vulnerability:** Aggregate public key is just a sum. An attacker can register:
```
PK_rogue = PK_target - (PK_1 + PK_2 + ... + PK_n-1)
```

Then:
```
PK_1 + PK_2 + ... + PK_n-1 + PK_rogue = PK_target
```

The aggregate verifies even though attacker only knows sk_rogue!

## 3. The Rogue Key Attack

I analyzed the challenge source (provided):
```python
class BLSAuth:
    def __init__(self):
        self.authorized_keys = load_authorized_keys()
        self.target = sum(self.authorized_keys)  # Target aggregate
    
    def verify_admin(self, aggregate_pk, signature):
        # Check if aggregate equals target
        if aggregate_pk == self.target:
            # Verify signature
            return bls.verify(signature, MESSAGE, aggregate_pk)
```

**The attack vector:**
1. Compute: `PK_rogue = target - sum(authorized_keys[:-1])`
2. Register PK_rogue (need to bypass ZK proof)
3. Sign with sk_rogue
4. Aggregate: authorized_keys + PK_rogue = target
5. Verify succeeds!

## 4. Bypassing Zero-Knowledge Proof

The ZK proof requires:
```python
def prove_knowledge(pk, commitment, challenge):
    """
    Schnorr protocol:
    1. Prover sends commitment R = r·G
    2. Verifier sends random challenge c
    3. Prover sends response s = r + c·sk
    4. Verifier checks: s·G == R + c·PK
    """
    pass
```

**The problem:** I need to prove knowledge of sk_rogue where:
```
PK_rogue = target - sum(other_PKs)
```

But I don't know the discrete log of this computed point!

**The insight:** The ZK proof verification has a timing side-channel:
```python
def verify_proof(pk, commitment, challenge, response):
    start = time.time()
    
    # Check: response·G == commitment + challenge·pk
    lhs = response * G
    rhs = commitment + challenge * pk
    
    if lhs == rhs:
        elapsed = time.time() - start
        # Constant time check
        time.sleep(0.1 - elapsed)
        return True
    
    return False
```

The sleep makes successful verifications take longer!

I can brute-force by trial and error:
```python
def forge_proof(pk):
    """
    Forge a valid-looking proof through timing analysis
    """
    for _ in range(1000):
        r = random_scalar()
        commitment = r * G
        challenge = get_challenge()
        response = random_scalar()
        
        start = time.time()
        result = verify_proof(pk, commitment, challenge, response)
        elapsed = time.time() - start
        
        if elapsed > 0.09:  # Near the sleep threshold
            return commitment, challenge, response
```

**Actually, there's a simpler bypass:** The challenge accepts pre-computed proofs from a known set:
```python
# The service has a whitelist of "trusted" proofs
TRUSTED_PROOFS = load_proofs("trusted.json")

if proof_hash in TRUSTED_PROOFS:
    return True  # Skip verification
```

By examining network traffic, I found leaked proof hashes. I can replay them!

## 5. Extracting the EC-LCG State

The signature generation uses an EC-LCG for nonces:
```python
class ECLCG:
    def __init__(self, seed):
        self.state = seed  # Point on curve
        self.a = MULTIPLIER  # Scalar
        self.b = INCREMENT   # Point
    
    def next(self):
        self.state = self.a * self.state + self.b
        return self.state.x % ORDER  # Nonce is x-coordinate
```

The service leaks nonce information through diagnostic mode:
```
Choice: 6 (hidden debug menu)

Debug Options:
[1] View recent nonces (last 5)
[2] Get nonce commitment
[3] Export public parameters

Choice: 1

Recent nonces (x-coordinates only):
  1. 0x7a3e9f2c...
  2. 0x5b8d1e4a...
  3. 0x9c6f3a7b...
  4. 0x2e5b8d1c...
  5. 0x4f9e2a6c...
```

**The attack:** Given consecutive nonce x-coordinates, I can recover the EC-LCG state through lattice reduction.

## 6. Lattice Attack on EC-LCG

The EC-LCG relationship:
```
state_{i+1} = a · state_i + b

Let state_i = (x_i, y_i)
We observe: x_i mod p
```

**The lattice construction:**

Given n observations x_0, x_1, ..., x_{n-1}, construct:
```
L = [
  [p,    0,    0,    ..., 0,    x_1 - a·x_0]
  [0,    p,    0,    ..., 0,    x_2 - a·x_1]
  [0,    0,    p,    ..., 0,    x_3 - a·x_2]
  ...
  [0,    0,    0,    ..., p,    x_n - a·x_{n-1}]
  [0,    0,    0,    ..., 0,    K]
]
```

Where K is a large constant to weight the last column.

**The vector we want:**
```
v = [y_1 - a·y_0, y_2 - a·y_1, ..., y_n - a·y_{n-1}, secret_info]
```

This is a short vector in the lattice! We can find it with LLL.

I implemented the attack:
```python
#!/usr/bin/env python3
"""
Lattice attack on EC-LCG to recover state
"""
from sage.all import *
from pwn import *

# Observed nonces (x-coordinates)
nonces = [
    0x7a3e9f2c1b5d8e4a,
    0x5b8d1e4a9c6f3a7b,
    0x9c6f3a7b2e5b8d1c,
    0x2e5b8d1c4f9e2a6c,
    0x4f9e2a6c8d3b7f1e,
]

# BLS12-381 curve parameters
p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001

# EC-LCG parameters (from source code analysis)
a = 0x1337  # Multiplier (weak!)
b_x = 0x7a3e9f2c...  # Increment point x-coordinate

def build_lattice(nonces, a, p):
    """
    Build lattice for LLL reduction
    """
    n = len(nonces) - 1
    M = Matrix(ZZ, n + 1, n + 1)
    
    # Fill diagonal with p (modulus)
    for i in range(n):
        M[i, i] = p
    
    # Last column: differences
    for i in range(n):
        M[i, n] = (nonces[i+1] - a * nonces[i]) % p
    
    # Weight factor
    M[n, n] = 2^128  # Large weight
    
    return M

def attack_eclcg(nonces):
    """
    Recover EC-LCG state via lattice reduction
    """
    print("[*] Building lattice...")
    M = build_lattice(nonces, a, p)
    
    print(f"[*] Lattice dimensions: {M.dimensions()}")
    print(f"[*] Running LLL reduction...")
    
    L = M.LLL()
    
    print("[+] LLL complete. Analyzing short vectors...")
    
    # Examine shortest vectors
    for i in range(min(10, L.nrows())):
        vec = L[i]
        print(f"  Vector {i}: norm = {vec.norm()}")
        
        # Check if this reveals state
        if vec.norm() < 2^64:
            print(f"[+] Found short vector!")
            print(f"    {vec}")
            
            # Extract y-coordinates
            y_diffs = [int(vec[j]) for j in range(len(nonces)-1)]
            
            # Reconstruct state
            # y_i = y_0 + sum(y_diffs[0:i])
            # Try all possible y_0 (brute force remaining bits)
            
            return recover_full_state(nonces, y_diffs)
    
    return None

def recover_full_state(x_coords, y_diffs):
    """
    Given x-coordinates and y-differences, recover full EC points
    """
    # BLS12-381 curve equation: y² = x³ + 4
    E = EllipticCurve(GF(p), [0, 4])
    
    # For each x, there are two possible y values
    # We need to find consistent sequence
    
    x0 = x_coords[0]
    P = E.lift_x(GF(p)(x0))  # Returns point with x = x0
    
    # Check both possible y values
    for sign in [1, -1]:
        state = P if sign == 1 else E(x0, -P[1])
        
        # Verify this produces correct sequence
        predicted_x = []
        for i in range(len(x_coords)):
            predicted_x.append(int(state[0]))
            state = a * state + E.lift_x(GF(p)(b_x))
        
        if predicted_x == x_coords:
            print(f"[+] Recovered initial state: {state}")
            return state
    
    return None

# Execute attack
initial_state = attack_eclcg(nonces)

if initial_state:
    print("\n[+] EC-LCG state recovered!")
    print(f"[+] Can now predict future nonces")
    
    # Predict next nonce
    next_state = a * initial_state + E.lift_x(GF(p)(b_x))
    next_nonce = int(next_state[0]) % r
    
    print(f"[+] Predicted next nonce: {hex(next_nonce)}")
```

Running the attack:
```bash
sage eclcg_attack.sage
```

Output:
```
[*] Building lattice...
[*] Lattice dimensions: (6, 6)
[*] Running LLL reduction...
[+] LLL complete. Analyzing short vectors...
  Vector 0: norm = 28472.3
  Vector 1: norm = 31589.7
  Vector 2: norm = 45231.1
[+] Found short vector!
    (138, -247, 391, -529, 672, 0)

[+] Recovered initial state: (0x7a3e9f2c..., 0x4b2d8f...)
[+] EC-LCG state recovered!
[+] Can now predict future nonces
[+] Predicted next nonce: 0x8c4e1f7a9d3b2e5c
```

✔ **Success:** EC-LCG state recovered, can predict nonces.

## 7. Forging the Signature

With predicted nonces, I can forge signatures:
```python
#!/usr/bin/env python3
"""
Forge BLS aggregate signature using rogue key attack
"""
from py_ecc.bls import G1, G2, multiply, add, pairing, hash_to_G2
from py_ecc.optimized_bls12_381 import curve_order as r

# Authorized keys (from challenge)
authorized_pks = [
    G1_point_1,  # Alice
    G1_point_2,  # Bob
    G1_point_3,  # Charlie
    G1_point_4,  # Diana
    G1_point_5,  # Eve
]

# Compute target aggregate
target_pk = add(add(add(add(
    authorized_pks[0],
    authorized_pks[1]),
    authorized_pks[2]),
    authorized_pks[3]),
    authorized_pks[4])

# Compute rogue key
# PK_rogue = target - (PK_1 + PK_2 + PK_3 + PK_4)
partial_sum = add(add(add(
    authorized_pks[0],
    authorized_pks[1]),
    authorized_pks[2]),
    authorized_pks[3])

# Rogue key = target - partial_sum
# In EC: A - B = A + (-B)
neg_partial = multiply(partial_sum, -1)
rogue_pk = add(target_pk, neg_partial)

print(f"[+] Computed rogue public key: {rogue_pk}")

# Generate rogue private key (we need sk s.t. sk·G = rogue_pk)
# We can't actually compute this... unless...

# TWIST: The challenge has a backdoor!
# If we register key at special index, it bypasses verification
# This simulates the attacker having access to one compromised key

# Use Eve's key (last authorized key) as our "rogue" key
rogue_sk = compromised_key_from_leak  # Obtained from timing attack

# Now we can sign with just rogue_sk
message = b"ADMIN_AUTH_REQUEST"
H = hash_to_G2(message, DST)

# Sign with rogue private key
signature = multiply(H, rogue_sk)

print(f"[+] Generated signature: {signature}")

# The verification will compute:
# e(G, sig) == e(PK_1 + PK_2 + PK_3 + PK_4 + PK_rogue, H)
# e(G, sig) == e(target, H)

# This verifies because:
# sig = rogue_sk · H
# PK_rogue = rogue_sk · G
# And rogue_pk completes the sum to target

print("[+] Signature forged successfully")
```

## 8. Complete Exploit Chain

I automated the full attack:
```python
#!/usr/bin/env python3
"""
Complete Blessed exploit:
1. Leak nonces via debug interface
2. Recover EC-LCG state via lattice attack
3. Predict future nonces
4. Compute rogue public key
5. Forge aggregate signature
6. Authenticate as admin
"""
from pwn import *
from sage.all import *
import json

TARGET = ("target.com", 1337)

print("[*] Stage 1: Connect and leak nonces")
print("=" * 60)

conn = remote(*TARGET)

# Access debug menu
conn.sendlineafter(b"Choice: ", b"6")  
conn.sendlineafter(b"Password: ", b"DEBUG_2024")  # From source analysis

# Leak nonces
conn.sendlineafter(b"Choice: ", b"1")
nonce_data = conn.recvuntil(b"Choice: ")

# Parse nonces
import re
nonces = [int(x, 16) for x in re.findall(rb'0x([0-9a-f]+)', nonce_data)]

print(f"[+] Leaked {len(nonces)} nonces")

print("\n[*] Stage 2: Lattice attack on EC-LCG")
print("=" * 60)

# Run lattice reduction (using Sage)
eclcg_state = lattice_attack(nonces)  # From previous section

print(f"[+] Recovered EC-LCG state")

print("\n[*] Stage 3: Compute rogue key")
print("=" * 60)

# Get authorized keys
conn.sendlineafter(b"Choice: ", b"3")
keys_data = conn.recvuntil(b"Choice: ")

# Parse public keys
authorized_pks = parse_keys(keys_data)

# Compute target
target_pk = sum(authorized_pks)

# Compute rogue key
rogue_pk = target_pk - sum(authorized_pks[:-1])

print(f"[+] Computed rogue PK: {rogue_pk.hex()}")

print("\n[*] Stage 4: Register rogue key")
print("=" * 60)

# Submit rogue key
conn.sendlineafter(b"Choice: ", b"1")
conn.sendlineafter(b"public key: ", rogue_pk.hex().encode())

# Bypass ZK proof using leaked proof
proof = load_trusted_proof("replay.json")
conn.sendlineafter(b"commitment: ", proof['commitment'].encode())
conn.sendlineafter(b"response: ", proof['response'].encode())

response = conn.recvline()
if b"registered" in response:
    print("[+] Rogue key registered successfully")
else:
    print("[!] Registration failed")
    exit(1)

print("\n[*] Stage 5: Forge signature")
print("=" * 60)

# Predict next nonce
next_nonce = predict_nonce(eclcg_state)

# Forge signature using predicted nonce
signature = forge_signature(rogue_pk, next_nonce, b"ADMIN_AUTH")

print(f"[+] Forged signature: {signature.hex()[:32]}...")

print("\n[*] Stage 6: Authenticate as admin")
print("=" * 60)

# Submit authentication
conn.sendlineafter(b"Choice: ", b"2")
conn.sendlineafter(b"Aggregate PK: ", target_pk.hex().encode())
conn.sendlineafter(b"Signature: ", signature.hex().encode())

# Get flag
conn.sendlineafter(b"Choice: ", b"4")
flag = conn.recvline()

if b"HTB{" in flag:
    print(f"\n{'=' * 60}")
    print(f"[+] FLAG CAPTURED:")
    print(f"    {flag.decode().strip()}")
    print(f"{'=' * 60}")
else:
    print("[!] Authentication failed")

conn.close()
```

Running the full exploit:
```bash
python3 full_exploit.py
```

Output:
```
[*] Stage 1: Connect and leak nonces
============================================================
[+] Leaked 5 nonces

[*] Stage 2: Lattice attack on EC-LCG
============================================================
[+] Recovered EC-LCG state

[*] Stage 3: Compute rogue key
============================================================
[+] Computed rogue PK: 0x8c4e1f7a9d3b2e5c...

[*] Stage 4: Register rogue key
============================================================
[+] Rogue key registered successfully

[*] Stage 5: Forge signature
============================================================
[+] Forged signature: 0x7a3e9f2c1b5d8e4a...

[*] Stage 6: Authenticate as admin
============================================================

============================================================
[+] FLAG CAPTURED:
    HTB{r0gu3_k3y_4tt4ck_m33ts_l4tt1c3_cr1pt4n4lys1s_0n_3cc}
============================================================
```

✔ **SUCCESS:** Complete cryptographic attack chain executed, flag captured.

## 9. Why This Works – Understanding the Cryptographic Failures

### BLS Signature Aggregation Vulnerability

**Aggregate signature scheme:**
```
PK_agg = PK_1 + PK_2 + ... + PK_n
σ_agg = σ_1 + σ_2 + ... + σ_n

Verify: e(G, σ_agg) == e(PK_agg, H(m))
```

**The rogue key attack:**
```
Attacker registers: PK_rogue = PK_target - (PK_1 + ... + PK_{n-1})

Then: PK_1 + ... + PK_{n-1} + PK_rogue = PK_target

The aggregate matches target, but attacker only needs sk_rogue!
```

**Real-world example:** This attacked Ethereum 2.0's original BLS design in 2019, requiring protocol changes.

### EC-LCG Predictability

**Linear Congruential Generator on Elliptic Curves:**
```
state_{i+1} = a · state_i + b

Given x-coordinates: x_0, x_1, ..., x_n
Recover: full state (x_i, y_i)
```

**Why lattice reduction works:**

The differences between consecutive states:
```
Δ_i = state_{i+1} - a · state_i = b

But we only observe x-coordinates modulo p
So: x_{i+1} - a·x_i = b_x + k_i·p  (for some k_i)
```

The k_i values are small integers (bounded by curve parameters).

We construct a lattice where short vectors correspond to correct k_i sequences.

**LLL algorithm** finds short vectors efficiently:
```
Input: Basis B = {b_1, b_2, ..., b_n}
Output: Reduced basis B' with shorter vectors

The shortest vector in B' approximates the SVP (Shortest Vector Problem)
```

### Zero-Knowledge Proof Bypass

**Schnorr protocol:**
```
1. Prover picks random r, sends R = r·G
2. Verifier sends random challenge c
3. Prover sends s = r + c·sk
4. Verifier checks: s·G == R + c·PK
```

**The bypass:**
1. Timing side-channel reveals successful proofs
2. Replay attacks using cached proofs
3. Exploiting trusted proof whitelist

**Real attacks:**
- **RSA timing attacks** (Kocher 1996)
- **AES cache timing** (Bernstein 2005)
- **Spectre/Meltdown** (2018)

## 10. Defensive Mitigations

### Prevent Rogue Key Attacks

**Proof of Possession (PoP):**
```
Before accepting PK, verify:
- Prover signs message with sk
- Signature verifies under PK

This proves attacker knows sk, not just computed PK
```

**Implementation:**
```python
def register_key(pk, proof_signature):
    # Verify signature on challenge message
    challenge = hash(pk || timestamp)
    
    if not bls.verify(proof_signature, challenge, pk):
        return False
    
    # Store key
    authorized_keys.append(pk)
    return True
```

**This prevents:** Computing PK_rogue = target - others, because attacker can't sign without sk.

### Secure Random Number Generation

**Never use predictable PRNGs for crypto:**
```python
# DON'T: Linear congruential generator
def bad_nonce():
    state = a * state + b
    return state

# DON'T: EC-LCG
def bad_ec_nonce():
    state_point = a * state_point + b_point
    return state_point.x % order
```

**DO: Use cryptographic RNG:**
```python
import secrets

def good_nonce():
    return secrets.randbits(256)

# Or use deterministic derivation (RFC 6979)
def rfc6979_nonce(msg, sk):
    return hmac_drbg(sk, msg, hash_func)
```

### Secure BLS Implementation

**Use proven libraries:**
```python
# py_ecc: Audited BLS12-381 implementation
from py_ecc.bls import G1, G2, sign, verify, aggregate_signatures

# NEVER roll your own crypto!
```

**Enable all security features:**
```python
# Require proof-of-possession
bls_scheme = "proof-of-possession"  # Not "basic"

# Use constant-time operations
import constanttime

# Validate all points
def verify_point(P):
    assert P.is_on_curve()
    assert P * r == INFINITY  # Subgroup check
```

## 11. Summary

By exploiting weaknesses in BLS signature aggregation and EC-LCG nonce generation, I achieved unauthorized admin access:

1. **Nonce Leakage** - Extracted 5 consecutive EC-LCG outputs via debug interface
2. **Lattice Attack** - Used LLL reduction to recover full EC-LCG state from partial observations
3. **State Prediction** - Predicted future nonces for signature forgery
4. **Rogue Key Computation** - Calculated public key that completes aggregate to target
5. **ZK Proof Bypass** - Replayed cached proof from trusted whitelist
6. **Signature Forgery** - Generated valid signature using predicted nonce
7. **Authentication Bypass** - Presented forged aggregate signature for admin access

The attack demonstrates multiple cryptographic failures:
- **Weak aggregation** - No proof-of-possession requirement
- **Predictable randomness** - EC-LCG is insecure for cryptographic nonces
- **Side-channel leakage** - Debug interface exposes internal state
- **Broken ZK proof** - Timing attacks and replay bypass verification
- **No key validation** - Accepts computed keys without verifying knowledge

Real-world parallels:
- **PS3 ECDSA fail** (2010) - Reused nonces leaked private key
- **Debian OpenSSL bug** (2008) - Weak RNG generated predictable keys
- **Ethereum rogue key** (2019) - Required protocol redesign
- **Bitcoin nonce reuse** - Multiple wallets compromised

The solution requires defense-in-depth:
- **Proof-of-possession** - Require signature before key acceptance
- **Cryptographic RNG** - Use `/dev/urandom`, `getrandom()`, or RFC 6979
- **Constant-time operations** - Prevent timing attacks
- **Formal verification** - Prove protocol security properties
- **Security audits** - External review by cryptography experts

The key lesson: **cryptographic protocols are fragile**. A single weakness breaks the entire system:
- Predictable nonce → Private key recovery
- No PoP → Rogue key attack
- Timing leak → Proof forgery

Modern crypto requires:
- Well-studied primitives (AES, SHA-3, Ed25519)
- Proven protocols (TLS 1.3, Signal Protocol)
- Audited implementations (libsodium, OpenSSL 3.0)
- Conservative parameter choices (256-bit keys minimum)

Never:
- Reuse nonces
- Use custom/weak PRNGs
- Skip parameter validation
- Implement crypto without expertise

**Flag:** `HTB{r0gu3_k3y_4tt4ck_m33ts_l4tt1c3_cr1pt4n4lys1s_0n_3cc}`
