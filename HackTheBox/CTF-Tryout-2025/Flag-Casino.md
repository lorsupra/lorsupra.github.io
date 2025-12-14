---
layout: default
title: Flag Casino - Rev
page_type: writeup
---

# HTB: Flag Casino – Predictable PRNG Exploitation

**Category:** Reverse Engineering

## 0. Challenge Overview

This challenge presented a "casino" binary that validates user input character-by-character using a pseudo-random number generator (PRNG). The goal: predict the PRNG outputs to construct the correct flag string.

**The setup:**
- ELF 64-bit executable (not stripped)
- Character-by-character validation using `rand()`
- Each character seeds `srand()` with its ASCII value
- Expected values stored in a `check[]` array at `0x4080`

**Core concept:** The C standard library `rand()` is deterministic - same seed produces same output. By brute-forcing all printable ASCII characters for each position and comparing against expected values, we can recover the flag.

## 1. Initial Reconnaissance

I examined the binary:
```bash
file casino
```

Output:
```
casino: ELF 64-bit LSB pie executable, x86-64, dynamically linked
```

Checked security features:
```bash
checksec casino
```

Output:
```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        PIE enabled
Stripped:   No
```

Ran the binary:
```bash
./casino
```

Output:
```
[ ** WELCOME TO ROBO CASINO **]
     ,     ,
    (\____/)
     (_oo_)
       (O)
     __||__    \)
  []/______\[] /
  / \______/ \/
 /    /__\
(\   /____\
---------------------
[*** PLEASE PLACE YOUR BETS ***]
> test
[ ** WRONG!! COME BACK ANOTHER TIME ** ]
```

**Key observation:** The binary accepts input and immediately rejects it. This suggests character-by-character validation with no tolerance for errors.

## 2. Reverse Engineering the Validation

Listed symbols:
```bash
nm casino | grep -E "main|check"
```

Output:
```
0000000000004080 D check
0000000000001185 T main
```

**Two key symbols:**
- `main` at `0x1185` - entry point
- `check` at `0x4080` - data array

I disassembled `main` using Ghidra and reconstructed the logic:

```c
#include <stdio.h>
#include <stdlib.h>

unsigned int check[] = {
    0x244b28be, 0x0af77805, 0x110dfc17, 0x07afc3a1,
    0x6afec533, 0x4ed659a2, 0x33c5d4b0, 0x286582b8,
    0x43383720, 0x055a14fc, 0x19195f9f, 0x43383720,
    0x63149380, 0x615ab299, 0x6afec533, 0x6c6fcfb8,
    0x43383720, 0x0f3da237, 0x6afec533, 0x615ab299,
    0x286582b8, 0x055a14fc, 0x3ae44994, 0x06d7dfe9,
    0x4ed659a2, 0x0ccd4acd, 0x57d8ed64, 0x615ab299,
    0x2abce922
};

int main() {
    char input[100];
    printf("[*** PLEASE PLACE YOUR BETS ***]\n> ");
    fgets(input, sizeof(input), stdin);

    for (int i = 0; i < 29; i++) {
        char c = input[i];

        // Seed PRNG with character ASCII value
        srand((unsigned int)c);

        // Get random value
        unsigned int random_val = rand();

        // Compare with expected value
        if (random_val == check[i]) {
            printf("[ * CORRECT *]\n");
        } else {
            printf("[ ** WRONG!! COME BACK ANOTHER TIME ** ]\n");
            return 1;
        }
    }

    printf("[ ** HOUSE BALANCE $0 - PLEASE COME BACK LATER ** ]\n");
    return 0;
}
```

**The vulnerability:**
```c
srand(input[i]);        // Seed with user input
random_val = rand();    // Get "random" value
if (random_val == check[i]) { ... }
```

**Key observation:** `rand()` is completely deterministic. Seeding with the same value always produces the same output. Since we control the input, we control the seed.

## 3. Understanding the PRNG Weakness

### How rand() Works

The C `rand()` function is a **linear congruential generator (LCG)**:

```c
state = (state * 1103515245 + 12345) % (2^31)
return state
```

**Key property:** Given the same seed, the sequence is identical.

```c
srand(72);  // Seed with 'H' (ASCII 72)
rand();     // Always returns 0x244b28be

srand(84);  // Seed with 'T' (ASCII 84)
rand();     // Always returns 0x0af77805
```

### The Attack Vector

For each character position:
1. Try all printable ASCII (32-126)
2. For each candidate: `srand(candidate); result = rand()`
3. Compare `result` with `check[position]`
4. When match found → that's the correct character

**Search space:** 95 characters per position × 29 positions = 2,755 total attempts (trivial)

## 4. Exploitation Script

```python
#!/usr/bin/env python3
from ctypes import CDLL, c_uint

# Load libc for srand/rand
libc = CDLL('libc.so.6')

# Expected values from check array at 0x4080
expected = [
    0x244b28be, 0x0af77805, 0x110dfc17, 0x07afc3a1,
    0x6afec533, 0x4ed659a2, 0x33c5d4b0, 0x286582b8,
    0x43383720, 0x055a14fc, 0x19195f9f, 0x43383720,
    0x63149380, 0x615ab299, 0x6afec533, 0x6c6fcfb8,
    0x43383720, 0x0f3da237, 0x6afec533, 0x615ab299,
    0x286582b8, 0x055a14fc, 0x3ae44994, 0x06d7dfe9,
    0x4ed659a2, 0x0ccd4acd, 0x57d8ed64, 0x615ab299,
    0x2abce922
]

solution = []

# For each expected value, find the character that produces it
for i, target in enumerate(expected):
    found = False
    
    # Try all printable ASCII characters
    for c in range(32, 127):
        char = chr(c)
        
        # Seed with character value
        libc.srand(c)
        
        # Get rand() result
        result = c_uint(libc.rand()).value

        if result == target:
            solution.append(char)
            print(f"Position {i+1:2d}: '{char}' (ASCII {c:3d}) -> 0x{result:08x}")
            found = True
            break

    if not found:
        print(f"Position {i+1:2d}: NOT FOUND for 0x{target:08x}")
        solution.append('?')

print("\n" + "="*60)
print("FLAG:")
print(''.join(solution))
print("="*60)
```

Running the exploit:
```bash
python3 solve.py
```

Output:
```
Position  1: 'H' (ASCII  72) -> 0x244b28be
Position  2: 'T' (ASCII  84) -> 0x0af77805
Position  3: 'B' (ASCII  66) -> 0x110dfc17
Position  4: '{' (ASCII 123) -> 0x07afc3a1
Position  5: 'r' (ASCII 114) -> 0x6afec533
Position  6: '4' (ASCII  52) -> 0x4ed659a2
Position  7: 'n' (ASCII 110) -> 0x33c5d4b0
Position  8: 'd' (ASCII 100) -> 0x286582b8
Position  9: '_' (ASCII  95) -> 0x43383720
Position 10: '1' (ASCII  49) -> 0x055a14fc
Position 11: 's' (ASCII 115) -> 0x19195f9f
Position 12: '_' (ASCII  95) -> 0x43383720
Position 13: 'v' (ASCII 118) -> 0x63149380
Position 14: '3' (ASCII  51) -> 0x615ab299
Position 15: 'r' (ASCII 114) -> 0x6afec533
Position 16: 'y' (ASCII 121) -> 0x6c6fcfb8
Position 17: '_' (ASCII  95) -> 0x43383720
Position 18: 'p' (ASCII 112) -> 0x0f3da237
Position 19: 'r' (ASCII 114) -> 0x6afec533
Position 20: '3' (ASCII  51) -> 0x615ab299
Position 21: 'd' (ASCII 100) -> 0x286582b8
Position 22: '1' (ASCII  49) -> 0x055a14fc
Position 23: 'c' (ASCII  99) -> 0x3ae44994
Position 24: 't' (ASCII 116) -> 0x06d7dfe9
Position 25: '4' (ASCII  52) -> 0x4ed659a2
Position 26: 'b' (ASCII  98) -> 0x0ccd4acd
Position 27: 'l' (ASCII 108) -> 0x57d8ed64
Position 28: '3' (ASCII  51) -> 0x615ab299
Position 29: '}' (ASCII 125) -> 0x2abce922

============================================================
FLAG:
HTB{r4nd_1s_v3ry_pr3d1ct4bl3}
============================================================
```

## 5. Verification

I verified the flag:
```bash
echo "HTB{r4nd_1s_v3ry_pr3d1ct4bl3}" | ./casino
```

Output:
```
[ ** WELCOME TO ROBO CASINO **]
...
[*** PLEASE PLACE YOUR BETS ***]
> [ * CORRECT *]
> [ * CORRECT *]
> [ * CORRECT *]
... (29 times)
> [ * CORRECT *]
[ ** HOUSE BALANCE $0 - PLEASE COME BACK LATER ** ]
```

✔ **Success:** All characters validated. Flag retrieved.

## 6. Why This Works – Understanding PRNG Security

### The Fundamental Problem

```c
// VULNERABLE: Predictable seeding
srand(user_input);
if (rand() == secret_value) {
    // User can brute-force this!
}
```

**Issues:**
1. **Deterministic output** - Same seed = same sequence
2. **Small input space** - Only 95 printable ASCII chars
3. **Known algorithm** - LCG is well-studied and reversible

### Linear Congruential Generators (LCG)

The `rand()` implementation:
```c
static unsigned long next = 1;

int rand(void) {
    next = next * 1103515245 + 12345;
    return (unsigned int)(next / 65536) % 32768;
}

void srand(unsigned int seed) {
    next = seed;
}
```

**Properties:**
- **Period:** ~2^31 before repeating
- **Predictable:** Given one output, can compute all future outputs
- **Not cryptographically secure:** Statistical patterns emerge

### Real-World PRNG Failures

**Debian OpenSSL Bug (2008):**
```c
// Vulnerable code
MD_Update(&m, buf, j);  // j was always 0 due to bug
// Only 32,768 possible keys instead of 2^128
```
Affected SSH keys, SSL certificates worldwide.

**PHP mt_rand() Seed Recovery:**
```php
// Single mt_rand() output reveals internal state
mt_srand(time());  // Only 2^32 possible seeds
$token = mt_rand();  // Predictable
```

**Casino RNG Exploits:**
- Video poker machines (1990s) - Predictable seed from clock
- Slot machines - PRNG state leaked via timing
- Online poker - Weak shuffle algorithms

**Android Bitcoin Wallet (2013):**
```java
// SecureRandom was not properly seeded
SecureRandom sr = new SecureRandom();
// On Android 4.2, this was deterministic!
```
Multiple wallets generated identical keys.

## 7. Defensive Mitigations

### Never Use rand() for Security

```c
// WRONG: rand() for secrets
srand(time(NULL));
int session_id = rand();

// WRONG: rand() for crypto
srand(getpid());
char key[16];
for (int i = 0; i < 16; i++) {
    key[i] = rand() % 256;
}
```

### Use Cryptographically Secure RNGs

**Linux: getrandom() syscall**
```c
#include <sys/random.h>

unsigned char buffer[32];
ssize_t result = getrandom(buffer, sizeof(buffer), 0);

if (result == -1) {
    perror("getrandom");
    exit(1);
}
```

**POSIX: /dev/urandom**
```c
FILE *urandom = fopen("/dev/urandom", "rb");
unsigned char buffer[32];
fread(buffer, 1, sizeof(buffer), urandom);
fclose(urandom);
```

**OpenSSL**
```c
#include <openssl/rand.h>

unsigned char buffer[32];
if (RAND_bytes(buffer, sizeof(buffer)) != 1) {
    // Error handling
}
```

**Windows**
```c
#include <windows.h>
#include <bcrypt.h>

BYTE buffer[32];
BCryptGenRandom(NULL, buffer, sizeof(buffer), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
```

### Proper Seed Management

Even cryptographic PRNGs need good seeds:

**Bad seeding:**
```c
// Predictable: only 2^32 possible seeds
srand(time(NULL));

// Worse: always same seed
srand(12345);

// Dangerous: PID is guessable
srand(getpid());
```

**Good seeding:**
```c
// Use hardware entropy
unsigned int seed;
getrandom(&seed, sizeof(seed), 0);
srand(seed);  // If you must use rand()

// Better: Don't use rand() at all
```

### When rand() is Acceptable

**Non-security contexts only:**
- Game mechanics (procedural generation)
- Simulations
- Testing/fuzzing
- Visual effects

**Even then, document it:**
```c
// NOTE: Using rand() for game content generation only
// NOT suitable for security-critical operations
srand(time(NULL));
int enemy_spawn_x = rand() % MAP_WIDTH;
```

### Secure Implementation Example

```c
// Secure random session token generation
#include <sys/random.h>
#include <stdint.h>

void generate_session_token(char *token, size_t length) {
    unsigned char random_bytes[length];
    
    // Get cryptographically secure random bytes
    if (getrandom(random_bytes, length, 0) != (ssize_t)length) {
        perror("getrandom failed");
        exit(1);
    }
    
    // Convert to hex string
    for (size_t i = 0; i < length; i++) {
        sprintf(&token[i*2], "%02x", random_bytes[i]);
    }
}

// Usage
char session[65];  // 32 bytes = 64 hex chars + null
generate_session_token(session, 32);
```

### Testing for Weak RNG

**Statistical tests:**
```bash
# Generate sample from PRNG
for i in {1..1000000}; do
    ./your_rng
done > samples.txt

# Test with dieharder
dieharder -a -f samples.txt

# Test with ent
ent samples.txt
```

**Reversibility test:**
```python
# Can you predict next value from current?
def predict_next(current_output):
    # If this succeeds, RNG is weak
    pass
```

## 8. Summary

By recognizing that `rand()` with user-controlled seeds is deterministic, I brute-forced each character position to reconstruct the flag:

1. **Reverse engineered validation logic** - character-by-character check with `srand(char)`
2. **Extracted expected values** - 29 PRNG outputs from `check[]` array at `0x4080`
3. **Brute-forced each position** - tried all 95 printable ASCII chars
4. **Matched outputs** - found character that produces expected `rand()` result
5. **Reconstructed flag** - combined all 29 characters

The vulnerability is straightforward: **`rand()` is not cryptographically secure**. It's designed for simulations and games, not security. Using it with predictable or user-controlled seeds makes it trivially breakable.

This mirrors real-world failures:
- **Weak session tokens** - PHP `mt_rand()` tokens cracked in minutes
- **Predictable encryption keys** - Debian OpenSSL bug compromised millions of keys  
- **Casino exploits** - PRNG state recovery enabled jackpot prediction
- **Cryptographic failures** - Android Bitcoin wallets generated duplicate keys

The fix is mandatory: **use cryptographically secure RNGs** (`getrandom()`, `/dev/urandom`, `RAND_bytes()`) for anything security-related. The performance difference is negligible (~microseconds), and the security improvement is absolute.

The key lesson: **random !== secure random**. `rand()` provides unpredictable behavior for games but predictable behavior for attackers. For security, use CSPRNGs (Cryptographically Secure Pseudo-Random Number Generators) that resist:
- Prediction (forward security)
- State recovery (backward security)
- Pattern analysis (statistical indistinguishability)

**Flag:** `HTB{r4nd_1s_v3ry_pr3d1ct4bl3}`
