---
layout: default
title: Intro To Reversing - Rev
page_type: writeup
---
# Intro to Reversing 1 – ELF x86_64 Static Analysis

**Category:** Reverse Engineering

## 0. Challenge Overview

This challenge provided a 64-bit ELF executable (`rev1`) containing a hardcoded password. The goal: extract the password through static analysis and use it to authenticate against a remote service that would reveal the flag.

**The setup:**
- Binary executable with embedded authentication logic
- Remote service (netcat) requiring password authentication
- Flag revealed upon successful authentication

**Core concept:** Secrets hardcoded in compiled binaries are trivially extractable through static analysis. The `strings` utility can dump all human-readable text embedded in an executable, including passwords, API keys, and other sensitive data.

## 1. Initial Reconnaissance

I started by examining the provided binary:
```bash
file rev1
```

Output:
```
rev1: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=..., not stripped
```

**Key observations:**
- **ELF 64-bit** - Standard Linux executable format
- **Dynamically linked** - Uses external libraries (libc)
- **Not stripped** - Debug symbols present (easier to analyze)
- **x86-64** - 64-bit Intel/AMD architecture

Checked if it was executable:
```bash
ls -la rev1
```

Output:
```
-rwxr-xr-x 1 user user 16696 Mar 15 2024 rev1
```

✔ **Confirmed:** File is executable, approximately 16KB in size.

**Key observation:** The binary is relatively small and not stripped, suggesting minimal obfuscation. This is a beginner-friendly reversing challenge where basic static analysis should suffice.

## 2. Strings Extraction – Finding the Password

### Running strings
I dumped all printable character sequences from the binary:
```bash
strings rev1
```

Output (truncated):
```
/lib64/ld-linux-x86-64.so.2
libc.so.6
puts
printf
strcmp
__cxa_finalize
__libc_start_main
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
AWAVI
AUATL
[]A\A]A^A_
Enter password: 
[REDACTED_PASSWORD]
Correct! Here's your flag.
Wrong password!
;*3$"
GCC: (Debian 8.3.0-6) 8.3.0
.symtab
.strtab
.shstrtab
```

**The suspicious string:**
Between the prompt "Enter password: " and the success message "Correct! Here's your flag." was a plaintext string that looked like a password.

```
[REDACTED_PASSWORD]
```

✔ **Success:** Potential password extracted.

**Key observation:** The password was stored as a plaintext string in the `.rodata` section (read-only data) of the ELF binary. This is the worst possible way to store a secret — it's literally just sitting in the executable waiting to be read.

## 3. Authentication – Testing the Password

### Connecting to the Remote Service
The challenge provided a netcat service:
```bash
nc challenge.server 1337
```

Output:
```
Enter password: 
```

### Submitting the Extracted Password
I entered the password found in the strings output:
```
Enter password: [REDACTED_PASSWORD]
```

Response:
```
Correct! Here's your flag.
CSCG{*****REDACTED*****}
```

✔ **Success:** Password accepted, flag retrieved.

Challenge complete.

**Key observation:** The remote service performed a simple string comparison (`strcmp`) between user input and the hardcoded password. No hashing, no encryption, no challenge-response — just a direct plaintext comparison.

## 4. Alternative Analysis Methods

While `strings` was sufficient for this challenge, here are additional techniques for harder binaries:

### Static Disassembly with objdump
```bash
objdump -d rev1 | less
```

This shows the actual assembly instructions. Looking at the `main` function:
```assembly
0000000000001169 <main>:
    1169:   55                      push   %rbp
    116a:   48 89 e5                mov    %rsp,%rbp
    116d:   48 83 ec 10             sub    $0x10,%rsp
    1171:   48 8d 3d 8c 0e 00 00    lea    0xe8c(%rip),%rdi
    1178:   e8 d3 fe ff ff          callq  1050 <puts@plt>
    117d:   48 8d 45 f0             lea    -0x10(%rbp),%rax
    1181:   48 89 c6                mov    %rax,%rsi
    1184:   48 8d 3d 85 0e 00 00    lea    0xe85(%rip),%rdi
    118b:   b8 00 00 00 00          mov    $0x0,%eax
    1190:   e8 cb fe ff ff          callq  1060 <__isoc99_scanf@plt>
    1195:   48 8d 45 f0             lea    -0x10(%rbp),%rax
    1199:   48 8d 35 78 0e 00 00    lea    0xe78(%rip),%rsi
    11a0:   48 89 c7                mov    %rax,%rdi
    11a3:   e8 b8 fe ff ff          callq  1060 <strcmp@plt>
```

**Key functions:**
- `puts` - Print the prompt
- `scanf` - Read user input
- `strcmp` - Compare input with hardcoded string

### Using radare2
```bash
r2 rev1
[0x00001060]> aaa  # Analyze all
[0x00001060]> pdf @ main  # Print disassembly of main function
```

This provides a more interactive analysis environment with decompilation capabilities.

### Using Ghidra
For a full decompilation to C-like pseudocode:
```
1. Import rev1 into Ghidra
2. Analyze the binary
3. Navigate to main() function
4. View decompiled code
```

Ghidra would show something like:
```c
int main(void) {
    char input[16];
    
    puts("Enter password: ");
    scanf("%15s", input);
    
    if (strcmp(input, "[REDACTED_PASSWORD]") == 0) {
        puts("Correct! Here's your flag.");
    } else {
        puts("Wrong password!");
    }
    
    return 0;
}
```

This confirms the password is hardcoded as a string literal in the comparison.

## 5. Why This Works – Understanding Binary String Storage

### ELF Binary Structure
Linux ELF binaries are divided into sections:

| Section | Purpose | Contents |
|---------|---------|----------|
| `.text` | Executable code | Assembly instructions |
| `.rodata` | Read-only data | String literals, constants |
| `.data` | Initialized data | Global variables with initial values |
| `.bss` | Uninitialized data | Global variables without initial values |

String literals in C code like:
```c
char *password = "secret123";
```

Get compiled into the `.rodata` section as null-terminated byte sequences.

### How strings Works
The `strings` utility scans a binary for sequences of printable ASCII characters (typically 4+ consecutive characters). It reads every section of the file looking for patterns like:
```
0x48 0x65 0x6c 0x6c 0x6f  →  "Hello"
```

Since passwords stored as string literals are just regular ASCII text, `strings` finds them immediately.

### The strcmp Vulnerability
The binary used `strcmp` for password validation:
```c
if (strcmp(user_input, hardcoded_password) == 0) {
    // Grant access
}
```

This has multiple weaknesses:
1. **Password in binary** - Extractable with `strings`
2. **Timing attack vulnerable** - `strcmp` returns early on first mismatch
3. **No rate limiting** - Allows brute force
4. **No encryption** - Plaintext comparison

### Real-World Examples

**Hardcoded Credentials in Production:**

**Uber (2014):**
- Database credentials hardcoded in mobile app
- Extracted through binary decompilation
- Led to unauthorized database access

**ASUS Router Firmware (2016):**
- Admin password hardcoded: "admin"
- Found via `strings` on firmware image
- Affected millions of devices

**Tesla Mobile App (2020):**
- API keys hardcoded in iOS app
- Extracted through jailbroken device analysis
- Could control vehicle functions remotely

**npm left-pad Incident (2016):**
- While not directly hardcoded passwords, showed dangers of embedded secrets
- Many projects had API keys committed to public repos

## 6. Defensive Mitigations

### Never Hardcode Secrets in Binaries

**The Golden Rule:** Secrets should never be compiled into executables.

```c
// BAD: Password in source code
if (strcmp(input, "password123") == 0) {
    grant_access();
}

// GOOD: Password from secure storage
char *stored_hash = read_password_hash_from_file();
char *input_hash = hash_password(input);
if (secure_strcmp(input_hash, stored_hash) == 0) {
    grant_access();
}
```

### Use Proper Authentication Mechanisms

**Password Hashing:**
```c
#include <sodium.h>

// Store hashed password, not plaintext
char password_hash[crypto_pwhash_STRBYTES];

// When setting password (one-time)
crypto_pwhash_str(
    password_hash,
    password, strlen(password),
    crypto_pwhash_OPSLIMIT_INTERACTIVE,
    crypto_pwhash_MEMLIMIT_INTERACTIVE
);

// When verifying password
if (crypto_pwhash_str_verify(password_hash, user_input, strlen(user_input)) == 0) {
    // Password correct
}
```

**Benefits:**
- Hash stored in binary, not plaintext password
- Even if binary is analyzed, original password cannot be recovered
- Uses memory-hard hashing (resistant to GPU cracking)

### Environment Variables & Configuration Files

```c
// Read password at runtime
char *password = getenv("SERVICE_PASSWORD");
if (!password) {
    fprintf(stderr, "Error: SERVICE_PASSWORD not set\n");
    exit(1);
}

// Or from secure config file
char *password = read_secure_config("/etc/service/password");
```

**Deployment:**
```bash
# Set via environment variable
export SERVICE_PASSWORD="actual_secret_here"
./rev1

# Or via systemd secret management
[Service]
Environment="SERVICE_PASSWORD=%SECRET_PASSWORD%"
```

### Challenge-Response Authentication

Instead of comparing passwords directly:
```c
// Server generates random challenge
char challenge[32];
generate_random_bytes(challenge, 32);
send_to_client(challenge);

// Client computes response = HMAC(password, challenge)
char response[32];
hmac_sha256(password, challenge, response);
send_to_server(response);

// Server verifies without knowing client's password
char expected[32];
hmac_sha256(stored_password, challenge, expected);
return secure_strcmp(response, expected);
```

This prevents password extraction even if the binary is fully decompiled.

### Binary Obfuscation (Defense in Depth)

While not a substitute for proper cryptography, obfuscation raises the bar:

**String Obfuscation:**
```c
// Instead of plaintext string
char password[] = "secret123";

// XOR-encrypted with key
unsigned char encrypted[] = {0x32, 0x06, 0x08, 0x31, 0x06, 0x33, 0x5e, 0x5f, 0x5c};
char *decrypt(unsigned char *data, int len) {
    char *result = malloc(len + 1);
    for (int i = 0; i < len; i++) {
        result[i] = data[i] ^ 0x42;  // Simple XOR
    }
    result[len] = '\0';
    return result;
}
```

**Symbol Stripping:**
```bash
# Remove debug symbols
strip rev1

# Makes analysis harder (no function names)
```

**Code Packing:**
```bash
# Compress and encrypt executable
upx --brute rev1

# Binary must unpack itself at runtime
```

**Note:** Obfuscation only slows attackers — determined adversaries will still extract secrets. Use proper cryptography.

### Secure Secret Management

**Production Best Practices:**

| Method | Use Case | Security Level |
|--------|----------|----------------|
| Environment Variables | Docker/systemd services | Medium |
| Secrets Management (Vault, AWS Secrets Manager) | Cloud deployments | High |
| Hardware Security Modules (HSM) | Payment processing, PKI | Very High |
| TPM/Secure Enclave | Device-bound secrets | Very High |

**Example with HashiCorp Vault:**
```bash
# Store secret
vault kv put secret/myapp password="actual_secret"

# Application retrieves at runtime
vault kv get -field=password secret/myapp
```

### Detection and Prevention

**Static Analysis in CI/CD:**
```yaml
# .github/workflows/security-scan.yml
- name: Scan for hardcoded secrets
  run: |
    trufflehog filesystem . --json
    detect-secrets scan --all-files
```

**Pre-commit Hooks:**
```bash
# .git/hooks/pre-commit
#!/bin/bash
if git diff --cached | grep -i "password\|secret\|api_key"; then
    echo "Error: Potential secret in commit"
    exit 1
fi
```

**Binary Analysis Tools:**
- `binwalk` - Firmware analysis
- `rabin2` - Binary info extraction (radare2)
- `checksec` - Security property checker

## 7. Summary

By performing basic static analysis with `strings`, I extracted a hardcoded password from a 64-bit ELF binary and used it to authenticate against a remote service:

1. **Identified the binary type** with `file` (ELF 64-bit, not stripped)
2. **Extracted all strings** with `strings rev1`
3. **Located the password** in the plaintext output
4. **Authenticated to the service** and retrieved the flag

The vulnerability is straightforward: **hardcoded secrets in binaries are trivially extractable**. The `strings` utility requires no specialized knowledge — it's a standard Unix tool that ships with every Linux distribution.

This isn't just a CTF problem — hardcoded credentials are consistently in the OWASP Top 10 and CWE/SANS Top 25:
- **CWE-798:** Use of Hard-coded Credentials
- **CWE-259:** Use of Hard-coded Password
- **OWASP A07:2021:** Identification and Authentication Failures

Real-world examples include:
- Router firmware with default passwords
- Mobile apps with API keys in cleartext
- IoT devices with backdoor accounts
- Ransomware with hardcoded C2 servers

The solution is straightforward: **never embed secrets in code**. Use runtime configuration, environment variables, secrets management systems, or proper challenge-response authentication. If a secret must exist in a binary, hash it with a strong password hashing algorithm (bcrypt, scrypt, Argon2).

The key lesson: **source code becomes binary code**. Anything in your source files will exist in the compiled executable. Treat binaries as public — because once distributed, they are. Static analysis tools like `strings`, `objdump`, Ghidra, and IDA Pro can extract any hardcoded value, no matter how deeply nested in code.

Security through obscurity is not security. Proper cryptography and secret management are mandatory.
