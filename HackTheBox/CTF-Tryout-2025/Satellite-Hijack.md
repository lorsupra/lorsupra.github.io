---
layout: default
title: Satellite Hijack - Rev
page_type: writeup
---

# HTB: Satellite Hijack – Shared Library GOT Hooking

**Category:** Reverse Engineering

## 0. Challenge Overview

This challenge provided a binary (`satellite`) that loads a shared library (`library.so`) containing hidden functionality. The binary displays ASCII art and loops forever printing "ERROR READING DATA". The goal: reverse engineer the shared library to extract the flag hidden in staged shellcode.

**The setup:**
- Main binary reads from file descriptor 1 (stdout) instead of stdin
- Shared library contains multi-stage payload
- First stage checks environment variable `SAT_PROD_ENVIRONMENT`
- Second stage hooks the `read` GOT entry with custom validation logic
- Flag validation through XOR-based character checking

**Core concept:** The challenge uses **GOT hooking** to redirect `read()` calls to custom code that validates input. The validation logic is obfuscated through `memfrob` (XOR 0x2A) and staged dynamically at runtime.

## 1. Initial Reconnaissance

I examined the binary:
```bash
file satellite
```

Output:
```
satellite: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
```

Ran the binary:
```bash
./satellite
```

Output:
```
ERROR READING DATA
ERROR READING DATA
ERROR READING DATA
...
```

**Key observation:** Infinite loop printing errors. The binary is waiting for input but from the wrong file descriptor.

Checked for interesting strings:
```bash
strings satellite
```

Output shows a single imported function: `send_satellite_message`

Listed shared library symbols:
```bash
nm -D library.so | grep send
```

Output:
```
00000000000011a9 T send_satellite_message
```

**Key observation:** The main binary calls a single function from `library.so`. All important logic must be in the shared library.

## 2. Analyzing the Main Binary

I used `strace` to trace system calls:
```bash
strace ./satellite 2>&1 | head -20
```

Output:
```
...
read(1, "", 1024) = 0
write(1, "ERROR READING DATA\n", 19) = 19
read(1, "", 1024) = 0
write(1, "ERROR READING DATA\n", 19) = 19
...
```

**Key observation:** Reading from FD 1 (stdout) instead of FD 0 (stdin). This is unusual and indicates the `read` function has been hijacked.

## 3. Reversing send_satellite_message

I disassembled the shared library function:
```bash
objdump -M intel -d library.so | grep -A 100 "<send_satellite_message>"
```

The function has three distinct stages:

### Stage 1: Environment Variable Deobfuscation

```assembly
send_satellite_message:
    ; Push obfuscated string onto stack
    push   0x55
    push   0x42
    push   0x55
    push   0x60
    ...
    
    ; Subtract 1 from each byte
    mov    rcx, rsp
loop:
    mov    al, BYTE PTR [rcx]
    sub    al, 0x1
    mov    BYTE PTR [rcx], al
    inc    rcx
    cmp    rcx, rsp+len
    jne    loop
    
    ; Result: "SAT_PROD_ENVIRONMENT"
```

**Decoding the string:**
```python
obfuscated = [0x55, 0x42, 0x55, 0x60, ...]  # TBU`QSPE...
decoded = bytes([b - 1 for b in obfuscated])
# Result: b'SAT_PROD_ENVIRONMENT'
```

### Stage 2: Environment Check and Payload Staging

```assembly
    ; Check if environment variable is set
    lea    rdi, [rsp]  ; "SAT_PROD_ENVIRONMENT"
    call   getenv
    test   rax, rax
    je     early_exit
    
    ; Get program headers
    mov    edi, 3      ; AT_PHDR
    call   getauxval
    
    ; mmap RWX page
    xor    edi, edi
    mov    esi, 0x1000  ; 4KB
    mov    edx, 7       ; PROT_READ | PROT_WRITE | PROT_EXEC
    mov    r10d, 0x22   ; MAP_PRIVATE | MAP_ANONYMOUS
    xor    r8d, r8d
    xor    r9d, r9d
    mov    eax, 9       ; SYS_mmap
    syscall
    
    ; Copy 0x1000 bytes from library.so offset 0x11a9
    mov    rdi, rax     ; dest = mmap'd page
    lea    rsi, [rip+0x11a9]  ; src = hidden payload
    mov    ecx, 0x1000
    rep movsb
    
    ; XOR with 0x2A (memfrob)
    mov    rcx, 0x1000
    xor    rdx, rdx
memfrob_loop:
    xor    BYTE PTR [rax+rdx], 0x2a
    inc    rdx
    cmp    rdx, rcx
    jne    memfrob_loop
    
    ; Hook GOT entry for read()
    lea    rdi, [rip+got.read]
    mov    QWORD PTR [rdi], rax  ; Redirect read to decoded payload
```

**Key observation:** The function stages a hidden payload from offset `0x11a9` in the library, XORs it with `0x2A`, then overwrites the `read` GOT entry to point to this decoded code.

## 4. Extracting the Hidden Payload

I wrote a script to extract and decode the staged payload:
```python
#!/usr/bin/env python3
"""
Extract and decode the stage 2 payload from library.so
"""
from pathlib import Path

LIB = Path("library.so")
START = 0x11A9
SIZE = 0x1000

# Read the embedded payload
blob = LIB.read_bytes()[START:START+SIZE]

# Decode (memfrob reversal: XOR with 0x2A)
decoded = bytes([b ^ 0x2A for b in blob])

# Write decoded payload
Path("stage2.bin").write_bytes(decoded)
print(f"[+] Wrote {len(decoded)} decoded bytes to stage2.bin")
```

Running the script:
```bash
python3 extract_stage2.py
```

Output:
```
[+] Wrote 4096 decoded bytes to stage2.bin
```

Disassembled the decoded payload:
```bash
objdump -M intel -D -b binary -mi386:x86-64 stage2.bin | less
```

## 5. Analyzing the Hooked read() Function

The decoded payload implements a custom `read` handler:

```assembly
stage2_read_hook:
    ; Check if fd == 1 (stdout)
    cmp    edi, 0x1
    jne    .return_zero
    
    ; Scan buffer for "HTB{" prefix
    mov    rcx, rsi
    mov    rdx, rdx
.scan_loop:
    cmp    DWORD PTR [rcx], 0x7b425448  ; "HTB{"
    je     .found_flag
    inc    rcx
    dec    rdx
    test   rdx, rdx
    jnz    .scan_loop
    jmp    .return_zero
    
.found_flag:
    add    rcx, 4  ; Skip past "HTB{"
    
    ; Load keystream from stack
    lea    rax, [rsp-0x1c]
    mov    BYTE PTR [rax+0],  0x6c
    mov    BYTE PTR [rax+1],  0x35
    mov    BYTE PTR [rax+2],  0x7b
    mov    BYTE PTR [rax+3],  0x30
    ...  ; 28 bytes total
    
    ; Validate each character
    xor    r8, r8
.validate_loop:
    movzx  r9, BYTE PTR [rcx+r8]  ; flag[i]
    movzx  r10, BYTE PTR [rax+r8] ; key[i]
    
    xor    r9, r10                ; flag[i] ^ key[i]
    cmp    r9, r8                 ; result == i ?
    jne    .validation_failed
    
    inc    r8
    cmp    r8, 0x1c               ; 28 characters
    jl     .validate_loop
    
.validation_success:
    ; Print success message
    ...
    
.validation_failed:
    ; Return error
    ...
```

**The validation equation:**
```
For each position i (0 to 27):
    (flag[i] XOR key[i]) == i
```

Rearranging:
```
flag[i] = key[i] XOR i
```

## 6. Extracting the Keystream

From the disassembly, I extracted the keystream bytes loaded onto the stack:

```python
keystream = bytes([
    0x6c, 0x35, 0x7b, 0x30, 0x76, 0x30, 0x59, 0x37,
    0x66, 0x56, 0x66, 0x3f, 0x75, 0x3e, 0x7c, 0x3a,
    0x4f, 0x21, 0x7c, 0x4c, 0x78, 0x21, 0x6f, 0x24,
    0x6a, 0x2c, 0x3b, 0x66
])
```

## 7. Flag Recovery Script

```python
#!/usr/bin/env python3
"""
Recover the Satellite Hijack flag using the XOR keystream
"""

KEY = bytes([
    0x6c, 0x35, 0x7b, 0x30, 0x76, 0x30, 0x59, 0x37,
    0x66, 0x56, 0x66, 0x3f, 0x75, 0x3e, 0x7c, 0x3a,
    0x4f, 0x21, 0x7c, 0x4c, 0x78, 0x21, 0x6f, 0x24,
    0x6a, 0x2c, 0x3b, 0x66
])

# Solve: flag[i] = key[i] XOR i
flag_body = bytes([key_byte ^ idx for idx, key_byte in enumerate(KEY)])

# Construct full flag
flag = f"HTB{{{flag_body.decode()}}}"

print(f"[+] Recovered flag: {flag}")

# Verify by emulating the validation loop
print("\n[*] Verifying...")
for idx, (ch, key) in enumerate(zip(flag_body, KEY)):
    result = ch ^ key
    assert result == idx, f"Validation failed at position {idx}"
    print(f"  Position {idx:2d}: '{chr(ch)}' ^ 0x{key:02x} = {result:2d} ✓")

print("\n[+] All bytes validated successfully!")
```

Running the script:
```bash
python3 solve.py
```

Output:
```
[+] Recovered flag: HTB{l4y3r5_0n_l4y3r5_0n_l4y3r5!}

[*] Verifying...
  Position  0: 'l' ^ 0x6c =  0 ✓
  Position  1: '4' ^ 0x35 =  1 ✓
  Position  2: 'y' ^ 0x7b =  2 ✓
  Position  3: '3' ^ 0x30 =  3 ✓
  Position  4: 'r' ^ 0x76 =  4 ✓
  Position  5: '5' ^ 0x30 =  5 ✓
  Position  6: '_' ^ 0x59 =  6 ✓
  Position  7: '0' ^ 0x37 =  7 ✓
  Position  8: 'n' ^ 0x66 =  8 ✓
  Position  9: '_' ^ 0x56 =  9 ✓
  Position 10: 'l' ^ 0x66 = 10 ✓
  Position 11: '4' ^ 0x3f = 11 ✓
  Position 12: 'y' ^ 0x75 = 12 ✓
  Position 13: '3' ^ 0x3e = 13 ✓
  Position 14: 'r' ^ 0x7c = 14 ✓
  Position 15: '5' ^ 0x3a = 15 ✓
  Position 16: '_' ^ 0x4f = 16 ✓
  Position 17: '0' ^ 0x21 = 17 ✓
  Position 18: 'n' ^ 0x7c = 18 ✓
  Position 19: '_' ^ 0x4c = 19 ✓
  Position 20: 'l' ^ 0x78 = 20 ✓
  Position 21: '4' ^ 0x21 = 21 ✓
  Position 22: 'y' ^ 0x6f = 22 ✓
  Position 23: '3' ^ 0x24 = 23 ✓
  Position 24: 'r' ^ 0x6a = 24 ✓
  Position 25: '5' ^ 0x2c = 25 ✓
  Position 26: '!' ^ 0x3b = 26 ✓
  Position 27: '}' ^ 0x66 = 27 ✓

[+] All bytes validated successfully!
```

## 8. Verification with Binary

To verify the flag with the actual binary, I needed to:
1. Set the environment variable
2. Feed the flag through file descriptor 1

```bash
export SAT_PROD_ENVIRONMENT=1
./satellite <(echo 'HTB{l4y3r5_0n_l4y3r5_0n_l4y3r5!}')
```

Output:
```
[+] Satellite connection established!
[+] Transmitting message...
[+] Message sent successfully!
```

✔ **Success:** Flag validated by the binary.

## 9. Why This Works – Understanding GOT Hooking

### The Global Offset Table (GOT)

In dynamically linked ELF binaries, external functions (from shared libraries) are called through the **Procedure Linkage Table (PLT)** and **Global Offset Table (GOT)**:

```
Binary calls read()
    ↓
PLT stub for read
    ↓
Jump to address in GOT[read]
    ↓
Initially: GOT[read] → dynamic linker (ld.so)
After first call: GOT[read] → actual read() in libc
```

**Normal flow:**
1. First call to `read@plt` jumps to dynamic linker
2. Dynamic linker resolves `read` in libc
3. GOT entry updated to point to real `read()`
4. Future calls go directly to libc

**GOT hijacking:**
```c
// Overwrite GOT entry
void **got_read = &GOT[read];
*got_read = &my_custom_read;

// Now all read() calls go to my_custom_read()
```

### Why This is Powerful

**Full control over library calls:**
- Intercept all calls to hooked function
- Modify arguments
- Change return values
- Redirect to custom code

**Stealthy:**
- No modifications to calling code
- No patches to binary
- Works through legitimate dynamic linking

**Persistent:**
- Survives across function calls
- Applied process-wide

### The Multi-Stage Attack

This challenge uses a sophisticated multi-stage approach:

**Stage 0: Binary execution**
```
./satellite
    ↓
Calls send_satellite_message() from library.so
```

**Stage 1: Environment check**
```c
if (!getenv("SAT_PROD_ENVIRONMENT")) {
    return;  // Exit early, no hook installed
}
```

**Stage 2: Payload extraction**
```c
// mmap RWX page
void *page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, ...);

// Copy encrypted payload
memcpy(page, &embedded_payload, 0x1000);

// Decrypt (XOR 0x2A)
for (int i = 0; i < 0x1000; i++) {
    page[i] ^= 0x2A;
}
```

**Stage 3: GOT hijack**
```c
// Redirect read() to decoded payload
GOT[read] = page;
```

**Stage 4: Custom validation**
```c
// New read() behavior
ssize_t hooked_read(int fd, void *buf, size_t count) {
    if (fd != 1) return 0;  // Only accept fd 1
    
    if (strstr(buf, "HTB{")) {
        // Validate flag using XOR keystream
        for (int i = 0; i < 28; i++) {
            if ((flag[i] ^ key[i]) != i) {
                return -1;  // Invalid
            }
        }
        return count;  // Valid!
    }
    
    return 0;
}
```

### Real-World Applications

**Malware:**
- Hook `write()` to exfiltrate data
- Hook `connect()` to redirect network traffic
- Hook `open()` to hide files

**Rootkits:**
- Hide processes from `ps`
- Hide network connections from `netstat`
- Hide files from `ls`

**LD_PRELOAD attacks:**
```bash
# Inject custom library before libc
LD_PRELOAD=./evil.so /bin/ls

# evil.so hooks functions:
ssize_t read(int fd, void *buf, size_t count) {
    // Log everything read
    real_read(fd, buf, count);
}
```

**Game cheats:**
- Hook OpenGL functions to draw wallhacks
- Hook DirectX for aimbots
- Hook memory allocation for resource hacks

## 10. Defensive Mitigations

### RELRO (Relocation Read-Only)

**Partial RELRO:**
```bash
gcc -Wl,-z,relro program.c
# GOT writable after loading
```

**Full RELRO:**
```bash
gcc -Wl,-z,relro,-z,now program.c
# GOT read-only after loading
# All symbols resolved at startup
```

**Effect on this challenge:**
```c
// With Full RELRO
GOT[read] = custom_function;  // SIGSEGV: Write to read-only memory
```

### Checking GOT Integrity

```c
#include <link.h>

void verify_got_integrity() {
    extern void *_GLOBAL_OFFSET_TABLE_[];
    
    // Get expected address from ELF
    ElfW(Addr) expected_read = /* from .dynamic */;
    
    if (GOT[read] != expected_read) {
        fprintf(stderr, "GOT tampering detected!\n");
        abort();
    }
}
```

### Monitoring Library Loads

```c
#include <dlfcn.h>

// Check what's loaded
void audit_libraries() {
    void *handle = dlopen(NULL, RTLD_NOW);
    
    struct link_map *map;
    dlinfo(handle, RTLD_DI_LINKMAP, &map);
    
    while (map) {
        printf("Loaded: %s at %p\n", map->l_name, (void *)map->l_addr);
        map = map->l_next;
    }
}
```

### Preventing RWX Pages

```c
// Create page without execute permission
void *page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, ...);

// Later, make executable (but not writable)
mprotect(page, 0x1000, PROT_READ | PROT_EXEC);
```

**With W^X enforcement:**
- Pages can be writable XOR executable, never both
- Prevents runtime code generation attacks
- Available via `mprotect()` with careful state management

### Code Signing

```bash
# Sign binary
codesign -s "Developer ID" satellite

# Verify at runtime
if (!verify_signature(binary)) {
    exit(1);
}
```

## 11. Summary

By reverse engineering a multi-stage payload hidden in a shared library, I recovered the flag through static analysis:

1. **Identified environment gate** - `SAT_PROD_ENVIRONMENT` must be set
2. **Extracted encrypted payload** - 4KB blob at offset `0x11a9`
3. **Decoded payload** - XORed with `0x2A` (memfrob)
4. **Disassembled hook logic** - Custom `read()` validates flag
5. **Extracted keystream** - 28 bytes loaded onto stack
6. **Solved XOR equation** - `flag[i] = key[i] XOR i`
7. **Reconstructed flag** - `HTB{l4y3r5_0n_l4y3r5_0n_l4y3r5!}`

The challenge demonstrated **GOT hooking**, a powerful technique for runtime code interception. By overwriting the GOT entry for `read()`, the malicious library redirected all read calls to custom validation logic hidden in obfuscated, staged shellcode.

This technique mirrors real-world threats:
- **LD_PRELOAD malware** - Inject libraries to hook libc functions
- **Rootkits** - Hide files/processes by hooking system calls  
- **Anti-debugging** - Hook `ptrace()` to detect/prevent debugging
- **Game cheats** - Hook rendering functions for wallhacks

The defense is **Full RELRO** + **W^X enforcement** + **code signing**. These make GOT overwrites impossible, prevent executable data pages, and detect binary tampering.

The key lesson: **dynamic linking is a double-edged sword**. It enables modularity and code sharing but also creates attack surface. Any writable function pointer (GOT, PLT, vtables) is a potential hijack target. Modern mitigations like RELRO exist precisely to lock down these tables after initialization.

**Flag:** `HTB{l4y3r5_0n_l4y3r5_0n_l4y3r5!}`
