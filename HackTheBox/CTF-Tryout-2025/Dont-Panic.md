---
layout: default
title: Don't Panic - Rev
page_type: writeup
---
# HTB: Don't Panic – Rust Closure Table Extraction

**Category:** Reverse Engineering

## 0. Challenge Overview

The challenge provided a Rust ELF binary (`dontpanic`) that always responded with "😱 You made me panic!" regardless of input. The goal: extract the hidden flag by analyzing the validation logic embedded in the binary.

**The setup:**
- Rust executable with DWARF debug info intact
- Flag validation through 31 character-checking closures
- Each closure validates one character position
- Correct input triggers success message, wrong input causes panic

**Core concept:** Rust closures compiled as individual functions contain the validation logic. By extracting the comparison values from each closure's assembly, we can reconstruct the entire flag without ever executing the program correctly.

## 1. Initial Reconnaissance

I started by examining the binary:
```bash
file dontpanic
```

Output:
```
dontpanic: ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
```

Ran the binary to observe behavior:
```bash
./dontpanic
```

Output:
```
🤖💬 < Have you got a message for me? > 🗨️
test
🤖: 😱 You made me panic!
```

Tried various inputs - all resulted in panic.

**Key observation:** The binary always panics. The validation must be checking every character, and failure on any character causes immediate panic.

## 2. Analyzing Available Symbols

Listed symbols to find interesting functions:
```bash
nm -C dontpanic | grep src::
```

Output:
```
000000000000a1d0 T src::check_flag
000000000000b450 T src::main
```

Two key functions:
- `src::main` - Entry point, handles I/O
- `src::check_flag` - Validates the flag

**Key observation:** Symbol `check_flag` suggests this is where validation happens. The `-C` flag demangles Rust symbols, making them human-readable.

## 3. Disassembling check_flag

I disassembled the validation function:
```bash
objdump -M intel -d dontpanic | grep -A 100 "<src::check_flag>"
```

Examining the assembly revealed the validation logic:

**The closure table:**
```assembly
src::check_flag:
    a1d0:   push   rbp
    a1d1:   mov    rbp,rsp
    a1d4:   sub    rsp,0xf8
    
    # Allocate space for 0x1f (31) function pointers
    # Each pointer is 8 bytes
    a1db:   lea    rax,[rbp-0xf8]
    
    # Push closure addresses onto stack
    a1e2:   mov    QWORD PTR [rbp-0xf8],0x8b80  # Closure 0
    a1ed:   mov    QWORD PTR [rbp-0xf0],0x8d80  # Closure 1
    a1f8:   mov    QWORD PTR [rbp-0xe8],0x8d40  # Closure 2
    ...
    # 31 total closures
```

**The validation loop:**
```assembly
    # Check length == 0x1f (31 bytes)
    cmp    rsi,0x1f
    jne    panic
    
    # Loop through each character
    mov    rcx,0x0
loop_start:
    # Get function pointer from table
    mov    rax,QWORD PTR [rbp+rcx*8-0xf8]
    
    # Get character from input
    movzx  edi,BYTE PTR [rdi+rcx*1]
    
    # Call closure: table[i](flag[i])
    call   rax
    
    # Check result
    test   al,al
    je     panic
    
    # Next character
    inc    rcx
    cmp    rcx,0x1f
    jne    loop_start
```

**Key observation:** The validation creates a table of 31 function pointers, then calls `table[i](flag[i])` for each character. Each closure validates one specific character position.

## 4. Examining a Single Closure

I inspected one of the closures to understand the validation pattern:
```bash
objdump -M intel -d dontpanic --start-address=0x8b80 --stop-address=0x8bc0
```

Output:
```assembly
0000000000008b80:
    8b80:   cmp    dil,0x48        # Compare with ASCII 'H'
    8b84:   jb     8b8e            # Jump if below (fail)
    8b86:   jne    8b8e            # Jump if not equal (fail)
    8b88:   mov    al,0x1          # Return true
    8b8a:   ret
    8b8e:   xor    eax,eax         # Return false
    8b90:   ret
```

**The pattern:**
```c
bool validate_char(char c) {
    if (c < 0x48) return false;   // Too low
    if (c != 0x48) return false;  // Not exact match
    return true;                  // Must be 0x48 ('H')
}
```

**Key observation:** Each closure has the same structure - compare `dil` (first function argument, the character) against a hardcoded immediate value. The only thing that changes between closures is the comparison byte.

## 5. Extracting All Closure Addresses

From the disassembly of `check_flag`, I extracted all 31 closure addresses:
```python
TABLE_ADDRS = [
    0x8B80, 0x8D80, 0x8D40, 0x8E00, 0x8E40, 0x8C00, 0x8C80, 0x8AC0,
    0x8B00, 0x8A80, 0x8D00, 0x8C80, 0x8CC0, 0x8B40, 0x8B00, 0x8B40,
    0x8D00, 0x8AC0, 0x8B40, 0x8A40, 0x8B00, 0x8AC0, 0x8A40, 0x8DC0,
    0x8B00, 0x8E80, 0x8C40, 0x8C40, 0x8BC0, 0x8C40, 0x8EC0,
]
```

## 6. Automated Flag Extraction Script

I wrote a Python script to automate the extraction:

```python
#!/usr/bin/env python3
"""
Don't Panic Flag Extractor
Scrapes the closure validation table to recover the flag
"""
import subprocess

BIN = "dontpanic"

# Closure addresses from check_flag
TABLE_ADDRS = [
    0x8B80, 0x8D80, 0x8D40, 0x8E00, 0x8E40, 0x8C00, 0x8C80, 0x8AC0,
    0x8B00, 0x8A80, 0x8D00, 0x8C80, 0x8CC0, 0x8B40, 0x8B00, 0x8B40,
    0x8D00, 0x8AC0, 0x8B40, 0x8A40, 0x8B00, 0x8AC0, 0x8A40, 0x8DC0,
    0x8B00, 0x8E80, 0x8C40, 0x8C40, 0x8BC0, 0x8C40, 0x8EC0,
]

flag_chars = []

for addr in TABLE_ADDRS:
    # Disassemble this closure
    cmd = [
        "objdump", "-M", "intel", "-d", BIN,
        f"--start-address={addr}",
        f"--stop-address={addr+0x40}",
    ]
    
    output = subprocess.check_output(cmd, text=True)
    
    # Find the "cmp dil, <value>" instruction
    for line in output.splitlines():
        if "cmp" in line and "dil" in line:
            # Extract the immediate value
            parts = line.split(",")
            hex_value = parts[-1].strip()
            
            # Convert to character
            char_code = int(hex_value, 0)
            flag_chars.append(chr(char_code))
            break

# Reconstruct flag
flag = "".join(flag_chars)
print(f"[+] Recovered flag: {flag}")
```

Running the script:
```bash
python3 extract_flag.py
```

Output:
```
[+] Recovered flag: HTB{d0nt_p4n1c_c4tch_the_3rror}
```

✔ **Success:** Flag extracted through static analysis.

## 7. Verification

I verified the flag by feeding it to the binary:
```bash
echo 'HTB{d0nt_p4n1c_c4tch_the_3rror}' | ./dontpanic
```

Output:
```
🤖💬 < Have you got a message for me? > 🗨️
🤖: 😌😌😌 All is well 😌😌😌
```

✔ **Success:** Flag validated. Challenge complete.

**Key observation:** The binary accepts the extracted flag and displays the success message instead of panicking.

## 8. Why This Works – Understanding Rust Closures

### Rust Closure Compilation
In Rust, closures are anonymous functions that can capture variables from their environment:

```rust
fn check_flag(input: &str) -> bool {
    let validators: Vec<Box<dyn Fn(char) -> bool>> = vec![
        Box::new(|c| c == 'H'),
        Box::new(|c| c == 'T'),
        Box::new(|c| c == 'B'),
        // ... 28 more closures
    ];
    
    if input.len() != validators.len() {
        return false;
    }
    
    for (i, ch) in input.chars().enumerate() {
        if !validators[i](ch) {
            return false;
        }
    }
    
    true
}
```

When compiled, each closure becomes a separate function with a unique address. The validator table is just an array of function pointers.

### Assembly Structure
Each compiled closure follows the same pattern:

```assembly
closure_N:
    cmp    dil, <expected_char>   # Compare argument with constant
    jb     fail                    # Jump if below
    jne    fail                    # Jump if not equal
    mov    al, 0x1                # Return true
    ret
fail:
    xor    eax, eax               # Return false
    ret
```

**Why this pattern?**
The Rust compiler:
1. Knows each closure validates exactly one character
2. Knows the expected character is constant
3. Optimizes the comparison to a simple `cmp` instruction
4. Inlines the comparison value directly into the code

### Why Static Analysis Works
The validation logic is **completely deterministic**:
- No runtime randomness
- No network calls
- No dynamic key derivation
- All comparison values hardcoded in the binary

This makes extraction trivial - just read the binary's `.text` section.

### Real-World Parallels

**Hardcoded License Keys:**
Many commercial software products use similar validation:
```c
bool check_license(char *key) {
    return strcmp(key, "ABCD-EFGH-1234-5678") == 0;
}
```
The license key sits in the binary as plaintext, extractable with `strings`.

**Anti-Debugging Checks:**
Some malware uses closure tables for obfuscation:
```rust
let anti_debug_checks = vec![
    Box::new(|| check_debugger_present()),
    Box::new(|| check_ptrace()),
    Box::new(|| check_timing()),
];
```
Each check is a separate function, making the malware harder to patch (must patch all closures).

**Game Anti-Cheat:**
Client-side anti-cheat often uses similar patterns:
- Array of validation functions
- Each checks one aspect of game state
- All must pass or game exits

But these are all **client-side checks** that can be reversed.

## 9. Defensive Mitigations

### Why Client-Side Validation Fails

The fundamental problem: **the client (binary) contains the answer**.

```
Server: "What's the password?"
Client: *checks hardcoded value in own code*
Attacker: *reads client code*
```

This is security through obscurity - it only works if the attacker doesn't look.

### Proper Secret Validation

**Wrong (Client-Side):**
```rust
fn validate_password(input: &str) -> bool {
    input == "secret123"  // Password in binary!
}
```

**Right (Server-Side):**
```rust
fn validate_password(input: &str) -> Result<bool> {
    // Send to server for validation
    let response = http::post("https://api.server.com/validate")
        .json(&json!({ "password": input }))
        .send()?;
    
    Ok(response.status().is_success())
}
```

The server holds the secret, client just forwards input.

### Challenge-Response Authentication

Instead of storing secrets client-side:

```rust
// Client
fn authenticate() -> Result<()> {
    // 1. Get challenge from server
    let challenge: [u8; 32] = server.get_challenge()?;
    
    // 2. User provides password
    let password = prompt_user("Password: ");
    
    // 3. Compute response = HMAC(password, challenge)
    let response = hmac_sha256(&password, &challenge);
    
    // 4. Send response to server
    server.verify(response)?;
    
    Ok(())
}

// Server
fn verify_response(response: &[u8]) -> bool {
    let expected = hmac_sha256(&stored_password, &session.challenge);
    constant_time_compare(response, expected)
}
```

**Benefits:**
- Password never transmitted (only HMAC)
- Server holds the actual secret
- Challenge prevents replay attacks
- Client binary contains no secrets

### Code Obfuscation (Defense in Depth)

While not a substitute for proper crypto, obfuscation raises the difficulty bar:

**Symbol Stripping:**
```bash
# Remove function names
strip --strip-all dontpanic

# Now functions have no names
nm dontpanic
# 000000000000a1d0 T <anonymous_function_1>
```

**Packing:**
```bash
# Compress and encrypt the binary
upx --brute --ultra-brute dontpanic

# Binary must decompress itself at runtime
```

**Control Flow Flattening:**
Use LLVM obfuscation passes:
```bash
clang -mllvm -fla -mllvm -sub -mllvm -bcf program.c
```

Transforms:
```c
// Before
if (x) { a(); } else { b(); }

// After (flattened)
state = 0;
while (true) {
    switch (state) {
        case 0: state = x ? 1 : 2; break;
        case 1: a(); return;
        case 2: b(); return;
    }
}
```

**Note:** Obfuscation only slows attackers. Determined adversaries will still extract secrets. Use proper cryptography.

### Anti-Debugging Techniques

Detect if binary is being analyzed:
```rust
fn check_debugger() -> bool {
    #[cfg(target_os = "linux")]
    {
        // Check for ptrace
        use std::fs;
        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            return status.contains("TracerPid:\t0");
        }
    }
    true
}

if check_debugger() {
    panic!("Debugger detected!");
}
```

**But remember:** This is also client-side, so can be patched out.

## 10. Summary

By analyzing the compiled Rust closures, I extracted the flag without ever executing the validation logic successfully:

1. **Identified validation function** (`check_flag`) through symbol table
2. **Disassembled closure table** to find 31 function addresses
3. **Analyzed closure structure** - each compares input character to hardcoded value
4. **Automated extraction** - scraped all comparison values from assembly
5. **Reconstructed flag** from the 31 extracted characters
6. **Verified** by feeding flag to binary (success message displayed)

The vulnerability is simple: **secrets hardcoded in client-side code are not secrets**. Whether it's a Rust closure, C comparison, or JavaScript variable, if it's in the binary, it's extractable.

This mirrors real-world issues:
- **Mobile app API keys** - extractable via decompilation
- **Game license checks** - patchable via binary modification
- **DRM systems** - breakable through static analysis
- **Hardware dongles** - emulatable once algorithm is reverse-engineered

The solution: **never trust the client**. Validate secrets server-side, use challenge-response protocols, and treat client binaries as public information because once distributed, they are.

The key lesson: **compilation is not encryption**. Source code becomes assembly becomes machine code, but the logic remains. With debug symbols (like DWARF), it's trivial to reverse. Even without symbols, the validation pattern is recognizable. Any secret in client code is a leaked secret.

**Flag:** `HTB{d0nt_p4n1c_c4tch_the_3rror}`
