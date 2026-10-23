#!/usr/bin/env python3
"""
Patch b657 TA's RAND_bytes to return 0 immediately, preventing the
deadlock when TEE_GenerateRandom's SVC handler hangs in 该厂商 TEE fork.

Before (Thumb-2, 14 bytes @ .ta file offset 0x48d2c):
  82 b0       sub  sp, #8
  cd e9 00 3e strd r3, lr, [sp]
  42 f0 87 fb bl   0x83310 <TEE_GenerateRandom>
  01 20       movs r0, #1            <-- always returns 1 (ignores TEE call)
  08 bd       pop  {r3, pc}

After (Thumb-2, 14 bytes):
  00 20       movs r0, #0            <-- always return 0 (= failure)
  70 47       bx   lr
  + 10 bytes nop padding (5x 00 bf)

Effect: bn_rand_range's 100 retries all fail -> ECDSA_sign_setup returns
error -> TA reports back to user space -> no more deadlock, just ECDSA
returns -1 which user space can handle (or even crash gracefully).
"""
import sys, struct, os, hashlib, shutil

TA_DEBUG   = "/media/ben/work_2021/mtk/<workspace>/vendor/<vendor>/proprietary/trustzone/<tee>/source/binary/sec_modules/ta_debug/b657ba17-b3b3-47f5-b389-6b53f30c0baf.ta"
TA_RELEASE = "/media/ben/work_2021/mtk/<workspace>/vendor/<vendor>/proprietary/trustzone/<tee>/source/binary/sec_modules/b657ba17-b3b3-47f5-b389-6b53f30c0baf.ta"

# b657 .ta format: 308 (0x134) byte TEE TA header, then ELF
# ELF program header: LOAD #0 file_off 0x8000, vaddr 0x0
# RAND_bytes vaddr 0x40bf8 -> file_off 0x40bf8 + 0x8000 = 0x48bf8
# In .ta: 0x134 + 0x48bf8 = 0x48d2c
RAND_BYTES_OFFSET_IN_TA = 0x48d2c

ORIGINAL_BYTES = bytes.fromhex("82b0cde9003e42f087fb012008bd")  # 14 bytes
NEW_BYTES      = bytes.fromhex("00207047" + "00bf" * 5)          # 14 bytes

assert len(ORIGINAL_BYTES) == len(NEW_BYTES) == 14

def patch_file(path):
    if not os.path.exists(path):
        print(f"[SKIP] {path}: not found")
        return False
    with open(path, "rb") as f:
        data = f.read()
    cur = data[RAND_BYTES_OFFSET_IN_TA:RAND_BYTES_OFFSET_IN_TA+14]
    if cur == NEW_BYTES:
        print(f"[SKIP] {path}: already patched (sha256={hashlib.sha256(data).hexdigest()[:16]})")
        return False
    if cur != ORIGINAL_BYTES:
        print(f"[ERROR] {path}: unexpected bytes at offset 0x{RAND_BYTES_OFFSET_IN_TA:x}:")
        print(f"  expected (orig): {ORIGINAL_BYTES.hex()}")
        print(f"  found:           {cur.hex()}")
        return False
    patched = data[:RAND_BYTES_OFFSET_IN_TA] + NEW_BYTES + data[RAND_BYTES_OFFSET_IN_TA+14:]
    with open(path, "wb") as f:
        f.write(patched)
    print(f"[OK]   {path}")
    print(f"       patched 14 bytes @ 0x{RAND_BYTES_OFFSET_IN_TA:x}")
    print(f"       sha256={hashlib.sha256(patched).hexdigest()[:16]}")
    return True

print("=" * 75)
print("Patch b657 keymaster4 TA: make RAND_bytes return 0 (avoid deadlock)")
print("=" * 75)
print(f"Target offset in .ta file: 0x{RAND_BYTES_OFFSET_IN_TA:x}")
print(f"Original: {ORIGINAL_BYTES.hex()}")
print(f"Patched:  {NEW_BYTES.hex()}")
print()
p1 = patch_file(TA_DEBUG)
p2 = patch_file(TA_RELEASE)
print()
if p1 or p2:
    print("✓ .ta file(s) patched. Rebuild OTA / flash to test.")
else:
    print("✓ Both .ta files already patched.")
