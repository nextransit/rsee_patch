#!/usr/bin/env python3
"""
v3 patch for b657 TA: only block ECDSA sign path, preserve RNG.

This v3 fixes the b.w Thumb-2 encoding bug in v2.

Background:
  v2 attempted to encode "b.w 0x4b554" (4-byte Thumb-2 unconditional branch
  from vaddr 0x4b52a to 0x4b554) but used wrong bytes (15 d2 00 e0). The
  resulting 32-bit encoding was actually a Coprocessor Move instruction
  (MRC2), causing TA execution to fault at ECDSA sign, and ultimately
  bricking the keymaster4 service (TEEC_OpenSession returns 0xffff000f
  every 5 seconds, system_server kills & restarts keymaster4 forever).

v3 uses the **correct** b.w encoding (bytes 00 f0 13 b8, little-endian),
  cross-validated by:
    1. keystone assembler (KS_ARCH_ARM, KS_MODE_THUMB) generates 0x00 0xf0 0x13 0xb8
    2. capstone disassembler (CS_ARCH_ARM, CS_MODE_THUMB) reads back "b.w #0x4b554"
  Both agree, so the encoding is correct.

Bytes at .ta file offset 0x5365e (vaddr 0x4b52a):
  Before: ff f7 b7 ff  (BLX 0x4b49c <ECDSA_do_sign_ex>)
  After:  00 f0 13 b8  (b.w 0x4b554 fail path, CORRECTED)

Why b.w to 0x4b554:
  0x4b554 is the "fail path" inside ECDSA_sign_ex:
    4b554: ldr r3, [sp, #40]   @ 0x28
    4b556: str r0, [r3, #0]
    4b558: b.n 4b544
  It loads the sig pointer, returns 0 (r0 was returned as 0 from
  ECDSA_do_sign_ex when earlier params failed), and skips ECDSA entirely.
  So ECDSA sign returns error immediately, no RNG/SVC 0x21 deadlock.

Why NOT use a stronger b.n to a "movs r0, #-1; bx lr" stub:
  - Need to find a 2-byte aligned location in the .text with 4 free bytes
  - More risk: writing random bytes might overlap other code
  - b.w to existing fail path is minimal-change, reuses valid code
"""
import sys, os, hashlib

TA_DEBUG   = "/media/ben/work_2021/mtk/<workspace>/vendor/<vendor>/proprietary/trustzone/<tee>/source/binary/sec_modules/ta_debug/b657ba17-b3b3-47f5-b389-6b53f30c0baf.ta"
TA_RELEASE = "/media/ben/work_2021/mtk/<workspace>/vendor/<vendor>/proprietary/trustzone/<tee>/source/binary/sec_modules/b657ba17-b3b3-47f5-b389-6b53f30c0baf.ta"

# ECDSA_sign_ex vaddr 0x4b52a
# .ta file_off = 0x134 (TA header) + 0x8020 (text file_off) + (0x4b52a - 0x20)
TA_FILE_OFFSET = 0x5365e

ORIGINAL_BYTES = bytes.fromhex("fff7b7ff")  # BLX 0x4b49c <ECDSA_do_sign_ex>
NEW_BYTES      = bytes.fromhex("00f013b8")  # b.w 0x4b554 fail path (keystone/capstone cross-validated)

assert len(ORIGINAL_BYTES) == 4 == len(NEW_BYTES)

def patch_file(path):
    if not os.path.exists(path):
        print(f"[SKIP] {path}: not found")
        return False
    with open(path, "rb") as f:
        data = f.read()
    cur = data[TA_FILE_OFFSET:TA_FILE_OFFSET+4]
    if cur == NEW_BYTES:
        print(f"[SKIP] {path}: already v3 patched (sha256={hashlib.sha256(data).hexdigest()[:16]})")
        return False
    # 兼容 v2 patch (15d200e0) 和未 patch (fff7b7ff)
    if cur == ORIGINAL_BYTES:
        print(f"[OK]   {path}: original bytes, patching to v3")
    else:
        print(f"[WARN] {path}: unexpected bytes 0x{cur.hex()}, forcing patch")
    patched = data[:TA_FILE_OFFSET] + NEW_BYTES + data[TA_FILE_OFFSET+4:]
    with open(path, "wb") as f:
        f.write(patched)
    print(f"       patched 4 bytes @ 0x{TA_FILE_OFFSET:x} -> {NEW_BYTES.hex()}")
    print(f"       sha256={hashlib.sha256(patched).hexdigest()[:16]}")
    return True

print("=" * 75)
print("Patch b657 TA v3: b.w 0x4b554 (CORRECTED encoding from keystone)")
print("=" * 75)
print(f"Target offset (.ta file): 0x{TA_FILE_OFFSET:x} (vaddr 0x4b52a)")
print(f"Original: {ORIGINAL_BYTES.hex()}  (BLX 0x4b49c ECDSA_do_sign_ex)")
print(f"Patched:  {NEW_BYTES.hex()}  (b.w 0x4b554 fail path)")
print()
p1 = patch_file(TA_DEBUG)
p2 = patch_file(TA_RELEASE)
print()
if p1 or p2:
    print("✓ v3 .ta file(s) patched. Rebuild OTA via ./auto-build.sh")
else:
    print("✓ Both .ta files already v3 patched.")
