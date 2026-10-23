#!/usr/bin/env python3
"""
Targeted patch for b657 TA: only block ECDSA sign path, preserve RNG.

The previous attempt (patch_b657_randbytes.py) replaced RAND_bytes with
`movs r0, #0; bx lr` which broke RSA key generation, AES, HMAC and
attestation key creation. System services (class early_hal) called
these at boot and hung waiting for keymaster, bricking the device.

This patch instead modifies ECDSA_sign_ex at vaddr 0x4b52a (4 bytes)
to skip the call to ECDSA_do_sign_ex. ECDSA sign returns error
immediately but RNG-dependent operations (RSA, AES, HMAC, attestation)
work normally.

The replacement is a Thumb-2 branch (b.w) to 0x4b554 (fail path),
4 bytes total, no side effects on RNG.

Bytes at .ta file offset 0x5365e (vaddr 0x4b52a):
  Before: ff f7 b7 ff  (bl 0x4b49c <ECDSA_do_sign_ex>)
  After:  00 f0 10 b8  (b.w 0x4b554 <ECDSA_sign_ex+0x58>)

b.w encoding (Thumb-2 32-bit):
  bits 31-27: 11110
  bit 26: S (sign)
  bits 25-16: imm10
  bit 15: 0
  bits 14-12: 010 (B)
  bit 11: J1
  bit 10: 1
  bit 9: J2
  bits 8-0: imm11

For b.w to 0x4b554 from 0x4b52a:
  offset = 0x4b554 - (0x4b52a + 4) = 0x2a
  imm11 = lower 11 bits of (offset/2) = 0x15
  imm10 = bits [16:25] of (offset/2) = 0
  J2 = !S = 0
  J1 = !S = 0
  S = 0 (positive)
  Encoding: 11110 0 0000000000 0 010 0 1 0 00010001010
           E 0 0 0 2 0 A 1 5
  = 0xe000d215
  bytes (LE): 15 d2 00 e0
"""
import sys, os, hashlib

from paths import TA_DEBUG, TA_RELEASE, require_workspace  # noqa: E402

require_workspace()

# ECDSA_sign_ex vaddr 0x4b52a
# .ta file_off = 0x134 (TA header) + 0x8020 (text file_off) + (0x4b52a - 0x20)
TA_FILE_OFFSET = 0x5365e

ORIGINAL_BYTES = bytes.fromhex("fff7b7ff")  # bl 0x4b49c <ECDSA_do_sign_ex>
NEW_BYTES      = bytes.fromhex("15d200e0")  # b.w 0x4b554 <ECDSA_sign_ex+0x58>

assert len(ORIGINAL_BYTES) == 4 == len(NEW_BYTES)

def patch_file(path):
    if not os.path.exists(path):
        print(f"[SKIP] {path}: not found")
        return False
    with open(path, "rb") as f:
        data = f.read()
    cur = data[TA_FILE_OFFSET:TA_FILE_OFFSET+4]
    if cur == NEW_BYTES:
        print(f"[SKIP] {path}: already patched (sha256={hashlib.sha256(data).hexdigest()[:16]})")
        return False
    if cur != ORIGINAL_BYTES:
        print(f"[ERROR] {path}: unexpected bytes at offset 0x{TA_FILE_OFFSET:x}:")
        print(f"  expected (orig): {ORIGINAL_BYTES.hex()}")
        print(f"  found:           {cur.hex()}")
        return False
    patched = data[:TA_FILE_OFFSET] + NEW_BYTES + data[TA_FILE_OFFSET+4:]
    with open(path, "wb") as f:
        f.write(patched)
    print(f"[OK]   {path}")
    print(f"       patched 4 bytes @ 0x{TA_FILE_OFFSET:x}")
    print(f"       sha256={hashlib.sha256(patched).hexdigest()[:16]}")
    return True

print("=" * 75)
print("Patch b657 TA: block ECDSA sign path (preserve RNG for RSA/AES/HMAC)")
print("=" * 75)
print(f"Target offset (.ta file): 0x{TA_FILE_OFFSET:x} (vaddr 0x4b52a)")
print(f"Original: {ORIGINAL_BYTES.hex()}  (bl 0x4b49c ECDSA_do_sign_ex)")
print(f"Patched:  {NEW_BYTES.hex()}  (b.w 0x4b554 fail path)")
print()
p1 = patch_file(TA_DEBUG)
p2 = patch_file(TA_RELEASE)
print()
if p1 or p2:
    print("✓ .ta file(s) patched. Rebuild OTA via ./auto-build.sh")
else:
    print("✓ Both .ta files already patched (or not present).")
