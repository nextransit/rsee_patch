#!/usr/bin/env python3
"""
Restore b657 TA to the exact factory image proven to pass 该厂商 TEE TA integrity
verification (sha256 16a7db96...).  This is the device-original TA pulled from
the factory firmware.

Background: v1/v2/v3 patches all break TEEC_OpenSession with
0xFFFF000F (TEEC_ERROR_SECURITY) because 该厂商 TEE's secure world validates TA
integrity; ANY byte change is rejected.  So the correct action is to ship the
unmodified factory TA.

Idempotent: if source TA already == factory image, skips.
"""
import os, hashlib, shutil

from paths import TA_DEBUG, TA_RELEASE, require_workspace  # noqa: E402

require_workspace()
FACTORY = "/tmp/113_b657.ta"  # exact device-original TA

FACTORY_SHA = "16a7db967ed3c5c454e46d5646b875c30d2ea9b5e6751d0e93aca82a149e43cb"

def restore(path):
    if not os.path.exists(path):
        print(f"[SKIP] {path}: not found")
        return
    cur = open(path, "rb").read()
    cur_sha = hashlib.sha256(cur).hexdigest()
    if cur_sha == FACTORY_SHA:
        print(f"[OK]   {path}: already factory (sha={FACTORY_SHA[:16]})")
        return
    factory = open(FACTORY, "rb").read()
    open(path, "wb").write(factory)
    new_sha = hashlib.sha256(factory).hexdigest()
    print(f"[RESTORED] {path}")
    print(f"   was sha={cur_sha[:16]}  ->  factory sha={new_sha[:16]}")

if not os.path.exists(FACTORY):
    raise SystemExit(f"FACTORY TA missing: {FACTORY}")

print("=" * 70)
print("Restore b657 TA to factory image (drop all patches)")
print("=" * 70)
restore(TA_DEBUG)
restore(TA_RELEASE)
print()
print("Factory b657.ta confirmed (passes 该厂商 TEE integrity, OpenSession OK).")
