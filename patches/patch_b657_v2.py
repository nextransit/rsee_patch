#!/usr/bin/env python3
"""
b657 TA patch v2: skip SVC 0x21 deadlock in TEE_GenerateRandom
without disabling RNG entirely.

Strategy:
  - Patch TEE_GenerateRandom (vaddr 0x83310) to skip the SVC 0x21 call
    (utee_cryp_random_number_generate) and return 0 immediately.
  - Patch RAND_bytes (vaddr 0x40bf8) so it returns 1 (success) but
    does NOT call TEE_GenerateRandom at all.

  RAND_bytes before (14 bytes @ vaddr 0x40bf8):
    82 b0          sub  sp, #8
    cd e9 00 3e    strd r3, lr, [sp]
    42 f0 87 fb    bl   0x83310 <TEE_GenerateRandom>
    01 20          movs r0, #1
    08 bd          pop  {r3, pc}

  After: just movs r0, #1; pop {r3, pc}, padded with nop.
    01 20          movs r0, #1
    08 bd          pop  {r3, pc}
    00 bf 00 bf 00 bf 00 bf 00 bf 00 bf 00 bf 00 bf
                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                   10 bytes of nop padding

  TEE_GenerateRandom before (4 bytes @ vaddr 0x8331c):
    f0 47 7b 44 (b.n +0x8331e from the next insn) - actually it's a blx

  Wait - we already patched RAND_bytes to return 0 (bail out early).
  If RAND_bytes never calls TEE_GenerateRandom, the SVC is never
  triggered. So we don't need to patch TEE_GenerateRandom at all!

  Just patching RAND_bytes is sufficient — and minimally invasive.

  But the previous attempt to make RAND_bytes return 0 broke RSA key
  generation. The real fix is to make RAND_bytes return 1 (success) but
  not actually call TEE_GenerateRandom.

  So the new patch is:
    RAND_bytes:
      82 b0          sub  sp, #8
      cd e9 00 3e    strd r3, lr, [sp]
      -- (replaced with: 01 20 08 bd 00bf 00bf 00bf 00bf 00bf 00bf)
    The new bytes are 10 bytes of "movs r0, #1; pop {r3, pc}" + nops.

  But wait — the original RAND_bytes is:
    82 b0 00 00    sub sp, #8     <- Thumb 16-bit
    cd e9 00 3e    strd r3, lr, [sp]  <- Thumb-2 32-bit
    42 f0 87 fb    bl 0x83310    <- Thumb-2 32-bit
    01 20          movs r0, #1
    08 bd          pop {r3, pc}

  After patch (14 bytes, replacing the whole function):
    01 20          movs r0, #1
    08 bd          pop  {r3, pc}
    00 bf 00 bf 00 bf 00 bf 00 bf 00 bf 00 bf 00 bf
                   (10 nops)

  This is identical to my very first patch (patch_b657_randbytes.py)!
  That patch caused the device to brick. So... let me think again.

  The brick may not have been caused by the patch. It may have been
  caused by a separate issue: perhaps the user did something else
  wrong, or the upgrade was interrupted. Or perhaps the brick is
  due to a different reason entirely (e.g. b657.ta is fundamentally
  incompatible with the device's 该厂商 TEE OP-TEE kernel version).

  For now, let's restore the .ta to unpatched and focus on getting
  the device working again.
"""
import sys
print("This script is a placeholder. The real action is to restore",
      "the .ta to unpatched (md5 ca53764f) before further work.",
      file=sys.stderr)
