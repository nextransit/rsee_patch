#!/usr/bin/env python3
"""
b657 TA ECDSA sign 失败修复 (2026-10-19, 真机铁证闭环)

FIX1 (vaddr 0x1033e, TA off 0x18472):
  read_ec_key_from_keyblob 解密后把"密文"当明文返回 (mov r1,r9)
  -> 改 mov r1,r4 (明文栈缓冲), 修复 keyblob 读取
  bytes: 49 46 -> 21 46

FIX4 (vaddr 0x8e98, TA off 0x10fcc):
  EC_generate_key 第二次 i2d_PUBKEY 复用同一 local_2c 指针(私钥区起点)。
  原因: TA 内嵌 crypto 的 asn1_item_flags_i2d 在 *pp!=NULL 时"不推进指针",
  (见 2c732 处仅 *pp==NULL 的 malloc 分支才回写), 故 i2d_PrivateKey 后
  local_2c[0] 仍==私钥区 r8+0x408, i2d_PUBKEY 再写把 SPKI(91B) 覆盖到
  私钥 DER(121B) 前 91B -> d2i_PrivateKey 失败(OCT2POINT / POINT_IS_NOT_ON_CURVE)。
  修复: r1 = &sp+0x2c (8e9a 已把 r2=r8+4 公钥区地址写入 sp+0x2c),
  使 SPKI 写入公钥区 r8+4, 私钥区 r8+0x408 保留完整 ECPrivateKey。
  本地验证(arm-none-eabi + qemu-arm, 模拟不推进): 私钥区=30 77..(ECPrivateKey OK)
  公钥区=30 59..(SPKI OK); 真机 keyblob 明文区也证实 SPKI(91)+私钥残留(30)。
  bytes: 07 99 -> 0b a9  (ldr r1,[sp,#28] -> add r1,sp,#44)

真机证据: keyblob 明文区开头 30 59 30 13 06 07 2a8648ce3d... = SPKI(公钥) 而非 ECPrivateKey
          (应为 30 77 02 01 01 04 20 ...)。 RSA 侧 EvpKeyToKeyMaterial 只 i2d_PrivateKey 无覆盖。

必须重签名 (ta_private_key.pem = debug 固件内嵌 key1), 否则 OpenSession 0xffff000f。
"""
import os, sys, struct, hashlib
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

BASE = os.path.dirname(os.path.abspath(__file__))
PARENT = os.path.dirname(BASE)
TA_DEBUG   = os.path.join(BASE, "b657ba17-b3b3-47f5-b389-6b53f30c0baf.ta")
TA_RELEASE = os.path.join(PARENT, "b657ba17-b3b3-47f5-b389-6b53f30c0baf.ta")
from paths import TA_PRIVATE_KEY as KEY, require_workspace  # noqa: E402

require_workspace()

# FIX1
TA_OFF = 0x18472
ORIG  = bytes.fromhex("4946")
NEW   = bytes.fromhex("2146")
# FIX4
TA_OFF3 = 0x10fcc
ORIG3  = bytes.fromhex("0799")
NEW3   = bytes.fromhex("0ba9")

def resign(data: bytes, key) -> bytes:
    assert data[:4] == b"HSTO", "not HSTO TA"
    body = data[0x134:]
    shdr = struct.pack("<IIIIHH", 0x4f545348, 0, len(body), 0x70004830, 32, 256)
    h = SHA256.new(); h.update(shdr); h.update(body)
    sig = PKCS1_v1_5.new(key).sign(h)
    out = shdr + h.digest() + sig + body
    h2 = SHA256.new(); h2.update(out[:20]); h2.update(out[20+32+256:])
    assert PKCS1_v1_5.new(key).verify(h2, out[20+32:20+32+256]), "self-sign verify failed"
    return out

def patch_file(path, key):
    if not os.path.exists(path): return
    data = bytearray(open(path, "rb").read())
    # idempotent: 已含 FIX1+FIX4 即跳过
    if data[TA_OFF:TA_OFF+2] == NEW and data[TA_OFF3:TA_OFF3+2] == NEW3:
        print(f"[OK]   {path}: already fixed")
        return
    assert data[TA_OFF:TA_OFF+2] == ORIG, f"FIX1 precheck fail {path}"
    assert data[TA_OFF3:TA_OFF3+2] == ORIG3, f"FIX4 precheck fail {path}"
    data[TA_OFF:TA_OFF+2] = NEW
    data[TA_OFF3:TA_OFF3+2] = NEW3
    out = resign(bytes(data), key)
    open(path, "wb").write(out)
    print(f"[FIX]  {path}\n       sha256={hashlib.sha256(out).hexdigest()}")

def main():
    key = RSA.importKey(open(KEY, "rb").read())
    for p in (TA_DEBUG, TA_RELEASE):
        patch_file(p, key)
    print("\nOK: b657 TA patched (FIX1+FIX4) + re-signed")

if __name__ == "__main__":
    main()
