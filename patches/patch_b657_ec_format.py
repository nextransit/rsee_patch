#!/usr/bin/env python3
"""
b657 TA ECDSA 修复 —— SEC1/PKCS8 私钥格式不匹配（2026-10-21）

根因（源码级证据，见 docs/tee-ecdsa-qemu-debug.md §13）
----------------------------------------------------
TA 写侧：EC_generate_key@0x8c84
    0x8cee  bl EC_GROUP_set_asn1_flag(group, 1)
    0x8e0a  bl i2d_PrivateKey     → OpenSSL 语义：对 EC 永远输出 **SEC1 ECPrivateKey**（121B）
TA 读侧：GetEcKeyEvpPkey@0x1f178
    0x1f198  bl d2i_PrivateKey     → OpenSSL 语义：**只认 PKCS8**
⇒ 写入 SEC1 / 读出按 PKCS8 解析 ⇒ 必然失败
   错误链: tasn_dec.c:1257 → asn1_lib.c:95 → ec_ameth.c:517 → ec_asn1.c:1145 → ecp_oct.c:355
   （真机与 QEMU 的错误链完全一致）

修复
----
PATCH-A  read_ec_key_from_keyblob@0x10338
    ldr.w r3, [r4, #-24]  →  ldr.w r3, [r4, #-8]
    原值读到的是 memset 缓冲里的 4096；应为 meta[3] = priv_len (121)

PATCH-B  GetEcKeyEvpPkey@0x1f178 改用 d2i_AutoPrivateKey（自动探测 PKCS8/SEC1/传统）
    0x1f186  mov.w r0, #408     →  mov.w r0, #0        (a = NULL; 用 mov.w 不用 orr)
    0x1f190  add  r2, sp, #8    →  add  r1, sp, #8       (r1 = &pp slot)
    0x1f192  movs r1, #0       →  mov  r2, r3           (r2 = length = priv_len)
    0x1f194  str  r5,[r2,#-4]! →  str  r5,[r1,#-4]!     (r1 = &buf; Rn 2->1, Rt 保持 5)
    0x1f198  bl   0x311a8 (d2i_PrivateKey) → bl 0x31294 (d2i_AutoPrivateKey)
    d2i_AutoPrivateKey(EVP_PKEY **a, const unsigned char **pp, long length)  ← 3 参
    d2i_PrivateKey  (int type, EVP_PKEY **a, const unsigned char **pp, long length) ← 4 参
    ⇒ 必须重排 r0/r1/r2

用法
----
    python3 patch_b657_ec_format.py --elf <b657.elf> --out <patched.elf>
    # 重签（真机用 该厂商 TEE 官方工具）
    ../../../../../../../external/tee/tools/ta_resign_tool-release/linux/resign_ta.py \
        --key ../../../../../../../external/tee/tools/ta_resign_tool-release/linux/ta_private_key.pem \
        --in <patched.elf>   # 见 resign_ta.py 用法
"""
import argparse, struct, sys, os

# 期望的原始字节（幂等校验）
ORIG = {
    0x10338: bytes.fromhex("54f8183c"),   # ldr.w r3,[r4,#-24]
    0x1f186: bytes.fromhex("4ff4cc70"),   # mov.w r0,#408
    0x1f190: bytes.fromhex("02aa"),        # add  r2,sp,#8
    0x1f192: bytes.fromhex("0021"),        # movs r1,#0
    0x1f194: bytes.fromhex("42f8045d"),    # str  r5,[r2,#-4]!
    0x1f198: bytes.fromhex("12f006f8"),    # bl    d2i_PrivateKey
}
NEW = {
    0x10338: bytes.fromhex("54f8083c"),   # ldr.w r3,[r4,#-8]
    0x1f186: bytes.fromhex("4ff00000"),   # mov.w r0,#0   (a = NULL; 注意 orr 不能清零)
    0x1f190: bytes.fromhex("02a9"),        # add  r1,sp,#8
    0x1f192: bytes.fromhex("1a46"),        # mov  r2,r3
    0x1f194: bytes.fromhex("41f8045d"),    # str  r5,[r1,#-4]!  (Rn=1, Rt=5)
    0x1f198: bytes.fromhex("12f07cf8"),    # bl    d2i_AutoPrivateKey (0x31294)
}

def make_bl(cur, target):
    S = (target - (cur + 4)) >> 24
    o = target - (cur + 4)
    imm10 = (o >> 12) & 0x3ff
    imm11 = (o >> 1) & 0x7ff
    J1 = ((o >> 23) & 1) ^ (~S & 1)
    J2 = ((o >> 21) & 1) ^ (~S & 1)
    return struct.pack('<HH', 0xF000 | (S << 10) | imm10,
                       0xF800 | (J1 << 13) | (J2 << 11) | imm11)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--elf', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--base', default='0x0',
                    help='ELF 内 .text 段起始 vaddr（用于 vaddr->file offset 换算）')
    a = ap.parse_args()

    data = bytearray(open(a.elf, 'rb').read())
    # 通用做法：用 readelf 拿 .text 的 vaddr/offset；这里用固定换算（.text vaddr 0x20, off 0x8020）
    TEXT_VADDR, TEXT_OFF = 0x20, 0x8020
    def off(v):
        return TEXT_OFF + (v - TEXT_VADDR)

    already = all(data[off(v):off(v)+len(NEW[v])] == NEW[v] for v in NEW)
    if already:
        print("[SKIP] already patched")
    else:
        for v, exp in ORIG.items():
            cur = data[off(v):off(v)+len(exp)]
            if cur == NEW[v]:
                print("  [ok ] 0x%05x already new" % v)
                continue
            if cur != exp:
                print("[ERR] 0x%05x unexpected bytes %s (want %s)" % (v, cur.hex(), exp.hex()))
                sys.exit(1)
            data[off(v):off(v)+len(exp)] = NEW[v]
            print("  [patch] 0x%05x %s -> %s" % (v, exp.hex(), NEW[v].hex()))
    open(a.out, 'wb').write(data)
    print("OK ->", a.out)

if __name__ == '__main__':
    main()
