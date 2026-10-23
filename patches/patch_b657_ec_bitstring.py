#!/usr/bin/env python3
"""
b657 TA ECDSA 修复 —— ASN.1 BIT STRING unused-bits 字节未跳过（2026-10-21）

根因（源码级 + 运行时证据）
--------------------------
TA 内 d2i_ECPrivateKey (0x6f368) 在把 SEC1 ECPrivateKey 的公钥交给
EC_POINT_oct2point 时，把 ASN.1 BIT STRING 的 data/length 原样传下去：

    6f41a: ldr  r2, [r3, #8]   ; r2 = pub_key->data  → 指向 unused-bits 计数字节(0x00)
    6f41c: ldr  r3, [r3, #0]   ; r3 = pub_key->length = 66
    6f41e: ldrb r6, [r2, #0]   ; r6 = buf[0] = 0x00（不是点格式 0x04！）
    6f420: bic.w r6, r6, #1
    6f428: bl   EC_POINT_oct2point

而 ec_GFp_simple_oct2point (0x7bef6) 把 buf[0] 当作点格式字节：

    7bef6: ldrb r2, [r2, #0]
    7bef8: tst  r2, #0xf8      ; 0x00 通过 → 走“非压缩”分支
    ...
    ; 随后把 buf[1..] 当成 X/Y  → 每个坐标错位 1 字节

⇒ 解出的点不在 P-256 曲线上 ⇒ EC_POINT_is_on_curve 失败
⇒ ecp_oct.c:355 → ec_asn1.c:1145 → ec_ameth.c:517(old_ec_priv_decode)
⇒ TA 报 "Ecdsa_CreateOperation GetEcKeyEvpPkey error" (-1000)

即：私钥/公钥数据完全正确（已用 d*G 校验通过），纯粹是**读侧少跳了
ASN.1 BIT STRING 的 unused-bits 字节**。

修复
----
在 d2i_ECPrivateKey 内跳过该字节：

    6f41e  ldrb r6,[r2,#0]      →  adds  r2, r2, #1
    6f420  bic.w r6,r6,#1        →  subs  r3, r3, #1
                                →  ldrb  r6, [r2, #0]
    6f424  str  r6,[r4,#20]      →  bic.w r6, r6, #1
    6f426  str  r5,[sp,#0]       →  str  r6, [r4, #20]   (原 6f424 位置后移)

注：0x6f426 是 `str r5,[sp,#0]`（第5参数 ctx=NULL），必须保留；
    因此把 str r6,[r4,#20] 放在 0x6f428 之前不可行 —— 实际布局：
    0x6f41e(2) 0x6f420(4) 0x6f424(2) = 8 字节 → 4 条新指令正好 8 字节。

实际字节（文件内小端，替换 0x6f41e..0x6f426 共 8 字节）：
    0x6f41e: 01 32       adds  r2, r2, #1     ; buf++（跳过 unused-bits 字节）
    0x6f420: 01 3b       subs  r3, r3, #1     ; len--
    0x6f422: 16 78       ldrb  r6, [r2, #0]   ; r6 = 真正的点格式字节(0x04)
    0x6f424: 66 61       str  r6, [r4, #20]   ; EC_KEY->conv_form

注：原来的 `bic.w r6,r6,#1`（清压缩标志位）被去掉。跳过 unused-bits 后
    buf[0] == 0x04（POINT_CONVERSION_UNCOMPRESSED），bit0 本来就是 0，
    bic 属于 no-op，语义不变。

用法
----
    python3 patch_b657_ec_bitstring.py --elf <in.elf> --out <out.elf>
"""
import argparse, sys

TEXT_VADDR, TEXT_OFF = 0x20, 0x8020

# 原始 8 字节 (0x6f41e .. 0x6f426)
#   6f41e: 1678        ldrb  r6, [r2, #0]
#   6f420: 26f00106    bic.w r6, r6, #1
#   6f424: 6661        str   r6, [r4, #20]
ORIG = bytes.fromhex("167826f001066661")

# 修正后 8 字节
NEW = bytes.fromhex("0132013b16786661")

def off(v):
    return TEXT_OFF + (v - TEXT_VADDR)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--elf', required=True)
    ap.add_argument('--out', required=True)
    a = ap.parse_args()

    data = bytearray(open(a.elf, 'rb').read())
    o = off(0x6f41e)
    cur = bytes(data[o:o+len(ORIG)])
    if cur == NEW:
        print("[SKIP] already patched")
    else:
        if cur != ORIG:
            print("[ERR] @0x6f41e unexpected bytes %s (want %s)" % (cur.hex(), ORIG.hex()))
            sys.exit(1)
        data[o:o+len(NEW)] = NEW
        print("[patch] 0x6f41e %s -> %s" % (ORIG.hex(), NEW.hex()))
    open(a.out, 'wb').write(data)
    print("OK ->", a.out)

if __name__ == '__main__':
    main()
