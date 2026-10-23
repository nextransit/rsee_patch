#!/usr/bin/env python3
"""
b657 TA ECDSA 修复 —— 读侧公钥恢复（2026-10-21）

根因（离线数学 + 反汇编证据闭环）
--------------------------------
写侧 `EC_generate_key` 生成的 SEC1 私钥数据**本身正确**（host 模拟 t9 证明：
i2d_ECPrivateKey 输出 121B SEC1，X/Y 都正确且在 P-256 上）。

但写入 keyblob 后，SEC1 的 `[1] pubkey` 的 Y **后 8 字节被覆盖/损坏**
（blob 密文解密后第 113~121 字节 = `7a9d4aebfc8a3e6cc4 49b90aba...`，
而正确应为 `...c9ce06cd554a1d963c`）。SPKI（明文区）里的 Y 是正确的。

⇒ 读侧 `d2i_ECPrivateKey` 解析 SEC1 的 [1] pubkey 时，
   `EC_POINT_oct2point` → `EC_POINT_is_on_curve` 失败
   ⇒ ecp_oct.c:355 → ec_asn1.c:1145 → ec_ameth.c:517(old_ec_priv_decode)
   ⇒ TA 报 "GetEcKeyEvpPkey error"(-1000)。

修复（两个补丁配合）
--------------------
PATCH-C  d2i_ECPrivateKey@0x6f368 内 [1] pubkey 解析失败时不再报错，
         而是“跳过 pubkey”继续（EC_KEY 保持无 public_key）。
         - 0x6f42c: `cbz r0, 0x6f452`(失败→报错) 改为 `cbz r0, 0x6f430`(跳过)

PATCH-D  EC 的 asn1_method(priv_decode) 从 old_ec_priv_decode 改为
         eckey_priv_decode（后者在解析出私钥 d 后用 d*G 重算公钥，不信任
         SEC1 里可能损坏的 [1] pubkey）。
         - .data eckey_asn1_meth@0xc4a98 + 0x5c = 0xc4af4
           值 0x0006dd45(old_ec_priv_decode|1) → 0x0006dadd(eckey_priv_decode|1)

用法
----
    python3 patch_b657_pubkey_recover.py --elf <in.elf> --out <out.elf>
"""
import argparse, sys, struct

TEXT_V, TEXT_O = 0x20, 0x8020
DATA_V, DATA_O = 0xb9000, 0xc1000

def off_t(v): return TEXT_O + (v - TEXT_V)
def off_d(v): return DATA_O + (v - DATA_V)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--elf', required=True)
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    data = bytearray(open(a.elf, 'rb').read())

    # PATCH-C: 0x6f42c cbz 目标 0x452 -> 0x430
    oc = off_t(0x6f42c)
    cur_c = bytes(data[oc:oc+2])
    want_c = bytes.fromhex("88b1")
    new_c = bytes.fromhex("00b1")
    if cur_c == new_c:
        print("[skip] PATCH-C already")
    elif cur_c != want_c:
        print("[ERR] PATCH-C @0x6f42c unexpected %s want %s" % (cur_c.hex(), want_c.hex()))
        sys.exit(1)
    else:
        data[oc:oc+2] = new_c
        print("[patch] PATCH-C 0x6f42c %s -> %s" % (want_c.hex(), new_c.hex()))

    # (PATCH-D 已撤销：eckey_priv_decode 期望 PKCS8 输入，TA 传 SEC1，
    #  改用 PKCS8_pkey_get0 反而在 tasn_dec.c:1257 失败。old_ec_priv_decode
    #  直接 d2i_ECPrivateKey 更适合 SEC1 输入，配合 PATCH-C 跳过坏 pubkey 即可。)

    open(a.out, 'wb').write(data)
    print("OK ->", a.out)

if __name__ == '__main__':
    main()
