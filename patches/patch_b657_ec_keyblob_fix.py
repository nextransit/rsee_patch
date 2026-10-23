#!/usr/bin/env python3
"""
b657 TA 真正根因修复: read_ec_key_from_keyblob 把密文当明文返回
- patch: vaddr 0x1033e, TA 文件 offset 0x18472, Thumb mov r1,r9(密文) -> mov r1,r4(明文)
- 字节: 49 46 -> 21 46
- 必须重签名(ta_private_key.pem), 否则 OpenSession 0xffff000f
"""
import sys, os, struct, hashlib
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

SRC  = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "..", "b657ba17-b3b3-47f5-b389-6b53f30c0baf.ta.orig_backup")
OUT  = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "b657_ecfix_resigned.ta")
KEY  = "/media/ben/work_2021/mtk/<workspace>/external/tee/tools/ta_resign_tool-release/linux/ta_private_key.pem"
TA_OFF = 0x18472
ORIG  = bytes.fromhex("4946")   # mov r1, r9 (密文) -- BUG
NEW   = bytes.fromhex("2146")   # mov r1, r4 (明文栈缓冲) -- FIX

def main():
    data = bytearray(open(SRC,'rb').read())
    assert data[TA_OFF:TA_OFF+2] == ORIG, f"unexpected bytes {data[TA_OFF:TA_OFF+2].hex()}"
    data[TA_OFF:TA_OFF+2] = NEW
    body = bytes(data[0x134:])
    key = RSA.importKey(open(KEY,'rb').read())
    shdr = struct.pack('<IIIIHH', 0x4f545348, 0, len(body), 0x70004830, 32, 256)
    h = SHA256.new(); h.update(shdr); h.update(body)
    sig = PKCS1_v1_5.new(key).sign(h)
    out = shdr + h.digest() + sig + body
    open(OUT,'wb').write(out)
    # 自验证
    h2 = SHA256.new(); h2.update(out[:20]); h2.update(out[20+32+256:])
    assert PKCS1_v1_5.new(key).verify(h2, out[20+32:20+32+256])
    print(f"patched+resigned -> {OUT}")
    print(f"sha256 {hashlib.sha256(out).hexdigest()}")
    print(f"signature verified with {KEY.split('/')[-1]}")

if __name__ == "__main__":
    main()
