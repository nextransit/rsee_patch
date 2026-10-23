#!/bin/bash
# apply_ecdsa_rootcause_fix.sh — 一键把修复后的 TA 落到固件工程
#
# fix8 = fix1 + PATCH-C, 共 4 字节:
#   - 0x1033e (fix1):    read_ec_key_from_keyblob 拷贝明文 (49 46 -> 21 46)
#   - 0x6f42c (PATCH-C): d2i_ECPrivateKey oct2point 失败时跳过坏 pubkey 继续 (88 b1 -> 00 b1)
#
# QEMU 端到端已验证: EC keygen + ECDSA sign + ECDSA verify 全部 PASS
# 真机 keystore 已验证: 15 组 ECDSA sign+verify 全部 tee=true PASS
#
# 用法:
#   WORKSPACE=/path/to/your/workspace ./apply_ecdsa_rootcause_fix.sh
#
# WORKSPACE 指向固件工程根目录 (含 vendor/ 与 external/ 两层)。
# 若目录结构不同, 用 SEC_MODULES 环境变量覆盖。

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

WORKSPACE="${WORKSPACE:-}"
if [ -z "$WORKSPACE" ]; then
    echo "ERROR: 未设置 WORKSPACE 环境变量"
    echo "  export WORKSPACE=/path/to/your/android/workspace"
    exit 1
fi
SEC_MODULES="${SEC_MODULES:-$WORKSPACE/vendor/<vendor>/proprietary/trustzone/<tee>/source/binary/sec_modules}"

# 修复后的 TA 优先取仓内 ta/ 目录, 其次取脚本同级的产物
FIXED=""
for cand in "$SCRIPT_DIR/../ta/b657_fix8_patched.ta" "$SCRIPT_DIR/b657_fix8_patched.ta"; do
    [ -f "$cand" ] && { FIXED="$cand"; break; }
done
[ -n "$FIXED" ] || { echo "ERROR: 找不到修复后的 TA (b657_fix8_patched.ta)"; exit 1; }

TA_DEBUG="$SEC_MODULES/ta_debug/b657ba17-b3b3-47f5-b389-6b53f30c0baf.ta"
TA_RELEASE="$SEC_MODULES/b657ba17-b3b3-47f5-b389-6b53f30c0baf.ta"

EXPECTED_SHA="7334367d65e41af4206ddf3cec74510d9390d59994898d453160d5f22ecd54b4"

echo "== apply b657 TA fix8 (fix1 + PATCH-C) =="
echo "  WORKSPACE = $WORKSPACE"
[ "$(sha256sum "$FIXED" | cut -d' ' -f1)" = "$EXPECTED_SHA" ] || {
    echo "ERROR: fix8 TA sha mismatch"; exit 1; }
echo "  [OK] fix8 TA sha256 verified"

for TA in "$TA_DEBUG" "$TA_RELEASE"; do
  if [ -f "$TA" ]; then
    cp -f "$FIXED" "$TA"
    echo "  [OK] $TA  sha256=$(sha256sum "$TA" | cut -d' ' -f1)"
  else
    echo "  [SKIP] $TA not found"
  fi
done

# 校验落位（两处 Patch 都应在位）
python3 - "$TA_DEBUG" <<'PY'
import sys
ta = open(sys.argv[1], 'rb').read()
i = ta.find(b'\x7fELF')
checks = [("0x1033e", 0x1033e, '2146', "fix1: 拷明文栈缓冲"),
          ("0x6f42c", 0x6f42c, '00b1', "PATCH-C: 跳过坏 pubkey")]
for name, off, want, desc in checks:
    o = i + 0x8020 + (off - 0x20)
    got = ta[o:o+2].hex()
    assert got == want, f'{name} 未落位: {got} != {want}'
    print(f'  [OK] {name} = {got}  ({desc})')
PY
echo "== done: b657 TA = fix8 (fix1 + PATCH-C), ECDSA sign/verify 可工作 =="
