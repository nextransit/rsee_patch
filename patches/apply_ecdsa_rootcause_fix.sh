#!/bin/bash
# 应用 b657 TA ECDSA 修复 (2026-10-22 更新: 由 fix1 升级为 fix8 = PATCH-C)
# fix8 内容:
#   - 0x1033e (fix1): read_ec_key_from_keyblob 拷贝明文 (49 46 -> 21 46)
#   - 0x6f42c (PATCH-C): d2i_ECPrivateKey oct2point 失败时跳过坏 pubkey 继续 (88 00)
# QEMU 已端到端验证: EC keygen + ECDSA sign + ECDSA verify 全部 PASS
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FIXED="$SCRIPT_DIR/b657_fix8_patched.ta"
TA_DEBUG="$SCRIPT_DIR/../b657ba17-b3b3-47f5-b389-6b53f30c0baf.ta"
TA_RELEASE="$SCRIPT_DIR/../../b657ba17-b3b3-47f5-b389-6b53f30c0baf.ta"

EXPECTED_SHA="7334367d65e41af4206ddf3cec74510d9390d59994898d453160d5f22ecd54b4"

echo "== apply b657 TA fix8 (PATCH-C) =="
[ -f "$FIXED" ] || { echo "ERROR: $FIXED missing"; exit 1; }
[ "$(sha256sum "$FIXED" | cut -d' ' -f1)" = "$EXPECTED_SHA" ] || { echo "ERROR: fix8 TA sha mismatch"; exit 1; }

for TA in "$TA_DEBUG" "$TA_RELEASE"; do
  if [ -f "$TA" ]; then
    cp -f "$FIXED" "$TA"
    echo "  [OK] $TA  sha256=$(sha256sum "$TA" | cut -d' ' -f1)"
  else
    echo "  [SKIP] $TA not found"
  fi
done

# 校验落位（PATCH-C 应已在 0x6f42c 为 00 b1）
python3 - "$TA_DEBUG" <<'PY'
import sys
ta = open(sys.argv[1],'rb').read()
i = ta.find(b'\x7fELF')
o = i + 0x8020 + (0x6f42c - 0x20)
got = ta[o:o+2].hex()
assert got == '00b1', 'PATCH-C not landed: 0x6f42c=%s' % got
print('  [OK] PATCH-C landed: 0x6f42c = 00b1 (跳过坏 pubkey)')
PY
echo "== done: b657 TA = fix8 (fix1 + PATCH-C), ECDSA sign/verify 可工作 =="
