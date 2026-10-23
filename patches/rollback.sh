#!/bin/bash
# rollback.sh — 回滚 b657 TA 到原厂版本
#
# 用途: 若打了补丁的 TA 导致设备 boot 失败, 用原厂 .orig_backup 还原。
#
# 用法:
#   WORKSPACE=/path/to/your/workspace ./rollback.sh
#
# WORKSPACE 指向固件工程根目录 (含 vendor/ 那一层)。厂商/平台路径已匿名化,
# 请按你的实际工程路径填写 SEC_MODULES 环境变量覆盖。

set -e

REPO="${WORKSPACE:-$(cd "$(dirname "$0")/../.." && pwd)}"
SEC_MODULES="${SEC_MODULES:-$REPO/vendor/<vendor>/proprietary/trustzone/<tee>/source/binary/sec_modules}"
DEBUG_BAK="$SEC_MODULES/ta_debug/b657ba17-b3b3-47f5-b389-6b53f30c0baf.ta.orig_backup"
DEBUG_TA="$SEC_MODULES/ta_debug/b657ba17-b3b3-47f5-b389-6b53f30c0baf.ta"
RELEASE_BAK="$SEC_MODULES/.orig_backup_b657"
RELEASE_TA="$SEC_MODULES/b657ba17-b3b3-47f5-b389-6b53f30c0baf.ta"

# Check backup exists
if [ ! -f "$DEBUG_BAK" ]; then
    echo "ERROR: no .orig_backup at $DEBUG_BAK"
    exit 1
fi

echo "=== Rolling back b657 TA ==="
echo "Source: $DEBUG_BAK"
echo

# Restore debug
cp -v "$DEBUG_BAK" "$DEBUG_TA"
md5sum "$DEBUG_TA"

# Restore release (use debug backup as fallback if no separate backup)
if [ -f "$RELEASE_BAK" ]; then
    cp -v "$RELEASE_BAK" "$RELEASE_TA"
    md5sum "$RELEASE_TA"
else
    echo "Note: no release backup, copying debug backup to release too"
    cp -v "$DEBUG_BAK" "$RELEASE_TA"
    md5sum "$RELEASE_TA"
fi

echo
echo "✓ Rollback complete. Now rebuild OTA."
