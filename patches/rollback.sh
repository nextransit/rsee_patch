#!/bin/bash
# Rollback: restore b657.ta from .orig_backup
# Use this if patched b657.ta causes device boot failure

set -e

REPO=/media/ben/work_2021/mtk/<workspace>
DEBUG_BAK="$REPO/vendor/<vendor>/proprietary/trustzone/<tee>/source/binary/sec_modules/ta_debug/b657ba17-b3b3-47f5-b389-6b53f30c0baf.ta.orig_backup"
DEBUG_TA="$REPO/vendor/<vendor>/proprietary/trustzone/<tee>/source/binary/sec_modules/ta_debug/b657ba17-b3b3-47f5-b389-6b53f30c0baf.ta"
RELEASE_BAK="$REPO/vendor/<vendor>/proprietary/trustzone/<tee>/source/binary/sec_modules/.orig_backup_b657"
RELEASE_TA="$REPO/vendor/<vendor>/proprietary/trustzone/<tee>/source/binary/sec_modules/b657ba17-b3b3-47f5-b389-6b53f30c0baf.ta"

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
echo "✓ Rollback complete. Now run ./auto-build.sh to rebuild OTA."
