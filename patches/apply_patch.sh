#!/bin/bash
# Auto-apply b657 TA ECDSA deadlock fix to all .ta files in this dir.
# Idempotent. Run before build.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PATCH_SCRIPT="$SCRIPT_DIR/restore_factory_ta.py"

# Patch debug + release .ta files
python3 "$PATCH_SCRIPT"

# If release .ta also exists in the sec_modules root, patch it too
RELEASE_TA="$(dirname "$SCRIPT_DIR")/../b657ba17-b3b3-47f5-b389-6b53f30c0baf.ta"
if [ -f "$RELEASE_TA" ]; then
    python3 "$PATCH_SCRIPT"
fi

echo ""
echo "✓ Build ready. Continue with:"
echo "  cd $WORKSPACE   # 你的固件工程根目录"
echo "  ./build.sh"
