"""统一的工程路径解析（供各 patch 脚本 import）。

厂商名 / 平台代号 / 产品代号已匿名化，所以**默认路径是占位符**，
使用者必须通过环境变量 `WORKSPACE`（工程根目录）指向自己的固件工程：

    export WORKSPACE=/path/to/your/android/workspace
    python3 patch_b657_pubkey_recover.py --elf b657.elf --out patched.elf

若工程里 TEE 目录结构与默认不同，还可以用 `SEC_MODULES` / `RESIGN_TOOL_DIR`
单独覆盖。
"""
import os
from pathlib import Path

def _resolve(env_name: str, default: str = "") -> Path:
    """读环境变量并展开为绝对路径（未设置时返回当前目录）。"""
    raw = os.environ.get(env_name, "").strip() or default
    return Path(raw).expanduser().resolve()


# 工程根目录（必填，用 WORKSPACE 环境变量指定）
WORKSPACE = _resolve("WORKSPACE")

# 固件工程里 TEE 二进制模块目录
SEC_MODULES = _resolve(
    "SEC_MODULES",
    str(WORKSPACE / "vendor/<vendor>/proprietary/trustzone/<tee>/source/binary/sec_modules"),
)

# TA 重签工具目录（含 ta_private_key.pem 与 resign_ta.py）
RESIGN_TOOL_DIR = _resolve(
    "RESIGN_TOOL_DIR",
    str(WORKSPACE / "external/tee/tools/ta_resign_tool-release/linux"),
)

TA_UUID = "b657ba17-b3b3-47f5-b389-6b53f30c0baf"
TA_FILENAME = f"{TA_UUID}.ta"

TA_DEBUG = SEC_MODULES / "ta_debug" / TA_FILENAME
TA_RELEASE = SEC_MODULES / TA_FILENAME
TA_PRIVATE_KEY = RESIGN_TOOL_DIR / "ta_private_key.pem"


def require_workspace() -> None:
    """路径未配置时给出明确报错，而不是让脚本在奇怪路径上静默失败。"""
    if not os.environ.get("WORKSPACE"):
        raise SystemExit(
            "ERROR: 未设置 WORKSPACE 环境变量。\n"
            "  export WORKSPACE=/path/to/your/android/workspace\n"
            "（该目录应包含 vendor/ 与 external/ 两层）"
        )


def describe() -> None:
    print(f"  WORKSPACE      = {WORKSPACE}")
    print(f"  SEC_MODULES    = {SEC_MODULES}")
    print(f"  TA_DEBUG       = {TA_DEBUG}")
    print(f"  TA_RELEASE     = {TA_RELEASE}")
