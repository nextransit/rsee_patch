#!/usr/bin/env python3
"""串口日志 → 演示用精简流（边收边滤）。

用法:
    python3 filter_serial.py <in.log> <out.log>        # 过滤已有日志
    python3 filter_serial.py --follow <in.log> <out>   # 持续跟随并过滤(用于录屏)

原始日志 1300+ 行，绝大多数是 OP-TEE 的 D/TC 调试行、Linux 驱动噪声和 TA 内部的
逐条 DEBUG。这两类内容既看不清叙事，也会把 GIF 撑到几 MB。
这里只保留能讲清「启动 → 加载 TA → ECDSA 签名 → 验签」这条链的行。
"""
import re
import sys
import time

# 只保留这些"叙事行"：一行一句，能独立读懂
STORY = [
    (re.compile(r"OP-TEE version"), "OP-TEE 启动"),
    (re.compile(r"Primary CPU switching to normal world"), "切回 NS 世界"),
    (re.compile(r"Linux version"), "Linux 启动"),
    (re.compile(r"Run /etc/init\.d/rcS"), "rcS 启动"),
    (re.compile(r"^\[rcS\] running"), "rcS 步骤"),
    (re.compile(r"^\[rcS\] launching tee-supplicant"), "起 tee-supplicant"),
    (re.compile(r"^\[rcS\] DONE"), "rcS 结束"),
    (re.compile(r"^ECDSA_P256"), "示例 ECDSA TA"),
    (re.compile(r"invoke CMD_GENERATE_KEY"), "generate"),
    (re.compile(r"invoke CMD_BEGIN"), "begin"),
    (re.compile(r"OpenSession OK"), "OpenSession 成功"),
    (re.compile(r"EC_generate_key 492"), "EC_generate_key"),
    (re.compile(r"CreateKeyBlob success"), "CreateKeyBlob 成功"),
    (re.compile(r"read_ec_key_from_keyblob begin"), "read_ec_key_from_keyblob"),
    (re.compile(r"Ecdsa_Sign_Begin 282"), "Ecdsa_Sign_Begin"),
    (re.compile(r"Ecdsa_Sign_Finish 426"), "Ecdsa_Sign_Finish"),
    (re.compile(r"Ecdsa_Verify_Begin 321"), "Ecdsa_Verify_Begin"),
    (re.compile(r"Ecdsa_Verify_Finish 494"), "Ecdsa_Verify_Finish result"),
    (re.compile(r"ECDSA SIGN OK"), "**SIGN OK**"),
    (re.compile(r"ECDSA VERIFY OK"), "**VERIFY OK**"),
]


def keep(line):
    for rx, _ in STORY:
        if rx.search(line):
            return True
    return False


def filter_file(src, dst):
    out = []
    with open(src, "rb") as f:
        for raw in f:
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if line.strip() and keep(line):
                out.append(line)
    with open(dst, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")
    print(f"[filter] {src} -> {dst}: {len(out)} 行")


def follow(src, dst):
    """跟随输入文件, 把新到的、符合规则的行追加到输出文件。"""
    pos = 0
    with open(src, "rb") as fin, open(dst, "w", encoding="utf-8") as fout:
        while True:
            fin.seek(pos)
            chunk = fin.read()
            pos = fin.tell()
            for raw in chunk.decode("utf-8", "replace").split("\n"):
                line = raw.rstrip("\r")
                if line.strip() and keep(line):
                    fout.write(line + "\n")
                    fout.flush()
            time.sleep(0.15)


def main():
    args = sys.argv[1:]
    if args and args[0] == "--follow":
        follow(args[1], args[2])
    else:
        filter_file(args[0], args[1])


if __name__ == "__main__":
    main()
