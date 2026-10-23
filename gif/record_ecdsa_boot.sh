#!/bin/bash
# 录制「QEMU(ATF + OP-TEE + Linux) 启动 → ECDSA sign/verify 成功」联机器 GIF
#
# 方案: Xvfb 虚拟显示 → xterm 里 tail -f 过滤后的串口日志 → ffmpeg x11grab 录屏
#       → 调色板压缩成 GIF
#
# QEMU 参数(与 run-auto.sh 一致, 只是串口改写文件 + -display none):
#   -machine virt,secure=on -cpu cortex-a57 -m 2047 -smp 1
#   -bios bl1.bin + loader fip.bin@0x04000000 + Image@0x60000000 + clean.dtb@0x7fe00000
#
# 用法: ./record_ecdsa_boot.sh <out.gif> [秒数]
set -eu

OUT="${1:-/tmp/ecdsa-boot.gif}"
DURATION="${2:-22}"
export DISPLAY=":99"
QEMU_ROOT=${QEMU_ROOT:-/media/ben/work_2021/qemu-tee}
HERE="$(cd "$(dirname "$0")" && pwd)"
W=1280
H=800
SER=/tmp/ecdsa_boot_serial.log
CLEAN=/tmp/ecdsa_boot_clean.log

cleanup() {
    pkill -9 -f "qemu-system-aarch64.*virt,secure=on" 2>/dev/null || true
    pkill -9 -f "filter_serial.py --follow" 2>/dev/null || true
    pkill -9 -f "tail -f -n +1 $CLEAN" 2>/dev/null || true
    [ -n "${XVFB_PID:-}" ] && kill -9 "$XVFB_PID" 2>/dev/null || true
    true
}
trap cleanup EXIT

echo "[1/8] 起 Xvfb $DISPLAY (${W}x${H}x24)"
rm -f /tmp/.X99-lock 2>/dev/null || true
setsid Xvfb "$DISPLAY" -screen 0 ${W}x${H}x24 -nolisten tcp >/tmp/xvfb_gif.log 2>&1 &
XVFB_PID=$!
for i in $(seq 1 30); do xdpyinfo >/dev/null 2>&1 && break; sleep 0.5; done
xdpyinfo >/dev/null 2>&1 || { echo "ERROR: Xvfb 未起来"; tail -5 /tmp/xvfb_gif.log; exit 1; }

echo "[2/8] 起 QEMU (OP-TEE 3.6 + Linux 6.6 + 真实 b657 TA, 含两处 Patch)"
rm -f "$SER" "$CLEAN"
setsid qemu-system-aarch64 -display none \
  -machine virt,secure=on -cpu cortex-a57 -m 2047 -smp 1 \
  -serial "file:$SER" \
  -bios "$QEMU_ROOT/atf-pc/build/qemu/debug/bl1.bin" \
  -device loader,file="$QEMU_ROOT/atf-pc/build/qemu/debug/fip.bin",addr=0x04000000,force-raw=on \
  -device loader,file="$QEMU_ROOT/work/Image",addr=0x60000000,force-raw=on \
  -device loader,file=/tmp/virt-aarch64-clean.dtb,addr=0x7fe00000,force-raw=on \
  -semihosting-config enable=on,target=native -no-reboot >/tmp/qemu_gif.log 2>&1 &

echo "[3/8] 串口日志实时过滤 + xterm 显示"
# 等 QEMU 把串口日志文件建出来再启动 filter, 否则 follow() 会 FileNotFoundError
for i in $(seq 1 40); do [ -f "$SER" ] && break; sleep 0.25; done
setsid python3 "$HERE/filter_serial.py" --follow "$SER" "$CLEAN" >/tmp/filter_gif.log 2>&1 &
sleep 1
setsid xterm -fa "Monospace" -fs 12 -bg "#0d1117" -fg "#c9d1d9" \
  -title "QEMU: ATF + OP-TEE 3.6 + Linux 6.6 (arm64 virt)" -geometry 132x40+0+0 \
  -e bash -c "exec tail -f -n +1 $CLEAN" >/tmp/xterm_gif.log 2>&1 &
sleep 2

echo "[4/8] 录屏 ${DURATION}s"
RAW=/tmp/ecdsa_boot_raw.mp4
rm -f "$RAW"
ffmpeg -y -f x11grab -framerate 20 -video_size ${W}x${H} -i "$DISPLAY" \
  -t "$DURATION" -c:v libx264 -preset veryfast -crf 20 -pix_fmt yuv420p "$RAW" \
  >/tmp/ffmpeg_gif.log 2>&1 || { echo "ERROR: 录屏失败"; tail -10 /tmp/ffmpeg_gif.log; exit 1; }

echo "[5/8] 存终端窗口参考图 (用于校验 GIF 内容)"
XW=$(xdotool search --name "QEMU: ATF" 2>/dev/null | tail -1 || true)
[ -n "$XW" ] && import -window "$XW" /tmp/ecdsa_boot_window.png 2>/dev/null || true

echo "[6/8] 压缩成 GIF (调色板)"
ffmpeg -y -i "$RAW" -vf "fps=8,scale=820:-1:flags=lanczos,split[s0][s1];[s0]palettegen=max_colors=96[p];[s1][p]paletteuse=dither=bayer:bayer_scale=5" \
  -loop 0 "$OUT" 2>/tmp/ffmpeg_gif2.log || { echo "ERROR: 压缩失败"; tail -10 /tmp/ffmpeg_gif2.log; exit 1; }

echo "[7/8] 关键帧检查"
for k in "OP-TEE version" "ECDSA SIGN OK" "ECDSA VERIFY OK"; do
    printf "  %-18s : %s 处\n" "$k" "$(grep -acE "$k" "$CLEAN" || true)"
done

echo "[8/8] 完成"
ls -la "$OUT"
ffprobe -v error -show_entries stream=nb_frames,width,height,duration -of default=nw=1 "$OUT"
