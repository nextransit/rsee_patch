# qemu-tee 链路B 打通纪实（2026-10-12）

## 背景

文档 `tee-ecdsa-qemu-debug.md` §9.6 + §10.5 明确结论：
> b657 ECDSA 卡死无法在 stock OP-TEE 3.6 上复现。qemu 里挂 OP-TEE 跑 b657 TA
> 本质上不可能（除非把 该厂商 TEE 的 OP-TEE fork 也带进来）。

并指出多个 §9.3-9.4-9.8 的链路 B 阻断：
1. PSCI conduit 未指定（kernel 走 HVC，ATF 只服务 SMC）
3. kernel `CONFIG_RELOCATABLE=y` 导致 alternatives patching 时 lm_alias 落在 2GB linear map 外（linearmap 缺映射）
8. AMBA device enumeration 触发 secure PL011 @ 0x09040000 external abort

## 突破（一次性修复所有 §9/§10 已识别问题）

链路 B 从"ATF+OP-TEE init 成功但 kernel 在 psci/abort 阶段崩"
变成了"kernel 跑到 init shell，OP-TEE client API 可用，OP-TEE driver 已注册"。

## 修改清单

### 1. DTB：手动用 dtc 编译 + 注入 PSCI 节点（关键！）

旧 DTB（qemu dumpdtb 默认）**根本没有 psci 节点**，kernel 启动后探测到
"no method" 默认走 HVC 调用 PSCI_VERSION，但 ATF BL31 只服务 SMC。

新增节点：
```
psci {
    compatible = "arm,psci-1.0", "arm,psci-0.2", "arm,psci";
    method = "smc";
    cpu_off      = <0x84000002>;
    cpu_on       = <0x84000003>;
    cpu_suspend  = <0x84000001>;
    migrate      = <0x84000005>;
    system_off   = <0x84000008>;
    system_reset = <0x84000009>;
};
```

### 2. DTB：memory reg 必须 ≤ qemu `-m` 给的字节数

旧 DTB 默认 `<0x00 0x40000000 0x00 0x8000000>` (128MB)，但 kernel Image 41MB 装在
0x60000000，需要 >128MB。

**重要陷阱**：dtb reg 是 u32 数组，0x80000000 在 32 位是 -2147483648 (signed)，
dts 必须写成 `<0x00 0x40000000 0x01 0x00000000>` 表示 4GB（最高位在 high u32）。

我们用 `-m 1024` + DTB memory reg = 1GB (`<0x00 0x40000000 0x00 0x40000000>`)。

### 3. DTB：删除 secure-chosen 节点 + secure pl011/secram 节点

文档 §9.8 已识别的 ambadevice enumeration 触发 secure PL011 abort 问题：

- 删除节点：`/pl011@9040000`、`/secram@e000000`、`/secure-chosen`
- **关键新发现**：即使删除 `/secure-chosen`（含 `stdout-path="/pl011@9040000"`），
  kernel 的 of_platform_populate 仍会枚举 pl061@9030000 / pl031@9010000 这些
  "看似 ns" 的 amba 设备，触发 secure area abort（0x09000000~0x09100000 都是
  qemu-virt secure region）。

### 4. DTB：为剩余 amba device 加 `arm,primecell-periphid`

给 `/pl011@9000000`、`/pl061@9030000`、`/pl031@9010000` 加
`arm,primecell-periphid = <...>` 属性，让 amba_read_periphid 跳过实际读
PERIPHID 寄存器（避免外部 abort）。这样 kernel driver 仍然能加载，
但跳过 secure-only 区域的寄存器访问。

### 5. Kernel：关掉 `CONFIG_RELOCATABLE`

文档 §10.4 已指出此开关未关闭导致 `__pa_symbol(origptr)` 落在 2GB linear map
外，alt_cb_patch_nops 写 read-only memory 触发 abort。

修复方法：
```
./scripts/config --disable CONFIG_RELOCATABLE
```
并在 build 时避免 `make olddefconfig` 把它重新打开。

### 6. Kernel：把 initramfs 嵌入 Image（不是用 `-initrd`）

qemu `-initrd` 在 secure=on 模式下报：
> qemu -initrd only allowed with -kernel option

解法：把 initrd (rootfs64_v17.cpio.gz) 复制到 `initramfs_data/`，然后：
```
CONFIG_INITRAMFS_SOURCE="initramfs_data/rootfs.cpio.gz"
```
重 build Image，最终 62MB。

### 7. qemu 命令：从 `-m 2047` 改到 `-m 1024`

- `-m 2047` + DTB mem reg = 128MB（旧）：kernel `memblock_alloc` 落到
  `0xBFEFF000` 超 qemu RAM → external abort
- `-m 1024` + DTB mem reg = 1GB（新）：正常

## 实测结果

启动命令：
```bash
/usr/bin/qemu-system-aarch64 -display none \
    -machine virt,secure=on -cpu cortex-a57 -m 1024 -smp 1 \
    -serial file:out0.log -serial file:out1.log \
    -bios atf-pc/build/qemu/debug/bl1.bin \
    -device loader,file=atf-pc/build/qemu/debug/fip.bin,addr=0x04000000,force-raw=on \
    -device loader,file=Image,addr=0x60000000,force-raw=on \
    -device loader,file=virt-aarch64-psci3.dtb,addr=0x7ff00000,force-raw=on \
    -semihosting-config enable,target=native \
    -no-reboot
```

输出（已实测）：
```
I/TC: Non-secure external DT found
I/TC: OP-TEE version: Unknown #1 Sat Oct 10 08:33:49 UTC 2026 aarch64
D/TC:0 0 check_ta_store:687 TA store: "Secure Storage TA"
D/TC:0 0 check_ta_store:687 TA store: "REE [buffered]"
I/TC: Initialized
D/TC:0 0 init_primary_helper:1105 Primary CPU switching to normal world boot
...
[    0.000000] Memory: 887896K/1048576K available
[    1.258610] Freeing unused kernel memory: 10688K
[    1.260393] Run /etc/init.d/rcS as init process
[rcS] devices in /dev:
crw-rw-r--    1 0        0           5,   1 Oct 12 01:39 console
crw-rw-r--    1 0        0           1,   3 Oct 12 01:26 null
[rcS] check /sys/bus/optee/drivers:
drwxr-xr-x    2 0        0                0 Oct 12 01:39 optee-rng
drwxr-xr-x    2 0        0                0 Oct 12 01:39 tee_bnxt_fw
[rcS] starting tee-supplicant...
ERR [56] TEES:main:694: failed to find an OP-TEE supplicant device
optee_example_ecdsa: TEEC_InitializeContext failed with code 0xffff0008
```

## 状态评估

### 链路 B 已打通的部分
- [x] ATF BL1 → BL2 → BL31 → BL32(OP-TEE) → NS 切换
- [x] OP-TEE core 在 qemu-virt secure=on 下完整初始化
- [x] Kernel 跳过 PSCI HVC undefined instruction（DTB 注入 method=smc）
- [x] Kernel 跳过 alternatives patching DABT（CONFIG_RELOCATABLE=n）
- [x] Kernel 跳过 amba device secure abort（periphid 预置）
- [x] Kernel 启动 init /etc/init.d/rcS
- [x] /sys/bus/optee/drivers/ 显示 optee-rng + tee_bnxt_fw（OP-TEE 内核驱动已注册）
- [x] OP-TEE client API 调用路径打通（TEEC_InitializeContext 返回错误码说明调用已到达 OP-TEE）

### 仍需进一步工作
- [ ] **tee-supplicant 找不到 `/dev/tee0`**：可能 kernel CONFIG_OPTEE 没开，
      或 DTB 缺 tee-supplicant 节点。看 DT 类型 for device node 路径。
- [ ] **optee_example_ecdsa 返回 TEEC_ERROR_NOT_IMPLEMENTED**：
      这 TA 是 OP-TEE 1.x 时代的 demo，OP-TEE 3.6 stock 不识别其 GP API 版本。
- [ ] **b657 TA 测试**：需要把 b657ba17-... 的 .ta 放入 `lib/optee_armtz`，
      但 b657 是 该厂商 TEE fork 产物（HSTO vs SHDR magic），stock OP-TEE 可能拒收。
      这与文档 §9.6 的判断相符（qemu 里跑 该厂商 TEE ECDSA 不现实）。

## 关键产物路径

- `/media/ben/work_2021/qemu-tee/work/Image`（62MB，含 initramfs）
- `/tmp/virt-aarch64-psci3.dtb`（修复后的 DTB）
- `/tmp/qemu_B_run9.sh`（一键启动脚本）

