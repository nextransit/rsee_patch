---
name: tee-ecdsa-patch
description: >
  复现、定位并修复闭源 TEE（OP-TEE 3.6 闭源分支）里 keymaster TA 的 ECDSA 签名失败问题。
  适用于「ECDSA 密钥生成成功但 sign/验签全部失败」这一类症状，涵盖静态逆向定位、
  QEMU 受控复现、二进制字节级 Patch、原厂私钥重签、真机 keystore 闭环验证全流程。
  触发关键词：TEE ECDSA, keymaster TA, OP-TEE 二进制 patch, TA 重签, OpenSession ffff000f,
  ecp_oct.c, d2i_ECPrivateKey, QEMU 复现 TEE, 闭源 TEE 调试, keyblob 私钥读出是公钥。
---

# 闭源 TEE ECDSA 修复操作手册

> 本 skill 是 `rsee_patch` 仓的操作手册：如何在**没有源码**的 TEE 环境里，把一个
> keymaster TA 的 ECDSA sign/verify 从「全失败」修复到「双向 PASS」并推到真机闭环。

---

## 0. 适用判断（先确认再动手）

| 症状 | 是否适用 |
|---|---|
| ECDSA keygen 成功，但 sign / 验签全失败 | ✅ 典型场景 |
| RSA / AES / HMAC 正常，只有 EC 系异常 | ✅ 高度怀疑（读侧拷贝 bug） |
| OpenSession 直接返回 `ffff000f` | ⚠️ 不是本问题，是**没重签**（见 §4） |
| TA 加载即 panic / Secure World 崩溃 | ⚠️ 不是本问题，先看 last_kmsg |
| keygen 本身也失败 | ⚠️ 不是本问题，先查 keyblob 写入侧 |

**关键判据**：真机 last_kmsg 里 TA 是否能打出 `read_ec_key_from_keyblob begin → end`。
能打出 = 解密成功 = 问题在**读出后的解析**，正是本手册覆盖的范围。

---

## 1. 复现环境：QEMU + OP-TEE 3.6

### 组件

| 组件 | 说明 |
|---|---|
| OP-TEE OS 3.6（`vexpress-qemu_armv8a`） | TEE OS（BL32） |
| ATF（`PLAT=qemu`, `SPD=opteed`） | BL1/BL2/BL31 + FIP |
| Linux 6.6（arm64 defconfig + `CONFIG_OPTEE`） | NS 世界，内置 initramfs |
| optee_client（libteec + tee-supplicant） | REE↔TEE 通信 |
| 目标 TA（`b657ba17-*.ta`） | 被测对象 |
| host 测试程序（`test_b657_real`） | 照真机 HAL 协议调 TA |

TA 是 32-bit ARM ELF → **arm64 core + `ta_arm32` 混编**。

### 启动命令

```bash
qemu-system-aarch64 -display none \
  -machine virt,secure=on -cpu cortex-a57 -m 2047 -smp 1 \
  -serial file:serial0.log -serial file:serial1.log \
  -bios atf-pc/build/qemu/debug/bl1.bin \
  -device loader,file=atf-pc/build/qemu/debug/fip.bin,addr=0x04000000,force-raw=on \
  -device loader,file=work/Image,addr=0x60000000,force-raw=on \
  -device loader,file=/tmp/virt-aarch64-clean.dtb,addr=0x7fe00000,force-raw=on \
  -semihosting-config enable=on,target=native -no-reboot
```

> ⚠️ **DTB 地址**：OP-TEE 3.6 的 `init_external_dt` 从 **0x7fe00000** 读外部 DTB。
> 放到 0x7ff00000 会 panic：`Invalid Device Tree at 0x7fe00000: error -9`。

成功标志：`I/TC: OP-TEE version: ... aarch64` → `Primary CPU switching to normal world boot` → Linux rcS 跑完测试。

### 启动路上的坑

1. **EFI_ZBOOT**：Linux 6.6 默认把 Image 打成 PE/COFF（MZ 头），ATF 跳不过 →
   关闭 `CONFIG_EFI_GENERIC_STUB`，Image 首字节应为 `1f2003d5`。
2. **PAC/BTI**：GCC 默认启用，需按 defconfig 关掉。
3. **alternatives**：`CONFIG_RELOCATABLE=n` + `CONFIG_ARM64_VA_BITS_48`。
4. **secure-only DTB 节点**泄漏到 NS 世界 → 手工删 pl011 等节点。
5. **内存**：`-m 2047` 且 DTB 用同参数生成，保证 memory 节点覆盖整个 Image。

---

## 2. 三种调试手段

### A. TA 自带 trace（最快）

debug 版 TA 每条 OpenSSL 错误会打到 NS dmesg，**精确到文件:行**：

```
ERROR: TeeCrypto error: lib 16 func 103 reason 107
  file lib/crypto/ec/ecp_oct.c line 355
```

### B. gdb 连 QEMU

```bash
./run-auto.sh 75 gdb      # 启动后停在 first instruction
# 另开一个终端
gdb -ex "target remote :1234" -ex "add-symbol-file b657.elf 0x4000fe0"
```

- TA 运行时基址 = **0x40010000**（ldelf 打印）；
- `.text` vaddr 0x20 → 运行时 0x40010000，故 `add-symbol-file` 用 `0x4000fe0`；
- **按符号下断点**，别手算基址+偏移：

```gdb
break EC_POINT_oct2point
info registers r0 r1 r2 r3     # 32-bit ARM ELF → r0..r3，不是 x0..x3
x/16bx $r2                     # r2=buf(公钥字节), r3=len
```

> `EC_POINT_oct2point` 在 ELF 里 vaddr 是 `0x6fcb0`，加 `0x4000fe0` 得运行时 `0x4070c90`。

### C. 离线反汇编 + addr2line

TA ELF 不是 stripped，且 TEE 侧自带 `libcrypto.a` 带 DWARF：

```bash
arm-none-eabi-objdump -d b657.elf | less
arm-none-eabi-addr2line -e b657.elf -f -C 0x...   # 错误地址 → 文件:行
```

---

## 3. 五层证据链（定位套路）

| 层 | 做什么 | 得到什么 |
|---|---|---|
| 1 静态逆向 | 反汇编 TA ELF、查 `__utee_entry` / cmd 分发 | TA 结构与命令表 |
| 2 真机证据 | 抓 last_kmsg + 设备 keyblob | 错误链 + 密文/明文对比 |
| 3 离线数学 | host 上跑 crypto 库模拟写侧 | **只能排除，不能定论**（见下） |
| 4 QEMU 复现 | 装未修复 TA 跑 host 测试 | 错误链与真机**一致** → 确认是通用 bug |
| 5 端到端验证 | 打补丁后跑完整 sign/verify | 修复是否真正有效 |

> ⚠️ **第 3 层的坑**：host 上的 `libcrypto.a` 与**真机 TA 内嵌的实现不是同一份**。
> 标准库 `i2d_*` 会推进 `*pp`，TA 内嵌的那份**不会**。所以第 3 层**不能**用来证明
> 「写侧没 bug」，只能证明「数学上自洽、长度判定正确」。

### 关键取证：keyblob 密文 vs 明文

从设备 `/data/misc/keystore` 抓 keyblob，解密明文区：

- 开头 `30 59 30 13 ...` = **SubjectPublicKeyInfo（公钥 SPKI）**
- 标准 ECPrivateKey 应是 `30 77 02 01 01 04 20 ...`

→ **私钥区读出来是公钥**，问题在读侧。

---

## 4. 根因与修复

### Bug 1：read_ec_key_from_keyblob 拷回密文

`DecryptKeyBlob` 把明文写到栈缓冲，但函数末尾 `TEE_MemMove(输出, __dest, enc_len)`
拷的是**原始密文**。

（RSA 侧 `read_rsa_key_from_keyblob` 拷贝明文栈缓冲，所以 RSA 一直正常。）

**修复**：`0x1033e` `49 46`（`mov r1, r9` 密文）→ `21 46`（`mov r1, r4` 明文栈缓冲）。

### Bug 2：SPKI 覆盖导致 SEC1 解析失败（读侧绕过）

修复 1 后错误链前移到 `ecp_oct.c:355`。gdb 断 `EC_POINT_oct2point` 看到：
SEC1 私钥数据里 `[1] pubkey` 的 **Y 坐标后 8 字节被损坏**，但同一 keyblob 明文区
SPKI 里的 Y 正确。

**写侧机理尚未定论**。曾怀疑 `EC_generate_key` 里两次 `i2d_PrivateKey` + 两次
`i2d_PUBKEY` 共用缓冲导致 SPKI 覆盖私钥区，但实验证伪：把两次 `i2d_PUBKEY` 的
`pp` 改传 NULL（SPKI 变全 0），**错误链完全不变**。

**修复（PATCH-C）**：`0x6f42c` `88 b1`（`cbz r0` → 报错）→ `00 b1`（`cbz r0` → 跳过坏 pubkey 继续）。

> ⚠️ **PATCH-C 是绕过，不是修复。** 代价是 `EC_KEY` 里**没有公钥**，
> `export_key` 路径因此不适用（报 `blob_2_instance error`）。
> 想要完整公钥只能在读侧 `d2i` 后用 `d*G` 重算，但库内 `eckey_priv_decode`
> 期望 PKCS8 输入，与 TA 实传的 SEC1 不匹配（`tasn_dec.c:1257` 失败）。

### 字节对照速查

```text
位置        原始字节      修复后字节     指令含义变化
─────────────────────────────────────────────────────────────────────
0x1033e    49 46    →    21 46      mov r1, r9 (密文)   →  mov r1, r4 (明文栈缓冲)
0x6f42c    88 b1    →    00 b1      cbz r0, <报错分支>   →  cbz r0, <跳过坏 pubkey>
```

两组字节都不涉及指令长度变化（`cbz` 只改低字节偏移，`mov` 只改源寄存器编号），
不需要重排代码。

---

## 5. 改字节必须配重签

**只改字节没重算 digest + 重签名 → OpenSession `ffff000f`。**

debug 固件内嵌**两把** TA 验签公钥：

- **key1** = `ta_private_key.pem` 的公钥（debug key）——原厂 factory TA 由 key2（OEM key）签发；
- **key2** = 另一把 OEM key。

debug 固件**同时信任 key1 和 key2**，所以用 key1 重签就能通过：

```bash
python3 resign_ta.py --key ta_private_key.pem --in patched.ta
```

（RSA PKCS1_SHA256。`resign_ta.py` 来自 TEE 官方发布工具目录，私钥不入库。）

---

## 6. host 协议的坑

修复后 sign 通了但 verify 报「clientId 不匹配」。反汇编 `Ecdsa_CreateOperation` 发现：
TA 会把 **keyblob 里存的 purpose 与调用方传的 purpose 做 memcmp**。

而 host 测试把 verify 的 purpose 传成 3(VERIFY)，keyblob 里 generate 存的是 2(SIGN) → 被拒。

**且** host 只看 `TEEC_InvokeCommand res==0`，没看 head[4] 错误码 → 误报「VERIFY OK」。

**修协议**：verify 的 params 里 purpose 保持与 keyblob 一致，仅 head[16]=3 走 verify 分支。

> 教训：host 测试要**照 HAL 反汇编写协议**，且不能只看 `res==0`，要看 head 错误码。

---

## 7. 端到端验证

```bash
./run-auto.sh 75              # 起 QEMU
./test-b657-final.sh          # 端到端验证
```

成功标志：

```
[8.953] ECDSA SIGN OK
  [9.091] ECDSA VERIFY OK
```

### 真机闭环（不能省）

QEMU 通过**不等于**修完。真机 keystore 用例必须跑出 `tee=true` 的 PASS：

```
PASS ECDSA secp256r1 SHA-1   sign+verify - sig=72B  DER=true tee=true
PASS ECDSA secp384r1 SHA-256 sign+verify - sig=103B DER=true tee=true
PASS ECDSA secp521r1 SHA-512 sign+verify - sig=104B DER=true tee=true
```

`tee=true` = 走 TEE 而非软件回退。3 曲线 × 5 摘要 = 15 组全 PASS 才算闭环。

---

## 8. 产物索引

| 路径 | 内容 |
|---|---|
| `docs/tee-ecdsa-debug-fix-test-SUMMARY.md` | 总纲：完整操作手册 |
| `docs/tee-ecdsa-qemu-debug.md` | QEMU 调试全记录（含每层原始输出） |
| `docs/tee-ecdsa-rootcause-fix.md` | 根因分析：两处 Patch 的反汇编依据 |
| `docs/ta-b657ba17-protocol.md` | TA 协议逆向（cmd 分发表） |
| `docs/tee-b657-open-session-rootcause.md` | OpenSession `ffff000f` 的成因（重签问题） |
| `patches/patch_b657_ec_keyblob_fix.py` | fix1 脚本（0x1033e） |
| `patches/patch_b657_pubkey_recover.py` | PATCH-C 脚本（0x6f42c） |
| `patches/apply_ecdsa_rootcause_fix.sh` | 一键应用 fix8（sha256 校验 + 落位断言） |
| `patches/rollback.sh` / `restore_factory_ta.py` | 回滚原厂 TA |
| `ta/b657_fix8_patched.ta` | 最终交付 TA（fix1 + PATCH-C，已重签） |
| `gif/record_ecdsa_boot.sh` | 录「QEMU 启动 → ECDSA 验签通过」GIF |
| `evidence/device-keystore-run-*.log` | 真机 keystore 实跑日志 |

---

## 9. 安装

```bash
cp -r rsee_patch/skill ~/.codex/skills/tee-ecdsa-patch
```

或直接把本目录作为 skill 根使用。`SKILL.md` 的 frontmatter 已符合 Codex skill 规范
（`name` + `description`）。

---

## 10. 方法论沉淀

1. **闭源 TEE 也能闭环**：静态逆向 + QEMU 复现 + 二进制 Patch + 重签 + 端到端验证，
   可以替代「改源码」。
2. **「生成成功但加解密失败」= 写入/读取侧不对称**：先在 keyblob 明文里对比公私钥数据，
   通常能直接看出是「写错」还是「读错」。
3. **Patch TA 必须重签**：只改字节 = 验签失败 = OpenSession `ffff000f`。
4. **host 测试要照 HAL 反汇编写协议**，且不能只看 `res==0`，要看 head 错误码。
5. **模拟通过 ≠ 真机通过**：QEMU 双向 PASS 只是中间态，最后必须在真机 keystore 上
   跑出 `tee=true` 的 PASS 才算修完。
6. **能稳定复现 ≠ 能拿到最后一层解释**：写侧机理待查时，采用读侧绕过并把边界写清楚，
   不要把「现象已钉死」写成「根因已定论」。
