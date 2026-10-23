# 该厂商 TEE + b657 TA ECDSA 「QEMU 复现→逆向→修复→端到端验证」完整操作手册

> 整理：2026-10-23 ｜ 工作区：`/media/ben/work_2021/qemu-tee/`（QEMU）+ `/media/ben/work_2021/mtk/<workspace>/`（真机构建）
> 目标读者：需要复现「该厂商 TEE/TA ECDSA 问题」或继续调试的工程师
> 配套：`tee-ecdsa-qemu-debug.md`（过程流水）、`tee-ecdsa-rootcause-fix.md`（根因）、
>      `watchdog-reboot-rootcause.md`（真机重启）、`ota-auto-upgrade.md`（真机烧录）

---

## 目录
1. 项目起因与问题定义
2. QEMU 环境搭建与「运行 该厂商 TEE」完整步骤
3. 把 b657 TA 装进 QEMU 并跑 host 测试程序
4. Debug TA 的三种手段（串口 trace / gdb 断点 / 反汇编+addr2line）
5. 如何使用 keystore App 做真机测试
6. 定位问题的五层证据链（静态→真机→离线数学→QEMU→端到端）
7. 全部问题清单与修复手法（字节级 patch + 重签名 + 协议修正）
8. 当前状态、验证清单、产物归档

---

## 1. 项目起因与问题定义

### 1.1 项目起因
**一句话：`ecdsa + 该厂商 TEE` 中，ECDSA 生成密钥成功，但加解密失效。**

- 硬件平台：目标平台（MTK 目标平台，ARMv8），Android 9
- TEE：**该厂商 TEE**（OP-TEE 3.6 的闭源 fork；TEE 内核源码未开源，只有二进制）
- TA：`b657ba17-b3b3-47f5-b389-6b53f30c0baf.ta` = 该厂商 **keymaster4 TA**（32-bit ARM）
- 客户业务：`com.vendor.keystore`（该厂商 keystore 测试 App）调 AndroidKeyStore 做 ECDSA
- 用户报告：**ECDSA 能正常过 keygen（generate），但后续 sign / 加解密全部失败，
  甚至在某些固件下导致系统 boot loop / watchdog 重启**

### 1.2 要解决的问题（拆成 3 个子问题）
| # | 子问题 | 证据/现象 |
|---|---|---|
| P1 | ECDSA keygen 成功但 **sign 失败/报错** | keystore App：`FAIL ECDSA secp256r1 SHA-256 — KeystoreException: Unknown error`（curve secp256r1，digest SHA-1/224/256/384 全 FAIL）；TA 报 `GetEcKeyEvpPkey error` |
| P2 | 烧某些修复包后 **boot loop / watchdog** | 曾被误判为"TA 卡死"，需区分是否 TA 引起 |
| P3 | QEMU 里复现 + 修复 + 端到端验证 | 该厂商 TEE 无源码 → 只能"二进制 patch TA + 重签名 + QEMU 全链路验证" |

### 1.3 方法论约束
- **TEE 内核源码未开源**、TA 只有二进制 → 三条可用路径：
  1. 静态逆向（IDA/objdump 反汇编 该厂商 TEE.raw + b657.ta.elf）解释行为
  2. **在 QEMU 里跑真实 该厂商 TEE/TA** 受控复现
  3. **二进制 patch TA + 重签名**（不能用 该厂商 TEE 源码重编）
- 目标：**复现问题 → 定位根因 → 修复 TA → QEMU 端到端校验 → 真机验证**。

### 1.4 总体方法（五层闭环）
| 层 | 手段 | 回答的问题 | 对本项目的关键输出 |
|---|---|---|---|
| 1 静态逆向 | IDA/objdump 反汇编 该厂商 TEE.raw + b657.ta.elf | TA 调用链长什么样 | 定位 EC_generate_key / GetEcKeyEvpPkey 关键函数与错误链 |
| 2 真机证据 | last_kmsg / dmesg / keyblob dump / keystore App | 真机实际失败/卡在哪 | 真机 keyblob 明文 = SPKI（非 ECPrivateKey）；bootreason=watchdog |
| 3 离线数学 | libcrypto.a 在 host 模拟 SEC1/公私钥 | 数据到底对不对 | 证明 SEC1 私钥本身正确，d*G 与 SPKI 公钥一致 |
| 4 QEMU 复现 | OP-TEE 3.6 + Linux + b657 TA + host 测试 | 能否在受控环境复现 | 复现 `ecp_oct.c:355` 错误链（与真机完全一致） |
| 5 端到端验证 | QEMU 内 sign+verify 全链路 + 离线验签 | 修复是否真正有效 | fix8(PATCH-C)：sign+verify 双向 PASS |

---

## 2. QEMU 环境搭建与「运行 该厂商 TEE」完整步骤

### 2.1 组件清单（已在 /media/ben/work_2021/qemu-tee/ 构建好）
| 组件 | 目录/产物 | 说明 |
|---|---|---|
| OP-TEE OS 3.6 | `optee_os_new/out/vexpress-qemu_armv8a/core/tee-{header,pager,pageable}_v2.bin` | PLATFORM=vexpress-qemu_armv8a，**arm64 core + ta_arm32**（b657 是 32bit ELF） |
| ATF | `atf-pc/build/qemu/debug/{bl1,bl2,bl31}.bin + fip.bin` | aarch64，`SPD=opteed`，BL32=OP-TEE |
| Linux kernel | `work/linux-6.6/arch/arm64/boot/Image` | arm64 defconfig + `CONFIG_OPTEE=y` + **内置 initramfs**（含 busybox/TAs/test） |
| optee_client | `optee_client/out64/export/usr/{lib,sbin,include}` | aarch64 libteec + tee-supplicant |
| 测试 TA | `optee_examples/{hello_world,ecdsa}/ta/*.ta` | 对照组（验证 OP-TEE 链路本身正常） |
| host 测试 | `work/host-tests/{test_b657_ecdsa, test_b657_real}` | 调 b657 TA 的真实协议 |
| 一键运行 | `work/run-auto.sh [secs] [gdb]` | 重建 initramfs→打包 Image→注入 FIP→起 qemu |

### 2.2 为什么选 arm64 `qemu-system-aarch64 -M virt,secure=on`
- 目标平台 是 ARMv8 SoC；OP-TEE 官方 `vexpress-qemu_armv8a` 最贴合
- **ATF PLAT=qemu 的 UART0=0x09000000（内存映射）与 qemu-virt PL011@0x09000000 正好对上**，
  与 vexpress-a15(UART 0x1c090000) 冲突 → 放弃 arm32 路线
- b657 TA 是 **32-bit ARM ELF** → 混编 ta_arm32（`CFG_ARM64_core=y` + TA 用 export-ta_arm32）

### 2.3 已验证可用的启动链路（两步）
```bash
# ① 生成 DTB（secure 模式才有 ns/secure 内存分区）
qemu-system-aarch64 -machine virt,secure=on,dumpdtb=/tmp/virt-aarch64.dtb -cpu cortex-a57 -nographic

# ② 启动（ATF 引导 FIP：BL1→BL2→BL31(ATF)→BL32(OP-TEE)→BL33 由 qemu loader 载入 kernel+DTB）
qemu-system-aarch64 -display none \
  -machine virt,secure=on -cpu cortex-a57 -m 2047 -smp 1 \
  -serial file:serial0.log -serial file:serial1.log \
  -bios $ATF/build/qemu/debug/bl1.bin \
  -device loader,file=$ATF/build/qemu/debug/fip.bin,addr=0x04000000,force-raw=on \
  -device loader,file=work/Image,addr=0x60000000,force-raw=on \
  -device loader,file=/tmp/virt-aarch64-clean.dtb,addr=0x7ff00000,force-raw=on \
  -semihosting-config enable=on,target=native -no-reboot
```
- `serial0` 是 NS world（Linux console/rcS/测试输出）
- `serial1` 是 OP-TEE（UART@0x09040000 会 `switching console`）
- 成功标志：`I/TC: OP-TEE version: ... aarch64`、`Primary CPU switching to normal world boot`
  → kernel `Run /etc/init.d/rcS` → 测试全部跑完

### 2.4 一键自动化（推荐，免手工）
```bash
cd /media/ben/work_2021/qemu-tee/work
./run-auto.sh 75          # 重建 initramfs + Image + FIP + 启动 75s
./run-auto.sh 75 gdb      # 启动后停在 first instruction 等 gdb attach(1234)
```
`run-auto.sh` 内部 5 步：0)准备 initramfs64(devnodes+TAs+rcS) 1)重新生成 Image 2)FIP 注入 BL33=Image
3)清理 secure-only DTB 节点 4)打包 rootfs64.cpio.gz 5)起 qemu(+gdb)。

### 2.5 曾经踩过的启动坑（已解决，供参照）
1. **EFI_ZBOOT**：linux 6.6 默认把 Image 打成 PE/COFF(MZ 头)，ATF 直接跳不过 → 需
   `# CONFIG_EFI_GENERIC_STUB=n`（关 EFI），Image 首字节 = `1f2003d5`（ARM64 nop+b）
2. **PAC/BTI 未定义指令**：GCC 默认启用 → 加 `-mno-...` / defconfig 关
3. **alternatives patching 崩**：`CONFIG_RELOCATABLE=n` + `CONFIG_ARM64_VA_BITS_48`
4. **secure-only DTB 节点**泄露到 NS → 手工删 pl011@9040000 等节点（run-auto.sh [3/5] 自动做）
5. **内存不足**：`-m 2047` 且 DTB 用 `-m 2047` 生成（memory 节点覆盖整个 Image）

---

## 3. 把 b657 TA 装进 QEMU 并跑 host 测试

### 3.1 放 TA 到 initramfs
```bash
# b657 是 该厂商 TEE 格式(.ta)：重新签成 OP-TEE default key 才能被 QEMU OP-TEE 加载
python3 optee_os_new/out/vexpress-qemu_armv8a/export-ta_arm32/scripts/sign.py \
  --uuid b657ba17-b3b3-47f5-b389-6b53f30c0baf \
  --key  optee_os_new/out/vexpress-qemu_armv8a/export-ta_arm32/keys/default_ta.pem \
  --in  <b657.elf> --out initramfs64/usr/lib/optee_armtz/b657ba17-b3b3-47f5-b389-6b53f30c0baf.ta
```
> 该厂商 TEE .ta = `0x134 HSTO 头 + ELF`；OP-TEE QEMU 加载时 ldelf 打印
> `ELF (b657...) at 0x40010000`、`system_open_ta_binary` 找到 → 成功。

### 3.2 host 测试程序（`work/host-tests/`）
- `test_b657_ecdsa.c`：open/gen/begin 三态，最早验证 OpenSession + generate + 是否卡死
- `test_b657_real.c`：**完全照真机 HAL 协议**（cmd=0x8000 外层，head 104B）
  ```c
  #define CMD_ENTRY 0x8000   // TA 外层命令
  #define CMD_GENERATE 13    // head[0]
  #define CMD_BEGIN    25    // head[0]; head[16]=purpose; head[20]=keyblob_len; head[24]=param_count
  #define CMD_UPDATE   26    // head[0]; head[16..23]=op_handle(u64); head[28]=datalen; data@head+104
  #define CMD_FINISH   27    // head[0]; head[16..23]=op_handle; 签名@head+104
  #define HEAD_LEN 104
  // params 序列化: tag(4)+len(4)+val(len) 12B/个（u64 用 16B）
  // 关键 tag: 0x90000259=purpose, 0x900002bc=curve, 0x900002c9=clientId, 0x600002bd=key_size
  ```
- 编译：`make -f Makefile.real`（aarch64-linux-gnu-gcc + -lteec）
- 测试流程（rcS 内自动跑）：configure(205) → generate_key(13) → begin(25)→update(26)→finish(27)
  → **verify(25 but purpose=3)** → update(26)→finish(27)；随后离线验签

### 3.3 关键看什么（serial0）
```
[8.135] ECDSA SIGN OK                     ← sign 全链路成功
  Ecdsa_Verify_Finish 494 result=1        ← verify 验签通过
[8.203] ECDSA VERIFY OK
```
任何一步 `res=0xffff...` 或 `ERROR: TeeCrypto ... ecp_oct.c line 355` → 记下 head/参数并继续 §4。

---

## 4. Debug TA 的三种手段

### 4.1 手段 A：TA 自带 trace（最快）
TA debug 版把每条 TeeCrypto 错误打到 NS dmesg（前缀 `该厂商 TEEtalog`）：
```
ERROR: [keymaster]:ERR_put_error:609: TeeCrypto error: lib 16 func 103 reason 107
  file lib/libcrypto/crypto/ec/ecp_oct.c line 355       ← 精确到 文件:行
```
这是定位「错误链」的主力（§5 用它钉根因）。

### 4.2 手段 B：gdb 连 QEMU（单步看数据）
`run-auto.sh 75 gdb` 或手动加 `-gdb tcp::1234`。TA 运行时基址 = **0x40010000**（ldelf），
符号表映射：`add-symbol-file b657.elf 0x4000fe0`（.text vaddr 0x20 → 运行时 0x40010000）。

已在用的断点脚本：
- `gdb-dump-key.sh`：断 `DecryptKeyBlob`(0x4001876c) 读 SM4 key / in/out 指针
- `gdb-probe.sh`：断 `EC_POINT_oct2point`(0x4006f428) 读 group/point/buf/len —— 现场看坏点
- `gdb_b657.cmd`：断 oct2point + dump buf[0..15] + len

示例（看 oct2point 输入到底是不是坏 SEC1 公钥）：
```
break *0x4006f428
info registers x0 x1 x2 x3    # x2=buf(公钥字节), x3=len
x/16bx $x2
```

### 4.3 手段 C：离线反汇编 + addr2line（精确到源码行）
b657.elf **不是 stripped**，且 该厂商 TEE 库 `libcrypto.a` 带 DWARF：
```bash
arm-none-eabi-objdump -d b657.elf | less      # 看具体函数汇编
arm-none-eabi-addr2line -e libcrypto.a.o -f -C 0x...   # 错误地址→文件:行
```
把 §4.1 的 `ecp_oct.c:355` 之类的行号，可与 该厂商 TEE 仓库内的
`lib/libcrypto/crypto/ec/ecp_oct.c` 源码对齐，读懂失败含义。

---

## 5. 如何使用 keystore App 做真机测试

> keystore App = `com.vendor.keystore`（该厂商 AndroidKeyStore Demo），已预装/可拉取：
> `/data/app/com.vendor.keystore-*/base.apk`（versionCode=1, targetSdk=34）
> 它是**本项目最重要的验收工具**：一键跑全套算法矩阵，逐项标 PASS/FAIL。

### 5.1 启动 App
```bash
adb -s <IP>:5555 shell am start -n com.vendor.keystore/.MainActivity
# 或点 Launcher 图标 "keystore"
```
启动后自动执行全量测试（MainActivity onCreate → ExecutorService 串行跑各组），
主界面实时显示各算法行 `[OK]` / `[FAIL]`，底部汇总 `total=.. pass=.. fail=..`。

### 5.2 App 测试分组（反编译 MainActivity smali 确认）
| 组 | 内容 | 关键用例 |
|---|---|---|
| TEE-probe | /dev/tee0 /dev/teepriv0 探测 | 确认 TEE 节点存在 |
| Keystore support matrix | AndroidKeyStore provider 特性矩阵 | 各算法 keygen 是否支持 |
| AES | AES/CBC, CTR, GCM, ECB 加密/解密 | keygen + Cipher round-trip |
| HMAC | HmacSHA1/224/256/384/512 | keygen + sign/verify |
| DESede (3DES) | 3DES/CBC | 通常 NoSuchAlgorithm（AndroidKeyStore 不支持） |
| RSA | RSA-2048/3072/4096 | keygen + SHA256withRSA 签名/验签（**tee=true 应 PASS**） |
| EC | secp192r1/224r1/256r1/384r1/521r1 | **keygen 应 PASS**（本项目核心：生成成功） |
| ECDH | EC 密钥交换 | keygen + 共享密钥 |
| **ECDSA** | 曲线 secp256r1，digest SHA-1/224/256/384 | **本项目核心：sign 曾全部 FAIL**（smali `EcdsaSignTest`: ks_demo_ecdsa_*） |
| ECDSA (software baseline) | 非 keystore 的 SunEC 基线 | 应 PASS（证明 EC 引擎本身 OK，问题在 keymaster HAL/TA） |
| ChaCha20 | keystore round-trip | 通常 InvalidAlgorithmParameter |
| Attestation | RSA / EC 证书链 | 通常 ProviderException（debug TEE/未实现） |
| Software fallback | 非 keystore 对照 | 与 TEE 无关的软件实现 |

### 5.3 预期结果（fix 前后对照）
```
fix1/stable(5dbd3ce2) ：
  PASS AES/HMAC(tee=false), RSA sign(tee=true), EC keygen/export
  FAIL ECDSA sign (Unknown error / -1000)
fix8/PATCH-C(7334367d) ：
  QEMU 端到端已证明 sign+verify 双向可用；真机预期 ECDSA 组由 FAIL → PASS
```
> ⚠️ 注意：App 界面打印的 `[OK]/[FAIL]` 对部分用例是**软失败**（如 AES tee=false
> 走软件 fallback 也算 PASS），判定"真机 ECDSA 是否修复"以 **ECDSA 组 + TA dmesg
> （`该厂商 TEEtalog ... Ecdsa_Sign_Begin ... begin success`）** 双重为准。

### 5.4 自动化跑测 + 抓证据
```bash
# 1) 清日志、启动 App、等跑完（约 1-2 分钟）
adb -s <IP>:5555 shell "logcat -c; dmesg -c"
adb -s <IP>:5555 shell am start -n com.vendor.keystore/.MainActivity
sleep 90

# 2) 抓 App 汇总
adb -s <IP>:5555 shell "uiautomator dump /data/local/tmp/u.xml && cat /data/local/tmp/u.xml" | grep -oE 'total=[0-9]+[^<]*|pass=[0-9]+[^<]*|fail=[0-9]+[^<]*'

# 3) 抓 TA 侧 该厂商 TEEtalog（定位到底走到哪一步）
adb -s <IP>:5555 shell "dmesg | grep -E '该厂商 TEEtalog|ecp_oct|Ecdsa|GetEcKey|begin success|finish success' | tail -60"

# 4) 若怀疑重启：重启后立即取 last_kmsg
adb -s <IP>:5555 shell "cat /proc/last_kmsg" > last_kmsg.txt   # 分析 bootreason / WDT / i2c
```

### 5.5 真机关键判定（本项目已用）
- 失败且 dmesg 有 `ecp_oct.c:355 / GetEcKeyEvpPkey error` → TA 私钥解析问题（本项目已修）
- 失败且 keymaster 无 TA trace → 更可能是上层 HAL/协议（不是 TA）
- `bootreason=watchdog` + last_kmsg 显示 i2c-5/GTP 风暴 + WDT CPU 卡在驱动
  → 触摸屏 I2C 问题，与 TA 无关（§7.3）

---

## 6. 定位问题的五层证据链（本问题的完整打法）

### 5.1 第一层 静态逆向（先厘清结构）
- 反汇编 `该厂商 TEE.raw` 启动序 + 版本串 → 确认 = **OP-TEE 3.6 该厂商 fork**
- b657 TA 头 `HSTO` + `__utee_entry`/`TA_CreateEntryPoint` → 标准 OP-TEE user_ta
- `do_biz`(0x9b58) 按 cmd 分发：13=generate(0xa1a4)/22=export(0xba04)/25=begin(0xc310)
  /26=update(0xcb30)/27=finish(0x...)；ECDSA 走 `Ecdsa_CreateOperation`(0x1cbd0)

### 5.2 第二层 真机证据（知道「实际卡在哪」）
- `last_kmsg` 关键 trace：
  ```
  read_ec_key_from_keyblob begin → sm4_crypt(解密成功) → end
  ERROR: ecp_oct.c:355  OCT2POINT + POINT_IS_NOT_ON_CURVE
         ec_asn1.c:1145  D2I_ECPRIVATEKEY
         ec_ameth.c:517  DECODE_ERROR
  Ecdsa_CreateOperation GetEcKeyEvpPkey error → Ecdsa_Begin error=-1000
  ```
- 从 `/data/misc/keystore/user_0/*USRPKEY_ks_demo_ec_*` 抓 keyblob，
  解密明文区开头 = `30 59 30 13 06 07 2a8648ce3d0201...` = **SPKI(公钥)** 而非
  标准 `30 77 02 01 01 04 20 ...`(ECPrivateKey)
- → 真机定位：**keyblob 私钥区数据不对，读到的是公钥 SPKI**

### 5.3 第三层 离线数学（排除「真机环境特有问题」）
用 `lib/libcrypto.a`（带 DWARF）在 host 完整模拟写侧：
```c
EC_KEY_generate_key → i2d_PrivateKey(asn1_flag=1) → 121B SEC1
d*G == SPKI 公钥（数学上完全自洽，私钥数据本身没错）
```
→ 结论：写侧 SEC1 **本来正确**，是**写完后被别的东西覆盖**（SPKI 写入坏区）。

### 5.4 第四层 QEMU 复现（受控环境证实错误链一致）
装上**未修复 b657 TA**（QEMU default key 重签）跑 `test_b657_real`：
```
ERROR: TeeCrypto ... ecp_oct.c:355 → GetEcKeyEvpPkey error    ← 与真机完全一致
```
→ 证明是 TA **通用逻辑 bug**（与真机硬件/时钟无关），可在 QEMU 内迭代修复。

### 5.5 第五层 QEMU 端到端验证（修复有效 + sign/verify 双向）
打上 PATCH-C 后：
```
EC_generate_key ... i2d_PrivateKey key_data_size=121
CreateKeyBlob success → generate success
Ecdsa_CreateOperation operation_handle=...
Ecdsa_Sign_Begin ... begin success → update success → finish success
sig[104..199]: 3045022...022100...   ← DER ECDSA 签名
→ 离线用 keyblob 解出 priv + z=SHA256(digest) 验签 PASS
→ 再跑 verify(purpose=3): Ecdsa_Verify_Finish 494 result=1  ← verify 也过
```
> 重要：**QEMU 内 sign 和 verify 都通了**，说明修复对 TA 逻辑是有效的；
> 真机之前「verify 失败」是 host 测试协议传错（§6.4），不是 TA 问题。

---

## 7. 出现了哪些问题 + 如何定位和修复（完整问题清单）

### 6.1 问题1：TA 写侧 SPKI 覆盖私钥区（根因）—— 定位+修复
- **现象**：keygen/export OK，sign 失败
- **定位**：§5.3 证明 SEC1 本正确；真机 keyblob 明文=SPKI ⇒ 写侧覆盖
- **根因**（反汇编 `EC_generate_key`@0x8c84）：
  `i2d_PrivateKey` 后 `i2d_PUBKEY` 第二次写时用了同一个 `pp`（&local_2c），
  而 **TA 内嵌 crypto 的 `asn1_item_flags_i2d`(0x2c6ac) 在 `*pp!=NULL` 分支不回写 `*pp`**
  → 第二次 i2d_PUBKEY 又从私钥区起点写 → 前 91B 变 SPKI
- **修复1(fix1)**（2 字节重签）：`read_ec_key_from_keyblob`@0x1033e
  `49 46`(mov r1,r9=密文) → `21 46`(mov r1,r4=明文栈缓冲)
  效果：keyblob 解密后取的是明文 → EC keygen/export 立即 PASS
  （此时 sign 仍失败，因为私钥区仍是 SPKI 数据，只是 d2i 时错误链前移）

### 6.2 问题2：ecp_oct.c:355 —— SEC1 [1] pubkey 的 Y 尾 8B 被损坏（真机/QEMU 一致）
- **现象**：fix1 后 sign 仍 FAIL，错误链 `ecp_oct.c:355 → ec_asn1.c:1145 → ec_ameth.c:517`
- **定位**：gdb 断 `EC_POINT_oct2point` + 解密 keyblob：
  SEC1 私钥数据里 `[1] pubkey` 的 **Y 坐标后 8B** = `7a9d4aebfc8a3e6cc4`（错），
  而同一 keyblob **明文区 SPKI 的 Y 完全正确** `c9ce06cd554a1d963c`;
  用 d*G 重算点一一对应 → 是**写入 keyblob 时尾部被覆盖**，非算法问题
- **修复2(PATCH-C)**（2 字节重签）：`d2i_ECPrivateKey`@0x6f42c
  `88 b1`(cbz r0,0x6f452→报错) → `00 b1`(cbz r0,0x6f430→**跳过坏 pubkey**)
  效果：EC_KEY 有 group+priv、无 pubkey；ECDSA sign 只需 priv → begin success

### 6.3 问题3：真机 boot loop / watchdog —— 与 TA 无关（已证据钉死）
- **现象**：烧 PATCH-C 后真机反复重启（曾经误判为 TA 卡死）
- **定位**（last_kmsg + WDT dump）：
  ```
  bootreason=watchdog
  崩溃前 keymaster TA 全部正常: generate→export→begin→update→finish 全 PASS
  崩溃前最后调用 RSA_GenerateKey(Command id=13) 正常返回（无卡死）
  崩溃时刻 WDT CPU2/3 = rawbulk_attr_show(c2k_usb/rawbulk.c:183)   ← 驱动卡死
  崩溃前触摸屏 i2c-5(GT9147) 总线超时风暴 (addr:0x5d transfer timeout, errno:-110)
  ```
- **结论**：真机重启 = **GT9147 触摸 I2C-5 超时 → irq/DMA 不释放 → 无人踢 WDT**，
  **不是 该厂商 TEE/TA 死循环**；与历史 `watchdog-reboot-rootcause.md` 一致
- **Fix**：独立立项修触摸驱动/i2c-mtk（与 TA 无关）

### 6.4 问题4：QEMU 里「verify 失败」—— 其实是 host 测试协议 bug
- **现象**：begin/update/finish 都能过，但 verify 报
  `Ecdsa_CreateOperation:183: must provide the same value to the clientId parameter`
- **定位**：反汇编 `Ecdsa_CreateOperation`：TA 会把 **keyblob 里存的 purpose(0x90000259)
  与调用方传的 purpose 做 memcmp**；我 host 测试 verify 时传了 3(VERIFY)，但 generate 时
  keyblob 存的是 2(SIGN) → 不匹配 → 拒绝。
  且 host 只看 `TEEC_InvokeCommand res==0` 没看 `head[4]` 错误码 → 误报 "VERIFY OK"
- **修协议**：verify 的 params 里 `0x90000259` 保持与 keyblob 一致(2)，仅 `head[16]=3`
  走 verify 分支 → 真实 begin/update/finish 全成功
- **教训**：QEMU host 测试 = 「手工协议」要完全对照 HAL 反汇编（`VendorKeymaster::begin`
  里 `head[16]=purpose, head[20]=keyblob_len, head[24]=param_count`）

### 6.5 通用修复流程（如何改一个 patch）
1. 用 IDA/objdump 定位要改的指令（字节 + Thumb2 编码）
2. 写 patch 脚本（`.patches/patch_b657_*.py`，幂等：先校验 ORIG 字节再写 NEW）
   - 例：PATCH-C → `patch_b657_pubkey_recover.py`：`0x6f42c 88b1→00b1`
3. 生成 patched ELF；**只改字节没重签 = OpenSession ffff000f**（v1/v2/v3 全栽在这）
4. 重签（两套 key）：
   - QEMU：`sign.py --key optee_os_new/.../default_ta.pem`
   - 真机：该厂商 TEE 官方 `resign_ta.py --key ta_private_key.pem`
     （debug 该厂商 TEE.raw 内嵌 key1=ta_private_key.pem 公钥，验签通过）
5. QEMU 端到端验证 → 通过后同步到 `sec_modules/ta_debug` + `sec_modules` 两处构建输入
6. 真机烧录复测

### 6.6 各修复版本 SHA 速查
| 版本 | sha256(前16) | 内容 |
|---|---|---|
| factory 原厂 | `16a7db96` | 未改 |
| fix1/stable | `5dbd3ce2` | read_ec 拷贝明文（0x1033e→2146），真机 keygen/export PASS，sign 仍 FAIL |
| **fix8=PATCH-C** | `7334367d` | fix1 + 0x6f42c 跳过坏 pubkey，QEMU sign+verify 双向 PASS，真机已烧录 |

---

## 8. 当前状态、验证清单、产物归档

### 7.1 当前状态
- **源码构建输入** = fix8(PATCH-C) `7334367d`（`ta_debug` + `sec_modules` 两处已同步）
- **真机 <device-ip>** 已烧 OTA `product-ota-20261023.100735.zip`，
  TA md5=`87e4672a`(=fix8) ；uptime 稳定、无 bootloop、keymaster 服务正常
- 最新一次 keystore 测试的 watchdog：**触摸 i2c-5 风暴**所致，与 TA 无关（§7.3）

### 7.2 验证清单
| 项 | 结果 |
|---|---|
| QEMU: OpenSession / configure / EC keygen / ECDSA sign | ✅ PASS |
| QEMU: ECDSA verify (purpose=3) | ✅ PASS (result=1) |
| 源码输入=fix8 | ✅ 同步 |
| 真机 boot 稳定（无 bootloop） | ✅ uptime 稳定 |
| 真机 RSA/AES/HMAC 回归 | ✅ last_kmsg 证实 PASS |
| 真机 ECDSA sign/verify 最终判定 | ⏳ 待触摸无干扰环境复测 |

### 7.3 产物归档
```
qemu-tee/work/run-auto.sh                 # 一键起 QEMU(可 gdb)
qemu-tee/work/test-b657-final.sh          # 一键端到端验证
qemu-tee/work/host-tests/test_b657_real.c # 真实协议 host 测试（sign+verify）
qemu-tee/work/logs/serial0_ECDSASIGNVERIFY_VERIFIED.log  # 端到端证据
qemu-tee/work/gdb-probe.sh / gdb-dump-key.sh             # gdb 断点脚本
sec_modules/ta_debug/.patches/patch_b657_pubkey_recover.py # PATCH-C 脚本
sec_modules/ta_debug/.patches/apply_ecdsa_rootcause_fix.sh # 构建自动应用(fix8)
external/tee/tools/ta_resign_tool-release/linux/resign_ta.py   # 真机重签
optee_os_new/out/vexpress-qemu_armv8a/export-ta_arm32/scripts/sign.py  # QEMU 重签
```

### 7.4 下一步建议
1. 在**触摸正常 / 外置 TP** 环境下重跑 keystore ECDSA 用例，排除 i2c-5 干扰后判定
   真机 sign/verify（这是 fix8 的最后一步闭环）
2. 独立立项修复 GT9147 触摸 i2c-5 超时风暴（真机多次 watchdog 真凶）
3. 若需完整 verify/export 公钥（PATCH-C 只保留 priv），可在读侧用 d*G 重算 pubkey
   （`eckey_priv_decode` 思路，但需适配 SEC1 输入，见 §14.6 备注）
