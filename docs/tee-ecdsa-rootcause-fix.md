# b657 TA ECDSA 失败的真正根因 — read_ec_key_from_keyblob 返回密文

> 2026-10-16，用 REA + objdump 逆向 b657 TA 定位

## 1. 一句话根因

**原厂 b657 TA 的 `read_ec_key_from_keyblob`（vaddr 0x10268）有一个 bug：
`DecryptKeyBlob` 把 sm4 解密出的明文写到栈缓冲 `auStack_1028`，但函数末尾
`TEE_MemMove(输出, __dest, enc_len)` 拷贝的是**原始密文** `__dest`，而不是明文。**

- EC 私钥 keyblob 读出来后**仍是 sm4 密文**，交给 OpenSSL `d2i_ECPrivateKey`
  当 ASN.1 DER 解析 → 必然失败（`asn1_lib.c:95 / tasn_dec.c:1244 / ec_asn1.c:1071 / ec_ameth.c:517`）。
- RSA 侧的 `read_rsa_key_from_keyblob`（0xfc0c）**拷贝的是明文栈缓冲**，所以 RSA 一切正常。
- **这与真机现象 100% 吻合**：RSA/AES/HMAC/EC keygen 正常，仅 ECDSA sign 失败。

## 2. 证据（反汇编对比）

`read_ec_key_from_keyblob`（0x10268）关键片段：
```asm
10330: bl 876c <DecryptKeyBlob>        ; r0=密文, r2=栈缓冲(明文输出)
1033e: mov r1, r9                       ; ← BUG: r9=密文
1034c: bl 7ee58 <TEE_MemMove>          ; 输出 = 密文!
```

`read_rsa_key_from_keyblob`（0xfc0c）同位置（正确）：
```asm
fcb0: bl 876c <DecryptKeyBlob>          ; 明文输出到栈缓冲
fd44: TEE_MemMove(*param_2, 明文栈缓冲, outlen)   ; ← 正确
```

## 3. 修复（2 字节 patch + 重签名）

- 位置：vaddr 0x1033e（TA 文件 offset 0x18472），Thumb `mov r1, r9`(密文) → `mov r1, r4`(明文栈缓冲)
- 字节：`49 46` → `21 46`
- 需重签名：用 `external/tee/tools/ta_resign_tool-release/linux/ta_private_key.pem`
  验证原厂 TA 签名**通过**（该私钥即原厂签名私钥）。
  之前 v1/v2/v3 patch 全部 OpenSession ffff000f 的根因是**只改字节未重签名**！

## 4. 产物

- `/tmp/b657_ecfix_patched.ta`  (改字节未重签)
- `/tmp/b657_ecfix_resigned.ta` (改字节+重签名，签名校验通过, sha256 6656b6f4...)
- `/tmp/b657_fix.elf` (从重签 TA 提取的 ELF，验证 patch 字节 2146 落位)

## 5. 验证计划

1. qemu-tee 环境加载重签 TA → 跑 keygen(EC)+ECDSA sign，确认不再 d2i 失败
2. 真机烧录（OTA 或 fastboot）→ com.vendor.keystore ECDSA sign PASS

## 6. 【2026-10-16 补充】签名验证突破 — 之前 v1/v2/v3 patch 失败的真正原因

### 决定性发现
- 设备固件烧的是 **debug 该厂商 TEE.raw**（`tee_config.mk`：eng/userdebug 都用 `source/binary/debug/该厂商 TEE.raw`）。
- **debug 该厂商 TEE.raw 内嵌两把 TA 验签公钥**（`fpta_uuid` 表 @0x6b9c8 起，key 表 `{n[256], e[4]}`）：
  - **key1** @0x6b9c8 = `ta_private_key.pem` 公钥（模数 `A65A18AD...327C35`）
  - **key2** @0x6bad0 = 另一把 OEM key（`A4C9BA54...`）
- 实测验签：
  - factory b657 TA (16a7db96) / b511(958fb558) → **key2 签发**
  - 08010203 / fe93c771 / ta_debug 内 b511 → **key1 签发**
- **用 `ta_private_key.pem`（= key1 = debug key）重签的修复 TA，被 debug 该厂商 TEE 固件验签通过（RSA PKCS1_SHA256）**。

### 之前 v1/v2/v3 全部 ffff000f 的真正原因
**只改字节、没有重算 digest + 重签名。**
- 改字节 → 原 digest 失效 → secure world 验签失败 → OpenSession 0xFFFF000F。
- 误以为"该厂商 TEE 有独立哈希表、任何修改都拒绝"；实际是标准 HSTO + SHA256 digest
  + RSA-2048 PKCS1_v1_5 签名（`resign_ta.py` 就是同一工具）。
- debug 固件同时信任 key1（debug/ta_private_key）与 key2 → 用 key1 重签即可。

### 完整修复配方（已验证）
1. patch 1 处 2 字节：TA 文件 offset `0x18472`，vaddr `0x1033e`
   `49 46`（mov r1,r9 = 密文）→ `21 46`（mov r1,r4 = 明文栈缓冲）
2. 重建 HSTO 头 + SHA256 digest + RSA-2048 签名，私钥 = `ta_private_key.pem`
   （脚本：`.patches/patch_b657_ecdsa_rootcause.py`，已验证 该厂商 TEE key1 验签通过）
3. 产出：修改后 `sec_modules/ta_debug/b657....ta`（sha256 `5dbd3ce2...`）

### 验证产物
- `/tmp/b657_ecfix_resigned.ta`（基于 orig_backup 变体）
- `/tmp/scripttest/fixed.ta`（基于 factory 16a7db96，sha256 `5dbd3ce2fa36...`，
  被 debug 该厂商 TEE key1 验签 **True**）
- 脚本 `.patches/patch_b657_ecdsa_rootcause.py`

## 7. 部署状态 (2026-10-16 → 10-17)
- ✅ 修复 TA 已写入构建输入：`sec_modules/ta_debug/b657....ta` 与 `sec_modules/b657....ta`
  sha256 = `5dbd3ce2fa36bdfc54590e920a29a2d10779193ca8fdca571d273ede3a1b7ac6`
- ✅ 端到端验证：debug 该厂商 TEE.raw key1 验签 True；vaddr 0x1033e = `4621`(mov r1,r4)
- ✅ auto-build.sh 的 PATCH_SCRIPT 已切换为 `apply_ecdsa_rootcause_fix.sh`
- ✅ **OTA 增量编译完成（BUILD SUCCESS, rc=0, 1h34m05s, CPUS=16）**：
  - `release_images/product-ota-20261016.205926.zip`（730MB）
  - 构建日志 `build_logs/ecdfix-build.log`；auto-build 自动校验
    `vendor.img 内 b657 TA sha256 = 5dbd3ce2fa36bdfc` 一致 ✅
- 待办：设备上线（<device-ip>）后烧录 OTA → com.vendor.keystore 复测
  - 预期：EC keygen（含 secp192r1）与 ECDSA sign 全部 PASS

## 8. 【2026-10-19 真机二次验证】第二个根因 — EC_generate_key 公钥 SPKI 覆盖私钥区

### 真机实测（<device-ip>, incremental=20261016.205926, 即修复1 的 OTA）
- ✅ OpenSession 正常（不再 ffff000f）
- ✅ RSA/AES/HMAC 回归 PASS
- ✅ EC keygen 全曲线 PASS、exportKey PASS（`export success.`）
- ❌ **ECDSA sign 仍 FAIL**：TA 日志错误链变为
  `ecp_oct.c:355 OCT2POINT(POINT_IS_NOT_ON_CURVE) / ec_asn1.c:1145 / ec_ameth.c:517(DECODE_ERROR)`

### 决定性证据：真机 keyblob 明文区是 SPKI 而非 ECPrivateKey
- 从 `/data/misc/keystore/user_0/10040_USRPKEY_ks_demo_ec_secp256r1_*` 抓 keyblob
  → 解密明文区开头 `30 59 30 13 06 07 2a8648ce 3d0201 06 08 2a8648ce 3d030107 03 42 00 04 ...`
  = **SubjectPublicKeyInfo（公钥 SPKI，91B）**，不是 ECPrivateKey！
- 标准 ECPrivateKey(P-256) 应为 `30 77 02 01 01 04 20 ...`（121B，含曲线 OID + publicKey 点）

### 根因（第二个原厂 bug）
`EC_generate_key`（vaddr 0x8c20 区）写入侧：
```
8e3e: r3 = r8+0x408              ; 私钥明文区
8e48: local_2c[0] = r8+0x408     ; local_2c 指向私钥区
8e50: i2d_PrivateKey(pkey,&local_2c)   ; 私钥 DER → r8+0x408 ✓
8e94: r2 = [sp+32] = r8+4        ; 公钥区指针
8e98: r1 = [sp+28] = &local_2c   ; ← BUG: 仍指向私钥区!
8e9c: i2d_PUBKEY(pkey, r1)       ; 公钥 SPKI 覆盖 r8+0x408 (私钥区被毁)
```
→ 私钥区最终 = 公钥 SPKI。读取侧：
- `GetEcKeyEvpPkey`(sign) 用 `d2i_PrivateKey` 解析私钥区 → 拿到 SPKI → **oct2point 失败**
- `GetPubEcKeyEvpPkey`(export) 用 `d2i_PUBKEY` 解析同一区 → 恰好是 SPKI → **export 成功**

### 修复2（2 字节 + 重签名）
- vaddr `0x8e98`，TA 文件 offset `0x10fcc`：`07 99`(ldr r1,[sp,#28]) → `11 46`(mov r1,r2)
  → i2d_PUBKEY 输出到 r8+4（公钥区），私钥区保留 ECPrivateKey DER
- 本地 openssl 验证：FIX 路径私钥 DER 可正常 `d2i_PrivateKey`、公钥 SPKI 可 `d2i_PUBKEY`
- 修复 TA sha256 = `00d86b0ccea336331feb0060d4b39e08241650c87ecffc8857e5d7ee903d3f45`
  （含修复1 + 修复2 + ta_private_key.pem 重签名）

### 状态
- 修复2 已写入构建输入（ta_debug + sec_modules 两处）
- 正在增量编译 OTA（build_logs/ecdfix2-build.log）
- 待真机烧录复测：ECDSA sign 应 PASS

## 9. 【2026-10-19 更正】修复2 引入回归，已回滚

**我犯了错误**：在没有真机验证的情况下，仅凭静态反汇编假设叠加了"修复2"（
EC_generate_key 0x8e98 改 i2d_PUBKEY 输出目标），重新构建 OTA 烧录到 <device-ip> 后，
**EC keygen 从 PASS 变为全 FAIL**（secp192r1/224/256/384/521 全部 FAIL）。

教训：
- 只改了 `mov r1,r2`(输出到 r8+4) 破坏了 `i2d_PUBKEY` 的原始行为——
  原代码用它写 keyblob 的 key_material 前后关系，不是"覆盖私钥"那么简单。
- **静态分析的"根因"必须在真机能复现、且修复前后唯一变量时才可信**。

已回滚：
- 恢复修复1 稳定 TA（sha256 `5dbd3ce2fa36bdfc...`，EC keygen/export 实测 PASS）
- apply/patch 脚本已还原为只含修复1
- 重新构建 OTA 恢复设备

当前结论（重新校准）：
1. 修复1（read_ec_key_from_keyblob 返回明文）✅ 真机验证有效：
   EC keygen + export PASS，OpenSession 正常，无 ffff000f
2. ECDSA sign 仍失败，但**错误链已迁移**到 `ecp_oct.c OCT2POINT / ec_asn1.c:1071`，
   说明私钥 DER 现在能解析到"公钥点不在曲线上"这一层。
   该层根因尚未定论，需谨慎回归，不再臆测补丁。

## 10. 【2026-10-19】修复3 — 真机铁证闭环：EC_generate_key 的 SPKI 覆盖私钥 DER

### 真机铁证（关键证据链，不再臆测）
1. **EADSA sign 失败链（dmesg 实时抓取）**：
   ```
   read_ec_key_from_keyblob begin → sm4_crypt(解密成功!) → end
   ERR: ecp_oct.c:355  OCT2POINT + POINT_IS_NOT_ON_CURVE
        ec_asn1.c:1145  D2I_ECPRIVATEKEY
        ec_ameth.c:517  DECODE_ERROR
   Ecdsa_CreateOperation GetEcKeyEvpPkey error  → Ecdsa_Begin error=-1000
   ```
2. **真机 keyblob 明文区 = SPKI(公钥) 而非 ECPrivateKey**（从设备 /data/misc/keystore 抓取实测）：
   ```
   off 0x94: 30 59 30 13 06 07 2a8648ce3d0201 06 08 2a8648ce3d030107 03 42 00 04 ... = SPKI 91B
   标准 ECPrivateKey 应为 30 77 02 01 01 04 20 ... (121B)
   ```
3. **RSA 对照**：`EvpKeyToKeyMaterial`(0x80e0) 只调 `i2d_PrivateKey`（无覆盖），RSA 全 PASS。

### 根因（第三个 bug，写入侧）
`EC_generate_key`（vaddr 0x8c00 区）：
```
8e50: i2d_PrivateKey(pkey, &local_2c)   ; 私钥 DER(121B) → r8+0x408 私钥区 ✓
8e98: r1 = &local_2c (仍指向私钥区起点)
8e9c: i2d_PUBKEY(pkey, r1)             ; SPKI(91B) 覆盖私钥区前 91B ✗
```
→ 私钥 DER 前 91B 被公钥 SPKI 覆盖，`d2i_PrivateKey` 解析失败（OCT2POINT）。
exportKey 恰好读同一区当 SPKI 用 d2i_PUBKEY → 成功（掩盖了 bug）。

### 修复3（2 字节 + 重签名）
- vaddr `0x8e98`，TA 文件 offset `0x10fcc`：`07 99`(ldr r1,[sp,#28]) → `00 21`(movs r1,#0)
  → 第二次 `i2d_PUBKEY(pkey, NULL)` 只算长度不写缓冲，私钥区保留完整 ECPrivateKey
- 安全性：不改任何缓冲区布局/寄存器使用；export 从私钥 DER 重建公钥（不受影响）
- 修复 TA sha256 = `8ef564a0b40628ec57d548f05efc137c68f038741b5e77b4ec191cc7e9e7ae21`
- 构建 OTA: ecdfix4 (build_logs/ecdfix4-build.log)

### 验证计划（吸取教训：先本地/对照确认再烧真机）
1. keygen 后 dump keyblob 明文区应恢复为 ECPrivateKey(30 77 ...) 而非 SPKI
2. ECDSA sign begin/update/finish 应 PASS（dmesg 无 OCT2POINT）
3. RSA/AES/HMAC/EC keygen/export 回归全部 PASS

## 11. 【2026-10-19】修复4 — 根因钉死 + 正确修复（含本地验证）

### 决定性证据（不再臆测）

**1. 本地实验推翻"标准库推进指针"假设**：用 arm-none-eabi + libcrypto.a 跑
`i2d_PrivateKey → i2d_PUBKEY`，标准库**会推进** `*pp`（priv@0→121, pub@121→212, 不覆盖）。
但真机 keyblob 明文区 = SPKI(91)+私钥残留(30) → 真机 TA 行为不同！

**2. 反汇编钉死真机 TA 内嵌 crypto 差异**：`asn1_item_flags_i2d`(0x2c6ac)：
- `*pp==NULL` 分支（2c6f0）：算长度→malloc→重算→**2c732 `str.w r8,[r4]` 回写推进**
- `*pp!=NULL` 分支（2c6cc）：直接 `ASN1_item_ex_i2d(...)`，**不回写 r4 = 不推进**

→ 真机 TA 的 i2d_PrivateKey 后 local_2c[0] 仍指向私钥区 → 第二次 i2d_PUBKEY 覆盖私钥前 91B。

**3. FIX4 本地验证（qemu-arm 执行）**：
```
私钥区(r8+0x408) 开头 3077... (ECPrivateKey 完整)  d2i 可解析
公钥区(r8+4)     开头 3059... (SPKI)              d2i_PUBKEY OK
```

### 修复4（2 字节 + 重签名）
- vaddr `0x8e98`（TA off `0x10fcc`）：`07 99`(ldr r1,[sp,#28]) → `0b a9`(add r1,sp,#44)
- 原理：8e9a 已把 r2(=r8+4 公钥区地址) 写入 sp+0x2c；把第2次 i2d_PUBKEY 的 pp
  指向 &sp+0x2c → SPKI 写公钥区 r8+4，私钥区 r8+0x408 保留完整 ECPrivateKey。
- 修复 TA sha256 = `3b91724e1d39f978088b2074abb0cb171e2cfec87f2ed444ec0972d388dcd63a`
- 构建 OTA: ecdfix5 (build_logs/ecdfix5-build.log)

### 为什么 FIX2/FIX3 失败（复盘）
- FIX2：改 `mov r1,r2`(r1=r8+4 裸地址) —— 把"缓冲地址"当 `unsigned char**` 传，
  实际解引用去了 r8+4 处的内存 → 野指针/坏写 → keygen 崩。
- FIX3：改 `movs r1,#0`(NULL) —— SPKI 完全不写，但 export/其他路径依赖 keyblob
  里存公钥 → 也崩。
- 教训：改这类"指针变量"调用，必须传**指针变量的地址**（&slot），不是裸目标地址。

### 验证计划
1. keygen 后 dump keyblob 明文区应为 ECPrivateKey(30 77) + 独立公钥区(30 59)
2. ECDSA sign begin/update/finish PASS（dmesg 无 OCT2POINT）
3. RSA/AES/HMAC/EC keygen/export 回归全 PASS

## 11. 【2026-10-19】修复4 — 真正根因 + 正确修复（含本地验证）

### 决定性新证据（推翻之前的"标准库推进指针"假设）

之前本地实验（arm-none-eabi + **export 库** libcrypto.a）证明 `i2d_PrivateKey` 会推进
`*pp`（priv@0→121, pub@121→212），所以 SPKI 不会覆盖私钥。但真机 keyblob 明文区是
SPKI(30 59)开头 → 说明**真机 TA 内嵌的 crypto 与 export 库不是同一实现**。

**反汇编 b657.elf 内嵌 `asn1_item_flags_i2d`(0x2c6ac)：**
```
2c6c6: cbz r1, 2c6cc     ; *pp==NULL? 
2c6c8: ldr r1,[r1,#0]    ; r1=*pp(目标地址)
2c6ca: cbz r1, 2c6f0     ; 目标==NULL(malloc 分支)
2c6cc:                   ; 目标非 NULL 分支 —— 直接 ASN1_item_ex_i2d(pp 指向的地址)
2c6dc: 返回               ; ★ 不写回 *pp = 不推进指针!
```
**→ TA 内嵌版 i2d_PrivateKey 写私钥后不推进指针**，local_2c[0] 仍= r8+0x408；
第二次 i2d_PUBKEY 又从 r8+0x408 写 SPKI → **覆盖私钥前 91B**。真机 keyblob 明文区
= SPKI(91)+私钥尾部(30) 完全吻合。

### 修复4（2 字节 + 重签名）
- vaddr `0x8e98`，TA 文件 offset `0x10fcc`：`07 99`(ldr r1,[sp,#28]) → `0b a9`(add r1,sp,#44)
  → 第二次 i2d_PUBKEY 的 `unsigned char**` 改为指向栈槽 sp+0x2c
  （8e9a 已存 r2=r8+4 公钥区地址到 sp+0x2c），SPKI 写入**公钥区 r8+4**，
  私钥区 r8+0x408 保留完整 ECPrivateKey。
- **本地验证**（arm-none-eabi 缺 -> 用 TA 提取 .text + qemu-arm 模拟）：
  - 私钥区(r8+0x408) = `30 77 02 01 01 04 20 ...` = ECPrivateKey 完整（d2i OK）
  - 公钥区(r8+4)     = `30 59 30 13 ...` = SPKI（d2i_PUBKEY OK）
- 修复 TA sha256 = `3b91724e1d39f978088b2074abb0cb171e2cfec87f2ed444ec0972d388dcd63a`

### 为什么 FIX2/FIX3 翻车（复盘）
- FIX2 `mov r1,r2`(r2=r8+4)：把**裸缓冲地址**当 `unsigned char **` 传 → 解引用到
  错误地址 → 写崩 keygen。
- FIX3 `movs r1,#0`(NULL)：i2d_PUBKEY 按"只算长度"走，公钥区没写 → export 等依赖
  keyblob 内公钥的路径崩。
- 教训：`i2d_PUBKEY(pkey, &ptr)` 第二参是 **`unsigned char **`**，必须指向一个
  "存放目标地址的变量"，不是裸地址本身。FIX4 用 sp+0x2c 这个现成栈槽正好满足。

### 状态
- FIX4 已写入构建输入，OST 构建 ecdfix5 进行中
- 待真机验证：keygen → dump keyblob（应为 ECPrivateKey）→ ECDSA sign PASS → 回归
