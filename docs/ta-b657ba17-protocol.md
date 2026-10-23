# b657ba17 TA 全协议逆向规约（路线 C 地基）

> 对象：`ta_debug/b657ba17-b3b3-47f5-b389-6b53f30c0baf.ta`（keymaster4 TA）
> 入口：HAL 侧 `VendorKeymaster::begin/update/finish/...` → `TEEC_InvokeCommand(session, 0x8000, ...)`
> 输出：给新 `VendorKeymasterContext`（AOSP keymaster4 HAL + 该厂商 TEE）的实现用。

## 1. TA 命令表（cmd 值 → 处理函数，do_biz @0x9b58）

| cmd | TA handler | HAL 侧对应 | 说明 |
|-----|-----------|-----------|------|
| 13  | generate_key @0xa1a4 | generateKey | RSA/EC/AES/HMAC keygen |
| 20  | get_key_characteristics @0xac0c | getKeyCharacteristics | cmdID17 patch 生效分支 |
| 21  | import_key @0xb350 | importKey | |
| 22  | export_key @0xba04 | exportKey | 读 keyblob 并导出公钥 |
| 23  | delete_key @0xbe80 | deleteKey | |
| 25  | begin @0xc310 | begin | **keymaster 签名起点** |
| 26  | update @0xcb30 | update | |
| 27  | finish @0xd1f8 | finish | |
| 28  | Abort @0xda70 | abort | |
| 32  | get_hmac_sharingparameters @0xde6c | | |
| 33  | compute_shared_hmac @0xdf58 | | |
| 34  | verify_authorization @0xe254 | | |
| 35  | import_wrapped_key @0xe4c8 | | |
| 203 | attest_key @0xdb00 | attestKey | |
| 205 | configure @0x9fc4 | configure | |
| 601 | keybox_injection @0xdce0 | | |
| 602 | keybox_injection_check @0xdda4 | | |
| 其它 | 0xffff0006 | | 不支持 |

## 2. 命令头 wire 格式（HAL 组包）

- **104B 定长头**：`km_link_tee_head_2_buff`（0x9324）里 `TEE_MemMove(..., 104)`。
  - 头内 `offset 8` = cmd 值（`ldr r4,[sp,#8]` 后 do_biz 分发用）
  - `offset 12/16` = 后续段偏移/长度（begin 里据此取 keyblob / params）
- 头后依次拼接（begin 里 `c3b4` 附近）：key_blob（`buff_2_keymaster_key_blob` 0x939c，
  `{p,len}`）→ key_params_set（`buff_2_keymaster_key_params_set` 0x9848）。
- keyblob 结构（begin `c496`/`c4ea` 判定）：
  - `keyblob[12]` 的 u32 = type；`keyblob[0]` 前 88B = **KMKB 头**（magic `0x4b4d4b42`，
    `c512` cmp 校验），内含加密的密钥材料与 auth 参数。
  - type==2 → **read_ec_key_from_keyblob**（解密 keyblob，实测 EC 走这条路）
  - type!=2 → read_ec_key（SFS/RPMB 持久存储路径）

## 3. TA begin 内算法分派（@0xc310，`fp`=algorithm）

| fp | 算法 | 分支 | handler |
|----|------|------|---------|
| 1  | RSA   | c9a2 | Rsa 路径（GetRsaKey / Rsa_Base_CreateOperation / begin success） |
| 3  | ECDSA | c70c | Ecdsa_Begin(0x1dde0) |
| 32 | AES   | c810 | Aes 路径 |
| 33 | 3DES  | c896 | Triple_DES |
| 128| HMAC  | c91c | hmac_Begin |
| 其它 | | c5ee | trace + 0xffff0003 |

ECDSA_Begin(0x1dde0):
  purpose==2 → Ecdsa_Sign_Begin(0x1d44c)
  purpose==3 → Ecdsa_Verify_Begin(0x1d544)
  Ecdsa_Sign_Begin → Ecdsa_CreateOperation(0x1cbd0)
    → read_ec_key_from_keyblob(0x10268)         [type==2]
    → read_key_params_set_from_keyblob(0xf958)
    → add_operation → ... → EVP_DigestSignInit (TA 内 OpenSSL)

## 4. 实测运行证据（last_kmsg 2026-10-10 crash）

- EC keyblob 解密成功：`read_ec_key_from_keyblob begin → enc_len=121 →
  DecryptKeyBlob in_len=121 → sm4_crypt → out_len=121 → end → export success`。
  即 **keyblob 本身没问题，TA 能解 EC key**。
- ECDSA begin 后 TA 侧**无任何** Ecdsa_* trace，keymaster 线程 R 态 sum-exec=560 秒 →
  MTK SWWatchDog 软复位（bootreason=watchdog）。
- 卡死点锁定在 TA 内 ECDSA_CreateOperation 之后的 OpenSSL/签名路径，
  **不是** keyblob 读取，也**不是** cmdID dispatch。
- RSA 全程正常（Cmd 13/20/22/25/26/27 全链路 trace 都在）。

## 5. 给 VendorKeymasterContext 的实现要点

1. `KeymasterContext::ParseKeyBlob` → TA 命令需要正确组 104B 头 + keyblob + params，
   不可直接套 AOSP 的标准 blob 格式；必须 该厂商 专有（KMKB 头 + sm4 加密 + DoMac 校验）。
2. EC keyblob 走 type==2 解密分支是通的，HAL 无需改 keyblob 格式。
3. ECDSA 签名仍需解 TA 内卡死的 OpenSSL 路径（TA patch 或接受软件 fallback）。
4. attestation / import_wrapped_key 等 TA 命令（203/35）已有实现，可在 C 路线复用。

## 6. 运行时 keyblob 读取分支（必读修正）

实测（last_kmsg）：EC key 走 **`read_ec_key_from_keyblob`（type==2 → DecryptKeyBlob/sm4 解密成功）**
而非 SFS 持久存储。签名卡死点在解密**之后**的 ECDSA_CreateOperation/OpenSSL 路径，
不是"读不到 key"。早期"read_ec_key SFS 找不到"结论已被推翻。
