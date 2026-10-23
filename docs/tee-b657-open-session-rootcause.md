# b657 TA Patch 全部失败的根因 — TEEC_ERROR_SECURITY (0xFFFF000F)

> 2026-10-14, 设备 00012700202608001934 (product)
> 固件: v3 OTA product-ota-20261014.122841.zip (incremental 20261014.122841)

## 现象
- 烧入 v3 OTA 后 system_server 崩溃循环 (~5分钟) 后自行平衡, 现可 boot.
- 残留: `keymaster@4.0-service-rc` 每 ~5s 重复
  ```
  E keymaster4: TEEC_OpenSession error:ffff000f
  E keymaster4: VendorKeymaster can't open!!!
  ```
- 系统整体不再死机, 但 KM4 / 依赖硬绑密钥功能不可用.

## 决定性证据: 错误码 = 安全问题
`0xFFFF000F == TEEC_ERROR_SECURITY` ("A security fault was detected.")
定义于:
`vendor/.../该厂商 TEE/source/android/该厂商 TEE_client/public/tee_client_api.h:152`

调用链:
1. keymaster4 HAL: `TEEC_OpenSession(...b657ba17...)` (libteec)
2. driver: `ioctl(TEE_IOC_OPEN_SESSION)` 
3. kernel: `该厂商 TEE_open_session()` (drivers/tee/该厂商 TEE/call.c)
   - 仅转发 uuid + SMC 到 secure world, ret 原样返回
4. **secure world (该厂商 TEE/OP-TEE 内核): TA 完整性校验失败 → 返回 0xFFFF000F**

## 关键结论
- v1 (RNG kill), v2 (15d200e0 错编码), v3 (00f013b8 正确 b.w) —— **全部** OpenSession 失败.
- v3 字节已由 keystone+capstone 双重验证正确 (b.w 0x4b554), RAND_bytes 原码未动.
- **任何对 b657.ta ELF 内容的修改 (哪怕 4 字节) 都会触发 该厂商 TEE secure world 的 TA 完整性校验拒绝**
- 校验在 secure world (闭源), 不在 kernel driver (`drivers/tee/该厂商 TEE/*.c` 无该校验), 无法通过改 linux 侧绕过.
- TA 头 0x14..0x114 含 8*32=256B 校验表, 与 ELF 各分块 sha256 不对应 → 非普通分块哈希, 无法重算回填.

## 方案结论 & 修复方向
| 方案 | 可执行? | 说明 |
|---|---|---|
| A. 直接 patch b657.ta | ❌ 不可行 | OpenSession 即 ffff000f, 任意字节修改都触发校验 |
| B. 改 该厂商 TEE 内核 | ❌ 不可行 | secure world 闭源, linux 侧无校验逻辑 |
| C. Linux tee driver 加超时/watchdog | ✅ 可行 | drivers/tee/该厂商 TEE/*.c 有源码; 给 该厂商 TEE_do_call 加超时, SVC 卡死有兜底 |
| D. 上层 keymaster proxy/timeout | ✅ 可行 | 不碰 TA, 缓解 ECDSA 卡死导致的服务饿死 |
| E. 用厂商原厂 TA + 仅应用层限制 ECDSA | ✅ 可行 | 保 OpenSession 正常, 让 ECDSA 请求直接返错 |

**推荐**: 先前 v1 也"brick"其实也是 OpenSession 失败(而非 RNG 副作用) — 不是全局挂起, 而是 keymaster 服务链饿死.

## 善后
- 要恢复出厂正常功能: 撤掉 b657.ta patch, 回复原厂 TA (sha 见 .orig_backup), 重新 build OTA.
- 若须保留 ECDSA 修复: 只能走 C/D/E, 不碰 TA 二进制.
