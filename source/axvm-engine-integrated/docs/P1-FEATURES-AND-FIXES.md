# P1 功能与缺陷修复清单

本文档汇总本轮「商业 VM 差距收口」已实现的功能、已修复缺陷、APK 签名方案支持及验证方式。

## 一、已实现功能（P0 / P1）

| 模块 | 功能 | 说明 |
|------|------|------|
| axpack | `-scan` / `-report` | `diagnoseLift` 扫描可虚拟化符号与覆盖率 |
| axpack | Lift 失败降级 (`-degrade`) | 单符号 lift 失败时跳过该 native 符号，继续打包 |
| axpack | Native wipe 降级 (AXNW) | 无法 lift 的 native 符号可 stext 加密保留 |
| axpack | Stub 多模板 v2 | 8 种 prologue × 4 种 layout，`stub_meta` 记录 dispatch 偏移 |
| axpack | AXDS v3 + apk-bind | MasterSeed 绑定 `package + 签名证书 SHA-256` |
| axpack | Pack magic 派生 | 与 runtime `derive_pack_magic_from_raw` 对齐（label 不含 NUL） |
| axpack | APK 签名证书提取 | **v1 JAR / v2 / v3 全支持**；组合包 `v1+v2`、`v1+v2+v3` 等 |
| axpack | `-print-apk-cert` | 输出 `sha256\t# scheme=主方案 present=并存方案` |
| axpack | `-apk` / `-apk-cert-sha256` | 从 APK 自动读证书或手工指定 hex |
| runtime | Release 零 logcat | `AXVM_DEBUG` 关闭时 loader 静默 |
| runtime | Dispatch 无全局锁 | `axvm_invoke` 路径去掉全局互斥 |
| runtime | AXDS 扫描加固 | 取**最后一个**有效 AXDS；tail 优先 EOF-64 |
| runtime | APK bind 前缀 | `strlen(prefix)` 不含 NUL，与 Go 一致 |
| Android | `ApkBinding` | JNI 注册包名 + 证书；API 28+ 使用 `getApkContentsSigners` |
| E2E | `verify-all.ps1` | NDK + axpack + PIE + apk-bind APK + 全 MODULE 日志校验 |

## 二、APK 签名方案支持（v1 / v2 / v3）

### 解析顺序（与 Android `getApkContentsSigners()` 一致）

1. **v3**（APK Signature Scheme v3 block）
2. **v2**（v2 block）
3. **v1**（JAR `META-INF/*.RSA` / `*.DSA` / `*.EC`）

### 组合包行为

| APK 内实际块 | 选用证书 | `present=` 示例 |
|-------------|---------|----------------|
| 仅 v2 | v2 | `v2` |
| v1 + v2 | **v2**（非 v1） | `v1+v2` |
| v1 + v2 + v3 | **v3** | `v1+v2+v3` |
| 仅 v1 | v1 | `v1` |

- 多方案并存时校验 v1 与主选证书是否一致；不一致时 stderr 提示 `MismatchV1`，仍以 v3/v2 为准。
- **未实现 v4**（`.idsig`，Play 分发侧车文件）；apk-bind 以 APK 内 v1–v3 为准。

### CLI 示例

```powershell
.\build\axpack.exe -print-apk-cert android\app\build\outputs\apk\debug\app-debug.apk
# 3017cf92...	# scheme=v2 present=v2

# apk-bind（可 -apk 自动读证书，或 -apk-cert-sha256 手工指定）
.\build\axpack.exe -in libvictim.so -out libvictim.ax.so `
  -apk-bind -package com.axvm.demo -apk-cert-sha256 <64-hex>
```

`verify-all.ps1` 会交叉校验 keystore 证书与 APK 内解析结果一致。

## 三、已修复缺陷（根因级）

### 1. Pack magic Go/C 不一致

- **现象**：prepatch `magic=` 与 axpack `pack magic:` 不一致，pack 找不到。
- **根因**：C 用 `sizeof(k_pack_magic_label)`（含 NUL），Go 用 16 字节不含 NUL。
- **修复**：`runtime/src/axvm_dynseed.c` 中 `derive_pack_magic_from_raw` 使用 `strlen(k_pack_magic_label)`。

### 2. APK bind 前缀 NUL

- **现象**：设备 `master=` 与 Go `deriveBoundMaster` 不一致。
- **根因**：C `derive_apk_bound_master` 对 prefix 使用 `sizeof`（含 NUL）。
- **修复**：改用 `strlen(k_apk_bind_prefix)`。

### 3. SHA256 padding 位长（HMAC 长消息）

- **现象**：RFC4231 自检通过，但 apk-bind 向量失败。
- **根因**：`axvm_sha256_final` padding 时继续累加 `bitlen`，≥56 字节消息嵌入长度错误。
- **修复**：padding 前冻结 `total_bits`（`runtime/src/axvm_integrity.c`）。

### 4. Stub prologue X16Scratch 参数错误

- **现象**：`victimAdd(41,1)` 日志为 `dispatch a0=1 a1=1 ret=2`。
- **根因**：`MOV x1,x17` 应为 `MOV x1,x16`。
- **修复**：`tools/axpack/stub_prologue.go`。

### 5. Stub prologue X16Base 设备崩溃

- **现象**：SIGSEGV @ stub+0x1c。
- **根因**：经 `x16` 间接 `LDP [x16]` 在部分 JNI/PAC 环境失败。
- **修复**：改为 `emitIntReloadArgs` 从 `sp` 直接恢复参数。

### 6. Dispatch 槽与 prologue 重叠

- **现象**：`victim_check` 出现 `dispatch miss id=0xCAFEBABE`。
- **根因**：固定 `dispatchOff=56` 小于部分 prologue+MOVZ 长度；BLR patch 跳过 `MOVZ x0, func_id`。
- **修复**：`composeStubVariant` 在 MOVZ 后动态上推 dispatch 偏移并写回 `stub_meta`。

### 7. APK 签名方案优先级

- **现象**：v1+v2+v3 组合包可能先解析 v1，与 Android API 28+ 不一致。
- **修复**：证书提取顺序 **v3 → v2 → v1**；`schemeListString` 报告并存方案。

### 8. E2E 偶发失败 / EOF decoy 干扰

- **decoys 重叠**：旧版 runtime 可能误认 decoy；现 **MAC 校验 + `_axdecoy_*` 导出名过滤 + 取最后一个可信 AXPK**；AXDS 扫描跳过尾部 padding。
- **decoy magic**：不再复用 derived `realMagic`，避免静态排除。
- **verify-all**：默认 `-decoys 2`（与 axpack 默认一致）。
- **陈旧 libvictim**：脚本要求 `gradlew clean assembleDebug`。
- **logcat 超时**：模块测试约 90s，等待由 40s 增至 120s。

### 9. Dispatch 日志误导（诊断）

- **现象**：`victim_check` 日志 `a0`/`a1` 显示垃圾值且两次调用相同，但 `add`/`mul` 结果正确。
- **根因**：`AXVM_LOGI` 在 `axvm_invoke` **之后**打印参数寄存器；解释器已 clobber `x1`/`x2`。
- **修复**：改为打印栈上 `args[0]`/`args[1]`（`runtime/src/axvm_loader.c`）。

### 10. 应用启动 ANR / 主线程卡死

- **现象**：冷启动 `am start -W` WaitTime ~10s+；小米 **APP_SCOUT_HANG** @ 5s；界面白屏约 1 分钟。
- **根因 1**：`nativeRescan()` → `axvm_scan_proc_maps()` 在 pack 已加载后仍全进程 4 字节步进扫描 maps（~15s）。
- **根因 2**：`MainActivity.onCreate` 主线程同步跑 30+ 模块自检（bench/JIT 等 ~50s+）。
- **修复**：
  - `axvm_scan_proc_maps`：`g_module_count > 0` 时跳过全量扫描（`runtime/src/axvm_loader.c`）。
  - `MainActivity`：自检移至后台线程 `axvm-selftest`，UI 立即显示 loading（`android/.../MainActivity.java`）。
- **修复后**：冷启动 **~340ms**；自检 ~3s 在后台完成，logcat 仍输出全部 `MODULE_*: PASS`。

## 四、验证命令与结果

```powershell
# 全量 E2E（需 adb 设备）
.\scripts\verify-all.ps1

# axpack 单元测试（含 APK 签名）
cd tools\axpack
..\go1.22.10\bin\go.exe test -count=1 ./...

# 查看 APK 签名证书与方案
..\build\axpack.exe -print-apk-cert android\app\build\outputs\apk\debug\app-debug.apk
```

### 最近验证（2026-07-09）

| 项 | 结果 |
|----|------|
| `verify-all.ps1` 退出码 | **0** |
| PIE standalone | 全部 `module_*_standalone: PASS` |
| logcat | **`PACK: PASS`** + 全部 **`MODULE_*: PASS`** |
| axpack `go test ./...` | PASS |
| APK 证书交叉校验 | debug keystore == APK 解析 |
| `-print-apk-cert` | `scheme=v2 present=v2`（debug 构建仅 v2 块；逻辑支持 v1+v2+v3） |
| Activity 冷启动 | **~340ms**（修复前 ~10s+ ANR） |

**通过标准**：`verify-all.ps1` 退出码 0；logcat 含 `PACK: PASS` 与全部 `MODULE_*: PASS`。

## 六、交付版加固（逆向审计响应）

| 优先级 | 问题 | 修复 |
|--------|------|------|
| P0 | libaxvm 309 导出 + probe JNI | `-fvisibility=hidden` + `cmake/axvm_exports*.map`；`-DAXVM_DEMO_JNI=OFF` 关闭 NativeVm/VictimTest 注册 |
| P0 | `axvm_dynseed_get_master_plain` 导出 | runtime 默认 hidden，不再出现在 dynsym |
| P0 | libvictim 磁盘明文 `.text`（`-no-patch -wipe`） | axpack 在 no-patch 时仍 stext 加密**整段**函数体 |
| P1 | 6/14 未虚拟化 | `verify-all` 改用 `-protect-level aggressive`（14 导出全 lift） |
| P1 | symtab 源码路径 | axpack `-strip`（llvm-strip -s）+ Release `-Wl,-s` |
| P1 | dispatch logcat | Release `AXVM_DEBUG=OFF`；JNI_OnLoad 自检改 `AXVM_LOGE`；`victim_jni` VLOG 门控 |
| P2 | libaxvm 无自保护 | `-DAXVM_OLLVM=ON` + [AMICE](https://github.com/fuqiuluo/amice) `libamice.so`（runtime + axvm 均 `-fpass-plugin`） |
| P2 | 敏感字符串明文 | AMICE `AMICE_STRING_ENCRYPTION=1`；或后续 strcrypt 扩展 |
| P2 | stub dispatch NOP 槽 | 设计如此（MODULE P 运行时 prepatch）；可选 pack 预填 GOT gate 指针 |

**交付构建示例：**

```powershell
cmake ... -DCMAKE_BUILD_TYPE=Release -DAXVM_DEMO_JNI=OFF -DAXVM_OLLVM=ON
# export AMICE_PLUGIN=.../libamice.so  AMICE_STRING_ENCRYPTION=1

.\build\axpack.exe -in libvictim.so -out libvictim.ax.so `
  -protect-level aggressive -wipe -encrypt -no-patch -strip `
  -apk-bind -package com.example.app -apk-cert-sha256 <hex>
```

Demo/E2E 仍默认 `AXVM_DEMO_JNI=ON`（`verify-all.ps1` 需要 NativeVm 自检 JNI）。

## 五、已知限制 / 未做项

- Gradle `protectSo`：**已实现** `android/gradle/axvm-protect.gradle`（默认 `enabled=false`，见 README）。
- **单 SO 模式**：`-DAXVM_EMBED_RUNTIME=ON` 将 `axvm_runtime` 链入 `libvictim.so` 并在 constructor 登记 dispatch；JNI 仍依赖 `libaxvm.so`（完整单库待集成）。
- **NEON 128-bit**：LDR/STR Q 已提升为双 LDR/STR D；向量算术/ shuffle 仍待扩展。
- **原子指令真语义**：默认 `-skip-atomic`；`-no-skip-atomic` 为近似 lift，非 lock-free 安全。
- `tools/go1.22.10/` 为本地便携 Go，勿提交 git。
- APK Signature Scheme **v4**（`.idsig`）未解析。
- 诊断日志（`ApkBinding` cert、module crypt）Release 已门控 `BuildConfig.DEBUG`；其余可按需 `AXVM_DEBUG`。
