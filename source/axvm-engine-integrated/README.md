# axvm-engine

ARM64 native SO virtualizer for Android (NDK `arm64-v8a`).

- **Runtime** (`runtime/`): bytecode VM, loader, crypt, guard — shipped as **`libaxvm.so`**
- **Packer** (`tools/axpack/`): ELF lifter, EOF pack, stub trampoline, encrypt / wipe / apk-bind
- **Demo** (`android/`, `samples/victim/`): APK + protected victim SO E2E

## NDK one-click

Repo root `protect-ndk.ps1` (also `scripts/protect-ndk.ps1`):

```powershell
# SO in → protected SO out (SingleSo defaults)
..\..\..\protect-ndk.ps1 -In libfoo.so -Out libfoo.axvm.so -Package com.example.app -Apk app.apk
```

Gradle: `android/gradle/axvm-protect.gradle` (demo defaults ON; `-Paxvm.protect=false` to disable).

CMake: `include(cmake/AxvmProtect.cmake)` then `axvm_ndk_protect(mylib ...)`.

Detailed P1 feature list and fixes: [`docs/P1-FEATURES-AND-FIXES.md`](docs/P1-FEATURES-AND-FIXES.md).

## Prerequisites

- Android NDK (e.g. r26), JDK 17, Go 1.22+ (or `tools/go1.22.10/`)
- Device/emulator with `adb` for APK tests

## Full E2E verification

```powershell
.\scripts\verify-all.ps1
```

Builds release runtime, runs `axpack` tests, PIE standalone, **apk-bind** protected SO, installs debug APK, checks logcat for `PACK: PASS` and all `MODULE_*: PASS`. Uses default **2 EOF decoys** (runtime ignores them via MAC + `_axdecoy_*` name filter).

## Recommended pack command (production-style)

Scan first, then protect with **AXDS v3 + apk-bind** (matches Android `getApkContentsSigners()` cert):

```powershell
# 1. Scan lift coverage (optional JSON report)
.\build\axpack.exe -in libvictim.so -scan -report build\scan.json

# 2. Print signing cert from APK (v1/v2/v3; shows scheme= primary, present= all blocks)
.\build\axpack.exe -print-apk-cert app-release.apk

# 3. Protect + bind to package + cert SHA-256
.\build\axpack.exe -in libvictim.so -out libvictim.ax.so `
  -syms "fn1,fn2,fn3" `
  -wipe -encrypt -no-patch `
  -apk-bind -package com.example.app `
  -apk-cert-sha256 <64-hex-sha256>
# Or: -apk path\to\app.apk  (reads cert automatically)

# 4. Ship libvictim.ax.so as lib*.so + libaxvm.so; load via app-private extract (see ProtectedSoLoader)
```

Legacy fixed magic (no AXDS): add `-legacy-pack-magic`. Disable EOF decoys: `-decoys 0`.

## Lift / degrade options

| Flag | Purpose |
|------|---------|
| `-scan` / `-report` | List liftable symbols; JSON coverage |
| `-degrade` | Skip symbols that fail lift; continue pack |
| `-skip-atomic` | **Default ON** — skip LDXR/CAS/LDADD (approximate if forced off) |
| `-no-skip-atomic` | Lift atomics as plain load/store — **unsafe for real concurrency** |
| `-native-wipe` / AXNW | Keep non-liftable native as encrypted `.text` |

**Before virtualizing third-party SO:** run `-scan`. Crypto / ML / image SOs often need more NEON/SIMD in the lifter; atomics need true semantics (P1 gap). See P1 doc §「已知限制」.

## Quick demo APK (Windows)

```powershell
.\scripts\protect-and-test-apk.ps1   # lighter than verify-all; apk-bind aligned
```

## Minimal protect (no apk-bind)

```powershell
.\build\axpack.exe -in your.so -out your.ax.so -syms "fn1,fn2" -wipe -encrypt -no-patch
```

Ship **`libaxvm.so`** + protected SO; register APK binding only when using `-apk-bind`.

### Single-SO runtime init (optional)

Link the VM runtime into the victim SO so load-time dispatch registration needs no `dlsym` string:

```powershell
cmake -S . -B build -DAXVM_EMBED_RUNTIME=ON ...   # victim links axvm_runtime + constructor
```

JNI prepatch/rescan still lives in `libaxvm.so` in the demo APK; full single-library shipping is follow-up integration.

### Gradle protectSo (opt-in)

`android/gradle/axvm-protect.gradle` runs `axpack` after `mergeNativeLibs`. Enable in `android/app/build.gradle`:

```gradle
axvmProtect {
    enabled = true
    symbols = "fn1,fn2,..."
    apkBind = true
    packageName = android.defaultConfig.applicationId
    apkCertSha256 = "<64-hex>"
}
```

Build `build/axpack.exe` first (`go build -o ../build/axpack.exe .` in `tools/axpack`).

### Delivery libaxvm.so (minimal attack surface)

```powershell
cmake -S . -B build-del -DCMAKE_BUILD_TYPE=Release `
  -DAXVM_DEMO_JNI=OFF `
  -DAXVM_OLLVM=ON    # optional: needs AMICE libamice.so — see github.com/fuqiuluo/amice
# export AMICE_PLUGIN=/path/to/libamice.so
# export AMICE_STRING_ENCRYPTION=1

.\build\axpack.exe -in libvictim.so -out libvictim.ax.so `
  -protect-level aggressive -wipe -encrypt -no-patch -strip `
  -apk-bind -package com.example.app -apk-cert-sha256 <64-hex>
```

Exports shrink to `JNI_OnLoad`, `ApkBinding.nativeSetBinding`, `axvm_dispatch_ex`, loader API, and GOT gate — no `vm*Probe` / `*_selftest` / `axvm_dynseed_get_master_plain`.

## Status (P1 vs P2)

| Item | Status |
|------|--------|
| Pack magic derivation + EOF decoys | Done (decoys MAC-invalid + name `_axdecoy_*`) |
| Stub 8× prologue variants | Done (int + FP) |
| libaxvm static link into app | **P2 partial** — `-DAXVM_EMBED_RUNTIME=ON` links runtime into `libvictim.so`; JNI still uses `libaxvm.so` unless integrated |
| NEON / true atomics | **P1 partial** — LDR/STR Q (128-bit) lifted as dual D; scan warns atomics; default `-skip-atomic` |
| Delivery export surface | **Done** — `-DAXVM_DEMO_JNI=OFF` + export map (~10 symbols vs 309) |
| Disk stext with `-no-patch` | **Done** — full function body encrypted at pack time |
| OLLVM / AMICE runtime obfuscation | **Opt-in** — `-DAXVM_OLLVM=ON` + [fuqiuluo/amice](https://github.com/fuqiuluo/amice) |
| Delivery export surface | **Done** — `-DAXVM_DEMO_JNI=OFF` + export map (~10 symbols vs 309) |
| Disk stext with `-no-patch` | **Done** — full function body encrypted at pack time |
| OLLVM / AMICE runtime obfuscation | **Opt-in** — `-DAXVM_OLLVM=ON` + [fuqiuluo/amice](https://github.com/fuqiuluo/amice) |
