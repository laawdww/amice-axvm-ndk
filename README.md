# AMICE + AXVM Windows NDK Integration

This package contains the Windows-side AMICE/AXVM packer integration, Android arm64 runtime, protected SO sample, and APK regression test.

## One-click protect (recommended)

### CLI — protect an existing SO

```powershell
.\protect-ndk.ps1 -In .\libfoo.so -Out .\libfoo.axvm.so
```

Defaults: **SingleSo** (`-disk-ready`, no `DT_NEEDED libaxvm.so`), aggressive + degrade, auto-scan.

With APK binding:

```powershell
.\protect-ndk.ps1 -In .\libfoo.so -Out .\libfoo.axvm.so `
  -Package com.example.app -Apk .\app-release.apk
```

Compile C then protect (optional AMICE IR if `opt.exe` + `amice.dll` available):

```powershell
.\protect-ndk.ps1 -Source .\foo.c -Out .\libfoo.axvm.so -EnableAmice -EnableFlatten
```

Auto-detects `artifacts/axpack.exe`, `ANDROID_NDK_HOME` / SDK `ndk\*`.

### Gradle — build-time protect

```gradle
apply from: "<path>/android/gradle/axvm-protect.gradle"
axvmProtect {
    enabled = true
    libs = ["libfoo.so"]
    diskReady = true
    dep = "-"
}
```

Demo app defaults **ON** (`-Paxvm.protect=false` to disable). Already-packed SOs are skipped.

```text
gradlew assembleDebug
gradlew assembleRelease -Paxvm.apkBind=true -Paxvm.apkCertSha256=<64hex>
```

### CMake — POST_BUILD hook

```cmake
include(${AXVM_REPO}/source/axvm-engine-integrated/cmake/AxvmProtect.cmake)
axvm_ndk_protect(mylib PACKAGE com.example.app APK ${CMAKE_SOURCE_DIR}/app.apk)
```

## Contents

- `protect-ndk.ps1` — NDK one-click entry (SO or source).
- `source/axvm-engine-integrated/` — integrated AXVM source tree with the fixed axpack tool and runtime.
- `artifacts/axpack.exe` — Windows packer executable.
- `artifacts/libaxvm.so` — Android arm64 runtime library (dual-SO mode).
- `artifacts/libvmtest.full.axvm.so` — fully protected regression SO.
- `artifacts/amice-axvm-test.apk` — Android APK regression test.
- `artifacts/amice-axvm-ndk-oneclick.zip` — **NDK 一键保护分发包**（`protect-ndk.ps1` + `axpack.exe` + runtime + Gradle/CMake）。
- `artifacts/amice-win-ndk-ir-axvm.zip` — Windows AMICE/NDK/IR integration package（旧包）。
- `artifacts/amice-pass-test.zip` — AMICE pass smoke-test package.

## Verified On Device

Device regression passed on Android arm64 through both standalone loader and APK/JNI paths.

- Standalone SO regression: `28/28 pass`
- APK JNI regression: `28/28 pass`
- Protected mode tested: bytecode encryption, dynamic seed, opcode permutation, integrity, decoys, function body wipe, stable stub mode.

## Main Fixes Included

- Fixed 64-bit ADD/SUB extended decoding that could truncate runtime addresses.
- Fixed LDUR/STUR W direction decoding.
- Fixed scratch register save/restore detection for register-offset loads.
- Fixed native/BLR call return value writeback to VM `x0`.
- Fixed guard chain false positives for valid repeated calls with different return values.
- Fixed integrity dispatch checks so mutable/decrypted bytecode is not rehashed during execution.
- Added local symbol collection for explicitly protected helper functions.
- Added `-stable-stub` compatibility mode for argument-preserving stubs.

## Example Pack Command (raw axpack)

```powershell
.\artifacts\axpack.exe `
  -in .\libinput.so `
  -out .\libinput.axvm.so `
  -protect-level aggressive `
  -degrade `
  -stable-stub
```

For helper/internal functions that are called through protected chains, pass them explicitly with `-syms`.
