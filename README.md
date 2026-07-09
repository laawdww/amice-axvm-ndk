# AMICE + AXVM Windows NDK Integration

This package contains the Windows-side AMICE/AXVM packer integration, Android arm64 runtime, protected SO sample, and APK regression test.

## Contents

- `source/axvm-engine-integrated/` - integrated AXVM source tree with the fixed axpack tool and runtime.
- `artifacts/axpack.exe` - Windows packer executable.
- `artifacts/libaxvm.so` - Android arm64 runtime library.
- `artifacts/libvmtest.full.axvm.so` - fully protected regression SO.
- `artifacts/amice-axvm-test.apk` - Android APK regression test.
- `artifacts/amice-win-ndk-ir-axvm.zip` - Windows AMICE/NDK/IR integration package.
- `artifacts/amice-pass-test.zip` - AMICE pass smoke-test package.

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

## Example Pack Command

```powershell
.\artifacts\axpack.exe `
  -in .\libinput.so `
  -out .\libinput.axvm.so `
  -protect-level aggressive `
  -degrade `
  -stable-stub
```

For helper/internal functions that are called through protected chains, pass them explicitly with `-syms`.
