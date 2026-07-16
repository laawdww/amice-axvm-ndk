package main

import (
	"bytes"
	"crypto/rand"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
)

const (
	axpkMagic   = 0x31585041
	axpkVersion = 0x00010001
	axpkEncrypt = 0x00000001
	axpkWiped   = 0x00000002

	axvmMagic   = "AXV1"
	axvmVersion = 0x00010000

	/* 与 runtime/include/axvm_bytecode.h 对齐 */
	axvmBCFlagReloc      = 0x00000002
	axvmBCFlagOpcodePerm = 0x00000004
	axvmBCFlagAddrMap    = 0x00000010

	axpkToken = 0x00000004

	axpkVersionV2 = 0x00010002 /* per-func stub_meta (size + dispatch offset) */

	axvmRecSizeV1 = 72
	axvmRecSizeV2 = 76
)

type fnInfo struct {
	Name     string
	Addr     uint64
	FileOff  int64
	Size     int
	OrigCode []byte
	BC       []byte
	EntryPC  uint32
	StubOff  uint32
	UsesFP   bool /* 模块 F：需 d0-d7 marshaling stub */
	AddrMap  []addrMapEntry
	Lifted   bool
	StubSize uint16
	StubDisp uint16
	StubVar  uint8
}

func main() {
	in := flag.String("in", "", "input ARM64 .so")
	out := flag.String("out", "", "output protected .so")
	syms := flag.String("syms", "", "comma-separated symbols to protect (empty=all exported FUNC)")
	wipe := flag.Bool("wipe", true, "wipe original function bodies with NOP")
	enc := flag.Bool("encrypt", true, "encrypt bytecode in pack")
	dep := flag.String("dep", "libaxvm.so", "DT_NEEDED runtime library name")
	noPhdr := flag.Bool("no-phdr", false, "debug: append pack only, do not patch PHDR")
	noPatch := flag.Bool("no-patch", false, "debug: do not patch function entry jumps")
	noNorm := flag.Bool("no-norm", false, "debug: skip PHDR reorder after axvm PT_LOAD")
	integrity := flag.Bool("integrity", true, "emit segmented SHA256 integrity section (module I)")
	dynseed := flag.Bool("dynseed", true, "emit AXDS dynamic MasterSeed block (module M)")
	opcodePerm := flag.Bool("opcode-perm", true, "permute VM opcodes keyed by AXDS MasterSeed (module M; needs dynseed)")
	tokenEntry := flag.Bool("token", false, "VMPacker-style 3-instruction token entry trampoline")
	scan := flag.Bool("scan", false, "diagnose lift coverage per symbol (no pack)")
	report := flag.String("report", "", "write -scan JSON report to path")
	degrade := flag.Bool("degrade", true, "skip symbols that fail lift instead of aborting")
	nativeWipe := flag.Bool("native-wipe", true, "with -degrade, stext-encrypt symbols left native (needs -wipe -dynseed)")
	noNativeWipe := flag.Bool("no-native-wipe", false, "disable native symbol body encryption")
	skipAtomic := flag.Bool("skip-atomic", false, "with -degrade, skip symbols containing atomic insns (default: lift with true host atomics)")
	noSkipAtomic := flag.Bool("no-skip-atomic", false, "force-lift atomic symbols (default behavior; kept for compatibility)")
	diskReady := flag.Bool("disk-ready", false, "leave .text tails plaintext (NOP/wipe without stext crypt) so SO loads without runtime prepatch — single-SO mode")
	apkBind := flag.Bool("apk-bind", false, "bind MasterSeed to -package + APK signing cert (AXDS v3)")
	apkPath := flag.String("apk", "", "APK path to read signing cert SHA-256 (with -apk-bind)")
	apkPackage := flag.String("package", "", "Android applicationId for -apk-bind")
	apkCertHex := flag.String("apk-cert-sha256", "", "signing cert SHA-256 hex (64 chars); alternative to -apk")
	printApkCert := flag.String("print-apk-cert", "", "print APK signing cert SHA-256 hex and exit")
	legacyPackMagic := flag.Bool("legacy-pack-magic", false, "use fixed AXPK magic 'AXP1' instead of per-build derivation")
	stableStub := flag.Bool("stable-stub", false, "use classic argument-preserving stubs (debug/compatibility mode)")
	decoys := flag.Int("decoys", 2, "append N fake AXPK-like EOF decoys after AXDS (0=off)")
	protectLevel := flag.String("protect-level", "standard", "standard|aggressive (aggressive=all exported FUNC when -syms empty)")
	stripOut := flag.Bool("strip", false, "run llvm-strip -s on output (unsafe: truncates EOF pack; prefer strip input .so)")
	stripTool := flag.String("strip-tool", "", "path to llvm-strip/strip for -strip")
	flag.Parse()
	stableStubPrologue = *stableStub
	/*
	 * disk-ready（Android 单 SO）经 JNI 薄包装调入 stub：部分 prologue 变体
	 *（LDP reload 等）在 PAC 机型上会读到错误的 x0/x1，表现为 add 返回垃圾。
	 * 强制 classic 参数整理；布局尺寸多样性仍保留。
	 */
	if *diskReady && !*stableStub {
		stableStubPrologue = true
		fmt.Fprintf(os.Stderr, "axpack: note: -disk-ready enables stable stub prologues (PAC/JNI safe)\n")
	}

	if *printApkCert != "" {
		cert, info, err := apkSigningCertInfo(*printApkCert)
		if err != nil {
			fatal("print-apk-cert: %v", err)
		}
		schemes := schemeListString(info)
		if info.MismatchV1 {
			fmt.Fprintf(os.Stderr, "axpack: note: v1 JAR cert differs from selected %s (using %s)\n",
				info.Scheme, schemes)
		}
		fmt.Printf("%s\t# scheme=%s present=%s\n", hex.EncodeToString(cert), info.Scheme.String(), schemes)
		return
	}

	if *in == "" {
		flag.Usage()
		os.Exit(1)
	}
	if *scan {
		if *out != "" {
			fmt.Fprintf(os.Stderr, "axpack: -scan ignores -out\n")
		}
		targetSet := map[string]bool{}
		if *syms != "" {
			for _, s := range strings.Split(*syms, ",") {
				targetSet[strings.TrimSpace(s)] = true
			}
		} else if strings.EqualFold(*protectLevel, "aggressive") {
			targetSet = nil /* all exported */
		} else {
			for _, s := range []string{
				"victim_add", "victim_mul", "victim_check", "victim_mixed", "victim_fadd", "victim_fmul",
			} {
				targetSet[s] = true
			}
		}
		if err := scanFromELF(*in, targetSet, *report); err != nil {
			fatal("scan: %v", err)
		}
		return
	}
	if *out == "" {
		flag.Usage()
		os.Exit(1)
	}

	raw, err := os.ReadFile(*in)
	if err != nil {
		fatal("read: %v", err)
	}

	ef, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		fatal("elf: %v", err)
	}
	if ef.Machine != elf.EM_AARCH64 {
		fatal("only ARM64 supported")
	}

	targetSet := map[string]bool{}
	if *syms != "" {
		for _, s := range strings.Split(*syms, ",") {
			targetSet[strings.TrimSpace(s)] = true
		}
	} else if strings.EqualFold(*protectLevel, "aggressive") {
		targetSet = nil
	} else {
		for _, s := range []string{
			"victim_add", "victim_mul", "victim_check", "victim_mixed", "victim_fadd", "victim_fmul",
		} {
			targetSet[s] = true
		}
	}

	candidates, err := collectFuncs(ef, raw, targetSet)
	if err != nil {
		fatal("collect: %v", err)
	}
	if len(candidates) == 0 {
		fatal("no functions selected")
	}
	configureCallTargets(buildPLTCallTargetMap(ef))

	skipAtom := *skipAtomic && !*noSkipAtomic
	funcs, nativeLeft, err := liftFuncBatchDegrade(candidates, *degrade, skipAtom)
	if err != nil {
		fatal("lift: %v", err)
	}
	if len(nativeLeft) > 0 && *degrade {
		fmt.Fprintf(os.Stderr, "axpack: protected %d/%d symbols (%d left native)\n",
			len(funcs), len(candidates), len(nativeLeft))
	}
	doNativeWipe := *nativeWipe && !*noNativeWipe && *wipe && *dynseed && len(nativeLeft) > 0
	var nativeWipeN int
	if doNativeWipe {
		nativeWipeN = len(nativeLeft)
	}

	/*
	 * 模块 M：rawSeed 写入 AXDS；effective master 用于 opcode 置换/流密码。
	 * -apk-bind 时 effective = HMAC(rawSeed, package||cert)，SO 单独提取无法解密。
	 */
	var rawSeed, master []byte
	var useApkBind bool
	if *dynseed {
		rawSeed = make([]byte, 32)
		if _, err := rand.Read(rawSeed); err != nil {
			fatal("master rand: %v", err)
		}
		master = rawSeed
		if *apkBind {
			pkg, cert, err := resolveApkBinding(*apkPath, *apkPackage, *apkCertHex)
			if err != nil {
				fatal("apk-bind: %v", err)
			}
			master = deriveBoundMaster(rawSeed, pkg, cert)
			if master == nil {
				fatal("apk-bind: derive master failed")
			}
			useApkBind = true
			fmt.Printf("apk-bind: package=%s cert_sha256=%x...\n", pkg, cert[:4])
		}
	}

	packMagic := resolvePackMagic(rawSeed, *legacyPackMagic)
	if *dynseed && !*legacyPackMagic && len(rawSeed) >= 32 {
		fmt.Printf("pack magic: 0x%08X (derived)\n", packMagic)
	}

	pack, stubs, permApplied := buildPackAndStubs(funcs, *enc, *wipe, master, *opcodePerm && *dynseed, packMagic)
	if *tokenEntry {
		flags := binary.LittleEndian.Uint32(pack[8:12])
		binary.LittleEndian.PutUint32(pack[8:12], flags|axpkToken)
		sealPackManifestMAC(pack)
	}
	outData, err := injectAndPatch(raw, ef, pack, stubs, funcs, nativeLeft, *wipe, doNativeWipe, *dep, *noPhdr, *noPatch, *noNorm, *integrity, *dynseed, *tokenEntry, rawSeed, master, useApkBind, *decoys, packMagic, *diskReady)
	if err != nil {
		fatal("pack: %v", err)
	}
	if err := os.WriteFile(*out, outData, 0755); err != nil {
		fatal("write: %v", err)
	}
	if *stripOut {
		if err := stripDebugELF(*out, *stripTool); err != nil {
			fatal("strip: %v", err)
		}
	}
	fmt.Printf("protected %d functions -> %s (%d bytes, opcode_perm=%v, native_wipe=%d)\n",
		len(funcs), *out, len(outData), permApplied, nativeWipeN)
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "axpack: "+format+"\n", args...)
	os.Exit(1)
}
