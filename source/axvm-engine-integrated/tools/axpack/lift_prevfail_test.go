package main

import (
	"bytes"
	"debug/elf"
	"os"
	"testing"
)

func TestLiftPreviouslyFailed(t *testing.T) {
	so := os.Getenv("LOCALAPPDATA") + "/hongchaoren-gradle-build/app/intermediates/merged_native_libs/debug/mergeDebugNativeLibs/out/lib/arm64-v8a/libnative_core.so"
	raw, err := os.ReadFile(so)
	if err != nil {
		t.Skip(err)
	}
	ef, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	names := []string{
		"_ZN6filter12FilterEngine14setMaxPickupKmEd",
		"_ZN3geoL12transformLatEdd",
		"_ZN6filter12FilterEngine14setMinEarningsEd",
		"_ZN3map13CircleManager9addCircleEddd",
		"_ZN6shuanqL14canUseFeaturesEv",
		"_ZN6crypto11CryptoUtils10xorEncryptERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEES9_",
	}
	for _, n := range names {
		funcs, err := collectFuncs(ef, raw, map[string]bool{n: true})
		if err != nil || len(funcs) == 0 {
			t.Logf("skip %s: %v", n, err)
			continue
		}
		bc, _, fp, err := liftFunc(funcs[0].OrigCode, funcs[0].Addr)
		if err != nil {
			t.Errorf("FAIL %s: %v", n, err)
			continue
		}
		t.Logf("OK %s bc=%d fp=%v native=%d", n, len(bc), fp, funcs[0].Size)
	}
}
