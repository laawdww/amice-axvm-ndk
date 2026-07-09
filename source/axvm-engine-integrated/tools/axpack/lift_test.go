package main

import (
	"bytes"
	"debug/elf"
	"os"
	"testing"
)

func TestLiftVictimCheck(t *testing.T) {
	raw, err := os.ReadFile("../../build-ndk-arm64/samples/victim/libvictim.so")
	if err != nil {
		t.Skip(err)
	}
	ef, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	funcs, err := collectFuncs(ef, raw, map[string]bool{"victim_check": true})
	if err != nil || len(funcs) == 0 {
		t.Fatal(err)
	}
	bc, _, _, err := liftFunc(funcs[0].OrigCode, funcs[0].Addr)
	if err != nil {
		t.Fatal(err)
	}
	if len(bc) == 0 {
		t.Fatal("empty bc")
	}
	t.Logf("victim_check bc=%d bytes", len(bc))
}

func TestLiftVictimMixed(t *testing.T) {
	raw, err := os.ReadFile("../../build-ndk-arm64/samples/victim/libvictim.so")
	if err != nil {
		t.Skip(err)
	}
	ef, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	funcs, err := collectFuncs(ef, raw, map[string]bool{"victim_mixed": true})
	if err != nil || len(funcs) == 0 {
		t.Fatal(err)
	}
	bc, _, _, err := liftFunc(funcs[0].OrigCode, funcs[0].Addr)
	if err != nil {
		t.Fatalf("lift victim_mixed: %v", err)
	}
	t.Logf("victim_mixed bc=%d bytes (native=%d)", len(bc), len(funcs[0].OrigCode))
}

func TestLiftVictimFadd(t *testing.T) {
	raw, err := os.ReadFile("../../build-ndk-arm64/samples/victim/libvictim.so")
	if err != nil {
		t.Skip(err)
	}
	ef, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	funcs, err := collectFuncs(ef, raw, map[string]bool{"victim_fadd": true})
	if err != nil || len(funcs) == 0 {
		t.Fatal(err)
	}
	bc, _, _, err := liftFunc(funcs[0].OrigCode, funcs[0].Addr)
	if err != nil {
		t.Fatalf("lift victim_fadd: %v", err)
	}
	t.Logf("victim_fadd bc=%d bytes", len(bc))
}

func TestLiftAllExported(t *testing.T) {
	raw, err := os.ReadFile("../../build-ndk-arm64/samples/victim/libvictim.so")
	if err != nil {
		t.Skip(err)
	}
	ef, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	funcs, err := collectFuncs(ef, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := liftFuncBatch(funcs); err != nil {
		t.Fatal(err)
	}
}
