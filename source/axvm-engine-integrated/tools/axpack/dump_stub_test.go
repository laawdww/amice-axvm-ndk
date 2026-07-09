package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestDumpVictimAddStub(t *testing.T) {
	so := filepath.Join("..", "..", "build", "libvictim.ax.so")
	data, err := os.ReadFile(so)
	if err != nil {
		t.Skip(so)
	}
	raw, _, _ := probeDynSeedFromTail(data)
	if raw == nil {
		t.Skip("no AXDS in protected SO (run verify-all first)")
	}
	magic := resolvePackMagic(raw, false)
	off := findPackInBuf(data, magic)
	if off < 0 {
		t.Skip("pack not found in protected SO")
	}
	pack := data[off:]
	seed := pack[28:44]
	padBase := binary.LittleEndian.Uint64(seed[0:8]) ^ binary.LittleEndian.Uint64(seed[8:16])
	rec := pack[64 : 64+axvmRecSizeV2]
	stubOff := binary.LittleEndian.Uint32(rec[24:28])
	entry := binary.LittleEndian.Uint32(rec[8:12])
	funcID := uint32(1)
	padSeed := padBase ^ uint64(funcID)*0x9E3779B97F4A7C15 ^ uint64(entry)
	lay := pickStubLayout(funcID, padSeed)
	stub := genStubVariant(funcID, padSeed, &lay)
	t.Logf("prologue=%d layout=%d stubOff=%d dispatch=%d entry=0x%x",
		stubPrologueID(lay), stubLayoutIdx(lay), stubOff, lay.dispatchOff, entry)
	t.Logf("\n%s", hex.Dump(stub[:min(96, len(stub))]))
}

func TestDumpVictimCheckStub(t *testing.T) {
	so := filepath.Join("..", "..", "build", "libvictim.ax.so")
	data, err := os.ReadFile(so)
	if err != nil {
		t.Skip(so)
	}
	raw, _, _ := probeDynSeedFromTail(data)
	if raw == nil {
		t.Skip("no AXDS in protected SO (run verify-all first)")
	}
	magic := resolvePackMagic(raw, false)
	off := findPackInBuf(data, magic)
	if off < 0 {
		t.Skip("pack not found in protected SO")
	}
	pack := data[off:]
	seed := pack[28:44]
	padBase := binary.LittleEndian.Uint64(seed[0:8]) ^ binary.LittleEndian.Uint64(seed[8:16])
	hdrCount := binary.LittleEndian.Uint32(pack[12:16])
	for i := uint32(0); i < hdrCount; i++ {
		rec := pack[64+int64(i)*axvmRecSizeV2 : 64+int64(i+1)*axvmRecSizeV2]
		name := string(bytes.TrimRight(rec[32:68], "\x00"))
		if name != "victim_check" {
			continue
		}
		funcID := binary.LittleEndian.Uint32(rec[0:4])
		entry := binary.LittleEndian.Uint32(rec[8:12])
		meta := binary.LittleEndian.Uint32(rec[72:76])
		lay := decodeStubMeta(meta)
		padSeed := padBase ^ uint64(funcID)*0x9E3779B97F4A7C15 ^ uint64(entry)
		stub := genStubVariant(funcID, padSeed, &lay)
		t.Logf("check funcID=%d prologue=%d layout=%d dispatch=%d size=%d",
			funcID, stubPrologueID(lay), stubLayoutIdx(lay), lay.dispatchOff, lay.size)
		disp := int(lay.dispatchOff)
		t.Logf("bytes@movz area:\n%s", hex.Dump(stub[max(0, disp-16):min(len(stub), disp+32)]))
		return
	}
	t.Fatal("victim_check not found")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
