package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestDecoyPackInvalidMAC(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	realMagic := derivePackMagic(raw)
	blob := buildDecoyPacks(3, raw, realMagic)
	if len(blob) < 64*3 {
		t.Fatalf("short decoy blob %d", len(blob))
	}
	m0 := binary.LittleEndian.Uint32(blob[0:4])
	if m0 != axpkMagic {
		t.Fatalf("first decoy magic %08x", m0)
	}
	/* 假包 MAC 与真 seal 不同 */
	pack, _, _ := buildPackAndStubs([]fnInfo{{
		Name: "t", Addr: 0x1000, Size: 8, OrigCode: []byte{0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5},
		BC: []byte{0x50}, EntryPC: 0,
	}}, false, false, raw, false, realMagic)
	realMAC := binary.LittleEndian.Uint32(pack[44:48])
	decMAC := binary.LittleEndian.Uint32(blob[44:48])
	if decMAC == realMAC {
		t.Fatal("decoy MAC should not match real pack")
	}
}

func TestBuildDecoyZero(t *testing.T) {
	if buildDecoyPacks(0, nil, axpkMagic) != nil {
		t.Fatal("zero decoys")
	}
}

func TestDecoyRejectedByPackTrust(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	realMagic := derivePackMagic(raw)
	decoys := buildDecoyPacks(2, raw, realMagic)
	if len(decoys) == 0 {
		t.Fatal("no decoys")
	}
	if packFullyTrusted(decoys) {
		t.Fatal("decoy blob must not pass packFullyTrusted")
	}
	name := packFirstFuncName(decoys)
	if packExportNameTrusted(name) {
		t.Fatalf("decoy name %q should be rejected", name)
	}
}

func TestFindPackWithDecoys(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 11)
	}
	realMagic := derivePackMagic(raw)
	pack, stubs, _ := buildPackAndStubs([]fnInfo{{
		Name: "victim_add", Addr: 0x994, Size: 8,
		OrigCode: []byte{0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5},
		BC:       []byte{0x50}, EntryPC: 0,
	}}, false, false, raw, false, realMagic)
	decoys := buildDecoyPacks(2, raw, realMagic)
	blk := buildDynSeedBlock(raw, false)
	var file []byte
	file = append(file, pack...)
	file = append(file, stubs...)
	file = append(file, decoys...)
	file = append(file, blk...)
	for len(file)%16 != 0 {
		file = append(file, 0)
	}
	off := findLastTrustedPackInBuf(file, realMagic)
	if off != 0 {
		t.Fatalf("expected real pack at 0 got %d", off)
	}
	if !bytes.Equal(file[off:off+4], pack[:4]) {
		t.Fatal("wrong pack at offset")
	}
}
