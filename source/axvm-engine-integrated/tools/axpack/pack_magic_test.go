package main

import (
	"encoding/binary"
	"testing"
)

func TestDerivePackMagicMatchesRuntimeLabel(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(0x20 + i)
	}
	m := derivePackMagic(raw)
	if m == 0 || m == axpkMagic {
		t.Fatalf("bad magic %08x", m)
	}
	/* C 侧使用 strlen(label)，不含 NUL；与 derivePackMagic 一致 */
	msg := append([]byte(packMagicLabel), raw...)
	want := fnv1a32(msg)
	if want == 0 || want == axpkMagic {
		want ^= 0x5A5A5A5A
	}
	if m != want {
		t.Fatalf("label hash mismatch go=%08x want=%08x", m, want)
	}
	if derivePackMagic(raw) != m {
		t.Fatal("unstable")
	}
}

func TestResolvePackMagicLegacy(t *testing.T) {
	raw := make([]byte, 32)
	if resolvePackMagic(raw, true) != axpkMagic {
		t.Fatal("legacy")
	}
	if resolvePackMagic(nil, false) != axpkMagic {
		t.Fatal("no seed")
	}
}

func TestPackHeaderUsesDerivedMagic(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	magic := derivePackMagic(raw)
	funcs := []fnInfo{{
		Name: "f", Addr: 0x1000, Size: 16, OrigCode: []byte{0x1f, 0x20, 0x03, 0xd5},
		BC: []byte{0x50}, EntryPC: 0,
	}}
	pack, _, _ := buildPackAndStubs(funcs, false, false, raw, false, magic)
	got := binary.LittleEndian.Uint32(pack[0:4])
	if got != magic {
		t.Fatalf("pack magic got %08x want %08x", got, magic)
	}
}
