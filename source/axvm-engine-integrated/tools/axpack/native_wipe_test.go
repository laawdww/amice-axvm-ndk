package main

import (
	"bytes"
	"testing"
)

func TestNativeStextFuncIDDistinct(t *testing.T) {
	a := nativeStextFuncID("foo")
	b := nativeStextFuncID("bar")
	if a == b {
		t.Fatal("expected distinct ids")
	}
	if a&0x80000000 == 0 || b&0x80000000 == 0 {
		t.Fatal("expected high bit set")
	}
	if a == 1 || b == 1 {
		t.Fatal("must not collide with pack func_id=1")
	}
}

func TestNativeWipeRoundtrip(t *testing.T) {
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(i*17 + 3)
	}
	orig := bytes.Repeat([]byte{0xAA, 0xBB, 0xCC, 0xDD}, 8)
	buf := append([]byte(nil), orig...)
	fid := nativeStextFuncID("native_sym")
	stextCryptRange(buf, master, fid)
	if bytes.Equal(buf, orig) {
		t.Fatal("stext encrypt no-op")
	}
	stextCryptRange(buf, master, fid)
	if !bytes.Equal(buf, orig) {
		t.Fatal("stext decrypt mismatch")
	}
}

func TestBuildAXNWBlock(t *testing.T) {
	recs := []nativeWipeRec{
		{Vaddr: 0x1000, Size: 64, FuncID: nativeStextFuncID("a")},
		{Vaddr: 0x2000, Size: 128, FuncID: nativeStextFuncID("b")},
	}
	blk := buildAXNWBlock(recs)
	if len(blk) != 16+2*16 {
		t.Fatalf("len=%d", len(blk))
	}
	if got := uint32(blk[0]) | uint32(blk[1])<<8 | uint32(blk[2])<<16 | uint32(blk[3])<<24; got != axnwMagic {
		t.Fatalf("magic=0x%x", got)
	}
}
