package main

import (
	"encoding/binary"
	"testing"
)

func TestBuildDynSeedBlockApkBind(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	blk := buildDynSeedBlock(raw, true)
	if len(blk) != axdsSize {
		t.Fatalf("size %d", len(blk))
	}
	if binary.LittleEndian.Uint32(blk[4:]) != axdsVersion3 {
		t.Fatalf("version 0x%x", binary.LittleEndian.Uint32(blk[4:]))
	}
	if binary.LittleEndian.Uint32(blk[60:]) != axdsFlagApkBind {
		t.Fatalf("flags 0x%x", binary.LittleEndian.Uint32(blk[60:]))
	}
}
