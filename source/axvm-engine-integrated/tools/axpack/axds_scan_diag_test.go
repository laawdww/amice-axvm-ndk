package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestAXDSBlockCountInVictim(t *testing.T) {
	so := filepath.Join("..", "..", "build", "libvictim.ax.so")
	data, err := os.ReadFile(so)
	if err != nil {
		t.Skip(so)
	}
	var hits []int
	for off := 0; off+64 <= len(data); off += 4 {
		if binary.LittleEndian.Uint32(data[off:]) != axdsMagic {
			continue
		}
		blk := data[off : off+64]
		ver := binary.LittleEndian.Uint32(blk[4:8])
		if ver != axdsVersion && ver != axdsVersion2 && ver != axdsVersion3 {
			continue
		}
		want := fnv1a32(blk[:56])
		got := binary.LittleEndian.Uint32(blk[56:60])
		if got != want {
			continue
		}
		hits = append(hits, off)
	}
	t.Logf("file len=%d hits=%d", len(data), len(hits))
	for _, off := range hits {
		tail := len(data) - off
		raw, _, _ := probeDynSeedFromTail(data[:off+64])
		magic := uint32(0)
		if raw != nil {
			magic = resolvePackMagic(raw, false)
		}
		t.Logf("  off=0x%x tail=%d magic=0x%08X", off, tail, magic)
	}
	if len(hits) == 0 {
		t.Skip("no AXDS in protected SO (run verify-all first)")
	}
	last := hits[len(hits)-1]
	if last+64 != len(data) {
		t.Logf("WARN: last AXDS not at EOF (padding %d bytes after)", len(data)-last-64)
	}
}

func TestAXDSBlockCountPrint(t *testing.T) {
	so := filepath.Join("..", "..", "build", "libvictim.ax.so")
	data, err := os.ReadFile(so)
	if err != nil {
		t.Skip(so)
	}
	n := 0
	for off := 0; off+64 <= len(data); off += 4 {
		if binary.LittleEndian.Uint32(data[off:]) != axdsMagic {
			continue
		}
		blk := data[off : off+64]
		want := fnv1a32(blk[:56])
		got := binary.LittleEndian.Uint32(blk[56:60])
		if got == want {
			n++
			t.Logf("valid AXDS at 0x%x", off)
		}
	}
	t.Logf("total valid=%d file_len=%d eof_off=0x%x", n, len(data), len(data)-64)
}
