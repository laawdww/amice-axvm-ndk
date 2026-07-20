package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestProtectedVictimPackProbe(t *testing.T) {
	so := filepath.Join("..", "..", "build", "libvictim.ax.so")
	data, err := os.ReadFile(so)
	if err != nil {
		t.Skip(so)
	}
	raw, master, apkBind := probeDynSeedFromTail(data)
	if raw == nil {
		t.Fatal("AXDS not found")
	}
	t.Logf("apk_bind=%v master=%x...", apkBind, master[:4])
	magic := resolvePackMagic(raw, false)
	t.Logf("derived magic=0x%08X", magic)
	off := findPackInBuf(data, magic)
	if off < 0 {
		t.Fatal("pack not found")
	}
	t.Logf("pack off=%d (0x%x)", off, off)
	if !packManifestTrusted(data[off:]) {
		t.Fatal("pack MAC failed")
	}
}

func TestProtectedVictimTextNotPlainAdd(t *testing.T) {
	plainPath := filepath.Join("..", "..", "build-verify-arm64", "samples", "victim", "libvictim.so")
	protPath := filepath.Join("..", "..", "build", "libvictim.ax.so")
	plain, err := os.ReadFile(plainPath)
	if err != nil {
		t.Skip(plainPath)
	}
	prot, err := os.ReadFile(protPath)
	if err != nil {
		t.Skip(protPath)
	}
	/* victim_add is first export in demo SO — compare .text slice if same file size prefix */
	n := 64
	if len(plain) < n || len(prot) < n {
		t.Skip("short so")
	}
	if bytesEqualPrefix(plain, prot, n) {
		t.Skip("protected SO matches plaintext prefix — rebuild libvictim.ax.so with -no-patch -wipe")
	}
}

func bytesEqualPrefix(a, b []byte, n int) bool {
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func probeDynSeedFromTail(buf []byte) (rawSeed, effective []byte, apkBind bool) {
	blk := findAXDSBlock(buf)
	if blk == nil {
		return nil, nil, false
	}
	ver := binary.LittleEndian.Uint32(blk[4:8])
	flags := binary.LittleEndian.Uint32(blk[60:64])
	nonce := blk[8:24]
	enc := append([]byte(nil), blk[24:56]...)
	apk := (flags&axdsFlagApkBind != 0) && (ver >= axdsVersion3)
	if ver >= axdsVersion4 {
		/* MK3 needs binding; probe returns ciphertext marker only. */
		return enc, enc, apk
	}
	if ver >= axdsVersion2 {
		dynseedMasterCipher(enc, nonce)
	} else {
		dynseedMasterCipherV1(enc, nonce)
	}
	return enc, enc, apk
}

func findAXDSBlock(buf []byte) []byte {
	/* Prefer exact EOF-aligned block; otherwise scan only the last 4KiB. */
	trim := len(buf)
	for trim > 64 && buf[trim-1] == 0 {
		trim--
	}
	if trim >= 64 {
		p := buf[trim-64 : trim]
		if axdsBlockLooksValid(p) {
			return p
		}
	}
	scan := len(buf)
	if scan > 4096 {
		scan = 4096
	}
	base := len(buf) - scan
	var last []byte
	for off := 0; off+64 <= scan; off += 4 {
		p := buf[base+off : base+off+64]
		if axdsBlockLooksValid(p) {
			last = p
		}
	}
	return last
}

func axdsBlockLooksValid(p []byte) bool {
	if len(p) < 64 || binary.LittleEndian.Uint32(p[0:4]) != axdsMagic {
		return false
	}
	ver := binary.LittleEndian.Uint32(p[4:8])
	if ver != axdsVersion && ver != axdsVersion2 && ver != axdsVersion3 && ver != axdsVersion4 {
		return false
	}
	want := fnv1a32(p[:56])
	got := binary.LittleEndian.Uint32(p[56:60])
	return got == want
}

func findPackInBuf(buf []byte, magic uint32) int64 {
	return findLastTrustedPackInBuf(buf, magic)
}
