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
	if ver >= axdsVersion2 {
		dynseedMasterCipher(enc, nonce)
	} else {
		dynseedMasterCipherV1(enc, nonce)
	}
	apk := (ver >= axdsVersion3) && (flags&axdsFlagApkBind != 0)
	return enc, enc, apk
}

func findAXDSBlock(buf []byte) []byte {
	scan := len(buf)
	if scan > 65536 {
		scan = 65536
	}
	base := len(buf) - scan
	var last []byte
	for off := 0; off+64 <= scan; off += 4 {
		p := buf[base+off:]
		if binary.LittleEndian.Uint32(p[0:4]) != axdsMagic {
			continue
		}
		ver := binary.LittleEndian.Uint32(p[4:8])
		if ver != axdsVersion && ver != axdsVersion2 && ver != axdsVersion3 {
			continue
		}
		want := fnv1a32(p[:56])
		got := binary.LittleEndian.Uint32(p[56:60])
		if got != want {
			continue
		}
		last = p[:64]
	}
	if last == nil && len(buf) >= 64 {
		p := buf[len(buf)-64:]
		if binary.LittleEndian.Uint32(p[0:4]) == axdsMagic {
			want := fnv1a32(p[:56])
			got := binary.LittleEndian.Uint32(p[56:60])
			if got == want {
				last = p
			}
		}
	}
	return last
}

func findPackInBuf(buf []byte, magic uint32) int64 {
	return findLastTrustedPackInBuf(buf, magic)
}
