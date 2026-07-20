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
	cert := make([]byte, 32)
	for i := range cert {
		cert[i] = byte(0xA0 + i)
	}
	pkg := "com.example.iauuwnno"
	blk := buildDynSeedBlock(raw, true, pkg, cert)
	if len(blk) != axdsSize {
		t.Fatalf("size %d", len(blk))
	}
	if binary.LittleEndian.Uint32(blk[4:]) != axdsVersion4 {
		t.Fatalf("version 0x%x want v4", binary.LittleEndian.Uint32(blk[4:]))
	}
	if binary.LittleEndian.Uint32(blk[60:]) != axdsFlagApkBind {
		t.Fatalf("flags 0x%x", binary.LittleEndian.Uint32(blk[60:]))
	}
	/* Nonce alone must NOT recover rawSeed (MK3). */
	nonce := blk[8:24]
	enc := append([]byte(nil), blk[24:56]...)
	dynseedMasterCipher(enc, nonce) /* wrong: MK2 */
	if bytesEqual32(enc, raw) {
		t.Fatal("MK2 must not decrypt MK3 block")
	}
	enc = append([]byte(nil), blk[24:56]...)
	wrap := axdsWrapKey(pkg, cert)
	dynseedMasterCipherV3(enc, nonce, wrap)
	if !bytesEqual32(enc, raw) {
		t.Fatal("MK3+wrapKey should recover rawSeed")
	}
	enc = append([]byte(nil), blk[24:56]...)
	wrong := axdsWrapKey("com.other.app", cert)
	dynseedMasterCipherV3(enc, nonce, wrong)
	if bytesEqual32(enc, raw) {
		t.Fatal("wrong package must not decrypt")
	}
}

func TestBuildDynSeedBlockNoBind(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 3)
	}
	blk := buildDynSeedBlock(raw, false, "", nil)
	if binary.LittleEndian.Uint32(blk[4:]) != axdsVersion2 {
		t.Fatalf("version 0x%x", binary.LittleEndian.Uint32(blk[4:]))
	}
	nonce := blk[8:24]
	enc := append([]byte(nil), blk[24:56]...)
	dynseedMasterCipher(enc, nonce)
	if !bytesEqual32(enc, raw) {
		t.Fatal("legacy MK2 roundtrip")
	}
}

func bytesEqual32(a, b []byte) bool {
	if len(a) < 32 || len(b) < 32 {
		return false
	}
	for i := 0; i < 32; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
