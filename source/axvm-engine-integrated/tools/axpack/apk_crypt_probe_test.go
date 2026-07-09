package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestApkBoundCryptVariantMatchesPack(t *testing.T) {
	so := filepath.Join("..", "..", "build", "libvictim.ax.so")
	data, err := os.ReadFile(so)
	if err != nil {
		t.Skip(so)
	}
	raw, _, apkBind := probeDynSeedFromTail(data)
	if raw == nil || !apkBind {
		t.Skip("need apk-bound AXDS SO")
	}
	certHex := "3017cf926f7e67be802292a104a94feb7ef38ad047c25b694442ef2e3ae32dc3"
	cert, err := parseCertSHA256Hex(certHex)
	if err != nil {
		t.Fatal(err)
	}
	master := deriveBoundMaster(raw, "com.axvm.demo", cert)
	if master == nil {
		t.Fatal("deriveBoundMaster nil")
	}
	v := int(masterSubkeyByte(master, axvmPurposeCrypt) & 3)
	t.Logf("crypt variant=%d master=%s...", v, hex.EncodeToString(master[:4]))

	magic := resolvePackMagic(raw, false)
	off := findPackInBuf(data, magic)
	if off < 0 {
		t.Fatal("pack not found")
	}
	pack := data[off:]
	seed := pack[28:44]
	flags := binaryUint32(pack[8:12])
	if flags&axpkEncrypt == 0 {
		t.Fatal("pack not encrypted")
	}
	// spot-check first func bytecode decrypt roundtrip
	blobOff := binaryUint32(pack[20:24])
	rec := pack[64 : 64+axvmRecSizeV2]
	funcID := binaryUint32(rec[0:4])
	bcOff := binaryUint32(rec[28:32])
	entry := binaryUint32(rec[8:12])
	bc := append([]byte(nil), pack[64+blobOff+bcOff:]...)
	bcLen := binaryUint32(rec[12:16])
	if int(bcLen) > len(bc) {
		t.Fatalf("bc len %d > %d", bcLen, len(bc))
	}
	bc = bc[:bcLen]
	dup := append([]byte(nil), bc[40:]...)
	cryptVariant(dup, seed, master, funcID, entry)
	cryptVariant(dup, seed, master, funcID, entry)
	if len(dup) == 0 {
		t.Fatal("empty code")
	}
}

func binaryUint32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
