package main

import (
	"encoding/binary"
	"testing"
)

func TestPackManifestMACDetectsTamper(t *testing.T) {
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(i + 1)
	}
	funcs := []fnInfo{
		{
			Name:    "f",
			Addr:    0x1000,
			Size:    4,
			BC:      []byte{opRet},
			EntryPC: 0,
		},
	}
	pack, _, _ := buildPackAndStubs(funcs, true, false, master, false, axpkMagic)
	want := binary.LittleEndian.Uint32(pack[44:48])
	if want == 0 {
		t.Fatal("manifest MAC must be set")
	}
	if got := axpkManifestMAC32(pack); got != want {
		t.Fatalf("manifest MAC mismatch got=%08x want=%08x", got, want)
	}

	tampered := append([]byte(nil), pack...)
	tampered[len(tampered)-1] ^= 0x5A
	if axpkManifestMAC32(tampered) == want {
		t.Fatal("tamper should change manifest MAC")
	}
}
