package main

import (
	"bytes"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
)

func TestVictimAddBytecodeRoundtrip(t *testing.T) {
	raw, err := os.ReadFile("../../build-ndk-arm64/samples/victim/libvictim.so")
	if err != nil {
		t.Skip(err)
	}
	ef, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	funcs, err := collectFuncs(ef, raw, map[string]bool{"victim_add": true})
	if err != nil || len(funcs) == 0 {
		t.Fatal(err)
	}
	bc, _, _, err := liftFunc(funcs[0].OrigCode, funcs[0].Addr)
	if err != nil {
		t.Fatal(err)
	}
	wrapped := wrapBytecode(bc, 0, 0)
	seed := wrapped[28:44]
	crypt(wrapped[40:], seed, 0, 1)
	enc := append([]byte(nil), wrapped[40:]...)
	crypt(wrapped[40:], seed, 0, 1)
	if !bytes.Equal(wrapped[40:], bc) {
		t.Fatalf("decrypt mismatch got %s want %s", hex.EncodeToString(wrapped[40:]), hex.EncodeToString(bc))
	}
	fmt.Printf("raw=%s enc=%s dec=%s\n", hex.EncodeToString(bc), hex.EncodeToString(enc), hex.EncodeToString(wrapped[40:]))
	if wrapped[44] != 0x50 {
		t.Fatalf("ret byte got 0x%02x", wrapped[44])
	}
}
