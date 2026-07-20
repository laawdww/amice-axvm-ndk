package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestPackVictimAddCryptRoundtrip(t *testing.T) {
	victim, err := os.ReadFile(filepath.Join("..", "..", "build-verify-arm64", "samples", "victim", "libvictim.so"))
	if err != nil {
		t.Skip(err)
	}
	ef, err := elf.NewFile(bytes.NewReader(victim))
	if err != nil {
		t.Fatal(err)
	}
	funcs, err := collectFuncs(ef, victim, map[string]bool{"victim_add": true})
	if err != nil {
		t.Fatal(err)
	}
	if err := liftFuncBatch(funcs); err != nil {
		t.Fatal(err)
	}
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(i + 3)
	}
	pack, _, _ := buildPackAndStubs(funcs, true, false, master, true, axpkMagic)
	hdr := pack[:64]
	seed := append([]byte(nil), hdr[28:44]...)
	wire := append([]byte(nil), funcs[0].BC...)
	wire = injectJunkMicro(wire, master)
	fwdPre, _ := opcodePermBuild(master)
	permuteOpcodes(wire, fwdPre)
	buf := append([]byte(nil), wire...)
	cryptVariant(buf, seed, master, 1, 0)
	cryptVariant(buf, seed, master, 1, 0)
	if !bytes.Equal(buf, wire) {
		t.Fatalf("wire roundtrip failed got %x want %x", buf, wire)
	}
	rec := pack[64:136]
	bcOff := binary.LittleEndian.Uint32(rec[28:])
	bcSize := binary.LittleEndian.Uint32(rec[12:])
	blobOff := binary.LittleEndian.Uint32(hdr[20:])
	bc := append([]byte(nil), pack[blobOff+bcOff:blobOff+bcOff+bcSize]...)
	codeOff := binary.LittleEndian.Uint32(bc[12:])
	codeSize := binary.LittleEndian.Uint32(bc[16:])
	enc := append([]byte(nil), bc[codeOff:codeOff+codeSize]...)
	plain := append([]byte(nil), enc...)
	cryptVariant(plain, seed, master, 1, 0)
	_, inv := opcodePermBuild(master)
	i := 0
	for i < len(plain) {
		logical := inv[plain[i]]
		if logical == opJunk {
			if i+1 >= len(plain) {
				t.Fatalf("truncated junk at %d", i)
			}
			pad := int(plain[i+1])
			plain[i] = logical
			i += 2 + pad
			continue
		}
		n, ok := opOperandLen(logical)
		if !ok {
			t.Fatalf("bad op wire=%02x logical=%02x at %d", plain[i], logical, i)
		}
		plain[i] = logical
		i += 1 + n
	}
	if i != len(plain) {
		t.Fatalf("length mismatch walked=%d len=%d", i, len(plain))
	}
	if !opcodeStreamValid(plain) {
		t.Fatalf("invalid logical stream %x", plain)
	}
}

func TestCryptVariantRoundtripSingleByte(t *testing.T) {
	seed := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(i + 1)
	}
	for v := 0; v <= 3; v++ {
		orig := []byte{0x42}
		ref := append([]byte(nil), orig...)
		buf := append([]byte(nil), orig...)
		cryptVariant(buf, seed, master, 7, 0)
		if bytes.Equal(buf, ref) {
			t.Fatalf("variant %d did not change buffer", v)
		}
		cryptVariant(buf, seed, master, 7, 0)
		if !bytes.Equal(buf, ref) {
			t.Fatalf("variant %d single-byte roundtrip failed", v)
		}
	}
}

func TestStextCryptRoundtrip(t *testing.T) {
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(i + 0x11)
	}
	buf := []byte("wipe-tail-bytes-sample-data!!")
	ref := append([]byte(nil), buf...)
	stextCryptRange(buf, master, 3)
	if bytes.Equal(buf, ref) {
		t.Fatal("stext crypt did not change buffer")
	}
	stextCryptRange(buf, master, 3)
	if !bytes.Equal(buf, ref) {
		t.Fatal("stext crypt roundtrip failed")
	}
}

func TestResealPackManifestAfterWrap(t *testing.T) {
	pack := make([]byte, 96)
	copy(pack[0:4], []byte("AXPK"))
	binary.LittleEndian.PutUint32(pack[4:8], axpkVersionV2)
	binary.LittleEndian.PutUint32(pack[8:12], axpkEncrypt)
	binary.LittleEndian.PutUint32(pack[12:16], 1)  // func_count
	binary.LittleEndian.PutUint32(pack[16:20], 64) // table_off
	binary.LittleEndian.PutUint32(pack[20:24], 80) // blob_off
	binary.LittleEndian.PutUint32(pack[24:28], 16) // blob_size
	for i := 0; i < 16; i++ {
		pack[28+i] = byte(i + 1)
	}
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(0xA0 + i)
	}
	sealPackManifestMAC(pack)
	plainMAC := binary.LittleEndian.Uint32(pack[44:48])
	if plainMAC == 0 {
		t.Fatal("plain seal produced zero MAC")
	}
	if !packManifestTrusted(pack) {
		t.Fatal("plain pack not trusted")
	}
	wrapPackKeySeed(pack, master)
	if binary.LittleEndian.Uint32(pack[8:12])&axpkSeedWrapped == 0 {
		t.Fatal("expected SEED_WRAPPED")
	}
	/* Naive reseal with wrapped seed on disk would diverge from C verify. */
	bad := append([]byte(nil), pack...)
	sealPackManifestMAC(bad)
	resealPackManifestMAC(pack, master)
	if binary.LittleEndian.Uint32(pack[8:12])&axpkSeedWrapped == 0 {
		t.Fatal("reseal must re-wrap")
	}
	want := binary.LittleEndian.Uint32(pack[44:48])
	badMAC := binary.LittleEndian.Uint32(bad[44:48])
	if want == 0 {
		t.Fatal("reseal produced zero MAC")
	}
	if want == badMAC {
		t.Fatal("naive seal-after-wrap must differ from plaintext-seed MAC")
	}
	/* Simulate C: unwrap then MAC */
	unwrapped := append([]byte(nil), pack...)
	unwrapPackKeySeed(unwrapped, master)
	got := axpkManifestMAC32(unwrapped)
	if got != want {
		t.Fatalf("C-style verify mismatch want=%08x got=%08x", want, got)
	}
	if got != plainMAC {
		/* file_off / table may differ — here identical body, so equal */
		t.Fatalf("reseal MAC %08x != original plain %08x", got, plainMAC)
	}
}
