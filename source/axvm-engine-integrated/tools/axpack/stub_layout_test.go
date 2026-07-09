package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"testing"
)

func TestStubLayout(t *testing.T) {
	stub := genStub(1, 0)
	if len(stub) != int(stubSizeDefault) {
		t.Fatalf("stub size %d", len(stub))
	}
	lay := stubLayoutTable[0]
	if int(lay.dispatchOff)+16 > len(stub) {
		t.Fatal("dispatch slot oob")
	}
	// MOVZ x0,#1 then NOP pad to 64
	if binary.LittleEndian.Uint32(stub[stubFuncIDOff:stubFuncIDOff+4]) != 0xD2800020 {
		t.Fatalf("missing movz at %d: %08x", stubFuncIDOff,
			binary.LittleEndian.Uint32(stub[stubFuncIDOff:stubFuncIDOff+4]))
	}
	if binary.LittleEndian.Uint32(stub[80:84]) != 0xA8C67BFD {
		t.Fatalf("missing epilogue at 80: %08x", binary.LittleEndian.Uint32(stub[80:84]))
	}
}

func TestVictimCheckBytecode(t *testing.T) {
	raw, err := os.ReadFile("../../build-ndk-arm64/samples/victim/libvictim.so")
	if err != nil {
		t.Skip(err)
	}
	ef, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	funcs, err := collectFuncs(ef, raw, map[string]bool{"victim_check": true})
	if err != nil || len(funcs) == 0 {
		t.Fatal(err)
	}
	bc, _, _, err := liftFunc(funcs[0].OrigCode, funcs[0].Addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("native=%x", funcs[0].OrigCode)
	t.Logf("bc=%x", bc)
}

func TestStubDispatchOffset(t *testing.T) {
	lay := stubLayoutTable[0]
	buf := bytes.NewBuffer(nil)
	buf.Write(genStubVariant(1, 0, &lay))
	off := int(lay.dispatchOff)
	slot := buf.Bytes()[off : off+16]
	for i := 0; i < 16; i += 4 {
		if binary.LittleEndian.Uint32(slot[i:i+4]) != arm64NOP {
			t.Fatalf("expected NOP pad at %d", off+i)
		}
	}
}
