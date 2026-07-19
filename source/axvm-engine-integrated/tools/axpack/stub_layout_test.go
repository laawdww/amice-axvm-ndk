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
	if int(lay.dispatchOff)+24 > len(stub) {
		t.Fatal("dispatch slot oob")
	}
	// MOVZ x0,#1 then NOP pad to 64
	if binary.LittleEndian.Uint32(stub[stubFuncIDOff:stubFuncIDOff+4]) != 0xD2800020 {
		t.Fatalf("missing movz at %d: %08x", stubFuncIDOff,
			binary.LittleEndian.Uint32(stub[stubFuncIDOff:stubFuncIDOff+4]))
	}
	lay = pickStubLayout(1, 0)
	stub2 := genStubVariant(1, 0, &lay)
	epi := int(lay.dispatchOff) + 24 /* after keep/zero bridge */
	if binary.LittleEndian.Uint32(stub2[epi:epi+4]) != 0x910043FF {
		t.Fatalf("missing add sp,#16 at %d: %08x", epi,
			binary.LittleEndian.Uint32(stub2[epi:epi+4]))
	}
	if binary.LittleEndian.Uint32(stub2[epi+4:epi+8]) != 0xA8C67BFD {
		t.Fatalf("missing ldp epilogue at %d: %08x", epi+4,
			binary.LittleEndian.Uint32(stub2[epi+4:epi+8]))
	}
	_ = stub
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
	slot := buf.Bytes()[off : off+24]
	if binary.LittleEndian.Uint32(slot[0:4]) != 0x14000005 {
		t.Fatalf("expected safe-zero B at dispatch, got %08x", binary.LittleEndian.Uint32(slot[0:4]))
	}
	for i := 4; i < 16; i += 4 {
		if binary.LittleEndian.Uint32(slot[i:i+4]) != arm64NOP {
			t.Fatalf("expected NOP pad at %d", off+i)
		}
	}
	if binary.LittleEndian.Uint32(slot[16:20]) != 0x14000002 {
		t.Fatalf("expected keep-X0 B")
	}
	if binary.LittleEndian.Uint32(slot[20:24]) != 0xAA1F03E0 {
		t.Fatalf("expected MOV X0,XZR")
	}
}

func TestStubUnpatchedReturnsZeroNotFuncID(t *testing.T) {
	/* Document the ABI hazard: unpatched NOP-only slots returned func_id in X0. */
	lay := stubLayoutForTest(0, 0)
	stub := genStubVariant(0x41, 0xBEEF, &lay)
	disp := int(lay.dispatchOff)
	if binary.LittleEndian.Uint32(stub[disp:disp+4]) == arm64NOP {
		t.Fatal("unpatched slot must not be NOP-only (func_id leak)")
	}
	if binary.LittleEndian.Uint32(stub[disp+20:disp+24]) != 0xAA1F03E0 {
		t.Fatal("missing null-return on unpatched fallthrough")
	}
}
