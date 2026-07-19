package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestPrologueVariantsDistinct(t *testing.T) {
	seen := make(map[string]struct{})
	for pid := 0; pid < stubPrologueCount; pid++ {
		lay := stubLayoutForTest(0, pid)
		stub := genStubVariant(7, 0xBEEF, &lay)
		if len(stub) != int(lay.size) {
			t.Fatalf("prologue %d size %d", pid, len(stub))
		}
		/* 跳过公共 STP/MOV 头，比较 prologue 主体（至 funcID 前） */
		end := bytes.Index(stub, []byte{0x20, 0x00, 0x80, 0xD2}) // MOVZ x0,#0 pattern for func 7
		if end < 8 {
			end = 48
		}
		if end > len(stub) {
			end = len(stub)
		}
		key := string(stub[8:end])
		seen[key] = struct{}{}
	}
	if len(seen) < 6 {
		t.Fatalf("prologue bodies too similar: %d unique", len(seen))
	}
}

func TestFPPrologueVariants(t *testing.T) {
	for pid := 0; pid < stubPrologueCount; pid++ {
		lay := stubLayoutForTest(0, pid)
		stub := genStubFPVariant(3, 0xCAFE, &lay)
		disp := int(lay.dispatchOff)
		if disp+24 > len(stub) {
			t.Fatalf("fp prologue %d dispatch oob", pid)
		}
		/* Unpatched slot: B to zero-path, then NOPs; +16 keep-B, +20 MOV X0,XZR. */
		if binary.LittleEndian.Uint32(stub[disp:disp+4]) != 0x14000005 {
			t.Fatalf("fp prologue %d missing safe-zero B at dispatch", pid)
		}
		for i := 4; i < 16; i += 4 {
			if binary.LittleEndian.Uint32(stub[disp+i:disp+i+4]) != arm64NOP {
				t.Fatalf("fp prologue %d missing NOP at %d", pid, disp+i)
			}
		}
		if binary.LittleEndian.Uint32(stub[disp+16:disp+20]) != 0x14000002 {
			t.Fatalf("fp prologue %d missing keep-X0 B", pid)
		}
		if binary.LittleEndian.Uint32(stub[disp+20:disp+24]) != 0xAA1F03E0 {
			t.Fatalf("fp prologue %d missing MOV X0,XZR", pid)
		}
	}
}

func TestPickStubLayoutPrologueSpread(t *testing.T) {
	var prologues, layouts int
	seenP := make(map[uint8]bool)
	seenL := make(map[uint8]bool)
	for i := uint32(0); i < 64; i++ {
		lay := pickStubLayout(i, 0x123456789ABCDEF0)
		seenP[stubPrologueID(lay)] = true
		seenL[stubLayoutIdx(lay)] = true
	}
	for range seenP {
		prologues++
	}
	for range seenL {
		layouts++
	}
	if prologues < 4 || layouts < 2 {
		t.Fatalf("spread prologue=%d layout=%d", prologues, layouts)
	}
}

func TestPrologueMetaRoundtrip(t *testing.T) {
	lay := stubLayoutForTest(2, 5)
	meta := encodeStubMeta(lay.size, lay.dispatchOff, lay.variant)
	dec := decodeStubMeta(meta)
	if dec.size != lay.size || dec.dispatchOff != lay.dispatchOff || dec.variant != lay.variant {
		t.Fatalf("meta %+v lay %+v", dec, lay)
	}
	if stubPrologueID(dec) != 5 || stubLayoutIdx(dec) != 2 {
		t.Fatalf("decode variant bits 0x%02x", dec.variant)
	}
}

func TestClassicPrologueMatchesLegacy(t *testing.T) {
	lay := stubLayoutForTest(0, 0)
	legacy := composeStubVariant(&lay, 1, 0, emitIntPrologue,
		[]uint32{0x910043FF, 0xA8C67BFD, arm64RET}, 0x9E3779B97F4A7C15, true)
	stub := genStub(1, 0)
	if !bytes.Equal(legacy, stub) {
		t.Fatalf("prologue0 drift from legacy genStub")
	}
}

func intPrologueRestoresCallerX0(body []byte) bool {
	if bytes.Contains(body, []byte{0xE1, 0x0B, 0x40, 0xF9}) { // LDR x1,[sp,#16]
		return true
	}
	if bytes.Contains(body, []byte{0xE1, 0x0B, 0x40, 0xA9}) { // LDP x1,x2,[sp,#16]
		return true
	}
	i := bytes.Index(body, []byte{0xF0, 0x03, 0x00, 0xAA}) // MOV x16,x0
	j := bytes.Index(body, []byte{0xE1, 0x03, 0x10, 0xAA}) // MOV x1,x16
	return i >= 0 && j > i
}

func TestDispatchSlotAfterFuncID(t *testing.T) {
	for pid := 0; pid < stubPrologueCount; pid++ {
		for _, base := range stubLayoutTable {
			lay := base
			lay.variant = uint8((pid << 4) | int(lay.variant&0x0F))
			stub := genStubVariant(5, 0xBEEF, &lay)
			disp := int(lay.dispatchOff)
			if disp+16 > len(stub) {
				t.Fatalf("pid=%d layout=%d dispatch oob", pid, stubLayoutIdx(lay))
			}
			movz := []byte{0xa0, 0x00, 0x80, 0xd2} // MOVZ x0,#5
			idx := bytes.Index(stub[:disp], movz)
			if idx < 0 {
				t.Fatalf("pid=%d layout=%d: MOVZ before dispatch missing", pid, stubLayoutIdx(lay))
			}
			if idx+4 > disp {
				t.Fatalf("pid=%d layout=%d: MOVZ overlaps dispatch at %d", pid, stubLayoutIdx(lay), disp)
			}
		}
	}
}

func TestIntPrologueMapsCallerX0ToDispatchA0(t *testing.T) {
	for pid := 0; pid < stubPrologueCount; pid++ {
		lay := stubLayoutForTest(0, pid)
		stub := genStubVariant(1, 0xBEEF, &lay)
		end := bytes.Index(stub, []byte{0x20, 0x00, 0x80, 0xD2}) // MOVZ x0,#1
		if end < 0 {
			t.Fatalf("prologue %d: missing func id movz", pid)
		}
		if !intPrologueRestoresCallerX0(stub[:end]) {
			t.Fatalf("prologue %d: x1 does not restore caller x0", pid)
		}
	}
}
