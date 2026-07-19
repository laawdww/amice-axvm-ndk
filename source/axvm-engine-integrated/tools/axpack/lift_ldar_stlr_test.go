package main

import (
	"encoding/binary"
	"testing"
)

func liftOneWord(t *testing.T, word uint32) liftedInsn {
	t.Helper()
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], word)
	cache := &relocCache{}
	var fp bool
	li, err := decodeInsnAt(buf[:], 0, 0x1000, cache, nil, &fp)
	if err != nil {
		t.Fatalf("lift 0x%08X: %v", word, err)
	}
	return li
}

func TestLiftLdarStlr(t *testing.T) {
	cases := []struct {
		name  string
		word  uint32
		want0 byte
	}{
		{"ldar_x", 0xC8DFFC20, opLdrU64},   /* ldar x0, [x1] */
		{"stlr_x", 0xC89FFC20, opStrU64},   /* stlr x0, [x1] */
		{"ldar_w", 0x88DFFC20, opLdrU32},   /* ldar w0, [x1] */
		{"stlr_w", 0x889FFC20, opStrU32},   /* stlr w0, [x1] */
		{"ldarb", 0x08DFFC20, opLdrU8},     /* ldarb w0, [x1] */
		{"stlrb", 0x089FFC20, opStrU8},     /* stlrb w0, [x1] */
		{"ldarh", 0x48DFFC20, opLdrU16},    /* ldarh w0, [x1] */
		{"stlrh", 0x489FFC20, opStrU16},    /* stlrh w0, [x1] */
		{"ldapr_x", 0xC8BFFC20, opLdrU64},  /* ldapr x0, [x1] */
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			li := liftOneWord(t, tc.word)
			if len(li.bytes) < 1 || li.bytes[0] != tc.want0 {
				t.Fatalf("got %v want opcode 0x%02X", li.bytes, tc.want0)
			}
		})
	}
}

func TestLiftNarrowWriteback(t *testing.T) {
	/* ldrb w0, [x1], #1  — post-index */
	word := uint32(0x38401420) /* imm9=1, mode=01, Rn=1, Rt=0 */
	li := liftOneWord(t, word)
	if len(li.bytes) < 2 || li.bytes[0] != opLdrU8 {
		t.Fatalf("expected LDRB then WB, got %v", li.bytes)
	}
	foundAdd := false
	for i := 0; i+2 < len(li.bytes); i++ {
		if li.bytes[i] == opAddImm && li.bytes[i+1] == 1 && li.bytes[i+2] == 1 {
			foundAdd = true
			break
		}
	}
	if !foundAdd {
		t.Fatalf("missing ADD writeback in %v", li.bytes)
	}
}

func TestLiftAddsShifted(t *testing.T) {
	/* adds x0, x1, x2 */
	li := liftOneWord(t, 0xAB020020)
	if len(li.bytes) < 4 || li.bytes[0] != opAddReg {
		t.Fatalf("expected ADD then CMP, got %v", li.bytes)
	}
	foundCmp := false
	for i := 0; i+2 < len(li.bytes); i++ {
		if li.bytes[i] == opCmpReg && li.bytes[i+1] == 0 {
			foundCmp = true
			break
		}
	}
	if !foundCmp {
		t.Fatalf("missing CMP after ADDS: %v", li.bytes)
	}
}

func TestLiftScvtfDX(t *testing.T) {
	/* scvtf d0, x1 */
	li := liftOneWord(t, 0x9E620020)
	if len(li.bytes) < 1 || li.bytes[0] != opFmovDX {
		t.Fatalf("SCVTF D,X: got %v", li.bytes)
	}
}
