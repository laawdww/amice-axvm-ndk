package main

import "testing"

func TestLiftPrevFailFPOps(t *testing.T) {
	words := []uint32{
		0x1E604028, // fmov d8, d1
		0x1E604120, // fmov d0, d9
		0x1E604100, // fmov d0, d8
		0x1E6301C3, // ucvtf d3, w14
		0x1E601C28, // fcsel d8, d1, d0, ne
		0x1E614001, // fneg d1, d0
		0xFC746B60, // ldr d0, [x27, x20]
	}
	var fp bool
	for _, w := range words {
		li, ok := tryDecodeFloatInsn(w, 0, &fp)
		if !ok || len(li.bytes) == 0 {
			t.Fatalf("failed to lift 0x%08X", w)
		}
	}
	if !fp {
		t.Fatal("fpUsed not set")
	}
}
