package main

import (
	"encoding/binary"
	"testing"
)

func TestStubLayoutVariants(t *testing.T) {
	for _, lay := range stubLayoutTable {
		stub := genStubVariant(42, 0x1234, &lay)
		if len(stub) != int(lay.size) {
			t.Fatalf("variant %d size got %d want %d", lay.variant, len(stub), lay.size)
		}
		disp := int(lay.dispatchOff)
		if disp+16 > len(stub) {
			t.Fatalf("variant %d dispatch oob", lay.variant)
		}
		for i := 0; i < 16; i += 4 {
			word := binary.LittleEndian.Uint32(stub[disp+i : disp+i+4])
			if word != arm64NOP {
				t.Fatalf("variant %d dispatch slot @%d got 0x%08X want NOP", lay.variant, disp+i, word)
			}
		}
		meta := encodeStubMeta(lay.size, lay.dispatchOff, lay.variant)
		dec := decodeStubMeta(meta)
		if dec.size != lay.size || dec.dispatchOff != lay.dispatchOff {
			t.Fatalf("meta roundtrip variant %d", lay.variant)
		}
	}
}

func TestEncodeStubMetaDefault(t *testing.T) {
	d := decodeStubMeta(0)
	if d.size != stubSizeDefault || d.dispatchOff != stubDispatchFixed {
		t.Fatalf("default meta")
	}
}
