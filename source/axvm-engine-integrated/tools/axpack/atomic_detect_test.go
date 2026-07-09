package main

import (
	"encoding/binary"
	"testing"
)

func TestClassifyAtomicInsn(t *testing.T) {
	cases := []struct {
		word   uint32
		family string
	}{
		{0xC85F7C00, "LDXR"},  /* LDXR x0, [x0] */
		{0xC8007C1F, "STXR"},  /* STXR w0, x0, [x0] */
		{0xF820001F, "LDADD"}, /* LDADD x0, x0, [x0] */
		{0xC8A07C1F, "CAS"},   /* CAS x0, x0, [x0] */
	}
	for _, c := range cases {
		fam, ok := classifyAtomicInsn(c.word)
		if !ok || fam != c.family {
			t.Fatalf("word 0x%08X got %q ok=%v want %q", c.word, fam, ok, c.family)
		}
	}
	if fam, ok := classifyAtomicInsn(arm64NOP); ok {
		t.Fatalf("NOP classified as %s", fam)
	}
}

func TestDiagnoseAtomicApprox(t *testing.T) {
	code := make([]byte, 8)
	binary.LittleEndian.PutUint32(code[0:], 0xC85F7C00)
	binary.LittleEndian.PutUint32(code[4:], arm64NOP)
	hits := diagnoseAtomicApprox(code)
	if len(hits) != 1 || hits[0].Family != "LDXR" || hits[0].Offset != 0 {
		t.Fatalf("hits=%+v", hits)
	}
}
