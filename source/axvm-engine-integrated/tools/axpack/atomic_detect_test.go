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
		{0xB820001F, "LDADD32"},
		{0x88A07C1F, "CAS32"},
		{0x885F7C00, "LDXR32"},
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

func TestLiftTrueAtomicLdadd(t *testing.T) {
	/* LDADD x0, x1, [x2] */
	bc, err := liftRawInsn([]uint32{0xF8210040}, 0x1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(bc) < 1 || bc[0] != opAtomicLdadd64 {
		t.Fatalf("expected opAtomicLdadd64, got %v", bc)
	}
}

func TestLiftTrueAtomicCas(t *testing.T) {
	/* CAS x0, x1, [x2] */
	bc, err := liftRawInsn([]uint32{0xC8A07C41}, 0x1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(bc) < 1 || bc[0] != opAtomicCas64 {
		t.Fatalf("expected opAtomicCas64, got %v", bc)
	}
}

func TestLiftTrueAtomicLdadd32(t *testing.T) {
	/* LDADD w0, w1, [x2] */
	bc, err := liftRawInsn([]uint32{0xB8210040}, 0x1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(bc) < 1 || bc[0] != opAtomicLdadd32 {
		t.Fatalf("expected opAtomicLdadd32, got %v", bc)
	}
}

func TestLiftLdxpDedicated(t *testing.T) {
	/* LDXP x0, x1, [x2] */
	bc, err := liftRawInsn([]uint32{0xC8600440}, 0x1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(bc) < 1 || bc[0] != opAtomicLdxp64 {
		t.Fatalf("expected opAtomicLdxp64, got %v", bc)
	}
}

func TestLiftFmla4S(t *testing.T) {
	/* FMLA v0.4s, v1.4s, v2.4s */
	bc, err := liftRawInsn([]uint32{0x4E22CC20}, 0x1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(bc) < 1 || bc[0] != opVfma4S {
		t.Fatalf("expected opVfma4S, got %v", bc)
	}
}

func TestLiftLd1Q(t *testing.T) {
	/* LD1 {v0.16b}, [x1] */
	bc, err := liftRawInsn([]uint32{0x4C407020}, 0x1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(bc) < 1 || bc[0] != opFldrQ {
		t.Fatalf("expected opFldrQ from LD1, got %v", bc)
	}
}
