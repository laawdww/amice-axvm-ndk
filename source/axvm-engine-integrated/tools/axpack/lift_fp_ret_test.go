package main

import (
	"encoding/binary"
	"testing"
)

func TestLiftFpRetSyncsV0ToX0(t *testing.T) {
	/* FADD D0, D0, D1 ; RET — MODULE_F regression: RET must see x0 = bits(v0). */
	code := make([]byte, 8)
	binary.LittleEndian.PutUint32(code[0:], 0x1E612800) /* FADD D0, D0, D1 */
	binary.LittleEndian.PutUint32(code[4:], arm64RET)

	bc, _, fp, err := liftFunc(code, 0x1000)
	if err != nil {
		t.Fatal(err)
	}
	if !fp {
		t.Fatal("expected UsesFP")
	}
	found := false
	for i := 0; i+3 < len(bc); i++ {
		if bc[i] == opFmovXBits && bc[i+1] == 0 && bc[i+2] == 0 && bc[i+3] == opRet {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("missing FMOV_X_BITS x0,v0 before RET in %x", bc)
	}
}

func TestLiftIntRetUnchanged(t *testing.T) {
	/* ADD X0, X0, X1 ; RET — must not inject FP sync. */
	code := make([]byte, 8)
	binary.LittleEndian.PutUint32(code[0:], 0x8B010000) /* ADD X0, X0, X1 */
	binary.LittleEndian.PutUint32(code[4:], arm64RET)

	bc, _, fp, err := liftFunc(code, 0x1000)
	if err != nil {
		t.Fatal(err)
	}
	if fp {
		t.Fatal("integer add should not set UsesFP")
	}
	for i := 0; i < len(bc); i++ {
		if bc[i] == opFmovXBits {
			t.Fatalf("unexpected FMOV_X_BITS in int lift: %x", bc)
		}
	}
}
