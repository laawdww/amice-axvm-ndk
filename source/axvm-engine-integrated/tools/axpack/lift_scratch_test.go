package main

import "testing"

func TestArmInsnWritesScratchForRegOffsetLoad(t *testing.T) {
	if !armInsnWritesReg(0xb867d851, scratchReg1) { // ldr w17, [x2, w7, sxtw #2]
		t.Fatalf("register-offset LDR into w17 must be treated as writing scratchReg1")
	}
	if armInsnWritesReg(0xb827d851, scratchReg1) { // str w17, [x2, w7, sxtw #2]
		t.Fatalf("register-offset STR must not be treated as writing scratchReg1")
	}
}
