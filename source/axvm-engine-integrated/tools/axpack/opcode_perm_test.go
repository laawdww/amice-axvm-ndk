package main

import "testing"

func TestOpcodePermBijection(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i*7 + 3)
	}
	fwd, inv := opcodePermBuild(key)
	var seen [256]bool
	for i := 0; i < 256; i++ {
		if inv[fwd[i]] != byte(i) {
			t.Fatalf("inv∘fwd mismatch at %d", i)
		}
		if seen[fwd[i]] {
			t.Fatalf("fwd not a permutation: dup %d", fwd[i])
		}
		seen[fwd[i]] = true
	}
}

func TestOpcodePermIdentityNoKey(t *testing.T) {
	fwd, inv := opcodePermBuild(nil)
	for i := 0; i < 256; i++ {
		if fwd[i] != byte(i) || inv[i] != byte(i) {
			t.Fatalf("expected identity at %d", i)
		}
	}
}

func TestOpcodeStreamWalkAndPermuteRoundTrip(t *testing.T) {
	// LDRI64 x1,#5 ; ADD_IMM x0,x1,#1 ; CMP x0,x1 ; RET
	code := []byte{
		opLdri64, 1, 5, 0, 0, 0, 0, 0, 0, 0,
		opAddImm, 0, 1, 1, 0, 0, 0,
		opCmpReg, 0, 1,
		opRet,
	}
	if !opcodeStreamValid(code) {
		t.Fatal("stream should be valid")
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	fwd, inv := opcodePermBuild(key)

	orig := append([]byte(nil), code...)
	permuteOpcodes(code, fwd)

	// 操作数字节不变（偏移 1..9 属 LDRI64 操作数，11 属 ADD_IMM 的 rd）
	if code[1] != orig[1] || code[11] != orig[11] || code[18] != orig[18] {
		t.Fatal("operand bytes must not change")
	}
	// 逆置换还原
	i := 0
	for i < len(code) {
		got := inv[code[i]]
		if got != orig[i] {
			t.Fatalf("opcode round-trip mismatch at %d: %#x vs %#x", i, got, orig[i])
		}
		n, _ := opOperandLen(got)
		i += 1 + n
	}
}

func TestOpcodeStreamInvalidRejected(t *testing.T) {
	if opcodeStreamValid([]byte{0xEE}) {
		t.Fatal("unknown opcode must be rejected")
	}
	if opcodeStreamValid([]byte{opLdri64, 1, 2}) {
		t.Fatal("truncated instruction must be rejected")
	}
}
