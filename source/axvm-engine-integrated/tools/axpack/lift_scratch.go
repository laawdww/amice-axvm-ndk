package main

func chunkWritesScratch(code []byte) bool {
	for i := 0; i < len(code); {
		op := code[i]
		if op == opJunk {
			if i+2 > len(code) || i+2+int(code[i+1]) > len(code) {
				return false
			}
			i += 2 + int(code[i+1])
			continue
		}
		olen, ok := opOperandLen(op)
		if !ok || i+1+olen > len(code) {
			return false
		}
		dstAt := -1
		switch op {
		case opLdri64, opLdri64Vaddr,
			opAddImm, opSubImm,
			opAddReg, opSubReg, opAndReg, opOrrReg, opEorReg,
			opLslImm, opLsrImm, opMulReg, opUdivReg, opSdivReg, opCselReg, opMovk,
			opLdrU64, opLdrU32, opLdurU64, opLdurU32, opLdrU8, opLdrU16,
			opMovReg, opMvnReg, opAsrImm, opLdrRegOff, opZext32,
			opFmovXBits, opFcvtzsD:
			dstAt = i + 1
		}
		if dstAt >= 0 {
			rd := code[dstAt]
			if rd == scratchReg0 || rd == scratchReg1 {
				return true
			}
		}
		i += 1 + olen
	}
	return false
}

func armInsnWritesReg(word uint32, reg byte) bool {
	rd := byte(word & 0x1F)

	/* Branches, compares/tests, and stores do not write Rd even if low bits match. */
	if ((word&0x7C000000) == 0x14000000 || // B/BL
		(word&0x7E000000) == 0x34000000 || // CBZ/CBNZ
		(word&0x7E000000) == 0x36000000 || // TBZ/TBNZ
		(word&0xFF000010) == 0x54000000 || // B.cond
		(word&0xFFFFFC1F) == 0xD65F0000 || // RET/BR/BLR family with no Rd
		(word&0x7F000000) == 0x71000000 || // CMP/SUBS imm 32-bit
		(word&0xFF000000) == 0xF1000000 || // CMP/SUBS imm 64-bit
		(word&0x7FE00000) == 0x6B000000 || // CMP/SUBS reg 32-bit
		(word&0xFFE00000) == 0xEB000000 || // CMP/SUBS reg 64-bit
		(word&0xFFC00000) == 0xB9000000 || // STR W unsigned
		(word&0xFFC00000) == 0xF9000000 || // STR X unsigned
		(word&0xFFC00000) == 0x39000000 || // STRB unsigned
		(word&0xFFC00000) == 0x79000000 || // STRH unsigned
		(word&0xFFC00000) == 0xB8000000 || // STUR W
		(word&0xFFC00000) == 0xF8000000 || // STUR X
		(word&0xFFC00000) == 0x38000000 || // STURB
		(word&0xFFC00000) == 0x78000000 || // STURH
		(word&0x3B600C00) == 0x38200800) { // STR register offset family, L bit clear
		return false
	}

	if rd == reg {
		return true
	}

	/* Load-pair writes Rt and Rt2. Store-pair is filtered by bit 22 == 0. */
	if (word&0x3B000000) == 0x29000000 || (word&0x3B000000) == 0x28000000 {
		if ((word >> 22) & 1) == 1 {
			rt2 := byte((word >> 10) & 0x1F)
			return rd == reg || rt2 == reg
		}
	}
	return false
}
