package main

func liftAddSubExtended(word uint32, off int, op byte, is32 bool, setFlags bool, cache *relocCache) (liftedInsn, error) {
	rd := byte(word & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	rm := byte((word >> 16) & 0x1F)
	amount := byte((word >> 10) & 0x7)
	option := byte((word >> 13) & 0x7)
	if amount > 4 {
		return liftedInsn{}, unsupportedInsn{off, word, "ADD_EXT", "invalid extend shift"}
	}
	tmp, maskReg, ok := pickTwoScratch(rd, rn, rm)
	if !ok {
		return liftedInsn{}, unsupportedInsn{off, word, "ADD_EXT", "scratch register unavailable"}
	}

	bc := []byte{opMovReg, tmp, rm}
	switch option {
	case 0: /* UXTB */
		bc = append(bc, cache.imm64BC(maskReg, 0xFF)...)
		bc = append(bc, opAndReg, tmp, tmp, maskReg)
	case 1: /* UXTH */
		bc = append(bc, cache.imm64BC(maskReg, 0xFFFF)...)
		bc = append(bc, opAndReg, tmp, tmp, maskReg)
	case 2: /* UXTW */
		bc = append(bc, cache.imm64BC(maskReg, 0xFFFFFFFF)...)
		bc = append(bc, opAndReg, tmp, tmp, maskReg)
	case 3: /* UXTX/LSL */
	case 4: /* SXTB */
		bc = append(bc, opLslImm, tmp, tmp, 56)
		bc = append(bc, opAsrImm, tmp, tmp, 56)
	case 5: /* SXTH */
		bc = append(bc, opLslImm, tmp, tmp, 48)
		bc = append(bc, opAsrImm, tmp, tmp, 48)
	case 6: /* SXTW */
		bc = append(bc, opLslImm, tmp, tmp, 32)
		bc = append(bc, opAsrImm, tmp, tmp, 32)
	case 7: /* SXTX */
	default:
		return liftedInsn{}, unsupportedInsn{off, word, "ADD_EXT", "unsupported extend option"}
	}
	if amount != 0 {
		bc = append(bc, opLslImm, tmp, tmp, amount)
	}
	if setFlags && rd == regXZR {
		cmpOp := byte(opCmpReg)
		if is32 {
			cmpOp = opCmpReg32
		}
		bc = append(bc, cmpOp, rn, tmp)
		return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
	}
	bc = append(bc, op, rd, rn, tmp)
	if is32 {
		bc = appendMask32(bc, rd, cache)
	}
	if setFlags && rd != regXZR {
		cmpOp := byte(opCmpReg)
		if is32 {
			cmpOp = opCmpReg32
		}
		bc = append(bc, cmpOp, rd, regXZR)
	}
	return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
}
