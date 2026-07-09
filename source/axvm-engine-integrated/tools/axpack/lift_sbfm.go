package main

func liftSbfm(word uint32, off int, cache *relocCache) (liftedInsn, error) {
	rd := byte(word & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	immr := (word >> 16) & 0x3F
	imms := (word >> 10) & 0x3F
	sf := (word >> 31) & 1
	dataSize := uint32(32)
	if sf != 0 {
		dataSize = 64
	}
	if immr >= dataSize || imms >= dataSize {
		return liftedInsn{}, unsupportedInsn{off, word, "SBFM", "invalid bitfield immediate"}
	}
	tmp, maskReg, ok := pickTwoScratch(rd, rn)
	if !ok {
		return liftedInsn{}, unsupportedInsn{off, word, "SBFM", "scratch registers unavailable"}
	}

	var bc []byte
	var signBit uint32
	if immr > imms {
		lsb := dataSize - immr
		width := imms + 1
		signBit = lsb + width - 1
		bc = append(bc, cache.imm64BC(maskReg, bitMask(width))...)
		bc = append(bc, opAndReg, tmp, rn, maskReg)
		if lsb != 0 {
			bc = append(bc, opLslImm, tmp, tmp, byte(lsb))
		}
	} else {
		width := imms - immr + 1
		signBit = width - 1
		if immr == 0 {
			bc = append(bc, opMovReg, tmp, rn)
		} else {
			bc = append(bc, opLsrImm, tmp, rn, byte(immr))
		}
		bc = append(bc, cache.imm64BC(maskReg, bitMask(width))...)
		bc = append(bc, opAndReg, tmp, tmp, maskReg)
	}
	if signBit < 63 {
		sh := byte(63 - signBit)
		bc = append(bc, opLslImm, tmp, tmp, sh)
		bc = append(bc, opAsrImm, tmp, tmp, sh)
	}
	bc = append(bc, opMovReg, rd, tmp)
	if sf == 0 {
		bc = appendMask32(bc, rd, cache)
	}
	return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
}

func liftUbfm(word uint32, off int, cache *relocCache) (liftedInsn, error) {
	rd := byte(word & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	immr := (word >> 16) & 0x3F
	imms := (word >> 10) & 0x3F
	sf := (word >> 31) & 1
	dataSize := uint32(32)
	if sf != 0 {
		dataSize = 64
	}
	if immr >= dataSize || imms >= dataSize {
		return liftedInsn{}, unsupportedInsn{off, word, "UBFM", "invalid bitfield immediate"}
	}
	if rd == regXZR {
		return liftedInsn{bytes: []byte{opNOP}, armOff: off, armSize: 4}, nil
	}

	var bc []byte
	var width uint32
	if immr > imms {
		lsb := dataSize - immr
		width = imms + 1
		tmp, maskReg, ok := pickTwoScratch(rd, rn)
		if !ok {
			if rd == rn {
				var okOne bool
				maskReg, okOne = pickScratchAvoid(rn)
				if !okOne {
					return liftedInsn{}, unsupportedInsn{off, word, "UBFM", "scratch register unavailable"}
				}
				tmp = rd
			} else {
				tmp = rd
				maskReg = rd
			}
		}
		bc = append(bc, cache.imm64BC(maskReg, bitMask(width))...)
		bc = append(bc, opAndReg, tmp, rn, maskReg)
		if lsb != 0 {
			bc = append(bc, opLslImm, tmp, tmp, byte(lsb))
		}
		if tmp != rd {
			bc = append(bc, opMovReg, rd, tmp)
		}
	} else {
		width = imms - immr + 1
		maskReg, ok := pickScratchAvoid(rd, rn)
		if !ok {
			return liftedInsn{}, unsupportedInsn{off, word, "UBFM", "scratch register unavailable"}
		}
		if immr == 0 {
			if rd != rn {
				bc = append(bc, opMovReg, rd, rn)
			}
		} else {
			bc = append(bc, opLsrImm, rd, rn, byte(immr))
		}
		bc = append(bc, cache.imm64BC(maskReg, bitMask(width))...)
		bc = append(bc, opAndReg, rd, rd, maskReg)
	}
	if sf == 0 {
		bc = appendMask32(bc, rd, cache)
	}
	return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
}
