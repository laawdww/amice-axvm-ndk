package main

func bitMask(width uint32) uint64 {
	if width >= 64 {
		return ^uint64(0)
	}
	return (uint64(1) << width) - 1
}

func pickTwoScratch(avoid ...byte) (byte, byte, bool) {
	candidates := []byte{scratchReg0, scratchReg1}
	out := make([]byte, 0, 2)
	for _, c := range candidates {
		blocked := false
		for _, a := range avoid {
			if a == c {
				blocked = true
				break
			}
		}
		if !blocked {
			out = append(out, c)
		}
	}
	if len(out) < 2 {
		return 0, 0, false
	}
	return out[0], out[1], true
}

func pickScratchAvoid(avoid ...byte) (byte, bool) {
	for _, c := range []byte{scratchReg0, scratchReg1} {
		blocked := false
		for _, a := range avoid {
			if a == c {
				blocked = true
				break
			}
		}
		if !blocked {
			return c, true
		}
	}
	return 0, false
}

func appendShiftForBfm(bc []byte, dst, src byte, left bool, amount byte) []byte {
	if src == regXZR {
		return append(bc, emitImm64(dst, 0)...)
	}
	if amount == 0 {
		return append(bc, opMovReg, dst, src)
	}
	if left {
		return append(bc, opLslImm, dst, src, amount)
	}
	return append(bc, opLsrImm, dst, src, amount)
}

/* BFM aliases used by clang: BFI when immr > imms, BFXIL when immr <= imms. */
func liftBfm(word uint32, off int, cache *relocCache) (liftedInsn, error) {
	rd := byte(word & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	immr := (word >> 16) & 0x3F
	imms := (word >> 10) & 0x3F
	sf := (word >> 31) & 1
	dataSize := uint32(32)
	dataMask := uint64(0xFFFFFFFF)
	if sf != 0 {
		dataSize = 64
		dataMask = ^uint64(0)
	}
	if immr >= dataSize || imms >= dataSize {
		return liftedInsn{}, unsupportedInsn{off, word, "BFM", "invalid 32-bit bitfield immediate"}
	}
	if rd == regXZR {
		return liftedInsn{bytes: []byte{opNOP}, armOff: off, armSize: 4}, nil
	}

	tmp, maskReg, ok := pickTwoScratch(rd, rn)
	if !ok {
		return liftedInsn{}, unsupportedInsn{off, word, "BFM", "scratch registers unavailable"}
	}

	var srcShifted []byte
	var mask uint64
	if immr > imms {
		lsb := dataSize - immr
		width := imms + 1
		mask = bitMask(width) << lsb
		srcShifted = appendShiftForBfm(srcShifted, tmp, rn, true, byte(lsb))
	} else {
		width := imms - immr + 1
		mask = bitMask(width)
		srcShifted = appendShiftForBfm(srcShifted, tmp, rn, false, byte(immr))
	}
	mask &= dataMask

	bc := srcShifted
	bc = append(bc, cache.imm64BC(maskReg, mask)...)
	bc = append(bc, opAndReg, tmp, tmp, maskReg)

	clearMask := dataMask &^ mask
	if clearMask == 0 {
		bc = append(bc, opMovReg, rd, tmp)
	} else {
		bc = append(bc, cache.imm64BC(maskReg, clearMask)...)
		bc = append(bc, opAndReg, rd, rd, maskReg)
		bc = append(bc, opOrrReg, rd, rd, tmp)
	}
	if sf == 0 {
		bc = appendMask32(bc, rd, cache)
	}
	return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
}
