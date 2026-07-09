package main

/*
 * AArch64 logical immediate 解码（与 VMPacker decodeBitmaskImm 对齐）。
 */
func arm64ExpandLogicalImm(n, immr, imms uint32, is64 bool) (uint64, bool) {
	regSize := uint32(32)
	if is64 {
		regSize = 64
	}
	var len_ int
	if n != 0 {
		len_ = 6
	} else {
		combined := (^imms) & 0x3F
		for len_ = 5; len_ >= 1; len_-- {
			if combined&(1<<len_) != 0 {
				break
			}
		}
		if len_ < 1 {
			return 0, false
		}
	}
	eSize := uint32(1) << len_
	if eSize > regSize {
		return 0, false
	}
	levels := eSize - 1
	s := imms & levels
	r := immr & levels
	if s == levels {
		return 0, false
	}
	welem := uint64((1 << (s + 1)) - 1)
	if r != 0 {
		welem = (welem >> r) | (welem << (eSize - r))
		welem &= (1 << eSize) - 1
	}
	var result uint64
	for pos := uint32(0); pos < regSize; pos += eSize {
		result |= welem << pos
	}
	return result, true
}

func liftLogicalImm(word uint32, off int, op byte, cache *relocCache) (liftedInsn, error) {
	rd := byte(word & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	n := (word >> 22) & 1
	immr := (word >> 16) & 0x3F
	imms := (word >> 10) & 0x3F
	is64 := (word >> 31) & 1
	val, ok := arm64ExpandLogicalImm(n, immr, imms, is64 != 0)
	if !ok {
		return liftedInsn{}, unsupportedInsn{off, word, "LOGICAL_IMM", "invalid bitmask"}
	}
	var bc []byte
	bc = append(bc, cache.imm64BC(scratchReg1, val)...)
	if rn == regXZR {
		bc = append(bc, []byte{opMovReg, rd, scratchReg1}...)
	} else {
		bc = append(bc, []byte{op, rd, rn, scratchReg1}...)
	}
	if is64 == 0 {
		bc = appendMask32(bc, rd, cache)
	}
	return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
}

func liftLogicalImmSetFlags(word uint32, off int, cache *relocCache) (liftedInsn, error) {
	rd := byte(word & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	n := (word >> 22) & 1
	immr := (word >> 16) & 0x3F
	imms := (word >> 10) & 0x3F
	is64 := (word >> 31) & 1
	val, ok := arm64ExpandLogicalImm(n, immr, imms, is64 != 0)
	if !ok {
		return liftedInsn{}, unsupportedInsn{off, word, "ANDS_IMM", "invalid bitmask"}
	}
	var bc []byte
	dst := rd
	maskReg := byte(scratchReg1)
	src := rn
	if rd == regXZR {
		dst = scratchReg0
		if rn == scratchReg0 {
			dst = scratchReg1
			maskReg = scratchReg0
			bc = append(bc, opMovReg, dst, rn)
			src = dst
		} else if rn == scratchReg1 {
			dst = scratchReg0
			maskReg = scratchReg1
			bc = append(bc, opMovReg, dst, rn)
			src = dst
		}
	}
	bc = append(bc, cache.imm64BC(maskReg, val)...)
	if rn == regXZR {
		bc = append(bc, opMovReg, dst, maskReg)
	} else {
		bc = append(bc, opAndReg, dst, src, maskReg)
	}
	if is64 == 0 {
		bc = appendMask32(bc, dst, cache)
	}
	bc = append(bc, []byte{opCmpReg, dst, regXZR}...)
	if rd == regXZR {
		bc = withScratchPairSaved(bc)
	}
	return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
}
