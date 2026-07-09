package main

import "encoding/binary"

/* CMP/CMN imm — SUBS/ADDS 写 XZR */
func liftCmpImm(rn byte, imm int32, subtract bool, is32 bool, off int, cache *relocCache) (liftedInsn, error) {
	cmpImm := imm
	if !subtract {
		cmpImm = -imm
	}
	is32b := byte(0)
	if is32 {
		is32b = 1
	}
	bc := []byte{opCmpImm, rn, is32b, byte(cmpImm), byte(cmpImm >> 8), byte(cmpImm >> 16), byte(cmpImm >> 24)}
	_ = cache
	return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
}

/* ASR imm — 解释器无原生 ASR，用算术右移语义合成（新增 AXOP_ASR_IMM） */
func liftAsrImm(rd, rn byte, sh byte, off int) (liftedInsn, error) {
	return liftedInsn{bytes: []byte{opAsrImm, rd, rn, sh}, armOff: off, armSize: 4}, nil
}

/* LDR/STR Rt, [Xn, Rm{, extend #sh}] */
func liftLdrStrReg(word uint32, off int, store bool, widthBytes int, cache *relocCache) (liftedInsn, error) {
	rt := byte(word & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	rm := byte((word >> 16) & 0x1F)
	opt := byte((word >> 13) & 0x7)
	scale := byte(0)
	if ((word >> 12) & 1) != 0 {
		switch widthBytes {
		case 8:
			scale = 3
		case 4:
			scale = 2
		case 2:
			scale = 1
		case 1:
			scale = 0
		default:
			return liftedInsn{}, unsupportedInsn{off, word, "LDR_REG", "unsupported access width"}
		}
	}
	switch opt {
	case 3, 7: /* LSL / SXTX: 64-bit index */
	case 2: /* UXTW */
	case 6: /* SXTW: (x<<32)>>32 */
	default:
		return liftedInsn{}, unsupportedInsn{off, word, "LDR_REG", "unsupported extend option"}
	}
	memOp := byte(opLdrRegOff)
	if store {
		memOp = opStrRegOff
	}
	bc := emitLdrStrRegOff(memOp, rt, rn, rm, byte(widthBytes), opt, scale)
	_ = cache
	return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
}

/* LDP/STP Xt1, Xt2, [Xn{, #imm}] — 64-bit，含前/后变址 */
func liftLoadStorePair(word uint32, off int, store bool, cache *relocCache) (liftedInsn, error) {
	rt := byte(word & 0x1F)
	rt2 := byte((word >> 10) & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	imm7 := int32((word>>15)&0x7F) << 25 >> 25 /* 7-bit signed */
	isSimd := ((word >> 26) & 1) != 0
	opc := (word >> 30) & 0x3
	elemBytes := int32(8)
	if isSimd {
		if opc != 2 {
			return liftedInsn{}, unsupportedInsn{off, word, "LDP/STP", "unsupported SIMD pair width"}
		}
		elemBytes = 16
	}
	simm := imm7 * elemBytes
	mode := (word >> 23) & 0x3
	postIdx := mode == 1
	signedOff := mode == 2
	preIdx := mode == 3
	if mode == 0 {
		return liftedInsn{}, unsupportedInsn{off, word, "LDP/STP", "reserved pair addressing mode"}
	}

	appendWriteback := func(bc []byte) []byte {
		if simm == 0 {
			return bc
		}
		return append(bc, emitAddImm(rn, rn, simm)...)
	}

	var bc []byte
	memOp := byte(opLdrU64)
	if store {
		memOp = opStrU64
	}
	if isSimd {
		memOp = opFldrQ
		if store {
			memOp = opFstrQ
		}
	}
	if preIdx {
		bc = append(bc, emitAddImm(scratchReg0, rn, simm)...)
		bc = append(bc, emitLdrStrU64(memOp, rt, scratchReg0, 0)...)
		bc = append(bc, emitLdrStrU64(memOp, rt2, scratchReg0, elemBytes)...)
		bc = appendWriteback(bc)
	} else if postIdx {
		bc = append(bc, emitLdrStrU64(memOp, rt, rn, 0)...)
		bc = append(bc, emitLdrStrU64(memOp, rt2, rn, elemBytes)...)
		bc = appendWriteback(bc)
	} else if signedOff {
		bc = append(bc, emitLdrStrU64(memOp, rt, rn, simm)...)
		bc = append(bc, emitLdrStrU64(memOp, rt2, rn, simm+elemBytes)...)
	} else {
		return liftedInsn{}, unsupportedInsn{off, word, "LDP/STP", "unknown pair addressing mode"}
	}
	_ = cache
	return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
}

/* LDXR/LDAXR Xt, [Xn] -> 普通加载语义（不建模独占监视器） */
func liftLdxr(word uint32, off int) (liftedInsn, error) {
	rt := byte(word & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	return liftedInsn{
		bytes:   emitLdrStrU64(opLdrU64, rt, rn, 0),
		armOff:  off,
		armSize: 4,
	}, nil
}

/* STXR/STLXR Ws, Xt, [Xn] -> 普通存储 + Ws=0（成功） */
func liftStxr(word uint32, off int) (liftedInsn, error) {
	rt := byte(word & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	rs := byte((word >> 16) & 0x1F)
	var bc []byte
	bc = append(bc, emitLdrStrU64(opStrU64, rt, rn, 0)...)
	bc = append(bc, emitImm64(rs, 0)...)
	return liftedInsn{
		bytes:   bc,
		armOff:  off,
		armSize: 4,
	}, nil
}

/* CAS/CASA/CASL/CASAL Xs, Xt, [Xn] -> 比较交换语义近似 */
func liftCas(word uint32, off int) (liftedInsn, error) {
	rt := byte(word & 0x1F)         /* new */
	rn := byte((word >> 5) & 0x1F)  /* addr */
	rs := byte((word >> 16) & 0x1F) /* expected + return old */

	var bc []byte
	/* old = [rn] */
	bc = append(bc, emitLdrStrU64(opLdrU64, scratchReg0, rn, 0)...)
	/* if old==rs then write rt else write old */
	bc = append(bc, []byte{opCmpReg, scratchReg0, rs}...)
	bc = append(bc, []byte{opCselReg, scratchReg1, rt, scratchReg0, 0}...) /* EQ=0 */
	bc = append(bc, emitLdrStrU64(opStrU64, scratchReg1, rn, 0)...)
	/* rs gets old value */
	bc = append(bc, []byte{opMovReg, rs, scratchReg0}...)
	return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
}

/* LDADD/LDADDA/LDADDL/LDADDAL Xs, Xt, [Xn] -> 原子加语义近似 */
func liftLdadd(word uint32, off int) (liftedInsn, error) {
	rt := byte(word & 0x1F)         /* return old */
	rn := byte((word >> 5) & 0x1F)  /* addr */
	rs := byte((word >> 16) & 0x1F) /* addend */

	var bc []byte
	bc = append(bc, emitLdrStrU64(opLdrU64, scratchReg0, rn, 0)...)
	bc = append(bc, []byte{opAddReg, scratchReg1, scratchReg0, rs}...)
	bc = append(bc, emitLdrStrU64(opStrU64, scratchReg1, rn, 0)...)
	bc = append(bc, []byte{opMovReg, rt, scratchReg0}...)
	return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
}

func liftLdclr(word uint32, off int) (liftedInsn, error) {
	rt := byte(word & 0x1F)         /* return old */
	rn := byte((word >> 5) & 0x1F)  /* addr */
	rs := byte((word >> 16) & 0x1F) /* mask */

	var bc []byte
	bc = append(bc, emitLdrStrU64(opLdrU64, scratchReg0, rn, 0)...)
	bc = append(bc, []byte{opMvnReg, scratchReg1, rs}...)
	bc = append(bc, []byte{opAndReg, scratchReg1, scratchReg0, scratchReg1}...)
	bc = append(bc, emitLdrStrU64(opStrU64, scratchReg1, rn, 0)...)
	bc = append(bc, []byte{opMovReg, rt, scratchReg0}...)
	return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
}

func liftLdset(word uint32, off int) (liftedInsn, error) {
	rt := byte(word & 0x1F)         /* return old */
	rn := byte((word >> 5) & 0x1F)  /* addr */
	rs := byte((word >> 16) & 0x1F) /* bits */

	var bc []byte
	bc = append(bc, emitLdrStrU64(opLdrU64, scratchReg0, rn, 0)...)
	bc = append(bc, []byte{opOrrReg, scratchReg1, scratchReg0, rs}...)
	bc = append(bc, emitLdrStrU64(opStrU64, scratchReg1, rn, 0)...)
	bc = append(bc, []byte{opMovReg, rt, scratchReg0}...)
	return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
}

func liftLdeor(word uint32, off int) (liftedInsn, error) {
	rt := byte(word & 0x1F)         /* return old */
	rn := byte((word >> 5) & 0x1F)  /* addr */
	rs := byte((word >> 16) & 0x1F) /* xor value */

	var bc []byte
	bc = append(bc, emitLdrStrU64(opLdrU64, scratchReg0, rn, 0)...)
	bc = append(bc, []byte{opEorReg, scratchReg1, scratchReg0, rs}...)
	bc = append(bc, emitLdrStrU64(opStrU64, scratchReg1, rn, 0)...)
	bc = append(bc, []byte{opMovReg, rt, scratchReg0}...)
	return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
}

func liftSwp(word uint32, off int) (liftedInsn, error) {
	rt := byte(word & 0x1F)         /* return old */
	rn := byte((word >> 5) & 0x1F)  /* addr */
	rs := byte((word >> 16) & 0x1F) /* new value */

	var bc []byte
	bc = append(bc, emitLdrStrU64(opLdrU64, scratchReg0, rn, 0)...)
	bc = append(bc, emitLdrStrU64(opStrU64, rs, rn, 0)...)
	bc = append(bc, []byte{opMovReg, rt, scratchReg0}...)
	return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
}

/* LDXP/LDAXP Xt1, Xt2, [Xn] */
func liftLdxp(word uint32, off int) (liftedInsn, error) {
	rt := byte(word & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	rt2 := byte((word >> 10) & 0x1F)
	var bc []byte
	bc = append(bc, emitLdrStrU64(opLdrU64, rt, rn, 0)...)
	bc = append(bc, emitLdrStrU64(opLdrU64, rt2, rn, 8)...)
	return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
}

/* STXP/STLXP Ws, Xt1, Xt2, [Xn] */
func liftStxp(word uint32, off int) (liftedInsn, error) {
	rt := byte(word & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	rt2 := byte((word >> 10) & 0x1F)
	rs := byte((word >> 16) & 0x1F)
	var bc []byte
	bc = append(bc, emitLdrStrU64(opStrU64, rt, rn, 0)...)
	bc = append(bc, emitLdrStrU64(opStrU64, rt2, rn, 8)...)
	bc = append(bc, emitImm64(rs, 0)...)
	return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
}

/* CASP/CASPA/CASPL/CASPAL Xs, Xs+1, Xt, Xt+1, [Xn] */
func liftCasp(word uint32, off int) (liftedInsn, error) {
	rt := byte(word & 0x1F)         /* new low */
	rn := byte((word >> 5) & 0x1F)  /* addr */
	rs := byte((word >> 16) & 0x1F) /* expected low / return old low */
	rt2 := rt + 1
	rs2 := rs + 1

	var bc []byte
	bc = append(bc, emitLdrStrU64(opLdrU64, scratchReg0, rn, 0)...)
	bc = append(bc, emitLdrStrU64(opLdrU64, scratchReg1, rn, 8)...)
	bc = append(bc, []byte{opCmpReg, scratchReg0, rs}...)
	bc = append(bc, []byte{opCselReg, 14, rt, scratchReg0, 0}...)
	bc = append(bc, []byte{opCmpReg, scratchReg1, rs2}...)
	bc = append(bc, []byte{opCselReg, 15, rt2, scratchReg1, 0}...)
	bc = append(bc, emitLdrStrU64(opStrU64, 14, rn, 0)...)
	bc = append(bc, emitLdrStrU64(opStrU64, 15, rn, 8)...)
	bc = append(bc, []byte{opMovReg, rs, scratchReg0}...)
	bc = append(bc, []byte{opMovReg, rs2, scratchReg1}...)
	return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
}

/* 用于测试：单条机器码提升 */
func liftRawInsn(words []uint32, funcAddr uint64) ([]byte, error) {
	code := make([]byte, len(words)*4)
	for i, w := range words {
		binary.LittleEndian.PutUint32(code[i*4:], w)
	}
	bc, _, _, _, err := liftFuncWithCache(code, funcAddr, newRelocCache())
	return bc, err
}
