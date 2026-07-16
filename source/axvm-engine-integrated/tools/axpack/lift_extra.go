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
		switch opc {
		case 0:
			elemBytes = 4
		case 1:
			elemBytes = 8
		case 2:
			elemBytes = 16
		default:
			return liftedInsn{}, unsupportedInsn{off, word, "LDP/STP", "unsupported SIMD pair width"}
		}
	} else {
		switch opc {
		case 0:
			elemBytes = 4
		case 2:
			elemBytes = 8
		default:
			return liftedInsn{}, unsupportedInsn{off, word, "LDP/STP", "unsupported GPR pair width"}
		}
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
		switch opc {
		case 0: /* S */
			memOp = opFldrS
			if store {
				memOp = opFstrS
			}
		case 1: /* D */
			memOp = opFldrD
			if store {
				memOp = opFstrD
			}
		case 2: /* Q */
			memOp = opFldrQ
			if store {
				memOp = opFstrQ
			}
		}
	} else if opc == 0 {
		memOp = opLdrU32
		if store {
			memOp = opStrU32
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

/* LDXR/LDAXR Xt, [Xn] — 真独占加载 */
func liftLdxr(word uint32, off int) (liftedInsn, error) {
	rt := byte(word & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	return liftedInsn{
		bytes:   []byte{opAtomicLdxr64, rt, rn},
		armOff:  off,
		armSize: 4,
	}, nil
}

/* LDXR/LDAXR Wt, [Xn] */
func liftLdxr32(word uint32, off int) (liftedInsn, error) {
	rt := byte(word & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	return liftedInsn{
		bytes:   []byte{opAtomicLdxr32, rt, rn},
		armOff:  off,
		armSize: 4,
	}, nil
}

/* STXR/STLXR Ws, Xt, [Xn] — 真独占存储 */
func liftStxr(word uint32, off int) (liftedInsn, error) {
	rt := byte(word & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	rs := byte((word >> 16) & 0x1F)
	return liftedInsn{
		bytes:   []byte{opAtomicStxr64, rs, rt, rn},
		armOff:  off,
		armSize: 4,
	}, nil
}

func liftStxr32(word uint32, off int) (liftedInsn, error) {
	rt := byte(word & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	rs := byte((word >> 16) & 0x1F)
	return liftedInsn{
		bytes:   []byte{opAtomicStxr32, rs, rt, rn},
		armOff:  off,
		armSize: 4,
	}, nil
}

/* CAS — 宿主 atomic compare-exchange */
func liftCas(word uint32, off int) (liftedInsn, error) {
	rt := byte(word & 0x1F)         /* new */
	rn := byte((word >> 5) & 0x1F)  /* addr */
	rs := byte((word >> 16) & 0x1F) /* expected + return old */
	return liftedInsn{
		bytes:   []byte{opAtomicCas64, rs, rt, rn},
		armOff:  off,
		armSize: 4,
	}, nil
}

func liftCas32(word uint32, off int) (liftedInsn, error) {
	rt := byte(word & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	rs := byte((word >> 16) & 0x1F)
	return liftedInsn{
		bytes:   []byte{opAtomicCas32, rs, rt, rn},
		armOff:  off,
		armSize: 4,
	}, nil
}

/* LDADD — 宿主 atomic fetch-add */
func liftLdadd(word uint32, off int) (liftedInsn, error) {
	rt := byte(word & 0x1F)         /* return old */
	rn := byte((word >> 5) & 0x1F)  /* addr */
	rs := byte((word >> 16) & 0x1F) /* addend */
	return liftedInsn{
		bytes:   []byte{opAtomicLdadd64, rt, rs, rn},
		armOff:  off,
		armSize: 4,
	}, nil
}

func liftLdadd32(word uint32, off int) (liftedInsn, error) {
	rt := byte(word & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	rs := byte((word >> 16) & 0x1F)
	return liftedInsn{
		bytes:   []byte{opAtomicLdadd32, rt, rs, rn},
		armOff:  off,
		armSize: 4,
	}, nil
}

func liftLdclr(word uint32, off int) (liftedInsn, error) {
	rt := byte(word & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	rs := byte((word >> 16) & 0x1F)
	return liftedInsn{
		bytes:   []byte{opAtomicLdclr64, rt, rs, rn},
		armOff:  off,
		armSize: 4,
	}, nil
}

func liftLdclr32(word uint32, off int) (liftedInsn, error) {
	rt := byte(word & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	rs := byte((word >> 16) & 0x1F)
	return liftedInsn{
		bytes:   []byte{opAtomicLdclr32, rt, rs, rn},
		armOff:  off,
		armSize: 4,
	}, nil
}

func liftLdset(word uint32, off int) (liftedInsn, error) {
	rt := byte(word & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	rs := byte((word >> 16) & 0x1F)
	return liftedInsn{
		bytes:   []byte{opAtomicLdset64, rt, rs, rn},
		armOff:  off,
		armSize: 4,
	}, nil
}

func liftLdset32(word uint32, off int) (liftedInsn, error) {
	rt := byte(word & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	rs := byte((word >> 16) & 0x1F)
	return liftedInsn{
		bytes:   []byte{opAtomicLdset32, rt, rs, rn},
		armOff:  off,
		armSize: 4,
	}, nil
}

func liftLdeor(word uint32, off int) (liftedInsn, error) {
	rt := byte(word & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	rs := byte((word >> 16) & 0x1F)
	return liftedInsn{
		bytes:   []byte{opAtomicLdeor64, rt, rs, rn},
		armOff:  off,
		armSize: 4,
	}, nil
}

func liftLdeor32(word uint32, off int) (liftedInsn, error) {
	rt := byte(word & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	rs := byte((word >> 16) & 0x1F)
	return liftedInsn{
		bytes:   []byte{opAtomicLdeor32, rt, rs, rn},
		armOff:  off,
		armSize: 4,
	}, nil
}

func liftSwp(word uint32, off int) (liftedInsn, error) {
	rt := byte(word & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	rs := byte((word >> 16) & 0x1F)
	return liftedInsn{
		bytes:   []byte{opAtomicSwp64, rt, rs, rn},
		armOff:  off,
		armSize: 4,
	}, nil
}

func liftSwp32(word uint32, off int) (liftedInsn, error) {
	rt := byte(word & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	rs := byte((word >> 16) & 0x1F)
	return liftedInsn{
		bytes:   []byte{opAtomicSwp32, rt, rs, rn},
		armOff:  off,
		armSize: 4,
	}, nil
}

/* LDXP/LDAXP — 128-bit 独占加载 */
func liftLdxp(word uint32, off int) (liftedInsn, error) {
	rt := byte(word & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	rt2 := byte((word >> 10) & 0x1F)
	return liftedInsn{
		bytes:   []byte{opAtomicLdxp64, rt, rt2, rn},
		armOff:  off,
		armSize: 4,
	}, nil
}

/* STXP — 独占双字：监视有效则写低+高字，否则仅置失败状态 */
func liftStxp(word uint32, off int) (liftedInsn, error) {
	rt := byte(word & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	rt2 := byte((word >> 10) & 0x1F)
	rs := byte((word >> 16) & 0x1F)
	/* opAtomicStxp64: rs, rt, rt2, rn */
	return liftedInsn{
		bytes:   []byte{opAtomicStxp64, rs, rt, rt2, rn},
		armOff:  off,
		armSize: 4,
	}, nil
}

/* CASP — 128-bit 宿主 atomic CAS */
func liftCasp(word uint32, off int) (liftedInsn, error) {
	rt := byte(word & 0x1F)         /* new low */
	rn := byte((word >> 5) & 0x1F)  /* addr */
	rs := byte((word >> 16) & 0x1F) /* expected low / return old low */
	return liftedInsn{
		bytes:   []byte{opAtomicCasp64, rs, rt, rn},
		armOff:  off,
		armSize: 4,
	}, nil
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
