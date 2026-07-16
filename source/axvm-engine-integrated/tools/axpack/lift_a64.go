package main

import (
	"encoding/binary"
	"fmt"
)

type unsupportedInsn struct {
	Offset int
	Word   uint32
	Mnemo  string
	Hint   string
}

func (u unsupportedInsn) Error() string {
	return fmt.Sprintf("unsupported A64 0x%08X at +%d (%s): %s", u.Word, u.Offset, u.Mnemo, u.Hint)
}

/* signExtend helpers */
func sext19(x uint32) int32 {
	v := int32(x & 0x7FFFF)
	if (v & 0x40000) != 0 {
		v |= ^int32(0x7FFFF)
	}
	return v * 4
}

func sext26(x uint32) int32 {
	v := int32(x & 0x03FFFFFF)
	if (v & 0x02000000) != 0 {
		v |= ^int32(0x03FFFFFF)
	}
	return v * 4
}

func sext9(x uint32) int32 {
	v := int32(x & 0x1FF)
	if (v & 0x100) != 0 {
		v |= ^int32(0x1FF)
	}
	return v
}

func sext14(x uint32) int32 {
	v := int32(x & 0x3FFF)
	if (v & 0x2000) != 0 {
		v |= ^int32(0x3FFF)
	}
	return v * 4
}

func decodeInsnAt(code []byte, off int, funcAddr uint64, cache *relocCache, layout map[int]int, fpUsed *bool) (liftedInsn, error) {
	if off+4 > len(code) {
		return liftedInsn{}, unsupportedInsn{off, 0, "TRUNC", "function truncated"}
	}
	word := binary.LittleEndian.Uint32(code[off:])
	pc := funcAddr + uint64(off)

	/* NOP */
	if word == arm64NOP {
		return liftedInsn{bytes: []byte{opNOP}, armOff: off, armSize: 4}, nil
	}
	/* BTI / PAC hint — 当作 NOP 跳过 */
	if (word&0xFFFFFFFE) == 0xD503245E || word == 0xD503201F {
		return liftedInsn{bytes: []byte{opNOP}, armOff: off, armSize: 4}, nil
	}
	/* DMB/DSB/ISB/CLREX 等屏障 — 宿主原子已带 memory order，提升为 NOP */
	if (word & 0xFFFFF000) == 0xD5033000 {
		return liftedInsn{bytes: []byte{opNOP}, armOff: off, armSize: 4}, nil
	}
	if word == arm64RET {
		_ = fpUsed
		return liftedInsn{bytes: []byte{opRet}, armOff: off, armSize: 4}, nil
	}

	/* ADRP + ADD lo12 成对折叠 */
	if (word&0x9F000000) == 0x90000000 && off+8 <= len(code) {
		next := binary.LittleEndian.Uint32(code[off+4:])
		if (next & 0xFF800000) == 0x91000000 {
			rd := byte(word & 0x1F)
			rd2 := byte(next & 0x1F)
			rn2 := byte((next >> 5) & 0x1F)
			if rd == rd2 && rn2 == rd {
				page := cache.pageFor(pc, word)
				lo12 := int32((next >> 10) & 0xFFF)
				full := page + uint64(lo12)
				return liftedInsn{bytes: emitImm64Vaddr(rd, full), armOff: off, armSize: 8}, nil
			}
		}
	}

	/* ADRP 单条 */
	if (word & 0x9F000000) == 0x90000000 {
		rd := byte(word & 0x1F)
		page := cache.pageFor(pc, word)
		return liftedInsn{bytes: emitImm64Vaddr(rd, page), armOff: off, armSize: 4}, nil
	}

	/* ADR */
	if (word & 0x9F000000) == 0x10000000 {
		rd := byte(word & 0x1F)
		addr := decodeADR(pc, word)
		return liftedInsn{bytes: emitImm64Vaddr(rd, addr), armOff: off, armSize: 4}, nil
	}

	/* ADD/SUB imm — SUBS/ADDS 写 XZR 时转为 CMP/CMN */
	if (word & 0xFF000000) == 0x91000000 {
		rd := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		imm := int32((word >> 10) & 0xFFF)
		if ((word >> 22) & 1) != 0 {
			imm <<= 12
		}
		return liftedInsn{bytes: emitAddImm(rd, rn, imm), armOff: off, armSize: 4}, nil
	}
	if (word & 0xFF000000) == 0xB1000000 {
		rd := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		imm := int32((word >> 10) & 0xFFF)
		if ((word >> 22) & 1) != 0 {
			imm <<= 12
		}
		if rd == regXZR {
			return liftCmpImm(rn, imm, false, false, off, cache)
		}
		return liftedInsn{bytes: emitAddImm(rd, rn, imm), armOff: off, armSize: 4}, nil
	}
	if (word & 0xFF000000) == 0xD1000000 {
		rd := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		imm := int32((word >> 10) & 0xFFF)
		if ((word >> 22) & 1) != 0 {
			imm <<= 12
		}
		return liftedInsn{bytes: []byte{opSubImm, rd, rn, byte(imm), byte(imm >> 8), byte(imm >> 16), byte(imm >> 24)}, armOff: off, armSize: 4}, nil
	}
	if (word & 0xFF000000) == 0xF1000000 {
		rd := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		imm := int32((word >> 10) & 0xFFF)
		if ((word >> 22) & 1) != 0 {
			imm <<= 12
		}
		if rd == regXZR {
			return liftCmpImm(rn, imm, true, false, off, cache)
		}
		return liftedInsn{bytes: []byte{opSubImm, rd, rn, byte(imm), byte(imm >> 8), byte(imm >> 16), byte(imm >> 24)}, armOff: off, armSize: 4}, nil
	}
	if (word&0x7F000000) == 0x11000000 || (word&0x7F000000) == 0x31000000 {
		rd := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		imm := int32((word >> 10) & 0xFFF)
		if ((word >> 22) & 1) != 0 {
			imm <<= 12
		}
		if rd == regXZR {
			return liftCmpImm(rn, imm, false, true, off, cache)
		}
		bc := emitAddImm(rd, rn, imm)
		bc = appendMask32(bc, rd, cache)
		return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
	}
	if (word&0x7F000000) == 0x51000000 || (word&0x7F000000) == 0x71000000 {
		rd := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		imm := int32((word >> 10) & 0xFFF)
		if ((word >> 22) & 1) != 0 {
			imm <<= 12
		}
		if rd == regXZR {
			return liftCmpImm(rn, imm, true, true, off, cache)
		}
		bc := []byte{opSubImm, rd, rn, byte(imm), byte(imm >> 8), byte(imm >> 16), byte(imm >> 24)}
		bc = appendMask32(bc, rd, cache)
		return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
	}

	/* ADD/SUB reg */
	if (word & 0xFF200000) == 0x8B000000 {
		rd := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		rm := byte((word >> 16) & 0x1F)
		bc, rhs, ok := emitShiftedRegOperand(word, rd, rn, rm, false, cache)
		if !ok {
			return liftedInsn{}, unsupportedInsn{off, word, "ADD shifted reg", "unsupported shift"}
		}
		bc = append(bc, opAddReg, rd, rn, rhs)
		return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
	}
	if (word & 0xFF200000) == 0xCB000000 {
		rd := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		rm := byte((word >> 16) & 0x1F)
		bc, rhs, ok := emitShiftedRegOperand(word, rd, rn, rm, false, cache)
		if !ok {
			return liftedInsn{}, unsupportedInsn{off, word, "SUB shifted reg", "unsupported shift"}
		}
		bc = append(bc, opSubReg, rd, rn, rhs)
		return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
	}
	if (word & 0xFF200000) == 0xEB000000 {
		rd := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		rm := byte((word >> 16) & 0x1F)
		if rd == regXZR {
			return liftedInsn{bytes: []byte{opCmpReg, rn, rm}, armOff: off, armSize: 4}, nil
		}
		return liftedInsn{bytes: []byte{opSubReg, rd, rn, rm}, armOff: off, armSize: 4}, nil
	}
	if (word & 0xFFE00000) == 0x0B200000 {
		return liftAddSubExtended(word, off, opAddReg, true, false, cache)
	}
	if (word & 0xFFE00000) == 0x8B200000 {
		return liftAddSubExtended(word, off, opAddReg, false, false, cache)
	}
	if (word & 0xFFE00000) == 0x4B200000 {
		return liftAddSubExtended(word, off, opSubReg, true, false, cache)
	}
	if (word & 0xFFE00000) == 0xCB200000 {
		return liftAddSubExtended(word, off, opSubReg, false, false, cache)
	}
	if (word & 0xFFE00000) == 0x6B200000 {
		return liftAddSubExtended(word, off, opSubReg, true, true, cache)
	}
	if (word & 0xFFE00000) == 0xEB200000 {
		return liftAddSubExtended(word, off, opSubReg, false, true, cache)
	}
	if (word & 0x7F200000) == 0x0B000000 {
		rd := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		rm := byte((word >> 16) & 0x1F)
		bc, rhs, ok := emitShiftedRegOperand(word, rd, rn, rm, true, cache)
		if !ok {
			return liftedInsn{}, unsupportedInsn{off, word, "ADD W shifted reg", "unsupported shift"}
		}
		bc = append(bc, opAddReg, rd, rn, rhs)
		bc = appendMask32(bc, rd, cache)
		return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
	}
	if (word & 0x7F200000) == 0x4B000000 {
		rd := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		rm := byte((word >> 16) & 0x1F)
		bc, rhs, ok := emitShiftedRegOperand(word, rd, rn, rm, true, cache)
		if !ok {
			return liftedInsn{}, unsupportedInsn{off, word, "SUB W shifted reg", "unsupported shift"}
		}
		bc = append(bc, opSubReg, rd, rn, rhs)
		bc = appendMask32(bc, rd, cache)
		return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
	}
	if (word & 0x7F200000) == 0x6B000000 {
		rd := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		rm := byte((word >> 16) & 0x1F)
		if rd == regXZR {
			return liftedInsn{bytes: []byte{opCmpReg32, rn, rm}, armOff: off, armSize: 4}, nil
		}
		bc := []byte{opSubReg, rd, rn, rm}
		bc = appendMask32(bc, rd, cache)
		return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
	}

	/* AND/ORR/EOR */
	if (word & 0xFF200000) == 0x8A000000 {
		return liftLogicalRegShifted(word, off, opAndReg, false, cache)
	}
	if (word & 0xFF200000) == 0xAA000000 {
		return liftLogicalRegShifted(word, off, opOrrReg, false, cache)
	}
	if (word & 0xFF200000) == 0xCA000000 {
		return liftLogicalRegShifted(word, off, opEorReg, false, cache)
	}
	if (word & 0xFF200000) == 0x8A200000 {
		return liftLogicalRegInvert(word, off, opAndReg, false, cache)
	}
	if (word & 0xFF200000) == 0xAA200000 {
		return liftLogicalRegInvert(word, off, opOrrReg, false, cache)
	}
	if (word & 0xFF200000) == 0xCA200000 {
		return liftLogicalRegInvert(word, off, opEorReg, false, cache)
	}
	if (word & 0x7F200000) == 0x0A000000 {
		return liftLogicalReg32(word, off, opAndReg, cache)
	}
	if (word & 0x7F200000) == 0x2A000000 {
		return liftLogicalReg32(word, off, opOrrReg, cache)
	}
	if (word & 0x7F200000) == 0x4A000000 {
		return liftLogicalReg32(word, off, opEorReg, cache)
	}
	if (word & 0x7F200000) == 0x0A200000 {
		return liftLogicalRegInvert(word, off, opAndReg, true, cache)
	}
	if (word & 0x7F200000) == 0x2A200000 {
		return liftLogicalRegInvert(word, off, opOrrReg, true, cache)
	}
	if (word & 0x7F200000) == 0x4A200000 {
		return liftLogicalRegInvert(word, off, opEorReg, true, cache)
	}

	/* EXTR — 合成 LSR + LSL + ORR（旋转/拼接位域，常见于编译器循环优化） */
	if (word&0xFF800000) == 0x93800000 || (word&0xFF800000) == 0x13800000 {
		return liftExtr(word, off)
	}

	/* MVN = ORN rd, xzr, rm */
	if (word & 0xFFE0FFE0) == 0xAA2003E0 {
		rd := byte(word & 0x1F)
		rm := byte((word >> 16) & 0x1F)
		return liftedInsn{bytes: []byte{opMvnReg, rd, rm}, armOff: off, armSize: 4}, nil
	}

	/* MOVZ/MOVK / MOVN -> LDRI64 / MOVK */
	if (word&0xFF800000) == 0x92800000 || (word&0xFF800000) == 0x12800000 {
		rd := byte(word & 0x1F)
		imm16 := uint64((word >> 5) & 0xFFFF)
		hw := (word >> 21) & 0x3
		sf := (word >> 31) & 1
		chunk := imm16 << (hw * 16)
		val := ^chunk
		if sf == 0 {
			val &= 0xFFFFFFFF
		}
		return liftedInsn{bytes: emitImm64(rd, val), armOff: off, armSize: 4}, nil
	}
	if (word&0xFF800000) == 0xD2800000 || (word&0xFF800000) == 0x52800000 {
		rd := byte(word & 0x1F)
		imm16 := uint64((word >> 5) & 0xFFFF)
		hw := (word >> 21) & 0x3
		val := imm16 << (hw * 16)
		return liftedInsn{bytes: emitImm64(rd, val), armOff: off, armSize: 4}, nil
	}
	if (word&0xFF800000) == 0xF2800000 || (word&0xFF800000) == 0x72800000 {
		rd := byte(word & 0x1F)
		imm16 := uint16((word >> 5) & 0xFFFF)
		hw := byte((word >> 21) & 0x3)
		bc := []byte{opMovk, rd, hw, byte(imm16), byte(imm16 >> 8)}
		if ((word >> 31) & 1) == 0 {
			bc = appendMask32(bc, rd, cache)
		}
		return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
	}

	/* MADD/MSUB (including MUL when Ra=XZR) / CSEL */
	if (word & 0x7FE00000) == 0x1B000000 {
		rd := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		ra := byte((word >> 10) & 0x1F)
		rm := byte((word >> 16) & 0x1F)
		isSub := ((word >> 15) & 1) != 0
		is32 := ((word >> 31) & 1) == 0
		if ra == regXZR && !isSub {
			bc := []byte{opMulReg, rd, rn, rm}
			if is32 {
				bc = appendMask32(bc, rd, cache)
			}
			return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
		}
		tmp := pickScratch(rd, rn, rm, ra)
		bc := []byte{opMulReg, tmp, rn, rm}
		if isSub {
			bc = append(bc, opSubReg, rd, ra, tmp)
		} else {
			bc = append(bc, opAddReg, rd, tmp, ra)
		}
		if is32 {
			bc = appendMask32(bc, rd, cache)
		}
		return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
	}
	if (word&0xFFE0FC00) == 0x9B207C00 || (word&0xFFE0FC00) == 0x9BA07C00 {
		rd := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		rm := byte((word >> 16) & 0x1F)
		t0, t1, ok := pickTwoScratch(rd, rn, rm)
		if !ok {
			return liftedInsn{}, unsupportedInsn{off, word, "MULL", "scratch registers unavailable"}
		}
		signed := (word & 0x00800000) == 0
		var bc []byte
		bc = append(bc, opMovReg, t0, rn)
		bc = append(bc, opMovReg, t1, rm)
		if signed {
			bc = append(bc, opLslImm, t0, t0, 32, opAsrImm, t0, t0, 32)
			bc = append(bc, opLslImm, t1, t1, 32, opAsrImm, t1, t1, 32)
		} else {
			bc = append(bc, opLslImm, t0, t0, 32, opLsrImm, t0, t0, 32)
			bc = append(bc, opLslImm, t1, t1, 32, opLsrImm, t1, t1, 32)
		}
		bc = append(bc, opMulReg, rd, t0, t1)
		return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
	}
	if (word & 0x7FE0FC00) == 0x1B007C00 {
		rd := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		rm := byte((word >> 16) & 0x1F)
		return liftedInsn{bytes: []byte{opMulReg, rd, rn, rm}, armOff: off, armSize: 4}, nil
	}
	if (word&0x7FE00C00) == 0x1A800000 || (word&0x7FE00C00) == 0x9A800000 {
		rd := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		rm := byte((word >> 16) & 0x1F)
		cond := byte((word >> 12) & 0xF)
		bc := []byte{opCselReg, rd, rn, rm, cond}
		if ((word >> 31) & 1) == 0 {
			bc = appendMask32(bc, rd, cache)
		}
		return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
	}
	if (word&0x7FE00C00) == 0x1A800400 || (word&0x7FE00C00) == 0x9A800400 {
		rd := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		rm := byte((word >> 16) & 0x1F)
		cond := byte((word >> 12) & 0xF)
		tmp := pickScratch(rd, rn, rm)
		var bc []byte
		if rm == regXZR {
			bc = append(bc, emitImm64(tmp, 1)...)
		} else {
			bc = append(bc, emitAddImm(tmp, rm, 1)...)
		}
		bc = append(bc, []byte{opCselReg, rd, rn, tmp, cond}...)
		if ((word >> 31) & 1) == 0 {
			bc = appendMask32(bc, rd, cache)
		}
		if rd != scratchReg0 && rd != scratchReg1 {
			bc = withScratchPairSaved(bc)
		}
		return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
	}
	if (word&0x7FE00C00) == 0x5A800000 || (word&0x7FE00C00) == 0xDA800000 {
		rd := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		rm := byte((word >> 16) & 0x1F)
		cond := byte((word >> 12) & 0xF)
		tmp, ok := pickScratchAvoid(rd, rn, rm)
		if !ok {
			return liftedInsn{}, unsupportedInsn{off, word, "CSINV", "scratch register unavailable"}
		}
		bc := []byte{opMvnReg, tmp, rm, opCselReg, rd, rn, tmp, cond}
		if ((word >> 31) & 1) == 0 {
			bc = appendMask32(bc, rd, cache)
		}
		if rd != scratchReg0 && rd != scratchReg1 {
			bc = withScratchPairSaved(bc)
		}
		return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
	}
	if (word&0x7FE00C00) == 0x5A800400 || (word&0x7FE00C00) == 0xDA800400 {
		rd := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		rm := byte((word >> 16) & 0x1F)
		cond := byte((word >> 12) & 0xF)
		tmp, ok := pickScratchAvoid(rd, rn, rm)
		if !ok {
			return liftedInsn{}, unsupportedInsn{off, word, "CSNEG", "scratch register unavailable"}
		}
		bc := []byte{opSubReg, tmp, regXZR, rm, opCselReg, rd, rn, tmp, cond}
		if ((word >> 31) & 1) == 0 {
			bc = appendMask32(bc, rd, cache)
		}
		if rd != scratchReg0 && rd != scratchReg1 {
			bc = withScratchPairSaved(bc)
		}
		return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
	}

	/* MOV reg */
	if (word & 0xFFE0FFE0) == 0xAA0003E0 {
		rd := byte(word & 0x1F)
		rm := byte((word >> 16) & 0x1F)
		return liftedInsn{bytes: []byte{opMovReg, rd, rm}, armOff: off, armSize: 4}, nil
	}

	/* UBFM/SBFM -> LSL/LSR/ASR imm (32/64-bit) */
	if (word & 0x1F800000) == 0x13000000 {
		rd := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		immr := (word >> 16) & 0x3F
		imms := (word >> 10) & 0x3F
		opc := (word >> 29) & 0x3
		sf := (word >> 31) & 1
		maxS := uint32(31)
		if sf != 0 {
			maxS = 63
		}
		if opc == 1 { /* BFM: BFI/BFXIL */
			return liftBfm(word, off, cache)
		}
		if opc == 2 { /* UBFM */
			return liftUbfm(word, off, cache)
		} else if opc == 0 { /* SBFM */
			if imms == maxS {
				return liftAsrImm(rd, rn, byte(immr), off)
			}
			return liftSbfm(word, off, cache)
		}
	}

	/* AND/ORR/EOR imm (64-bit, bitmask immediate) */
	if (word & 0xFF800000) == 0x92000000 {
		return liftLogicalImm(word, off, opAndReg, cache)
	}
	if (word & 0xFF800000) == 0xB2400000 {
		return liftLogicalImm(word, off, opOrrReg, cache)
	}
	if (word & 0xFF800000) == 0xD2400000 {
		return liftLogicalImm(word, off, opEorReg, cache)
	}
	if (word & 0x7F800000) == 0x12000000 {
		return liftLogicalImm(word, off, opAndReg, cache)
	}
	if (word & 0x7F800000) == 0x32000000 {
		return liftLogicalImm(word, off, opOrrReg, cache)
	}
	if (word & 0x7F800000) == 0x52000000 {
		return liftLogicalImm(word, off, opEorReg, cache)
	}
	if (word & 0xFF800000) == 0xF2000000 {
		return liftLogicalImmSetFlags(word, off, cache)
	}
	if (word & 0x7F800000) == 0x72000000 {
		return liftLogicalImmSetFlags(word, off, cache)
	}

	/* LDXR/LDAXR/STXR/STLXR (64-bit exclusive) */
	if (word&0xFFC0FC00) == 0xC8407C00 || (word&0xFFC0FC00) == 0xC840FC00 {
		return liftLdxr(word, off)
	}
	/* LDXR/LDAXR Wt */
	if (word&0xFFC0FC00) == 0x88407C00 || (word&0xFFC0FC00) == 0x8840FC00 {
		return liftLdxr32(word, off)
	}
	if (word&0xFFE0FC00) == 0xC8007C00 || (word&0xFFE0FC00) == 0xC800FC00 {
		return liftStxr(word, off)
	}
	if (word&0xFFE0FC00) == 0x88007C00 || (word&0xFFE0FC00) == 0x8800FC00 {
		return liftStxr32(word, off)
	}
	/* LDXP/LDAXP */
	if (word&0xFFE07C00) == 0xC8600400 || (word&0xFFE07C00) == 0xC8601000 {
		return liftLdxp(word, off)
	}
	/* STXP/STLXP */
	if (word&0xFFE07C00) == 0xC8202000 || (word&0xFFE07C00) == 0xC8203000 {
		return liftStxp(word, off)
	}
	/* CAS/CASA/CASL/CASAL X */
	if (word & 0xFFA07C00) == 0xC8A07C00 {
		return liftCas(word, off)
	}
	/* CAS W */
	if (word & 0xFFA07C00) == 0x88A07C00 {
		return liftCas32(word, off)
	}
	/* CASP/CASPA/CASPL/CASPAL */
	if (word & 0xFFA07C00) == 0x48207C00 {
		return liftCasp(word, off)
	}
	/* LDADD/LDADDA/LDADDL/LDADDAL X */
	if (word & 0xFF20FC00) == 0xF8200000 {
		return liftLdadd(word, off)
	}
	if (word & 0xFF20FC00) == 0xB8200000 {
		return liftLdadd32(word, off)
	}
	/* LDCLR */
	if (word & 0xFF20FC00) == 0xF8201000 {
		return liftLdclr(word, off)
	}
	if (word & 0xFF20FC00) == 0xB8201000 {
		return liftLdclr32(word, off)
	}
	/* LDEOR */
	if (word & 0xFF20FC00) == 0xF8202000 {
		return liftLdeor(word, off)
	}
	if (word & 0xFF20FC00) == 0xB8202000 {
		return liftLdeor32(word, off)
	}
	/* LDSET */
	if (word & 0xFF20FC00) == 0xF8203000 {
		return liftLdset(word, off)
	}
	if (word & 0xFF20FC00) == 0xB8203000 {
		return liftLdset32(word, off)
	}
	/* SWP */
	if (word & 0xFF20FC00) == 0xF8208000 {
		return liftSwp(word, off)
	}
	if (word & 0xFF20FC00) == 0xB8208000 {
		return liftSwp32(word, off)
	}

	/* LDR/STR unsigned offset (64/32) */
	if (word & 0xFFC00000) == 0xF9400000 {
		rt := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		uimm := int32((word>>10)&0xFFF) * 8
		return liftedInsn{bytes: emitLdrStrU64(opLdrU64, rt, rn, uimm), armOff: off, armSize: 4}, nil
	}
	if (word & 0xFFC00000) == 0xF9000000 {
		rt := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		uimm := int32((word>>10)&0xFFF) * 8
		return liftedInsn{bytes: emitLdrStrU64(opStrU64, rt, rn, uimm), armOff: off, armSize: 4}, nil
	}
	if (word & 0xFFC00000) == 0xB9400000 {
		rt := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		uimm := int32((word>>10)&0xFFF) * 4
		return liftedInsn{bytes: emitLdrStrU64(opLdrU32, rt, rn, uimm), armOff: off, armSize: 4}, nil
	}
	if (word & 0xFFC00000) == 0xB9800000 {
		rt := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		uimm := int32((word>>10)&0xFFF) * 4
		bc := emitLdrStrU64(opLdrU32, rt, rn, uimm)
		bc = appendSignExtend32(bc, rt)
		return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
	}
	if (word & 0xFFC00000) == 0xB9000000 {
		rt := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		uimm := int32((word>>10)&0xFFF) * 4
		return liftedInsn{bytes: emitLdrStrU64(opStrU32, rt, rn, uimm), armOff: off, armSize: 4}, nil
	}

	/* LDR/STR 64-bit register offset (含 LSL #0/#3) */
	if (word & 0xFFE00C00) == 0xF8600800 {
		return liftLdrStrReg(word, off, false, 8, cache)
	}
	if (word & 0xFFE00C00) == 0xF8200800 {
		return liftLdrStrReg(word, off, true, 8, cache)
	}
	if (word & 0xFFE00C00) == 0xB8600800 {
		return liftLdrStrReg(word, off, false, 4, cache)
	}
	if (word & 0xFFE00C00) == 0xB8200800 {
		return liftLdrStrReg(word, off, true, 4, cache)
	}
	if (word & 0xFFE00C00) == 0x38600800 {
		return liftLdrStrReg(word, off, false, 1, cache)
	}
	if (word & 0xFFE00C00) == 0x38200800 {
		return liftLdrStrReg(word, off, true, 1, cache)
	}
	if (word & 0xFFE00C00) == 0x78600800 {
		return liftLdrStrReg(word, off, false, 2, cache)
	}
	if (word & 0xFFE00C00) == 0x78200800 {
		return liftLdrStrReg(word, off, true, 2, cache)
	}

	/* LDP/STP（整数 + SIMD/FP，含前/后变址；V 位在 bit26） */
	if (word & 0x3A000000) == 0x28000000 {
		store := ((word >> 22) & 1) == 0
		return liftLoadStorePair(word, off, store, cache)
	}

	/* LDUR/STUR — 0xF8x unscaled family */
	if (word&0xFFE00C00) == 0xF8400400 || (word&0xFFE00C00) == 0xF8000400 ||
		(word&0xFFE00C00) == 0xF8400C00 || (word&0xFFE00C00) == 0xF8000C00 {
		store := (word & 0x00400000) == 0
		return liftUnscaled(word, off, store)
	}
	if (word&0xFFE00C00) == 0xF8400000 || (word&0xFFE00C00) == 0xF8000000 {
		store := (word & 0x00400000) == 0
		return liftUnscaled(word, off, store)
	}

	/* legacy unscaled class */
	if (word & 0x3B600C00) == 0x38400000 {
		return liftUnscaled(word, off, false)
	}
	if (word & 0x3B600C00) == 0x38000000 {
		return liftUnscaled(word, off, true)
	}

	/* LDRB/STRB unsigned */
	if (word & 0xFFC00000) == 0x39400000 {
		return liftNarrowLoad(word, off, opLdrU8)
	}
	if (word & 0xFFC00000) == 0x39000000 {
		return liftNarrowStore(word, off, opStrU8)
	}

	/* LDRH/STRH unsigned */
	if (word & 0xFFC00000) == 0x79400000 {
		return liftNarrowLoad(word, off, opLdrU16)
	}
	if (word & 0xFFC00000) == 0x79000000 {
		return liftNarrowStore(word, off, opStrU16)
	}

	/* B unconditional */
	if (word & 0xFC000000) == 0x14000000 {
		target := off + int(sext26(word&0x03FFFFFF))
		li := liftedInsn{bytes: emitBrRel(0), armOff: off, armSize: 4}
		li.branches = []branchFixup{{relAt: 1, armTarget: target}}
		return li, nil
	}

	/* B.cond */
	if (word & 0xFF000010) == 0x54000000 {
		cond := byte(word & 0xF)
		target := off + int(sext19((word>>5)&0x7FFFF))
		li := liftedInsn{bytes: emitBCond(cond, 0), armOff: off, armSize: 4}
		li.branches = []branchFixup{{relAt: 2, armTarget: target}}
		return li, nil
	}

	/* CBZ/CBNZ (64-bit) */
	if (word&0x7F000000) == 0x34000000 || (word&0x7F000000) == 0x35000000 {
		return liftCbz(word, off, false, cache)
	}
	if (word&0x7F000000) == 0xB4000000 || (word&0x7F000000) == 0xB5000000 {
		return liftCbz(word, off, true, cache)
	}

	/* TBZ/TBNZ */
	if (word&0x7F000000) == 0x36000000 || (word&0x7F000000) == 0x37000000 {
		return liftTbz(word, off, false, cache)
	}
	if (word&0x7F000000) == 0xB6000000 || (word&0x7F000000) == 0xB7000000 {
		return liftTbz(word, off, true, cache)
	}

	/* BL — VMPacker 风格绝对地址原生调用 */
	if word&0xFC000000 == 0x94000000 {
		imm26 := int32(word & 0x03FFFFFF)
		if (imm26 & 0x02000000) != 0 {
			imm26 |= ^int32(0x03FFFFFF)
		}
		target := funcAddr + uint64(off) + uint64(int64(imm26)<<2)
		target = cache.resolveCallTarget(target)
		return liftedInsn{bytes: emitCallNatVaddr(target), armOff: off, armSize: 4}, nil
	}
	if (word & 0xFFFFFC1F) == 0xD63F0000 {
		rn := byte((word >> 5) & 0x1F)
		return liftedInsn{bytes: emitBlrReg(rn), armOff: off, armSize: 4}, nil
	}
	if (word & 0xFFFFFC1F) == 0xD61F0000 {
		rn := byte((word >> 5) & 0x1F)
		return liftedInsn{bytes: emitBrReg(rn), armOff: off, armSize: 4}, nil
	}

	if ch, ok := tryDecodeFloatInsn(word, off, fpUsed); ok {
		return ch, nil
	}

	return liftedInsn{}, unsupportedInsn{off, word, "UNKNOWN", "add to lift_a64.go or exclude symbol"}
}

func liftUnscaled(word uint32, off int, store bool) (liftedInsn, error) {
	rt := byte(word & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	simm := sext9((word >> 12) & 0x1FF)
	size := (word >> 30) & 0x3
	mode := (word >> 10) & 0x3
	memOff := simm
	if mode == 1 {
		memOff = 0
	}
	var op byte
	switch {
	case size == 3 && !store:
		op = opLdurU64
	case size == 3 && store:
		op = opSturU64
	case size == 2 && !store:
		op = opLdurU32
	case size == 2 && store:
		op = opSturU32
	default:
		if mode == 1 || mode == 3 {
			return liftedInsn{}, unsupportedInsn{off, word, "LDST_NARROW_WB", "8/16-bit pre/post-index writeback is not implemented"}
		}
		/* 8/16-bit unscaled 提升为 32-bit LDUR/STUR + 掩码 */
		if store {
			return liftNarrowStoreUnscaled(rt, rn, simm, off, size)
		}
		return liftNarrowLoadUnscaled(rt, rn, simm, off, size)
	}
	bc := emitLdStUR(op, rt, rn, memOff)
	if (mode == 1 || mode == 3) && simm != 0 {
		bc = append(bc, emitAddImm(rn, rn, simm)...)
	}
	return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
}

func liftNarrowLoad(word uint32, off int, ldrOp byte) (liftedInsn, error) {
	rt := byte(word & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	uoff := int32((word >> 10) & 0xFFF)
	if ldrOp == opLdrU16 {
		uoff *= 2
	}
	return liftedInsn{bytes: emitLdrStrU64(ldrOp, rt, rn, uoff), armOff: off, armSize: 4}, nil
}

func liftNarrowStore(word uint32, off int, strOp byte) (liftedInsn, error) {
	rt := byte(word & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	uoff := int32((word >> 10) & 0xFFF)
	if strOp == opStrU16 {
		uoff *= 2
	}
	return liftedInsn{bytes: emitLdrStrU64(strOp, rt, rn, uoff), armOff: off, armSize: 4}, nil
}

func liftNarrowLoadUnscaled(rt, rn byte, simm int32, off int, size uint32) (liftedInsn, error) {
	op := byte(opLdrU8)
	if size == 1 {
		op = opLdrU16
	}
	return liftedInsn{bytes: emitLdStUR(op, rt, rn, simm), armOff: off, armSize: 4}, nil
}

func liftNarrowStoreUnscaled(rt, rn byte, simm int32, off int, size uint32) (liftedInsn, error) {
	op := byte(opStrU8)
	if size == 1 {
		op = opStrU16
	}
	return liftedInsn{bytes: emitLdStUR(op, rt, rn, simm), armOff: off, armSize: 4}, nil
}

func liftCbz(word uint32, off int, is64 bool, cache *relocCache) (liftedInsn, error) {
	rt := byte(word & 0x1F)
	target := off + int(sext19((word>>5)&0x7FFFF))
	isCBZ := (word & 0x01000000) == 0
	cond := byte(0) /* EQ */
	if !isCBZ {
		cond = 1 /* NE */
	}
	var bc []byte
	cmpReg := rt
	if !is64 {
		var prep []byte
		dst := byte(scratchReg0)
		maskReg := byte(scratchReg1)
		src := rt
		if rt == scratchReg0 {
			dst = scratchReg1
			maskReg = scratchReg0
			prep = append(prep, opMovReg, dst, rt)
			src = dst
		} else if rt == scratchReg1 {
			dst = scratchReg0
			maskReg = scratchReg1
			prep = append(prep, opMovReg, dst, rt)
			src = dst
		}
		prep = append(prep, cache.imm64BC(maskReg, 0xffffffff)...)
		prep = append(prep, opAndReg, dst, src, maskReg)
		prep = append(prep, opCmpReg, dst, regXZR)
		bc = append(bc, withScratchPairSaved(prep)...)
		bc = append(bc, emitBCond(cond, 0)...)
		li := liftedInsn{bytes: bc, armOff: off, armSize: 4}
		li.branches = []branchFixup{{relAt: len(bc) - 4, armTarget: target}}
		return li, nil
	}
	bc = append(bc, []byte{opCmpReg, cmpReg, regXZR}...)
	bc = append(bc, emitBCond(cond, 0)...)
	li := liftedInsn{bytes: bc, armOff: off, armSize: 4}
	li.branches = []branchFixup{{relAt: len(bc) - 4, armTarget: target}}
	return li, nil
}

func liftTbz(word uint32, off int, is64 bool, cache *relocCache) (liftedInsn, error) {
	rt := byte(word & 0x1F)
	bit := (word >> 19) & 0x3F
	if !is64 {
		bit &= 31
	}
	target := off + int(sext14((word>>5)&0x3FFF))
	testZero := (word & 0x01000000) == 0
	mask := uint64(1) << bit
	var prep []byte
	dst := byte(scratchReg0)
	maskReg := byte(scratchReg1)
	src := rt
	if rt == scratchReg0 {
		dst = scratchReg1
		maskReg = scratchReg0
		prep = append(prep, opMovReg, dst, rt)
		src = dst
	} else if rt == scratchReg1 {
		dst = scratchReg0
		maskReg = scratchReg1
		prep = append(prep, opMovReg, dst, rt)
		src = dst
	}
	prep = append(prep, cache.imm64BC(maskReg, mask)...)
	prep = append(prep, opAndReg, dst, src, maskReg)
	prep = append(prep, opCmpReg, dst, regXZR)
	var bc []byte
	bc = append(bc, withScratchPairSaved(prep)...)
	cond := byte(0)
	if !testZero {
		cond = 1
	}
	bc = append(bc, emitBCond(cond, 0)...)
	li := liftedInsn{bytes: bc, armOff: off, armSize: 4}
	li.branches = []branchFixup{{relAt: len(bc) - 4, armTarget: target}}
	return li, nil
}

/* EXTR Xd,Xn,Xm,#imms → (Xn>>imms)|(Xm<<(width-imms))；解释器无原生 EXTR，用移位+ORR 合成 */
func appendMask32(bc []byte, rd byte, cache *relocCache) []byte {
	_ = cache
	return append(bc, opZext32, rd)
}

func withScratchPairSaved(bc []byte) []byte {
	out := []byte{opSaveScratch}
	out = append(out, bc...)
	out = append(out, opRestoreScratch)
	return out
}

func appendSignExtend32(bc []byte, rd byte) []byte {
	bc = append(bc, []byte{opLslImm, rd, rd, 32}...)
	return append(bc, []byte{opAsrImm, rd, rd, 32}...)
}

func pickScratch(avoid ...byte) byte {
	for _, r := range avoid {
		if r == scratchReg0 {
			return scratchReg1
		}
	}
	return scratchReg0
}

func emitShiftedRegOperand(word uint32, rd, rn, rm byte, is32 bool, cache *relocCache) ([]byte, byte, bool) {
	shift := byte((word >> 22) & 0x3)
	amount := byte((word >> 10) & 0x3F)
	if is32 {
		amount &= 0x1F
	}
	if shift == 0 && amount == 0 {
		return nil, rm, true
	}
	if shift == 3 {
		return nil, 0, false
	}
	tmp := pickScratch(rd, rn, rm)
	var bc []byte
	src := rm
	if is32 {
		bc = append(bc, []byte{opMovReg, tmp, rm}...)
		if shift == 2 {
			bc = appendSignExtend32(bc, tmp)
		} else {
			bc = appendMask32(bc, tmp, cache)
		}
		src = tmp
	}
	var op byte
	switch shift {
	case 0:
		op = opLslImm
	case 1:
		op = opLsrImm
	case 2:
		op = opAsrImm
	default:
		return nil, 0, false
	}
	bc = append(bc, []byte{op, tmp, src, amount}...)
	return bc, tmp, true
}

func liftLogicalRegShifted(word uint32, off int, op byte, is32 bool, cache *relocCache) (liftedInsn, error) {
	rd := byte(word & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	rm := byte((word >> 16) & 0x1F)
	shift := byte((word >> 22) & 0x3)
	amount := byte((word >> 10) & 0x3F)
	if is32 {
		amount &= 0x1F
	}
	src := rm
	var bc []byte
	if amount != 0 {
		if shift == 3 {
			return liftedInsn{}, unsupportedInsn{off, word, "ROR_LOGICAL", "logical register ROR is not implemented"}
		}
		src = scratchReg0
		switch shift {
		case 0:
			bc = append(bc, []byte{opLslImm, src, rm, amount}...)
		case 1:
			bc = append(bc, []byte{opLsrImm, src, rm, amount}...)
		case 2:
			bc = append(bc, []byte{opAsrImm, src, rm, amount}...)
		}
	}
	bc = append(bc, []byte{op, rd, rn, src}...)
	if is32 {
		bc = appendMask32(bc, rd, cache)
	}
	return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
}

func liftLogicalReg32(word uint32, off int, op byte, cache *relocCache) (liftedInsn, error) {
	rd := byte(word & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	rm := byte((word >> 16) & 0x1F)
	shift := (word >> 22) & 0x3
	amount := byte((word >> 10) & 0x1F)
	src := rm
	var bc []byte

	if amount != 0 {
		if shift == 3 {
			return liftedInsn{}, unsupportedInsn{off, word, "ROR32", "32-bit logical register ROR is not implemented"}
		}
		src = scratchReg0
		bc = append(bc, []byte{opMovReg, src, rm}...)
		switch shift {
		case 0:
			bc = appendMask32(bc, src, cache)
			bc = append(bc, []byte{opLslImm, src, src, amount}...)
		case 1:
			bc = appendMask32(bc, src, cache)
			bc = append(bc, []byte{opLsrImm, src, src, amount}...)
		case 2:
			bc = appendSignExtend32(bc, src)
			bc = append(bc, []byte{opAsrImm, src, src, amount}...)
		}
	}

	bc = append(bc, []byte{op, rd, rn, src}...)
	bc = appendMask32(bc, rd, cache)
	return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
}

func liftLogicalRegInvert(word uint32, off int, op byte, is32 bool, cache *relocCache) (liftedInsn, error) {
	rd := byte(word & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	rm := byte((word >> 16) & 0x1F)
	shift := (word >> 22) & 0x3
	amount := byte((word >> 10) & 0x3F)
	if is32 {
		amount &= 0x1F
	}
	src := rm
	var bc []byte

	if amount != 0 {
		if shift == 3 {
			return liftedInsn{}, unsupportedInsn{off, word, "ROR_LOGICAL_NOT", "logical NOT register ROR is not implemented"}
		}
		src = scratchReg0
		if is32 {
			bc = append(bc, []byte{opMovReg, src, rm}...)
		}
		switch shift {
		case 0:
			if is32 {
				bc = appendMask32(bc, src, cache)
				bc = append(bc, []byte{opLslImm, src, src, amount}...)
			} else {
				bc = append(bc, []byte{opLslImm, src, rm, amount}...)
			}
		case 1:
			if is32 {
				bc = appendMask32(bc, src, cache)
				bc = append(bc, []byte{opLsrImm, src, src, amount}...)
			} else {
				bc = append(bc, []byte{opLsrImm, src, rm, amount}...)
			}
		case 2:
			if is32 {
				bc = appendSignExtend32(bc, src)
				bc = append(bc, []byte{opAsrImm, src, src, amount}...)
			} else {
				bc = append(bc, []byte{opAsrImm, src, rm, amount}...)
			}
		}
	}

	inv := byte(scratchReg1)
	if src == inv {
		inv = scratchReg0
	}
	bc = append(bc, []byte{opMvnReg, inv, src}...)
	bc = append(bc, []byte{op, rd, rn, inv}...)
	if is32 {
		bc = appendMask32(bc, rd, cache)
	}
	return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
}

func liftExtr(word uint32, off int) (liftedInsn, error) {
	imms := byte((word >> 10) & 0x3F)
	sf := (word >> 31) & 1
	rm := byte((word >> 16) & 0x1F)
	rn := byte((word >> 5) & 0x1F)
	rd := byte(word & 0x1F)
	width := byte(64)
	if sf == 0 {
		width = 32
	}
	if imms == 0 {
		return liftedInsn{bytes: []byte{opMovReg, rd, rn}, armOff: off, armSize: 4}, nil
	}
	left := width - imms
	var bc []byte
	bc = append(bc, []byte{opLsrImm, scratchReg0, rn, imms}...)
	bc = append(bc, []byte{opLslImm, scratchReg1, rm, left}...)
	bc = append(bc, []byte{opOrrReg, rd, scratchReg0, scratchReg1}...)
	return liftedInsn{bytes: bc, armOff: off, armSize: 4}, nil
}
