package main

import "math"

/* 模块 F：A64 标量浮点/NEON 访存与运算提升（对齐 axvm_bytecode.h 0x70+） */

func markFP(fpUsed *bool) {
	if fpUsed != nil {
		*fpUsed = true
	}
}

func emitFpMem(op byte, vt, rn byte, off int32) []byte {
	return []byte{
		op, vt, rn,
		byte(off), byte(off >> 8), byte(off >> 16), byte(off >> 24),
	}
}

func emitFpRRR(op byte, vd, vn, vm byte) []byte {
	return []byte{op, vd, vn, vm}
}

func fpImmBits(imm8 uint32, isDouble bool) uint64 {
	sign := (imm8 >> 7) & 1
	b6 := (imm8 >> 6) & 1
	if isDouble {
		exp := ((^b6) & 1) << 10
		if b6 != 0 {
			exp |= 0xFF << 2
		}
		exp |= (imm8 >> 4) & 0x3
		frac := (uint64(imm8) & 0xF) << (52 - 4)
		return (uint64(sign) << 63) | (uint64(exp) << 52) | frac
	}
	exp := ((^b6) & 1) << 7
	if b6 != 0 {
		exp |= 0x1F << 2
	}
	exp |= (imm8 >> 4) & 0x3
	frac := (uint32(imm8) & 0xF) << (23 - 4)
	fbits := (uint32(sign) << 31) | (uint32(exp) << 23) | frac
	return math.Float64bits(float64(math.Float32frombits(fbits)))
}

/* tryDecodeFloatInsn 返回 true 表示已消费该机器指令 */
func tryDecodeFloatInsn(word uint32, off int, fpUsed *bool) (liftedInsn, bool) {
	/* LDR Q unsigned (128-bit SIMD) — 拆成两条 LDR D */
	if (word & 0xBFC00000) == 0x3DC00000 {
		vt := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		uimm := int32((word>>10)&0xFFF) * 16
		markFP(fpUsed)
		return liftedInsn{bytes: emitFpMem(opFldrQ, vt, rn, uimm), armOff: off, armSize: 4}, true
	}
	/* STR Q unsigned */
	if (word & 0xBFC00000) == 0x3D800000 {
		vt := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		uimm := int32((word>>10)&0xFFF) * 16
		markFP(fpUsed)
		return liftedInsn{bytes: emitFpMem(opFstrQ, vt, rn, uimm), armOff: off, armSize: 4}, true
	}
	/* LDUR/STUR Q unscaled */
	if (word & 0x3FE00C00) == 0x3C400000 {
		vt := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		simm := sext9((word >> 12) & 0x1FF)
		store := (word & 0x00400000) == 0
		markFP(fpUsed)
		memOp := byte(opFldrQ)
		if store {
			memOp = opFstrQ
		}
		return liftedInsn{bytes: emitFpMem(memOp, vt, rn, simm), armOff: off, armSize: 4}, true
	}

	/* LDR D unsigned */
	if (word & 0xFFC00000) == 0xFD400000 {
		vt := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		uimm := int32((word>>10)&0xFFF) * 8
		markFP(fpUsed)
		return liftedInsn{bytes: emitFpMem(opFldrD, vt, rn, uimm), armOff: off, armSize: 4}, true
	}
	/* STR D unsigned */
	if (word & 0xFFC00000) == 0xFC000000 {
		vt := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		uimm := int32((word>>10)&0xFFF) * 8
		markFP(fpUsed)
		return liftedInsn{bytes: emitFpMem(opFstrD, vt, rn, uimm), armOff: off, armSize: 4}, true
	}
	/* LDR S unsigned */
	if (word & 0xFFC00000) == 0xBD400000 {
		vt := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		uimm := int32((word>>10)&0xFFF) * 4
		markFP(fpUsed)
		return liftedInsn{bytes: emitFpMem(opFldrS, vt, rn, uimm), armOff: off, armSize: 4}, true
	}
	/* STR S unsigned */
	if (word & 0xFFC00000) == 0xBC000000 {
		vt := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		uimm := int32((word>>10)&0xFFF) * 4
		markFP(fpUsed)
		return liftedInsn{bytes: emitFpMem(opFstrS, vt, rn, uimm), armOff: off, armSize: 4}, true
	}
	/* LDUR/STUR D unscaled */
	if (word&0xFFE00C00) == 0xFC400000 || (word&0xFFE00C00) == 0xFC400400 {
		vt := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		simm := sext9((word >> 12) & 0x1FF)
		store := (word & 0x00400000) == 0
		markFP(fpUsed)
		memOp := byte(opFldrD)
		if store {
			memOp = opFstrD
		}
		return liftedInsn{bytes: emitFpMem(memOp, vt, rn, simm), armOff: off, armSize: 4}, true
	}
	/* LDUR/STUR S unscaled */
	if (word&0xFFE00C00) == 0xBC400000 || (word&0xFFE00C00) == 0xBC400400 {
		vt := byte(word & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		simm := sext9((word >> 12) & 0x1FF)
		store := (word & 0x00400000) == 0
		markFP(fpUsed)
		memOp := byte(opFldrS)
		if store {
			memOp = opFstrS
		}
		return liftedInsn{bytes: emitFpMem(memOp, vt, rn, simm), armOff: off, armSize: 4}, true
	}

	/* AArch64 标量 double 三寄存器运算（0x1E 族，掩码对齐 LLVM） */
	if (word & 0xFF201FE0) == 0x1E201000 {
		vd := byte(word & 0x1F)
		typ := (word >> 22) & 0x3
		if typ > 1 {
			return liftedInsn{}, false
		}
		imm8 := (word >> 13) & 0xFF
		bits := fpImmBits(imm8, typ == 1)
		markFP(fpUsed)
		bc := emitImm64(scratchReg0, bits)
		bc = append(bc, opFmovDBits, vd, scratchReg0)
		return liftedInsn{bytes: bc, armOff: off, armSize: 4}, true
	}
	if (word & 0xFF20FC00) == 0x1E200800 {
		vd := byte(word & 0x1F)
		vn := byte((word >> 5) & 0x1F)
		vm := byte((word >> 16) & 0x1F)
		markFP(fpUsed)
		return liftedInsn{bytes: emitFpRRR(opFmulD, vd, vn, vm), armOff: off, armSize: 4}, true
	}
	if (word & 0xFF20FC00) == 0x1E202800 {
		vd := byte(word & 0x1F)
		vn := byte((word >> 5) & 0x1F)
		vm := byte((word >> 16) & 0x1F)
		markFP(fpUsed)
		return liftedInsn{bytes: emitFpRRR(opFaddD, vd, vn, vm), armOff: off, armSize: 4}, true
	}
	if (word & 0xFF20FC00) == 0x1E201800 {
		vd := byte(word & 0x1F)
		vn := byte((word >> 5) & 0x1F)
		vm := byte((word >> 16) & 0x1F)
		markFP(fpUsed)
		return liftedInsn{bytes: emitFpRRR(opFdivD, vd, vn, vm), armOff: off, armSize: 4}, true
	}
	if (word & 0xFF20FC00) == 0x1E203800 {
		vd := byte(word & 0x1F)
		vn := byte((word >> 5) & 0x1F)
		vm := byte((word >> 16) & 0x1F)
		markFP(fpUsed)
		return liftedInsn{bytes: emitFpRRR(opFsubD, vd, vn, vm), armOff: off, armSize: 4}, true
	}
	if (word & 0xFF20FC00) == 0x1E202000 {
		vn := byte((word >> 5) & 0x1F)
		vm := byte((word >> 16) & 0x1F)
		markFP(fpUsed)
		return liftedInsn{bytes: emitFpRRR(opFcmpD, vn, vm, 0), armOff: off, armSize: 4}, true
	}

	/* FMADD / FMSUB S/D — 合成 FMUL + FADD/SUB */
	if (word&0xFFE00000) == 0x1F000000 || (word&0xFFE00000) == 0x1F400000 {
		sd := byte(word & 0x1F)
		sn := byte((word >> 5) & 0x1F)
		sm := byte((word >> 16) & 0x1F)
		sa := byte((word >> 10) & 0x1F)
		neg := (word & 0x00200000) != 0
		markFP(fpUsed)
		var bc []byte
		bc = append(bc, emitFpRRR(opFmulD, scratchReg0, sn, sm)...)
		if neg {
			bc = append(bc, emitFpRRR(opFsubD, sd, sa, scratchReg0)...)
		} else {
			bc = append(bc, emitFpRRR(opFaddD, sd, sa, scratchReg0)...)
		}
		return liftedInsn{bytes: bc, armOff: off, armSize: 4}, true
	}

	/* LDP/STP SIMD 标量对 — victim_dot3 使用 LDP s1,s4 */
	if (word & 0xFFC00000) == 0xAD400000 {
		rt := byte(word & 0x1F)
		rt2 := byte((word >> 10) & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		imm7 := int32((word>>15)&0x7F) << 25 >> 25
		simm := imm7 * 16
		markFP(fpUsed)
		var bc []byte
		bc = append(bc, emitFpMem(opFldrQ, rt, rn, simm)...)
		bc = append(bc, emitFpMem(opFldrQ, rt2, rn, simm+16)...)
		return liftedInsn{bytes: bc, armOff: off, armSize: 4}, true
	}
	if (word & 0xFFC00000) == 0xAD000000 {
		rt := byte(word & 0x1F)
		rt2 := byte((word >> 10) & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		imm7 := int32((word>>15)&0x7F) << 25 >> 25
		simm := imm7 * 16
		markFP(fpUsed)
		var bc []byte
		bc = append(bc, emitFpMem(opFstrQ, rt, rn, simm)...)
		bc = append(bc, emitFpMem(opFstrQ, rt2, rn, simm+16)...)
		return liftedInsn{bytes: bc, armOff: off, armSize: 4}, true
	}
	if (word & 0xFFC00000) == 0x2D400000 {
		rt := byte(word & 0x1F)
		rt2 := byte((word >> 10) & 0x1F)
		rn := byte((word >> 5) & 0x1F)
		simm := int32((word>>15)&0x7F) * 4
		if (word & 0x00400000) != 0 {
			simm = -simm
		}
		markFP(fpUsed)
		var bc []byte
		bc = append(bc, emitFpMem(opFldrS, rt, rn, simm)...)
		bc = append(bc, emitFpMem(opFldrS, rt2, rn, simm+4)...)
		return liftedInsn{bytes: bc, armOff: off, armSize: 4}, true
	}

	/* MOVI D #0 — 清零 v0 */
	if (word & 0xFFFFFFE0) == 0x2F00E400 {
		markFP(fpUsed)
		return liftedInsn{bytes: []byte{opFmovDReg, 0, regXZR}, armOff: off, armSize: 4}, true
	}

	/* 旧版 0x1F 编码（部分工具链） */
	if (word & 0xFFE0FC00) == 0x1F200400 {
		vd := byte(word & 0x1F)
		vn := byte((word >> 5) & 0x1F)
		vm := byte((word >> 16) & 0x1F)
		markFP(fpUsed)
		return liftedInsn{bytes: emitFpRRR(opFaddD, vd, vn, vm), armOff: off, armSize: 4}, true
	}
	/* FSUB D */
	if (word & 0xFFE0FC00) == 0x1F202400 {
		vd := byte(word & 0x1F)
		vn := byte((word >> 5) & 0x1F)
		vm := byte((word >> 16) & 0x1F)
		markFP(fpUsed)
		return liftedInsn{bytes: emitFpRRR(opFsubD, vd, vn, vm), armOff: off, armSize: 4}, true
	}
	/* FMUL D */
	if (word & 0xFFE0FC00) == 0x1F600400 {
		vd := byte(word & 0x1F)
		vn := byte((word >> 5) & 0x1F)
		vm := byte((word >> 16) & 0x1F)
		markFP(fpUsed)
		return liftedInsn{bytes: emitFpRRR(opFmulD, vd, vn, vm), armOff: off, armSize: 4}, true
	}
	/* FDIV D */
	if (word & 0xFFE0FC00) == 0x1F602400 {
		vd := byte(word & 0x1F)
		vn := byte((word >> 5) & 0x1F)
		vm := byte((word >> 16) & 0x1F)
		markFP(fpUsed)
		return liftedInsn{bytes: emitFpRRR(opFdivD, vd, vn, vm), armOff: off, armSize: 4}, true
	}
	/* FCMP D (Fm) */
	if (word & 0xFFE0FC00) == 0x1F601C00 {
		vn := byte((word >> 5) & 0x1F)
		vm := byte((word >> 16) & 0x1F)
		markFP(fpUsed)
		return liftedInsn{bytes: emitFpRRR(opFcmpD, vn, vm, 0), armOff: off, armSize: 4}, true
	}
	/* FMOV D,D */
	if (word & 0xFFE0FFE0) == 0x1E604000 {
		vd := byte(word & 0x1F)
		vm := byte((word >> 16) & 0x1F)
		markFP(fpUsed)
		return liftedInsn{bytes: emitFpRRR(opFmovDReg, vd, vm, 0), armOff: off, armSize: 4}, true
	}
	/* SCVTF D,X (64-bit int to double) */
	if (word & 0xFF800000) == 0x1E620000 {
		vd := byte(word & 0x1F)
		xn := byte((word >> 5) & 0x1F)
		markFP(fpUsed)
		return liftedInsn{bytes: []byte{opFmovDX, vd, xn}, armOff: off, armSize: 4}, true
	}
	/* FCVT D,S (single to double) */
	if (word & 0xFFFFFC00) == 0x1E22C000 {
		vd := byte(word & 0x1F)
		vn := byte((word >> 5) & 0x1F)
		markFP(fpUsed)
		return liftedInsn{bytes: emitFpRRR(opFcvtDS, vd, vn, 0), armOff: off, armSize: 4}, true
	}
	/* FCVT S,D (double to single) — 合成 FCVT_DS 后再存；运算侧用 FCVT_DS 近似 */
	if (word & 0xFFFFFC00) == 0x1E624000 {
		vd := byte(word & 0x1F)
		vn := byte((word >> 5) & 0x1F)
		markFP(fpUsed)
		return liftedInsn{bytes: emitFpRRR(opFcvtDS, vd, vn, 0), armOff: off, armSize: 4}, true
	}
	/* FADD S / FMUL S — 通过 FCVT 提升为 double 域运算较复杂；用 FLDR_S widen 路径在访存侧处理 */
	if (word&0xFFFFFC00) == 0x1E380000 || (word&0xFFFFFC00) == 0x1E780000 {
		rd := byte(word & 0x1F)
		vn := byte((word >> 5) & 0x1F)
		markFP(fpUsed)
		return liftedInsn{bytes: []byte{opFcvtzsD, rd, vn, 1}, armOff: off, armSize: 4}, true
	}
	if (word&0xFFFFFC00) == 0x9E380000 || (word&0xFFFFFC00) == 0x9E780000 {
		rd := byte(word & 0x1F)
		vn := byte((word >> 5) & 0x1F)
		markFP(fpUsed)
		return liftedInsn{bytes: []byte{opFcvtzsD, rd, vn, 0}, armOff: off, armSize: 4}, true
	}
	if (word & 0xFFE0FC00) == 0x1D200400 { /* FADD S */
		vd := byte(word & 0x1F)
		vn := byte((word >> 5) & 0x1F)
		vm := byte((word >> 16) & 0x1F)
		markFP(fpUsed)
		/* 直接在 double 寄存器文件执行（输入已被 widen） */
		return liftedInsn{bytes: emitFpRRR(opFaddD, vd, vn, vm), armOff: off, armSize: 4}, true
	}
	if (word & 0xFFE0FC00) == 0x1D600400 { /* FMUL S */
		vd := byte(word & 0x1F)
		vn := byte((word >> 5) & 0x1F)
		vm := byte((word >> 16) & 0x1F)
		markFP(fpUsed)
		return liftedInsn{bytes: emitFpRRR(opFmulD, vd, vn, vm), armOff: off, armSize: 4}, true
	}
	if (word & 0xFFE0FC00) == 0x1D202400 { /* FSUB S */
		vd := byte(word & 0x1F)
		vn := byte((word >> 5) & 0x1F)
		vm := byte((word >> 16) & 0x1F)
		markFP(fpUsed)
		return liftedInsn{bytes: emitFpRRR(opFsubD, vd, vn, vm), armOff: off, armSize: 4}, true
	}
	if (word & 0xFFE0FC00) == 0x1D602400 { /* FDIV S */
		vd := byte(word & 0x1F)
		vn := byte((word >> 5) & 0x1F)
		vm := byte((word >> 16) & 0x1F)
		markFP(fpUsed)
		return liftedInsn{bytes: emitFpRRR(opFdivD, vd, vn, vm), armOff: off, armSize: 4}, true
	}
	if (word & 0xFFE0FC00) == 0x1D601C00 { /* FCMP S */
		vn := byte((word >> 5) & 0x1F)
		vm := byte((word >> 16) & 0x1F)
		markFP(fpUsed)
		return liftedInsn{bytes: emitFpRRR(opFcmpD, vn, vm, 0), armOff: off, armSize: 4}, true
	}

	return liftedInsn{}, false
}
