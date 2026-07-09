package main

/* 整数 stub：8 种 prologue 骨架（语义等价，指令序列不同） */

func emitIntPrologue(pid uint8, buf []byte) []byte {
	switch pid & 7 {
	case 0:
		return emitIntPrologueClassic(buf)
	case 1:
		return emitIntPrologueX16Scratch(buf)
	case 2:
		return emitIntPrologueReverseSave(buf)
	case 3:
		return emitIntPrologueLdpReload(buf)
	case 4:
		return emitIntPrologueNoise(buf)
	case 5:
		return emitIntPrologueX16Base(buf)
	case 6:
		return emitIntPrologueInterleaved(buf)
	case 7:
		return emitIntPrologueNopLead(buf)
	default:
		return emitIntPrologueClassic(buf)
	}
}

func emitIntPrologueClassic(buf []byte) []byte {
	buf = appendU32(buf, 0xA9BA7BFD) // STP x29,x30,[sp,#-96]!
	buf = appendU32(buf, 0x910003FD) // MOV x29,sp
	buf = appendU32(buf, 0xA90107E0) // STP x0,x1,[sp,#16]
	buf = appendU32(buf, 0xA9020FE2) // STP x2,x3,[sp,#32]
	buf = appendU32(buf, 0xA90317E4) // STP x4,x5,[sp,#48]
	buf = appendU32(buf, 0xA9041FE6) // STP x6,x7,[sp,#64]
	buf = appendU32(buf, 0xF9400BE1) // LDR x1,[sp,#16]
	buf = appendU32(buf, 0xF9400FE2) // LDR x2,[sp,#24]
	buf = appendU32(buf, 0xF94013E3) // LDR x3,[sp,#32]
	buf = appendU32(buf, 0xF94017E4) // LDR x4,[sp,#40]
	buf = appendU32(buf, 0xF9401BE5) // LDR x5,[sp,#48]
	buf = appendU32(buf, 0xF9401FE6) // LDR x6,[sp,#56]
	buf = appendU32(buf, 0xF94023E7) // LDR x7,[sp,#64]
	return buf
}

func emitIntPrologueX16Scratch(buf []byte) []byte {
	buf = appendU32(buf, 0xA9BA7BFD)
	buf = appendU32(buf, 0x910003FD)
	buf = appendU32(buf, 0xAA0003F0) // MOV x16,x0
	buf = appendU32(buf, 0xAA0103F1) // MOV x17,x1
	buf = appendU32(buf, 0xA90107E0)
	buf = appendU32(buf, 0xA9020FE2)
	buf = appendU32(buf, 0xA90317E4)
	buf = appendU32(buf, 0xA9041FE6)
	buf = appendU32(buf, 0xAA1003E1) // MOV x1,x16 (1st arg saved in x16 before STP)
	buf = appendU32(buf, 0xF9400FE2) // LDR x2,[sp,#24]
	buf = appendU32(buf, 0xF94013E3)
	buf = appendU32(buf, 0xF94017E4)
	buf = appendU32(buf, 0xF9401BE5)
	buf = appendU32(buf, 0xF9401FE6)
	buf = appendU32(buf, 0xF94023E7)
	return buf
}

func emitIntPrologueReverseSave(buf []byte) []byte {
	buf = appendU32(buf, 0xA9BA7BFD)
	buf = appendU32(buf, 0x910003FD)
	buf = appendU32(buf, 0xA9041FE6) // STP x6,x7,[sp,#64]
	buf = appendU32(buf, 0xA90317E4)
	buf = appendU32(buf, 0xA9020FE2)
	buf = appendU32(buf, 0xA90107E0)
	return emitIntReloadArgs(buf)
}

func emitIntPrologueLdpReload(buf []byte) []byte {
	buf = appendU32(buf, 0xA9BA7BFD)
	buf = appendU32(buf, 0x910003FD)
	buf = appendU32(buf, 0xA90107E0)
	buf = appendU32(buf, 0xA9020FE2)
	buf = appendU32(buf, 0xA90317E4)
	buf = appendU32(buf, 0xA9041FE6)
	buf = appendU32(buf, 0xA9400BE1) // LDP x1,x2,[sp,#16]
	buf = appendU32(buf, 0xA94113E3) // LDP x3,x4,[sp,#32]
	buf = appendU32(buf, 0xA9421BE5) // LDP x5,x6,[sp,#48]
	buf = appendU32(buf, 0xF94023E7) // LDR x7,[sp,#64]
	return buf
}

func emitIntPrologueNoise(buf []byte) []byte {
	buf = appendU32(buf, 0xA9BA7BFD)
	buf = appendU32(buf, 0x910003FD)
	buf = appendU32(buf, 0xAA1F03F0) // EOR x16,xzr,xzr
	buf = appendU32(buf, 0xA90107E0)
	buf = appendU32(buf, 0xAA1F03F0)
	buf = appendU32(buf, 0xA9020FE2)
	buf = appendU32(buf, 0xA90317E4)
	buf = appendU32(buf, 0xA9041FE6)
	return emitIntReloadArgs(buf)
}

func emitIntPrologueX16Base(buf []byte) []byte {
	buf = appendU32(buf, 0xA9BA7BFD)
	buf = appendU32(buf, 0x910003FD)
	buf = appendU32(buf, 0xA90107E0)
	buf = appendU32(buf, 0xA9020FE2)
	buf = appendU32(buf, 0xA90317E4)
	buf = appendU32(buf, 0xA9041FE6)
	/* 勿经 x16 间接寻址：JNI 入口 x16 为 caller-saved，部分机型上
	 * ADD/LDP 序列与 PAC 交互会导致 LDP [x16] 读到垃圾地址。 */
	return emitIntReloadArgs(buf)
}

func emitIntPrologueInterleaved(buf []byte) []byte {
	buf = appendU32(buf, 0xA9BA7BFD)
	buf = appendU32(buf, 0x910003FD)
	buf = appendU32(buf, 0xA90107E0)
	buf = appendU32(buf, 0xA9020FE2)
	buf = appendU32(buf, 0xA90317E4)
	buf = appendU32(buf, 0xA9041FE6)
	buf = appendU32(buf, 0xF9400BE1)
	buf = appendU32(buf, 0xAA1F03F0)
	buf = appendU32(buf, 0xF9400FE2)
	buf = appendU32(buf, 0xAA1F03F0)
	buf = appendU32(buf, 0xF94013E3)
	buf = appendU32(buf, 0xF94017E4)
	buf = appendU32(buf, 0xF9401BE5)
	buf = appendU32(buf, 0xF9401FE6)
	buf = appendU32(buf, 0xF94023E7)
	return buf
}

func emitIntPrologueNopLead(buf []byte) []byte {
	buf = appendU32(buf, 0xA9BA7BFD)
	buf = appendU32(buf, 0x910003FD)
	buf = appendU32(buf, arm64NOP)
	buf = appendU32(buf, arm64NOP)
	buf = appendU32(buf, 0xA90107E0)
	buf = appendU32(buf, 0xA9020FE2)
	buf = appendU32(buf, 0xA90317E4)
	buf = appendU32(buf, 0xA9041FE6)
	return emitIntReloadArgs(buf)
}

func emitIntReloadArgs(buf []byte) []byte {
	buf = appendU32(buf, 0xF9400BE1)
	buf = appendU32(buf, 0xF9400FE2)
	buf = appendU32(buf, 0xF94013E3)
	buf = appendU32(buf, 0xF94017E4)
	buf = appendU32(buf, 0xF9401BE5)
	buf = appendU32(buf, 0xF9401FE6)
	buf = appendU32(buf, 0xF94023E7)
	return buf
}

/* FP stub：8 种 prologue 变体 */

func emitFPPrologue(pid uint8, buf []byte) []byte {
	switch pid & 7 {
	case 0:
		return emitFPPrologueClassic(buf)
	case 1:
		return emitFPPrologueNopLead(buf)
	case 2:
		return emitFPPrologueReverseSave(buf)
	case 3:
		return emitFPPrologueNoise(buf)
	case 4:
		return emitFPPrologueX16After(buf)
	case 5:
		return emitFPPrologueSplitFmov(buf)
	case 6:
		return emitFPPrologueLateD7(buf)
	case 7:
		return emitFPPrologueX17Scratch(buf)
	default:
		return emitFPPrologueClassic(buf)
	}
}

func emitFPPrologueClassic(buf []byte) []byte {
	buf = appendU32(buf, 0xA9B97BFD) // STP x29,x30,[sp,#-112]!
	buf = appendU32(buf, 0x910003FD)
	buf = appendU32(buf, 0x6D0107E0)
	buf = appendU32(buf, 0x6D020FE2)
	buf = appendU32(buf, 0x6D0317E4)
	buf = appendU32(buf, 0x6D041FE6)
	return emitFPFmovToX(buf)
}

func emitFPPrologueNopLead(buf []byte) []byte {
	buf = appendU32(buf, 0xA9B97BFD)
	buf = appendU32(buf, 0x910003FD)
	buf = appendU32(buf, arm64NOP)
	buf = appendU32(buf, 0x6D0107E0)
	buf = appendU32(buf, 0x6D020FE2)
	buf = appendU32(buf, 0x6D0317E4)
	buf = appendU32(buf, 0x6D041FE6)
	return emitFPFmovToX(buf)
}

func emitFPPrologueReverseSave(buf []byte) []byte {
	buf = appendU32(buf, 0xA9B97BFD)
	buf = appendU32(buf, 0x910003FD)
	buf = appendU32(buf, 0x6D041FE6)
	buf = appendU32(buf, 0x6D0317E4)
	buf = appendU32(buf, 0x6D020FE2)
	buf = appendU32(buf, 0x6D0107E0)
	return emitFPFmovToX(buf)
}

func emitFPPrologueNoise(buf []byte) []byte {
	buf = appendU32(buf, 0xA9B97BFD)
	buf = appendU32(buf, 0x910003FD)
	buf = appendU32(buf, 0xAA1F03F0)
	buf = appendU32(buf, 0x6D0107E0)
	buf = appendU32(buf, 0x6D020FE2)
	buf = appendU32(buf, 0xAA1F03F0)
	buf = appendU32(buf, 0x6D0317E4)
	buf = appendU32(buf, 0x6D041FE6)
	return emitFPFmovToX(buf)
}

func emitFPPrologueX16After(buf []byte) []byte {
	buf = appendU32(buf, 0xA9B97BFD)
	buf = appendU32(buf, 0x910003FD)
	buf = appendU32(buf, 0x6D0107E0)
	buf = appendU32(buf, 0x6D020FE2)
	buf = appendU32(buf, 0x6D0317E4)
	buf = appendU32(buf, 0x6D041FE6)
	buf = appendU32(buf, 0xAA1F03F0) // EOR x16,xzr,xzr
	return emitFPFmovToX(buf)
}

func emitFPPrologueSplitFmov(buf []byte) []byte {
	buf = appendU32(buf, 0xA9B97BFD)
	buf = appendU32(buf, 0x910003FD)
	buf = appendU32(buf, 0x6D0107E0)
	buf = appendU32(buf, 0x6D020FE2)
	buf = appendU32(buf, 0x9E660001)
	buf = appendU32(buf, 0x9E660022)
	buf = appendU32(buf, 0x6D0317E4)
	buf = appendU32(buf, 0x6D041FE6)
	buf = appendU32(buf, 0x9E660043)
	buf = appendU32(buf, 0x9E660064)
	buf = appendU32(buf, 0x9E660085)
	buf = appendU32(buf, 0x9E6600A6)
	buf = appendU32(buf, 0x9E6600C7)
	return buf
}

func emitFPPrologueLateD7(buf []byte) []byte {
	buf = appendU32(buf, 0xA9B97BFD)
	buf = appendU32(buf, 0x910003FD)
	buf = appendU32(buf, 0x6D0107E0)
	buf = appendU32(buf, 0x6D020FE2)
	buf = appendU32(buf, 0x6D0317E4)
	buf = appendU32(buf, 0x6D041FE6)
	buf = appendU32(buf, 0x9E660001)
	buf = appendU32(buf, 0x9E660022)
	buf = appendU32(buf, 0x9E660043)
	buf = appendU32(buf, 0x9E660064)
	buf = appendU32(buf, 0x9E660085)
	buf = appendU32(buf, 0x9E6600A6)
	buf = appendU32(buf, arm64NOP)
	buf = appendU32(buf, 0x9E6600C7)
	return buf
}

func emitFPPrologueX17Scratch(buf []byte) []byte {
	buf = appendU32(buf, 0xA9B97BFD)
	buf = appendU32(buf, 0x910003FD)
	buf = appendU32(buf, 0x6D0107E0)
	buf = appendU32(buf, 0x6D020FE2)
	buf = appendU32(buf, 0x6D0317E4)
	buf = appendU32(buf, 0x6D041FE6)
	buf = appendU32(buf, 0x9E660001)
	buf = appendU32(buf, 0xAA0003F0) // MOV x16,x0 (d0 bits)
	buf = appendU32(buf, 0x9E660022)
	buf = appendU32(buf, 0x9E660043)
	buf = appendU32(buf, 0x9E660064)
	buf = appendU32(buf, 0x9E660085)
	buf = appendU32(buf, 0x9E6600A6)
	buf = appendU32(buf, 0x9E6600C7)
	return buf
}

func emitFPFmovToX(buf []byte) []byte {
	buf = appendU32(buf, 0x9E660001)
	buf = appendU32(buf, 0x9E660022)
	buf = appendU32(buf, 0x9E660043)
	buf = appendU32(buf, 0x9E660064)
	buf = appendU32(buf, 0x9E660085)
	buf = appendU32(buf, 0x9E6600A6)
	buf = appendU32(buf, 0x9E6600C7)
	return buf
}

func stubPrologueID(lay stubLayout) uint8 { return lay.variant >> 4 }
func stubLayoutIdx(lay stubLayout) uint8  { return lay.variant & 0x0F }
func stubEarlyNopPad(lay stubLayout) bool { return (stubPrologueID(lay) & 1) != 0 }

func composeStubVariant(lay *stubLayout, funcID uint32, padSeed uint64, prologue func(uint8, []byte) []byte, epilogue []uint32, padSeedMix uint64) []byte {
	buf := make([]byte, 0, lay.size)
	disp := int(lay.dispatchOff)
	pid := stubPrologueID(*lay)

	buf = prologue(pid, buf)

	if stubEarlyNopPad(*lay) {
		for len(buf) < disp-20 && len(buf)+4 <= disp-16 {
			buf = appendU32(buf, arm64NOP)
		}
	}

	buf = appendMOVZ(buf, 0, funcID&0xFFFF, 0)
	if funcID > 0xFFFF {
		buf = appendMOVK(buf, 0, (funcID>>16)&0xFFFF, 16)
	}

	/* dispatch 槽必须在 prologue+func_id 之后，否则运行时 BLR patch 会跳过 MOVZ x0。 */
	if need := (len(buf) + 15) &^ 15; need > disp {
		disp = need
	}
	if disp > 255 {
		panic("stub dispatch offset exceeds 255")
	}
	lay.dispatchOff = uint16(disp)

	for len(buf) < disp {
		buf = appendU32(buf, arm64NOP)
	}
	for len(buf) < disp+16 {
		buf = appendU32(buf, arm64NOP)
	}

	for _, ins := range epilogue {
		buf = appendU32(buf, ins)
	}

	x := padSeed ^ (uint64(funcID) * padSeedMix)
	for len(buf) < int(lay.size) {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		buf = appendU32(buf, uint32(x))
	}
	return buf[:lay.size]
}
