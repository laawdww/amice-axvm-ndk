package main

// 模块 M — opcode 置换（与 runtime/src/axvm_opcode_perm.c 逐位一致）。

func opcodePermBuild(key []byte) (fwd [256]byte, inv [256]byte) {
	for i := 0; i < 256; i++ {
		fwd[i] = byte(i)
	}
	if len(key) >= 32 {
		var acc uint32 = 0x9E3779B9
		for i := 255; i > 0; i-- {
			acc = acc*1664525 + 1013904223 + uint32(key[i&31]) + uint32(i)
			j := int(acc % uint32(i+1))
			fwd[i], fwd[j] = fwd[j], fwd[i]
		}
	}
	for i := 0; i < 256; i++ {
		inv[fwd[i]] = byte(i)
	}
	return
}

func opOperandLen(op byte) (int, bool) {
	switch op {
	case opNOP, 0x01 /*HALT*/, opRet:
		return 0, true
	case opSaveScratch, opRestoreScratch:
		return 0, true
	case opJunk:
		return 1, true
	case opLdri64:
		return 9, true
	case opAddImm, opSubImm:
		return 6, true
	case opAddReg, opSubReg, opAndReg, opOrrReg, opEorReg, opLslImm, opLsrImm, opMulReg:
		return 3, true
	case opCmpReg, opCmpReg32:
		return 2, true
	case opCselReg:
		return 4, true
	case opMovk:
		return 4, true
	case opLdrU64, opStrU64, opLdrU32, opStrU32, opLdurU64, opSturU64, opLdurU32, opSturU32,
		opLdrU8, opStrU8, opLdrU16, opStrU16:
		return 6, true
	case opLdrRegOff, opStrRegOff:
		return 6, true
	case opZext32:
		return 1, true
	case opCmpImm:
		return 6, true
	case opMovReg, opMvnReg:
		return 2, true
	case opAsrImm:
		return 3, true
	case opBr:
		return 4, true
	case opBCond:
		return 5, true
	case opBlNative:
		return 2, true
	case opBrReg, opBlrReg:
		return 1, true
	case opCallNat:
		return 9, true
	case opLdri64Vaddr, opCallNatVaddr:
		return 9, true
	case opPushPair, opPopPair:
		return 2, true
	case 0x62 /*VM_ENTER*/ :
		return 5, true
	case 0x63 /*VM_LEAVE*/ :
		return 0, true
	case opFldrD, opFstrD, opFldrS, opFstrS, opFldrQ, opFstrQ:
		return 6, true
	case opFaddD, opFsubD, opFmulD, opFdivD:
		return 3, true
	case opFcmpD, opFmovDReg, opFmovXBits, opFmovDBits, opFmovDX, opFcvtDS:
		return 2, true
	case opFcvtzsD:
		return 3, true
	}
	return 0, false
}

func opcodeStreamValid(code []byte) bool {
	i := 0
	for i < len(code) {
		step, ok := insnStepLen(code, i)
		if !ok {
			return false
		}
		i += step
	}
	return i == len(code)
}

func permuteOpcodes(code []byte, fwd [256]byte) {
	i := 0
	for i < len(code) {
		step, ok := insnStepLen(code, i)
		if !ok {
			return
		}
		code[i] = fwd[code[i]]
		i += step
	}
}
