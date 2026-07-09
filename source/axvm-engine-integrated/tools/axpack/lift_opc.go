package main

/* 与 runtime/include/axvm_bytecode.h 严格对齐 */
const (
	opNOP          = 0x00
	opLdri64       = 0x10
	opAddImm       = 0x11
	opSubImm       = 0x12
	opAddReg       = 0x13
	opSubReg       = 0x14
	opAndReg       = 0x15
	opOrrReg       = 0x16
	opEorReg       = 0x17
	opLslImm       = 0x18
	opLsrImm       = 0x19
	opCmpReg       = 0x1A
	opMulReg       = 0x1B
	opCselReg      = 0x1C
	opMovk         = 0x1D
	opLdrU64       = 0x20
	opStrU64       = 0x21
	opLdrU32       = 0x22
	opStrU32       = 0x23
	opLdurU64      = 0x24
	opSturU64      = 0x25
	opLdurU32      = 0x26
	opSturU32      = 0x27
	opLdrU8        = 0x28
	opStrU8        = 0x29
	opLdrU16       = 0x2A
	opStrU16       = 0x2B
	opMovReg       = 0x30
	opMvnReg       = 0x31
	opAsrImm       = 0x32 /* u8 rd; u8 rs; u8 shamt — 算术右移 */
	opCmpReg32     = 0x33
	opBr           = 0x40
	opBCond        = 0x41
	opBlNative     = 0x42
	opBrReg        = 0x43
	opBlrReg       = 0x44
	opCallNat      = 0x45
	opLdri64Vaddr  = 0x46 /* u8 rd; u64 vaddr — 运行时 +load_base */
	opCallNatVaddr = 0x47 /* u64 vaddr — 运行时 +load_base 原生调用 */
	opRet          = 0x50
	opPushPair     = 0x60
	opPopPair      = 0x61

	/* 模块 F 浮点 opcode（需 runtime AXVM_FLOAT_VM） */
	opFldrD          = 0x70
	opFstrD          = 0x71
	opFldrS          = 0x72
	opFstrS          = 0x73
	opFaddD          = 0x74
	opFsubD          = 0x75
	opFmulD          = 0x76
	opFdivD          = 0x77
	opFcmpD          = 0x78
	opFmovDReg       = 0x79
	opFmovXBits      = 0x7A
	opFmovDBits      = 0x7B
	opFmovDX         = 0x7C
	opFcvtDS         = 0x7D
	opFcvtzsD        = 0x7F
	opFldrQ          = 0x80
	opFstrQ          = 0x81
	opSaveScratch    = 0x82
	opRestoreScratch = 0x83
	opLdrRegOff      = 0x84
	opStrRegOff      = 0x85
	opZext32         = 0x86
	opCmpImm         = 0x87

	arm64NOP = 0xD503201F
	arm64RET = 0xD65F03C0

	/* 合成指令使用的临时寄存器（AAPCS64 IP0/IP1） */
	scratchReg0 = 16
	scratchReg1 = 17
	regXZR      = 31
)
