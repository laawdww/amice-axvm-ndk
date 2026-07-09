package main

import (
	"encoding/binary"
	"fmt"
)

const (
	stubSizeDefault   = 256
	stubDispatchFixed = 64
	stubFuncIDOff     = 52 /* legacy tests; MOVZ slot for variant 0 */
)

type stubLayout struct {
	size        uint16
	dispatchOff uint16
	variant     uint8
}

const stubPrologueCount = 8

var stableStubPrologue bool

/* 多模板：4 种尺寸/dispatch × 8 种 prologue（variant 高 4 bit=prologue，低 4 bit=layout） */
var stubLayoutTable = []stubLayout{
	{256, 64, 0},
	{272, 72, 1},
	{240, 56, 2},
	{288, 80, 3},
}

func pickStubLayout(funcID uint32, padSeed uint64) stubLayout {
	x := padSeed ^ uint64(funcID)*0xD6E8FEB86659FD93
	layoutIdx := int(x % uint64(len(stubLayoutTable)))
	prologueID := int((x >> 33) % stubPrologueCount)
	if stableStubPrologue {
		prologueID = 0
	}
	lay := stubLayoutTable[layoutIdx]
	lay.variant = uint8((prologueID << 4) | (layoutIdx & 0x0F))
	return lay
}

func stubLayoutForTest(layoutIdx, prologueID int) stubLayout {
	if layoutIdx < 0 || layoutIdx >= len(stubLayoutTable) {
		layoutIdx = 0
	}
	prologueID &= 7
	lay := stubLayoutTable[layoutIdx]
	lay.variant = uint8((prologueID << 4) | (layoutIdx & 0x0F))
	return lay
}

func encodeStubMeta(sz, disp uint16, variant uint8) uint32 {
	/* dispatch offset 仅 8 bit（runtime rec_stub_dispatch_off）；stub size 16 bit */
	if disp > 255 {
		panic(fmt.Sprintf("encodeStubMeta: dispatch offset %d exceeds 255", disp))
	}
	return uint32(sz) | (uint32(disp) << 16) | (uint32(variant) << 24)
}

func decodeStubMeta(meta uint32) stubLayout {
	if meta == 0 {
		return stubLayout{stubSizeDefault, stubDispatchFixed, 0}
	}
	return stubLayout{
		size:        uint16(meta & 0xFFFF),
		dispatchOff: uint16((meta >> 16) & 0xFF),
		variant:     uint8((meta >> 24) & 0xFF),
	}
}

func genStubForFunc(funcID uint32, padSeed uint64, usesFP bool) ([]byte, stubLayout) {
	lay := pickStubLayout(funcID, padSeed)
	var stub []byte
	if usesFP {
		stub = genStubFPVariant(funcID, padSeed, &lay)
	} else {
		stub = genStubVariant(funcID, padSeed, &lay)
	}
	return stub, lay
}

func genStub(funcID uint32, padSeed uint64) []byte {
	lay := stubLayoutForTest(0, 0)
	return genStubVariant(funcID, padSeed, &lay)
}

func genStubVariant(funcID uint32, padSeed uint64, lay *stubLayout) []byte {
	epilogue := []uint32{0xA8C67BFD, arm64RET}
	return composeStubVariant(lay, funcID, padSeed, emitIntPrologue, epilogue, 0x9E3779B97F4A7C15)
}

func genStubFP(funcID uint32, padSeed uint64) []byte {
	lay := stubLayoutForTest(0, 0)
	return genStubFPVariant(funcID, padSeed, &lay)
}

func genStubFPVariant(funcID uint32, padSeed uint64, lay *stubLayout) []byte {
	epilogue := []uint32{0x9E670000, 0xA8C77BFD, arm64RET}
	return composeStubVariant(lay, funcID, padSeed, emitFPPrologue, epilogue, 0xBF58476D1CE4E5B9)
}

/* VMPacker 风格 3 指令 token 跳板：MOV W16,#lo; MOVK W16,#hi; B entry */
func encodeTokenTrampoline(funcAddr, entryVA uint64, token uint32) []byte {
	patch := make([]byte, 12)
	lo16 := token & 0xFFFF
	hi16 := (token >> 16) & 0xFFFF
	binary.LittleEndian.PutUint32(patch[0:], 0x52800010|uint32(lo16)<<5)
	binary.LittleEndian.PutUint32(patch[4:], 0x72A00010|uint32(hi16)<<5)
	off := int64(entryVA) - int64(funcAddr+8)
	if off%4 != 0 || off < -134217728 || off > 134217724 {
		return nil
	}
	imm26 := uint32(off/4) & 0x03FFFFFF
	binary.LittleEndian.PutUint32(patch[8:], 0x14000000|imm26)
	return patch
}

func tokenEncode(funcID uint32, xorKey byte) uint32 {
	return (uint32(xorKey) << 24) | (funcID & 0xFFF)
}

func encodeJump4(fromVA, toVA uint64) []byte {
	off := int64(toVA) - int64(fromVA)
	if off%4 != 0 || off < -134217728 || off > 134217724 {
		return nil
	}
	imm26 := uint32(off / 4)
	ins := uint32(0x14000000) | (imm26 & 0x03FFFFFF)
	return appendU32(nil, ins)
}

func encodeJump16(fromVA, toVA uint64) []byte {
	_ = fromVA
	patch := make([]byte, 16)
	binary.LittleEndian.PutUint32(patch[0:], 0x58000050)
	binary.LittleEndian.PutUint32(patch[4:], 0xD61F0200)
	binary.LittleEndian.PutUint64(patch[8:], toVA)
	return patch
}

func appendU32(buf []byte, v uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return append(buf, b[:]...)
}

func appendMOVZ(buf []byte, rd uint32, imm uint32, shift uint32) []byte {
	hw := shift / 16
	ins := uint32(0xD2800000) | ((imm & 0xFFFF) << 5) | (hw << 21) | (rd & 0x1F)
	return appendU32(buf, ins)
}

func appendMOVK(buf []byte, rd uint32, imm uint32, shift uint32) []byte {
	hw := shift / 16
	ins := uint32(0xF2800000) | ((imm & 0xFFFF) << 5) | (hw << 21) | (rd & 0x1F)
	return appendU32(buf, ins)
}
