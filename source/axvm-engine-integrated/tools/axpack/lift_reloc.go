package main

import (
	"encoding/binary"
	"sync"
)

/* 重定位缓存：ADRP/ADR 页地址与 64-bit 常量字节码片段 */
type relocCache struct {
	mu          sync.Mutex
	pages       map[uint64]uint64
	immBC       map[uint64][]byte
	callTargets map[uint64]uint64
}

func newRelocCache() *relocCache {
	callTargetsMu.Lock()
	ct := make(map[uint64]uint64, len(globalCallTargets))
	for k, v := range globalCallTargets {
		ct[k] = v
	}
	callTargetsMu.Unlock()
	return &relocCache{
		pages:       make(map[uint64]uint64),
		immBC:       make(map[uint64][]byte),
		callTargets: ct,
	}
}

var (
	callTargetsMu     sync.Mutex
	globalCallTargets map[uint64]uint64
)

func configureCallTargets(targets map[uint64]uint64) {
	callTargetsMu.Lock()
	defer callTargetsMu.Unlock()
	globalCallTargets = make(map[uint64]uint64, len(targets))
	for k, v := range targets {
		globalCallTargets[k] = v
	}
}

func (c *relocCache) resolveCallTarget(vaddr uint64) uint64 {
	if c == nil {
		return vaddr
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.callTargets[vaddr]; ok && v != 0 {
		return v
	}
	return vaddr
}

func (c *relocCache) pageFor(pc uint64, word uint32) uint64 {
	key := pc<<32 | uint64(word)
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.pages[key]; ok {
		return v
	}
	v := decodeADRPage(pc, word)
	c.pages[key] = v
	return v
}

func (c *relocCache) imm64BC(rd byte, val uint64) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := uint64(rd)<<56 | val
	if b, ok := c.immBC[key]; ok {
		return append([]byte(nil), b...)
	}
	b := emitImm64(rd, val)
	c.immBC[key] = append([]byte(nil), b...)
	return append([]byte(nil), b...)
}

/* ADRP: imm21 << 12 + PC 页对齐 */
func decodeADRPage(pc uint64, word uint32) uint64 {
	immlo := (word >> 29) & 0x3
	immhi := (word >> 5) & 0x7FFFF
	imm21 := int32((immhi << 2) | immlo)
	if (imm21 & 0x100000) != 0 {
		imm21 |= ^int32(0x1FFFFF)
	}
	return (pc & ^uint64(0xFFF)) + uint64(int64(imm21)<<12)
}

/* ADR: PC + simm21 */
func decodeADR(pc uint64, word uint32) uint64 {
	immlo := (word >> 29) & 0x3
	immhi := (word >> 5) & 0x7FFFF
	imm21 := int32((immhi << 2) | immlo)
	if (imm21 & 0x100000) != 0 {
		imm21 |= ^int32(0x1FFFFF)
	}
	return pc + uint64(int64(imm21))
}

func emitImm64(rd byte, val uint64) []byte {
	out := []byte{opLdri64, rd}
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], val)
	return append(out, buf[:]...)
}

func emitImm64Vaddr(rd byte, val uint64) []byte {
	out := []byte{opLdri64Vaddr, rd}
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], val)
	return append(out, buf[:]...)
}

func emitAddImm(rd, rn byte, imm int32) []byte {
	return []byte{
		opAddImm, rd, rn,
		byte(imm), byte(imm >> 8), byte(imm >> 16), byte(imm >> 24),
	}
}

func emitBrRel(rel int32) []byte {
	return []byte{
		opBr,
		byte(rel), byte(rel >> 8), byte(rel >> 16), byte(rel >> 24),
	}
}

func emitBCond(cond byte, rel int32) []byte {
	return []byte{
		opBCond, cond,
		byte(rel), byte(rel >> 8), byte(rel >> 16), byte(rel >> 24),
	}
}

func emitBrReg(rn byte) []byte {
	return []byte{opBrReg, rn}
}

func emitBlrReg(rn byte) []byte {
	return []byte{opBlrReg, rn}
}

func emitCallNat(addr uint64) []byte {
	out := []byte{opCallNat}
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], addr)
	return append(out, buf[:]...)
}

func emitCallNatVaddr(addr uint64) []byte {
	out := []byte{opCallNatVaddr}
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], addr)
	return append(out, buf[:]...)
}

func emitLdrStrU64(op byte, rt, rn byte, off int32) []byte {
	return []byte{
		op, rt, rn,
		byte(off), byte(off >> 8), byte(off >> 16), byte(off >> 24),
	}
}

func emitLdrStrRegOff(op byte, rt, rn, rm, width, extend, scale byte) []byte {
	return []byte{op, rt, rn, rm, width, extend, scale}
}

func emitLdStUR(op byte, rt, rn byte, simm int32) []byte {
	return []byte{
		op, rt, rn,
		byte(simm), byte(simm >> 8), byte(simm >> 16), byte(simm >> 24),
	}
}
