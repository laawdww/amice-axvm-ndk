package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

/*
 * 假 AXPK 干扰块：置于 AXDS 之后，结构形似真 pack 但 MAC/布局故意错误。
 * runtime 的 pack_valid / pack_trusted 会跳过；静态扫描会看到多个 AXP* magic。
 */
func buildDecoyPacks(n int, padSeed []byte, realMagic uint32) []byte {
	if n <= 0 {
		return nil
	}
	var out []byte
	for i := 0; i < n; i++ {
		out = append(out, buildOneDecoyPack(i, padSeed, realMagic)...)
		for len(out)%16 != 0 {
			out = append(out, 0)
		}
	}
	return out
}

/* 在 RX/RW 虚拟地址间隙内尽可能多放 decoy；AXDS 等 tail 块由 caller 预留 budget。 */
func buildDecoyPacksWithin(n int, padSeed []byte, realMagic uint32, budget int64) ([]byte, int) {
	if n <= 0 || budget <= 0 {
		return nil, 0
	}
	var out []byte
	got := 0
	for i := 0; i < n; i++ {
		one := buildOneDecoyPack(i, padSeed, realMagic)
		need := int64(len(one))
		if need%16 != 0 {
			need += 16 - need%16
		}
		if int64(len(out))+need > budget {
			break
		}
		out = append(out, one...)
		for len(out)%16 != 0 {
			out = append(out, 0)
		}
		got++
	}
	return out, got
}

func buildOneDecoyPack(idx int, padSeed []byte, realMagic uint32) []byte {
	rec := make([]byte, axvmRecSizeV2)
	name := fmt.Sprintf("_axdecoy_%d", idx)
	copy(rec[32:], name)
	binary.LittleEndian.PutUint32(rec[0:], uint32(idx+1000))
	binary.LittleEndian.PutUint32(rec[4:], fnv1a32([]byte(name)))
	binary.LittleEndian.PutUint32(rec[12:], 8)
	binary.LittleEndian.PutUint32(rec[68:], 16)
	binary.LittleEndian.PutUint32(rec[72:], encodeStubMeta(256, 64, uint8(idx&7)))

	blob := make([]byte, 40)
	copy(blob[0:], axvmMagic)
	binary.LittleEndian.PutUint32(blob[4:], axvmVersion)
	binary.LittleEndian.PutUint32(blob[16:], 40)

	hdr := make([]byte, 64)
	magic := pickDecoyMagic(idx, realMagic)
	binary.LittleEndian.PutUint32(hdr[0:], magic)
	binary.LittleEndian.PutUint32(hdr[4:], axpkVersionV2)
	binary.LittleEndian.PutUint32(hdr[8:], axpkEncrypt|axpkWiped)
	binary.LittleEndian.PutUint32(hdr[12:], 1)
	binary.LittleEndian.PutUint32(hdr[16:], 64)
	blobOff := uint32(64 + len(rec))
	binary.LittleEndian.PutUint32(hdr[20:], blobOff)
	binary.LittleEndian.PutUint32(hdr[24:], uint32(len(blob)))

	seed := make([]byte, 16)
	if len(padSeed) >= 16 {
		copy(seed, padSeed[:16])
	} else {
		_, _ = rand.Read(seed)
	}
	x := binary.LittleEndian.Uint64(seed) ^ uint64(idx+1)*0xBF58476D1CE4E5B9
	for i := 0; i < 16; i++ {
		seed[i] ^= byte(x >> (i * 3))
	}
	copy(hdr[28:44], seed)
	binary.LittleEndian.PutUint32(hdr[44:], uint32(x^0xDEC0ADD0)) /* 故意错误 MAC */

	var buf bytes.Buffer
	buf.Write(hdr)
	buf.Write(rec)
	buf.Write(blob)
	return buf.Bytes()
}

func pickDecoyMagic(idx int, realMagic uint32) uint32 {
	_ = realMagic /* 不得复用真 pack derived magic，避免静态排除 */
	candidates := []uint32{
		axpkMagic,
		0x31585042, /* AXP2 */
		0x32585041, /* 2XP1 */
		0x41585031, /* APX1 */
		0x31585030, /* AXP0 */
	}
	return candidates[idx%len(candidates)]
}
