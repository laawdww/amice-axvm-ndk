package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
)

const (
	axIntegMagic   = 0x32585041 /* 'AXP2' */
	axIntegVersion = 0x00010000

	axIntSegBC   = 0
	axIntSegStub = 1
	axIntSegText = 2
)

// integSeg 描述一个待哈希段。off 为运行时相对基准（BC/STUB 相对 pack 首字节，
// TEXT 相对 load_base）；data 为打包时用于计算 SHA256 的最终字节视图。
type integSeg struct {
	id   uint32
	off  uint64
	size uint64
	data []byte
}

// buildIntegritySection 生成 EOF 完整性节：
//
//	hdr: magic u32, version u32, seg_count u32, reserved u32, key_seed[16]
//	entry[n]: seg_id u32, flags u32, seg_off u64, seg_size u64, enc_hash[32]
//
// enc_hash 为 SHA256(data) 经 integXorHash(keySeed, seg_id) 加密。
func buildIntegritySection(segs []integSeg, keySeed []byte) []byte {
	var buf bytes.Buffer

	hdr := make([]byte, 32)
	binary.LittleEndian.PutUint32(hdr[0:], axIntegMagic)
	binary.LittleEndian.PutUint32(hdr[4:], axIntegVersion)
	binary.LittleEndian.PutUint32(hdr[8:], uint32(len(segs)))
	binary.LittleEndian.PutUint32(hdr[12:], 0)
	copy(hdr[16:32], keySeed)
	buf.Write(hdr)

	for _, s := range segs {
		rec := make([]byte, 56)
		binary.LittleEndian.PutUint32(rec[0:], s.id)
		binary.LittleEndian.PutUint32(rec[4:], 0)
		binary.LittleEndian.PutUint64(rec[8:], s.off)
		binary.LittleEndian.PutUint64(rec[16:], s.size)

		sum := sha256.Sum256(s.data)
		h := make([]byte, 32)
		copy(h, sum[:])
		integXorHash(h, keySeed, s.id)
		copy(rec[24:], h)
		buf.Write(rec)
	}
	return buf.Bytes()
}

// integXorHash 与 runtime/src/axvm_integrity.c 的 integ_xor_hash 逐字节一致。
func integXorHash(hash []byte, keySeed []byte, segID uint32) {
	roll := byte(segID ^ uint32(keySeed[0]) ^ 0xA5)
	for i := 0; i < 32; i++ {
		k := byte(uint32(keySeed[i&15]) ^ uint32(roll) ^ uint32(i*13+int(segID)))
		cipher := hash[i]
		hash[i] ^= k
		roll = byte((uint32(roll) + uint32(cipher) + uint32(k)) ^ 0x5A)
	}
}
