package main

import (
	"crypto/rand"
	"encoding/binary"
)

const (
	axdsMagic       = 0x31445841 /* 'AXD1' */
	axdsVersion     = 0x00010000
	axdsVersion2    = 0x00010001
	axdsVersion3    = 0x00010002 /* flags: APK_BIND */
	axdsFlagApkBind = 0x00000001
	axdsSize        = 64
)

func dynseedMasterCipherV1(buf []byte, nonce []byte) {
	for i := range buf {
		k := nonce[i&15] ^ nonce[(i*7+3)&15] ^ byte(i*167+0x3B)
		buf[i] ^= k
	}
}

func dynseedMasterCipher(buf []byte, nonce []byte) {
	for round := 0; round < 4; round++ {
		for i := range buf {
			k := nonce[i&15] ^ nonce[(i*7+3)&15] ^ byte(i*167+0x3B) ^ byte(round*31+17)
			buf[i] ^= k
		}
	}
}

/*
 * rawSeed：AXDS 中加密存放的 32 字节种子材料（非最终 MasterSeed）。
 * apkBind=true 时运行时用 package + 签名证书 SHA-256 与 rawSeed 混合派生有效 MasterSeed。
 */
func buildDynSeedBlock(rawSeed []byte, apkBind bool) []byte {
	seed := make([]byte, 32)
	nonce := make([]byte, 16)
	if len(rawSeed) >= 32 {
		copy(seed, rawSeed[:32])
	} else {
		_, _ = rand.Read(seed)
	}
	_, _ = rand.Read(nonce)

	enc := make([]byte, 32)
	copy(enc, seed)
	dynseedMasterCipher(enc, nonce)

	ver := uint32(axdsVersion2)
	var flags uint32
	if apkBind {
		ver = axdsVersion3
		flags = axdsFlagApkBind
	}

	blk := make([]byte, axdsSize)
	binary.LittleEndian.PutUint32(blk[0:], axdsMagic)
	binary.LittleEndian.PutUint32(blk[4:], ver)
	copy(blk[8:24], nonce)
	copy(blk[24:56], enc)
	binary.LittleEndian.PutUint32(blk[56:], fnv1a32(blk[:56]))
	binary.LittleEndian.PutUint32(blk[60:], flags)

	for i := range seed {
		seed[i] = 0
	}
	return blk
}
