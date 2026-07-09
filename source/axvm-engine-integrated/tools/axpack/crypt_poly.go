package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

const axvmPurposeCrypt = 0x50595243 /* 'CRYP' */

func masterSubkeyByte(master []byte, purpose uint32) byte {
	if len(master) < 32 {
		return 0
	}
	tag := make([]byte, 4)
	binary.LittleEndian.PutUint32(tag, purpose)
	m := hmac.New(sha256.New, master[:32])
	_, _ = m.Write(tag)
	sum := m.Sum(nil)
	return sum[0]
}

func cryptV1(buf, seed []byte, funcID uint32) {
	s := funcID ^ 0xC3A5C85C
	for i := range buf {
		s = s*1664525 + 1013904223 + uint32(seed[i&15])
		k := byte(s >> 24)
		k ^= byte(i*7 + int(funcID))
		buf[i] ^= k
	}
}

func cryptV2(buf, seed []byte, funcID uint32) {
	roll := seed[7] ^ byte(funcID)
	for i := range buf {
		k := seed[(i+int(funcID))&15] + roll + byte(i>>2)
		buf[i] ^= k
		/* 仅用 keystream 字节推进 roll，保证 XOR 自逆（多字节 roundtrip）。 */
		roll = (roll*31 + k) ^ seed[i&15]
	}
}

func cryptV3(buf, seed []byte, funcID uint32) {
	s := uint64(seed[0])<<56 | uint64(seed[1])<<48 | uint64(funcID)
	for i := range buf {
		s ^= s << 13
		s ^= s >> 7
		s ^= s << 17
		k := byte(s>>(i&7)) ^ seed[(i*3+int(funcID))&15]
		buf[i] ^= k
		s += uint64(k) + uint64(i)
	}
}

func cryptVariant(buf []byte, seed []byte, master []byte, funcID, entryPC uint32) {
	if len(buf) == 0 {
		return
	}
	v := int(seed[15] & 3)
	if len(master) >= 32 {
		v = int(masterSubkeyByte(master, axvmPurposeCrypt) & 3)
	}
	switch v {
	case 1:
		cryptV1(buf, seed, funcID)
	case 2:
		cryptV2(buf, seed, funcID)
	case 3:
		cryptV3(buf, seed, funcID)
	default:
		crypt(buf, seed, entryPC, funcID)
	}
}
