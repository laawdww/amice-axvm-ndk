package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
)

const (
	axdsMagic       = 0x31445841 /* 'AXD1' */
	axdsVersion     = 0x00010000
	axdsVersion2    = 0x00010001
	axdsVersion3    = 0x00010002 /* flags: APK_BIND; cipher MK2 (nonce-as-key, legacy) */
	axdsVersion4    = 0x00010003 /* APK_BIND required; cipher MK3 (wrap key from pkg||cert) */
	axdsFlagApkBind = 0x00000001
	axdsSize        = 64
	axdsWrapPrefix  = "AXVM_AXDS_WRAP1"
)

func dynseedMasterCipherV1(buf []byte, nonce []byte) {
	for i := range buf {
		k := nonce[i&15] ^ nonce[(i*7+3)&15] ^ byte(i*167+0x3B)
		buf[i] ^= k
	}
}

/* Legacy MK2: HMAC-SHA256(nonce, "AXDS-MK2"||block) — nonce is public; do not use for new packs. */
func dynseedMasterCipher(buf []byte, nonce []byte) {
	if len(nonce) < 16 {
		return
	}
	key := nonce[:16]
	for off, block := 0, 0; off < len(buf); off, block = off+32, block+1 {
		msg := []byte{'A', 'X', 'D', 'S', '-', 'M', 'K', '2', byte(block)}
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write(msg)
		ks := mac.Sum(nil)
		n := len(buf) - off
		if n > 32 {
			n = 32
		}
		for i := 0; i < n; i++ {
			buf[off+i] ^= ks[i]
		}
	}
}

/*
 * axdsWrapKey: domain-separated key from package + cert SHA-256.
 * Must match runtime axvm_dynseed_axds_wrap_key.
 * HMAC key is a fixed public domain separator (not a secret); secrecy comes from
 * requiring apk identity before any rawSeed plaintext exists — nonce alone is insufficient.
 */
func axdsWrapKey(packageName string, certSHA256 []byte) []byte {
	if len(certSHA256) != 32 {
		return nil
	}
	domain := []byte{
		0x41, 0x58, 0x56, 0x4d, 0x5f, 0x41, 0x58, 0x44,
		0x53, 0x5f, 0x44, 0x4b, 0x31, 0x00, 0x00, 0x00,
		0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x15,
		0xd1, 0xce, 0x4e, 0x5b, 0x9f, 0xa5, 0x5a, 0xa5,
	}
	msg := make([]byte, 0, len(axdsWrapPrefix)+len(packageName)+1+32)
	msg = append(msg, axdsWrapPrefix...)
	msg = append(msg, packageName...)
	msg = append(msg, 0)
	msg = append(msg, certSHA256...)
	mac := hmac.New(sha256.New, domain)
	_, _ = mac.Write(msg)
	return mac.Sum(nil)
}

/* MK3: HMAC-SHA256(wrapKey, "AXDS-MK3"||nonce||block) keystream. */
func dynseedMasterCipherV3(buf, nonce, wrapKey []byte) {
	if len(nonce) < 16 || len(wrapKey) < 32 {
		return
	}
	for off, block := 0, 0; off < len(buf); off, block = off+32, block+1 {
		msg := make([]byte, 0, 8+16+1)
		msg = append(msg, 'A', 'X', 'D', 'S', '-', 'M', 'K', '3')
		msg = append(msg, nonce[:16]...)
		msg = append(msg, byte(block))
		mac := hmac.New(sha256.New, wrapKey[:32])
		_, _ = mac.Write(msg)
		ks := mac.Sum(nil)
		n := len(buf) - off
		if n > 32 {
			n = 32
		}
		for i := 0; i < n; i++ {
			buf[off+i] ^= ks[i]
		}
	}
}

/*
 * rawSeed：AXDS 中加密存放的 32 字节种子材料（非最终 MasterSeed）。
 * apkBind=true → AXDS v4 + MK3（wrap key = pkg||cert）；运行时再 HMAC 派生有效 MasterSeed。
 */
func buildDynSeedBlock(rawSeed []byte, apkBind bool, packageName string, certSHA256 []byte) []byte {
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

	ver := uint32(axdsVersion2)
	var flags uint32
	if apkBind {
		if packageName == "" || len(certSHA256) != 32 {
			/* Caller must supply binding; fall back would reintroduce nonce-as-key. */
			panic("buildDynSeedBlock: apk-bind requires package + cert")
		}
		wrap := axdsWrapKey(packageName, certSHA256)
		dynseedMasterCipherV3(enc, nonce, wrap)
		ver = axdsVersion4
		flags = axdsFlagApkBind
		for i := range wrap {
			wrap[i] = 0
		}
	} else {
		dynseedMasterCipher(enc, nonce)
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
