package main

const packMagicLabel = "AXVM_PACK_MAGIC1"

/* 与 runtime axvm_dynseed.c derive_pack_magic 对齐；基于 AXDS raw seed，非 APK 绑定后的 master */
func derivePackMagic(rawSeed []byte) uint32 {
	if len(rawSeed) < 32 {
		return axpkMagic
	}
	msg := make([]byte, 0, len(packMagicLabel)+32)
	msg = append(msg, packMagicLabel...)
	msg = append(msg, rawSeed[:32]...)
	h := fnv1a32(msg)
	if h == 0 || h == axpkMagic {
		h ^= 0x5A5A5A5A
	}
	return h
}

func resolvePackMagic(rawSeed []byte, legacy bool) uint32 {
	if legacy || len(rawSeed) < 32 {
		return axpkMagic
	}
	return derivePackMagic(rawSeed)
}
