package main

// 模块 O — 原生 .text wipe 区 XOR 加密（与 runtime axvm_stext_crypt 对合）。

func stextCryptRange(buf []byte, master []byte, fnID uint32) {
	if len(buf) == 0 || len(master) < 32 {
		return
	}
	roll := byte(fnID ^ uint32(master[1]) ^ 0x7E)
	for i := range buf {
		k := master[(i+int(fnID)*3)&31] ^ roll ^ byte(i*11+0x2D)
		buf[i] ^= k
		roll = (roll + byte(i+1) + k) ^ 0xA3
	}
}
