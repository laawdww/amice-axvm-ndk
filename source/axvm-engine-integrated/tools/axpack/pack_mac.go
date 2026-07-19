package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

const axpkManifestLabel = "AXPK-MANIFEST-V1"

func axpkManifestMAC32(pack []byte) uint32 {
	if len(pack) < 64 {
		return 0
	}
	hdr := pack[:64]
	blobOff := binary.LittleEndian.Uint32(hdr[20:24])
	blobSize := binary.LittleEndian.Uint32(hdr[24:28])
	total := int(blobOff + blobSize)
	if total > len(pack) || total < 64 {
		return 0
	}

	canon := append([]byte(nil), pack[:total]...)
	binary.LittleEndian.PutUint32(canon[44:48], 0) // checksum 自身不参与
	binary.LittleEndian.PutUint64(canon[48:56], 0) // file_off 为注入阶段回填
	flags := binary.LittleEndian.Uint32(canon[8:12])
	flags &^= axpkWiped // 运行时 prepatch 可能清除此位
	flags &^= axpkSeedWrapped
	binary.LittleEndian.PutUint32(canon[8:12], flags)

	seed := append([]byte(nil), hdr[28:44]...)
	/* Caller must unwrap seed before seal/verify when SEED_WRAPPED; seal path uses plaintext. */
	kdf := hmac.New(sha256.New, seed)
	_, _ = kdf.Write([]byte(axpkManifestLabel))
	key := kdf.Sum(nil)

	m := hmac.New(sha256.New, key)
	_, _ = m.Write(canon)
	sum := m.Sum(nil)
	return binary.LittleEndian.Uint32(sum[:4])
}

func sealPackManifestMAC(pack []byte) {
	if len(pack) < 64 {
		return
	}
	mac := axpkManifestMAC32(pack)
	binary.LittleEndian.PutUint32(pack[44:48], mac)
}

func packManifestTrusted(pack []byte) bool {
	if len(pack) < 64 {
		return false
	}
	want := binary.LittleEndian.Uint32(pack[44:48])
	got := axpkManifestMAC32(pack)
	return got != 0 && got == want
}
