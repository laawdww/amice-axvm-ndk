package main

import (
	"encoding/binary"
	"strings"
)

/* 与 runtime pack_export_name_trusted / pack_trusted 对齐（供 axpack 探测与测试） */

func packExportNameTrusted(name string) bool {
	name = strings.TrimRight(name, "\x00")
	if name == "" {
		return false
	}
	if strings.HasPrefix(name, "_axdecoy_") {
		return false
	}
	for _, c := range name {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' {
			continue
		}
		return false
	}
	return true
}

func packFirstFuncName(pack []byte) string {
	if len(pack) < 64 {
		return ""
	}
	tableOff := binary.LittleEndian.Uint32(pack[16:20])
	funcCount := binary.LittleEndian.Uint32(pack[12:16])
	if funcCount == 0 || tableOff+axvmRecSizeV2 > uint32(len(pack)) {
		return ""
	}
	rec := pack[tableOff:]
	return strings.TrimRight(string(rec[32:68]), "\x00")
}

func packFullyTrusted(pack []byte) bool {
	if !packManifestTrusted(pack) {
		return false
	}
	return packExportNameTrusted(packFirstFuncName(pack))
}

func findLastTrustedPackInBuf(buf []byte, magic uint32) int64 {
	scan := len(buf)
	if scan > 65536 {
		scan = 65536
	}
	base := len(buf) - scan
	var last int64 = -1
	for off := 0; off+64 <= scan; off += 4 {
		p := buf[base+off:]
		got := binary.LittleEndian.Uint32(p[0:4])
		if got != magic && got != axpkMagic {
			continue
		}
		if packFullyTrusted(p) {
			last = int64(base + off)
		}
	}
	return last
}
