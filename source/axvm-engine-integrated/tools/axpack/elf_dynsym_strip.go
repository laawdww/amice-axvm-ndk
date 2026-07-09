package main

import (
	"debug/elf"
	"encoding/binary"
)

// 模块 P — pack 阶段 scrub 受保护符号在 .dynstr 中的可读名称。
func stripDynSymNames(out []byte, ef *elf.File, funcs []fnInfo) error {
	dynstr := ef.Section(".dynstr")
	dynsym := ef.Section(".dynsym")
	if dynstr == nil || dynsym == nil {
		return nil
	}
	names := map[string]bool{}
	for i := range funcs {
		names[funcs[i].Name] = true
	}
	data, err := dynsym.Data()
	if err != nil {
		return err
	}
	entSize := int(dynsym.Entsize)
	if entSize <= 0 {
		entSize = 24
	}
	strBase := int64(dynstr.Offset)
	for off := 0; off+entSize <= len(data); off += entSize {
		stName := binary.LittleEndian.Uint32(data[off:])
		if stName == 0 {
			continue
		}
		nameOff := strBase + int64(stName)
		if nameOff <= 0 || nameOff >= int64(len(out)) {
			continue
		}
		end := nameOff
		for end < int64(len(out)) && out[end] != 0 {
			end++
		}
		name := string(out[nameOff:end])
		if !names[name] {
			continue
		}
		for i := nameOff; i <= end && i < int64(len(out)); i++ {
			out[i] = 0
		}
		symOff := int64(dynsym.Offset) + int64(off)
		if symOff+4 <= int64(len(out)) {
			binary.LittleEndian.PutUint32(out[symOff:], 0)
		}
	}
	return nil
}
