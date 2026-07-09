package main

import (
	"debug/elf"
	"encoding/binary"
)

func buildPLTCallTargetMap(ef *elf.File) map[uint64]uint64 {
	out := make(map[uint64]uint64)
	if ef == nil || ef.Machine != elf.EM_AARCH64 {
		return out
	}
	plt := ef.Section(".plt")
	rela := ef.Section(".rela.plt")
	if plt == nil || rela == nil || plt.Addr == 0 {
		return out
	}
	data, err := rela.Data()
	if err != nil || len(data) < 24 {
		return out
	}
	syms, err := ef.DynamicSymbols()
	if err != nil {
		return out
	}
	entSize := int(rela.Entsize)
	if entSize <= 0 {
		entSize = 24
	}
	slotVA := plt.Addr + 0x20
	for i, off := 0, 0; off+24 <= len(data); i, off = i+1, off+entSize {
		info := binary.LittleEndian.Uint64(data[off+8:])
		typ := uint32(info)
		if typ != uint32(elf.R_AARCH64_JUMP_SLOT) {
			continue
		}
		symIdx := int(info >> 32)
		if symIdx <= 0 {
			continue
		}
		/* debug/elf omits the ELF null symbol from DynamicSymbols(). */
		symIdx--
		if symIdx < 0 || symIdx >= len(syms) {
			continue
		}
		s := syms[symIdx]
		if s.Value == 0 || s.Section == elf.SHN_UNDEF || elf.ST_TYPE(s.Info) != elf.STT_FUNC {
			continue
		}
		out[slotVA+uint64(i)*0x10] = s.Value
	}
	return out
}
