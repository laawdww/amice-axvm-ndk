package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"strings"
)

const dtNeeded = 1

/* 向 .dynamic 追加 DT_NEEDED（dep 为 soname，如 libaxvm.so）；dep 为 "-" 或空则跳过 */
func addDTNeeded(raw []byte, dep string) ([]byte, error) {
	dep = strings.TrimSpace(dep)
	if dep == "" || dep == "-" {
		return raw, nil
	}

	ef, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	dynSec := ef.Section(".dynamic")
	dynstrSec := ef.Section(".dynstr")
	if dynSec == nil || dynstrSec == nil {
		return nil, fmt.Errorf("addDTNeeded: missing .dynamic or .dynstr")
	}

	out := append([]byte(nil), raw...)
	dynstr, err := dynstrSec.Data()
	if err != nil {
		return nil, err
	}
	if bytes.Contains(dynstr, []byte(dep)) {
		return out, nil
	}

	newStrOff := len(dynstr)
	dynstr = append(dynstr, []byte(dep)...)
	dynstr = append(dynstr, 0)

	dynOff := int(dynSec.Offset)
	dynEnd := dynOff + int(dynSec.Size)
	if dynEnd > len(out) {
		return nil, fmt.Errorf("addDTNeeded: .dynamic oob")
	}
	dynstrOff := int(dynstrSec.Offset)
	oldStrEnd := dynstrOff + int(dynstrSec.Size)
	/* .dynstr is often packed flush against .gnu.version — never clobber the next section. */
	nextSecOff := len(out)
	for _, sec := range ef.Sections {
		if sec == nil || sec.Offset == 0 {
			continue
		}
		off := int(sec.Offset)
		if off >= oldStrEnd && off < nextSecOff {
			nextSecOff = off
		}
	}
	if dynstrOff+len(dynstr) > nextSecOff {
		return nil, fmt.Errorf("addDTNeeded: no room to grow .dynstr by %d bytes (would clobber next section at 0x%x); link -l%s at build time or use -dep -",
			len(dynstr)-int(dynstrSec.Size), nextSecOff, dep)
	}
	if dynstrOff+len(dynstr) > len(out) {
		grow := dynstrOff + len(dynstr) - len(out)
		out = append(out, make([]byte, grow)...)
	}
	copy(out[dynstrOff:], dynstr)

	entsz := 16
	if ef.Class != elf.ELFCLASS64 {
		entsz = 8
	}
	nullIdx := -1
	for off := dynOff; off+entsz <= dynEnd; off += entsz {
		var tag uint64
		if entsz == 16 {
			tag = binary.LittleEndian.Uint64(out[off : off+8])
		} else {
			tag = uint64(binary.LittleEndian.Uint32(out[off : off+4]))
		}
		if tag == uint64(elf.DT_NULL) {
			nullIdx = off
			break
		}
	}
	if nullIdx < 0 {
		return nil, fmt.Errorf("addDTNeeded: no DT_NULL slot")
	}
	next := nullIdx + entsz
	if next+entsz > dynEnd {
		return nil, fmt.Errorf("addDTNeeded: no room after DT_NULL")
	}
	if entsz == 16 {
		binary.LittleEndian.PutUint64(out[nullIdx:nullIdx+8], dtNeeded)
		binary.LittleEndian.PutUint64(out[nullIdx+8:nullIdx+16], uint64(newStrOff))
		binary.LittleEndian.PutUint64(out[next:next+8], uint64(elf.DT_NULL))
		binary.LittleEndian.PutUint64(out[next+8:next+16], 0)
	} else {
		binary.LittleEndian.PutUint32(out[nullIdx:nullIdx+4], dtNeeded)
		binary.LittleEndian.PutUint32(out[nullIdx+4:nullIdx+8], uint32(newStrOff))
		binary.LittleEndian.PutUint32(out[next:next+4], uint32(elf.DT_NULL))
		binary.LittleEndian.PutUint32(out[next+4:next+8], 0)
	}

	newDynSize := uint64(dynEnd - dynOff + entsz)
	newStrSize := uint64(len(dynstr))
	shoff := int(binary.LittleEndian.Uint64(out[40:48]))
	shentsize := int(binary.LittleEndian.Uint16(out[58:60]))
	shnum := int(binary.LittleEndian.Uint16(out[60:62]))
	shstr := ef.Section(".shstrtab")
	var shstrData []byte
	if shstr != nil {
		shstrData, _ = shstr.Data()
	}
	for i := 0; i < shnum; i++ {
		sh := shoff + i*shentsize
		if sh+64 > len(out) {
			break
		}
		noff := int(binary.LittleEndian.Uint32(out[sh : sh+4]))
		name := ""
		if shstrData != nil && noff < len(shstrData) {
			end := bytes.IndexByte(shstrData[noff:], 0)
			if end >= 0 {
				name = string(shstrData[noff : noff+end])
			}
		}
		switch name {
		case ".dynstr":
			binary.LittleEndian.PutUint64(out[sh+32:sh+40], newStrSize)
		case ".dynamic":
			binary.LittleEndian.PutUint64(out[sh+32:sh+40], newDynSize)
		}
	}

	phoff := int(binary.LittleEndian.Uint64(out[32:40]))
	phentsize := int(binary.LittleEndian.Uint16(out[54:56]))
	phnum := int(binary.LittleEndian.Uint16(out[56:58]))
	for i := 0; i < phnum; i++ {
		po := phoff + i*phentsize
		if po+56 > len(out) {
			break
		}
		if elf.ProgType(binary.LittleEndian.Uint32(out[po:])) != elf.PT_DYNAMIC {
			continue
		}
		binary.LittleEndian.PutUint64(out[po+32:po+40], newDynSize)
		binary.LittleEndian.PutUint64(out[po+40:po+48], newDynSize)
		break
	}

	return out, nil
}
