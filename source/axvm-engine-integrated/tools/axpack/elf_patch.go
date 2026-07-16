package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"strings"
)

const axvmLoadAlign uint64 = 0x4000

func rwLoadSeg(ef *elf.File) (*elf.Prog, error) {
	for _, p := range ef.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&elf.PF_W != 0 && p.Flags&elf.PF_X == 0 {
			return p, nil
		}
	}
	return nil, fmt.Errorf("no RW PT_LOAD")
}

func align64(v uint64, a uint64) uint64 {
	if a == 0 {
		return v
	}
	return (v + a - 1) / a * a
}

func vaddrForFileOffset(minVaddr uint64, fileOff int64, align uint64) uint64 {
	if align == 0 {
		return minVaddr
	}
	rem := uint64(fileOff) % align
	vaddr := align64(minVaddr, align) + rem
	if vaddr < minVaddr {
		vaddr += align
	}
	return vaddr
}

func fillSparePhdr(raw []byte, poff, vaddr, filesz uint64) error {
	phoff := int(binary.LittleEndian.Uint64(raw[32:40]))
	phentsize := int(binary.LittleEndian.Uint16(raw[54:56]))
	phnum := int(binary.LittleEndian.Uint16(raw[56:58]))
	rep := -1
	for _, typ := range []elf.ProgType{elf.PT_GNU_EH_FRAME, elf.PT_GNU_STACK, elf.PT_NOTE} {
		for i := 0; i < phnum; i++ {
			off := phoff + i*phentsize
			if binary.LittleEndian.Uint32(raw[off:]) == uint32(typ) {
				rep = off
				break
			}
		}
		if rep >= 0 {
			break
		}
	}
	if rep < 0 {
		return fmt.Errorf("no spare phdr slot")
	}
	binary.LittleEndian.PutUint32(raw[rep:], uint32(elf.PT_LOAD))
	binary.LittleEndian.PutUint32(raw[rep+4:], uint32(elf.PF_R|elf.PF_X))
	binary.LittleEndian.PutUint64(raw[rep+8:], poff)
	binary.LittleEndian.PutUint64(raw[rep+16:], vaddr)
	binary.LittleEndian.PutUint64(raw[rep+24:], vaddr)
	binary.LittleEndian.PutUint64(raw[rep+32:], filesz)
	binary.LittleEndian.PutUint64(raw[rep+40:], filesz)
	binary.LittleEndian.PutUint64(raw[rep+48:], axvmLoadAlign)
	return nil
}

// normalizePhdrOrder keeps PT_PHDR first, then PT_LOAD sorted by vaddr, then
// PT_DYNAMIC / PT_GNU_RELRO, then other program headers.
func normalizePhdrOrder(raw []byte) error {
	if len(raw) < 64 {
		return fmt.Errorf("elf too small")
	}
	phoff := int(binary.LittleEndian.Uint64(raw[32:40]))
	phentsize := int(binary.LittleEndian.Uint16(raw[54:56]))
	phnum := int(binary.LittleEndian.Uint16(raw[56:58]))
	if phoff <= 0 || phentsize <= 0 || phnum <= 0 {
		return fmt.Errorf("invalid phdr table")
	}

	read := func() [][]byte {
		out := make([][]byte, phnum)
		for i := 0; i < phnum; i++ {
			off := phoff + i*phentsize
			out[i] = append([]byte(nil), raw[off:off+phentsize]...)
		}
		return out
	}

	entries := read()
	var phdr []byte
	var loads [][]byte
	var dynamic []byte
	var relro []byte
	var rest [][]byte
	for _, e := range entries {
		switch elf.ProgType(binary.LittleEndian.Uint32(e[0:4])) {
		case elf.PT_PHDR:
			phdr = e
		case elf.PT_LOAD:
			loads = append(loads, e)
		case elf.PT_DYNAMIC:
			dynamic = e
		case elf.PT_GNU_RELRO:
			relro = e
		default:
			rest = append(rest, e)
		}
	}
	if phdr == nil {
		/* NDK ET_DYN 常省略 PT_PHDR；仍重排 LOAD，不强制要求 PHDR */
		fmt.Fprintf(os.Stderr, "axpack: note: input has no PT_PHDR; reordering LOADs only\n")
	}
	sort.Slice(loads, func(i, j int) bool {
		vi := binary.LittleEndian.Uint64(loads[i][16:24])
		vj := binary.LittleEndian.Uint64(loads[j][16:24])
		return vi < vj
	})

	ordered := make([][]byte, 0, phnum)
	if phdr != nil {
		ordered = append(ordered, phdr)
	}
	ordered = append(ordered, loads...)
	if dynamic != nil {
		ordered = append(ordered, dynamic)
	}
	if relro != nil {
		ordered = append(ordered, relro)
	}
	ordered = append(ordered, rest...)
	if len(ordered) != phnum {
		return fmt.Errorf("phdr reorder mismatch")
	}
	for i := 0; i < phnum; i++ {
		off := phoff + i*phentsize
		copy(raw[off:off+phentsize], ordered[i])
	}
	return nil
}

func insertAxvmPhdrSlot(raw []byte) ([]byte, error) {
	if len(raw) < 64 {
		return nil, fmt.Errorf("elf too small")
	}
	phoff := int64(binary.LittleEndian.Uint64(raw[32:40]))
	phentsize := int64(binary.LittleEndian.Uint16(raw[54:56]))
	phnum := int64(binary.LittleEndian.Uint16(raw[56:58]))
	insertAt := phoff + phnum*phentsize

	newPh := make([]byte, phentsize)
	out := make([]byte, 0, len(raw)+int(phentsize))
	out = append(out, raw[:insertAt]...)
	out = append(out, newPh...)
	out = append(out, raw[insertAt:]...)

	delta := phentsize
	if err := shiftPhdrOffsets(out, insertAt, delta); err != nil {
		return nil, err
	}
	if err := fixElfHeader(out, insertAt, delta); err != nil {
		return nil, err
	}
	if err := fixSectionHeaders(out, nil, insertAt, delta); err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint16(out[56:58], uint16(phnum+1))

	for i := int64(0); i <= phnum; i++ {
		off := int(phoff + i*phentsize)
		if binary.LittleEndian.Uint32(out[off:]) == uint32(elf.PT_PHDR) {
			fs := binary.LittleEndian.Uint64(out[off+32 : off+40])
			binary.LittleEndian.PutUint64(out[off+32:off+40], fs+uint64(phentsize))
			ms := binary.LittleEndian.Uint64(out[off+40 : off+48])
			binary.LittleEndian.PutUint64(out[off+40:off+48], ms+uint64(phentsize))
			break
		}
	}
	return out, nil
}

func fillAxvmPhdr(raw []byte, poff, vaddr, filesz uint64) error {
	phoff := int(binary.LittleEndian.Uint64(raw[32:40]))
	phentsize := int(binary.LittleEndian.Uint16(raw[54:56]))
	phnum := int(binary.LittleEndian.Uint16(raw[56:58]))
	if phnum == 0 {
		return fmt.Errorf("no phdrs")
	}
	off := phoff + (phnum-1)*phentsize
	if off+phentsize > len(raw) {
		return fmt.Errorf("axvm phdr slot oob")
	}
	binary.LittleEndian.PutUint32(raw[off:], uint32(elf.PT_LOAD))
	binary.LittleEndian.PutUint32(raw[off+4:], uint32(elf.PF_R|elf.PF_X))
	binary.LittleEndian.PutUint64(raw[off+8:], poff)
	binary.LittleEndian.PutUint64(raw[off+16:], vaddr)
	binary.LittleEndian.PutUint64(raw[off+24:], vaddr)
	binary.LittleEndian.PutUint64(raw[off+32:], filesz)
	binary.LittleEndian.PutUint64(raw[off+40:], filesz)
	binary.LittleEndian.PutUint64(raw[off+48:], 0x1000)
	return nil
}

func insertAxvmPhdr(raw []byte, poff, vaddr, filesz uint64) ([]byte, error) {
	if len(raw) < 64 {
		return nil, fmt.Errorf("elf too small")
	}
	phoff := int64(binary.LittleEndian.Uint64(raw[32:40]))
	phentsize := int64(binary.LittleEndian.Uint16(raw[54:56]))
	phnum := int64(binary.LittleEndian.Uint16(raw[56:58]))
	insertAt := phoff + phnum*phentsize

	newPh := make([]byte, phentsize)
	binary.LittleEndian.PutUint32(newPh[0:], uint32(elf.PT_LOAD))
	binary.LittleEndian.PutUint32(newPh[4:], uint32(elf.PF_R|elf.PF_X))
	binary.LittleEndian.PutUint64(newPh[8:], poff)
	binary.LittleEndian.PutUint64(newPh[16:], vaddr)
	binary.LittleEndian.PutUint64(newPh[24:], vaddr)
	binary.LittleEndian.PutUint64(newPh[32:], filesz)
	binary.LittleEndian.PutUint64(newPh[40:], filesz)
	binary.LittleEndian.PutUint64(newPh[48:], 0x1000)

	out := make([]byte, 0, len(raw)+int(phentsize))
	out = append(out, raw[:insertAt]...)
	out = append(out, newPh...)
	out = append(out, raw[insertAt:]...)

	delta := phentsize
	if err := shiftPhdrOffsets(out, insertAt, delta); err != nil {
		return nil, err
	}
	if err := fixElfHeader(out, insertAt, delta); err != nil {
		return nil, err
	}
	if err := fixSectionHeaders(out, nil, insertAt, delta); err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint16(out[56:58], uint16(phnum+1))

	for i := int64(0); i <= phnum; i++ {
		off := int(phoff + i*phentsize)
		if binary.LittleEndian.Uint32(out[off:]) == uint32(elf.PT_PHDR) {
			fs := binary.LittleEndian.Uint64(out[off+32 : off+40])
			binary.LittleEndian.PutUint64(out[off+32:off+40], fs+uint64(phentsize))
			ms := binary.LittleEndian.Uint64(out[off+40 : off+48])
			binary.LittleEndian.PutUint64(out[off+40:off+48], ms+uint64(phentsize))
			break
		}
	}
	return out, nil
}

func shiftPhdrOffsets(raw []byte, insertOff, delta int64) error {
	phoff := int(binary.LittleEndian.Uint64(raw[32:40]))
	phentsize := int(binary.LittleEndian.Uint16(raw[54:56]))
	phnum := int(binary.LittleEndian.Uint16(raw[56:58]))
	for i := 0; i < phnum; i++ {
		off := phoff + i*phentsize
		if off+56 > len(raw) {
			break
		}
		po := int64(binary.LittleEndian.Uint64(raw[off+8 : off+16]))
		if po >= insertOff {
			binary.LittleEndian.PutUint64(raw[off+8:off+16], uint64(po+delta))
		}
	}
	return nil
}

func appendAxvmPhdr(raw []byte, poff, vaddr, filesz uint64) error {
	if len(raw) < 64 {
		return fmt.Errorf("elf too small")
	}
	phoff := binary.LittleEndian.Uint64(raw[32:40])
	phentsize := int(binary.LittleEndian.Uint16(raw[54:56]))
	phnum := int(binary.LittleEndian.Uint16(raw[56:58]))

	rep := -1
	for i := 0; i < phnum; i++ {
		off := int(phoff) + i*phentsize
		if binary.LittleEndian.Uint32(raw[off:]) == uint32(elf.PT_NOTE) {
			rep = off
			break
		}
	}
	if rep < 0 {
		for i := 0; i < phnum; i++ {
			off := int(phoff) + i*phentsize
			if binary.LittleEndian.Uint32(raw[off:]) == uint32(elf.PT_GNU_STACK) {
				rep = off
				break
			}
		}
	}
	if rep < 0 {
		return fmt.Errorf("no spare phdr slot")
	}

	binary.LittleEndian.PutUint32(raw[rep:], uint32(elf.PT_LOAD))
	binary.LittleEndian.PutUint32(raw[rep+4:], uint32(elf.PF_R|elf.PF_X))
	binary.LittleEndian.PutUint64(raw[rep+8:], poff)
	binary.LittleEndian.PutUint64(raw[rep+16:], vaddr)
	binary.LittleEndian.PutUint64(raw[rep+24:], vaddr)
	binary.LittleEndian.PutUint64(raw[rep+32:], filesz)
	binary.LittleEndian.PutUint64(raw[rep+40:], filesz)
	binary.LittleEndian.PutUint64(raw[rep+48:], 0x1000)
	return nil
}

func sortPhdrsByVaddr(raw []byte) error {
	phoff := int(binary.LittleEndian.Uint64(raw[32:40]))
	phentsize := int(binary.LittleEndian.Uint16(raw[54:56]))
	phnum := int(binary.LittleEndian.Uint16(raw[56:58]))
	if phnum <= 1 {
		return nil
	}
	entries := make([][]byte, phnum)
	for i := 0; i < phnum; i++ {
		off := phoff + i*phentsize
		entries[i] = append([]byte(nil), raw[off:off+phentsize]...)
	}
	for i := 0; i < phnum-1; i++ {
		for j := i + 1; j < phnum; j++ {
			vi := binary.LittleEndian.Uint64(entries[i][16:24])
			vj := binary.LittleEndian.Uint64(entries[j][16:24])
			if vi > vj {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}
	for i := 0; i < phnum; i++ {
		off := phoff + i*phentsize
		copy(raw[off:off+phentsize], entries[i])
	}
	return nil
}

/* bumpProgramVaddrs slides RW (and later) LOAD vaddrs to widen the RX/RW pack hole. */
func bumpProgramVaddrs(raw []byte, threshold, delta uint64) error {
	if delta == 0 {
		return nil
	}
	phoff := int(binary.LittleEndian.Uint64(raw[32:40]))
	phentsize := int(binary.LittleEndian.Uint16(raw[54:56]))
	phnum := int(binary.LittleEndian.Uint16(raw[56:58]))
	for i := 0; i < phnum; i++ {
		off := phoff + i*phentsize
		if off+56 > len(raw) {
			break
		}
		ptype := elf.ProgType(binary.LittleEndian.Uint32(raw[off:]))
		if ptype != elf.PT_LOAD && ptype != elf.PT_GNU_RELRO && ptype != elf.PT_DYNAMIC {
			continue
		}
		vaddr := binary.LittleEndian.Uint64(raw[off+16 : off+24])
		if vaddr < threshold {
			continue
		}
		binary.LittleEndian.PutUint64(raw[off+16:off+24], vaddr+delta)
		binary.LittleEndian.PutUint64(raw[off+24:off+32], vaddr+delta)
	}
	shoff := binary.LittleEndian.Uint64(raw[40:48])
	shentsize := int(binary.LittleEndian.Uint16(raw[58:60]))
	shnum := int(binary.LittleEndian.Uint16(raw[60:62]))
	for i := 0; i < shnum; i++ {
		off := int(shoff) + i*shentsize
		if off+64 > len(raw) {
			break
		}
		addr := binary.LittleEndian.Uint64(raw[off+16 : off+24])
		if addr != 0 && addr >= threshold {
			binary.LittleEndian.PutUint64(raw[off+16:off+24], addr+delta)
		}
	}
	if err := patchDynamicTags(raw, threshold, delta); err != nil {
		return err
	}
	if err := patchRelaOffsets(raw, threshold, delta); err != nil {
		return err
	}
	if err := patchDynsymValues(raw, threshold, delta); err != nil {
		return err
	}
	/* .text/.plt 里 ADRP 页偏移在链接期已写死；RW 上滑后必须改写，否则 ctor/GOT 仍落进洞 */
	return patchExecutableAdrpForBump(raw, threshold, delta)
}

/* ADRP: (insn & 0x9F000000) == 0x90000000 */
func isADRP(word uint32) bool {
	return word&0x9F000000 == 0x90000000
}

func encodeADRP(rd uint32, pc, targetPage uint64) (uint32, error) {
	page := pc &^ uint64(0xFFF)
	imm21 := int64(targetPage-page) >> 12
	if imm21 < -(1<<20) || imm21 >= (1<<20) {
		return 0, fmt.Errorf("ADRP imm out of range pc=0x%X target=0x%X", pc, targetPage)
	}
	immlo := uint32(imm21) & 0x3
	immhi := (uint32(imm21) >> 2) & 0x7FFFF
	return (1 << 31) | (immlo << 29) | (0x10 << 24) | (immhi << 5) | (rd & 0x1F), nil
}

/* 仅扫描 .text/.plt：RX PT_LOAD 还含 .gnu.hash/.dynsym，其 uint32 会误匹配 ADRP 掩码 */
func patchExecutableAdrpForBump(raw []byte, threshold, delta uint64) error {
	if delta == 0 {
		return nil
	}
	if delta&0xFFF != 0 {
		return fmt.Errorf("RW bump delta 0x%X not page-aligned", delta)
	}
	thresholdPage := threshold &^ uint64(0xFFF)
	ef, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	patched := 0
	for _, name := range []string{".text", ".plt"} {
		sec := ef.Section(name)
		if sec == nil || sec.Size == 0 {
			continue
		}
		base := int64(sec.Offset)
		end := base + int64(sec.Size)
		if end > int64(len(raw)) {
			end = int64(len(raw))
		}
		vaddr0 := sec.Addr
		for fo := base; fo+4 <= end; fo += 4 {
			word := binary.LittleEndian.Uint32(raw[fo:])
			if !isADRP(word) {
				continue
			}
			pc := vaddr0 + uint64(fo-base)
			target := decodeADRPage(pc, word)
			if target < thresholdPage {
				continue
			}
			rd := word & 0x1F
			newWord, err := encodeADRP(rd, pc, target+delta)
			if err != nil {
				return err
			}
			binary.LittleEndian.PutUint32(raw[fo:], newWord)
			patched++
		}
	}
	if patched > 0 {
		fmt.Fprintf(os.Stderr, "axpack: rewritten %d ADRP after RW bump (+0x%X)\n", patched, delta)
	}
	return nil
}

func dynTagIsPointer(tag elf.DynTag) bool {
	switch tag {
	case elf.DT_NEEDED, elf.DT_SONAME, elf.DT_RPATH, elf.DT_RUNPATH,
		elf.DT_FLAGS, elf.DT_FLAGS_1, elf.DT_RELENT, elf.DT_RELAENT,
		elf.DT_STRSZ, elf.DT_SYMENT, elf.DT_RELSZ, elf.DT_RELASZ,
		elf.DT_PLTRELSZ, elf.DT_BIND_NOW,
		elf.DT_INIT_ARRAYSZ, elf.DT_FINI_ARRAYSZ, elf.DT_PREINIT_ARRAYSZ,
		elf.DT_VERNEEDNUM, elf.DT_VERDEFNUM:
		/* 计数/大小/字符串索引 — 非 vaddr */
		return false
	case elf.DT_INIT_ARRAY, elf.DT_FINI_ARRAY, elf.DT_PREINIT_ARRAY:
		/* 指向 RW 内数组的 vaddr — RW bump 必须跟着滑 */
		return true
	default:
		return true
	}
}

func patchDynamicTags(raw []byte, threshold, delta uint64) error {
	ef, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	dyn := ef.Section(".dynamic")
	if dyn == nil {
		return nil
	}
	base := int64(dyn.Offset)
	end := base + int64(dyn.Size)
	for off := base; off+16 <= end; off += 16 {
		tag := elf.DynTag(binary.LittleEndian.Uint64(raw[off:]))
		if tag == elf.DT_NULL {
			break
		}
		val := binary.LittleEndian.Uint64(raw[off+8:])
		if dynTagIsPointer(tag) && val >= threshold {
			binary.LittleEndian.PutUint64(raw[off+8:], val+delta)
		}
	}
	return nil
}

/* AArch64 relocation types we must slide when RW vaddrs move */
const (
	rAarch64Abs64    = 257
	rAarch64Relative = 1027
)

func patchRelaOffsets(raw []byte, threshold, delta uint64) error {
	ef, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	for _, name := range []string{".rela.dyn", ".rela.plt"} {
		sec := ef.Section(name)
		if sec == nil || sec.Size == 0 {
			continue
		}
		base := int64(sec.Offset)
		end := base + int64(sec.Size)
		for off := base; off+24 <= end; off += 24 {
			rOff := binary.LittleEndian.Uint64(raw[off:])
			if rOff >= threshold {
				binary.LittleEndian.PutUint64(raw[off:], rOff+delta)
			}
			rInfo := binary.LittleEndian.Uint64(raw[off+8:])
			rType := uint32(rInfo & 0xffffffff)
			/* RELATIVE/ABS64 addend 若指向被滑走的 RW，也要 +delta */
			if rType == rAarch64Relative || rType == rAarch64Abs64 {
				addend := int64(binary.LittleEndian.Uint64(raw[off+16:]))
				if addend >= int64(threshold) {
					binary.LittleEndian.PutUint64(raw[off+16:], uint64(addend+int64(delta)))
				}
			}
		}
	}
	return nil
}

/* 动态符号 st_value 落在 RW 的也要滑，避免 IFUNC/对象地址陈旧 */
func patchDynsymValues(raw []byte, threshold, delta uint64) error {
	ef, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	sec := ef.Section(".dynsym")
	if sec == nil || sec.Size == 0 || sec.Entsize == 0 {
		return nil
	}
	entsize := int64(sec.Entsize)
	if entsize < 24 {
		entsize = 24
	}
	base := int64(sec.Offset)
	end := base + int64(sec.Size)
	for off := base; off+entsize <= end; off += entsize {
		/* Elf64_Sym: st_value at +8 */
		val := binary.LittleEndian.Uint64(raw[off+8:])
		if val >= threshold {
			binary.LittleEndian.PutUint64(raw[off+8:], val+delta)
		}
	}
	return nil
}

func ensureAxvmVirtualRoom(raw []byte, packVaddr, needEnd, rwVaddr uint64) (uint64, error) {
	guardEnd := align64(needEnd, axvmLoadAlign)
	if guardEnd <= rwVaddr {
		return rwVaddr, nil
	}
	delta := align64(guardEnd-rwVaddr, axvmLoadAlign)
	if err := bumpProgramVaddrs(raw, rwVaddr, delta); err != nil {
		return rwVaddr, err
	}
	fmt.Fprintf(os.Stderr, "axpack: RW vaddr bumped 0x%X -> 0x%X (pack span 0x%X bytes)\n",
		rwVaddr, rwVaddr+delta, needEnd-packVaddr)
	return rwVaddr + delta, nil
}

func rxLoadSeg(ef *elf.File) (*elf.Prog, error) {
	for _, p := range ef.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 {
			return p, nil
		}
	}
	return nil, fmt.Errorf("no RX PT_LOAD")
}

func fixElfHeader(raw []byte, insertOff, delta int64) error {
	if len(raw) < 64 {
		return fmt.Errorf("elf too small")
	}
	shoff := int64(binary.LittleEndian.Uint64(raw[40:48]))
	if shoff >= insertOff {
		binary.LittleEndian.PutUint64(raw[40:48], uint64(shoff+delta))
	}
	return nil
}

func fixSectionHeaders(raw []byte, ef *elf.File, insertOff, delta int64) error {
	if len(raw) < 64 {
		return fmt.Errorf("elf too small")
	}
	shoff := binary.LittleEndian.Uint64(raw[40:48])
	shentsize := int(binary.LittleEndian.Uint16(raw[58:60]))
	shnum := int(binary.LittleEndian.Uint16(raw[60:62]))
	for i := 0; i < shnum; i++ {
		off := int(shoff) + i*shentsize
		if off+64 > len(raw) {
			break
		}
		shOffset := binary.LittleEndian.Uint64(raw[off+24 : off+32])
		if int64(shOffset) >= insertOff {
			binary.LittleEndian.PutUint64(raw[off+24:off+32], uint64(int64(shOffset)+delta))
		}
	}
	_ = ef
	return nil
}

func shiftSegments(raw []byte, ef *elf.File, insertOff, delta int64) error {
	phoff := int(binary.LittleEndian.Uint64(raw[32:40]))
	phentsize := int(binary.LittleEndian.Uint16(raw[54:56]))
	phnum := int(binary.LittleEndian.Uint16(raw[56:58]))
	for i := 0; i < phnum; i++ {
		off := phoff + i*phentsize
		if off+56 > len(raw) {
			break
		}
		poff := binary.LittleEndian.Uint64(raw[off+8 : off+16])
		if int64(poff) >= insertOff {
			binary.LittleEndian.PutUint64(raw[off+8:off+16], uint64(int64(poff)+delta))
		}
	}
	_ = ef
	return nil
}

func shiftRwSegment(raw []byte, ef *elf.File, insertOff, delta int64) error {
	return shiftSegments(raw, ef, insertOff, delta)
}

func alignFile(v int64, a int64) int64 {
	if a == 0 {
		return v
	}
	return (v + a - 1) / a * a
}

func patchPhdrFilesz(raw []byte, seg *elf.Prog, filesz uint64) error {
	if len(raw) < 64 {
		return fmt.Errorf("elf too small")
	}
	phoff := int(binary.LittleEndian.Uint64(raw[32:40]))
	phentsize := int(binary.LittleEndian.Uint16(raw[54:56]))
	phnum := int(binary.LittleEndian.Uint16(raw[56:58]))
	for i := 0; i < phnum; i++ {
		off := phoff + i*phentsize
		if off+56 > len(raw) {
			break
		}
		ptype := binary.LittleEndian.Uint32(raw[off:])
		pflags := binary.LittleEndian.Uint32(raw[off+4:])
		poffset := binary.LittleEndian.Uint64(raw[off+8:])
		if elf.ProgType(ptype) != elf.PT_LOAD || elf.ProgFlag(pflags)&elf.PF_X == 0 {
			continue
		}
		if poffset != seg.Off {
			continue
		}
		binary.LittleEndian.PutUint64(raw[off+32:], filesz)
		binary.LittleEndian.PutUint64(raw[off+40:], filesz)
		return nil
	}
	return fmt.Errorf("RX PT_LOAD phdr not found (off=0x%X)", seg.Off)
}

func collectFuncs(ef *elf.File, raw []byte, targets map[string]bool) ([]fnInfo, error) {
	syms, err := ef.DynamicSymbols()
	if err != nil {
		syms, err = ef.Symbols()
		if err != nil {
			return nil, err
		}
	}
	if len(targets) > 0 {
		if allSyms, symErr := ef.Symbols(); symErr == nil {
			syms = append(syms, allSyms...)
		}
	}

	text := ef.Section(".text")
	if text == nil {
		return nil, fmt.Errorf(".text not found")
	}

	var out []fnInfo
	seen := map[string]bool{}

	for _, s := range syms {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC {
			continue
		}
		if s.Section == elf.SHN_UNDEF || s.Value == 0 {
			continue
		}
		if s.Value < text.Addr || s.Value >= text.Addr+text.Size {
			continue
		}
		name := s.Name
		if len(targets) > 0 && !targets[name] {
			continue
		}
		/* aggressive（targets=nil）默认不碰 JNI/嵌入初始化：wipe 会弄断 System.load 后的 Java_* 解析 */
		if len(targets) == 0 && skipProtectByDefault(name) {
			continue
		}
		if seen[name] {
			continue
		}
		seen[name] = true

		off := int64(s.Value - text.Addr + text.Offset)
		size := int(s.Size)
		if size <= 0 || size > 8192 {
			size = scanFuncSize(raw, off, int(text.Offset+text.Size)-int(off))
		}
		code := make([]byte, size)
		copy(code, raw[off:off+int64(size)])

		out = append(out, fnInfo{
			Name:     name,
			Addr:     s.Value,
			FileOff:  off,
			Size:     size,
			OrigCode: code,
		})
	}
	return out, nil
}

/* JNI 包装、嵌入 runtime、单 SO 构造器必须留 native；业务符号用 -syms 或 aggressive 其余导出 */
func skipProtectByDefault(name string) bool {
	if strings.HasPrefix(name, "Java_") || strings.HasPrefix(name, "JNI_") {
		return true
	}
	/* Embedded runtime exports (dispatch/got_gate/invoke_native/…) must stay native.
	 * Aggressive protect of axvm_got_gate / axvm_invoke_native_asm causes stub→dispatch
	 * recursion and breaks mul/check/native-call paths. */
	if strings.HasPrefix(name, "axvm_") {
		return true
	}
	return false
}

func scanFuncSize(raw []byte, off int64, max int) int {
	limit := max
	if limit > 4096 {
		limit = 4096
	}
	for i := 0; i+4 <= limit; i += 4 {
		w := binary.LittleEndian.Uint32(raw[off+int64(i):])
		if w == arm64RET {
			return i + 4
		}
	}
	return limit
}

func fnv1a32(data []byte) uint32 {
	h := uint32(2166136261)
	for _, c := range data {
		h ^= uint32(c)
		h *= 16777619
	}
	return h
}

var _ = bytes.MinRead
