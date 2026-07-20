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
	/*
	 * Always merge .dynsym + .symtab. Version-script / stripped SOs often keep only
	 * JNI_* in dynsym; aggressive mode previously saw 0 protectable symbols.
	 */
	var syms []elf.Symbol
	if dyn, err := ef.DynamicSymbols(); err == nil {
		syms = append(syms, dyn...)
	}
	if all, err := ef.Symbols(); err == nil {
		syms = append(syms, all...)
	}
	if len(syms) == 0 {
		return nil, fmt.Errorf("no ELF symbols (.dynsym/.symtab empty)")
	}

	text := ef.Section(".text")
	if text == nil {
		return nil, fmt.Errorf(".text not found")
	}

	/* All symbol addrs in .text (FUNC/OBJECT/NOTYPE) — clamp wipe/patch against islands. */
	var allTextAddrs []uint64
	allSeen := map[uint64]bool{}
	for _, s := range syms {
		if s.Section == elf.SHN_UNDEF || s.Value == 0 {
			continue
		}
		if s.Value < text.Addr || s.Value >= text.Addr+text.Size {
			continue
		}
		if !allSeen[s.Value] {
			allSeen[s.Value] = true
			allTextAddrs = append(allTextAddrs, s.Value)
		}
	}

	var out []fnInfo
	seen := map[string]bool{}
	seenAddr := map[uint64]bool{}

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
		if name == "" || strings.Contains(name, "$") {
			continue
		}
		/* Clang unnamed lambdas: ...ENKUlvE_clEv / ...ENUlvE0_clEv (no '$' in mangling).
		 * These often wrap ObfuscatedString and must stay native. */
		if strings.Contains(name, "UlvE") {
			continue
		}
		if skipProtectByDefault(name) {
			continue
		}
		if len(targets) > 0 && !targets[name] {
			continue
		}
		if seen[name] || seenAddr[s.Value] {
			continue
		}
		seen[name] = true
		seenAddr[s.Value] = true

		off := int64(s.Value - text.Addr + text.Offset)
		size := int(s.Size)
		/* Prefer st_size; only scan when missing. Cap high — neighbor clamp is the real bound. */
		if size <= 0 || size > 65536 {
			size = scanFuncSize(raw, off, int(text.Offset+text.Size)-int(off))
		}
		if size < 8 {
			continue
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
	sort.Slice(allTextAddrs, func(i, j int) bool { return allTextAddrs[i] < allTextAddrs[j] })
	clampFuncSizesToTextNeighbors(out, text, allTextAddrs)
	/* Re-copy OrigCode after clamp (size may shrink). */
	for i := range out {
		f := &out[i]
		if f.Size < 8 {
			continue
		}
		code := make([]byte, f.Size)
		copy(code, raw[f.FileOff:f.FileOff+int64(f.Size)])
		f.OrigCode = code
	}
	filtered := out[:0]
	for _, f := range out {
		if f.Size >= 8 {
			filtered = append(filtered, f)
		}
	}
	return filtered, nil
}

/* Prevent wipe/trampoline from clobbering the next .text symbol (fat SOs often have wrong st_size). */
func clampFuncSizesToTextNeighbors(funcs []fnInfo, text *elf.Section, allTextAddrs []uint64) {
	if len(funcs) == 0 || text == nil {
		return
	}
	textEnd := text.Addr + text.Size
	for i := range funcs {
		addr := funcs[i].Addr
		end := textEnd
		/* First symbol strictly after addr. */
		idx := sort.Search(len(allTextAddrs), func(j int) bool { return allTextAddrs[j] > addr })
		if idx < len(allTextAddrs) {
			end = allTextAddrs[idx]
		}
		maxSz := int(end - addr)
		if maxSz < 0 {
			maxSz = 0
		}
		if maxSz >= 12 {
			maxSz -= 4 /* guard gap before next symbol */
		}
		if funcs[i].Size > maxSz {
			funcs[i].Size = maxSz &^ 3
		}
	}
}

/* Third-party / hook-engine symbols must stay native. Prefer denylist of known
 * libraries over an app allowlist so victim tests and app C exports stay liftable. */
func isThirdPartySkipSymbol(name string) bool {
	if strings.Contains(name, "_ZN2zz") || strings.Contains(name, "_ZNK2zz") ||
		strings.Contains(name, "Interceptor") || strings.Contains(name, "CodeBuffer") ||
		strings.Contains(name, "MemoryArena") || strings.Contains(name, "AssemblyCode") ||
		strings.Contains(name, "TurboAssembler") || strings.Contains(name, "InterceptEntry") ||
		strings.Contains(name, "InterceptRouting") || strings.Contains(name, "ClosureTrampoline") ||
		strings.Contains(name, "ZipArchive") || strings.Contains(name, "ZipEntry") ||
		strings.Contains(name, "CurlHttpClient") || strings.Contains(name, "IterCookie") ||
		/* Dobby / assembler leaves often lack zz:: prefix in this SO */
		strings.Contains(name, "OSMemory") || strings.Contains(name, "RegisterBase") ||
		strings.Contains(name, "relo_") || strings.Contains(name, "Relocate") ||
		strings.Contains(name, "Trampoline") || strings.Contains(name, "MemBlock") ||
		strings.Contains(name, "CodeGenBase") || strings.Contains(name, "AssemblerBase") ||
		strings.Contains(name, "MemoryAllocator") || strings.Contains(name, "make_addr_hookable") ||
		strings.Contains(name, "Dobby") || strings.Contains(name, "dobby") {
		return true
	}
	if strings.HasPrefix(name, "_Z") {
		return false
	}
	lower := strings.ToLower(name)
	if strings.HasPrefix(name, "__") && !strings.Contains(lower, "hook") {
		return true
	}
	for _, p := range []string{
		"ssl3_", "ssl_", "tls1_", "dtls", "seed_", "aria_", "siphash", "whirlpool",
		"x25519", "ed25519", "blake2", "poly1305", "chacha", "nconf_", "_conf_",
		"do_ext_nconf", "crypto_", "openssl", "ossl_", "evp_", "asn1", "x509",
		"bio_", "pem_", "rsa_", "dsa_", "ecdsa_", "aes_", "bn_", "err_", "obj_",
		"pkcs", "hmac_", "sha1", "sha224", "sha256", "sha384", "sha512", "md5_",
		"des_", "rand_", "cms_", "ocsp", "engine_", "sct_", "comp_", "dso_",
		"async_", "srp_", "bf_", "cast_", "idea_", "rc2_", "rc4_", "sm2_", "sm4_",
		"camellia", "curl_", "lws_", "nghttp", "brotli", "miniz", "inflate",
		"deflate", "adler32", "cjson", "lh_", "i2d_", "d2i_", "hkdf_", "scrypt_",
		"conf_modules", "conf_value", "conf_ssl", "cmac_", "md4_", "ripemd",
		"sha3_", "sm3_", "ctr_bcc",
		/* OpenSSL TLS leaf names often lack ssl_/tls1_ prefixes */
		"tls_parse_", "tls_construct_", "tls_process_", "tls_choose_", "tls_post_",
		"tls_validate_", "tls_collect_", "tls_prepare_", "tls12_", "tls13_",
		"do_ssl3_", "n_ssl3_", "ssl3_mac", "bytes_to_cipher", "send_certificate",
		"gf_", "curve448", "x448_", "handshake_", "rops_handle_",
		/* cJSON static helpers (plain names — PrintUnformatted calls print) */
		"parse_value", "parse_number", "parse_string", "parse_array", "parse_object",
		"buffer_skip", "skip_utf8", "print_value", "print_number", "print_string",
		"print_array", "print_object", "print_string_ptr", "parse_hex4", "parse_ca_names",
		"parse_bag", "parse_tagging", "sanitize_cookie", "sanitize_line",
	} {
		if strings.HasPrefix(lower, p) || lower == "print" || lower == "update" {
			/* bare "print"/"update" are cJSON/OpenSSL internals in this SO */
			if lower == "update" && (strings.Contains(name, "hook") || strings.HasPrefix(name, "_Z")) {
				continue
			}
			if lower == "print" && strings.HasPrefix(name, "_Z") {
				continue
			}
			return true
		}
	}
	/* OpenSSL ASN.1/DH/EC *print* leaves (DHparams_print, print_bio, …) — plain C only */
	if !strings.HasPrefix(name, "_Z") &&
		(strings.Contains(lower, "_print") || strings.HasPrefix(lower, "print")) {
		return true
	}
	/* OpenSSL CONF def_* / hash helpers sitting next to Dobby in .text — wipe corrupts hooks */
	if !strings.HasPrefix(name, "_Z") && (strings.HasPrefix(lower, "def_") ||
		strings.HasPrefix(lower, "value_free") || strings.HasPrefix(lower, "dump_value") ||
		lower == "get_next_file" || lower == "isdigit_l") {
		return true
	}
	for _, p := range []string{
		"SSL_", "TLS_", "DTLS", "EVP_", "ASN1", "X509", "BIO_", "PEM_", "RSA_",
		"AES_", "BN_", "ERR_", "OBJ_", "PKCS", "HMAC_", "SHA1", "SHA224", "SHA256",
		"SHA384", "SHA512", "MD5_", "DES_", "RAND_", "DH_", "EC_", "CMS_", "OCSP",
		"ENGINE_", "UI_", "SCT_", "COMP_", "CT_", "DSO_", "ASYNC", "SRP_", "BF_",
		"CAST_", "IDEA_", "RC2_", "RC4_", "SM2_", "SM4_", "SEED_", "NCONF_", "CONF_",
		"CRYPTO_", "OPENSSL", "CURL_", "SHA3_", "BLAKE2", "Camellia_", "WHIRLPOOL",
		"ED25519_", "X25519_", "SipHash_", "SSL3_", "DTLSv1_", "_CONF_",
		"CMAC_", "MD4_", "RIPEMD", "SHA3_", "SM3_",
	} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

/* File-static (_ZL/_ZZ) helpers in hook/ELF bridges: pointer/heap ABI still unsafe.
 * Lift known business statics only — avoid broad tokens (filter/extract) that match
 * /proc scrubbers and zip helpers which must stay native. */
func isBusinessStaticProtectCandidate(lower string) bool {
	/* Do NOT auto-lift aesCbc/hexEncode wrappers — they call OpenSSL EVP and feed
	 * ShuanQ URL params; VM corruption yields garbage query and biz_code=-2. */
	for _, p := range []string{
		"fake_", "grab_", "md5_update",
		"wsp_", "tamper_", "notify_java",
		"signrate", "jd_jma_fake", "filterengine", "shuanq",
		"anticheat_hooks_ready", "native_bypass_critical", "xorencrypt",
		"dada_fs", "timeguard", "heartbeat",
	} {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

/* Unmangled C symbols owned by the app (not OpenSSL/LWS/curl). */
func isAppOwnedPlainCProtectCandidate(lower string) bool {
	for _, p := range []string{
		"fake_", "grab_", "report_mitm", "jma_", "shuanq", "dada_",
		"tamper_", "activecrash", "active_crash", "apkverify", "native_core",
		"write_callback",
		"victim_", "notify_java",
		"fs_hide", "bypass_enter", "bypass_leave",
	} {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

/* Skip only what cannot safely execute under AXVM (engine/ABI/3rd-party/ctors).
 * Business logic (fake_*, shuanq, md5 helpers, detection policy) MUST be protected. */
func skipProtectByDefault(name string) bool {
	lower := strings.ToLower(name)
	/* Explicitly keep /proc filter + zip extract helpers native (hook path). */
	for _, p := range []string{
		"filter_lines", "filter_status", "filter_comm", "create_filtered_fd",
		"extract_zip_entry", "filter_config_derive", "initheartbeatcallback",
		"apkverify_logf",
	} {
		if strings.Contains(lower, p) {
			return true
		}
	}
	/* Device-bisect toxic set for lingxitai-dada / libnative_core — keep native.
	 * (login hot path, SIGSYS hosts/mtls, antiDebug, ActiveCrash logs, libunwind) */
	for _, p := range []string{
		"versioncheckerrormessage", "fetch_time_from_center",
		"clearloginstate", "setauthverified",
		"sendheartbeatonce", "applyheartbeatresult",
		"canusefeatures", "versionnetworkguardhandle",
		"needsmtls", "sq_blob5hosts", "7sq_blob5hosts",
		"isfridadetected", "isxposeddetected", "isdebuggerattached",
		"activecrash", "scheduleactivecrash", "apkverifylog",
		"libunwind", "wsp_http_get",
	} {
		if strings.Contains(lower, p) {
			return true
		}
	}
	/* Compiler-rt emulated TLS — ObfuscatedString::c_str uses thread_local via
	 * __emutls_get_address → emutls_alloc/init. Virtualizing helpers leaves the
	 * native get_address path returning garbage (fault @0x3f0). CRT must stay native. */
	if strings.Contains(lower, "emutls") {
		return true
	}
	if isThirdPartySkipSymbol(name) {
		return true
	}
	/* Plain C (no Itanium mangling): default-deny. Fat SO embeds OpenSSL/LWS/curl;
	 * virtualizing ECDH_/CTLOG_/AcceptServerConnect corrupts heap → print_object.
	 * Only lift known app plain-C exports. */
	if !strings.HasPrefix(name, "_Z") {
		if !isAppOwnedPlainCProtectCandidate(lower) {
			return true
		}
	}
	/* Default-deny file-static locals — hook bridge _ZL* was corrupting libc read
	 * stubs / ELF lookups / heap while JDGuard sanitize runs. */
	if strings.HasPrefix(name, "_ZL") || strings.HasPrefix(name, "_ZZL") ||
		(strings.HasPrefix(name, "_ZZ") && !strings.HasPrefix(name, "_ZZN")) {
		if !isBusinessStaticProtectCandidate(lower) {
			return true
		}
	}
	/* fake_fn_for_* / fake_hook_for_* return native fn pointers for RegisterNatives. */
	if strings.Contains(lower, "fake_fn_for") || strings.Contains(lower, "fake_hook_for") {
		return true
	}
	/* jobject/jstring constant fakes: stub fallthrough used to leak func_id in X0
	 * (JniDecode @0x40 / x0=0x41). Safe-zero bridge is in place; re-enable LDR+RET
	 * / null / passthrough bodies. Still skip anything that allocates via JNI under VM. */
	if strings.Contains(lower, "fake_jni_") || strings.Contains(lower, "fake_dada_") ||
		strings.Contains(lower, "fake_signrate_") {
		safe := strings.Contains(lower, "fake_jni_void") ||
			strings.Contains(lower, "fake_jni_zero") ||
			strings.Contains(lower, "fake_jni_false") ||
			strings.Contains(lower, "fake_jni_neg_one") ||
			strings.Contains(lower, "fake_jni_detect_ok") ||
			strings.Contains(lower, "fake_jni_null_obj") ||
			strings.Contains(lower, "fake_jni_empty_string") ||
			strings.Contains(lower, "fake_jni_simulator_ok") ||
			strings.Contains(lower, "fake_jni_empty_jsonobject") ||
			strings.Contains(lower, "fake_jni_empty_bytearray") ||
			strings.Contains(lower, "fake_jni_passthrough") ||
			strings.Contains(lower, "fake_dada_environment") ||
			strings.Contains(lower, "fake_dada_version") ||
			strings.Contains(lower, "fake_signrate_official_hash")
		if !safe {
			return true
		}
	}
	/* TLS guards / thread-local wrappers */
	if strings.HasPrefix(name, "_ZTWL") || strings.HasPrefix(name, "_ZTW") {
		return true
	}
	if strings.Contains(name, "_ZN2qx") || strings.Contains(name, "_ZNK2qx") {
		return true
	}
	/* Tiny crypto/URL helpers only — not whole networking stacks.
	 * aesCbc/hex/MD5 feed ShuanQ signed+encrypted query; VM → 签名校验失败/公告挂. */
	if strings.Contains(lower, "aescbcencrypt") || strings.Contains(lower, "aescbcdecrypt") ||
		strings.Contains(lower, "hexencode") || strings.Contains(lower, "hexdecode") ||
		strings.Contains(lower, "normalizekeybytes") ||
		strings.Contains(lower, "md5encode") || strings.Contains(lower, "md5decode") ||
		strings.Contains(lower, "md5init") || strings.Contains(lower, "md5update") ||
		strings.Contains(lower, "md5final") || strings.Contains(lower, "md5transform") {
		return true
	}
	/* Narrow: only the two variable/notice fetch wrappers — OBF+ApiClient under VM
	 * still yields HTTP 500 on get_variable_info while get_version_info (JNI) is OK. */
	if strings.Contains(name, "updateCloudVersionFromApi") ||
		strings.Contains(name, "fetchAndCacheVariable") ||
		strings.Contains(name, "writeVariableToCache") ||
		strings.Contains(name, "readVariableFromCache") ||
		strings.Contains(name, "sanitizeVarNameForFile") ||
		strings.Contains(lower, "jstring2string") {
		return true
	}
	/* Network clients: map/string/lws heavy under VM (keep class-level until
	 * per-method lift of sendRequest is proven; prefer shrinking later). */
	if strings.Contains(name, "ShuanQApiClient") || strings.Contains(name, "ShuanQWsProxy") ||
		strings.Contains(name, "15ShuanQApiClient") || strings.Contains(name, "12ShuanQWsProxy") ||
		strings.Contains(name, "WsProxyClient") || strings.Contains(name, "13WsProxyClient") ||
		strings.Contains(name, "HTTPSession") || strings.Contains(name, "HttpClient") {
		return true
	}
	/* cxxabi anonymous-ns internals (not app _GLOBAL__N_1 business helpers). */
	if strings.Contains(name, "__cxxabiv") && strings.Contains(name, "_GLOBAL__N_") {
		return true
	}
	/* ELF / dl / libc symbol resolvers return pointers in X0 — AXVM still corrupts
	 * pointer returns (hooks logged @0x6a → KnightConfig NPE). Keep native. */
	if strings.Contains(lower, "elf_lookup") || strings.Contains(lower, "find_lib") ||
		strings.Contains(lower, "ac_resolve") || strings.Contains(lower, "resolve_libc") ||
		strings.Contains(lower, "get_proc_ft") || strings.Contains(lower, "safe_read_mem") ||
		strings.Contains(lower, "lookup_dl") || strings.Contains(lower, "dyn_sym") ||
		strings.Contains(lower, "elf_base") || strings.Contains(lower, "elf_foreach") ||
		strings.Contains(lower, "load_bias") || strings.Contains(lower, "make_addr_hookable") ||
		strings.Contains(lower, "get_module_base") || strings.Contains(lower, "module_base") ||
		strings.Contains(lower, "read_fd_full") || strings.Contains(lower, "line_contains_lib") ||
		strings.Contains(lower, "maps_addr") || strings.Contains(lower, "export_addr") ||
		strings.Contains(lower, "raw_open") || strings.Contains(lower, "raw_close") ||
		strings.Contains(lower, "raw_read") || strings.Contains(lower, "raw_faccess") ||
		strings.Contains(lower, "npatch") || strings.Contains(lower, "read_needs_in_place") ||
		(strings.Contains(lower, "repair") && strings.Contains(lower, "read")) ||
		strings.Contains(lower, "getenv_spoof") || strings.Contains(lower, "file_exists_readable") ||
		strings.Contains(lower, "read_first_line") || strings.Contains(lower, "is_self_apk") ||
		strings.Contains(lower, "arm64_movz") || strings.Contains(lower, "patch_exec_memory") ||
		strings.Contains(lower, "patch_libc") || strings.Contains(lower, "syscall_stub") ||
		strings.Contains(lower, "is_our_read") || strings.Contains(lower, "is_libc_symbol") ||
		strings.Contains(lower, "parse_self_apk_from_maps") {
		return true
	}
	/* Owning char*-returning helpers — AXVM still corrupts pointer returns.
	 * Match mangled C++ (..._dupE... / dup_tagged) and C (..._dup). */
	if strings.Contains(lower, "_dup") && (strings.Contains(lower, "mitm_") ||
		strings.Contains(lower, "jma_") || strings.Contains(lower, "report_") ||
		strings.Contains(lower, "sanitize") || strings.Contains(lower, "scrub") ||
		strings.Contains(lower, "classify") || strings.Contains(name, "_ZN2qx") ||
		strings.Contains(name, "_ZNK2qx") || strings.Contains(lower, "grab_")) {
		return true
	}
	if strings.HasSuffix(name, "_dup") || strings.Contains(lower, "dup_tagged") ||
		strings.Contains(lower, "dup_bool") || strings.Contains(lower, "dup_fmt") ||
		(strings.Contains(name, "_GLOBAL__N_") && strings.Contains(lower, "dup_")) {
		return true
	}
	/* const char* factories — SetValuestring(mitm_*_safe(...)) crashes if X0 garbage. */
	if strings.Contains(lower, "mitm_") && (strings.Contains(lower, "_safe") ||
		strings.Contains(lower, "fallback_scrub") || strings.Contains(lower, "sanitize_socket") ||
		strings.Contains(lower, "sanitize_fuvj") || strings.Contains(lower, "classpath_value")) {
		return true
	}
	/* mitm / JDGuard sanitize predicates + tree walkers: VM side-effects still corrupt
	 * cJSON trees (print_object fault @0x11c/@0x140). Keep native until heap ABI solid;
	 * fake_*, shuanq, filter stay protected. */
	if strings.Contains(lower, "mitm_") && (strings.Contains(lower, "looks_detection") ||
		strings.Contains(lower, "script_hit") || strings.Contains(lower, "exempt_key") ||
		strings.Contains(lower, "contains_any") || strings.Contains(lower, "pkg_blocked") ||
		strings.Contains(lower, "qagq_hit") || strings.Contains(lower, "device_other") ||
		strings.Contains(lower, "str_contains") || strings.Contains(lower, "heuristic") ||
		strings.Contains(lower, "sanitize") || strings.Contains(lower, "neutralize") ||
		strings.Contains(lower, "to_lower") || strings.Contains(lower, "setvaluestring") ||
		strings.Contains(lower, "scrub")) {
		return true
	}
	if strings.Contains(lower, "jdg_sanitize") || strings.Contains(lower, "report_mitm") ||
		strings.Contains(lower, "sanitize_classpath") || strings.Contains(lower, "classpath_value") {
		return true
	}
	/* const char* factories used by jma classify — pointer returns. */
	if strings.Contains(lower, "expected_undetected") || strings.Contains(lower, "fallback_malloc") ||
		strings.Contains(lower, "fallback_free") || strings.Contains(lower, "install_seccomp") ||
		strings.Contains(lower, "split_kv") {
		return true
	}
	/* C++ global new/delete — static ctors call these before AXVM pack is registered. */
	if strings.HasPrefix(name, "_Znwm") || strings.HasPrefix(name, "_Znam") ||
		strings.HasPrefix(name, "_Zdl") || strings.HasPrefix(name, "_Zda") {
		return true
	}
	if strings.HasPrefix(name, "Java_") || strings.HasPrefix(name, "JNI_") {
		return true
	}
	/* C++ JavaVM/JNIEnv method wrappers only (not every fn taking JNIEnv*) */
	if strings.HasPrefix(name, "_ZN7_JNIEnv") || strings.HasPrefix(name, "_ZN7_JavaVM") {
		return true
	}
	if strings.HasPrefix(name, "axvm_") {
		return true
	}
	if strings.HasPrefix(name, "_ZTV") || strings.HasPrefix(name, "_ZTI") ||
		strings.HasPrefix(name, "_ZTS") || strings.HasPrefix(name, "_ZTC") ||
		strings.HasPrefix(name, "_ZGV") {
		return true
	}
	/* libc++ / Itanium ABI — virtualizing STL breaks containers & exception paths.
	 * Only skip symbols whose *primary* namespace is std/__gnu_cxx — NOT app methods
	 * that merely take std::string params (those mangle as ...RKNSt6__ndk1...).
	 * A bare strings.Contains("__ndk1") previously skipped almost all C++ business APIs. */
	if strings.HasPrefix(name, "_ZNSt") || strings.HasPrefix(name, "_ZNKSt") ||
		strings.HasPrefix(name, "_ZSt") || strings.HasPrefix(name, "_ZN9__gnu_cxx") ||
		strings.HasPrefix(name, "__cxa_") || strings.HasPrefix(name, "_ZNK9__gnu_cxx") ||
		strings.Contains(name, "__cxx_global") ||
		strings.Contains(name, "_GLOBAL__sub_I_") || strings.Contains(name, "_GLOBAL__sub_D_") ||
		(strings.HasPrefix(name, "_GLOBAL__") && !strings.Contains(name, "_GLOBAL__N_")) {
		return true
	}
	/* C++ ABI runtime must stay native (even when nested under _GLOBAL__N_1). */
	if strings.Contains(name, "__cxxabiv") || strings.Contains(name, "itanium_demangle") {
		return true
	}
	/* CRT / loader / atexit — must stay native or process teardown / dlclose breaks. */
	for _, p := range []string{
		"atexit", "__on_dlclose", "__dl_", "__loader_", "call_constructors",
		"call_destructors", "__fini", "__init_array", "pthread_atfork",
	} {
		if strings.Contains(lower, p) {
			return true
		}
	}
	/* Inline-hook engines + RegisterNatives tables — patch foreign .text / ART. */
	for _, p := range []string{
		"dobby", "a64hook", "and64", "inlinehook", "lsplant", "sandhook",
		"shadowhook", "sh_add_to_list", "sh_remove_from", "sh_testbit",
		"dobbycodepatch", "dobbyhook", "dobbydestroy",
		"code_patch", "patch_exec_memory",
		"register_jclass_natives", "register_natives", "nativemethodspec",
		"make_", /* make_*_methods builds JNI fn-ptr tables — VM corrupts pointers */
		"native_core_after_vm_ready", "native_core_jni_onload",
		"nativebindmodule", "ensuremodulejni",
		/* And64InlineHook / A64Hook internals (mangled as context:: / __fix_*) */
		"__fix_", "process_fix", "a64hookfunction", "fix_instructions",
		"fix_loadlit", "fix_pcrel", "fix_branch", "fix_cond_comp",
		"dada_sig_bypass", "install_openat", "hooked_openat",
		"fastallocatetrampoline", "allocate_trampoline", "a64hookinit",
		"is_in_fixing_range", "insert_fix_map", "reset_current_ins",
		"get_and_set_current_index",
		/* Compile-time string obfuscation must stay native (used in static ctors). */
		"obfuscatedstring", "obfuscatedbytes", "obf_key", "obf_bytes",
		/* Hook installers / libc I/O trampolines — virtualizing them corrupts
		 * concurrent JDGuard sanitize (print_object @0x128). fake_* stay protected. */
		"hook_", "install_", "do_install", "deferred_", "ensure_sig", "ensure_code",
		"ensure_exec", "ensure_all", "raw_open", "raw_access", "raw_getenv",
		"raw_fstat", "raw_readlink", "call_orig_", "patch_libc", "npatch",
		"vmp_stub", "vmp_clinit", "register_natives", "nativespec",
	} {
		if strings.Contains(lower, p) {
			/* make_ alone is broad — only JNI method-table builders */
			if p == "make_" && !strings.Contains(lower, "method") {
				continue
			}
			/* hook_ matches fake_hook_for_java — keep those protectable */
			if p == "hook_" && strings.Contains(lower, "fake_") {
				continue
			}
			return true
		}
	}
	/* And64InlineHook C++ namespace context:: */
	if strings.Contains(name, "_ZN7context") || strings.Contains(name, "_ZNK7context") {
		return true
	}
	/* mangled obf:: namespace (ObfuscatedString / obf_key / helpers) */
	if strings.Contains(name, "_ZN3obf") || strings.Contains(name, "_ZNK3obf") ||
		strings.Contains(name, "_ZN4obf") || strings.Contains(name, "_ZNK4obf") {
		return true
	}
	/* strings:: getters wrap ObfuscatedString — called from static ctors before AXVM ready. */
	if strings.Contains(name, "_ZN7strings") || strings.Contains(name, "_ZNK7strings") {
		return true
	}
	/* memProtect SecureData ctors often run as globals during .init_array. */
	if strings.Contains(name, "_ZN10memProtect") {
		return true
	}
	/* C++ terminate / EH personality must stay native. */
	if strings.Contains(lower, "clang_call_terminate") || strings.Contains(lower, "gxx_personality") ||
		strings.Contains(lower, "__gnu_unwind") {
		return true
	}
	/* Anonymous-namespace helpers: often run from .init_array / OBF paths; VM
	 * before pack-ready corrupts heap. Allow known business anon-ns only. */
	if strings.Contains(name, "_GLOBAL__N_") {
		biz := strings.Contains(lower, "shuanq") || strings.Contains(lower, "fake_") ||
			strings.Contains(lower, "filter") || strings.Contains(lower, "crypto") ||
			strings.Contains(lower, "logger") || strings.Contains(lower, "grab_") ||
			strings.Contains(lower, "apkverify") || strings.Contains(lower, "dada_") ||
			strings.Contains(lower, "heartbeat") || strings.Contains(lower, "timeguard") ||
			strings.Contains(lower, "xorencrypt") || strings.Contains(lower, "signrate")
		if !biz {
			return true
		}
	}
	/* C++ ctors/dtors — objects with std::string/map must be constructed natively
	 * or members are garbage (ShuanQApiClientC2 → map crash in addRequestParam). */
	if strings.Contains(name, "C1E") || strings.Contains(name, "C2E") ||
		strings.Contains(name, "C3E") || strings.Contains(name, "D0E") ||
		strings.Contains(name, "D1E") || strings.Contains(name, "D2E") {
		return true
	}
	/* TLS init must stay native (pairs with emutls). */
	if strings.Contains(lower, "__tls_init") || name == "__tls_init" {
		return true
	}
	/* Syscall/seccomp/openat + Dobby *installers* only — replacement/fake logic is protected. */
	for _, p := range []string{
		"hooked_", "call_openat", "raw_openat", "sigsys", "trusted_thread",
		"syscall_name", "needs_mode", "openat_impl", "install_openat",
		"ensure_all_detection", "hook_anticheat", "install_export", "got_patch",
		"schedule_deferred", "install_anticheat",
	} {
		if strings.Contains(lower, p) {
			return true
		}
	}
	if strings.Contains(lower, "hook_") && (strings.Contains(lower, "install") ||
		strings.Contains(lower, "anticheat") || strings.Contains(lower, "detection") ||
		strings.Contains(lower, "export") || strings.Contains(lower, "dobby")) {
		return true
	}
	if strings.HasPrefix(name, "sh_") || strings.HasPrefix(name, "bh_") ||
		strings.HasPrefix(name, "bytehook") {
		return true
	}
	/* Third-party crypto/net/compress commonly linked into fat SOs */
	for _, p := range []string{
		"curl_", "curl_easy", "curl_multi", "lws_", "ssl_", "tls1_", "aes_", "evp_",
		"rsa_", "dsa_", "ecdsa_", "crypto_", "openssl", "bn_", "bio_", "x509",
		"asn1_", "hmac_", "sha1_", "sha256_", "sha512_", "md5_", "chacha",
		"poly1305", "pkcs", "pem_", "ossl_", "zlib", "inflate", "deflate",
		"adler32", "hpatch", "hdiff", "cjson", "miniz", "brotli", "nghttp",
		"pkey_", "hkdf_", "scrypt_", "ocb_", "cipher_fn", "do_all_",
		"obj_name", "names_lh", "trans_cb", "cleanup_cb", "int_update",
		"dummy_dup", "pmeth_",
		/* OpenSSL / BoringSSL leaf symbols often lack the prefixes above */
		"bf_cbc", "bf_ecb", "bf_set", "cast_cbc", "cast_encrypt", "cast_decrypt",
		"cast_set_key", "des_cbc", "des_ncbc", "des_ede", "des_cfb", "des_ofb",
		"des_set_key", "des_xcbc", "camellia_", "idea_cbc", "idea_set",
		"rc2_cbc", "rc2_set", "rc4_set", "sm4_", "whirlpool_", "blake2",
		"ed25519_", "x25519_", "ocsp_", "cms_", "engine_", "smime_",
		"ecpkparameters", "name_constraints", "mod_exp_ctime", "ui_add_input",
		"ui_dup_input", "ui_set_result", "sct_print", "sha3_absorb",
		"tinystl", "assemblerpseudolabel", "interceptrouting", "clearcache",
		"extracttomemory", "openarchive", "processzipentry", "unwind_iterate",
	} {
		if strings.Contains(lower, p) {
			return true
		}
	}
	/* Bare OpenSSL-style prefixes (BF_cbc_encrypt, CAST_set_key, …) */
	for _, p := range []string{
		"BF_", "CAST_", "DES_", "IDEA_", "RC2_", "RC4_", "SM4_", "CMS_",
		"OCSP_", "ENGINE_", "BLAKE2", "Camellia_", "WHIRLPOOL_", "ED25519_",
		"X25519_", "SHA3_", "SCT_", "SMIME_", "UI_", "ECPK", "SSL_", "TLS_",
		"EVP_", "RSA_", "AES_", "BIO_", "PEM_", "X509", "ASN1_", "HMAC_",
		"SHA1_", "SHA256_", "SHA512_", "MD5_", "EC_", "DH_", "DSA_", "BN_",
		"BUF_", "CONF_", "NCONF_", "COMP_", "CT_", "SCT_", "RAND_", "ERR_",
		"OBJ_", "TXT_", "UI_", "CMS_", "PKCS", "PEM_", "DTLS_", "WPACKET_",
		"SRP_", "ASYNC_", "DSO_", "POLY1305_", "SIPHASH_", "SM2_", "KX_",
	} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	/* OpenSSL heap helpers often named foo_free / bar_new without library prefix */
	if len(name) > 2 && (strings.HasSuffix(name, "_free") || strings.HasSuffix(name, "_new") ||
		strings.HasSuffix(name, "_free_func")) {
		/* Keep app mitm/report/grab/fake protectable */
		if !strings.Contains(lower, "mitm_") && !strings.Contains(lower, "report_") &&
			!strings.Contains(lower, "grab_") && !strings.Contains(lower, "shuanq") &&
			!strings.Contains(lower, "fake_") && !strings.Contains(lower, "hook_") &&
			!strings.Contains(lower, "bypass") && !strings.Contains(lower, "native_") &&
			!strings.HasPrefix(name, "_Z") && !strings.HasPrefix(name, "_ZL") {
			return true
		}
	}
	return false
}

func scanFuncSize(raw []byte, off int64, max int) int {
	limit := max
	if limit > 65536 {
		limit = 65536
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
