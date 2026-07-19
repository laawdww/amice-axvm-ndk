package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

func buildPackAndStubs(funcs []fnInfo, encrypt, wiped bool, master []byte, permOpcodes bool, packMagic uint32) ([]byte, []byte, bool) {
	flags := uint32(0)
	if encrypt {
		flags |= axpkEncrypt
	}
	if wiped {
		flags |= axpkWiped
	}

	seed := make([]byte, 16)
	_, _ = rand.Read(seed)
	padSeedBase := binary.LittleEndian.Uint64(seed[0:8]) ^ binary.LittleEndian.Uint64(seed[8:16])

	/*
	 * 模块 M：opcode 置换。仅当携带真实 MasterSeed 且所有函数字节码均为
	 * 整齐指令流（fail-safe 校验通过）时才置换，否则整体放弃（保持恒等）。
	 */
	doPerm := permOpcodes && len(master) >= 32
	var fwd [256]byte
	if doPerm {
		fwd, _ = opcodePermBuild(master)
		for i := range funcs {
			if !opcodeStreamValid(funcs[i].BC) {
				doPerm = false
				break
			}
		}
	}

	const recSize = axvmRecSizeV2
	var recs bytes.Buffer
	var bcBlob bytes.Buffer

	var stubBuf bytes.Buffer
	stubBase := uint32(0)
	bcCursor := uint32(0)

	for i := range funcs {
		f := &funcs[i]
		funcID := uint32(i + 1)
		rawBC := append([]byte(nil), f.BC...)
		bcFlags := uint32(0)
		if len(master) >= 32 {
			plain := append([]byte(nil), rawBC...)
			rawBC = injectJunkMicro(rawBC, master)
			var amap []addrMapEntry
			if len(f.AddrMap) > 0 {
				amap = append([]addrMapEntry(nil), f.AddrMap...)
			}
			rawBC, amap = realignBytecodeAfterJunk(plain, rawBC, amap)
			f.AddrMap = amap
		}
		if doPerm && opcodeStreamValid(rawBC) {
			permuteOpcodes(rawBC, fwd)
			bcFlags |= axvmBCFlagOpcodePerm
		}
		if bytecodeNeedsReloc(rawBC) {
			bcFlags |= axvmBCFlagReloc
		}
		if len(f.AddrMap) > 0 {
			rawBC = appendAddrMapTrailer(rawBC, f.Addr, f.Size, f.AddrMap)
			bcFlags |= axvmBCFlagAddrMap
		}
		bc := wrapBytecode(rawBC, f.EntryPC, bcFlags)
		if encrypt {
			cryptVariant(bc[40:], seed, master, uint32(i+1), f.EntryPC)
		}

		f.StubOff = stubBase
		var stub []byte
		var lay stubLayout
		if f.UsesFP {
			padSeed := padSeedBase ^ uint64(funcID)*0xBF58476D1CE4E5B9 ^ uint64(f.EntryPC)
			stub, lay = genStubForFunc(funcID, padSeed, true)
		} else {
			padSeed := padSeedBase ^ uint64(funcID)*0x9E3779B97F4A7C15 ^ uint64(f.EntryPC)
			stub, lay = genStubForFunc(funcID, padSeed, false)
		}
		f.StubSize = lay.size
		f.StubDisp = lay.dispatchOff
		f.StubVar = lay.variant
		stubBuf.Write(stub)
		stubBase += uint32(lay.size)

		rec := make([]byte, recSize)
		binary.LittleEndian.PutUint32(rec[0:], uint32(i+1))
		binary.LittleEndian.PutUint32(rec[4:], fnv1a32([]byte(f.Name)))
		binary.LittleEndian.PutUint32(rec[8:], f.EntryPC)
		binary.LittleEndian.PutUint32(rec[12:], uint32(len(bc)))
		binary.LittleEndian.PutUint64(rec[16:], f.Addr)
		binary.LittleEndian.PutUint32(rec[24:], f.StubOff)
		binary.LittleEndian.PutUint32(rec[28:], bcCursor)
		n := copy(rec[32:], f.Name)
		if n > 36 {
			n = 36
		}
		_ = n
		binary.LittleEndian.PutUint32(rec[68:], uint32(f.Size))
		binary.LittleEndian.PutUint32(rec[72:], encodeStubMeta(f.StubSize, f.StubDisp, f.StubVar))
		recs.Write(rec)
		bcBlob.Write(bc)
		bcCursor += uint32(len(bc))
	}

	hdr := make([]byte, 64)
	binary.LittleEndian.PutUint32(hdr[0:], packMagic)
	binary.LittleEndian.PutUint32(hdr[4:], axpkVersionV2)
	binary.LittleEndian.PutUint32(hdr[8:], flags)
	binary.LittleEndian.PutUint32(hdr[12:], uint32(len(funcs)))
	binary.LittleEndian.PutUint32(hdr[16:], 64)
	blobOff := uint32(64 + recs.Len())
	binary.LittleEndian.PutUint32(hdr[20:], blobOff)
	binary.LittleEndian.PutUint32(hdr[24:], uint32(bcBlob.Len()))
	copy(hdr[28:44], seed)

	var pack bytes.Buffer
	pack.Write(hdr)
	pack.Write(recs.Bytes())
	pack.Write(bcBlob.Bytes())
	out := pack.Bytes()
	sealPackManifestMAC(out)
	return out, stubBuf.Bytes(), doPerm
}

/* Replace plaintext mangled names with opaque axfNN (pack_name_sane); reseal MAC. */
func scrubPackFuncNames(pack []byte) {
	if len(pack) < 64 {
		return
	}
	ver := binary.LittleEndian.Uint32(pack[4:8])
	funcCount := binary.LittleEndian.Uint32(pack[12:16])
	tableOff := binary.LittleEndian.Uint32(pack[16:20])
	if tableOff != 64 || funcCount == 0 || funcCount > 128 {
		return
	}
	recSize := uint32(axvmRecSizeV1)
	if ver >= axpkVersionV2 {
		recSize = axvmRecSizeV2
	}
	for i := uint32(0); i < funcCount; i++ {
		rec := tableOff + i*recSize
		if int(rec+recSize) > len(pack) {
			break
		}
		nameOff := rec + 32
		opaque := []byte(fmt.Sprintf("axf%02d", i+1))
		for k := uint32(0); k < 36; k++ {
			pack[nameOff+k] = 0
		}
		copy(pack[nameOff:], opaque)
		binary.LittleEndian.PutUint32(pack[rec+4:], fnv1a32(opaque))
	}
	sealPackManifestMAC(pack)
}

func wrapBytecode(code []byte, entry uint32, bcFlags uint32) []byte {
	pureSize := uint32(len(code))
	if (bcFlags&axvmBCFlagAddrMap) != 0 && len(code) >= 21 {
		/* trailer 在 code 末尾；可执行区不含 trailer */
		tail := code[len(code)-21:]
		mapCount := binary.LittleEndian.Uint32(tail[5:9])
		trailerLen := mapCount*8 + 21
		if int(trailerLen) <= len(code) {
			pureSize = uint32(len(code)) - trailerLen
		}
	}
	codeSize := pureSize
	hdr := make([]byte, 40)
	copy(hdr[0:], axvmMagic)
	binary.LittleEndian.PutUint32(hdr[4:], axvmVersion)
	binary.LittleEndian.PutUint32(hdr[8:], bcFlags)
	binary.LittleEndian.PutUint32(hdr[12:], 40)
	binary.LittleEndian.PutUint32(hdr[16:], codeSize)
	dataOff := 40 + uint32(len(code))
	binary.LittleEndian.PutUint32(hdr[20:], dataOff)
	binary.LittleEndian.PutUint32(hdr[28:], entry)

	out := append(hdr, code...)
	cs := fnv1a32(out[:32])
	cs ^= fnv1a32(out[36:])
	binary.LittleEndian.PutUint32(out[32:], cs)
	return out
}

func crypt(buf []byte, seed []byte, entryPC, funcID uint32) {
	if len(buf) == 0 {
		return
	}
	roll := byte(funcID ^ uint32(seed[0]) ^ 0xA5)
	for i := range buf {
		k := byte(seed[i&15] ^ roll ^ byte(i*13+int(funcID)))
		buf[i] ^= k
		roll = byte((roll + k) ^ 0x5A)
	}
}

func bytecodeNeedsReloc(code []byte) bool {
	for i := 0; i < len(code); {
		step, ok := insnStepLen(code, i)
		if !ok {
			return false
		}
		op := code[i]
		if op == opLdri64Vaddr || op == opCallNatVaddr {
			return true
		}
		i += step
	}
	return false
}

func patchPackVaddrRelocs(pack []byte, threshold, delta uint64, master []byte) error {
	if delta == 0 {
		return nil
	}
	if len(pack) < 64 {
		return fmt.Errorf("pack too small")
	}
	flags := binary.LittleEndian.Uint32(pack[8:12])
	funcCount := binary.LittleEndian.Uint32(pack[12:16])
	tableOff := binary.LittleEndian.Uint32(pack[16:20])
	blobOff := binary.LittleEndian.Uint32(pack[20:24])
	blobSize := binary.LittleEndian.Uint32(pack[24:28])
	if int(blobOff+blobSize) > len(pack) {
		return fmt.Errorf("pack blob oob")
	}
	seed := pack[28:44]
	recSize := uint32(axvmRecSizeV1)
	if binary.LittleEndian.Uint32(pack[4:8]) >= axpkVersionV2 {
		recSize = axvmRecSizeV2
	}
	for i := uint32(0); i < funcCount; i++ {
		rec := int(tableOff + i*recSize)
		if rec+32 > len(pack) {
			return fmt.Errorf("pack rec oob")
		}
		funcID := binary.LittleEndian.Uint32(pack[rec : rec+4])
		bcSize := binary.LittleEndian.Uint32(pack[rec+12 : rec+16])
		bcRel := binary.LittleEndian.Uint32(pack[rec+28 : rec+32])
		start := int(blobOff + bcRel)
		end := start + int(bcSize)
		if start < 0 || end > len(pack) || start > end {
			return fmt.Errorf("bytecode oob")
		}
		bc := pack[start:end]
		if len(bc) < 40 || string(bc[:4]) != axvmMagic {
			return fmt.Errorf("bad bytecode header")
		}
		entryPC := binary.LittleEndian.Uint32(bc[28:32])
		encrypted := (flags & axpkEncrypt) != 0
		if encrypted {
			cryptVariant(bc[40:], seed, master, funcID, entryPC)
		}
		if n := patchBytecodeVaddrRelocs(bc, threshold, delta, master); n > 0 {
			refreshBytecodeChecksum(bc)
		}
		if encrypted {
			cryptVariant(bc[40:], seed, master, funcID, entryPC)
		}
	}
	return nil
}

func patchBytecodeVaddrRelocs(bc []byte, threshold, delta uint64, master []byte) int {
	if len(bc) < 40 {
		return 0
	}
	flags := binary.LittleEndian.Uint32(bc[8:12])
	codeOff := binary.LittleEndian.Uint32(bc[12:16])
	codeSize := binary.LittleEndian.Uint32(bc[16:20])
	if int(codeOff+codeSize) > len(bc) {
		return 0
	}
	var inv [256]byte
	if (flags & axvmBCFlagOpcodePerm) != 0 {
		if len(master) < 32 {
			return 0
		}
		_, inv = opcodePermBuild(master)
	}
	code := bc[codeOff : codeOff+codeSize]
	changed := 0
	patchImm := func(immAt int) {
		if immAt < 0 || immAt+8 > len(code) {
			return
		}
		v := binary.LittleEndian.Uint64(code[immAt : immAt+8])
		if v >= threshold {
			binary.LittleEndian.PutUint64(code[immAt:immAt+8], v+delta)
			changed++
		}
	}
	patchRemainingConservative := func(start int) {
		for j := start; j < len(code); j++ {
			switch code[j] {
			case opLdri64Vaddr:
				if j+10 <= len(code) && code[j+1] <= regXZR {
					patchImm(j + 2)
				}
			case opCallNatVaddr:
				if j+9 <= len(code) {
					patchImm(j + 1)
				}
			}
		}
	}
	for i := 0; i < len(code); {
		wireOp := code[i]
		op := wireOp
		if (flags & axvmBCFlagOpcodePerm) != 0 {
			op = inv[wireOp]
		}
		if op == opJunk {
			if i+2 > len(code) || i+2+int(code[i+1]) > len(code) {
				return changed
			}
			i += 2 + int(code[i+1])
			continue
		}
		olen, ok := opOperandLen(op)
		if !ok || i+1+olen > len(code) {
			patchRemainingConservative(i + 1)
			return changed
		}
		switch op {
		case opLdri64Vaddr:
			patchImm(i + 2)
		case opCallNatVaddr:
			patchImm(i + 1)
		}
		i += 1 + olen
	}
	return changed
}

func refreshBytecodeChecksum(bc []byte) {
	if len(bc) < 40 {
		return
	}
	cs := fnv1a32(bc[:32])
	cs ^= fnv1a32(bc[36:])
	binary.LittleEndian.PutUint32(bc[32:36], cs)
}
