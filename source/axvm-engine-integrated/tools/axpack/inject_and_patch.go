package main

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
)

func injectAndPatch(raw []byte, ef *elf.File, pack, stubs []byte, funcs, nativeLeft []fnInfo, wipe, nativeWipe bool, depLib string, noPhdr, noPatch, noNorm, integrity, dynseed, tokenEntry bool, rawSeed, effectiveMaster []byte, apkBind bool, decoys int, packMagic uint32) ([]byte, error) {
	rx, err := rxLoadSeg(ef)
	if err != nil {
		return nil, err
	}
	rw, err := rwLoadSeg(ef)
	if err != nil {
		return nil, err
	}
	rwVaddr := rw.Vaddr

	out := make([]byte, len(raw), len(raw)+len(pack)+len(stubs)+64)
	copy(out, raw)

	appendOff := alignFile(int64(len(out)), int64(axvmLoadAlign))
	if appendOff > int64(len(out)) {
		out = append(out, make([]byte, appendOff-int64(len(out)))...)
	}
	packVaddr := vaddrForFileOffset(rx.Vaddr+rx.Memsz, appendOff, axvmLoadAlign)
	packStart := int64(len(out))
	out = append(out, pack...)
	for int64(len(out))%16 != 0 {
		out = append(out, 0)
	}
	stubRelBase := int64(len(out))
	out = append(out, stubs...)
	for int64(len(out))%16 != 0 {
		out = append(out, 0)
	}
	segLen := int64(len(out)) - appendOff
	if segLen <= 0 {
		return nil, fmt.Errorf("empty axvm segment")
	}
	ensureRoom := func(segLen int64) error {
		oldRwVaddr := rwVaddr
		var bumpErr error
		rwVaddr, bumpErr = ensureAxvmVirtualRoom(out, packVaddr, packVaddr+uint64(segLen), rwVaddr)
		if bumpErr != nil || rwVaddr == oldRwVaddr {
			return bumpErr
		}
		packEnd := packStart + int64(len(pack))
		if packStart >= 0 && packEnd <= int64(len(out)) {
			return patchPackVaddrRelocs(out[packStart:packEnd], oldRwVaddr, rwVaddr-oldRwVaddr, effectiveMaster)
		}
		return nil
	}
	if err := ensureRoom(segLen); err != nil {
		return nil, err
	}

	if packStart+56 <= int64(len(out)) {
		binary.LittleEndian.PutUint64(out[packStart+48:packStart+56], uint64(appendOff))
	}

	stubVA := packVaddr + uint64(stubRelBase-appendOff)

	for i := range funcs {
		funcs[i].StubOff = uint32(stubRelBase) + funcs[i].StubOff
	}

	text := ef.Section(".text")
	if text == nil {
		return nil, fmt.Errorf(".text missing")
	}

	for i := range funcs {
		f := &funcs[i]
		stubVAEntry := packVaddr + uint64(f.StubOff) - uint64(appendOff)
		recOff := packStart + 64 + int64(i)*axvmRecSizeV2 + 24
		if recOff+4 <= int64(len(out)) {
			binary.LittleEndian.PutUint32(out[recOff:recOff+4], uint32(stubVAEntry))
		}
		if noPatch {
			if wipe {
				tailStart := f.FileOff
				tailEnd := f.FileOff + int64(f.Size)
				if tailStart < tailEnd {
					if len(effectiveMaster) >= 32 {
						tail := out[tailStart:tailEnd]
						stextCryptRange(tail, effectiveMaster, uint32(i+1))
					} else {
						for off := tailStart; off < tailEnd; off += 4 {
							binary.LittleEndian.PutUint32(out[off:], arm64NOP)
						}
					}
				}
			}
			continue
		}
		var patch []byte
		if tokenEntry {
			for off := 0; off < 12; off += 4 {
				binary.LittleEndian.PutUint32(out[f.FileOff+int64(off):], arm64NOP)
			}
			patch = out[f.FileOff : f.FileOff+12]
		} else {
			targetVA := stubVA + uint64(f.StubOff-uint32(stubRelBase))
			patch = encodeJump4(f.Addr, targetVA)
			if patch == nil {
				patch = encodeJump16(f.Addr, targetVA)
			}
		}
		if patch == nil || int64(len(patch)) > int64(f.Size) {
			return nil, fmt.Errorf("%s patch failed addr=0x%X size=%d patch=%d",
				f.Name, f.Addr, f.Size, len(patch))
		}
		copy(out[f.FileOff:], patch)
		if wipe {
			tailStart := f.FileOff + int64(len(patch))
			tailEnd := f.FileOff + int64(f.Size)
			if tailStart < tailEnd {
				if len(effectiveMaster) >= 32 {
					tail := out[tailStart:tailEnd]
					stextCryptRange(tail, effectiveMaster, uint32(i+1))
				} else {
					for off := tailStart; off < tailEnd; off += 4 {
						binary.LittleEndian.PutUint32(out[off:], arm64NOP)
					}
				}
			}
		}
	}

	var axnwRecs []nativeWipeRec
	if nativeWipe && wipe && len(effectiveMaster) >= 32 {
		axnwRecs = wipeNativeSymbols(out, nativeLeft, effectiveMaster)
	}

	/* 模块 P：运行时 loader 侧 strip；pack 阶段不改 dynstr，避免 dlsym 失效 */

	/* 模块 I：在 .text 打补丁 + pack/stub 写入完成后，构造分段 SHA256 完整性节 */
	if integrity {
		keySeed := make([]byte, 16)
		copy(keySeed, pack[28:44])

		blobOff := int64(binary.LittleEndian.Uint32(pack[20:24]))
		blobSize := int64(binary.LittleEndian.Uint32(pack[24:28]))

		bcStart := packStart + blobOff
		stubOff := stubRelBase - packStart

		segs := []integSeg{
			{
				id:   axIntSegBC,
				off:  uint64(blobOff),
				size: uint64(blobSize),
				data: out[bcStart : bcStart+blobSize],
			},
			{
				id:   axIntSegStub,
				off:  uint64(stubOff),
				size: uint64(len(stubs)),
				data: out[stubRelBase : stubRelBase+int64(len(stubs))],
			},
			{
				id:   axIntSegText,
				off:  text.Addr,
				size: text.Size,
				data: out[int64(text.Offset) : int64(text.Offset)+int64(text.Size)],
			},
		}

		sect := buildIntegritySection(segs, keySeed)
		out = append(out, sect...)
		for int64(len(out))%16 != 0 {
			out = append(out, 0)
		}

		newSegLen := int64(len(out)) - appendOff
		if err := ensureRoom(newSegLen); err != nil {
			return nil, err
		}
	}

	if len(axnwRecs) > 0 {
		out = append(out, buildAXNWBlock(axnwRecs)...)
		for int64(len(out))%16 != 0 {
			out = append(out, 0)
		}
		axnwSegLen := int64(len(out)) - appendOff
		if err := ensureRoom(axnwSegLen); err != nil {
			return nil, err
		}
	}

	if decoys > 0 {
		tailReserve := int64(0)
		if dynseed {
			tailReserve = 64 + 16
		}
		budget := int64(rwVaddr) - int64(packVaddr) - (int64(len(out)) - appendOff) - tailReserve
		blob, got := buildDecoyPacksWithin(decoys, rawSeed, packMagic, budget)
		if got < decoys {
			fmt.Fprintf(os.Stderr, "axpack: decoys clamped %d -> %d (RX/RW gap 0x%X bytes)\n",
				decoys, got, budget)
		}
		if len(blob) > 0 {
			out = append(out, blob...)
		}
	}

	/* 模块 M：AXDS 置于 EOF（decoy 之后）；其后仅做 16 字节对齐 padding。 */
	if dynseed {
		blk := buildDynSeedBlock(rawSeed, apkBind)
		out = append(out, blk...)
		for int64(len(out))%16 != 0 {
			out = append(out, 0)
		}
		dynSegLen := int64(len(out)) - appendOff
		if err := ensureRoom(dynSegLen); err != nil {
			return nil, err
		}
	}

	/* pack 记录/偏移在注入阶段有回填，最终落盘前重算 manifest MAC。 */
	packEnd := packStart + int64(len(pack))
	if packStart >= 0 && packEnd <= int64(len(out)) {
		sealPackManifestMAC(out[packStart:packEnd])
	}

	if !noPhdr {
		finalSegLen := uint64(int64(len(out)) - appendOff)
		if err := fillSparePhdr(out, uint64(appendOff), packVaddr, finalSegLen); err != nil {
			return nil, err
		}
		if !noNorm {
			if err := normalizePhdrOrder(out); err != nil {
				return nil, err
			}
		}
	}

	var errDep error
	out, errDep = addDTNeeded(out, depLib)
	if errDep != nil {
		return nil, errDep
	}

	return out, nil
}
