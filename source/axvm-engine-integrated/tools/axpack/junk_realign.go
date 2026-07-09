package main

import "encoding/binary"

/* 收集每条真实指令在字节码中的起始偏移（跳过 AXOP_JUNK 填充）。 */
func insnStartOffsets(code []byte) []int {
	var starts []int
	for i := 0; i < len(code); {
		step, ok := insnStepLen(code, i)
		if !ok {
			break
		}
		if code[i] != opJunk {
			starts = append(starts, i)
		}
		i += step
	}
	return starts
}

/*
 * injectJunkMicro 在指令间插入垃圾后，重算 B/BR 相对偏移与 addr_map 的 vmOff。
 * plain 为注入前的字节码；junked 为注入后副本（原地修补）。
 */
func realignBytecodeAfterJunk(plain, junked []byte, addrMap []addrMapEntry) ([]byte, []addrMapEntry) {
	if len(plain) == 0 || len(junked) == 0 {
		return junked, addrMap
	}
	plainStarts := insnStartOffsets(plain)
	junkStarts := insnStartOffsets(junked)
	if len(plainStarts) != len(junkStarts) || len(plainStarts) == 0 {
		return junked, addrMap
	}

	findInsnAt := func(starts []int, code []byte, off int) int {
		for i := len(starts) - 1; i >= 0; i-- {
			if starts[i] <= off {
				step, ok := insnStepLen(code, starts[i])
				if ok && off < starts[i]+step {
					return i
				}
			}
		}
		return -1
	}

	patchRel := func(plainIdx int, relAt int) {
		pi := plainStarts[plainIdx]
		ji := junkStarts[plainIdx]
		plainStep, _ := insnStepLen(plain, pi)
		junkStep, _ := insnStepLen(junked, ji)
		oldRel := int32(binary.LittleEndian.Uint32(plain[pi+relAt:]))
		plainPcAfter := pi + plainStep
		plainTarget := plainPcAfter + int(oldRel)
		tgtIdx := findInsnAt(plainStarts, plain, plainTarget)
		if tgtIdx < 0 {
			return
		}
		junkPcAfter := ji + junkStep
		newRel := int32(junkStarts[tgtIdx] - junkPcAfter)
		binary.LittleEndian.PutUint32(junked[ji+relAt:], uint32(newRel))
	}

	for idx := 0; idx < len(plainStarts); idx++ {
		pi := plainStarts[idx]
		op := plain[pi]
		switch op {
		case opBr:
			patchRel(idx, 1)
		case opBCond:
			patchRel(idx, 2)
		default:
			step, ok := insnStepLen(plain, pi)
			if !ok {
				continue
			}
			if step >= 4 {
				relAt := step - 4
				if relAt > 0 && (op == 0x34 || op == 0x35 || op == 0x36 || op == 0x37 ||
					op == 0xB4 || op == 0xB5 || op == 0xB6 || op == 0xB7) {
					_ = relAt
				}
			}
		}
	}

	if len(addrMap) == 0 {
		return junked, addrMap
	}
	outMap := make([]addrMapEntry, len(addrMap))
	for i, e := range addrMap {
		outMap[i] = e
		tgtIdx := findInsnAt(plainStarts, plain, e.vmOff)
		if tgtIdx >= 0 && tgtIdx < len(junkStarts) {
			outMap[i].vmOff = junkStarts[tgtIdx]
		}
	}
	return junked, outMap
}
