package main

import "encoding/binary"

type branchFixup struct {
	relAt     int
	armTarget int
}

type addrMapEntry struct {
	arm64Off int
	vmOff    int
}

type liftedInsn struct {
	bytes    []byte
	armOff   int
	armSize  int
	branches []branchFixup
}

func patchBranches(chunks []liftedInsn, layout map[int]int) {
	for i := range chunks {
		ch := &chunks[i]
		pcAfter := layout[ch.armOff] + len(ch.bytes)
		for _, br := range ch.branches {
			targetBC, ok := layout[br.armTarget]
			if !ok {
				/* 目标不在当前函数布局：保持 rel=0 退化为 fallthrough，避免回跳入口。 */
				continue
			}
			rel := int32(targetBC - pcAfter)
			binary.LittleEndian.PutUint32(ch.bytes[br.relAt:], uint32(rel))
		}
	}
}

func buildLayout(chunks []liftedInsn) map[int]int {
	layout := make(map[int]int, len(chunks))
	pos := 0
	for i := range chunks {
		layout[chunks[i].armOff] = pos
		pos += len(chunks[i].bytes)
	}
	return layout
}
