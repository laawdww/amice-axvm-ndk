package main

import (
	"encoding/binary"
	"sort"
)

/* VMPacker trailer：addr_map + reverse + oc_key + map_count + func_addr + func_size */

func buildAddrMapEntries(chunks []liftedInsn, layout map[int]int) []addrMapEntry {
	entries := make([]addrMapEntry, 0, len(chunks))
	seen := make(map[int]struct{}, len(chunks))
	for i := range chunks {
		off := chunks[i].armOff
		if _, ok := seen[off]; ok {
			continue
		}
		seen[off] = struct{}{}
		vm, ok := layout[off]
		if !ok {
			continue
		}
		entries = append(entries, addrMapEntry{arm64Off: off, vmOff: vm})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].arm64Off < entries[j].arm64Off
	})
	return entries
}

func appendAddrMapTrailer(code []byte, funcAddr uint64, funcSize int, entries []addrMapEntry) []byte {
	out := append([]byte(nil), code...)
	for _, e := range entries {
		var b [8]byte
		binary.LittleEndian.PutUint32(b[0:], uint32(e.arm64Off))
		binary.LittleEndian.PutUint32(b[4:], uint32(e.vmOff))
		out = append(out, b[:]...)
	}
	out = append(out, 0) // reverse
	var z [4]byte
	out = append(out, z[:]...) // oc_key
	binary.LittleEndian.PutUint32(z[:], uint32(len(entries)))
	out = append(out, z[:]...)
	var fa [8]byte
	binary.LittleEndian.PutUint64(fa[:], funcAddr)
	out = append(out, fa[:]...)
	var fs [4]byte
	binary.LittleEndian.PutUint32(fs[:], uint32(funcSize))
	out = append(out, fs[:]...)
	return out
}
