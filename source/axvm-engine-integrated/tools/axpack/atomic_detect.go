package main

import "encoding/binary"

/* 与 lift_a64.go 原子 decode 掩码对齐，供 scan / degrade 风险提示 */
type atomicHit struct {
	Offset int
	Word   uint32
	Family string
}

func classifyAtomicInsn(word uint32) (string, bool) {
	switch {
	case (word & 0xFFC0FC00) == 0xC8407C00, (word & 0xFFC0FC00) == 0xC840FC00:
		return "LDXR", true
	case (word & 0xFFC0FC00) == 0x88407C00, (word & 0xFFC0FC00) == 0x8840FC00:
		return "LDXR32", true
	case (word & 0xFFE0FC00) == 0xC8007C00, (word & 0xFFE0FC00) == 0xC800FC00:
		return "STXR", true
	case (word & 0xFFE0FC00) == 0x88007C00, (word & 0xFFE0FC00) == 0x8800FC00:
		return "STXR32", true
	case (word & 0xFFE07C00) == 0xC8600400, (word & 0xFFE07C00) == 0xC8601000:
		return "LDXP", true
	case (word & 0xFFE07C00) == 0xC8202000, (word & 0xFFE07C00) == 0xC8203000:
		return "STXP", true
	case (word & 0xFFA07C00) == 0xC8A07C00:
		return "CAS", true
	case (word & 0xFFA07C00) == 0x88A07C00:
		return "CAS32", true
	case (word & 0xFFA07C00) == 0x48207C00:
		return "CASP", true
	case (word & 0xFF20FC00) == 0xF8200000:
		return "LDADD", true
	case (word & 0xFF20FC00) == 0xB8200000:
		return "LDADD32", true
	case (word & 0xFF20FC00) == 0xF8201000:
		return "LDCLR", true
	case (word & 0xFF20FC00) == 0xB8201000:
		return "LDCLR32", true
	case (word & 0xFF20FC00) == 0xF8202000:
		return "LDEOR", true
	case (word & 0xFF20FC00) == 0xB8202000:
		return "LDEOR32", true
	case (word & 0xFF20FC00) == 0xF8203000:
		return "LDSET", true
	case (word & 0xFF20FC00) == 0xB8203000:
		return "LDSET32", true
	case (word & 0xFF20FC00) == 0xF8208000:
		return "SWP", true
	case (word & 0xFF20FC00) == 0xB8208000:
		return "SWP32", true
	default:
		return "", false
	}
}

func diagnoseAtomicApprox(code []byte) []atomicHit {
	var hits []atomicHit
	for off := 0; off+4 <= len(code); off += 4 {
		word := binary.LittleEndian.Uint32(code[off:])
		if fam, ok := classifyAtomicInsn(word); ok {
			hits = append(hits, atomicHit{Offset: off, Word: word, Family: fam})
		}
	}
	return hits
}

func hasAtomicApprox(code []byte) bool {
	return len(diagnoseAtomicApprox(code)) > 0
}
