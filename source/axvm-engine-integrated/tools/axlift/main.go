// Package main — L1 预处理工具链：ELF ARM64 Lifter + 字节码发射
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
)

const (
	magic0 = 'A'
	magic1 = 'X'
	magic2 = 'V'
	magic3 = '1'
	version = 0x00010000

	opNop     = 0x00
	opHalt    = 0x01
	opLdri64  = 0x10
	opAddImm  = 0x11
	opSubImm  = 0x12
	opAddReg  = 0x13
	opSubReg  = 0x14
	opMovReg  = 0x30
	opBr      = 0x40
	opBCond   = 0x41
	opRet     = 0x50
)

type bcBuilder struct {
	code []byte
	data []byte
}

func (b *bcBuilder) emit(bytes ...byte) {
	b.code = append(b.code, bytes...)
}

func fnv1a32(data []byte) uint32 {
	h := uint32(2166136261)
	for _, c := range data {
		h ^= uint32(c)
		h *= 16777619
	}
	return h
}

func checksum(hdr []byte, payload []byte) uint32 {
	skip := 28 // offset of checksum field
	h := fnv1a32(hdr[:skip])
	h2 := fnv1a32(append(hdr[skip+4:], payload...))
	return h ^ h2
}

func buildHeader(codeSize, dataSize, entryPC uint32) []byte {
	hdr := make([]byte, 40)
	hdr[0], hdr[1], hdr[2], hdr[3] = magic0, magic1, magic2, magic3
	binary.LittleEndian.PutUint32(hdr[4:], version)
	binary.LittleEndian.PutUint32(hdr[8:], 0)
	binary.LittleEndian.PutUint32(hdr[12:], 40)
	binary.LittleEndian.PutUint32(hdr[16:], codeSize)
	binary.LittleEndian.PutUint32(hdr[20:], 40+codeSize)
	binary.LittleEndian.PutUint32(hdr[24:], dataSize)
	binary.LittleEndian.PutUint32(hdr[28:], entryPC)
	return hdr
}

// decodeArm64Insn — 自研 MVP 解码器，覆盖 ADD/SUB/MOVZ/RET
func decodeArm64Insn(word uint32) ([]byte, bool) {
	// RET: 0xD65F03C0 pattern
	if word == 0xD65F03C0 {
		return []byte{opRet}, true
	}

	// ADD/XR immediate: sf=1 opc=00 10001
	if (word & 0xFF000000) == 0x91000000 {
		rd := int(word & 0x1F)
		rn := int((word >> 5) & 0x1F)
		imm := word >> 10 & 0xFFF
		return []byte{opAddImm, byte(rd), byte(rn),
			byte(imm), byte(imm >> 8), byte(imm >> 16), byte(imm >> 24)}, true
	}

	// SUB immediate
	if (word & 0xFF000000) == 0xD1000000 {
		rd := int(word & 0x1F)
		rn := int((word >> 5) & 0x1F)
		imm := word >> 10 & 0xFFF
		return []byte{opSubImm, byte(rd), byte(rn),
			byte(imm), byte(imm >> 8), byte(imm >> 16), byte(imm >> 24)}, true
	}

	// ADD reg: sf=1 opc=00 01011 shift=0
	if (word & 0xFFE0FFE0) == 0x8B000000 {
		rd := int(word & 0x1F)
		rn := int((word >> 5) & 0x1F)
		rm := int((word >> 16) & 0x1F)
		return []byte{opAddReg, byte(rd), byte(rn), byte(rm)}, true
	}

	// MOVZ 64-bit
	if (word & 0xFF800000) == 0xD2800000 {
		rd := int(word & 0x1F)
		imm16 := uint64((word >> 5) & 0xFFFF)
		hw := (word >> 21) & 0x3
		val := imm16 << (hw * 16)
		out := []byte{opLdri64, byte(rd)}
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], val)
		return append(out, buf[:]...), true
	}

	// ORR x_d, xzr, x_m  => MOV reg
	if (word & 0xFFE0FFE0) == 0xAA0003E0 {
		rd := int(word & 0x1F)
		rm := int((word >> 16) & 0x1F)
		return []byte{opMovReg, byte(rd), byte(rm)}, true
	}

	return nil, false
}

func liftFunction(code []byte) ([]byte, error) {
	b := &bcBuilder{}
	for off := 0; off+4 <= len(code); off += 4 {
		word := binary.LittleEndian.Uint32(code[off:])
		ins, ok := decodeArm64Insn(word)
		if !ok {
			return nil, fmt.Errorf("unsupported insn 0x%08X at +%d", word, off)
		}
		b.emit(ins...)
	}
	codeSize := uint32(len(b.code))
	hdr := buildHeader(codeSize, uint32(len(b.data)), 0)
	full := append(hdr, b.code...)
	full = append(full, b.data...)
	cs := fnv1a32(full[:32])
	cs ^= fnv1a32(full[36:])
	binary.LittleEndian.PutUint32(full[32:36], cs)
	return full, nil
}

func emitCHex(blob []byte, name string) string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "static const uint8_t %s[] = {\n", name)
	for i, b := range blob {
		if i%12 == 0 {
			buf.WriteString("    ")
		}
		fmt.Fprintf(&buf, "0x%02X, ", b)
		if i%12 == 11 {
			buf.WriteString("\n")
		}
	}
	buf.WriteString("\n};\n")
	return buf.String()
}

func main() {
	inPath := flag.String("in", "", "raw ARM64 function bytes (binary)")
	outPath := flag.String("out", "", "output .axbc bytecode")
	emitC := flag.String("emit-c", "", "optional C header var name")
	demo := flag.Bool("demo-add", false, "emit sample add bytecode")
	flag.Parse()

	var blob []byte
	var err error

	if *demo {
		// ADD x0, x0, x1 ; RET
		raw := []byte{
			0x00, 0x00, 0x01, 0x8b, // ADD x0, x0, x1
			0xc0, 0x03, 0x5f, 0xd6, // RET
		}
		blob, err = liftFunction(raw)
	} else if *inPath != "" {
		raw, e := os.ReadFile(*inPath)
		if e != nil {
			fmt.Fprintf(os.Stderr, "read: %v\n", e)
			os.Exit(1)
		}
		blob, err = liftFunction(raw)
	} else {
		flag.Usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "lift: %v\n", err)
		os.Exit(2)
	}

	if *outPath != "" {
		if e := os.WriteFile(*outPath, blob, 0644); e != nil {
			fmt.Fprintf(os.Stderr, "write: %v\n", e)
			os.Exit(3)
		}
	}

	if *emitC != "" {
		fmt.Print(emitCHex(blob, *emitC))
	} else if *outPath == "" {
		fmt.Printf("bytecode %d bytes, checksum=0x%08X\n", len(blob),
			binary.LittleEndian.Uint32(blob[32:36]))
	}
}
