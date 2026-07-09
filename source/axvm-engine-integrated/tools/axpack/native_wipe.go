package main

import "encoding/binary"

/* 模块 O 扩展 — degrade 保留的 native 符号整段 stext 加密 + EOF AXNW 表供 prepatch 解密。 */

const (
	axnwMagic   = 0x574E5841 /* 'AXNW' little-endian */
	axnwVersion = 1
)

type nativeWipeRec struct {
	Vaddr  uint64
	Size   uint32
	FuncID uint32
}

// nativeStextFuncID 与 pack 内 func_id (1..N) 隔离，高位置位。
func nativeStextFuncID(name string) uint32 {
	return 0x80000000 | (fnv1a32([]byte(name)) & 0x7FFFFFFF)
}

func wipeNativeSymbols(out []byte, natives []fnInfo, master []byte) []nativeWipeRec {
	if len(natives) == 0 || len(master) < 32 {
		return nil
	}
	var recs []nativeWipeRec
	for _, f := range natives {
		if f.Size <= 0 || f.FileOff < 0 {
			continue
		}
		end := f.FileOff + int64(f.Size)
		if end > int64(len(out)) {
			continue
		}
		fid := nativeStextFuncID(f.Name)
		body := out[f.FileOff:end]
		stextCryptRange(body, master, fid)
		recs = append(recs, nativeWipeRec{
			Vaddr:  f.Addr,
			Size:   uint32(f.Size),
			FuncID: fid,
		})
	}
	return recs
}

func buildAXNWBlock(recs []nativeWipeRec) []byte {
	if len(recs) == 0 {
		return nil
	}
	buf := make([]byte, 16+len(recs)*16)
	binary.LittleEndian.PutUint32(buf[0:], axnwMagic)
	binary.LittleEndian.PutUint32(buf[4:], axnwVersion)
	binary.LittleEndian.PutUint32(buf[8:], uint32(len(recs)))
	for i, r := range recs {
		off := 16 + i*16
		binary.LittleEndian.PutUint64(buf[off:], r.Vaddr)
		binary.LittleEndian.PutUint32(buf[off+8:], r.Size)
		binary.LittleEndian.PutUint32(buf[off+12:], r.FuncID)
	}
	return buf
}
