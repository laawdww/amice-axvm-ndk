package main

// AXZC v4 — proprietary frame + zlib payload (BestCompression).
// Must match shell/src/axgate_axzc.c.
//
// Layout:
//   ver=4 | flags | block_count u16 | seed u32
//   blocks: raw_len u32 | packed_len u32 | dyn_check u16 | payload
// payload = perturb(zlib(plain_block))
//
// Block key = key_c(seed,blk) XOR smc_mix(seed,blk).

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"encoding/binary"
	"io"
)

const (
	axzcVer       = 4
	axzcPrefBlock = 4 * 1024 * 1024
)

func axzcKeyC(seed, blk uint32) uint32 {
	return (seed * 0x85EBCA6B) ^ ((blk + 1) * 0xC2B2AE35)
}

func axzcSmcMix(seed, blk uint32) uint32 {
	return ((seed ^ 0xA5C96357) * 0x45D9F3B) ^ ((blk + 7) * 0x119DE1F3)
}

func axzcBlockKey(seed, blk uint32) uint32 {
	return axzcKeyC(seed, blk) ^ axzcSmcMix(seed, blk)
}

func axzcDynCheck(p []byte, seed, blk uint32) uint16 {
	h := seed ^ (blk * 0x9E3779B9) ^ uint32(len(p))
	for _, b := range p {
		h ^= uint32(b)
		h *= 0x01000193
		h ^= h >> 7
	}
	return uint16(h ^ (h >> 16))
}

func axzcPerturb(buf []byte, key, blk uint32) {
	for i := range buf {
		b := buf[i]
		b ^= byte(key >> ((i & 3) * 8))
		b = (b << 3) | (b >> 5)
		b ^= byte(i) ^ byte(blk)
		buf[i] = b
	}
}

func axzcUnperturb(buf []byte, key, blk uint32) {
	for i := range buf {
		b := buf[i]
		b ^= byte(i) ^ byte(blk)
		b = (b >> 3) | (b << 5)
		b ^= byte(key >> ((i & 3) * 8))
		buf[i] = b
	}
}

func axzcZlibCompress(src []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(src); err != nil {
		_ = w.Close()
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func axzcZlibInflate(src []byte, dstLen int) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(src))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	dst := make([]byte, dstLen)
	if _, err := io.ReadFull(r, dst); err != nil {
		return nil, err
	}
	return dst, nil
}

func axzcCompress(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	var seedBuf [4]byte
	if _, err := rand.Read(seedBuf[:]); err != nil {
		seedBuf[0], seedBuf[1], seedBuf[2], seedBuf[3] = 0xA7, 0x3C, 0x9E, 0x1B
	}
	seed := binary.LittleEndian.Uint32(seedBuf[:])

	blockSz := len(src)
	if blockSz > axzcPrefBlock {
		blockSz = axzcPrefBlock
	}
	nblk := (len(src) + blockSz - 1) / blockSz

	out := make([]byte, 0, len(src)/2+32+nblk*16)
	out = append(out, axzcVer, 0)
	var tmp [4]byte
	binary.LittleEndian.PutUint16(tmp[:2], uint16(nblk))
	out = append(out, tmp[0], tmp[1])
	binary.LittleEndian.PutUint32(tmp[:], seed)
	out = append(out, tmp[:]...)

	for bi := 0; bi < nblk; bi++ {
		start := bi * blockSz
		end := start + blockSz
		if end > len(src) {
			end = len(src)
		}
		raw := src[start:end]
		packed, err := axzcZlibCompress(raw)
		if err != nil {
			panic(err)
		}
		check := axzcDynCheck(raw, seed, uint32(bi))
		key := axzcBlockKey(seed, uint32(bi))
		pert := append([]byte(nil), packed...)
		axzcPerturb(pert, key, uint32(bi))

		binary.LittleEndian.PutUint32(tmp[:], uint32(len(raw)))
		out = append(out, tmp[:]...)
		binary.LittleEndian.PutUint32(tmp[:], uint32(len(pert)))
		out = append(out, tmp[:]...)
		binary.LittleEndian.PutUint16(tmp[:2], check)
		out = append(out, tmp[0], tmp[1])
		out = append(out, pert...)
	}
	return out
}

func axzcInflate(src []byte, dstLen int) ([]byte, error) {
	if len(src) < 8 || src[0] != axzcVer {
		return nil, errAxzc
	}
	nblk := int(binary.LittleEndian.Uint16(src[2:4]))
	seed := binary.LittleEndian.Uint32(src[4:8])
	if nblk <= 0 {
		return nil, errAxzc
	}
	dst := make([]byte, dstLen)
	off, di := 8, 0
	for bi := 0; bi < nblk; bi++ {
		if off+10 > len(src) {
			return nil, errAxzc
		}
		rawLen := int(binary.LittleEndian.Uint32(src[off : off+4]))
		packedLen := int(binary.LittleEndian.Uint32(src[off+4 : off+8]))
		expect := binary.LittleEndian.Uint16(src[off+8 : off+10])
		off += 10
		if rawLen <= 0 || packedLen <= 0 ||
			off+packedLen > len(src) || di+rawLen > dstLen {
			return nil, errAxzc
		}
		buf := append([]byte(nil), src[off:off+packedLen]...)
		off += packedLen
		key := axzcBlockKey(seed, uint32(bi))
		axzcUnperturb(buf, key, uint32(bi))
		part, err := axzcZlibInflate(buf, rawLen)
		if err != nil {
			return nil, err
		}
		if axzcDynCheck(part, seed, uint32(bi)) != expect {
			return nil, errAxzc
		}
		copy(dst[di:di+rawLen], part)
		di += rawLen
	}
	if off != len(src) || di != dstLen {
		return nil, errAxzc
	}
	return dst, nil
}

type axzcError string

func (e axzcError) Error() string { return string(e) }

const errAxzc = axzcError("axzc inflate failed")
