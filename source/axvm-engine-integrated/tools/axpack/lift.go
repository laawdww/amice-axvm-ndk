package main

import (
	"bytes"
	"fmt"
	"os"
	"sync"
)

var globalRelocCache = newRelocCache()

/* 批量提升：共享重定位缓存，降低大型 SO 重复常量展开开销 */
func liftFuncBatch(funcs []fnInfo) error {
	lifted, _, err := liftFuncBatchDegrade(funcs, false, false)
	if err != nil {
		return err
	}
	mergeLiftedInto(funcs, lifted)
	return nil
}

func mergeLiftedInto(funcs []fnInfo, lifted []fnInfo) {
	byName := make(map[string]fnInfo, len(lifted))
	for _, f := range lifted {
		byName[f.Name] = f
	}
	for i := range funcs {
		if f, ok := byName[funcs[i].Name]; ok {
			funcs[i] = f
		}
	}
}

/*
 * degrade=true 时 lift 失败符号保留为 native（不写入 pack），继续处理其余符号。
 * skipAtomic=true 时含 ATOMIC_APPROX 的符号也跳过（默认与 -degrade 联用）。
 */
func liftFuncBatchDegrade(funcs []fnInfo, degrade bool, skipAtomic bool) ([]fnInfo, []fnInfo, error) {
	cache := newRelocCache()
	var lifted []fnInfo
	var native []fnInfo
	for i := range funcs {
		f := funcs[i]
		if skipAtomic && hasAtomicApprox(f.OrigCode) {
			n := len(diagnoseAtomicApprox(f.OrigCode))
			if degrade {
				fmt.Fprintf(os.Stderr, "[lift] SKIP %s: ATOMIC_APPROX (%d insns, not thread-safe if lifted)\n", f.Name, n)
				native = append(native, f)
				continue
			}
			return nil, nil, fmt.Errorf("%s: ATOMIC_APPROX (%d insns)", f.Name, n)
		}
		bc, entry, fp, amap, err := liftFuncWithCache(f.OrigCode, f.Addr, cache)
		if err != nil {
			if degrade {
				fmt.Fprintf(os.Stderr, "[lift] SKIP %s: %v\n", f.Name, err)
				native = append(native, f)
				continue
			}
			return nil, nil, fmt.Errorf("%s: %w", f.Name, err)
		}
		f.BC = bc
		f.EntryPC = entry
		f.UsesFP = fp
		f.AddrMap = amap
		f.Lifted = true
		fmt.Printf("[lift] %s size=%d bc=%d\n", f.Name, len(f.OrigCode), len(bc))
		lifted = append(lifted, f)
	}
	if len(lifted) == 0 {
		return nil, native, fmt.Errorf("no symbols lifted (%d candidates)", len(funcs))
	}
	return lifted, native, nil
}

func liftFunc(code []byte, funcAddr uint64) ([]byte, uint32, bool, error) {
	bc, entry, fp, _, err := liftFuncWithCache(code, funcAddr, globalRelocCache)
	return bc, entry, fp, err
}

func liftFuncWithCache(code []byte, funcAddr uint64, cache *relocCache) ([]byte, uint32, bool, []addrMapEntry, error) {
	if len(code) == 0 {
		return nil, 0, false, nil, fmt.Errorf("empty function body")
	}
	if len(code)%4 != 0 {
		return nil, 0, false, nil, fmt.Errorf("function size %d not 4-byte aligned", len(code))
	}

	var chunks []liftedInsn
	var fpUsed bool
	for off := 0; off < len(code); {
		ch, err := decodeInsnAt(code, off, funcAddr, cache, nil, &fpUsed)
		if err != nil {
			return nil, 0, false, nil, err
		}
		word := uint32(0)
		if off+4 <= len(code) {
			word = uint32(code[off]) |
				(uint32(code[off+1]) << 8) |
				(uint32(code[off+2]) << 16) |
				(uint32(code[off+3]) << 24)
		}
		if chunkWritesScratch(ch.bytes) &&
			!armInsnWritesReg(word, scratchReg0) &&
			!armInsnWritesReg(word, scratchReg1) &&
			(len(ch.bytes) == 0 || ch.bytes[0] != opSaveScratch) {
			ch.bytes = withScratchPairSaved(ch.bytes)
			for i := range ch.branches {
				ch.branches[i].relAt++
			}
		}
		chunks = append(chunks, ch)
		off += ch.armSize
	}

	layout := buildLayout(chunks)
	patchBranches(chunks, layout)

	var bc bytes.Buffer
	for _, ch := range chunks {
		bc.Write(ch.bytes)
	}
	if bc.Len() == 0 {
		return nil, 0, false, nil, fmt.Errorf("empty bytecode")
	}
	amap := buildAddrMapEntries(chunks, layout)
	return bc.Bytes(), 0, fpUsed, amap, nil
}

/* 供测试/诊断：列出函数内全部不支持指令 */
func diagnoseLift(code []byte, funcAddr uint64) []unsupportedInsn {
	var fails []unsupportedInsn
	cache := newRelocCache()
	for off := 0; off < len(code); {
		_, err := decodeInsnAt(code, off, funcAddr, cache, nil, nil)
		if err != nil {
			if u, ok := err.(unsupportedInsn); ok {
				fails = append(fails, u)
				off += 4
				continue
			}
			break
		}
		ch, _ := decodeInsnAt(code, off, funcAddr, cache, nil, nil)
		off += ch.armSize
	}
	return fails
}

var liftCacheMu sync.Mutex
