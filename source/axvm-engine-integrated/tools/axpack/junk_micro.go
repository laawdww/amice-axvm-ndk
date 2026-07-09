package main

// 模块 S — 指令微拆分：在真实指令间插入 AXOP_JUNK 填充，抬高静态特征提取成本。

const opJunk = 0x7E

func insnStepLen(code []byte, i int) (int, bool) {
	if i >= len(code) {
		return 0, false
	}
	op := code[i]
	if op == opJunk {
		if i+1 >= len(code) {
			return 0, false
		}
		pad := int(code[i+1])
		if i+2+pad > len(code) {
			return 0, false
		}
		return 2 + pad, true
	}
	n, ok := opOperandLen(op)
	if !ok {
		return 0, false
	}
	if i+1+n > len(code) {
		return 0, false
	}
	return 1 + n, true
}

func injectJunkMicro(code []byte, master []byte) []byte {
	if len(master) < 32 || len(code) == 0 {
		return code
	}
	if !opcodeStreamValid(code) {
		return code
	}
	var out []byte
	i := 0
	for i < len(code) {
		step, ok := insnStepLen(code, i)
		if !ok {
			return code
		}
		out = append(out, code[i:i+step]...)
		i += step
		if i >= len(code) {
			break
		}
		pad := int(master[(len(out)+i)&31]&7) + 1
		if pad > 8 {
			pad = 8
		}
		out = append(out, opJunk, byte(pad))
		for j := 0; j < pad; j++ {
			out = append(out, master[(len(out)+j)&31]^byte(j*17+0x5A))
		}
	}
	return out
}
