package main

import (
	"bytes"
	"debug/elf"
	"os"
	"testing"
)

type insnCase struct {
	name  string
	words []uint32
}

func TestLiftInsnMatrix(t *testing.T) {
	cases := []insnCase{
		{"nop", []uint32{0xD503201F}},
		{"ret", []uint32{0xD65F03C0}},
		{"add_reg", []uint32{0x8B000020}}, /* add x0, x1, x0 */
		{"sub_reg", []uint32{0xCB000020}}, /* sub x0, x1, x0 */
		{"mul", []uint32{0x9B007C20}},     /* mul x0, x1, x0 */
		{"and_reg", []uint32{0x8A000020}},
		{"orr_reg", []uint32{0xAA000020}},
		{"eor_reg", []uint32{0xCA000020}},
		{"mov_reg", []uint32{0xAA0003E0}}, /* mov x0, x0 */
		{"mvn", []uint32{0xAA2003E0}},     /* orn x0, xzr, x0 */
		{"movz", []uint32{0xD2800040}},    /* movz x0, #2 */
		{"movk", []uint32{0xF2A00040}},    /* movk x0, #0, lsl 16 */
		{"movn", []uint32{0x92BFFFE0}},    /* movn x0, #0xFFFF */
		{"add_imm", []uint32{0x91000400}}, /* add x0, x0, #1 */
		{"sub_imm", []uint32{0xD1000400}}, /* sub x0, x0, #1 */
		{"cmp_imm", []uint32{0xF100142F}}, /* cmp x1, #5 */
		{"neg", []uint32{0xCB0003E0}},     /* neg x0, x0 */
		{"lsl_imm", []uint32{0x9343FC00}}, /* lsl x0, x0, #4 */
		{"lsr_imm", []uint32{0xD343FC00}}, /* lsr x0, x0, #4 */
		{"asr_imm", []uint32{0x9344FC00}}, /* asr x0, x0, #4 */
		{"csel", []uint32{0x9A800020}},
		{"ldr_u64", []uint32{0xF9400000}},
		{"str_u64", []uint32{0xF9000000}},
		{"ldxr_u64", []uint32{0xC85F7C20}},  /* ldxr x0, [x1] */
		{"stxr_u64", []uint32{0xC8027C20}},  /* stxr w2, x0, [x1] */
		{"ldxp_u64", []uint32{0xC87F0440}},  /* ldxp x0, x1, [x2] */
		{"stxp_u64", []uint32{0xC8262127}},  /* stxp w6, x7, x8, [x9] */
		{"cas_u64", []uint32{0xC8AA7D8B}},   /* cas x10, x11, [x12] */
		{"casp_u64", []uint32{0x482E7E50}},  /* casp x14, x15, x16, x17, [x18] */
		{"ldadd_u64", []uint32{0xF8360317}}, /* ldadd x22, x23, [x24] */
		{"ldclr_u64", []uint32{0xF8211062}}, /* ldclr x1, x2, [x3] */
		{"ldeor_u64", []uint32{0xF839237A}}, /* ldeor x25, x26, [x27] */
		{"ldset_u64", []uint32{0xF82D31EE}}, /* ldset x13, x14, [x15] */
		{"swp_u64", []uint32{0xF829816A}},   /* swp x9, x10, [x11] */
		{"ldur_u64", []uint32{0xF8400000}},
		{"stur_u64", []uint32{0xF8000000}},
		{"ldur_w", []uint32{0xB85FC3A8}}, /* ldur w8, [x29, #-4] */
		{"stur_w", []uint32{0xB81FC3A8}}, /* stur w8, [x29, #-4] */
		{"ldrb", []uint32{0x39400000}},
		{"strb", []uint32{0x39000000}},
		{"b", []uint32{0x14000001, 0xD65F03C0}},
		{"b_cond", []uint32{0x54000001, 0xD65F03C0}},
		{"cbz", []uint32{0xB4000001, 0xD65F03C0}},
		{"tbz", []uint32{0x37000001, 0xD65F03C0}},
		{"bl", []uint32{0x94000001, 0xD65F03C0}},
		{"blr", []uint32{0xD63F0000, 0xD65F03C0}},
		{"br", []uint32{0xD61F0000, 0xD65F03C0}},
		{"stp", []uint32{0xA9BF7BFD, 0xD65F03C0}},   /* stp x29,x30,[sp,#-16]! */
		{"ldp", []uint32{0xA8C17BFD, 0xD65F03C0}},   /* ldp x29,x30,[sp],#16 */
		{"ldr_q", []uint32{0x3DC04020, 0xD65F03C0}}, /* ldr q0, [x1] */
		{"str_q", []uint32{0x3C804020, 0xD65F03C0}}, /* str q0, [x1] */
		{"and_imm", []uint32{0x92785C08}},           /* and x0, x1, #0xFF00FF00 */
		{"bti", []uint32{0xD503245F, 0xD65F03C0}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bc, err := liftRawInsn(tc.words, 0x1000)
			if err != nil {
				t.Fatalf("lift %s: %v", tc.name, err)
			}
			if len(bc) == 0 {
				t.Fatalf("lift %s: empty bc", tc.name)
			}
			if !opcodeStreamValid(bc) {
				t.Fatalf("lift %s: invalid opcode stream", tc.name)
			}
		})
	}
}

func TestLiftUnscaledLoadStoreDirection(t *testing.T) {
	bc, err := liftRawInsn([]uint32{0xB85FC3A8}, 0x1000) // ldur w8, [x29, #-4]
	if err != nil {
		t.Fatal(err)
	}
	if len(bc) == 0 || bc[0] != opLdurU32 {
		t.Fatalf("LDUR W encoded op 0x%02x, want 0x%02x", bc[0], opLdurU32)
	}
	bc, err = liftRawInsn([]uint32{0xB81FC3A8}, 0x1000) // stur w8, [x29, #-4]
	if err != nil {
		t.Fatal(err)
	}
	if len(bc) == 0 || bc[0] != opSturU32 {
		t.Fatalf("STUR W encoded op 0x%02x, want 0x%02x", bc[0], opSturU32)
	}
}

func TestLiftAddExtended64DoesNotZext(t *testing.T) {
	bc, err := liftRawInsn([]uint32{0x8B2BD12B}, 0x1000) // add x11, x9, w11, sxtw #4
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(bc, []byte{opAddReg, 11, 9}) {
		t.Fatalf("ADD extended did not emit ADD_REG rd=x11 rn=x9: % x", bc)
	}
	if bytes.Contains(bc, []byte{opZext32, 11}) {
		t.Fatalf("64-bit ADD extended was treated as 32-bit and zero-extended: % x", bc)
	}
}

func TestLiftVictimISA(t *testing.T) {
	paths := []string{
		"../../build-verify-arm64/samples/victim/libvictim.so",
		"../../build-ndk-arm64/samples/victim/libvictim.so",
	}
	var raw []byte
	var err error
	for _, p := range paths {
		raw, err = os.ReadFile(p)
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Skip("libvictim.so not built")
	}
	ef, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	names := []string{
		"victim_neg", "victim_cmp_imm", "victim_and_imm", "victim_asr",
		"victim_ldp_stp", "victim_movn", "victim_ldr_reg",
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			funcs, err := collectFuncs(ef, raw, map[string]bool{name: true})
			if err != nil || len(funcs) == 0 {
				t.Fatalf("collect %s: %v", name, err)
			}
			bc, _, _, amap, err := liftFuncWithCache(funcs[0].OrigCode, funcs[0].Addr, newRelocCache())
			if err != nil {
				t.Fatalf("lift %s: %v", name, err)
			}
			if len(bc) == 0 {
				t.Fatal("empty bc")
			}
			if !opcodeStreamValid(bc) {
				t.Fatal("invalid opcode stream")
			}
			t.Logf("%s native=%d bc=%d amap=%d", name, len(funcs[0].OrigCode), len(bc), len(amap))
		})
	}
}

func TestLiftAllExportedIncludesISA(t *testing.T) {
	paths := []string{
		"../../build-verify-arm64/samples/victim/libvictim.so",
		"../../build-ndk-arm64/samples/victim/libvictim.so",
	}
	var raw []byte
	var err error
	for _, p := range paths {
		raw, err = os.ReadFile(p)
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Skip("libvictim.so not built")
	}
	ef, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	funcs, err := collectFuncs(ef, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := liftFuncBatch(funcs); err != nil {
		t.Fatal(err)
	}
}
