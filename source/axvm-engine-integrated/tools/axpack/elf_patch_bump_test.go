package main

import (
	"debug/elf"
	"encoding/binary"
	"testing"
)

func TestDynTagIsPointerInitArray(t *testing.T) {
	/* Regression: DT_INIT_ARRAY/FINI_ARRAY must slide with RW bump.
	   Treating them as non-pointers left linker calling into the RX/RW hole. */
	for _, tag := range []elf.DynTag{elf.DT_INIT_ARRAY, elf.DT_FINI_ARRAY, elf.DT_PREINIT_ARRAY} {
		if !dynTagIsPointer(tag) {
			t.Fatalf("%v must be treated as a vaddr pointer", tag)
		}
	}
	for _, tag := range []elf.DynTag{elf.DT_INIT_ARRAYSZ, elf.DT_FINI_ARRAYSZ, elf.DT_PREINIT_ARRAYSZ} {
		if dynTagIsPointer(tag) {
			t.Fatalf("%v must stay a size/count tag", tag)
		}
	}
}

func TestPatchRelaRelativeAddend(t *testing.T) {
	const threshold, delta uint64 = 0x23368, 0x8000
	entry := make([]byte, 24)
	binary.LittleEndian.PutUint64(entry[0:], threshold+0x10)
	binary.LittleEndian.PutUint64(entry[8:], rAarch64Relative)
	binary.LittleEndian.PutUint64(entry[16:], threshold+0x100)
	rOff := binary.LittleEndian.Uint64(entry[0:])
	if rOff >= threshold {
		binary.LittleEndian.PutUint64(entry[0:], rOff+delta)
	}
	addend := int64(binary.LittleEndian.Uint64(entry[16:]))
	if addend >= int64(threshold) {
		binary.LittleEndian.PutUint64(entry[16:], uint64(addend+int64(delta)))
	}
	gotOff := binary.LittleEndian.Uint64(entry[0:])
	gotAdd := binary.LittleEndian.Uint64(entry[16:])
	if gotOff != threshold+0x10+delta {
		t.Fatalf("r_offset: got 0x%X want 0x%X", gotOff, threshold+0x10+delta)
	}
	if gotAdd != threshold+0x100+delta {
		t.Fatalf("r_addend: got 0x%X want 0x%X", gotAdd, threshold+0x100+delta)
	}
}

func TestEncodeAdrpRoundTrip(t *testing.T) {
	const pc, target uint64 = 0x3b84, 0x23000
	word, err := encodeADRP(0, pc, target)
	if err != nil {
		t.Fatal(err)
	}
	if !isADRP(word) {
		t.Fatalf("not ADRP: %08x", word)
	}
	got := decodeADRPage(pc, word)
	if got != target {
		t.Fatalf("page: got 0x%X want 0x%X", got, target)
	}
	/* bump +0xC000 → 0x2F000 */
	word2, err := encodeADRP(0, pc, target+0xC000)
	if err != nil {
		t.Fatal(err)
	}
	if decodeADRPage(pc, word2) != 0x2F000 {
		t.Fatalf("bumped page 0x%X", decodeADRPage(pc, word2))
	}
}

func TestSkipProtectByDefaultRuntimeExports(t *testing.T) {
	/* Aggressive single-SO must not virtualize embedded runtime entry points. */
	for _, name := range []string{
		"axvm_got_gate", "axvm_dispatch_ex", "axvm_invoke_native_asm",
		"axvm_embed_runtime_init", "Java_com_axvm_demo_VictimTest_victimAdd", "JNI_OnLoad",
	} {
		if !skipProtectByDefault(name) {
			t.Fatalf("expected skip protect for %s", name)
		}
	}
	for _, name := range []string{"victim_add", "victim_mul", "victim_check"} {
		if skipProtectByDefault(name) {
			t.Fatalf("must still protect business symbol %s", name)
		}
	}
}
