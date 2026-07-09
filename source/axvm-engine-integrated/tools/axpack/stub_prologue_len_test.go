package main

import "testing"

func TestMaxIntPrologueLen(t *testing.T) {
	maxLen := 0
	maxPID := 0
	for pid := 0; pid < stubPrologueCount; pid++ {
		buf := emitIntPrologue(uint8(pid), nil)
		if len(buf) > maxLen {
			maxLen = len(buf)
			maxPID = pid
		}
	}
	t.Logf("max int prologue=%d bytes pid=%d", maxLen, maxPID)
	if maxLen > 64 {
		t.Logf("warn: exceeds default dispatch 64")
	}
}
