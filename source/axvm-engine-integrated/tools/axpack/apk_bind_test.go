package main

import "testing"

func TestDeriveBoundMaster(t *testing.T) {
	if err := apkBindSelfTest(); err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = 0x11
	}
	cert, err := parseCertSHA256Hex("ab" + stringsRepeat("cd", 31))
	if err != nil {
		t.Fatal(err)
	}
	m := deriveBoundMaster(raw, "com.axvm.demo", cert)
	if len(m) != 32 {
		t.Fatalf("len %d", len(m))
	}
}

func stringsRepeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}
