package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestFindDeviceApkBindGot(t *testing.T) {
	raw := make([]byte, 32)
	cert := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	for i := range cert {
		cert[i] = byte(0xA0 + i)
	}
	msg := append([]byte(apkBindPrefix), []byte("com.example.app")...)
	msg = append(msg, 0)
	msg = append(msg, cert...)
	m := hmac.New(sha256.New, raw)
	_, _ = m.Write(msg)
	got := m.Sum(nil)
	t.Logf("standard=%s", hex.EncodeToString(got[:4]))

	// C sizeof prefix variant
	msg2 := append([]byte("AXVM_APK_BIND1\x00"), []byte("com.example.app")...)
	msg2 = append(msg2, 0)
	msg2 = append(msg2, cert...)
	m2 := hmac.New(sha256.New, raw)
	_, _ = m2.Write(msg2)
	t.Logf("nul_prefix=%s", hex.EncodeToString(m2.Sum(nil)[:4]))
	t.Logf("device=c4031ad4")
}
