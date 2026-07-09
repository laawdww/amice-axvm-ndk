package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestApkV2SigningCert(t *testing.T) {
	apk := filepath.Join("..", "..", "android", "app", "build", "outputs", "apk", "debug", "app-debug.apk")
	if _, err := os.Stat(apk); err != nil {
		t.Skip(apk)
	}
	cert, info, err := apkSigningCertInfo(apk)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert) != 32 {
		t.Fatalf("len %d", len(cert))
	}
	t.Logf("scheme=%s present=%s mismatch_v1=%v", info.Scheme, schemeListString(info), info.MismatchV1)
	if info.Scheme != apkSigV2 && info.Scheme != apkSigV3 {
		t.Fatalf("expected v2 or v3 primary for modern debug apk, got %s", info.Scheme)
	}
	if !info.AlsoV2 && !info.AlsoV3 {
		t.Fatal("debug apk should have v2 or v3 block")
	}
}

func TestApkSigningPrefersV2OverV1(t *testing.T) {
	apk := filepath.Join("..", "..", "android", "app", "build", "outputs", "apk", "debug", "app-debug.apk")
	if _, err := os.Stat(apk); err != nil {
		t.Skip(apk)
	}
	primary, info, err := apkSigningCertInfo(apk)
	if err != nil {
		t.Fatal(err)
	}
	if !info.AlsoV1 {
		t.Skip("apk has no v1 block to compare")
	}
	v1Only, err := apkSigningCertV1(apk)
	if err != nil {
		t.Fatal(err)
	}
	if info.Scheme == apkSigV1 {
		t.Fatal("should not prefer v1 when v2/v3 present")
	}
	if !bytes.Equal(primary, v1Only) && !info.MismatchV1 {
		t.Fatal("v1 differs from primary but MismatchV1 not set")
	}
}

func TestApkSigningV2V3Fallback(t *testing.T) {
	apk := filepath.Join("..", "..", "android", "app", "build", "outputs", "apk", "debug", "app-debug.apk")
	if _, err := os.Stat(apk); err != nil {
		t.Skip(apk)
	}
	data, err := os.ReadFile(apk)
	if err != nil {
		t.Fatal(err)
	}
	fromHelper, err := apkSigningCertV2V3(apk)
	if err != nil {
		t.Fatal(err)
	}
	fromInfo, info, err := apkSigningCertInfo(apk)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fromHelper, fromInfo) && info.Scheme != apkSigV3 {
		// v2v3 helper prefers v2; info prefers v3 when both exist
		v3, err := apkSigningCertV3FromData(data)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(fromInfo, v3) {
			t.Fatalf("info cert mismatch v3")
		}
	} else if !bytes.Equal(fromHelper, fromInfo) {
		t.Fatalf("helper vs info mismatch")
	}
}

func TestSchemeListString(t *testing.T) {
	s := schemeListString(apkSigningInfo{AlsoV1: true, AlsoV2: true, AlsoV3: true})
	if s != "v1+v2+v3" {
		t.Fatalf("got %q", s)
	}
	s = schemeListString(apkSigningInfo{AlsoV1: true, AlsoV2: true})
	if s != "v1+v2" {
		t.Fatalf("got %q", s)
	}
}

func TestPrintApkCertFormat(t *testing.T) {
	apk := filepath.Join("..", "..", "android", "app", "build", "outputs", "apk", "debug", "app-debug.apk")
	if _, err := os.Stat(apk); err != nil {
		t.Skip(apk)
	}
	cert, info, err := apkSigningCertInfo(apk)
	if err != nil {
		t.Fatal(err)
	}
	line := hex.EncodeToString(cert)
	if len(line) != 64 {
		t.Fatalf("hex len %d", len(line))
	}
	_ = info
}
