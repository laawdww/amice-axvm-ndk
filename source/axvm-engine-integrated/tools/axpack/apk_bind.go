package main

import (
	"archive/zip"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

const apkBindPrefix = "AXVM_APK_BIND1"

/* 与 runtime axvm_dynseed.c derive_apk_bound_master 对齐 */
func deriveBoundMaster(rawSeed []byte, packageName string, certSHA256 []byte) []byte {
	if len(rawSeed) < 32 || len(certSHA256) != 32 {
		return nil
	}
	msg := make([]byte, 0, len(apkBindPrefix)+len(packageName)+1+32)
	msg = append(msg, apkBindPrefix...)
	msg = append(msg, packageName...)
	msg = append(msg, 0)
	msg = append(msg, certSHA256...)
	mac := hmac.New(sha256.New, rawSeed[:32])
	_, _ = mac.Write(msg)
	return mac.Sum(nil)
}

func parseCertSHA256Hex(s string) ([]byte, error) {
	s = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(s), "0x"))
	if len(s) != 64 {
		return nil, fmt.Errorf("apk-cert-sha256: want 64 hex chars, got %d", len(s))
	}
	out, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("apk-cert-sha256: %w", err)
	}
	return out, nil
}

/* 从 APK 提取签名证书 SHA-256；与 Android getApkContentsSigners() 一致：优先 v3 > v2 > v1 */
func apkSigningCertSHA256(apkPath string) ([]byte, error) {
	h, _, err := apkSigningCertInfo(apkPath)
	return h, err
}

type apkSigScheme int

const (
	apkSigNone apkSigScheme = iota
	apkSigV1
	apkSigV2
	apkSigV3
)

func (s apkSigScheme) String() string {
	switch s {
	case apkSigV1:
		return "v1"
	case apkSigV2:
		return "v2"
	case apkSigV3:
		return "v3"
	default:
		return "none"
	}
}

type apkSigningInfo struct {
	SHA256     []byte
	Scheme     apkSigScheme
	AlsoV1     bool
	AlsoV2     bool
	AlsoV3     bool
	MismatchV1 bool /* v1 存在但与 v2/v3 主证书不一致 */
}

func apkSigningCertInfo(apkPath string) ([]byte, apkSigningInfo, error) {
	var info apkSigningInfo
	data, err := os.ReadFile(apkPath)
	if err != nil {
		return nil, info, err
	}

	var v1Hash, v2Hash, v3Hash []byte
	if h, err := apkSigningCertV1(apkPath); err == nil {
		v1Hash = h
		info.AlsoV1 = true
	}
	if h, err := apkSigningCertV2FromData(data); err == nil {
		v2Hash = h
		info.AlsoV2 = true
	}
	if h, err := apkSigningCertV3FromData(data); err == nil {
		v3Hash = h
		info.AlsoV3 = true
	}

	pick := func(primary []byte, scheme apkSigScheme) ([]byte, apkSigningInfo, error) {
		if primary == nil {
			return nil, info, fmt.Errorf("no signing cert in %s", apkPath)
		}
		info.SHA256 = primary
		info.Scheme = scheme
		if v1Hash != nil && !bytes.Equal(v1Hash, primary) {
			info.MismatchV1 = true
		}
		return primary, info, nil
	}

	if v3Hash != nil {
		return pick(v3Hash, apkSigV3)
	}
	if v2Hash != nil {
		return pick(v2Hash, apkSigV2)
	}
	if v1Hash != nil {
		return pick(v1Hash, apkSigV1)
	}
	return nil, info, fmt.Errorf("no signing cert in %s (tried v1 JAR, v2, v3)", apkPath)
}

func schemeListString(info apkSigningInfo) string {
	var parts []string
	if info.AlsoV1 {
		parts = append(parts, "v1")
	}
	if info.AlsoV2 {
		parts = append(parts, "v2")
	}
	if info.AlsoV3 {
		parts = append(parts, "v3")
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, "+")
}

func apkSigningCertV2FromData(data []byte) ([]byte, error) {
	v2, err := apkSigBlockValue(data, apkSigSchemeV2BlockID)
	if err != nil {
		return nil, err
	}
	cert, err := firstSignerCert(v2)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(cert.Raw)
	return sum[:], nil
}

func apkSigningCertV3FromData(data []byte) ([]byte, error) {
	v3, err := apkSigBlockValue(data, apkSigSchemeV3BlockID)
	if err != nil {
		return nil, err
	}
	cert, err := firstSignerCert(v3)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(cert.Raw)
	return sum[:], nil
}

func apkSigningCertV1(apkPath string) ([]byte, error) {
	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	for _, f := range zr.File {
		name := strings.ToUpper(f.Name)
		if !strings.HasPrefix(name, "META-INF/") {
			continue
		}
		if !(strings.HasSuffix(name, ".RSA") || strings.HasSuffix(name, ".DSA") || strings.HasSuffix(name, ".EC")) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}
		cert, err := parsePKCS7SigningCert(data)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(cert.Raw)
		return sum[:], nil
	}
	return nil, fmt.Errorf("no signing cert in %s", apkPath)
}

const (
	apkSigSchemeV2BlockID = 0x7109871a
	apkSigSchemeV3BlockID = 0xf05368c0
	zipEOCDSig            = 0x06054b50
)

var apkSigBlockMagic = []byte("APK Sig Block 42")

func apkSigningCertV2V3(apkPath string) ([]byte, error) {
	data, err := os.ReadFile(apkPath)
	if err != nil {
		return nil, err
	}
	if h, err := apkSigningCertV2FromData(data); err == nil {
		return h, nil
	}
	return apkSigningCertV3FromData(data)
}

func apkSigBlockValue(apk []byte, wantID uint32) ([]byte, error) {
	eocd := findZipEOCD(apk)
	if eocd < 0 {
		return nil, fmt.Errorf("eocd not found")
	}
	cdOff := binary.LittleEndian.Uint32(apk[eocd+16 : eocd+20])
	footer := int(cdOff)
	if footer < 24 || footer > len(apk) {
		return nil, fmt.Errorf("bad central dir offset")
	}
	magicOff := footer - len(apkSigBlockMagic)
	if magicOff < 0 || len(apk) < footer || !bytes.Equal(apk[magicOff:footer], apkSigBlockMagic) {
		return nil, fmt.Errorf("apk sig block magic missing at %d", magicOff)
	}
	blockSize := binary.LittleEndian.Uint64(apk[footer-24 : footer-16])
	blockStart := footer - int(blockSize) - 8
	if blockStart < 0 || blockStart+8 > magicOff {
		return nil, fmt.Errorf("bad apk sig block size")
	}
	if binary.LittleEndian.Uint64(apk[blockStart:blockStart+8]) != blockSize {
		return nil, fmt.Errorf("apk sig block size mismatch")
	}
	pairs := apk[blockStart+8 : footer-24]
	for len(pairs) >= 8 {
		pairLen := binary.LittleEndian.Uint64(pairs[:8])
		if pairLen < 4 || int(pairLen) > len(pairs)-8 {
			break
		}
		id := binary.LittleEndian.Uint32(pairs[8:12])
		val := pairs[12 : 8+pairLen]
		pairs = pairs[8+pairLen:]
		if id == wantID {
			return append([]byte(nil), val...), nil
		}
	}
	return nil, fmt.Errorf("sig block id 0x%x missing (magicOff=%d)", wantID, magicOff)
}

func findZipEOCD(apk []byte) int {
	/* EOCD comment length up to 65535; search last 64KiB+22 */
	start := len(apk) - 22
	if start < 0 {
		return -1
	}
	scan := 65535 + 22
	if scan > len(apk) {
		scan = len(apk)
	}
	for off := start; off >= len(apk)-scan; off-- {
		if binary.LittleEndian.Uint32(apk[off:off+4]) == zipEOCDSig {
			return off
		}
	}
	return -1
}

func firstSignerCert(schemeBlock []byte) (*x509.Certificate, error) {
	signers, err := readLenPrefixedItems(schemeBlock)
	if err != nil || len(signers) == 0 {
		return nil, fmt.Errorf("apk signer list empty")
	}
	signedData, _, err := readLenPrefixed(signers[0])
	if err != nil {
		return nil, err
	}
	_, rest, err := readLenPrefixed(signedData)
	if err != nil {
		return nil, err
	}
	certSeq, _, err := readLenPrefixed(rest)
	if err != nil {
		return nil, err
	}
	certs, err := readLenPrefixedSequence(certSeq)
	if err != nil || len(certs) == 0 {
		return nil, fmt.Errorf("apk signer cert empty")
	}
	return x509.ParseCertificate(certs[0])
}

func readLenPrefixedSequence(b []byte) ([][]byte, error) {
	var items [][]byte
	for len(b) > 0 {
		item, rest, err := readLenPrefixed(b)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
		b = rest
	}
	return items, nil
}

func readLenPrefixed(b []byte) ([]byte, []byte, error) {
	if len(b) < 4 {
		return nil, nil, fmt.Errorf("short len prefix")
	}
	n := binary.LittleEndian.Uint32(b[:4])
	b = b[4:]
	if int(n) > len(b) {
		return nil, nil, fmt.Errorf("len prefix overflow")
	}
	return b[:n], b[n:], nil
}

func readLenPrefixedItems(b []byte) ([][]byte, error) {
	chunk, _, err := readLenPrefixed(b)
	if err != nil {
		return nil, err
	}
	var items [][]byte
	for len(chunk) > 0 {
		var item []byte
		item, chunk, err = readLenPrefixed(chunk)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, nil
}

func resolveApkBinding(apkPath, packageName, certHex string) (string, []byte, error) {
	pkg := strings.TrimSpace(packageName)
	var cert []byte
	var err error
	if certHex != "" {
		cert, err = parseCertSHA256Hex(certHex)
		if err != nil {
			return "", nil, err
		}
	} else if apkPath != "" {
		cert, err = apkSigningCertSHA256(apkPath)
		if err != nil {
			return "", nil, err
		}
	} else {
		return "", nil, fmt.Errorf("apk-bind: need -apk or -apk-cert-sha256")
	}
	if pkg == "" && apkPath != "" {
		/* package 可单独指定；仅从 APK 无法可靠读出 applicationId */
		return "", nil, fmt.Errorf("apk-bind: -package required with -apk")
	}
	if pkg == "" {
		return "", nil, fmt.Errorf("apk-bind: -package required")
	}
	return pkg, cert, nil
}

/* META-INF/*.RSA — PKCS#7 SignedData，取首个嵌入证书 */
func parsePKCS7SigningCert(der []byte) (*x509.Certificate, error) {
	var outer struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		return nil, err
	}
	var signed struct {
		Certificates []asn1.RawValue `asn1:"optional,tag:0"`
	}
	if _, err := asn1.Unmarshal(outer.Content.Bytes, &signed); err != nil {
		return nil, err
	}
	for _, raw := range signed.Certificates {
		cert, err := x509.ParseCertificate(raw.FullBytes)
		if err == nil {
			return cert, nil
		}
	}
	return nil, fmt.Errorf("pkcs7: no certificate")
}

func apkBindSelfTest() error {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	cert := make([]byte, 32)
	for i := range cert {
		cert[i] = byte(0xA0 + i)
	}
	a := deriveBoundMaster(raw, "com.example.app", cert)
	b := deriveBoundMaster(raw, "com.example.app", cert)
	if len(a) != 32 || string(a) != string(b) {
		return fmt.Errorf("derive not stable")
	}
	wrong := deriveBoundMaster(raw, "com.other.app", cert)
	if string(a) == string(wrong) {
		return fmt.Errorf("derive ignored package")
	}
	return nil
}
