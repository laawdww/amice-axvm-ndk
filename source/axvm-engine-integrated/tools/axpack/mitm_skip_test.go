package main

import "testing"

func TestMitmSkip(t *testing.T) {
	mustSkip := []string{
		"_ZL24mitm_looks_detection_keyPKc",
		"print", "print_object", "cJSON_PrintUnformatted",
		"DHparams_print", "HMAC", "ECDH_compute_key", "AcceptServerConnect",
		"CTLOG_STORE_load_file", "ADMISSIONS_get0_admissionAuthority",
		"_ZN15ShuanQApiClient11sendRequestEv",
		"_ZN13WsProxyClient10disconnectEv",
		"_ZL13arm64_movz_x8t",
		"DobbyHook", "hook_anticheat_exports",
		/* Param crypto must stay native (OpenSSL EVP under VM → 公告 URL 乱码). */
		"_ZL16aesCbcEncryptHexRKNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEES7_S7_",
		"_ZL9hexEncodeRKNSt6__ndk16vectorIhNS_9allocatorIhEEEE",
		"_Z12MD5TransformPjPh",
		"_Z9MD5EncodePhPjj",
	}
	mustProtect := []string{
		"_ZN6shuanqL15heartbeatThreadEPv",
		"_ZL13fake_jni_voidP7_JNIEnvP7_jclass",
		"_ZN6filter12FilterEngine4initEv",
		"_ZN6config13ConfigManager9getConfigERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEES9_",
		"_ZN14switch_manager13SwitchManager18getAutoGrabEnabledEv",
	}
	for _, n := range mustSkip {
		if !skipProtectByDefault(n) {
			t.Errorf("expected skip: %s", n)
		}
	}
	for _, n := range mustProtect {
		if skipProtectByDefault(n) {
			t.Errorf("expected protect: %s", n)
		}
	}
}
