/*
 * axgate host — outer libaxvm.so surface.
 * JNI_OnLoad only stashes JavaVM; decrypt runs after Java injects APK identity.
 */
#include "axgate.h"
#include "axgate_kdf.h"

#include <jni.h>
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef jint(JNICALL *fn_JNI_OnLoad)(JavaVM *, void *);
typedef jboolean(JNICALL *fn_EnsureBinding)(JNIEnv *, jclass);
typedef jboolean(JNICALL *fn_Prepatch)(JNIEnv *, jclass, jstring);
typedef int (*fn_x7b)(const char *, const uint8_t *);
typedef uint64_t (*fn_x7)(uint32_t, uint64_t, uint64_t, uint64_t, uint64_t,
                          uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

static JavaVM *g_vm;
static int g_inner_jni_ok;
static int g_host_bind_ok;
static fn_EnsureBinding g_ensure;
static fn_Prepatch g_prepatch;
static fn_x7b g_x7b;
static fn_x7 g_x7d;
static fn_x7 g_x7g;

static int apply_host_bind(void)
{
    if (g_host_bind_ok) {
        return 1;
    }
    void *h = axgate_inner_handle();
    if (!h) {
        return 0;
    }
    if (!g_x7b) {
        g_x7b = (fn_x7b)dlsym(h, "x7b");
    }
    if (!g_x7b) {
        return 0;
    }
    char pkg[96];
    uint8_t cert[32];
    if (!axgate_runtime_identity(pkg, sizeof(pkg), cert)) {
        return 0;
    }
    int ok = g_x7b(pkg, cert);
    volatile char *pw = pkg;
    volatile uint8_t *cw = cert;
    size_t i;
    for (i = 0; i < sizeof(pkg); ++i) {
        pw[i] = 0;
    }
    for (i = 0; i < 32; ++i) {
        cw[i] = 0;
    }
    if (ok) {
        g_host_bind_ok = 1;
    }
    return ok;
}

static int resolve_inner(void)
{
    void *h = axgate_inner_handle();
    if (!h) {
        return 0;
    }
    if (!g_ensure) {
        g_ensure = (fn_EnsureBinding)dlsym(
            h, "Java_com_hook_bypass_AxvmApkBinding_nativeEnsureBinding");
    }
    if (!g_prepatch) {
        g_prepatch = (fn_Prepatch)dlsym(
            h, "Java_com_hook_bypass_AxvmPrepatch_nativePrepatch");
    }
    if (!g_x7b) {
        g_x7b = (fn_x7b)dlsym(h, "x7b");
    }
    if (!g_x7d) {
        g_x7d = (fn_x7)dlsym(h, "x7d");
    }
    if (!g_x7g) {
        g_x7g = (fn_x7)dlsym(h, "x7g");
    }
    return g_ensure != NULL && g_prepatch != NULL && g_x7d != NULL;
}

static int call_inner_jni_onload(JavaVM *vm)
{
    if (g_inner_jni_ok) {
        return 1;
    }
    void *h = axgate_inner_handle();
    if (!h || !vm) {
        return 0;
    }
    (void)apply_host_bind();
    fn_JNI_OnLoad onload = (fn_JNI_OnLoad)dlsym(h, "JNI_OnLoad");
    if (!onload) {
        return 0;
    }
    jint ver = onload(vm, NULL);
    if (ver < JNI_VERSION_1_6) {
        return 0;
    }
    g_inner_jni_ok = 1;
    return resolve_inner();
}

static int finish_boot_with_identity(const char *pkg, const uint8_t *cert)
{
    if (!axgate_set_runtime_identity(pkg, cert)) {
        return 0;
    }
    if (!axgate_ensure_booted()) {
        return 0;
    }
    if (g_vm && !call_inner_jni_onload(g_vm)) {
        return 0;
    }
    (void)apply_host_bind();
    return 1;
}

JNIEXPORT jboolean JNICALL
Java_com_hook_bypass_SoMemLoader_nativeFinishAxvmBoot(JNIEnv *env, jclass clazz,
                                                      jstring jpkg, jbyteArray jcert)
{
    (void)clazz;
    if (!jpkg || !jcert || (*env)->GetArrayLength(env, jcert) != 32) {
        return JNI_FALSE;
    }
    const char *pkg = (*env)->GetStringUTFChars(env, jpkg, NULL);
    if (!pkg) {
        return JNI_FALSE;
    }
    jbyte *cert = (*env)->GetByteArrayElements(env, jcert, NULL);
    if (!cert) {
        (*env)->ReleaseStringUTFChars(env, jpkg, pkg);
        return JNI_FALSE;
    }
    int ok = finish_boot_with_identity(pkg, (const uint8_t *)cert);
    (*env)->ReleaseByteArrayElements(env, jcert, cert, JNI_ABORT);
    (*env)->ReleaseStringUTFChars(env, jpkg, pkg);
    return ok ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_hook_bypass_AxvmApkBinding_nativeEnsureBinding(JNIEnv *env, jclass clazz)
{
    if (!axgate_ensure_booted()) {
        return JNI_FALSE;
    }
    if (g_vm && !g_inner_jni_ok) {
        (void)call_inner_jni_onload(g_vm);
    }
    if (apply_host_bind()) {
        return JNI_TRUE;
    }
    if (!resolve_inner() || !g_ensure) {
        return JNI_FALSE;
    }
    return g_ensure(env, clazz);
}

JNIEXPORT jboolean JNICALL
Java_com_hook_bypass_AxvmPrepatch_nativePrepatch(JNIEnv *env, jclass clazz, jstring path)
{
    if (!axgate_ensure_booted()) {
        return JNI_FALSE;
    }
    if (g_vm && !g_inner_jni_ok) {
        (void)call_inner_jni_onload(g_vm);
    }
    (void)apply_host_bind();
    if (!resolve_inner() || !g_prepatch) {
        return JNI_FALSE;
    }
    return g_prepatch(env, clazz, path);
}

static void gate_abort(void)
{
    abort();
}

__attribute__((visibility("default")))
uint64_t x7d(uint32_t func_id,
             uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
             uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7,
             uint64_t sret_x8)
{
    if (!g_x7d) {
        (void)resolve_inner();
    }
    if (!g_x7d) {
        gate_abort();
    }
    return g_x7d(func_id, a0, a1, a2, a3, a4, a5, a6, a7, sret_x8);
}

__attribute__((visibility("default")))
uint64_t x7g(uint32_t func_id,
             uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
             uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7,
             uint64_t sret_x8)
{
    if (!g_x7g) {
        (void)resolve_inner();
    }
    if (!g_x7g) {
        gate_abort();
    }
    return g_x7g(func_id, a0, a1, a2, a3, a4, a5, a6, a7, sret_x8);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void)reserved;
    g_vm = vm;
    /* Defer axgate_ensure_booted until nativeFinishAxvmBoot injects APK identity. */
    return JNI_VERSION_1_6;
}
