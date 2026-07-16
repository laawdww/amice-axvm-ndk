#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <android/log.h>

#include "axvm_pack.h"
#include "axvm_dynseed.h"
#include "axvm_log.h"

#if defined(AXVM_DEBUG) && AXVM_DEBUG
#define VLOG(...) AXVM_LOGI(__VA_ARGS__)
#else
#define VLOG(...) ((void)0)
#endif

typedef uint64_t (*victim_u64_u64)(uint64_t, uint64_t);
typedef uint64_t (*victim_u64)(uint64_t);
typedef double (*victim_dd)(double, double);

static void *g_victim_handle;
static char g_victim_path[512];
static victim_u64_u64 g_add;
static victim_u64_u64 g_mul;
static victim_u64     g_check;
static victim_dd      g_fadd;
static victim_dd      g_fmul;
static int g_victim_natives_registered;

static void *victim_dlsym(const char *name)
{
    void *sym = NULL;
    if (g_victim_handle) {
        sym = dlsym(g_victim_handle, name);
    }
    if (!sym) {
        sym = dlsym(RTLD_DEFAULT, name);
    }
    return sym;
}

static void register_victim_natives(JNIEnv *env)
{
    void *fn_prepatch;
    void *fn_rescan;
    void *fn_add;
    void *fn_mul;
    void *fn_check;
    void *fn_fadd;
    void *fn_fmul;
    jclass cls;
    JNINativeMethod methods[7];

    if (g_victim_natives_registered || !env) {
        return;
    }
    if (!g_victim_handle) {
        g_victim_handle = dlopen("libvictim.so", RTLD_NOW | RTLD_NOLOAD);
    }
    fn_prepatch = victim_dlsym("Java_com_axvm_demo_VictimTest_nativePrepatch");
    fn_rescan = victim_dlsym("Java_com_axvm_demo_VictimTest_nativeRescan");
    fn_add = victim_dlsym("Java_com_axvm_demo_VictimTest_victimAdd");
    fn_mul = victim_dlsym("Java_com_axvm_demo_VictimTest_victimMul");
    fn_check = victim_dlsym("Java_com_axvm_demo_VictimTest_victimCheck");
    fn_fadd = victim_dlsym("Java_com_axvm_demo_VictimTest_victimFadd");
    fn_fmul = victim_dlsym("Java_com_axvm_demo_VictimTest_victimFmul");
    if (!fn_prepatch || !fn_rescan || !fn_add || !fn_mul || !fn_check || !fn_fadd || !fn_fmul) {
        __android_log_print(ANDROID_LOG_ERROR, "AXVM",
                            "RegisterNatives dlsym miss pre=%p re=%p add=%p mul=%p chk=%p fa=%p fm=%p",
                            fn_prepatch, fn_rescan, fn_add, fn_mul, fn_check, fn_fadd, fn_fmul);
        return;
    }
    cls = (*env)->FindClass(env, "com/axvm/demo/VictimTest");
    if (!cls) {
        return;
    }
    methods[0] = (JNINativeMethod){"nativePrepatch", "(Ljava/lang/String;)Z", fn_prepatch};
    methods[1] = (JNINativeMethod){"nativeRescan", "()V", fn_rescan};
    methods[2] = (JNINativeMethod){"victimAdd", "(JJ)J", fn_add};
    methods[3] = (JNINativeMethod){"victimMul", "(JJ)J", fn_mul};
    methods[4] = (JNINativeMethod){"victimCheck", "(J)J", fn_check};
    methods[5] = (JNINativeMethod){"victimFadd", "(DD)D", fn_fadd};
    methods[6] = (JNINativeMethod){"victimFmul", "(DD)D", fn_fmul};
    if ((*env)->RegisterNatives(env, cls, methods, 7) == 0) {
        g_victim_natives_registered = 1;
    }
    (*env)->DeleteLocalRef(env, cls);
}

static void resolve_victim(void)
{
    if (g_add) {
        return;
    }
    if (!g_victim_handle && g_victim_path[0] != '\0') {
        g_victim_handle = dlopen(g_victim_path, RTLD_NOW | RTLD_NOLOAD);
        if (!g_victim_handle) {
            g_victim_handle = dlopen(g_victim_path, RTLD_NOW);
        }
    }
    if (!g_victim_handle) {
        g_victim_handle = dlopen("libvictim.so", RTLD_NOW | RTLD_NOLOAD);
        if (!g_victim_handle) {
            g_victim_handle = dlopen("libvictim.so", RTLD_NOW);
        }
    }
    void *symtab = g_victim_handle ? g_victim_handle : RTLD_DEFAULT;
    g_add   = (victim_u64_u64)dlsym(symtab, "victim_add");
    g_mul   = (victim_u64_u64)dlsym(symtab, "victim_mul");
    g_check = (victim_u64)dlsym(symtab, "victim_check");
    g_fadd  = (victim_dd)dlsym(symtab, "victim_fadd");
    g_fmul  = (victim_dd)dlsym(symtab, "victim_fmul");
    VLOG("resolve victim handle=%p add=%p mul=%p check=%p fadd=%p fmul=%p err=%s",
         g_victim_handle, (void *)g_add, (void *)g_mul, (void *)g_check,
         (void *)g_fadd, (void *)g_fmul,
         dlerror() ? dlerror() : "none");
}

JNIEXPORT jboolean JNICALL
Java_com_axvm_demo_ApkBinding_nativeSetBinding(JNIEnv *env, jclass clazz,
                                               jstring jpkg, jbyteArray jcert)
{
    (void)clazz;
    if (!jpkg || !jcert) {
        return JNI_FALSE;
    }
    const char *pkg = (*env)->GetStringUTFChars(env, jpkg, NULL);
    if (!pkg) {
        return JNI_FALSE;
    }
    if ((*env)->GetArrayLength(env, jcert) != 32) {
        (*env)->ReleaseStringUTFChars(env, jpkg, pkg);
        return JNI_FALSE;
    }
    jbyte *cert = (*env)->GetByteArrayElements(env, jcert, NULL);
    if (!cert) {
        (*env)->ReleaseStringUTFChars(env, jpkg, pkg);
        return JNI_FALSE;
    }
    int ok = axvm_dynseed_set_apk_binding(pkg, (const uint8_t *)cert);
    (*env)->ReleaseByteArrayElements(env, jcert, cert, JNI_ABORT);
    (*env)->ReleaseStringUTFChars(env, jpkg, pkg);
    return ok ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_axvm_demo_VictimTest_nativePrepatch(JNIEnv *env, jclass clazz, jstring jpath)
{
    (void)clazz;
    if (!jpath) {
        return JNI_FALSE;
    }
    const char *path = (*env)->GetStringUTFChars(env, jpath, NULL);
    if (!path) {
        return JNI_FALSE;
    }
    int ok = axvm_prepatch_so_file(path);
    if (ok) {
        strncpy(g_victim_path, path, sizeof(g_victim_path) - 1);
        g_victim_path[sizeof(g_victim_path) - 1] = '\0';
    }
    (*env)->ReleaseStringUTFChars(env, jpath, path);
    return ok ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL
Java_com_axvm_demo_VictimTest_nativeRescan(JNIEnv *env, jobject thiz)
{
    (void)thiz;
    void *sym = dlsym(RTLD_DEFAULT, "victim_add");
    if (!sym && g_victim_path[0] != '\0') {
        void *h = dlopen(g_victim_path, RTLD_NOW | RTLD_NOLOAD);
        if (h) {
            sym = dlsym(h, "victim_add");
        }
    }
    if (!sym) {
        void *h = dlopen("libvictim.so", RTLD_NOW | RTLD_NOLOAD);
        if (!h && g_victim_path[0] != '\0') {
            h = dlopen(g_victim_path, RTLD_NOW);
        }
        if (h) {
            g_victim_handle = h;
            sym = dlsym(h, "victim_add");
        }
    }
    if (sym) {
        axvm_register_symbol(sym);
    } else {
        __android_log_print(ANDROID_LOG_ERROR, "AXVM",
                            "nativeRescan: victim_add not found");
    }
    axvm_scan_proc_maps();
    register_victim_natives(env);
    g_add = NULL;
    g_mul = NULL;
    g_check = NULL;
    g_fadd = NULL;
    g_fmul = NULL;
    resolve_victim();
    __android_log_print(ANDROID_LOG_INFO, "AXVM",
                        "nativeRescan done add=%p check=%p",
                        (void *)g_add, (void *)g_check);
}

JNIEXPORT jlong JNICALL
Java_com_axvm_demo_VictimTest_victimAdd(JNIEnv *env, jobject thiz, jlong a, jlong b)
{
    (void)env;
    (void)thiz;
    resolve_victim();
    return g_add ? (jlong)g_add((uint64_t)a, (uint64_t)b) : -1;
}

JNIEXPORT jlong JNICALL
Java_com_axvm_demo_VictimTest_victimMul(JNIEnv *env, jobject thiz, jlong a, jlong b)
{
    (void)env;
    (void)thiz;
    resolve_victim();
    return g_mul ? (jlong)g_mul((uint64_t)a, (uint64_t)b) : -1;
}

JNIEXPORT jlong JNICALL
Java_com_axvm_demo_VictimTest_victimCheck(JNIEnv *env, jobject thiz, jlong key)
{
    (void)env;
    (void)thiz;
    resolve_victim();
    return g_check ? (jlong)g_check((uint64_t)key) : -1;
}

JNIEXPORT jdouble JNICALL
Java_com_axvm_demo_VictimTest_victimFadd(JNIEnv *env, jobject thiz, jdouble a, jdouble b)
{
    (void)env;
    (void)thiz;
    resolve_victim();
    return g_fadd ? g_fadd((double)a, (double)b) : -1.0;
}

JNIEXPORT jdouble JNICALL
Java_com_axvm_demo_VictimTest_victimFmul(JNIEnv *env, jobject thiz, jdouble a, jdouble b)
{
    (void)env;
    (void)thiz;
    resolve_victim();
    return g_fmul ? g_fmul((double)a, (double)b) : -1.0;
}
