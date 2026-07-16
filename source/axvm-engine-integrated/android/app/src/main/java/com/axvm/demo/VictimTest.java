package com.axvm.demo;

import android.content.Context;

/**
 * Loads protected victim SO. In single-SO mode the victim embeds runtime+JNI
 * ({@code AXVM_SINGLE_SO}); otherwise {@code libaxvm.so} provides binding/prepatch.
 */
public class VictimTest {
    private static boolean sLoaded;

    public static synchronized void ensureReady(Context context) {
        if (sLoaded) {
            return;
        }
        Context app = context.getApplicationContext();
        String victimPath = ProtectedSoLoader.extract(app, "victim");

        if (BuildConfig.AXVM_SINGLE_SO) {
            /* disk-ready pack: no file prepatch; load first so JNI natives resolve */
            ProtectedSoLoader.markExecutable(new java.io.File(victimPath));
            System.load(victimPath);
            ApkBinding.applyLoaded(app);
            nativeRescan();
        } else {
            System.loadLibrary("axvm");
            ApkBinding.apply(app);
            if (!nativePrepatch(victimPath)) {
                throw new UnsatisfiedLinkError("nativePrepatch failed: " + victimPath);
            }
            ProtectedSoLoader.markExecutable(new java.io.File(victimPath));
            System.load(victimPath);
            nativeRescan();
        }
        sLoaded = true;
    }

    public VictimTest(Context context) {
        ensureReady(context);
    }

    private static native boolean nativePrepatch(String soPath);
    private static native void nativeRescan();

    public native long victimAdd(long a, long b);
    public native long victimMul(long a, long b);
    public native long victimCheck(long key);
    public native double victimFadd(double a, double b);
    public native double victimFmul(double a, double b);
}
