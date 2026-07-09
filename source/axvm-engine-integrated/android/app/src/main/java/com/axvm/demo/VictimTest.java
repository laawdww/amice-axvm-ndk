package com.axvm.demo;

import android.content.Context;

public class VictimTest {
    private static boolean sLoaded;

    public static synchronized void ensureReady(Context context) {
        if (sLoaded) {
            return;
        }
        Context app = context.getApplicationContext();
        System.loadLibrary("axvm");
        ApkBinding.apply(app);
        String victimPath = ProtectedSoLoader.extract(app, "victim");
        if (!nativePrepatch(victimPath)) {
            throw new UnsatisfiedLinkError("nativePrepatch failed: " + victimPath);
        }
        ProtectedSoLoader.markExecutable(new java.io.File(victimPath));
        System.load(victimPath);
        nativeRescan();
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
