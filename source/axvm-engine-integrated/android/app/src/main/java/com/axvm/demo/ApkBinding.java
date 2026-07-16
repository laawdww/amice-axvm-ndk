package com.axvm.demo;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.util.Log;

import java.security.MessageDigest;

/**
 * Registers APK package + signing cert before loading apk-bound protected SOs.
 * Dual-SO: loads {@code libaxvm}. Single-SO: natives already resolved from victim.
 */
public final class ApkBinding {
    private static final String TAG = "AXVM";
    private static boolean sApplied;
    private static boolean sLibLoaded;

    private ApkBinding() {}

    /** Dual-SO path: ensure libaxvm is loaded then apply binding. */
    public static synchronized void apply(Context context) {
        ensureAxvmLibrary();
        applyLoaded(context);
    }

    /** Single-SO path: victim already loaded; only register binding. */
    public static synchronized void applyLoaded(Context context) {
        if (sApplied) {
            return;
        }
        Context app = context.getApplicationContext();
        try {
            byte[] cert = signingCertSha256(app);
            if (BuildConfig.DEBUG) {
                Log.d(TAG, "ApkBinding cert=" + toHex(cert).substring(0, 16) + "...");
            }
            if (!nativeSetBinding(app.getPackageName(), cert)) {
                throw new IllegalStateException("nativeSetBinding failed");
            }
            sApplied = true;
        } catch (Throwable t) {
            throw new RuntimeException("ApkBinding.apply", t);
        }
    }

    private static void ensureAxvmLibrary() {
        if (sLibLoaded || BuildConfig.AXVM_SINGLE_SO) {
            return;
        }
        System.loadLibrary("axvm");
        sLibLoaded = true;
    }

    private static byte[] signingCertSha256(Context context) throws Exception {
        PackageManager pm = context.getPackageManager();
        String pkg = context.getPackageName();
        Signature[] sigs;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            PackageInfo pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES);
            if (pi.signingInfo == null) {
                throw new IllegalStateException("no signingInfo");
            }
            sigs = pi.signingInfo.getApkContentsSigners();
        } else {
            @SuppressWarnings("deprecation")
            PackageInfo pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES);
            @SuppressWarnings("deprecation")
            Signature[] legacy = pi.signatures;
            sigs = legacy;
        }
        if (sigs == null || sigs.length == 0) {
            throw new IllegalStateException("no signatures");
        }
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(sigs[0].toByteArray());
    }

    private static native boolean nativeSetBinding(String packageName, byte[] certSha256);

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(String.format("%02x", x & 0xff));
        }
        return sb.toString();
    }
}
