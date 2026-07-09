package com.axvm.demo;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Build;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Loads a protected SO from app-private storage so runtime can patch .text (SELinux
 * blocks execmod on APK-extracted libs under apk_data_file).
 */
public final class ProtectedSoLoader {
    private ProtectedSoLoader() {}

    public static String extract(Context context, String libName) {
        try {
            String abi = Build.SUPPORTED_ABIS[0];
            String zipPath = findApkPath(context.getApplicationInfo());
            File outDir = new File(context.getFilesDir(), "axvm-libs");
            if (!outDir.exists() && !outDir.mkdirs()) {
                throw new IllegalStateException("mkdir " + outDir);
            }
            File out = new File(outDir, libName + ".so");
            extractLib(zipPath, "lib/" + abi + "/lib" + libName + ".so", out);
            return out.getAbsolutePath();
        } catch (Throwable t) {
            throw new UnsatisfiedLinkError("ProtectedSoLoader: " + t.getMessage());
        }
    }

    public static void load(Context context, String libName) {
        System.load(extract(context, libName));
    }

    private static String findApkPath(ApplicationInfo info) {
        if (info.sourceDir != null) {
            return info.sourceDir;
        }
        if (info.publicSourceDir != null) {
            return info.publicSourceDir;
        }
        throw new IllegalStateException("apk path missing");
    }

    private static void extractLib(String apkPath, String entryName, File out) throws Exception {
        long srcLen = 0;
        try (ZipFile zip = new ZipFile(apkPath)) {
            ZipEntry entry = zip.getEntry(entryName);
            if (entry == null) {
                throw new IllegalStateException("missing " + entryName);
            }
            srcLen = entry.getSize();
            try (InputStream in = zip.getInputStream(entry);
                 FileOutputStream fos = new FileOutputStream(out)) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) > 0) {
                    fos.write(buf, 0, n);
                }
            }
        }
        if (srcLen > 0 && out.length() != srcLen) {
            throw new IllegalStateException("size mismatch " + out.length() + " vs " + srcLen);
        }
        //noinspection ResultOfMethodCallIgnored
        out.setReadable(true, false);
        //noinspection ResultOfMethodCallIgnored
        out.setWritable(true, false);
        /* executable 在 prepatch 改写 .text 之后再设（见 VictimTest.ensureReady） */
    }

    static void markExecutable(File so) {
        //noinspection ResultOfMethodCallIgnored
        so.setExecutable(true, false);
    }
}
