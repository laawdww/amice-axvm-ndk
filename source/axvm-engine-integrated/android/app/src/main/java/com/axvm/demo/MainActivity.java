package com.axvm.demo;

import android.os.Bundle;
import android.widget.ScrollView;
import android.widget.TextView;
import android.util.Log;

import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "AXVM";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        TextView tv = new TextView(this);
        tv.setPadding(32, 32, 32, 32);
        tv.setTextSize(15f);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(tv);
        setContentView(scroll);
        tv.setText("AXVM Commercial Pack Test\n\nRunning module self-tests…");

        new Thread(() -> {
            StringBuilder sb = new StringBuilder();
            sb.append("AXVM Commercial Pack Test\n\n");
            try {
                runAllTests(sb);
            } catch (Throwable t) {
                sb.append("ERROR: ").append(t);
                Log.e(TAG, "pack test", t);
            }
            runOnUiThread(() -> tv.setText(sb.toString()));
        }, "axvm-selftest").start();
    }

    private void runAllTests(StringBuilder sb) {
        try {
            VictimTest vt = new VictimTest(getApplicationContext());

            long add = vt.victimAdd(41, 1);
            long mul = vt.victimMul(6, 7);
            long chkOk = vt.victimCheck(0xDEADBEEFCAFEBABEL);
            long chkBad = vt.victimCheck(0);
            Log.i(TAG, "victimAdd=" + add + " victimMul=" + mul
                    + " checkOk=" + chkOk + " checkBad=" + chkBad);

            sb.append("victim_add(41,1) = ").append(add).append("\n");
            sb.append("victim_mul(6,7) = ").append(mul).append("\n");
            sb.append("victim_check(ok) = ").append(chkOk).append("\n");
            sb.append("victim_check(bad) = ").append(chkBad).append("\n\n");

            boolean pass = add == 42 && mul == 42 && chkOk == 0x1337 && chkBad == 0;
            sb.append(pass ? "RESULT: PASS (VM protected SO)" : "RESULT: FAIL");

            Log.i(TAG, "pack test pass=" + pass + " add=" + add + " mul=" + mul);

            NativeVm nv = new NativeVm();
            nv.init();
            long blNative = nv.vmBlNativeAdd(41, 1);
            long direct = nv.nativeAdd(41, 1);
            sb.append("\n\n--- Module A JNI ---\n");
            sb.append("vmBlNativeAdd(41,1) = ").append(blNative).append("\n");
            sb.append("nativeAdd(41,1) = ").append(direct).append("\n");
            boolean modA = blNative == 42 && direct == 42;
            sb.append(modA ? "MODULE_A: PASS" : "MODULE_A: FAIL");
            Log.i(TAG, "module_a blNative=" + blNative + " direct=" + direct);

            int disp = nv.vmDispatchMode();
            long benchUs = nv.vmBenchLoop(1);
            sb.append("\n\n--- Module B Dispatch Bench ---\n");
            sb.append("dispatch = ").append(disp == 1 ? "computed_goto" : "switch").append("\n");
            sb.append("vmBenchLoop(1) = ").append(benchUs).append(" us\n");
            boolean modB = benchUs > 0;
            sb.append(modB ? "MODULE_B: PASS" : "MODULE_B: FAIL");
            Log.i(TAG, "module_b dispatch=" + disp + " bench_us=" + benchUs);

            int scrypt = nv.vmStackCryptEnabled();
            int leak = nv.vmStackDumpProbe();
            long keyMix = nv.vmStackCryptKeyMix();
            sb.append("\n\n--- Module C Stack Crypt ---\n");
            sb.append("stack_crypt = ").append(scrypt == 1 ? "ON" : "OFF").append("\n");
            sb.append("stack_dump_probe leak = ").append(leak).append("\n");
            sb.append("key_mix = 0x").append(Long.toHexString(keyMix)).append("\n");
            boolean modC = (scrypt == 0) || (leak == 0);
            sb.append(modC ? "MODULE_C: PASS" : "MODULE_C: FAIL");
            Log.i(TAG, "module_c scrypt=" + scrypt + " leak=" + leak);

            double fadd = vt.victimFadd(2.5, 1.5);
            double fmul = vt.victimFmul(3.0, 4.0);
            sb.append("\n\n--- Module F Float VM ---\n");
            sb.append("victim_fadd(2.5,1.5) = ").append(fadd).append("\n");
            sb.append("victim_fmul(3,4) = ").append(fmul).append("\n");
            boolean modF = Math.abs(fadd - 4.0) < 1e-9 && Math.abs(fmul - 12.0) < 1e-9;
            sb.append(modF ? "MODULE_F: PASS" : "MODULE_F: FAIL");
            Log.i(TAG, "module_f fadd=" + fadd + " fmul=" + fmul);

            int lazyEn = nv.vmLazyEnabled();
            int lazyLeak = nv.vmLazyDumpProbe();
            sb.append("\n\n--- Module G Lazy BB Decrypt ---\n");
            sb.append("lazy_enabled = ").append(lazyEn).append("\n");
            sb.append("bytecode_plaintext_leak = ").append(lazyLeak).append("\n");
            boolean modG = (lazyLeak == 0) || (lazyEn == 0 && lazyLeak == 1);
            sb.append(modG ? "MODULE_G: PASS" : "MODULE_G: FAIL");
            Log.i(TAG, "module_g enabled=" + lazyEn + " leak=" + lazyLeak);

            int guardEn = nv.vmGuardEnabled();
            int guardFlags = nv.vmGuardTripFlags();
            sb.append("\n\n--- Module H Guard ---\n");
            sb.append("guard_enabled = ").append(guardEn).append("\n");
            sb.append("trip_flags = 0x").append(Integer.toHexString(guardFlags)).append("\n");
            boolean modH = (guardFlags == 0) || (guardEn == 0);
            sb.append(modH ? "MODULE_H: PASS" : "MODULE_H: FAIL");
            Log.i(TAG, "module_h enabled=" + guardEn + " flags=0x" + Integer.toHexString(guardFlags));

            int jitEn = nv.vmJitEnabled();
            /* outer=1 避免主线程 ANR（全防护开启时单次 invoke 已含 1 万次内循环） */
            long jitRatio = nv.vmJitBenchCompare(1);
            sb.append("\n\n--- Module J Hotspot JIT ---\n");
            sb.append("jit_enabled = ").append(jitEn).append("\n");
            sb.append("speedup(OFF/ON) = ").append(jitRatio / 100.0).append("x\n");
            boolean modJ = jitRatio > 0;
            sb.append(modJ ? "MODULE_J: PASS" : "MODULE_J: FAIL");
            Log.i(TAG, "module_j enabled=" + jitEn + " speedupx100=" + jitRatio);

            int integEn = nv.vmIntegrityEnabled();
            int integFlags = nv.vmIntegrityTripFlags();
            sb.append("\n\n--- Module I SO Integrity ---\n");
            sb.append("integrity_enabled = ").append(integEn).append("\n");
            sb.append("tamper_trip_flags = 0x").append(Integer.toHexString(integFlags)).append("\n");
            boolean modI = (integEn == 0) || (integFlags != 0);
            sb.append(modI ? "MODULE_I: PASS" : "MODULE_I: FAIL");
            Log.i(TAG, "module_i enabled=" + integEn + " tamper_flags=0x" + Integer.toHexString(integFlags));

            int strEn = nv.vmStrcryptEnabled();
            int strTest = nv.vmStrcryptSelftest();
            sb.append("\n\n--- Module K String Crypt ---\n");
            sb.append("strcrypt_enabled = ").append(strEn).append("\n");
            sb.append("strcrypt_selftest = ").append(strTest).append("\n");
            boolean modK = (strEn == 0) || (strTest == 0);
            sb.append(modK ? "MODULE_K: PASS" : "MODULE_K: FAIL");
            Log.i(TAG, "module_k enabled=" + strEn + " selftest=" + strTest);

            int dsEn = nv.vmDynamicSeedEnabled();
            long mixA = nv.vmSessionSeedMix();
            long mixB = nv.vmSessionSeedMix();
            sb.append("\n\n--- Module M Dynamic Seed ---\n");
            sb.append("dynamic_seed = ").append(dsEn == 1 ? "ON" : "OFF").append("\n");
            sb.append("session_mix_1 = 0x").append(Long.toHexString(mixA)).append("\n");
            sb.append("session_mix_2 = 0x").append(Long.toHexString(mixB)).append("\n");
            boolean modM = (dsEn == 0) || (mixA != mixB && mixA != 0 && mixB != 0);
            sb.append(modM ? "MODULE_M: PASS" : "MODULE_M: FAIL");
            Log.i(TAG, "module_m enabled=" + dsEn + " mix1=0x" + Long.toHexString(mixA)
                    + " mix2=0x" + Long.toHexString(mixB));

            int chainTest = nv.vmChainHashSelftest();
            int chainTrip = nv.vmChainHashTripFlags();
            sb.append("\n\n--- Module Y Call-Chain Hash ---\n");
            sb.append("chain_hash_selftest = ").append(chainTest).append("\n");
            sb.append("chain_trip_flags = 0x").append(Integer.toHexString(chainTrip)).append("\n");
            boolean modY = (guardEn == 0) || (chainTest == 0 && chainTrip != 0);
            sb.append(modY ? "MODULE_Y: PASS" : "MODULE_Y: FAIL");
            Log.i(TAG, "module_y chain_selftest=" + chainTest
                    + " chain_trip=0x" + Integer.toHexString(chainTrip));

            int aaEn = nv.vmJniGuardEnabled();
            byte[] aaData = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            int aaValid = nv.vmJniGuardSelftest(aaData, "hello");
            int aaTamper = nv.vmJniGuardSelftest(aaData, null); /* 负例：空引用应被检出 */
            sb.append("\n\n--- Module AA JNI Param Integrity ---\n");
            sb.append("jni_guard_enabled = ").append(aaEn).append("\n");
            sb.append("valid_args_flags = 0x").append(Integer.toHexString(aaValid)).append("\n");
            sb.append("tampered_args_flags = 0x").append(Integer.toHexString(aaTamper)).append("\n");
            boolean modAA = (aaEn == 0) || (aaValid == 0 && aaTamper != 0);
            sb.append(modAA ? "MODULE_AA: PASS" : "MODULE_AA: FAIL");
            Log.i(TAG, "module_aa enabled=" + aaEn + " valid=" + aaValid
                    + " tamper=0x" + Integer.toHexString(aaTamper));

            int gotEn = nv.vmGotCryptEnabled();
            int gotLeak = nv.vmGotCryptLeakProbe();
            sb.append("\n\n--- Module P GOT Crypt ---\n");
            sb.append("got_crypt_enabled = ").append(gotEn).append("\n");
            sb.append("stub_dispatch_leak = ").append(gotLeak).append("\n");
            boolean modP = (gotEn == 0) || (gotLeak == 0);
            sb.append(modP ? "MODULE_P: PASS" : "MODULE_P: FAIL");
            Log.i(TAG, "module_p enabled=" + gotEn + " leak=" + gotLeak);

            int dynsymStrip = nv.vmDynsymStripProbe();
            sb.append("\n\n--- Module P Dynsym Strip ---\n");
            sb.append("dynsym_stripped_funcs = ").append(dynsymStrip).append("\n");
            boolean modPStrip = (gotEn == 0) || (dynsymStrip > 0);
            sb.append(modPStrip ? "MODULE_P_STRIP: PASS" : "MODULE_P_STRIP: FAIL");
            Log.i(TAG, "module_p_strip count=" + dynsymStrip);

            int regEn = nv.vmRegPermEnabled();
            int regTest = nv.vmRegPermSelftest();
            sb.append("\n\n--- Module U Register Perm ---\n");
            sb.append("reg_perm_enabled = ").append(regEn).append("\n");
            sb.append("reg_perm_selftest = ").append(regTest).append("\n");
            boolean modU = (regEn == 0) || (regTest == 0);
            sb.append(modU ? "MODULE_U: PASS" : "MODULE_U: FAIL");
            Log.i(TAG, "module_u enabled=" + regEn + " selftest=" + regTest);

            int qTest = nv.vmStrcryptSessionSelftest();
            sb.append("\n\n--- Module Q Session Strcrypt ---\n");
            sb.append("session_strcrypt_selftest = ").append(qTest).append("\n");
            boolean modQ = (dsEn == 0) || (qTest == 0);
            sb.append(modQ ? "MODULE_Q: PASS" : "MODULE_Q: FAIL");
            Log.i(TAG, "module_q session_selftest=" + qTest);

            int cryptVar = nv.vmCryptVariant();
            int cryptRt = nv.vmCryptRoundtripSelftest();
            sb.append("\n\n--- Module N Polymorphic Crypt ---\n");
            sb.append("crypt_variant = ").append(cryptVar).append("\n");
            sb.append("crypt_roundtrip = ").append(cryptRt).append("\n");
            boolean modN = cryptVar >= 0 && cryptVar <= 3 && cryptRt == 0;
            sb.append(modN ? "MODULE_N: PASS" : "MODULE_N: FAIL");
            Log.i(TAG, "module_n variant=" + cryptVar + " roundtrip=" + cryptRt);

            int dispPermEn = nv.vmDispatchPermEnabled();
            int dispPermTest = nv.vmDispatchPermSelftest();
            sb.append("\n\n--- Module N Dispatch Perm ---\n");
            sb.append("dispatch_perm_enabled = ").append(dispPermEn).append("\n");
            sb.append("dispatch_perm_selftest = ").append(dispPermTest).append("\n");
            boolean modND = (dispPermEn == 0) || (dispPermTest == 0);
            sb.append(modND ? "MODULE_N_DISPATCH: PASS" : "MODULE_N_DISPATCH: FAIL");
            Log.i(TAG, "module_n_dispatch enabled=" + dispPermEn + " selftest=" + dispPermTest);

            int handlerPolyEn = nv.vmHandlerPolyEnabled();
            int handlerPolyTest = nv.vmHandlerPolySelftest();
            sb.append("\n\n--- Phase 3 Handler Polymorphism ---\n");
            sb.append("handler_poly_enabled = ").append(handlerPolyEn).append("\n");
            sb.append("handler_poly_selftest = ").append(handlerPolyTest).append("\n");
            boolean modNH = (handlerPolyEn == 0) || (handlerPolyTest == 0);
            sb.append(modNH ? "MODULE_N_HANDLER: PASS" : "MODULE_N_HANDLER: FAIL");
            Log.i(TAG, "module_n_handler enabled=" + handlerPolyEn + " selftest=" + handlerPolyTest);

            int lazyPfEn = nv.vmLazyPfEnabled();
            int lazyPfTest = nv.vmLazyPfSelftest();
            sb.append("\n\n--- Phase 3 Page-Fault Lazy Decrypt ---\n");
            sb.append("lazy_pf_enabled = ").append(lazyPfEn).append("\n");
            sb.append("lazy_pf_selftest = ").append(lazyPfTest).append("\n");
            boolean modGPf = (lazyPfEn == 0) || (lazyPfTest == 0);
            sb.append(modGPf ? "MODULE_G_PF: PASS" : "MODULE_G_PF: FAIL");
            Log.i(TAG, "module_g_pf enabled=" + lazyPfEn + " selftest=" + lazyPfTest);

            int svcEn = nv.vmGuardSvcEnabled();
            int svcTest = nv.vmGuardSvcSelftest();
            sb.append("\n\n--- Phase 3 SVC Anti-Debug ---\n");
            sb.append("guard_svc_enabled = ").append(svcEn).append("\n");
            sb.append("guard_svc_selftest = ").append(svcTest).append("\n");
            boolean modHSvc = (svcEn == 0) || (svcTest == 0);
            sb.append(modHSvc ? "MODULE_H_SVC: PASS" : "MODULE_H_SVC: FAIL");
            Log.i(TAG, "module_h_svc enabled=" + svcEn + " selftest=" + svcTest);

            int wdEn = nv.vmWatchdogEnabled();
            int wdTest = nv.vmWatchdogSelftest();
            sb.append("\n\n--- Phase 3 Watchdog ---\n");
            sb.append("watchdog_enabled = ").append(wdEn).append("\n");
            sb.append("watchdog_selftest = ").append(wdTest).append("\n");
            boolean modWd = (wdEn == 0) || (wdTest == 0);
            sb.append(modWd ? "MODULE_WATCHDOG: PASS" : "MODULE_WATCHDOG: FAIL");
            Log.i(TAG, "module_watchdog enabled=" + wdEn + " selftest=" + wdTest);

            int jitHardEn = nv.vmJitHardenEnabled();
            int jitHardTest = nv.vmJitHardenSelftest();
            sb.append("\n\n--- Phase 3 JIT Harden ---\n");
            sb.append("jit_harden_enabled = ").append(jitHardEn).append("\n");
            sb.append("jit_harden_selftest = ").append(jitHardTest).append("\n");
            boolean modJH = (jitHardEn == 0) || (jitHardTest == 0);
            sb.append(modJH ? "MODULE_J_HARDEN: PASS" : "MODULE_J_HARDEN: FAIL");
            Log.i(TAG, "module_j_harden enabled=" + jitHardEn + " selftest=" + jitHardTest);

            int junkTest = nv.vmJunkSelftest();
            sb.append("\n\n--- Module S Junk Micro-ops ---\n");
            sb.append("junk_selftest = ").append(junkTest).append("\n");
            sb.append(junkTest == 0 ? "MODULE_S: PASS" : "MODULE_S: FAIL");
            Log.i(TAG, "module_s junk_selftest=" + junkTest);

            int memEn = nv.vmMemGuardEnabled();
            int memTest = nv.vmMemGuardSelftest();
            sb.append("\n\n--- Module X Mem Pool Guard ---\n");
            sb.append("mem_guard_enabled = ").append(memEn).append("\n");
            sb.append("mem_guard_selftest = ").append(memTest).append("\n");
            boolean modX = (memEn == 0) || (memTest == 0);
            sb.append(modX ? "MODULE_X: PASS" : "MODULE_X: FAIL");
            Log.i(TAG, "module_x enabled=" + memEn + " selftest=" + memTest);

            int emuProbe = nv.vmEmulatorProbe();
            int timingTest = nv.vmTimingGuardSelftest();
            sb.append("\n\n--- Module V/W Env + Timing ---\n");
            sb.append("emulator_probe = ").append(emuProbe).append("\n");
            sb.append("timing_selftest = ").append(timingTest).append("\n");
            boolean modVW = (guardEn == 0) || (emuProbe == 0 && timingTest == 0);
            sb.append(modVW ? "MODULE_VW: PASS" : "MODULE_VW: FAIL");
            Log.i(TAG, "module_vw emu=" + emuProbe + " timing=" + timingTest);

            int stextEn = nv.vmStextEnabled();
            int stextWiped = nv.vmStextWipedModules();
            sb.append("\n\n--- Module O Native Text Wipe ---\n");
            sb.append("stext_enabled = ").append(stextEn).append("\n");
            sb.append("wiped_modules = ").append(stextWiped).append("\n");
            boolean modO = (stextEn == 0) || (stextWiped > 0);
            sb.append(modO ? "MODULE_O: PASS" : "MODULE_O: FAIL");
            Log.i(TAG, "module_o enabled=" + stextEn + " wiped=" + stextWiped);

            int nestedTest = nv.vmNestedVmSelftest();
            int nestedDepth = nv.vmNestedDepthSelftest();
            sb.append("\n\n--- Module R Nested VM ---\n");
            sb.append("nested_selftest = ").append(nestedTest).append("\n");
            sb.append("nested_depth_selftest = ").append(nestedDepth).append("\n");
            boolean modR = nestedTest == 0 && nestedDepth == 0;
            sb.append(modR ? "MODULE_R: PASS" : "MODULE_R: FAIL");
            Log.i(TAG, "module_r nested_selftest=" + nestedTest + " depth=" + nestedDepth);

            int engineId = nv.vmDispatchEngineId();
            int risccTest = nv.vmRisccSelftest();
            sb.append("\n\n--- Module T Multi-ISA ---\n");
            sb.append("engine_id = 0x").append(Integer.toHexString(engineId)).append("\n");
            sb.append("riscc_selftest = ").append(risccTest).append("\n");
            boolean modT = engineId == 0xA64 && risccTest == 0;
            sb.append(modT ? "MODULE_T: PASS" : "MODULE_T: FAIL");
            Log.i(TAG, "module_t engine_id=0x" + Integer.toHexString(engineId) + " riscc=" + risccTest);

            int risccPermEn = nv.vmRisccPermEnabled();
            int risccPermTest = nv.vmRisccPermSelftest();
            sb.append("\n\n--- Phase 3 RISCC Wire Perm ---\n");
            sb.append("riscc_perm_enabled = ").append(risccPermEn).append("\n");
            sb.append("riscc_perm_selftest = ").append(risccPermTest).append("\n");
            boolean modTP = (risccPermEn == 0) || (risccPermTest == 0);
            sb.append(modTP ? "MODULE_T_PERM: PASS" : "MODULE_T_PERM: FAIL");
            Log.i(TAG, "module_t_perm enabled=" + risccPermEn + " selftest=" + risccPermTest);

            int isaTest = nv.vmInterpSelftest();
            sb.append("\n\n--- VM Opcode Matrix ---\n");
            sb.append("interp_selftest = ").append(isaTest).append("\n");
            boolean modISA = isaTest == 0;
            sb.append(modISA ? "MODULE_ISA: PASS" : "MODULE_ISA: FAIL");
            Log.i(TAG, "module_isa interp_selftest=" + isaTest);

            int abReg = nv.vmJniRegisterNativesActive();
            int abTunnel = nv.vmJniTunnelSelftest(0xBEEF);
            sb.append("\n\n--- Module AB JNI Hide + Tunnel ---\n");
            sb.append("register_natives = ").append(abReg).append("\n");
            sb.append("tunnel_selftest = ").append(abTunnel).append("\n");
            boolean modAB = (abReg == 1 && abTunnel == 0);
            sb.append(modAB ? "MODULE_AB: PASS" : "MODULE_AB: FAIL");
            Log.i(TAG, "module_ab reg=" + abReg + " tunnel=" + abTunnel);

            Log.i(TAG, pass ? "PACK: PASS" : "PACK: FAIL");
            Log.i(TAG, modA ? "MODULE_A: PASS" : "MODULE_A: FAIL");
            Log.i(TAG, modB ? "MODULE_B: PASS" : "MODULE_B: FAIL");
            Log.i(TAG, modC ? "MODULE_C: PASS" : "MODULE_C: FAIL");
            Log.i(TAG, modF ? "MODULE_F: PASS" : "MODULE_F: FAIL");
            Log.i(TAG, modG ? "MODULE_G: PASS" : "MODULE_G: FAIL");
            Log.i(TAG, modH ? "MODULE_H: PASS" : "MODULE_H: FAIL");
            Log.i(TAG, modJ ? "MODULE_J: PASS" : "MODULE_J: FAIL");
            Log.i(TAG, modI ? "MODULE_I: PASS" : "MODULE_I: FAIL");
            Log.i(TAG, modK ? "MODULE_K: PASS" : "MODULE_K: FAIL");
            Log.i(TAG, modM ? "MODULE_M: PASS" : "MODULE_M: FAIL");
            Log.i(TAG, modY ? "MODULE_Y: PASS" : "MODULE_Y: FAIL");
            Log.i(TAG, modAA ? "MODULE_AA: PASS" : "MODULE_AA: FAIL");
            Log.i(TAG, modP ? "MODULE_P: PASS" : "MODULE_P: FAIL");
            Log.i(TAG, modPStrip ? "MODULE_P_STRIP: PASS" : "MODULE_P_STRIP: FAIL");
            Log.i(TAG, modU ? "MODULE_U: PASS" : "MODULE_U: FAIL");
            Log.i(TAG, modQ ? "MODULE_Q: PASS" : "MODULE_Q: FAIL");
            Log.i(TAG, modN ? "MODULE_N: PASS" : "MODULE_N: FAIL");
            Log.i(TAG, modND ? "MODULE_N_DISPATCH: PASS" : "MODULE_N_DISPATCH: FAIL");
            Log.i(TAG, modNH ? "MODULE_N_HANDLER: PASS" : "MODULE_N_HANDLER: FAIL");
            Log.i(TAG, modGPf ? "MODULE_G_PF: PASS" : "MODULE_G_PF: FAIL");
            Log.i(TAG, modHSvc ? "MODULE_H_SVC: PASS" : "MODULE_H_SVC: FAIL");
            Log.i(TAG, modWd ? "MODULE_WATCHDOG: PASS" : "MODULE_WATCHDOG: FAIL");
            Log.i(TAG, modJH ? "MODULE_J_HARDEN: PASS" : "MODULE_J_HARDEN: FAIL");
            Log.i(TAG, modTP ? "MODULE_T_PERM: PASS" : "MODULE_T_PERM: FAIL");
            Log.i(TAG, (junkTest == 0) ? "MODULE_S: PASS" : "MODULE_S: FAIL");
            Log.i(TAG, modX ? "MODULE_X: PASS" : "MODULE_X: FAIL");
            Log.i(TAG, modVW ? "MODULE_VW: PASS" : "MODULE_VW: FAIL");
            Log.i(TAG, modO ? "MODULE_O: PASS" : "MODULE_O: FAIL");
            Log.i(TAG, modR ? "MODULE_R: PASS" : "MODULE_R: FAIL");
            Log.i(TAG, modT ? "MODULE_T: PASS" : "MODULE_T: FAIL");
            Log.i(TAG, modTP ? "MODULE_T_PERM: PASS" : "MODULE_T_PERM: FAIL");
            Log.i(TAG, modISA ? "MODULE_ISA: PASS" : "MODULE_ISA: FAIL");
            Log.i(TAG, modAB ? "MODULE_AB: PASS" : "MODULE_AB: FAIL");
        } catch (Throwable t) {
            sb.append("ERROR: ").append(t);
            Log.e(TAG, "pack test", t);
        }
    }
}
