"""
P15 -- tests of analysis/primary_analysis.py on simulated data with known truth.

Run: python analysis/test_primary_analysis.py   (exit code 0 = all checks pass)
"""
import os, sys, tempfile
import numpy as np
from statsmodels.stats.multitest import multipletests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import primary_analysis as pa
from simulate_results import simulate

fails = 0


def check(ok, msg):
    global fails
    fails += not ok
    print(f"  {'ok:  ' if ok else 'FAIL:'} {msg}")


def base(rsa, ml1024s, ml1024e, hyb_extra):
    return {"rsa3072:na": rsa, "mlkem768:seed": ml1024s * 0.7, "mlkem768:expanded": ml1024e * 0.7,
            "mlkem1024:seed": ml1024s, "mlkem1024:expanded": ml1024e,
            "hybrid:seed": rsa + ml1024s + hyb_extra, "hybrid:expanded": rsa + ml1024e + hyb_extra}


tmp = tempfile.mkdtemp(prefix="p15sim_")
truth = {
    # platform: (medians, expected H2.1 status, expected H2.2 status)
    "native":          (base(1.75, 0.12, 0.17, 0.0), "supported", "supported"),
    # ML-KEM-1024 seed exactly as fast as RSA: H2.1 inconclusive
    "android":         (base(2.8, 2.8, 0.20, 0.0), "inconclusive", "supported"),
    # ML-KEM slower than RSA here: H2.1 must NOT be supported
    "chrome_desktop":  (base(1.0, 1.10, 0.60, 0.0), "refuted", "supported"),
    # hybrid 25 ms slower than RSA: inferiority shown, H2.2 refuted
    "firefox_desktop": (base(4.2, 1.7, 1.1, 23.3), "supported", "refuted"),
    # hybrid exactly 16 ms slower than RSA: H2.2 inconclusive
    "chrome_android":  (base(4.6, 2.1, 1.25, 13.9), "supported", "inconclusive"),
}
dirs = {}
for i, (pl, (med, _, _)) in enumerate(truth.items()):
    temps = (lambda rid: 420 if rid.startswith("r03p1") else 300) if pl == "android" else None
    dirs[pl] = simulate(os.path.join(tmp, pl), med, seed=i, temps_tenths=temps, header=pl)

# a host-side temperature log for chrome_android, with runs.csv end times
cd = dirs["chrome_android"]
rids = sorted(f[:-4] for f in os.listdir(cd) if f.startswith("r") and f.endswith(".csv"))
with open(os.path.join(cd, "runs.csv"), "w") as fh:
    fh.write("run_id,end_local\n")
    fh.writelines(f"{r},2026-12-01T10:{k // 60:02d}:{k % 60:02d}\n" for k, r in enumerate(rids))
tlog = os.path.join(tmp, "temp_chrome_android.csv")
with open(tlog, "w") as fh:
    fh.write("time_local,battery_temp_tenths_c\n")
    fh.writelines(f"2026-12-01T10:{k // 60:02d}:{k % 60:02d},{350 + (k % 7)}\n" for k in range(0, 120, 20))

o = pa.run(dirs, {"chrome_android": tlog})
pa.report(o, open(os.path.join(tmp, "report.txt"), "w"))
P = o["primary"]

print("Simulated data in", tmp)
check(o["n_warmup_discarded"] == 5 * 7, "warm-up block (00) discarded on every platform (35 runs)")
check(len(o["runs"]) == 5 * 10 * 7, "350 runs analysed")
check(not o["runs"].flag_stall.any(), "no stall flags when warm-up runs (3x slower) are discarded")
check(int(o["runs"].flag_hot.sum()) == 1, "one run flagged hot (start temperature 42.0 C)")
ca = o["runs"][o["runs"].platform == "chrome_android"]
check(ca.temp_tenths.notna().all() and ca.temp_tenths.between(350, 356).all(),
      "host temperature log matched to every chrome_android run")
for pl, (_, t21, t22) in truth.items():
    r21 = P[(P.platform == pl) & (P.hypothesis == "H2.1")].status.item()
    r22 = P[(P.platform == pl) & (P.hypothesis.str.startswith("H2.2"))].status.item()
    check(r21 == t21, f"{pl}: H2.1 {r21} (expected {t21})")
    check(r22 == t22, f"{pl}: H2.2 {r22} (expected {t22})")
st = P.set_index(["platform", "hypothesis"]).status
check(np.allclose(P.p_holm, multipletests(P.p, method="holm")[1]), "Holm adjustment equals statsmodels")
h = o["h23"]
est = h[(h.platform == "android") & (h.ratio.str.startswith("mlkem1024"))].iloc[0]
tr = truth["android"][0]["mlkem1024:seed"] / truth["android"][0]["mlkem1024:expanded"]
check(est.ci95_low < tr < est.ci95_high, f"H2.3 CI covers the true seed/expanded ratio {tr:.2f} "
      f"(estimate {est.estimate:.3f}, CI {est.ci95_low:.3f}-{est.ci95_high:.3f})")
s5 = o["sens_delta5"]
check(s5[(s5.platform == "firefox_desktop") & s5.hypothesis.str.startswith("H2.2")].status.item() == "refuted",
      "sensitivity delta = 5 ms computed")
check(len(o["tost"]) == 5 * 21, "TOST rows for every pair of 7 configurations on 5 platforms")
print(f"\n{'TESTS FAILED' if fails else 'ALL TESTS PASSED'} ({fails} failure{'s' if fails != 1 else ''})")
sys.exit(1 if fails else 0)
