"""
P15 -- tests of analysis/population_analysis.py on simulated E3 sessions with known unit costs.
Run: python analysis/test_population_analysis.py   (exit code 0 = all checks pass)
"""
import os, sys, tempfile
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import population_analysis as pa
from simulate_results import simulate, CONFIGS

fails = 0
def check(ok, msg):
    global fails
    fails += not ok
    print(f"  {'ok:  ' if ok else 'FAIL:'} {msg}")

# true unit costs (ms): E (encap), K (keygen) per suite, W (rewrap)
TRUTH = {
    "native":         dict(W=0.008, E=dict(rsa3072=0.035, mlkem768=0.016, mlkem1024=0.022, hybrid=0.059),
                           K=dict(rsa3072=60.0, mlkem768=0.015, mlkem1024=0.021, hybrid=60.0)),
    "chrome_desktop": dict(W=0.10, E=dict(rsa3072=0.15, mlkem768=0.40, mlkem1024=0.57, hybrid=0.75),
                           K=dict(rsa3072=300.0, mlkem768=0.35, mlkem1024=0.50, hybrid=300.0)),
}
tmp = tempfile.mkdtemp(prefix="p15pop_")
dirs = {}
for i, (pl, t) in enumerate(TRUTH.items()):
    dirs[pl] = []
    for op in ("encap", "keygen", "rewrap"):
        med = {c: (t["W"] if op == "rewrap" else t["E" if op == "encap" else "K"][c.split(":")[0]]) for c in CONFIGS}
        dirs[pl].append(simulate(os.path.join(tmp, f"{pl}_{op}"), med, iters=200, seed=10 * i + len(op), op=op,
                                 run_cv=0.02, block_cv=0.0))
costs, R = pa.load_unit_costs(dirs)
h31, h41 = pa.analyse(costs)
nt, nf, nh = pa.load_population()
print("Simulated data in", tmp)
check(int((R.rep == 0).sum()) == 0, "warm-up block discarded")
for pl, t in TRUTH.items():
    check(abs(costs[(pl, "W")].mean() / t["W"] - 1) < 0.03, f"{pl}: rewrap cost recovered")
    for s in pa.SUITES:
        E, W = t["E"][s], t["W"]
        true = np.median((nt * W + nh * E) / (nf * W + nh * E))
        row = h41[(h41.platform == pl) & (h41.suite == s)].iloc[0]
        check(abs(row.median_speedup / true - 1) < 0.03 and row.lo90 <= row.median_speedup <= row.hi90,
              f"{pl} {s}: H4.1 median speed-up {row.median_speedup:.2f} (truth {true:.2f}), "
              f"90% [{row.lo90:.2f}, {row.hi90:.2f}], {row.status}")
        expect = "supported" if true >= 10.5 else ("refuted" if true < 9.5 else None)
        check(expect is None or row.status == expect, f"{pl} {s}: H4.1 status {row.status} consistent with truth")
    for s in pa.PQ:
        E, K, W = t["E"][s], t["K"][s], t["W"]
        a1 = nh * E + nf * W; a2 = nt * K + (nt + np.round(0.8 * nt) + nh) * E
        row = h31[(h31.platform == pl) & (h31.suite == s)].iloc[0]
        check(abs(row["A2/A1 median"] / np.median(a2 / a1) - 1) < 0.03,
              f"{pl} {s}: H3.1 A2/A1 median {row['A2/A1 median']:.1f} (truth {np.median(a2 / a1):.1f}), status={row.status}")
# monotonicity: within a platform (same W), the speed-up falls as the encapsulation cost grows
for pl, t in TRUTH.items():
    h = h41[h41.platform == pl].assign(E=lambda x: [t["E"][s] for s in x.suite]).sort_values("E")
    check(bool(np.all(np.diff(h.median_speedup.to_numpy()) < 0)), f"{pl}: speed-up decreases as E/W grows")
h31k, h41k = pa.analyse(costs, holder_keygen=True)
for pl, t in TRUTH.items():
    s = "mlkem1024"; E, K, W = t["E"][s], t["K"][s], t["W"]
    true = np.median((nt * W + nh * E + nh * K) / (nf * W + nh * E + nh * K))
    row = h41k[(h41k.platform == pl) & (h41k.suite == s)].iloc[0]
    check(abs(row.median_speedup / true - 1) < 0.03, f"{pl}: holder-keygen sensitivity recovers {true:.2f} ({row.median_speedup:.2f})")
check(pa.threshold_status(10.2, 12, 10) == "supported" and pa.threshold_status(8, 9.9, 10) == "refuted"
      and pa.threshold_status(8, 13, 10) == "inconclusive", "threshold rule: three outcomes ([8, 13] is inconclusive)")
check(pa.order_status([(0, 1.2, 2), (0, 3, 4)]) == "supported" and pa.order_status([(0, 0.5, 0.9), (0, 3, 4)]) == "refuted"
      and pa.order_status([(0, 0.9, 1.3), (0, 3, 4)]) == "inconclusive", "order rule: three outcomes")
# D-030: the A2/A1b ratio uses the upper bound of A1b (children re-wrapped)
for pl, t in TRUTH.items():
    s = "mlkem1024"; E, K, W = t["E"][s], t["K"][s], t["W"]
    a1b_hi = nf * nh * E + (nt - nf) * W; a2 = nt * K + (nt + np.round(0.8 * nt) + nh) * E
    row = h31[(h31.platform == pl) & (h31.suite == s)].iloc[0]
    check(abs(row["A2/A1b median"] / np.median(a2 / a1b_hi) - 1) < 0.03,
          f"{pl}: A2/A1b uses the upper bound of A1b ({row['A2/A1b median']:.2f} vs {np.median(a2 / a1b_hi):.2f})")
    check(row["A1b/A1 lo90"] <= row["A1b/A1 median"] <= row["A1b/A1 hi90"], f"{pl}: 90 % interval brackets the estimate")
# the decision intervals are the 5th and 95th percentiles of the bootstrap medians
rng = np.random.default_rng(3)
Eb, Wb = rng.lognormal(np.log(0.02), 0.05, 2000), rng.lognormal(np.log(0.008), 0.05, 2000)
f = lambda p: (nt * p["W"] + nh * p["E"]) / (nf * p["W"] + nh * p["E"])
est, lo, hi = pa.interval(f, f, {"E": 0.02, "W": 0.008}, {"E": Eb, "W": Wb})
meds = np.array([np.median((nt * w + nh * e) / (nf * w + nh * e)) for e, w in zip(Eb, Wb)])
check(abs(lo - np.quantile(meds, 0.05)) < 1e-3 * lo and abs(hi - np.quantile(meds, 0.95)) < 1e-3 * hi,
      f"90 % interval = 5th/95th percentiles of bootstrap medians ([{lo:.3f}, {hi:.3f}])")
print(f"\n{'TESTS FAILED' if fails else 'ALL TESTS PASSED'} ({fails} failure{'s' if fails != 1 else ''})")
sys.exit(1 if fails else 0)
