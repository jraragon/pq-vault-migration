"""
P15 -- pre-registered population analysis (RQ3: H3.1; RQ4: H4.1) with measured unit costs.

Unit costs per platform (E3 sessions; block 00 discarded):
  E[s]  encapsulation for suite s           (op encap, configuration s:seed or rsa3072:na)
  K[s]  key generation for suite s          (op keygen)
  W     re-wrap of one key, AES-256-KW      (op rewrap; suite-independent: per block, the
                                             median over the configurations of that block)
The unit-cost estimate is the mean over blocks of the run medians; uncertainty comes from
resampling blocks (20 000 percentile-bootstrap replicates). The JCP population is a fixed,
published synthetic workload and is not resampled (D-025).

Cost model per account (n_total, n_f, n_h from data/population_jcp_seed42.csv; files
n_files = round(phi * n_total), phi = 0.8, sensitivity 0.7 / 0.9), migrating to suite s:
  A3   0                                            (no public-key sharing)
  A1   n_h E + n_f W                                (re-encapsulate the root to each holder,
                                                     re-wrap the root's children)
  A1b  n_f n_h E + c W, 0 <= c <= n_total - n_f      (rotate each shared folder key,
                                                     re-encapsulate it to each holder, re-wrap its
                                                     c children: unknown, bounded; A1b/A1 uses
                                                     c = 0 and A2/A1b uses c = n_total - n_f, so
                                                     that both comparisons are conservative)
  A2   n_total K + (n_total + n_files + n_h) E      (every node and file key packet)
  A1 naive global re-encryption: n_total W + n_h E  (JCP baseline in its own unit: every key
                                                     of the hierarchy re-processed)
Holders' own key generation is per user, common to every architecture and strategy, and
excluded.

Three outcomes (D-029). H3.1 per platform and post-quantum suite: A1 > 0 = A3; order
A1b/A1 and A2/A1b supported if both 90 % intervals lie wholly above 1, refuted if either lies
wholly below 1; threshold: median A2/A1 supported if the lower 90 % bound is >= 10, refuted if
the upper bound is < 10; H3.1 supported if both parts are, refuted if either is, else
inconclusive. H4.1 per platform and suite: median speed-up naive / agile (A1) supported if
the lower 90 % bound is >= 10, refuted if the upper bound is < 10, else inconclusive
(JCP: 15.3x in abstract units).

Usage: python analysis/population_analysis.py PLATFORM=DIR [PLATFORM=DIR ...] [--out DIR]
       (several DIRs per platform: one per E3 operation)
"""
import argparse, glob, os, sys
from collections import defaultdict
import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
POP = os.path.join(os.path.dirname(HERE), "data", "population_jcp_seed42.csv")
PLATFORMS = ["native", "android", "chrome_desktop", "firefox_desktop", "chrome_android"]
SUITES = ["rsa3072", "mlkem768", "mlkem1024", "hybrid"]
PQ = ["mlkem768", "mlkem1024", "hybrid"]
PHI, PHI_SENS = 0.8, (0.7, 0.9)
N_BOOT, LEVEL = 20000, 0.90
THRESH_A2A1, THRESH_H41 = 10.0, 10.0


def load_population(path=POP):
    P = np.loadtxt(path, delimiter=",", skiprows=1, dtype=np.int64)
    return P[:, 1].astype(float), P[:, 2].astype(float), P[:, 3].astype(float)


def load_unit_costs(dirs_by_platform):
    """Returns {(platform, name): array of per-block values in ms}, name in E:s, K:s, W."""
    rows = []
    for pl, dirs in dirs_by_platform.items():
        for d in dirs:
            for f in sorted(glob.glob(os.path.join(d, "r[0-9][0-9]p*.csv"))):
                df = pd.read_csv(f, comment="#")
                rows.append(dict(platform=pl, rep=int(df.run_id.iloc[0][1:3]), op=df.op.iloc[0],
                                 suite=df.suite.iloc[0], fmt=df.format.iloc[0],
                                 med_ms=float(np.median(df.ns.to_numpy(float))) / 1e6))
    R = pd.DataFrame(rows)
    R = R[R.rep > 0]                                   # warm-up block discarded
    costs = {}
    for pl in R.platform.unique():
        S = R[R.platform == pl]
        for s in SUITES:
            fmt = "na" if s == "rsa3072" else "seed"
            for op, key in (("encap", "E"), ("keygen", "K")):
                v = S[(S.op == op) & (S.suite == s) & (S.fmt == fmt)].sort_values("rep").med_ms.to_numpy()
                if len(v):
                    costs[(pl, f"{key}:{s}")] = v
        w = S[S.op == "rewrap"].groupby("rep").med_ms.median().to_numpy()
        if len(w):
            costs[(pl, "W")] = w
    return costs, R


def boot_means(v, rng, n=N_BOOT):
    """Bootstrap replicates of the mean of per-block values (block resampling)."""
    idx = rng.integers(0, len(v), size=(n, len(v)))
    return v[idx].mean(axis=1)


def medians(fn, params, chunk=400):
    """fn(params_chunk) -> 2-D array (replicates x accounts) of per-account ratios;
    returns the per-replicate median over accounts."""
    n = len(next(iter(params.values())))
    out = np.empty(n)
    for i in range(0, n, chunk):
        sl = {k: v[i:i + chunk, None].astype(np.float32) for k, v in params.items()}
        out[i:i + chunk] = np.median(fn(sl), axis=1)
    return out


def interval(point_fn, boot_fn, params_point, params_boot):
    est = float(np.median(point_fn({k: np.array([[v]]) for k, v in params_point.items()})))
    b = medians(boot_fn, params_boot)
    lo, hi = np.quantile(b, [(1 - LEVEL) / 2, 1 - (1 - LEVEL) / 2])
    return est, float(lo), float(hi)


def threshold_status(lo, hi, thr):
    """Three outcomes for 'statistic >= thr' with a 90 % interval [lo, hi] (D-029)."""
    return "supported" if lo >= thr else ("refuted" if hi < thr else "inconclusive")


def order_status(intervals):
    """Adjacent pairs of the order (ratios that should exceed 1): supported if every interval
    lies wholly above 1, refuted if any lies wholly below 1, else inconclusive."""
    if any(hi < 1 for _, lo, hi in intervals):
        return "refuted"
    return "supported" if all(lo > 1 for _, lo, hi in intervals) else "inconclusive"


def _pop32(pop):
    return tuple(x.astype(np.float32) for x in pop)


def analyse(costs, phi=PHI, seed=20261121, pop=None, with_h41=True, holder_keygen=False):
    """holder_keygen=True adds n_h K_s (holders' new key pairs) to every migration cost
    (sensitivity analysis, D-027); the primary analysis excludes it."""
    nt, nf, nh = _pop32(pop if pop is not None else load_population())
    nfiles = np.round(phi * nt).astype(np.float32)
    rng = np.random.default_rng(seed)
    hk = (lambda p: nh * p["K"]) if holder_keygen else (lambda p: 0.0)
    a1 = lambda p: nh * p["E"] + nf * p["W"] + hk(p)
    # A1b: each shared folder key is rotated and re-encapsulated to each holder; the re-wrap of
    # its children is unknown (the population does not give children per folder) and bounded:
    # lower bound 0, upper bound n_total - n_f re-wraps. Each comparison uses the bound that
    # makes it conservative: A1b/A1 the lower bound, A2/A1b the upper bound (D-030).
    a1b = lambda p: nf * nh * p["E"] + hk(p)
    a1b_hi = lambda p: nf * nh * p["E"] + (nt - nf) * p["W"] + hk(p)
    a2 = lambda p: nt * p["K"] + (nt + nfiles + nh) * p["E"] + hk(p)
    naive = lambda p: nt * p["W"] + nh * p["E"] + hk(p)
    h31, h41 = [], []
    for pl in [p for p in PLATFORMS if any(k[0] == p for k in costs)]:
        if (pl, "W") not in costs:
            continue
        Wb = boot_means(costs[(pl, "W")], rng)
        for s in SUITES:
            if (pl, f"E:{s}") not in costs:
                continue
            E, Eb = costs[(pl, f"E:{s}")].mean(), boot_means(costs[(pl, f"E:{s}")], rng)
            W = costs[(pl, "W")].mean()
            pt, bt = {"E": E, "W": W}, {"E": Eb, "W": Wb}
            if holder_keygen:
                if (pl, f"K:{s}") not in costs:
                    continue
                pt["K"], bt["K"] = costs[(pl, f"K:{s}")].mean(), boot_means(costs[(pl, f"K:{s}")], rng)
            if with_h41:
                est, lo, hi = interval(lambda p: naive(p) / a1(p), lambda p: naive(p) / a1(p), pt, bt)
                h41.append(dict(platform=pl, suite=s, E_ms=E, W_ms=W, median_speedup=est,
                                lo90=lo, hi90=hi, status=threshold_status(lo, hi, THRESH_H41)))
            if s in PQ and (pl, f"K:{s}") in costs:
                if "K" not in pt:
                    pt["K"], bt["K"] = costs[(pl, f"K:{s}")].mean(), boot_means(costs[(pl, f"K:{s}")], rng)
                K = pt["K"]
                r = {}
                for name, f in (("A1b/A1", lambda p: a1b(p) / a1(p)), ("A2/A1b", lambda p: a2(p) / a1b_hi(p)),
                                ("A2/A1", lambda p: a2(p) / a1(p))):
                    r[name] = interval(f, f, pt, bt)
                st_order = order_status([r["A1b/A1"], r["A2/A1b"]])
                st_thr = threshold_status(r["A2/A1"][1], r["A2/A1"][2], THRESH_A2A1)
                a3_ok = bool(a1(pt).min() > 0)
                status = ("refuted" if (not a3_ok or "refuted" in (st_order, st_thr)) else
                          "supported" if (st_order == "supported" and st_thr == "supported") else "inconclusive")
                h31.append(dict(platform=pl, suite=s, phi=phi, K_ms=K,
                                **{f"{n} median": v[0] for n, v in r.items()},
                                **{f"{n} lo90": v[1] for n, v in r.items()},
                                **{f"{n} hi90": v[2] for n, v in r.items()},
                                A3_lt_A1=a3_ok, order=st_order, A2_A1_threshold=st_thr, status=status))
    return pd.DataFrame(h31), pd.DataFrame(h41)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("dirs", nargs="+", help="PLATFORM=DIR (repeat per operation)")
    ap.add_argument("--out")
    a = ap.parse_args(argv)
    dirs = defaultdict(list)
    for x in a.dirs:
        p, d = x.split("=", 1)
        if p not in PLATFORMS:
            sys.exit(f"unknown platform {p}")
        dirs[p].append(d)
    costs, _ = load_unit_costs(dirs)
    pd.set_option("display.width", 220); pd.set_option("display.max_columns", 30)
    pd.set_option("display.float_format", lambda x: f"{x:.4g}")
    lines = []
    for phi in (PHI,) + PHI_SENS:
        h31, h41 = analyse(costs, phi, with_h41=(phi == PHI))
        tag = "primary" if phi == PHI else "sensitivity"
        lines += [f"\n== H3.1 ({tag}, phi = {phi})", h31.to_string(index=False)]
        if phi == PHI:
            lines += [f"\n== H4.1 (phi does not enter A1)", h41.to_string(index=False)]
    h31, h41 = analyse(costs, PHI, holder_keygen=True)
    lines += ["\n== Sensitivity: holders' key generation included (n_h K_s added to every cost)",
              h31.to_string(index=False), h41.to_string(index=False)]
    text = "\n".join(lines)
    print(text)
    if a.out:
        os.makedirs(a.out, exist_ok=True)
        open(os.path.join(a.out, "population_report.txt"), "w").write(text + "\n")


if __name__ == "__main__":
    main()
