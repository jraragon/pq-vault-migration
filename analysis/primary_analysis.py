"""
P15 -- pre-registered analysis of E2 (open an A1 account), all platforms.

Implements Section "Statistical analysis" of the pre-registration (v0.4 and later):
  * unit: run median of 1 000 timed operations; block 00 (warm-up) is discarded;
  * H2.1 per platform: one-sided paired t-test on log(ML-KEM-1024 seed / RSA-3072) < 0;
  * H2.2 per platform: non-inferiority of hybrid (seed format) - RSA-3072 within
    delta = 16 ms on the paired difference of run medians (one-sided t);
  * Holm over the primary family (H2.1 and H2.2 x platforms);
  * robustness: percentile bootstrap (20 000) of the same statistics;
  * sensitivity: delta = 5 and 50 ms; run medians of the first 250 operations;
    excluding flagged runs (start temperature > 40 C, or median > 1.5 x cell median);
  * H2.3: estimation of the seed / expanded ratio with a 95 % CI;
  * TOST of relative equivalence (+-2, 5, 10 %) for every pair of configurations
    (reported, not confirmatory); order effect by OLS.

Usage:
  python analysis/primary_analysis.py PLATFORM=DIR [PLATFORM=DIR ...]
         [--temps PLATFORM=FILE] [--out DIR] [--seed N]
  PLATFORM is one of native, android, chrome_desktop, firefox_desktop, chrome_android.
  --temps gives the host-side battery temperature log for a browser run on the phone.
"""
import argparse, glob, math, os, re, sys
import numpy as np
import pandas as pd
from scipy import stats

PLATFORMS = ["native", "android", "chrome_desktop", "firefox_desktop", "chrome_android"]
DELTA_MS = 16.0
DELTA_SENS = (5.0, 50.0)
ALPHA = 0.05
N_BOOT = 20000
HOT_TENTHS = 400
STALL_FACTOR = 1.5
FIRST_K = 250
H21 = ("mlkem1024:seed", "rsa3072:na")
H22 = ("hybrid:seed", "rsa3072:na")
H23 = [("mlkem1024:seed", "mlkem1024:expanded"), ("mlkem768:seed", "mlkem768:expanded"),
       ("hybrid:seed", "hybrid:expanded")]
TOST_BOUNDS = (0.02, 0.05, 0.10)


# ------------------------------------------------------------------ loading
def _header(path):
    h = {}
    with open(path) as fh:
        for line in fh:
            if not line.startswith("#"):
                break
            for m in re.finditer(r"(\w+)=([^\s]+)", line):
                h[m.group(1)] = m.group(2)
    return h


def load_dir(platform, d, temps_file=None):
    rows = []
    for f in sorted(glob.glob(os.path.join(d, "r[0-9][0-9]p*.csv"))):
        df = pd.read_csv(f, comment="#")
        rid = df.run_id.iloc[0]
        ns = df.ns.to_numpy(dtype=float)
        h = _header(f)
        rows.append(dict(platform=platform, run_id=rid, rep=int(rid[1:3]),
                         pos=int(rid.split("p")[1].split("_")[0]),
                         cfg=f"{df.suite.iloc[0]}:{df.format.iloc[0]}",
                         med_ms=np.median(ns) / 1e6, med250_ms=np.median(ns[:FIRST_K]) / 1e6,
                         p95_ms=np.percentile(ns, 95) / 1e6, p99_ms=np.percentile(ns, 99) / 1e6,
                         n_ops=len(ns), temp_tenths=np.nan,
                         temp_hdr=float(h["battery_temp_c"]) * 10 if "battery_temp_c" in h else np.nan))
    R = pd.DataFrame(rows)
    if R.empty:
        sys.exit(f"no runs in {d}")
    # start temperature: Android app header, runner's temperatures.csv, or host log
    R["temp_tenths"] = R.temp_hdr
    tf = os.path.join(d, "temperatures.csv")
    if os.path.exists(tf):
        T = pd.read_csv(tf)
        R = R.drop(columns="temp_tenths").merge(
            T[["run_id", "battery_temp_tenths_c"]].rename(columns={"battery_temp_tenths_c": "temp_tenths"}),
            on="run_id", how="left")
    if temps_file:
        log = pd.read_csv(temps_file, names=["t", "temp"], header=None, dtype=str)
        log["t"] = pd.to_datetime(log.t, errors="coerce", format="ISO8601")
        log["temp"] = pd.to_numeric(log.temp, errors="coerce")
        log = log.dropna().sort_values("t")
        rf = os.path.join(d, "runs.csv")
        if os.path.exists(rf):
            E = pd.read_csv(rf)
            tcol = "end_local" if "end_local" in E else "start_local"
            E["t"] = pd.to_datetime(E[tcol])
            E = pd.merge_asof(E.sort_values("t"), log, on="t", direction="backward")
            R = R.drop(columns="temp_tenths").merge(
                E[["run_id", "temp"]].rename(columns={"temp": "temp_tenths"}), on="run_id", how="left")
    return R.drop(columns="temp_hdr")


def prepare(R):
    """Drop the warm-up block and flag runs (blind to suite)."""
    n_warm = int((R.rep == 0).sum())
    R = R[R.rep > 0].copy()
    cell_med = R.groupby(["platform", "cfg"]).med_ms.transform("median")
    R["flag_stall"] = R.med_ms > STALL_FACTOR * cell_med
    R["flag_hot"] = R.temp_tenths > HOT_TENTHS
    R["flagged"] = R.flag_stall | R.flag_hot
    return R, n_warm


# ------------------------------------------------------------------ statistics
def paired(R, platform, a, b, col="med_ms", log=True):
    W = R[R.platform == platform].pivot(index="rep", columns="cfg", values=col)
    W = W[[a, b]].dropna()
    return (np.log(W[a] / W[b]) if log else (W[a] - W[b])).to_numpy()


def t_less(x, mu):
    """One-sided test of H0: mean >= mu against mean < mu."""
    n = len(x)
    if n < 2:
        return np.nan
    se = x.std(ddof=1) / math.sqrt(n)
    if se == 0:
        return 0.0 if x.mean() < mu else 1.0
    return float(stats.t.cdf((x.mean() - mu) / se, n - 1))


def upper_bound(x, level=0.95):
    n = len(x)
    return x.mean() + stats.t.ppf(level, n - 1) * x.std(ddof=1) / math.sqrt(n)


def boot_upper(x, rng, level=0.95):
    idx = rng.integers(0, len(x), size=(N_BOOT, len(x)))
    return float(np.quantile(x[idx].mean(axis=1), level))


def holm(p):
    p = np.asarray(p, dtype=float)
    order = np.argsort(p)
    adj = np.empty_like(p)
    m, run = len(p), 0.0
    for k, i in enumerate(order):
        run = max(run, min(1.0, (m - k) * p[i]))
        adj[i] = run
    return adj


def primary(R, rng, col="med_ms", delta=DELTA_MS, label="primary"):
    rows = []
    for pl in [p for p in PLATFORMS if p in set(R.platform)]:
        d1 = paired(R, pl, *H21, col=col, log=True)
        d2 = paired(R, pl, *H22, col=col, log=False)
        h90 = stats.t.ppf(0.95, len(d1) - 1) * d1.std(ddof=1) / math.sqrt(len(d1))
        rows.append(dict(analysis=label, platform=pl, hypothesis="H2.1", n=len(d1),
                         estimate=f"ratio {math.exp(d1.mean()):.3f}",
                         upper95=f"{math.exp(upper_bound(d1)):.3f}",
                         ci90=f"[{math.exp(d1.mean() - h90):.3f}, {math.exp(d1.mean() + h90):.3f}]",
                         refuted=bool(d1.mean() - h90 > 0),
                         boot_upper95=f"{math.exp(boot_upper(d1, rng)):.3f}",
                         p=t_less(d1, 0.0), boot_ok=boot_upper(d1, rng) < 0))
        h90d = stats.t.ppf(0.95, len(d2) - 1) * d2.std(ddof=1) / math.sqrt(len(d2))
        rows.append(dict(analysis=label, platform=pl, hypothesis=f"H2.2 (delta {delta:g} ms)", n=len(d2),
                         estimate=f"diff {d2.mean():+.3f} ms", upper95=f"{upper_bound(d2):+.3f} ms",
                         ci90=f"[{d2.mean() - h90d:+.3f}, {d2.mean() + h90d:+.3f}] ms",
                         refuted=bool(d2.mean() - h90d > delta),
                         boot_upper95=f"{boot_upper(d2, rng):+.3f} ms",
                         p=t_less(d2, delta), boot_ok=boot_upper(d2, rng) < delta))
    T = pd.DataFrame(rows)
    T["p_holm"] = holm(T.p)
    T["reject_H0"] = T.p_holm < ALPHA
    # Pre-registered verdicts (D-029), three outcomes for both hypotheses:
    #   H2.1 supported (one-sided test rejects after Holm) / refuted (90 % interval of the
    #        ratio wholly above 1) / inconclusive;
    #   H2.2 supported (non-inferiority shown after Holm) / refuted (inferiority shown: 90 %
    #        interval of the difference wholly above delta) / inconclusive.
    T["status"] = ["supported" if r else ("refuted" if f else "inconclusive")
                   for r, f in zip(T.reject_H0, T.refuted)]
    return T


def h23(R):
    rows = []
    for pl in [p for p in PLATFORMS if p in set(R.platform)]:
        for a, b in H23:
            d = paired(R, pl, a, b)
            if len(d) < 2:
                continue
            h = stats.t.ppf(0.975, len(d) - 1) * d.std(ddof=1) / math.sqrt(len(d))
            rows.append(dict(platform=pl, ratio=f"{a} / {b}", n=len(d), estimate=math.exp(d.mean()),
                             ci95_low=math.exp(d.mean() - h), ci95_high=math.exp(d.mean() + h)))
    return pd.DataFrame(rows)


def tost(R):
    rows = []
    for pl in [p for p in PLATFORMS if p in set(R.platform)]:
        cfgs = sorted(set(R[R.platform == pl].cfg))
        for i, a in enumerate(cfgs):
            for b in cfgs[i + 1:]:
                d = paired(R, pl, a, b)
                if len(d) < 2:
                    continue
                h = stats.t.ppf(0.95, len(d) - 1) * d.std(ddof=1) / math.sqrt(len(d))
                lo, hi = math.exp(d.mean() - h), math.exp(d.mean() + h)
                row = dict(platform=pl, pair=f"{a} / {b}", ratio=math.exp(d.mean()), ci90_low=lo, ci90_high=hi)
                for e in TOST_BOUNDS:
                    row[f"equiv_{int(e * 100)}%"] = lo > 1 - e and hi < 1 / (1 - e)
                rows.append(row)
    return pd.DataFrame(rows)


def order_effect(R):
    import statsmodels.formula.api as smf
    rows = []
    for pl in [p for p in PLATFORMS if p in set(R.platform)]:
        S = R[R.platform == pl].assign(logmed=lambda x: np.log(x.med_ms))
        m = smf.ols("logmed ~ C(cfg) + C(rep) + pos", data=S).fit()
        rows.append(dict(platform=pl, pct_per_position=100 * m.params["pos"], p=m.pvalues["pos"]))
    return pd.DataFrame(rows)


def descriptives(R):
    g = R.groupby(["platform", "cfg"])
    return pd.DataFrame({"runs": g.size(), "median_ms": g.med_ms.median(), "p95_ms": g.p95_ms.median(),
                         "p99_ms": g.p99_ms.median(),
                         "cv_between_runs_%": 100 * g.med_ms.std() / g.med_ms.mean(),
                         "flagged": g.flagged.sum()}).reset_index()


# ------------------------------------------------------------------ driver
def run(dirs, temps=None, seed=20261121):
    rng = np.random.default_rng(seed)
    R = pd.concat([load_dir(p, d, (temps or {}).get(p)) for p, d in dirs.items()], ignore_index=True)
    R, n_warm = prepare(R)
    out = {"runs": R, "n_warmup_discarded": n_warm,
           "primary": primary(R, rng),
           "sens_first250": primary(R, rng, col="med250_ms", label=f"first {FIRST_K} ops"),
           "sens_unflagged": primary(R[~R.flagged], rng, label="flagged runs excluded"),
           "h23": h23(R), "tost": tost(R), "order": order_effect(R), "desc": descriptives(R)}
    for dl in DELTA_SENS:
        out[f"sens_delta{dl:g}"] = primary(R, rng, delta=dl, label=f"delta {dl:g} ms")
    return out


def report(o, fh=sys.stdout):
    pd.set_option("display.width", 200); pd.set_option("display.max_columns", 30)
    pd.set_option("display.max_rows", 500)
    pd.set_option("display.float_format", lambda x: f"{x:.4g}")
    w = lambda s="": print(s, file=fh)
    R = o["runs"]
    w(f"P15 E2 -- pre-registered analysis. Runs analysed: {len(R)} "
      f"({o['n_warmup_discarded']} warm-up runs discarded); flagged: {int(R.flagged.sum())} "
      f"(stall {int(R.flag_stall.sum())}, hot {int(R.flag_hot.sum())}).")
    if R.temp_tenths.notna().any():
        w(f"Battery temperature at run start: {R.temp_tenths.min() / 10:.1f}--{R.temp_tenths.max() / 10:.1f} C "
          f"(runs with a reading: {int(R.temp_tenths.notna().sum())}).")
    w("\n== Primary family (Holm over all rows; reject_H0 = hypothesis supported)")
    w(o["primary"].to_string(index=False))
    for k in [k for k in o if k.startswith("sens_")]:
        w(f"\n== Sensitivity: {o[k].analysis.iloc[0]}")
        w(o[k][["platform", "hypothesis", "estimate", "upper95", "p_holm", "status"]].to_string(index=False))
    w("\n== H2.3 (estimation): seed / expanded, 95 % CI")
    w(o["h23"].to_string(index=False))
    w("\n== Order effect (log run median ~ configuration + block + position)")
    w(o["order"].to_string(index=False))
    w("\n== Descriptives (run medians, ms)")
    w(o["desc"].to_string(index=False))
    w("\n== Relative equivalence (TOST, 90 % CI of the ratio; reported, not confirmatory)")
    w(o["tost"].to_string(index=False))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("dirs", nargs="+", help="PLATFORM=DIR")
    ap.add_argument("--temps", action="append", default=[], help="PLATFORM=FILE (host temperature log)")
    ap.add_argument("--out", help="directory for the report and CSV tables")
    ap.add_argument("--seed", type=int, default=20261121)
    a = ap.parse_args(argv)
    dirs = dict(x.split("=", 1) for x in a.dirs)
    bad = [p for p in dirs if p not in PLATFORMS]
    if bad:
        sys.exit(f"unknown platform(s) {bad}; use {PLATFORMS}")
    o = run(dirs, dict(x.split("=", 1) for x in a.temps), a.seed)
    report(o)
    if a.out:
        os.makedirs(a.out, exist_ok=True)
        with open(os.path.join(a.out, "report.txt"), "w") as fh:
            report(o, fh)
        for k, v in o.items():
            if isinstance(v, pd.DataFrame):
                v.to_csv(os.path.join(a.out, f"{k}.csv"), index=False)


if __name__ == "__main__":
    main()
