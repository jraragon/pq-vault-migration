"""
P15 -- analysis of a pilot of E2 (open account, A1, native desktop).

Purpose (pre-registration, Section 6): check the pipeline and estimate the
between-run variability needed to fix the number of repetitions per cell.
Pilot data are NOT used for confirmatory claims.

Usage: python analysis/pilot_analysis.py results/pilot_open_<stamp>
"""
import sys, glob, os, math
import numpy as np
import pandas as pd
from scipy import stats

d = sys.argv[1]
runs = []
for f in sorted(glob.glob(os.path.join(d, "r[0-9][0-9]p*.csv"))):
    df = pd.read_csv(f, comment="#")
    rid = df.run_id.iloc[0]
    rep = int(rid[1:3]); pos = int(rid.split("p")[1].split("_")[0])
    ns = df.ns.to_numpy(dtype=float)
    runs.append(dict(run_id=rid, rep=rep, pos=pos, suite=df.suite.iloc[0], fmt=df.format.iloc[0],
                     med_us=np.median(ns) / 1e3, p95_us=np.percentile(ns, 95) / 1e3,
                     p99_us=np.percentile(ns, 99) / 1e3,
                     first100_us=np.median(ns[:100]) / 1e3, last100_us=np.median(ns[-100:]) / 1e3))
R = pd.DataFrame(runs)
R["cfg"] = R.suite + ":" + R.fmt
print(f"{len(R)} runs, {R.rep.nunique()} blocks, {R.cfg.nunique()} configurations\n")

# ------------------------------------------------------------ per configuration
g = R.groupby("cfg")
summ = pd.DataFrame({
    "median_of_run_medians_us": g.med_us.median(),
    "min_us": g.med_us.min(), "max_us": g.med_us.max(),
    "cv_between_runs_%": 100 * g.med_us.std() / g.med_us.mean(),
    "median_p95_us": g.p95_us.median(), "median_p99_us": g.p99_us.median(),
    "drift_last_vs_first_%": 100 * (g.last100_us.median() / g.first100_us.median() - 1),
}).sort_values("median_of_run_medians_us")
pd.set_option("display.width", 160); pd.set_option("display.float_format", lambda x: f"{x:9.1f}")
print("E2 open account (A1, n_f = 7) -- per configuration")
print(summ, "\n")

# ------------------------------------------------------------ paired comparisons
W = R.pivot(index="rep", columns="cfg", values="med_us")
base = W["rsa3072:na"]

def paired(a, b, label):
    lr = np.log(W[a] / W[b])
    diff = (W[a] - W[b]) / 1e3   # ms
    return dict(comparison=label, ratio_geo=math.exp(lr.mean()), sd_logratio=lr.std(ddof=1),
                diff_ms_mean=diff.mean(), sd_diff_ms=diff.std(ddof=1), n=len(lr))

cmp = pd.DataFrame([
    paired("mlkem1024:seed", "rsa3072:na", "H2.1  ML-KEM-1024 (seed) / RSA-3072"),
    paired("mlkem1024:expanded", "rsa3072:na", "      ML-KEM-1024 (expanded) / RSA-3072"),
    paired("mlkem768:seed", "rsa3072:na", "      ML-KEM-768 (seed) / RSA-3072"),
    paired("hybrid:seed", "rsa3072:na", "H2.2  hybrid (seed) - RSA-3072"),
    paired("hybrid:expanded", "rsa3072:na", "      hybrid (expanded) - RSA-3072"),
    paired("mlkem1024:seed", "mlkem1024:expanded", "      ML-KEM-1024 seed / expanded"),
])
pd.set_option("display.float_format", lambda x: f"{x:10.4f}")
print("Paired by block (run medians)")
print(cmp.to_string(index=False), "\n")

# ------------------------------------------------------------ repetitions needed
# Primary family: 2 hypotheses x 5 platforms = 10 tests; worst-case Holm alpha = 0.05/10.
alpha = 0.05 / 10; power = 0.8
za, zb = stats.norm.ppf(1 - alpha), stats.norm.ppf(power)
def n_noninf(sd, mean_diff, delta):
    margin = delta - mean_diff
    return math.inf if margin <= 0 else math.ceil(((za + zb) * sd / margin) ** 2)
h22 = cmp.iloc[3]
print("Repetitions needed (normal approximation, then t-correction by iteration)")
for delta in (16.0, 5.0):
    n = n_noninf(h22.sd_diff_ms, h22.diff_ms_mean, delta)
    # refine with t quantiles
    for _ in range(5):
        if not math.isfinite(n): break
        df_ = max(n - 1, 2)
        n = math.ceil(((stats.t.ppf(1 - alpha, df_) + stats.t.ppf(power, df_)) * h22.sd_diff_ms /
                       (delta - h22.diff_ms_mean)) ** 2)
    print(f"  H2.2 non-inferiority, delta = {delta:4.0f} ms: n = {n} (pre-registered minimum 10)")
h21 = cmp.iloc[0]
eff = abs(math.log(h21.ratio_geo)) / h21.sd_logratio
print(f"  H2.1 standardised effect |mean log ratio| / sd = {eff:.1f}: n = 10 (minimum) is far above what is needed\n")

# ------------------------------------------------------------ order effect
import statsmodels.formula.api as smf
R["logmed"] = np.log(R.med_us)
m = smf.ols("logmed ~ C(cfg) + C(rep) + pos", data=R).fit()
print(f"Order effect: position-in-block coefficient = {100*m.params['pos']:.2f} % per position "
      f"(p = {m.pvalues['pos']:.3f})")
