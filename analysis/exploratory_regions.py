"""
P15 -- planned exploratory analyses (pre-registration v0.9, D-028). Not confirmatory.

X1  Efficiency regions (population-free). With q = E_s / W per platform and suite, the
    A1 speed-up of agile over naive migration of an account is
        S = (n_total + n_h q) / (n_f + n_h q),
    so S >= k  <=>  n_total >= k n_f + (k - 1) n_h q.
    Reported: q with its 90 % bootstrap interval and, for k in {2, 5, 10}, the minimum
    n_total for (n_f, n_h) in {(7,1), (7,2), (7,5), (40,2)}.
X2  Alternative populations (stress scenarios, fixed seeds; N = 20 000 each):
      collab  : as JCP but n_h = 1 + Poisson(5)                       (seed 101)
      archive : n_total = clip(round(LogNormal(ln 2000, 1.0)), 1, 3e5),
                n_f = min(1 + Poisson(12), n_total), n_h = 1          (seed 102)
      flat    : as JCP but n_f = min(1 + Poisson(40), n_total)        (seed 103)
    The H3.1 and H4.1 statistics are recomputed on each (point estimates and 90 % intervals).
X3  Access latency by depth d = 1..10 (steady state, not migration):
      A1(d) = L_s + D_s + d U       A2(d) = L_s + d (D_s + L_s)
    L_s: credential load (seed expansion if any), D_s: decapsulation, U = W / 2 (one unwrap).

Usage: python analysis/exploratory_regions.py PLATFORM=DIR [...]   (E3 sessions incl. load, decap)
"""
import os, sys
from collections import defaultdict
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import population_analysis as pa


def population(name, N=20_000):
    if name == "jcp":
        return pa.load_population()
    seed = {"collab": 101, "archive": 102, "flat": 103}[name]
    rng = np.random.default_rng(seed)
    if name == "archive":
        nt = np.clip(np.round(rng.lognormal(np.log(2000), 1.0, N)), 1, 300_000)
        nf = np.minimum(rng.poisson(12, N) + 1, nt)
        nh = np.ones(N)
    else:
        nt = np.clip(np.round(rng.lognormal(np.log(150), 1.35, N)), 1, 300_000)
        nf = np.minimum(rng.poisson(40 if name == "flat" else 6, N) + 1, nt)
        nh = rng.poisson(5 if name == "collab" else 1.2, N) + 1
    return nt.astype(float), nf.astype(float), nh.astype(float)


def extra_costs(dirs):
    """Unit costs for X3: load (L) and decap (D) per suite, seed form."""
    costs, R = pa.load_unit_costs(dirs)
    for (pl, s), g in R[R.op.isin(["load", "decap"])].groupby(["platform", "suite"]):
        fmt = "na" if s == "rsa3072" else "seed"
        for op, key in (("load", "L"), ("decap", "D")):
            v = g[(g.op == op) & (g.fmt == fmt)].sort_values("rep").med_ms.to_numpy()
            if len(v):
                costs[(pl, f"{key}:{s}")] = v
    return costs


def x1(costs, rng):
    rows = []
    for (pl, key), E in costs.items():
        if not key.startswith("E:") or (pl, "W") not in costs:
            continue
        s, W = key[2:], costs[(pl, "W")]
        qb = pa.boot_means(E, rng) / pa.boot_means(W, rng)
        q = E.mean() / W.mean()
        row = dict(platform=pl, suite=s, q=q, q_lo90=np.quantile(qb, 0.05), q_hi90=np.quantile(qb, 0.95))
        for k in (2, 5, 10):
            for nf, nh in ((7, 1), (7, 2), (7, 5), (40, 2)):
                row[f"S>={k} n_f={nf} n_h={nh}"] = int(np.ceil(k * nf + (k - 1) * nh * q))
        rows.append(row)
    return pd.DataFrame(rows)


def x3(costs):
    rows = []
    for (pl, key), D in costs.items():
        if not key.startswith("D:") or (pl, f"L:{key[2:]}") not in costs or (pl, "W") not in costs:
            continue
        s = key[2:]
        L, Dm, U = costs[(pl, f"L:{s}")].mean(), D.mean(), costs[(pl, "W")].mean() / 2
        for d in range(1, 11):
            rows.append(dict(platform=pl, suite=s, depth=d, A1_ms=L + Dm + d * U, A2_ms=L + d * (Dm + L),
                             A2_over_A1=(L + d * (Dm + L)) / (L + Dm + d * U)))
    return pd.DataFrame(rows)


def main(argv=None):
    dirs = defaultdict(list)
    for x in (argv or sys.argv[1:]):
        p, d = x.split("=", 1)
        dirs[p].append(d)
    costs = extra_costs(dirs)
    rng = np.random.default_rng(20261121)
    pd.set_option("display.width", 250); pd.set_option("display.max_columns", 40)
    pd.set_option("display.float_format", lambda x: f"{x:.4g}")
    print("== X1 efficiency regions (minimum n_total for an A1 speed-up >= k)")
    print(x1(costs, rng).to_string(index=False))
    for name in ("collab", "archive", "flat"):
        h31, h41 = pa.analyse(costs, pop=population(name))
        print(f"\n== X2 population '{name}': H4.1 statistic"); print(h41.to_string(index=False))
        print(f"== X2 population '{name}': H3.1 statistics"); print(h31.to_string(index=False))
    print("\n== X3 access latency by depth (ms)")
    print(x3(costs).to_string(index=False))


if __name__ == "__main__":
    main()
