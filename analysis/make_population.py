"""
P15 -- regenerate and archive the JCP synthetic account population.

Follows the published model (Rodriguez-Aragon, Zato, Rodriguez-Gonzalez, J. Cybersecur.
Priv. 2026, 6, 197, Section 7.4, Eqs. 51-53): NumPy default_rng(seed=42), N = 20 000;
  n_total = clip(round(lognormal(ln 150, 1.35)), 1, 300 000)
  n_f     = min(1 + Poisson(6), n_total)
  n_h     = 1 + Poisson(1.2)
and checks the published figures: global cost 7 557 945, incremental cost
sum(1 + n_f + n_h) = 203 149, aggregate ratio 37.2x, median per-account ratio 15.3x,
5th/95th percentiles 1.5x / 150.1x.

The population is archived (data/population_jcp_seed42.csv) so that later analyses do
not depend on the NumPy version used to draw it.
"""
import hashlib, os, sys
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(os.path.dirname(HERE), "data", "population_jcp_seed42.csv")


def generate():
    rng = np.random.default_rng(seed=42)
    N = 20_000
    n_total = np.clip(np.round(rng.lognormal(mean=np.log(150), sigma=1.35, size=N)), 1, 300_000).astype(np.int64)
    n_f = np.minimum(rng.poisson(lam=6, size=N) + 1, n_total)
    n_h = rng.poisson(lam=1.2, size=N) + 1
    return n_total, n_f, n_h


def check(n_total, n_f, n_h):
    inc = 1 + n_f + n_h
    r = n_total / inc
    got = dict(global_cost=int(n_total.sum()), incremental_cost=int(inc.sum()),
               aggregate_ratio=round(float(n_total.sum() / inc.sum()), 1),
               median_ratio=round(float(np.median(r)), 1),
               p5_ratio=round(float(np.percentile(r, 5)), 1), p95_ratio=round(float(np.percentile(r, 95)), 1))
    want = dict(global_cost=7_557_945, incremental_cost=203_149, aggregate_ratio=37.2, median_ratio=15.3,
                p5_ratio=1.5, p95_ratio=150.1)
    assert got == want, (got, want)
    return got


if __name__ == "__main__":
    n_total, n_f, n_h = generate()
    print("Published JCP figures reproduced:", check(n_total, n_f, n_h))
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", newline="\n") as fh:
        fh.write("account,n_total,n_f,n_h\n")
        fh.writelines(f"{i},{a},{b},{c}\n" for i, (a, b, c) in enumerate(zip(n_total, n_f, n_h)))
    h = hashlib.sha256(open(OUT, "rb").read()).hexdigest()
    print(f"Written {OUT} (NumPy {np.__version__}), SHA-256 {h}")
