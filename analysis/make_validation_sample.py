#!/usr/bin/env python3
"""P15 -- sample and run plan of the exploratory validation of the cost model (D-026).

Pre-registration (Section "Exploratory validation of the cost model"): 30 accounts from
the archived population with default_rng(15), three from each decile of n_total among
the accounts with n_total <= 1000. Each account is migrated under every architecture
(A1, A1b, A2, A3) and target suite (ML-KEM-1024 and the hybrid, seed form), one run per
combination, in randomised order.

Deciles are formed by rank: the eligible accounts are sorted by (n_total, account id)
and split into ten groups of (almost) equal size, so ties at a decile edge are resolved
deterministically. The same generator then draws the run order.

Writes data/validation_sample.csv and data/validation_plan.csv. Uses no measured data.
"""
import os
import numpy as np

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POP = os.path.join(HERE, "data", "population_jcp_seed42.csv")
ARCHS = ("A1", "A1b", "A2", "A3")
SUITES = ("mlkem1024", "hybrid")


def make(pop_path=POP, seed=15, cap=1000, per_decile=3):
    pop = np.loadtxt(pop_path, delimiter=",", skiprows=1, dtype=np.int64)
    acc, n_total, n_f, n_h = pop[:, 0], pop[:, 1], pop[:, 2], pop[:, 3]
    rng = np.random.default_rng(seed)
    elig = np.flatnonzero(n_total <= cap)
    order = elig[np.lexsort((acc[elig], n_total[elig]))]
    sample = []
    for d, grp in enumerate(np.array_split(order, 10)):
        for i in sorted(rng.choice(grp, size=per_decile, replace=False)):
            sample.append((int(acc[i]), d + 1, int(n_total[i]), int(n_f[i]), int(n_h[i])))
    runs = [(a[0], arch, s) for a in sample for arch in ARCHS for s in SUITES]
    perm = rng.permutation(len(runs))
    plan = [runs[k] for k in perm]
    return sample, plan


if __name__ == "__main__":
    sample, plan = make()
    with open(os.path.join(HERE, "data", "validation_sample.csv"), "w") as f:
        f.write("account,decile,n_total,n_f,n_h\n")
        for r in sample:
            f.write(",".join(map(str, r)) + "\n")
    info = {a[0]: a for a in sample}
    with open(os.path.join(HERE, "data", "validation_plan.csv"), "w") as f:
        f.write("order,account,arch,suite,n_total,n_f,n_h\n")
        for k, (a, arch, s) in enumerate(plan, 1):
            _, _, n, nf, nh = info[a]
            f.write(f"{k},{a},{arch},{s},{n},{nf},{nh}\n")
    nt = [r[2] for r in sample]
    print(f"{len(sample)} accounts, {len(plan)} runs; n_total min {min(nt)}, median {int(np.median(nt))}, "
          f"max {max(nt)}, sum {sum(nt)}")
