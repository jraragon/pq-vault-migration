"""
P15 -- simulated result directories in the exact format written by the three
clients, for testing the analysis scripts before any real measurement
(pre-registration, Section "Pre-experimental design freeze").

simulate(dirpath, medians_ms, reps=10, ...) writes one directory: block 00
(warm-up) plus `reps` blocks, each configuration once per block in shuffled
order, `iters` lognormal operation times per run around the given median,
with a block effect and run-level noise.
"""
import os
import numpy as np

CONFIGS = ["rsa3072:na", "mlkem768:seed", "mlkem768:expanded", "mlkem1024:seed",
           "mlkem1024:expanded", "hybrid:seed", "hybrid:expanded"]


def simulate(d, medians_ms, reps=10, iters=1000, run_cv=0.01, block_cv=0.01, op_cv=0.05,
             warmup_factor=3.0, temps_tenths=None, seed=0, header="", op="open"):
    rng = np.random.default_rng(seed)
    os.makedirs(d, exist_ok=True)
    temps = []
    for rep in range(0, reps + 1):
        block = rng.lognormal(0, block_cv)
        order = list(CONFIGS)
        rng.shuffle(order)
        for pos, cfg in enumerate(order, 1):
            suite, fmt = cfg.split(":")
            rid = f"r{rep:02d}p{pos}_{suite}_{fmt}"
            m = medians_ms[cfg] * block * rng.lognormal(0, run_cv) * (warmup_factor if rep == 0 else 1.0)
            ns = np.round(m * 1e6 * rng.lognormal(0, op_cv, iters)).astype(np.int64)
            with open(os.path.join(d, rid + ".csv"), "w") as fh:
                fh.write(f"# simulated {header}\n# suite={suite} format={fmt} op={op} iters={iters}\n")
                fh.write("run_id,suite,format,op,iter,ns\n")
                fh.writelines(f"{rid},{suite},{fmt},{op},{k},{v}\n" for k, v in enumerate(ns))
            if temps_tenths is not None:
                t = temps_tenths(rid) if callable(temps_tenths) else temps_tenths
                temps.append(f"{rid},{t},{int(t > 400)}\n")
    if temps:
        with open(os.path.join(d, "temperatures.csv"), "w") as fh:
            fh.write("run_id,battery_temp_tenths_c,flag_hot\n")
            fh.writelines(temps)
    return d
