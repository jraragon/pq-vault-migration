#!/usr/bin/env python3
"""P15 -- exploratory validation of the migration cost model, native platform (D-026).

Compares the end-to-end migration times measured by native/scripts/run_validation.sh
with the times the cost model predicts from the native E3 unit costs of the main
campaign, and the measured suite-dependent bytes with the analytic byte model.

  predicted = K_ops * K_s + E_ops * E_s + W_ops * W
  K_s, E_s, W: median over the measured blocks (warm-up block discarded) of the run
  medians of the native E3 sessions (keygen and encap in seed form; rewrap pooled
  over configurations, as in population_analysis.py). K_ops, E_ops, W_ops are the
  structural counts of the account's tree reported by each run (the model's formula
  with the tree's actual n_files and c).

Reported per architecture and suite: ratio measured/predicted (median, min, max) and
the byte deviation. The model is described as adequate if the median ratio lies in
[0.8, 1.25]. A3 has no public-key operation: its predicted time is 0 and its measured
time is reported in absolute terms. Exploratory; no verdict on H3.1 or H4.1 changes.

Usage:
  python analysis/validation_analysis.py VALIDATION_DIR ENCAP_DIR KEYGEN_DIR REWRAP_DIR [--out DIR]
"""
import argparse, os, sys
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from population_analysis import load_unit_costs   # noqa: E402

# Suite-dependent object sizes in bytes (analytic byte model, p15_modelo_bytes.py, Table 1).
RSA_SK = 1767
SIZES = {"mlkem1024": dict(pk=1568, sk=64, ct=1568),
         "hybrid":    dict(pk=1966, sk=64 + RSA_SK, ct=1952)}
LO, HI = 0.8, 1.25


def unit_costs_ms(encap_dir, keygen_dir, rewrap_dir):
    costs, _ = load_unit_costs({"native": [encap_dir, keygen_dir, rewrap_dir]})
    return {k[1]: float(np.median(v)) for k, v in costs.items()}


def analytic_bytes(row):
    z = SIZES[row.suite]
    if row.arch == "A1":
        return row.n_h * z["ct"]
    if row.arch == "A1b":
        return row.n_f * row.n_h * z["ct"]
    if row.arch == "A2":
        return row.n_total * (z["pk"] + z["sk"] + z["ct"]) + row.n_files * z["ct"] + row.n_h * z["ct"]
    return 0


COLS = ["run_id", "account", "arch", "suite", "n_total", "n_f", "n_h", "n_files", "c",
        "K_ops", "E_ops", "W_ops", "bytes", "ns"]


def load_runs(path):
    """Reads runs.csv as written by p15_arch. On Windows the header line is repeated
    before every run (ftell is 0 on a file opened for append), and the last field (pin)
    contains commas; both are handled here: header lines are skipped and the pin
    description is kept whole."""
    rows = []
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.rstrip("\r\n")
        if not line or line.startswith("run_id,"):
            continue
        f = line.split(",")
        rows.append(f[:14] + [",".join(f[14:]).strip()])
    R = pd.DataFrame(rows, columns=COLS + ["pin"])
    for c in COLS[4:]:
        R[c] = pd.to_numeric(R[c])
    R["account"] = pd.to_numeric(R["account"])
    return R


def analyse(runs, u):
    R = runs.copy()
    R["measured_ms"] = R.ns / 1e6
    R["predicted_ms"] = [r.K_ops * u.get(f"K:{r.suite}", np.nan) + r.E_ops * u.get(f"E:{r.suite}", np.nan)
                         + r.W_ops * u["W"] for r in R.itertuples()]
    R["ratio"] = np.where(R.predicted_ms > 0, R.measured_ms / R.predicted_ms.where(R.predicted_ms > 0), np.nan)
    R["bytes_model"] = [analytic_bytes(r) for r in R.itertuples()]
    R["bytes_dev_pct"] = np.where(R.bytes_model > 0, 100 * (R.bytes - R.bytes_model) / R.bytes_model.where(R.bytes_model > 0), np.nan)
    rows = []
    for (arch, suite), g in R.groupby(["arch", "suite"], sort=True):
        r = g.ratio.dropna()
        med = float(r.median()) if len(r) else np.nan
        rows.append(dict(arch=arch, suite=suite, n=len(g),
                         ratio_median=med, ratio_min=float(r.min()) if len(r) else np.nan,
                         ratio_max=float(r.max()) if len(r) else np.nan,
                         adequate=("n/a" if np.isnan(med) else ("yes" if LO <= med <= HI else "no")),
                         measured_ms_median=float(g.measured_ms.median()),
                         bytes_dev_pct_median=float(g.bytes_dev_pct.median()) if g.bytes_dev_pct.notna().any() else np.nan,
                         bytes_dev_pct_max=float(g.bytes_dev_pct.abs().max()) if g.bytes_dev_pct.notna().any() else np.nan))
    return R, pd.DataFrame(rows)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("validation_dir"); ap.add_argument("encap_dir"); ap.add_argument("keygen_dir"); ap.add_argument("rewrap_dir")
    ap.add_argument("--out")
    a = ap.parse_args(argv)
    runs = load_runs(os.path.join(a.validation_dir, "runs.csv"))
    u = unit_costs_ms(a.encap_dir, a.keygen_dir, a.rewrap_dir)
    R, S = analyse(runs, u)
    pd.set_option("display.width", 220); pd.set_option("display.max_columns", 30)
    pd.set_option("display.float_format", lambda x: f"{x:.4g}")
    text = "\n".join([
        "== Native unit costs (ms; median over blocks of run medians)",
        "  " + ", ".join(f"{k}={v:.5g}" for k, v in sorted(u.items())),
        f"\n== Measured / predicted migration time per architecture and suite (adequate if median in [{LO}, {HI}])",
        S.to_string(index=False)])
    print(text)
    if a.out:
        os.makedirs(a.out, exist_ok=True)
        open(os.path.join(a.out, "validation_report.txt"), "w").write(text + "\n")
        R.to_csv(os.path.join(a.out, "validation_runs.csv"), index=False)


if __name__ == "__main__":
    main()
