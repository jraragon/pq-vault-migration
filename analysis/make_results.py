"""
P15 -- figures and LaTeX tables of the main campaign, built on the registered analysis scripts.

This script does not add or change any analysis: it calls primary_analysis.run (E2, H2.x),
population_analysis.load_unit_costs / analyse (E3, H3.1, H4.1) and exploratory_regions
(X1, X3), and formats what they return. Every number in a table is taken from those
functions; nothing is recomputed here except per-account migration times for the figure,
which use the same cost model and the point estimates of the unit costs.

Usage:
  python analysis/make_results.py CAMPAIGN.json --out DIR
CAMPAIGN.json maps each platform to its session directories (paths relative to the repo):
  {"native": {"open": "results/main_native_open_...", "encap": "...", "keygen": "...",
              "decap": "...", "load": "...", "rewrap": "..."},
   "chrome_android": {..., "temps": "results/temp_chrome_android_main.csv"}, ...}
Platforms with missing sessions are skipped where a session is needed.
Outputs (in DIR): tab_e2.tex, tab_e3.tex, tab_h31_h41.tex, tab_x1.tex, fig_e2.pdf,
fig_population.pdf, fig_x3.pdf, and the raw analysis tables as CSV.
"""
import argparse, json, os, sys
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import primary_analysis as pa2
import population_analysis as pop
import exploratory_regions as xr

PLATFORMS = pop.PLATFORMS
PNAME = {"native": "Native (OpenSSL)", "android": "Android app (BC)", "chrome_desktop": "Chrome desktop",
         "firefox_desktop": "Firefox desktop", "chrome_android": "Chrome Android"}
PSHORT = {"native": "Native", "android": "Android app", "chrome_desktop": "Chrome desk.",
          "firefox_desktop": "Firefox desk.", "chrome_android": "Chrome Andr."}
SNAME = {"rsa3072": "RSA-3072", "mlkem768": "ML-KEM-768", "mlkem1024": "ML-KEM-1024", "hybrid": "Hybrid"}
CFG_ORDER = ["rsa3072:na", "mlkem768:seed", "mlkem768:expanded", "mlkem1024:seed",
             "mlkem1024:expanded", "hybrid:seed", "hybrid:expanded"]
CFG_LABEL = {"rsa3072:na": "RSA-3072", "mlkem768:seed": "ML-KEM-768 seed",
             "mlkem768:expanded": "ML-KEM-768 exp.", "mlkem1024:seed": "ML-KEM-1024 seed",
             "mlkem1024:expanded": "ML-KEM-1024 exp.", "hybrid:seed": "Hybrid seed",
             "hybrid:expanded": "Hybrid exp."}
# Categorical slots 1-4 of the reference palette (light), fixed order, never cycled.
ARCH_COLOR = {"A1": "#2a78d6", "A1b": "#eb6834", "A2": "#1baf7a", "naive A1": "#52514e"}
ARCH_STYLE = {"A1": "-", "A1b": "--", "A2": "-.", "naive A1": ":"}
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e4e3df"
COL_W, PAGE_W = 3.5, 7.16          # elsarticle 5p: column and text width (in)

plt.rcParams.update({"font.family": "serif", "font.size": 8, "axes.labelsize": 8,
                     "axes.titlesize": 8, "xtick.labelsize": 7, "ytick.labelsize": 7,
                     "legend.fontsize": 7, "axes.edgecolor": INK2, "axes.labelcolor": INK,
                     "xtick.color": INK2, "ytick.color": INK2, "axes.spines.top": False,
                     "axes.spines.right": False, "axes.grid": True, "grid.color": GRID,
                     "grid.linewidth": 0.5, "pdf.fonttype": 42})


def _fmt(x, digits=3):
    """Significant-figure formatting for table cells (thin space as thousands separator)."""
    if x is None or (isinstance(x, float) and np.isnan(x)):
        return "--"
    if x == 0:
        return "0"
    v = float(f"{x:.{digits}g}")
    mag = int(np.floor(np.log10(abs(v))))
    d = max(0, digits - 1 - mag)
    return f"{v:,.{d}f}".replace(",", "\\,")


def _p(p):
    return "$<$0.001" if p < 0.001 else f"{p:.3f}"


def _logx(ax, numticks=6):
    """Log x-axis with decade ticks labelled as plain numbers and no minor labels."""
    from matplotlib.ticker import LogLocator, FuncFormatter, NullFormatter
    ax.set_xscale("log")
    ax.xaxis.set_major_locator(LogLocator(base=10, numticks=numticks))
    ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:g}" if v < 1e4 else f"$10^{{{int(np.log10(v))}}}$"))
    ax.xaxis.set_minor_formatter(NullFormatter())


def _status(s):
    return {"supported": "S", "refuted": "R", "inconclusive": "I"}.get(s, s)


def load_campaign(path):
    C = json.load(open(path))
    resolve = lambda p: p if os.path.isabs(p) else os.path.join(REPO, p)
    out = {}
    for pl, ops in C.items():
        if pl not in PLATFORMS:
            sys.exit(f"unknown platform {pl}")
        out[pl] = {op: resolve(d) for op, d in ops.items() if d}
    return out


# ------------------------------------------------------------------ E2
def e2(camp, outdir):
    dirs = {pl: c["open"] for pl, c in camp.items() if "open" in c and os.path.isdir(c["open"])}
    temps = {pl: c["temps"] for pl, c in camp.items() if "temps" in c and pl in dirs}
    o = pa2.run(dirs, temps)
    with open(os.path.join(outdir, "e2_report.txt"), "w") as fh:
        pa2.report(o, fh)
    for k, v in o.items():
        if isinstance(v, pd.DataFrame):
            v.to_csv(os.path.join(outdir, f"e2_{k}.csv"), index=False)
    R, P, D = o["runs"], o["primary"], o["desc"]
    plats = [p for p in PLATFORMS if p in dirs]

    # Table: medians and the primary verdicts
    lines = [r"\begin{table*}[t]", r"\centering\small",
             r"\caption{E2: time to open an A1 account (median over runs of the run medians, ms) and the "
             r"pre-registered tests. H2.1: ratio ML-KEM-1024 (seed) / RSA-3072, one-sided upper 95\,\% bound; "
             r"H2.2: difference hybrid (seed) $-$ RSA-3072, upper 95\,\% bound against $\delta = 16$\,ms. "
             r"Holm-adjusted $p$ over the ten tests. S: supported, R: refuted, I: inconclusive.}\label{tab:e2}",
             r"\begin{tabular}{@{}lrrrrlrlr@{}}", r"\toprule",
             r"Platform & RSA-3072 & ML-KEM-1024 & Hybrid & \multicolumn{2}{c}{H2.1 ratio (bound)} & "
             r"\multicolumn{2}{c}{H2.2 diff.\ ms (bound)} & $p_{\mathrm{Holm}}$ (H2.1, H2.2)\\", r"\midrule"]
    med = D.set_index(["platform", "cfg"]).median_ms
    for pl in plats:
        h1 = P[(P.platform == pl) & (P.hypothesis == "H2.1")].iloc[0]
        h2 = P[(P.platform == pl) & P.hypothesis.str.startswith("H2.2")].iloc[0]
        lines.append(f"{PNAME[pl]} & {_fmt(med[(pl, 'rsa3072:na')])} & {_fmt(med[(pl, 'mlkem1024:seed')])} & "
                     f"{_fmt(med[(pl, 'hybrid:seed')])} & {h1.estimate.split()[1]} ({h1.upper95}) & "
                     f"{_status(h1.status)} & {h2.estimate.split()[1]} ({h2.upper95.split()[0]}) & "
                     f"{_status(h2.status)} & {_p(h1.p_holm)}, {_p(h2.p_holm)}\\\\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table*}"]
    open(os.path.join(outdir, "tab_e2.tex"), "w").write("\n".join(lines) + "\n")

    # Figure: run medians per configuration, one panel per platform (log x)
    n = len(plats)
    fig, axes = plt.subplots(1, n, figsize=(PAGE_W, 1.9), sharey=True, sharex=True)
    axes = np.atleast_1d(axes)
    ys = {c: i for i, c in enumerate(reversed(CFG_ORDER))}
    for ax, pl in zip(axes, plats):
        S = R[R.platform == pl]
        for c in CFG_ORDER:
            v = S[S.cfg == c].med_ms.to_numpy()
            if not len(v):
                continue
            y = ys[c] + np.linspace(-0.18, 0.18, len(v))
            ax.scatter(v, y, s=9, color=ARCH_COLOR["A1"], alpha=0.55, linewidths=0, zorder=3)
            ax.plot([np.median(v)] * 2, [ys[c] - 0.32, ys[c] + 0.32], color=INK, lw=1.2, zorder=4)
        _logx(ax)
        ax.set_title(PSHORT[pl], color=INK)
        ax.grid(axis="y", visible=False)
        ax.set_xlabel("ms")
    axes[0].set_yticks(list(ys.values()), [CFG_LABEL[c] for c in ys])
    fig.tight_layout(pad=0.3, w_pad=0.6)
    fig.savefig(os.path.join(outdir, "fig_e2.pdf"), bbox_inches="tight", pad_inches=0.02)
    plt.close(fig)
    return o


# ------------------------------------------------------------------ E3, H3.1, H4.1
def e3(camp, outdir):
    dirs = {pl: [c[op] for op in ("encap", "keygen", "rewrap", "decap", "load") if op in c and os.path.isdir(c[op])]
            for pl, c in camp.items()}
    dirs = {pl: d for pl, d in dirs.items() if d}
    costs = xr.extra_costs(dirs)                 # E, K, W (population_analysis) plus L, D
    plats = [p for p in PLATFORMS if p in dirs]

    # Table of unit costs: rows operation x suite, columns platforms
    lines = [r"\begin{table*}[t]", r"\centering\small",
             r"\caption{E3: unit costs per platform (ms; mean over the ten blocks of the run medians). "
             r"Seed form for ML-KEM and the hybrid. $W$, one AES-256-KW re-wrap, does not depend on the suite.}"
             r"\label{tab:e3}",
             r"\begin{tabular}{@{}ll" + "r" * len(plats) + r"@{}}", r"\toprule",
             "Operation & Suite & " + " & ".join(PSHORT[p] for p in plats) + r"\\", r"\midrule"]
    for key, opname in (("K", "Key generation $K_s$"), ("E", "Encapsulation $E_s$"),
                        ("D", "Decapsulation $D_s$"), ("L", "Credential load $L_s$")):
        for i, s in enumerate(pop.SUITES):
            cells = [_fmt(costs[(p, f"{key}:{s}")].mean()) if (p, f"{key}:{s}") in costs else "--" for p in plats]
            lines.append(f"{opname if i == 0 else ''} & {SNAME[s]} & " + " & ".join(cells) + r"\\")
        lines.append(r"\addlinespace")
    lines.append(r"Re-wrap $W$ & any & " + " & ".join(
        _fmt(costs[(p, 'W')].mean()) if (p, "W") in costs else "--" for p in plats) + r"\\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table*}"]
    open(os.path.join(outdir, "tab_e3.tex"), "w").write("\n".join(lines) + "\n")

    # H3.1 and H4.1 (registered analysis, primary phi)
    h31, h41 = pop.analyse(costs, pop.PHI)
    h31.to_csv(os.path.join(outdir, "h31.csv"), index=False)
    h41.to_csv(os.path.join(outdir, "h41.csv"), index=False)
    sens = []
    for phi in pop.PHI_SENS:
        s31, _ = pop.analyse(costs, phi, with_h41=False)
        sens.append(s31)
    pd.concat(sens).to_csv(os.path.join(outdir, "h31_phi_sensitivity.csv"), index=False)
    k31, k41 = pop.analyse(costs, pop.PHI, holder_keygen=True)
    k31.to_csv(os.path.join(outdir, "h31_holder_keygen.csv"), index=False)
    k41.to_csv(os.path.join(outdir, "h41_holder_keygen.csv"), index=False)

    iv = lambda r, n: f"{_fmt(r[n + ' median'])} [{_fmt(r[n + ' lo90'])}, {_fmt(r[n + ' hi90'])}]"
    lines = [r"\begin{table*}[t]", r"\centering\small",
             r"\caption{H3.1 and H4.1 on the JCP population ($N = 20\,000$, $\varphi = 0.8$): medians over accounts "
             r"of per-account cost ratios, with 90\,\% block-bootstrap intervals. A1b/A1 uses the lower bound of A1b "
             r"and A2/A1b its upper bound. H4.1: speed-up of agile (A1) over naive migration; threshold 10. "
             r"S: supported, R: refuted, I: inconclusive.}\label{tab:h31}",
             r"\begin{tabular}{@{}llllllll@{}}", r"\toprule",
             r"Platform & Suite & A1b/A1 & A2/A1b & A2/A1 & H3.1 & H4.1 speed-up & H4.1\\", r"\midrule"]
    for pl in plats:
        for s in pop.PQ:
            a = h31[(h31.platform == pl) & (h31.suite == s)]
            b = h41[(h41.platform == pl) & (h41.suite == s)]
            if a.empty or b.empty:
                continue
            a, b = a.iloc[0], b.iloc[0]
            lines.append(f"{PSHORT[pl] if s == pop.PQ[0] else ''} & {SNAME[s]} & {iv(a, 'A1b/A1')} & "
                         f"{iv(a, 'A2/A1b')} & {iv(a, 'A2/A1')} & {_status(a.status)} & "
                         f"{_fmt(b.median_speedup)} [{_fmt(b.lo90)}, {_fmt(b.hi90)}] & {_status(b.status)}\\\\")
        lines.append(r"\addlinespace")
    lines[-1] = r"\bottomrule"
    lines += [r"\end{tabular}", r"\end{table*}"]
    open(os.path.join(outdir, "tab_h31_h41.tex"), "w").write("\n".join(lines) + "\n")

    # Figure: distribution over accounts of the migration time per architecture (ML-KEM-1024),
    # point estimates of the unit costs, one panel per platform.
    nt, nf, nh = pop.load_population()
    nfiles = np.round(pop.PHI * nt)
    s = "mlkem1024"
    fig, axes = plt.subplots(1, len(plats), figsize=(PAGE_W, 1.95), sharey=True, sharex=True)
    axes = np.atleast_1d(axes)
    for ax, pl in zip(axes, plats):
        if (pl, f"K:{s}") not in costs or (pl, "W") not in costs:
            ax.set_visible(False)
            continue
        E, K, W = costs[(pl, f"E:{s}")].mean(), costs[(pl, f"K:{s}")].mean(), costs[(pl, "W")].mean()
        curves = {"A1": nh * E + nf * W, "A1b": nf * nh * E, "A2": nt * K + (nt + nfiles + nh) * E,
                  "naive A1": nt * W + nh * E}
        for name, v in curves.items():
            x = np.sort(v)
            ax.plot(x, np.arange(1, len(x) + 1) / len(x), color=ARCH_COLOR[name], ls=ARCH_STYLE[name],
                    lw=1.4, label=name)
        _logx(ax, numticks=5)
        ax.set_title(PSHORT[pl], color=INK)
        ax.set_xlabel("ms per account")
    axes[0].set_ylabel("cum. share")
    h, l = axes[0].get_legend_handles_labels()
    fig.legend(h, l, loc="upper center", ncol=4, frameon=False, handlelength=2.6, bbox_to_anchor=(0.5, 1.0))
    fig.tight_layout(pad=0.3, w_pad=0.6, rect=(0, 0, 1, 0.86))
    fig.savefig(os.path.join(outdir, "fig_population.pdf"), bbox_inches="tight", pad_inches=0.02)
    plt.close(fig)
    return costs, h31, h41


# ------------------------------------------------------------------ X1, X3
def explor(costs, outdir):
    rng = np.random.default_rng(20261121)
    X1 = xr.x1(costs, rng)
    X1.to_csv(os.path.join(outdir, "x1.csv"), index=False)
    X3 = xr.x3(costs)
    X3.to_csv(os.path.join(outdir, "x3.csv"), index=False)
    for name in ("collab", "archive", "flat"):
        h31, h41 = pop.analyse(costs, pop=xr.population(name))
        h31.to_csv(os.path.join(outdir, f"x2_{name}_h31.csv"), index=False)
        h41.to_csv(os.path.join(outdir, f"x2_{name}_h41.csv"), index=False)

    plats = [p for p in PLATFORMS if p in set(X1.platform)]
    col = "S>=10 n_f=7 n_h=2"
    lines = [r"\begin{table}[t]", r"\centering\small",
             r"\caption{X1 (exploratory): $q = E_s/W$ and the smallest hierarchy ($n_{\mathrm{total}}$) for which "
             r"agile migration in A1 is at least ten times faster than naive, with $n_f = 7$ and $n_h = 2$.}"
             r"\label{tab:x1}",
             r"\begin{tabular}{@{}lrrrr@{}}", r"\toprule",
             r"Platform & \multicolumn{2}{c}{ML-KEM-1024} & \multicolumn{2}{c}{Hybrid}\\",
             r" & $q$ & $n_{\mathrm{total}}$ & $q$ & $n_{\mathrm{total}}$\\", r"\midrule"]
    for pl in plats:
        cells = []
        for s in ("mlkem1024", "hybrid"):
            r = X1[(X1.platform == pl) & (X1.suite == s)]
            cells += ([_fmt(r.q.iloc[0]), f"{int(r[col].iloc[0]):,}".replace(",", "\\,")] if len(r) else ["--", "--"])
        lines.append(f"{PSHORT[pl]} & " + " & ".join(cells) + r"\\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    open(os.path.join(outdir, "tab_x1.tex"), "w").write("\n".join(lines) + "\n")

    if not X3.empty:
        s = "mlkem1024"
        fig, ax = plt.subplots(figsize=(COL_W, 2.0))
        for i, pl in enumerate([p for p in PLATFORMS if p in set(X3.platform)]):
            S = X3[(X3.platform == pl) & (X3.suite == s)]
            if S.empty:
                continue
            ax.plot(S.depth, S.A2_over_A1, marker="o", ms=3.2, lw=1.2,
                    color=["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4"][i], label=PSHORT[pl])
        ax.axhline(1, color=INK2, lw=0.8)
        ax.set_xlabel("depth of the item in the hierarchy")
        ax.set_ylabel("A2 / A1 access time")
        ax.legend(frameon=False, ncol=2)
        fig.tight_layout(pad=0.3)
        fig.savefig(os.path.join(outdir, "fig_x3.pdf"), bbox_inches="tight", pad_inches=0.02)
        plt.close(fig)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("campaign")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    os.makedirs(a.out, exist_ok=True)
    camp = load_campaign(a.campaign)
    e2(camp, a.out)
    costs, _, _ = e3(camp, a.out)
    explor(costs, a.out)
    print("written to", a.out)


if __name__ == "__main__":
    main()
