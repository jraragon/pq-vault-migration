"""
P15 -- smoke test of analysis/make_results.py on simulated sessions (no real data is read).
Run: python analysis/test_make_results.py [OUTDIR]   (exit code 0 = all outputs produced)
"""
import json, os, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from simulate_results import simulate, CONFIGS
import make_results
import population_analysis as _pop
# Smoke test only: 200 bootstrap replicates instead of 20 000 (the real run uses the registered value).
_boot = _pop.boot_means
_pop.boot_means = lambda v, rng, n=200: _boot(v, rng, n)

# plausible magnitudes only (ms); not results
BASE = {"rsa3072": dict(open=2.0, encap=0.03, keygen=100, decap=1.5, load=0.3, rewrap=0.007),
        "mlkem768": dict(open=0.08, encap=0.02, keygen=0.03, decap=0.025, load=0.03, rewrap=0.007),
        "mlkem1024": dict(open=0.1, encap=0.026, keygen=0.05, decap=0.03, load=0.04, rewrap=0.007),
        "hybrid": dict(open=2.2, encap=0.06, keygen=100, decap=1.6, load=0.35, rewrap=0.007)}
SCALE = {"native": 1, "android": 3, "chrome_desktop": 8, "firefox_desktop": 10, "chrome_android": 25}

tmp = tempfile.mkdtemp(prefix="p15mk_")
out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(tmp, "out")
camp = {}
for i, (pl, k) in enumerate(SCALE.items()):
    camp[pl] = {}
    for j, op in enumerate(("open", "encap", "keygen", "decap", "load", "rewrap")):
        med = {}
        for c in CONFIGS:
            s, f = c.split(":")
            m = BASE[s][op] * k
            if f == "expanded" and op in ("open", "load"):
                m *= 0.8
            med[c] = m
        camp[pl][op] = simulate(os.path.join(tmp, f"{pl}_{op}"), med, iters=100, seed=100 * i + j, op=op)
cf = os.path.join(tmp, "campaign.json")
json.dump(camp, open(cf, "w"))
make_results.main([cf, "--out", out])
need = ["tab_e2.tex", "tab_e3.tex", "tab_h31_h41.tex", "tab_x1.tex", "fig_e2.pdf", "fig_population.pdf", "fig_x3.pdf"]
missing = [f for f in need if not os.path.exists(os.path.join(out, f))]
print("missing:", missing or "none")
sys.exit(1 if missing else 0)
