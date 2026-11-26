#!/usr/bin/env python3
"""
Extract the FIPS 203 ACVP vectors used by P15 (ML-KEM-768 and ML-KEM-1024, key
generation and decapsulation) from github.com/usnistgov/ACVP-Server
(gen-val/json-files/ML-KEM-keyGen-FIPS203 and ML-KEM-encapDecap-FIPS203) into a
plain line format read by the three clients' `acvp` test modes:

  kg SUITE SEED_HEX DK_HEX        seed = d || z (64 bytes, RFC 9935 seed form)
  dc SUITE DK_HEX C_HEX K_HEX     expanded decapsulation key, ciphertext, shared secret

Usage: python tools/gen_acvp_kat.py /path/to/ACVP-Server
"""
import json, os, subprocess, sys

root = sys.argv[1]
commit = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
base = os.path.join(root, "gen-val", "json-files")
SUITE = {"ML-KEM-768": "mlkem768", "ML-KEM-1024": "mlkem1024"}


def load(name):
    p = json.load(open(os.path.join(base, name, "prompt.json")))
    e = json.load(open(os.path.join(base, name, "expectedResults.json")))
    res = {(g["tgId"], t["tcId"]): t for g in e["testGroups"] for t in g["tests"]}
    return p, res


lines = [f"# FIPS 203 ACVP vectors from usnistgov/ACVP-Server@{commit}"]
p, r = load("ML-KEM-keyGen-FIPS203")
for g in p["testGroups"]:
    if g["parameterSet"] in SUITE:
        for t in g["tests"]:
            lines.append(f"kg {SUITE[g['parameterSet']]} {t['d']}{t['z']} {r[(g['tgId'], t['tcId'])]['dk']}")
p, r = load("ML-KEM-encapDecap-FIPS203")
for g in p["testGroups"]:
    if g["parameterSet"] in SUITE and g["function"] == "decapsulation":
        for t in g["tests"]:
            lines.append(f"dc {SUITE[g['parameterSet']]} {t['dk']} {t['c']} {r[(g['tgId'], t['tcId'])]['k']}")
out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "testdata", "acvp_mlkem.txt")
open(out, "w").write("\n".join(lines).lower().replace("# fips 203 acvp vectors from", "# FIPS 203 ACVP vectors from") + "\n")
print(f"{len(lines) - 1} vectors -> {out}")
