"""
P15 -- E1 (RQ1): measured artefact sizes against the analytic predictions P1.1-P1.3.

Input: the size tables printed by each client (`p15_a1 sizes`, P15Core `sizes`, the web
selftest), CSV columns suite,format,credential_pkcs8,public_raw,kem_ct,access_package.
P1.x are deterministic checks: deviations are reported and explained, not tested.

Usage: python analysis/e1_sizes.py IMPL=SIZES_CSV[,HYBRID_SEED_INTERCHANGE_FILE] ...
       (the interchange file, from `xexport`, enables the same-key check of P1.2)
"""
import os, sys
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import p15_modelo_bytes as model   # Table 1 sizes and the archived JCP population

P11 = {"mlkem768": 704, "mlkem1024": 1184, "hybrid": 1568}
NAME = {"rsa3072": "RSA-3072", "mlkem768": "ML-KEM-768", "mlkem1024": "ML-KEM-1024", "hybrid": "Híbrido"}
FMT = {"seed": "semilla", "expanded": "expandida", "na": "semilla"}
PKG_OVERHEAD = 2 + 40   # version byte, suite id, AES-KW of the root: identical for every suite


def _tlv(tag, v):
    n = len(v)
    l = bytes([n]) if n < 0x80 else bytes([0x81, n]) if n < 0x100 else bytes([0x82, n >> 8, n & 0xff])
    return bytes([tag]) + l + v


def _pkcs8(alg_content, priv):
    return _tlv(0x30, bytes([2, 1, 0]) + _tlv(0x30, alg_content) + _tlv(0x04, priv))


def _read(b, o):
    n, p = b[o + 1], o + 2
    if n & 0x80:
        k, n = n & 0x7f, 0
        for i in range(k):
            n = (n << 8) | b[p + i]
        p += k
    return p, p + n


def _pkcs8_content(der):
    s, _ = _read(der, 0)
    _, e = _read(der, s)          # version
    _, e = _read(der, e)          # AlgorithmIdentifier
    a, b = _read(der, e)          # privateKey OCTET STRING
    return der[a:b]


def check(impl, T, xfile=None):
    out = []
    rsa = T[T.suite == "rsa3072"].iloc[0]
    for s, d in P11.items():
        for f in ("seed", "expanded"):
            r = T[(T.suite == s) & (T.format == f)].iloc[0]
            delta = int(r.access_package - rsa.access_package)
            out.append(dict(impl=impl, check="P1.1", item=f"{s} {f}: package - RSA package", measured=delta,
                            predicted=d, ok=delta == d))
    for s in ("mlkem768", "mlkem1024"):
        r = T[(T.suite == s) & (T.format == "seed")].iloc[0]
        out.append(dict(impl=impl, check="P1.2", item=f"{s} seed credential < RSA credential",
                        measured=int(r.credential_pkcs8), predicted=f"< {int(rsa.credential_pkcs8)}",
                        ok=r.credential_pkcs8 < rsa.credential_pkcs8))
        r = T[(T.suite == s) & (T.format == "expanded")].iloc[0]
        out.append(dict(impl=impl, check="P1.2", item=f"{s} expanded credential > RSA credential",
                        measured=int(r.credential_pkcs8), predicted=f"> {int(rsa.credential_pkcs8)}",
                        ok=r.credential_pkcs8 > rsa.credential_pkcs8))
    if xfile:
        # Same key: the hybrid credential holds seed || RSAPrivateKey; re-encode its RSA part as an
        # RSA PKCS#8 credential and compare (content: exactly 64 bytes; PKCS#8: 64 - 3 bytes,
        # because the composite AlgorithmIdentifier is 3 bytes shorter than rsaEncryption's).
        der = bytes.fromhex(dict(l.split(" ", 1) for l in open(xfile).read().split("\n") if " " in l)["cred"])
        content = _pkcs8_content(der)
        rsa_p8 = _pkcs8(bytes.fromhex("06092a864886f70d0101010500"), content[64:])
        out.append(dict(impl=impl, check="P1.2", item="hybrid seed credential - RSA credential, same key (content)",
                        measured=len(content) - len(content[64:]), predicted=64, ok=len(content) - len(content[64:]) == 64))
        out.append(dict(impl=impl, check="P1.2", item="hybrid seed credential - RSA credential, same key (PKCS#8)",
                        measured=len(der) - len(rsa_p8), predicted=64, ok=len(der) - len(rsa_p8) == 64,
                        note="expected 61: composite AlgorithmIdentifier is 3 bytes shorter than rsaEncryption's"))
    # P1.3: per-account bytes at rest in A1 (median), measured artefacts vs Table 1
    nh = model.n_h.astype(float)
    for s in ("mlkem768", "mlkem1024", "hybrid", "rsa3072"):
        for f in (("na",) if s == "rsa3072" else ("seed", "expanded")):
            r = T[(T.suite == s) & (T.format == f)].iloc[0]
            spec = model.SUITES[NAME[s]]
            analytic = np.median(nh * (spec["pk"] + spec["sk"][FMT[f]] + spec["ct"]))
            measured = np.median(nh * (r.public_raw + r.credential_pkcs8 + r.access_package - PKG_OVERHEAD))
            dev = measured / analytic - 1
            out.append(dict(impl=impl, check="P1.3", item=f"A1 per-account bytes at rest, {s} {f}",
                            measured=round(float(measured)), predicted=round(float(analytic)),
                            ok=abs(dev) < 0.10, note=f"deviation {100 * dev:+.2f} % (PKCS#8 wrapper of the credential)"))
    return out


def main(argv=None):
    rows = []
    for x in (argv or sys.argv[1:]):
        impl, path = x.split("=", 1)
        paths = path.split(",")
        rows += check(impl, pd.read_csv(paths[0]), paths[1] if len(paths) > 1 else None)
    R = pd.DataFrame(rows)
    pd.set_option("display.width", 220); pd.set_option("display.max_colwidth", 120); pd.set_option("display.max_rows", 200)
    print(R.to_string(index=False))
    print(f"\n{int(R.ok.sum())}/{len(R)} checks as predicted")
    return R


if __name__ == "__main__":
    main()
