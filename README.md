# Replication package: the impact of key-hierarchy architecture on post-quantum migration costs in client-controlled encrypted storage

Replication package of study P15 (Rodríguez-Aragón, Zato, Alaejos Herrero, Fernández-Díaz and Rodríguez-González): reference implementations of four
key-hierarchy architectures on five client platforms, measurement harnesses, the raw
measurements of the pre-registered campaign and the analysis scripts.
Pre-registration: OSF, registration `f6ugk` (21 November 2026), frozen at tag `p15-prereg-v1.2`.

| Folder | Content |
|---|---|
| `prereg/` | Pre-registration (LaTeX and PDF), freeze manifests, OSF record and the deviation log `DEVIATIONS.md`. |
| `native/` | C reference implementation on OpenSSL 4.1.0 (Windows, MSYS2 UCRT64): A1 (`p15_a1`), the four architectures for the validation (`p15_arch`), runners. |
| `android/` | Android app (Java, Bouncy Castle 1.84) and its runner over adb. |
| `web/` | Browser client (WebCrypto and `@noble/post-quantum`), local server and harness. |
| `analysis/` | Registered analysis scripts, their tests on simulated data, and `make_results.py` (figures and tables). |
| `data/` | Archived JCP population (seed 42) and the validation sample. |
| `results/` | Raw measurements: `main_*` sessions of the campaign, `pilot_*` and `probe_*` sessions, correctness checks; `results/aborted/` holds sessions stopped before completion (not analysed). |
| `testdata/`, `tools/` | Known-answer vectors (NIST ACVP, composite-KEM draft) and their generators. |

## Reproducing the analysis from the archived data

No device is needed: every number of the study is computed from `results/`.

    python -m pip install -r analysis/requirements.txt
    python analysis/test_primary_analysis.py        # tests on simulated data
    python analysis/test_population_analysis.py
    python analysis/make_results.py analysis/main_campaign.json --out results/analysis_main

`analysis/main_campaign.json` lists the session directory of every platform and operation of
the main campaign. `make_results.py` calls the registered scripts (`primary_analysis.py` for
E2 and H2.x, `population_analysis.py` for H3.1 and H4.1, `exploratory_regions.py` for X1–X3)
and writes their reports, CSV tables, LaTeX tables and figures. E1 and the exploratory
validation of the cost model:

    python analysis/e1_sizes.py openssl=results/checks_20261121/sizes_openssl.csv \
        bouncycastle=results/checks_20261121/sizes_bouncycastle.csv noble=results/checks_20261121/sizes_noble.csv
    python analysis/validation_analysis.py results/main_validation_20261124_104838 \
        results/main_native_encap_20261122_012435 results/main_native_keygen_20261122_001011 \
        results/main_native_rewrap_20261122_013416

## Licence and citation

Code: MIT (`LICENSE`). Data and documents: CC BY 4.0 (`LICENSE-DATA.md`). Citation metadata:
`CITATION.cff`.

## Native build (Windows, MSYS2 UCRT64)

Toolchain fixed for the study (decision D-012): OpenSSL 4.1.0, GCC 16.2.0, CMake 4.5.0, Ninja 1.13.2.
Do **not** run `pacman -Syu` until measurements are finished.

```
cd native
cmake -S . -B build -G Ninja
cmake --build build
./build/p15_smoke.exe
```

`p15_smoke` is a correctness check, not a benchmark: it must end with `SMOKE TEST PASSED (0 failures)`.

### Architecture A1 (`p15_a1`)

```
./build/p15_a1.exe selftest     # must end with SELFTEST PASSED (0 failures)
./build/p15_a1.exe sizes        # E1: artefact sizes per suite and private-key format
./build/p15_a1.exe cpus         # logical CPUs and efficiency class (choose a P-core)
scripts/run_pilot.sh CPU        # E2 pilot: 10 randomised blocks x 7 configurations
```

Pilot results are written to `results/pilot_open_<timestamp>/` (one CSV per run plus `meta.txt`).
Measurement conditions (pre-registration, Section 6): mains power, best-performance power mode,
all other applications closed, network disconnected during the run, laptop untouched.

## Browser client (web/)

Same A1 construction as `native/` and `android/`, in JavaScript: ML-KEM from
`@noble/post-quantum` 0.7.1, SHA3-256 from `@noble/hashes` 2.4.0, RSA-OAEP / HKDF /
AES-KW from WebCrypto. The bundle `web/public/p15bench.js` is committed, so running
the pilot only needs Python 3 (standard library):

    cd web && python server.py          # http://localhost:8015 (COOP/COEP, 127.0.0.1 only)

Phone over USB: `adb reverse tcp:8015 tcp:8015`, then open http://localhost:8015 in
Chrome on the phone. Each run is a fresh page load; results go to
`results/pilot_web_<label>_open_<stamp>/`. Rebuild after editing `web/src`:
`npm ci && npm run build`; core test on Node: `npm test`.

## Known-answer tests (composite ML-KEM draft)

`tools/gen_composite_kat.py /path/to/draft-composite-kem` regenerates
`native/src/composite_kat.h`, `android/.../CompositeKat.java` and
`web/src/composite_kat.js` from the draft's `src/testvectors.json`. Every client's
selftest decapsulates the `id-MLKEM1024-RSA3072-SHA3-256` and ML-KEM-1024 vectors
and compares the shared secret. Current source: lamps-wg/draft-composite-kem@efdc41b.

## Runs and analysis

All runners add a warm-up block 00 (discarded by the analysis) and write
`runs.csv` with run times. `KIND=main` (shell runners) or "Campaign: main" (web page)
names the output `results/main_...` instead of `results/pilot_...`.
For the browser on the phone, log the battery temperature from the laptop:
`android/scripts/log_battery_temp.sh results/temp_<name>.csv`.

    python analysis/primary_analysis.py native=DIR android=DIR chrome_desktop=DIR \
        firefox_desktop=DIR chrome_android=DIR --temps chrome_android=FILE --out results/analysis_<name>
    python analysis/test_primary_analysis.py     # tests on simulated data

## Correctness checks

    ./build/p15_a1.exe acvp ../testdata/acvp_mlkem.txt          # native (from native/)
    java -cp <classes>:bcprov.jar es.usal.p15bench.P15Core acvp testdata/acvp_mlkem.txt
    (cd web && node src/acvp_test.js ../testdata/acvp_mlkem.txt)
    # interchange: each implementation exports 7 accounts and opens everyone's
    p15_a1 xexport DIR; P15Core xexport DIR; node web/src/xplat.js export DIR
    p15_a1 xopen DIR/*.txt; P15Core xopen DIR/*.txt; node web/src/xplat.js open DIR/*.txt

`testdata/acvp_mlkem.txt` is generated by `tools/gen_acvp_kat.py` from usnistgov/ACVP-Server.
Results of the 2026-11-21 run: `results/checks_20261121/correctness.txt`.

## Population and E1/E3-E5 analyses

    python analysis/make_population.py        # regenerates and checks data/population_jcp_seed42.csv
    python analysis/population_analysis.py native=DIR_encap native=DIR_keygen native=DIR_rewrap ...  # H3.1, H4.1
    python analysis/e1_sizes.py openssl=sizes.csv[,openssl_hybrid_seed.txt] ...                      # P1.x
    python analysis/test_population_analysis.py

E3 sessions use the same runners with another operation: `OP=encap|keygen|decap|rewrap`
(shell runners) or the "Operation" selector (web page).

## Provenance and pre-registration

This repository is published as a single snapshot. Commit identifiers and tags
cited in `prereg/` (for example `d364f6f`, `87ba518` or `p15-prereg-v1.2`) refer
to the private development history. The state frozen before data collection is
archived on OSF (https://osf.io/f6ugk) as `repository_at_freeze_v1.2.zip`,
together with `freeze_manifest.txt`, which lists the SHA-256 of every frozen
file. Changes made after the freeze are documented in `prereg/DEVIATIONS.md`.
Pre-registration drafts earlier than the registered version 1.2 are not included.
