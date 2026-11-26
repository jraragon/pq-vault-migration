#!/usr/bin/env python3
"""
P15 -- freeze manifest: SHA-256 of every file that defines the registered design and
the confirmatory instrument (pre-registration, analytic model, population, analysis
scripts, test data, A1 client sources and run scripts).

Usage: python tools/freeze_manifest.py PREREG_TEX [OUT]
"""
import glob, hashlib, os, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
tex = sys.argv[1]
out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(ROOT, "prereg", "freeze_manifest.txt")
patterns = [
    os.path.relpath(tex, ROOT), os.path.relpath(tex, ROOT)[:-4] + ".pdf",
    "analysis/*.py", "data/population_jcp_seed42.csv", "testdata/*.txt",
    "native/CMakeLists.txt", "native/src/*", "native/scripts/*",
    "android/app/build.gradle.kts", "android/gradle/libs.versions.toml",
    "android/app/src/main/java/es/usal/p15bench/*.java", "android/scripts/*",
    "web/package.json", "web/package-lock.json", "web/server.py", "web/src/*.js", "web/public/*",
    "tools/*.py",
]
files = sorted({f for p in patterns for f in glob.glob(os.path.join(ROOT, p)) if os.path.isfile(f)})
commit = subprocess.run(["git", "-C", ROOT, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
with open(out, "w", newline="\n") as fh:
    fh.write(f"# P15 freeze manifest -- files hashed at repository commit {commit}\n# sha256  path\n")
    for f in files:
        fh.write(f"{hashlib.sha256(open(f, 'rb').read()).hexdigest()}  {os.path.relpath(f, ROOT)}\n")
print(f"{len(files)} files -> {out}")
