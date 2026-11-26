#!/usr/bin/env bash
# P15 -- exploratory end-to-end validation of the migration cost model (D-026).
# Runs data/validation_plan.csv (30 accounts x 4 architectures x 2 target suites, in
# the pre-drawn random order): one fresh process per run, pinned to one CPU. Each run
# builds the account under RSA-3072 (untimed), times its migration to the target suite,
# and verifies afterwards that a holder can open it.
#
# Usage (MSYS2 UCRT64, from native/):
#   KIND=main scripts/run_validation.sh CPU
set -euo pipefail

CPU=${1:?usage: scripts/run_validation.sh CPU}
BIN=./build/p15_arch.exe;  [ -x "$BIN" ] || BIN=./build/p15_arch
A1=./build/p15_a1.exe;     [ -x "$A1" ]  || A1=./build/p15_a1
PLAN=${PLAN:-../data/validation_plan.csv}
KIND=${KIND:-pilot}
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*"

if [ "$KIND" = main ] && [ "${FORCE:-0}" != 1 ]; then
  for prev in ../results/main_validation_*; do
    [ -d "$prev" ] || continue
    echo "A main validation session already exists: $prev -- not starting a second one."; exit 1
  done
fi

STAMP=$(date +%Y%m%d_%H%M%S)
OUT=../results/${KIND}_validation_${STAMP}
mkdir -p "$OUT"

"$A1" selftest > "$OUT/selftest.txt" || { echo "SELFTEST FAILED -- aborting"; cat "$OUT/selftest.txt"; exit 1; }
"$BIN" check >> "$OUT/selftest.txt" || { echo "ARCH CHECK FAILED -- aborting"; cat "$OUT/selftest.txt"; exit 1; }
{
  echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host=$(hostname)"
  echo "uname=$(uname -a)"
  echo "openssl=$(openssl version)"
  echo "gcc=$(gcc --version | head -1)"
  echo "git_commit=$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "git_dirty=$(git status --porcelain 2>/dev/null | grep -v '^??' | wc -l)"
  echo "cpu_pin=$CPU plan=$PLAN phi=0.8"
  PC=/c/Windows/System32/powercfg.exe
  if [ -x "$PC" ]; then echo "power_scheme=$("$PC" /getactivescheme 2>/dev/null | tr -d '\r')"; fi
  if [ -x /c/Windows/System32/tasklist.exe ]; then
    echo "processes_running=$(/c/Windows/System32/tasklist.exe /fo csv /nh 2>/dev/null | wc -l)"
    /c/Windows/System32/tasklist.exe /fo csv /nh 2>/dev/null | cut -d, -f1 | sort -u | tr -d '"\r' > "$OUT/processes.txt" || true
  fi
} > "$OUT/meta.txt"
cp "$PLAN" "$OUT/plan.csv"

nruns=$(($(wc -l < "$PLAN") - 1))
echo "$KIND validation: $nruns runs, CPU $CPU. Output: $OUT"
echo "Do not use the laptop until it finishes."
echo "run_id,start_local" > "$OUT/runs_log.csv"
tail -n +2 "$PLAN" | tr -d '\r' | while IFS=, read -r order account arch suite n nf nh; do
  id=$(printf 'v%03d_%s_%s_%s' "$order" "$account" "$arch" "$suite")
  echo "$id,$(date +%Y-%m-%dT%H:%M:%S)" >> "$OUT/runs_log.csv"
  "$BIN" run --arch "$arch" --suite "$suite" --account "$account" --n-total "$n" --n-f "$nf" --n-h "$nh" \
        --cpu "$CPU" --run-id "$id" --out "$OUT/runs.csv"
  printf '.'
  if [ $((order % 40)) = 0 ]; then echo " $order/$nruns"; fi
  sleep 2
done
echo
echo "Finished: $(($(wc -l < "$OUT/runs.csv") - 1)) runs in $OUT"
