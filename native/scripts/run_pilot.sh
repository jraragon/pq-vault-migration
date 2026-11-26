#!/usr/bin/env bash
# P15 -- pilot of E2 (open account, architecture A1) on the native desktop client.
# Randomised complete blocks: each repetition runs every configuration once, in a
# freshly shuffled order; one process per run (the experimental unit).
# Block 00 is a warm-up block: it is run like the others and discarded by the
# analysis (pre-registration D-016/D-021). Set KIND=main for the main campaign.
#
# Usage (MSYS2 UCRT64, from native/):
#   scripts/run_pilot.sh CPU [REPS] [ITERS]
#     CPU    logical CPU to pin to (a P-core; see ./build/p15_a1.exe cpus)
#     REPS   repetitions (blocks), default 10
#     ITERS  timed operations per run, default 1000
set -euo pipefail

CPU=${1:?usage: scripts/run_pilot.sh CPU [REPS] [ITERS]}
REPS=${2:-10}
ITERS=${3:-1000}
WARMUP=50
NF=7
OP=${OP:-open}   # E2: open; E3: keygen, encap, decap, rewrap (D-025)
BIN=./build/p15_a1.exe
[ -x "$BIN" ] || BIN=./build/p15_a1

CONFIGS="rsa3072:na mlkem768:seed mlkem768:expanded mlkem1024:seed mlkem1024:expanded hybrid:seed hybrid:expanded"

STAMP=$(date +%Y%m%d_%H%M%S)
# MSYS2 rewrites arguments that look like POSIX paths (/fo, /nh, /getactivescheme) before
# handing them to Windows programs; disable that so tasklist and powercfg get their options.
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*"
KIND=${KIND:-pilot}
OUT=../results/${KIND}_native_${OP}_${STAMP}
mkdir -p "$OUT"

# ---------------------------------------------------------------- environment
"$BIN" selftest > "$OUT/selftest.txt" || { echo "SELFTEST FAILED -- aborting"; cat "$OUT/selftest.txt"; exit 1; }
{
  echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host=$(hostname)"
  echo "uname=$(uname -a)"
  echo "openssl=$(openssl version)"
  echo "gcc=$(gcc --version | head -1)"
  echo "git_commit=$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "git_dirty=$(git status --porcelain 2>/dev/null | grep -v '^??' | wc -l)"
  echo "cpu_pin=$CPU reps=$REPS iters=$ITERS warmup=$WARMUP nf=$NF op=$OP"
  PC=/c/Windows/System32/powercfg.exe
  if [ -x "$PC" ]; then echo "power_scheme=$("$PC" /getactivescheme 2>/dev/null | tr -d '\r')"; fi
  if [ -x /c/Windows/System32/tasklist.exe ]; then
    echo "processes_running=$(/c/Windows/System32/tasklist.exe /fo csv /nh 2>/dev/null | wc -l)"
    /c/Windows/System32/tasklist.exe /fo csv /nh 2>/dev/null | cut -d, -f1 | sort -u | tr -d '"\r' > "$OUT/processes.txt" || true
  fi
} > "$OUT/meta.txt"
"$BIN" cpus > "$OUT/cpus.csv" 2>&1 || true

echo "run_id,start_local" > "$OUT/runs.csv"
echo "$KIND: 1 warm-up block + $REPS blocks x $(echo $CONFIGS | wc -w) configurations, $ITERS ops each, CPU $CPU"
echo "Output: $OUT"
echo "Do not use the laptop until it finishes."

# ---------------------------------------------------------------- runs
for rep in $(seq 0 "$REPS"); do
  pos=0
  for cfg in $(echo $CONFIGS | tr ' ' '\n' | shuf); do
    pos=$((pos + 1))
    suite=${cfg%%:*}; fmt=${cfg##*:}
    id="r$(printf %02d "$rep")p${pos}_${suite}_${fmt}"
    echo "$id,$(date +%Y-%m-%dT%H:%M:%S)" >> "$OUT/runs.csv"
    "$BIN" bench --suite "$suite" --format "$fmt" --op "$OP" --iters "$ITERS" \
          --warmup "$WARMUP" --nf "$NF" --cpu "$CPU" --run-id "$id" --out "$OUT/$id.csv"
    printf '.'
    sleep 2
  done
  if [ "$rep" = 0 ]; then echo " warm-up block done"; else echo " block $rep/$REPS done"; fi
done
echo "Finished: $(ls "$OUT"/r*.csv | wc -l) runs in $OUT"
