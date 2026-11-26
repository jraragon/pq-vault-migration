#!/usr/bin/env bash
# P15 -- pilot of E2 (open account, A1) on the Android client, driven from the
# laptop over USB with adb. Randomised complete blocks; every run is a fresh app
# process (force-stop before and after), as on the desktop. Block 00 is a warm-up
# block, discarded by the analysis (pre-registration D-016/D-021). KIND=main for
# the main campaign.
#
# Prerequisites: release build of P15Bench installed on the phone; USB debugging
# on; phone charging over USB; airplane mode on; "Stay awake" on.
#
# Usage (MSYS2 UCRT64, from android/):
#   scripts/run_pilot_android.sh [REPS] [ITERS] [COOLDOWN_S]
set -euo pipefail

REPS=${1:-10}
ITERS=${2:-1000}
COOLDOWN=${3:-20}   # 20 s for the main campaign (DEV-007; was 60 s in the pilot)
WARMUP=${WARMUP:-50}   # pre-registered 50; only a KIND=probe timing check may lower it
TIMEOUT_S=${TIMEOUT_S:-14400}   # max wait for one run; a run that exceeds it aborts the session
NF=7
OP=${OP:-open}   # E2: open; E3: keygen, encap, decap, rewrap (D-025)
# MSYS2 rewrites arguments that look like POSIX paths (/sdcard/...) into Windows paths
# before handing them to adb.exe; disable that for this script.
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*"
PKG=es.usal.p15bench
REMOTE=/sdcard/Android/data/$PKG/files/p15
MAX_TEMP_TENTHS=400   # 40.0 C: runs starting above it are flagged (pre-registration, Section 6)

ADB=${ADB:-}
if [ -z "$ADB" ]; then
  for c in "$(cygpath -u "${LOCALAPPDATA:-}")/Android/Sdk/platform-tools/adb.exe" adb; do
    if command -v "$c" >/dev/null 2>&1 || [ -x "$c" ]; then ADB=$c; break; fi
  done
fi
[ -n "$ADB" ] || { echo "adb not found; set ADB=/path/to/adb.exe"; exit 1; }

state=$("$ADB" get-state 2>/dev/null | tr -d '\r' || true)
[ "$state" = "device" ] || { echo "No phone connected (adb get-state: '$state'). Check the USB cable and USB debugging."; exit 1; }

CONFIGS="rsa3072:na mlkem768:seed mlkem768:expanded mlkem1024:seed mlkem1024:expanded hybrid:seed hybrid:expanded"
STAMP=$(date +%Y%m%d_%H%M%S)
KIND=${KIND:-pilot}
if [ "$WARMUP" != 50 ] && [ "$KIND" != probe ]; then echo "WARMUP must be 50 except for KIND=probe"; exit 1; fi
# Refuse to repeat a main session that already exists outside results/aborted (DEV-008).
if [ "$KIND" = main ] && [ "${FORCE:-0}" != 1 ]; then
  for prev in ../results/main_android_${OP}_*; do
    [ -d "$prev" ] || continue
    echo "A main session for op=$OP already exists: $prev"
    echo "Not starting a second one. (Move it to results/aborted first, or set FORCE=1, only if a deviation says so.)"
    exit 1
  done
fi
OUT=../results/${KIND}_android_${OP}_${STAMP}
mkdir -p "$OUT"

dbg=$("$ADB" shell dumpsys package $PKG | tr -d '\r' | grep -c "DEBUGGABLE" || true)
if [ "$dbg" != "0" ]; then echo "The installed app is a DEBUG build. Install the release build first."; exit 1; fi

# Full ahead-of-time compilation, so that every run executes the same machine code.
"$ADB" shell cmd package compile -m speed -f $PKG | tr -d '\r'
"$ADB" shell rm -rf "$REMOTE" || true

{
  echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "device=$("$ADB" shell getprop ro.product.manufacturer | tr -d '\r') $("$ADB" shell getprop ro.product.model | tr -d '\r')"
  echo "android=$("$ADB" shell getprop ro.build.version.release | tr -d '\r') build=$("$ADB" shell getprop ro.build.display.id | tr -d '\r')"
  echo "app_version=$("$ADB" shell dumpsys package $PKG | tr -d '\r' | grep -m1 versionName | xargs)"
  echo "compile_filter=speed (forced)"
  echo "airplane_mode=$("$ADB" shell settings get global airplane_mode_on | tr -d '\r')"
  echo "stay_awake=$("$ADB" shell settings get global stay_on_while_plugged_in | tr -d '\r')"
  echo "git_commit=$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "reps=$REPS iters=$ITERS warmup=$WARMUP nf=$NF op=$OP cooldown_s=$COOLDOWN"
} > "$OUT/meta.txt"
cat "$OUT/meta.txt"

# Selftest on the phone (RFC 9935 and composite-draft vectors, round trips); abort on failure.
"$ADB" shell am force-stop $PKG
"$ADB" shell am start -W -n $PKG/.MainActivity --es selftest_id selftest > /dev/null
for _ in $(seq 1 300); do
  if "$ADB" shell "[ -f $REMOTE/selftest.done ] && echo y || ([ -f $REMOTE/selftest.error ] && echo e)" | tr -d '\r' | grep -q '[ye]'; then break; fi
  sleep 1
done
"$ADB" shell am force-stop $PKG
"$ADB" shell cat "$REMOTE/selftest.txt" | tr -d '\r' > "$OUT/selftest.txt" || true
if ! grep -q "SELFTEST PASSED" "$OUT/selftest.txt"; then echo "SELFTEST FAILED on the phone -- aborting"; cat "$OUT/selftest.txt"; exit 1; fi
"$ADB" shell rm -f "$REMOTE/selftest.txt" "$REMOTE/selftest.done"
echo "Selftest on the phone: passed"

echo "run_id,battery_temp_tenths_c,flag_hot" > "$OUT/temperatures.csv"
echo "run_id,start_local" > "$OUT/runs.csv"
echo "run_id,wall_s" > "$OUT/durations.csv"
nruns=$(( (REPS + 1) * $(echo $CONFIGS | wc -w) ))
echo "$KIND: $nruns runs (1 warm-up block + $REPS blocks), about $(( nruns * (COOLDOWN + 15) / 60 )) minutes. Do not touch the phone."

for rep in $(seq 0 "$REPS"); do
  pos=0
  for cfg in $(echo $CONFIGS | tr ' ' '\n' | shuf); do
    pos=$((pos + 1))
    suite=${cfg%%:*}; fmt=${cfg##*:}
    id="r$(printf %02d "$rep")p${pos}_${suite}_${fmt}"
    temp=$("$ADB" shell dumpsys battery | tr -d '\r' | awk '/temperature/{print $2; exit}')
    hot=0; [ "${temp:-0}" -gt $MAX_TEMP_TENTHS ] && hot=1
    echo "$id,$temp,$hot" >> "$OUT/temperatures.csv"
    echo "$id,$(date +%Y-%m-%dT%H:%M:%S)" >> "$OUT/runs.csv"
    "$ADB" shell am force-stop $PKG
    "$ADB" shell am start -W -n $PKG/.MainActivity \
        --es suite "$suite" --es format "$fmt" --es op "$OP" \
        --ei iters "$ITERS" --ei warmup "$WARMUP" --ei nf "$NF" --es run_id "$id" > /dev/null
    t0=$SECONDS; finished=0
    while [ $((SECONDS - t0)) -lt "$TIMEOUT_S" ]; do
      if "$ADB" shell "[ -f $REMOTE/$id.done ] && echo y || ([ -f $REMOTE/$id.error ] && echo e)" | tr -d '\r' | grep -q '[ye]'; then finished=1; break; fi
      sleep 1
    done
    "$ADB" shell am force-stop $PKG
    if [ "$finished" = 0 ]; then
      # Never continue silently past an unfinished run (DEV-007): stop and keep what is on the phone.
      echo; echo "Run $id did not finish within $TIMEOUT_S s -- session aborted."
      "$ADB" pull "$REMOTE/." "$OUT/" > /dev/null || true; exit 1
    fi
    echo "$id,$((SECONDS - t0))" >> "$OUT/durations.csv"
    if "$ADB" shell "[ -f $REMOTE/$id.error ] && echo e" | tr -d '\r' | grep -q e; then
      echo; echo "Run $id failed:"; "$ADB" shell cat "$REMOTE/$id.error"; exit 1
    fi
    printf '.'
    sleep "$COOLDOWN"
  done
  if [ "$rep" = 0 ]; then echo " warm-up block done"; else echo " block $rep/$REPS done"; fi
done

"$ADB" pull "$REMOTE/." "$OUT/" > /dev/null
rm -f "$OUT"/*.done
echo "Finished: $(ls "$OUT" | grep -c '^r[0-9][0-9]p.*\.csv$') runs in $OUT"
