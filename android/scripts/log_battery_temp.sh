#!/usr/bin/env bash
# P15 -- log the phone's battery temperature from the laptop while the browser
# client runs on the phone (the page cannot read it). One line every INTERVAL
# seconds, local clock, the same clock the web server uses for run end times.
#
# Usage (MSYS2 UCRT64): android/scripts/log_battery_temp.sh OUTFILE [INTERVAL_S]
#   Stop with Ctrl+C.
set -uo pipefail
OUTF=${1:?usage: log_battery_temp.sh OUTFILE [INTERVAL_S]}
INTERVAL=${2:-20}
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*"
ADB=${ADB:-}
if [ -z "$ADB" ]; then
  for c in "$(cygpath -u "${LOCALAPPDATA:-}" 2>/dev/null)/Android/Sdk/platform-tools/adb.exe" adb; do
    if command -v "$c" >/dev/null 2>&1 || [ -x "$c" ]; then ADB=$c; break; fi
  done
fi
[ -n "$ADB" ] || { echo "adb not found; set ADB=/path/to/adb.exe"; exit 1; }
[ -s "$OUTF" ] || echo "time_local,battery_temp_tenths_c" > "$OUTF"
echo "Logging battery temperature to $OUTF every ${INTERVAL}s (Ctrl+C to stop)"
while true; do
  t=$("$ADB" shell dumpsys battery | tr -d '\r' | awk '/temperature/{print $2; exit}')
  line="$(date +%Y-%m-%dT%H:%M:%S),${t:-NA}"
  echo "$line" | tee -a "$OUTF"
  sleep "$INTERVAL"
done
