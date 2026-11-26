#!/usr/bin/env bash
# P15 -- pre-flight check before a timed session on the laptop (main campaign).
# Lists what the protocol forbids during a session: network adapters that are up and
# applications with a visible window. Run it, fix what it reports, run it again until it
# prints PREFLIGHT OK, and only then launch the session.
PS=/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe
ok=1
echo "== Network adapters that are up (airplane mode should leave none):"
# Host-only virtual adapters (WSL, Hyper-V, the Claude desktop VM, VirtualBox host-only) reach no external network
# and are ignored; every other adapter that is up is reported with its description.
up=$("$PS" -NoProfile -Command "Get-NetAdapter | Where-Object { \$_.Status -eq 'Up' -and \$_.Name -notlike 'vEthernet*' -and \$_.InterfaceDescription -notlike '*Host-Only*' } | ForEach-Object { \$_.Name + '  (' + \$_.InterfaceDescription + ')' }" 2>/dev/null | tr -d '\r')
if [ -n "$up" ]; then echo "$up" | sed 's/^/   UP: /'; ok=0; else echo "   none"; fi
echo "== Applications with a visible window (only the terminal should be listed):"
apps=$("$PS" -NoProfile -Command "Get-Process | Where-Object { \$_.MainWindowTitle -ne '' } | ForEach-Object { \$_.ProcessName + '  [' + \$_.MainWindowTitle + ']' }" 2>/dev/null | tr -d '\r' | grep -aviE '^(mintty|WindowsTerminal|conhost|TextInputHost)')
if [ -n "$apps" ]; then echo "$apps" | sed 's/^/   OPEN: /'; ok=0; else echo "   none besides the terminal"; fi
echo "== Power plan:"
"$PS" -NoProfile -Command "powercfg /getactivescheme" 2>/dev/null | tr -d '\r' | sed 's/^/   /'
if [ $ok = 1 ]; then echo; echo "PREFLIGHT OK"; else echo; echo "PREFLIGHT: fix the items above and run this check again"; fi
