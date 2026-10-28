#!/usr/bin/env bash
# Bring the stack up with Mininet in the FOREGROUND (keeps the WSL session alive).
#   arg1 = seconds to hold (default 600)
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENV="${SDN_VENV:-/opt/sdn-venv}"
HOLD="${1:-600}"
LOG=/tmp/campus_twin
mkdir -p "$LOG"

service openvswitch-switch start >/dev/null 2>&1 || true
mn -c >/dev/null 2>&1 || true
pkill -f os_ken.cmd.manager 2>/dev/null || true
pkill -f run_campus.py 2>/dev/null || true
sleep 1

"$VENV/bin/python" -m os_ken.cmd.manager --observe-links --ofp-tcp-listen-port 6653 \
    "$ROOT/controller/campus_controller.py" > "$LOG/controller.log" 2>&1 &
CTL=$!
echo "controller pid $CTL"
sleep 5

# kick off normal traffic once the fabric has converged
( sleep 26
  curl -s -X POST http://localhost:8081/emu/scenario -H 'Content-Type: application/json' \
       -d "{\"name\":\"normal\",\"duration\":$HOLD}" >/dev/null && echo "[+] normal campus traffic started"
) &

echo "[*] dashboard will be at http://localhost:8080  (holding ${HOLD}s)"
# Mininet in the FOREGROUND keeps this shell (and the WSL session) alive.
python3 "$ROOT/emulation/run_campus.py" --hold "$HOLD" --services > "$LOG/mininet.log" 2>&1
kill $CTL 2>/dev/null
mn -c >/dev/null 2>&1 || true
echo "[*] stack stopped"
