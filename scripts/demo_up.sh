#!/usr/bin/env bash
# Bring the whole stack up for a live demo, run a scenario, keep it running.
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
echo "controller pid $!"
sleep 5
python3 "$ROOT/emulation/run_campus.py" --hold "$HOLD" --services > "$LOG/mininet.log" 2>&1 &
echo "mininet pid $!"
echo "waiting for the fabric to converge..."
sleep 26
# kick off a normal campus day so the dashboard shows live flows
curl -s -X POST http://localhost:8081/emu/scenario -H 'Content-Type: application/json' \
    -d "{\"name\":\"normal\",\"duration\":$HOLD}" >/dev/null && echo "normal traffic started"
echo "dashboard: http://localhost:8080   (holding ${HOLD}s)"
