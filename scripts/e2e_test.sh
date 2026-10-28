#!/usr/bin/env bash
# End-to-end verification: controller + Mininet live, exercised through REST.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENV="${SDN_VENV:-/opt/sdn-venv}"
LOG=/tmp/campus_twin
mkdir -p "$LOG"
PY="$VENV/bin/python"

service openvswitch-switch start >/dev/null 2>&1 || true
mn -c >/dev/null 2>&1 || true
pkill -f os_ken.cmd.manager 2>/dev/null || true
sleep 1

echo "=== starting controller ==="
"$PY" -m os_ken.cmd.manager --observe-links --ofp-tcp-listen-port 6653 \
    "$ROOT/controller/campus_controller.py" > "$LOG/controller.log" 2>&1 &
CTL=$!
sleep 5

echo "=== starting Mininet (hold 75s, services on) ==="
python3 "$ROOT/emulation/run_campus.py" --hold 75 --services > "$LOG/mininet.log" 2>&1 &
MN=$!
echo "    waiting for topology + LLDP discovery + q-learning to settle..."
sleep 30

echo
"$PY" "$ROOT/tests/verify_live.py" http://localhost:8080
RC=$?

echo
echo "=== controller errors (should be none) ==="
grep -iE "error|traceback|exception|failed" "$LOG/controller.log" \
    | grep -viE "eventlet|RLock|migrating|readthedocs|deprecat" | tail -15 || true
echo "(end of controller error scan)"

wait $MN 2>/dev/null
kill $CTL 2>/dev/null
mn -c >/dev/null 2>&1 || true
echo "=== done (verify_live exit=$RC) ==="
exit $RC
