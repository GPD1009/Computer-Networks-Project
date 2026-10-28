#!/usr/bin/env bash
# Start the Mininet campus emulation (infrastructure layer). Needs root.
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENV="${SDN_VENV:-/opt/sdn-venv}"

if [ "$(id -u)" -ne 0 ]; then
    echo "run with sudo: sudo $0 $*"; exit 1
fi
service openvswitch-switch start >/dev/null 2>&1 || true
mn -c >/dev/null 2>&1 || true
# Two-terminal workflow: the controller is started separately (start_controller.sh),
# so point Mininet at that already-running controller instead of launching another.
# (For the single-command experience, use `campus-twin` instead — it starts both.)
exec python3 "$ROOT/emulation/run_campus.py" --controller remote "$@"
