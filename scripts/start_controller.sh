#!/usr/bin/env bash
# Start the campus SDN controller (control + application layers).
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENV="${SDN_VENV:-/opt/sdn-venv}"
PORT_OF="${OF_PORT:-6653}"
PORT_REST="${REST_PORT:-8080}"

cd "$ROOT"
echo "[*] Campus SDN controller"
echo "    OpenFlow : tcp/$PORT_OF        REST+dashboard : http://localhost:$PORT_REST"
exec "$VENV/bin/python" -m os_ken.cmd.manager \
    --observe-links \
    --ofp-tcp-listen-port "$PORT_OF" \
    "$ROOT/controller/campus_controller.py"
