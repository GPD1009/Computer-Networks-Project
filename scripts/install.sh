#!/usr/bin/env bash
# Install the `campus-twin` command system-wide (run inside WSL/Ubuntu).
#   sudo scripts/install.sh            # install deps if missing + put campus-twin on PATH
#   sudo scripts/install.sh --uninstall
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENV="${SDN_VENV:-/opt/sdn-venv}"
DEST=/usr/local/bin/campus-twin

if [ "$1" = "--uninstall" ]; then
  rm -f "$DEST" && echo "removed $DEST"; exit 0
fi
if [ "$(id -u)" -ne 0 ]; then echo "run with sudo: sudo $0"; exit 1; fi

echo "[*] checking system packages (mininet, open vswitch, tools)…"
need=""
for p in mn ovs-vsctl iperf curl; do command -v "$p" >/dev/null 2>&1 || need="yes"; done
if [ -n "$need" ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq mininet openvswitch-switch openvswitch-testcontroller \
      iperf iperf3 net-tools tcpdump curl python3-venv python3-pip
fi

echo "[*] checking controller virtual-env at $VENV…"
if [ ! -x "$VENV/bin/python" ]; then
  python3 -m venv "$VENV"
fi
if ! "$VENV/bin/python" -c "import os_ken, networkx" >/dev/null 2>&1; then
  "$VENV/bin/pip" install -q --upgrade pip
  "$VENV/bin/pip" install -q -r "$ROOT/requirements.txt"
fi

chmod +x "$ROOT/bin/campus-twin" "$ROOT/scripts/"*.sh
ln -sf "$ROOT/bin/campus-twin" "$DEST"
echo "[*] installed:  $DEST -> $ROOT/bin/campus-twin"
echo
echo "Run it (Mininet style):"
echo "    sudo campus-twin --services"
echo "    sudo campus-twin --scenario normal"
echo "Dashboard: http://localhost:8080"
