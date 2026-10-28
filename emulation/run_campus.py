#!/usr/bin/env python3
"""
Launch the campus digital-twin emulation (infrastructure layer).

    sudo python3 emulation/run_campus.py            # interactive CLI
    sudo python3 emulation/run_campus.py --test      # auto self-test, then exit

Adds campus-specific CLI commands on top of the standard Mininet CLI:

    services                 start all campus servers (web/LMS/exam/PBX/...)
    scenario <name> [secs]   normal | exam | congestion | byod | stop
    examreport               latency report after an exam scenario
    probe <kind> [args]      sweep | denied | overrate   (IDS test traffic)
    jobs                     list running traffic jobs
    linkdown A B / linkup A B  fail or restore a link (fast-failover demo)
    checkpolicy              run a policy connectivity check from the CLI
    ...plus the usual pingall, iperf, xterm, dpctl, etc.
"""
import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from mininet.cli import CLI
from mininet.log import setLogLevel, info, output
from mininet.util import dumpNodeConnections

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "common"))

from topology import build_net, setup_qos_queues  # noqa: E402
from traffic import TrafficManager, LOG_DIR        # noqa: E402

DEFAULT_CONFIG = os.path.join(ROOT, "config", "campus.json")


class CampusCLI(CLI):
    "Mininet CLI extended with campus digital-twin commands."

    def __init__(self, net, traffic, model, *a, **k):
        self.traffic = traffic
        self.cmodel = model
        CLI.__init__(self, net, *a, **k)

    def do_services(self, _):
        "Start all campus services (servers listen for traffic)."
        output(self.traffic.start_services() + "\n")

    def do_scenario(self, line):
        "scenario <normal|exam|congestion|byod|stop> [seconds]"
        args = line.split()
        if not args:
            output("usage: scenario <normal|exam|congestion|byod|stop> [seconds]\n")
            return
        dur = int(args[1]) if len(args) > 1 else {"congestion": 90, "exam": 60, "byod": 60}.get(args[0], 600)
        output(self.traffic.scenario(args[0], dur) + "\n")

    def do_examreport(self, _):
        "Latency report for lab PCs after 'scenario exam'."
        output(self.traffic.exam_report() + "\n")

    def do_probe(self, line):
        "probe <sweep|denied|overrate> [args]  - bounded IDS test traffic"
        args = line.split()
        if not args:
            output("usage: probe <sweep|denied|overrate> [host ...]\n")
            return
        output(self.traffic.probe(args[0], *args[1:]) + "\n")

    def do_jobs(self, _):
        "List running traffic jobs."
        r = self.traffic.running()
        output((json.dumps(r) if r else "no traffic running") + "\n")

    def do_stoptraffic(self, _):
        "Stop all generated traffic."
        output(self.traffic.stop_all() + "\n")

    def do_linkdown(self, line):
        "linkdown <nodeA> <nodeB>  - fail a link (watch the controller reroute)"
        a, b = (line.split() + [None, None])[:2]
        if not a or not b:
            output("usage: linkdown <nodeA> <nodeB>\n")
            return
        self.mn.configLinkStatus(a, b, "down")
        output("link %s-%s DOWN\n" % (a, b))

    def do_linkup(self, line):
        "linkup <nodeA> <nodeB>  - restore a link"
        a, b = (line.split() + [None, None])[:2]
        if not a or not b:
            output("usage: linkup <nodeA> <nodeB>\n")
            return
        self.mn.configLinkStatus(a, b, "up")
        output("link %s-%s UP\n" % (a, b))

    def do_checkpolicy(self, line):
        "checkpolicy <srcHost> <dstHost>  - zero-trust reachability from the data plane"
        a, b = (line.split() + [None, None])[:2]
        if not a or not b or a not in self.mn or b not in self.mn:
            output("usage: checkpolicy <srcHost> <dstHost>\n")
            return
        dst_ip = self.cmodel.hosts[b]["ip"]
        output("ICMP  : %s" % self.mn.get(a).cmd("ping -c2 -W1 %s | tail -2" % dst_ip))
        output("Served pages on dst (HTTP):\n%s" % self.mn.get(a).cmd(
            "curl -s -o /dev/null -w 'http_code=%%{http_code} time=%%{time_total}s\\n' --max-time 3 http://%s/" % dst_ip))


class ControlHandler(BaseHTTPRequestHandler):
    """Tiny HTTP bridge so the dashboard can drive the emulation."""
    traffic = None
    net = None

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self._send(204, {})

    def do_GET(self):
        if self.path.rstrip("/") == "/emu/jobs":
            return self._send(200, {"running": self.traffic.running()})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n).decode() or "{}") if n else {}
        except ValueError:
            return self._send(400, {"error": "bad json"})
        path = self.path.rstrip("/")
        try:
            if path == "/emu/scenario":
                msg = self.traffic.scenario(body.get("name", "normal"), int(body.get("duration", 300)))
            elif path == "/emu/probe":
                msg = self.traffic.probe(body.get("kind", "sweep"), *body.get("args", []))
            elif path == "/emu/services":
                msg = self.traffic.start_services()
            elif path == "/emu/stop":
                msg = self.traffic.stop_all()
            elif path == "/emu/link":
                a, b, st = body.get("a"), body.get("b"), body.get("state", "down")
                self.net.configLinkStatus(a, b, st)
                msg = "link %s-%s %s" % (a, b, st.upper())
            else:
                return self._send(404, {"error": "not found"})
            self._send(200, {"ok": True, "message": msg})
        except Exception as e:
            self._send(500, {"error": str(e)})


def start_control_bridge(net, traffic, model):
    ControlHandler.traffic = traffic
    ControlHandler.net = net
    port = model.emulator_api_port
    try:
        srv = ThreadingHTTPServer(("0.0.0.0", port), ControlHandler)
    except OSError as e:
        info("*** emulation control bridge disabled (%s)\n" % e)
        return None
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    info("*** emulation control bridge on http://localhost:%d\n" % port)
    return srv


def self_test(net, model, traffic):
    output("\n=== Digital-twin self-test ===\n")
    output("*** waiting for switches to connect to the controller\n")
    net.waitConnected(timeout=30)
    time.sleep(8)                                   # let the controller learn hosts / LLDP
    output("*** %d switches connected, %d hosts\n" % (len(net.switches), len(net.hosts)))

    # Representative zero-trust checks (a full pingAll is slow now that denied
    # flows are really dropped — each would wait the ping timeout).
    def ping_ok(a, b):
        h = net.get(a)
        r = h.cmd("ping -c1 -W1 %s" % model.hosts[b]["ip"])
        return " 0% packet loss" in r

    def http_code(a, b):
        return net.get(a).cmd("curl -s -o /dev/null -w '%%{http_code}' --max-time 4 http://%s/ || true"
                              % model.hosts[b]["ip"]).strip()

    icmp = [("ab1-adm1", "dc-web", True, "admin diagnostics ping (R15)"),
            ("ab2-lab1", "dc-lms", True, "lab -> LMS (allowed)"),
            ("ab3-lap1", "ab1-adm1", False, "student -> admin PC (zero-trust deny)"),
            ("ab2-iot1", "ab2-cam1", False, "IoT -> CCTV (slice isolation)")]
    output("\n*** zero-trust ICMP checks (identity-based)\n")
    passes = 0
    for a, b, want, desc in icmp:
        got = ping_ok(a, b)
        ok = (got == want)
        passes += ok
        output("    [%s] %-34s %s -> %s  (%s)\n" % ("PASS" if ok else "FAIL", desc, a, b,
               "reachable" if got else "blocked"))

    http = [("ab3-lap1", "dc-lms", "200", "student laptop -> LMS (allowed, routed)"),
            ("ab3-lap1", "dc-exam", "000", "student laptop -> EXAM (denied)"),
            ("ab2-lab1", "dc-exam", "200", "lab PC -> EXAM (allowed, critical QoS)")]
    output("\n*** zero-trust HTTP checks\n")
    for a, b, want, desc in http:
        code = http_code(a, b)
        ok = (code == want)
        passes += ok
        output("    [%s] %-40s HTTP %s\n" % ("PASS" if ok else "FAIL", desc, code or "000"))

    total = len(icmp) + len(http)
    output("\n=== self-test: %d/%d checks passed ===\n\n" % (passes, total))


def _find_venv_python(venv):
    for cand in (os.path.join(venv, "bin", "python"), os.path.join(venv, "bin", "python3")):
        if os.path.isfile(cand):
            return cand
    return None


def _port_open(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.6)
        return s.connect_ex((host, port)) == 0


def start_controller(model, of_port, venv):
    """Launch our os-ken controller (control+application layers) as a subprocess."""
    py = _find_venv_python(venv)
    if not py:
        info("*** controller venv not found at %s — start the controller yourself "
             "(scripts/start_controller.sh) or pass --controller remote\n" % venv)
        return None
    app = os.path.join(ROOT, "controller", "campus_controller.py")
    env = dict(os.environ, CAMPUS_CONFIG=model.path)
    log = open(os.path.join(LOG_DIR, "controller.log"), "ab")
    info("*** starting SDN controller (os-ken) on tcp/%d — log: %s/controller.log\n" % (of_port, LOG_DIR))
    proc = subprocess.Popen([py, "-m", "os_ken.cmd.manager", "--observe-links",
                             "--ofp-tcp-listen-port", str(of_port), app],
                            stdout=log, stderr=subprocess.STDOUT, env=env)
    for _ in range(60):
        if proc.poll() is not None:
            info("*** controller exited early — see %s/controller.log\n" % LOG_DIR)
            return None
        if _port_open("127.0.0.1", of_port):
            info("*** controller is up and listening for switches\n")
            return proc
        time.sleep(0.5)
    info("*** controller did not open tcp/%d in time (continuing anyway)\n" % of_port)
    return proc


def main():
    ap = argparse.ArgumentParser(
        prog="campus-twin",
        description="Campus SDN Digital Twin — launches the controller + Mininet campus and drops "
                    "into an interactive CLI (Mininet style).",
        epilog="CLI once running:  services | scenario <normal|exam|congestion|byod|stop> [secs] | "
               "probe <sweep|denied|overrate> | linkdown A B | linkup A B | examreport | checkpolicy | "
               "pingall | iperf | exit")
    ap.add_argument("--controller", default="auto", metavar="auto|remote[:ip:port]",
                    help="'auto' (default) launches our controller; 'remote' uses an already-running one; "
                         "'remote:IP:PORT' points at a specific controller")
    ap.add_argument("--config", default=DEFAULT_CONFIG, help="campus topology/device inventory JSON")
    ap.add_argument("--venv", default=os.environ.get("SDN_VENV", "/opt/sdn-venv"),
                    help="virtual-env that has os-ken (for --controller auto)")
    ap.add_argument("--services", action="store_true", help="start campus services (servers) automatically")
    ap.add_argument("--scenario", metavar="NAME", help="auto-start a traffic scenario (implies --services)")
    ap.add_argument("--test", action="store_true", help="run a self-test and exit")
    ap.add_argument("--hold", type=int, default=0, metavar="SECS",
                    help="run non-interactively for SECS seconds, then exit (for scripted demos)")
    ap.add_argument("--no-qos", action="store_true", help="skip OVS QoS queue setup")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("campus-twin needs root (Mininet). Re-run with sudo:  sudo %s" % " ".join(sys.argv))

    setLogLevel("info")
    os.makedirs(LOG_DIR, exist_ok=True)

    # resolve / launch the controller before the switches look for it
    from campus_model import CampusModel
    model = CampusModel(args.config)
    ctl = model.controller
    ctl_proc = None
    mode = args.controller.split(":")[0]
    if mode == "auto":
        if shutil.which("ovs-vsctl"):
            subprocess.call(["service", "openvswitch-switch", "start"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.call(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ctl_proc = start_controller(model, ctl.get("port", 6653), args.venv)
    elif ":" in args.controller:                     # remote:ip:port
        _, ip, port = args.controller.split(":")
        ctl["ip"], ctl["port"] = ip, int(port)
        info("*** using remote controller at %s:%s\n" % (ip, port))
    else:
        info("*** using an already-running controller at %s:%s\n" % (ctl.get("ip"), ctl.get("port")))

    net, model = build_net(args.config)
    info("*** Campus SDN Digital Twin: %s\n" % json.dumps(model.summary()))
    info("*** dashboard: http://localhost:%s\n" % ctl.get("rest_port", 8080))
    net.start()
    if not args.no_qos:
        info("*** configuring OVS QoS queues (best-effort / real-time / bulk)\n")
        setup_qos_queues(model)
    traffic = TrafficManager(net, model)
    bridge = start_control_bridge(net, traffic, model)
    if args.services or args.scenario or args.test:
        info("*** " + traffic.start_services() + "\n")

    try:
        net.waitConnected(timeout=30)
        if args.scenario:
            time.sleep(6)
            info("*** " + traffic.scenario(args.scenario, max(args.hold, 600)) + "\n")
        if args.test:
            self_test(net, model, traffic)
        elif args.hold:
            info("*** holding the network up for %ds (dashboard + control bridge driving it)\n" % args.hold)
            time.sleep(args.hold)
        else:
            info("*** Campus twin ready. 'help' for commands; try: services, scenario normal, "
                 "linkdown core1 ab4d, probe sweep\n")
            CampusCLI(net, traffic, model)
    finally:
        info("*** stopping traffic and tearing down\n")
        traffic.shutdown()
        if bridge:
            bridge.shutdown()
        net.stop()
        if ctl_proc and ctl_proc.poll() is None:
            info("*** stopping the SDN controller\n")
            ctl_proc.terminate()
            try:
                ctl_proc.wait(timeout=6)
            except subprocess.TimeoutExpired:
                ctl_proc.kill()


if __name__ == "__main__":
    main()
