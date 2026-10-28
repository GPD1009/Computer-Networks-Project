"""
Campus services, traffic scenarios and bounded IDS test-probes that run on
the emulated hosts of the digital twin.

Every long-running process is started with Node.popen() (its own process in
the host's namespace) so the CLI, the HTTP control API and the generated
traffic never contend for a host's shell.

Note: the "probe" helpers here are deliberately small, rate-limited and
bounded.  They exist only so the controller's zero-trust policy and anomaly
detector have something benign to react to on your own emulated campus;
there is no flooding or denial-of-service tooling.
"""
import os
import re
import signal
import subprocess

LOG_DIR = "/tmp/campus_twin"
WWW = os.path.join(LOG_DIR, "www")

# server role -> list of (proto, port) it listens on
SERVICES = {
    "web": [("http", 80)], "lms": [("http", 80)], "exam": [("http", 80)],
    "internet": [("http", 80), ("tcp", 8080)],
    "storage": [("tcp", 5001)], "pbx": [("udp", 5060)], "nvr": [("udp", 554)],
    "iothub": [("udp", 1883)], "dns": [("udp", 53)], "printer": [("tcp", 9100)],
    "voip": [("udp", 5004)], "smartboard": [("udp", 5004)],
    "faculty": [("udp", 3478)], "admin": [("udp", 3478)], "research": [("udp", 3478)],
}


class TrafficManager(object):
    def __init__(self, net, model):
        self.net = net
        self.model = model
        self.services = []          # long-lived server processes
        self.jobs = {}              # scenario name -> [Popen]
        os.makedirs(WWW, exist_ok=True)
        with open(os.path.join(WWW, "index.html"), "w") as f:
            f.write("<html><body><h1>Campus service</h1>%s</body></html>" % ("x" * 20000))

    # ------------------------------------------------------------ utilities
    def h(self, name):
        return self.net.get(name)

    def ip(self, name):
        return self.model.hosts[name]["ip"]

    def by_type(self, t):
        return [n for n, h in self.model.hosts.items() if h["type"] == t and n in self.net]

    def by_role(self, r):
        return [n for n, h in self.model.hosts.items() if h["role"] == r and n in self.net]

    def _bg(self, job, host, script, log=None):
        log = log or os.path.join(LOG_DIR, "%s-%s.log" % (job, host))
        f = open(log, "ab")
        p = self.h(host).popen(["bash", "-c", script], stdout=f, stderr=subprocess.STDOUT,
                               preexec_fn=os.setsid)
        self.jobs.setdefault(job, []).append(p)
        return p

    def _run(self, host, script, timeout=60):
        p = self.h(host).popen(["bash", "-c", script], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        try:
            out, _ = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            out, _ = p.communicate()
        return out.decode(errors="replace")

    # ------------------------------------------------------------ services
    def start_services(self):
        started = 0
        for name, h in self.model.hosts.items():
            if name not in self.net:
                continue
            for proto, port in SERVICES.get(h["role"], []):
                log = open(os.path.join(LOG_DIR, "svc-%s-%d.log" % (name, port)), "ab")
                if proto == "http":
                    cmd = ["python3", "-m", "http.server", str(port), "--bind", "0.0.0.0", "--directory", WWW]
                elif proto == "tcp":
                    cmd = ["iperf", "-s", "-p", str(port)]
                else:
                    cmd = ["iperf", "-s", "-u", "-p", str(port)]
                self.services.append(self.h(name).popen(cmd, stdout=log, stderr=subprocess.STDOUT))
                started += 1
        return "started %d campus services (web/LMS/exam HTTP, PBX, NVR, IoT hub, DNS, storage, phones...)" % started

    def stop_all(self):
        n = 0
        for job in list(self.jobs):
            n += self.stop(job, quiet=True)
        return "stopped %d traffic processes" % n

    def stop(self, job, quiet=False):
        n = 0
        for p in self.jobs.pop(job, []):
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
            n += 1
        return n if quiet else "stopped %s (%d processes)" % (job, n)

    def shutdown(self):
        self.stop_all()
        for p in self.services:
            try:
                p.kill()
            except Exception:
                pass

    def running(self):
        out = {}
        for job, procs in self.jobs.items():
            alive = sum(1 for p in procs if p.poll() is None)
            if alive:
                out[job] = alive
        return out

    # ------------------------------------------------------------ scenarios
    def scenario(self, name, duration=600):
        fn = getattr(self, "sc_" + name, None)
        if fn is None:
            return "unknown scenario '%s' (normal|exam|congestion|byod|stop)" % name
        return fn(duration)

    def sc_stop(self, duration=0):
        return self.stop_all()

    def sc_normal(self, duration=600):
        """A typical campus day: CCTV, IoT telemetry, VoIP calls, web/LMS browsing, backups."""
        self.stop("normal", quiet=True)
        d = int(duration)
        for cam in self.by_type("cam"):
            self._bg("normal", cam, "iperf -u -c %s -p 554 -b 2M -t %d" % (self.ip("dc-nvr"), d))
        for s in self.by_type("iot"):
            self._bg("normal", s, "iperf -u -c %s -p 1883 -b 20K -l 100 -t %d" % (self.ip("dc-iot"), d))
        phones = self.by_type("phn")
        for a, b in zip(phones[0::2], phones[1::2]):
            self._bg("normal", a, "iperf -u -c %s -p 5004 -b 90K -l 200 -t %d" % (self.ip(b), d))
            self._bg("normal", b, "iperf -u -c %s -p 5004 -b 90K -l 200 -t %d" % (self.ip(a), d))
        for p in phones:
            self._bg("normal", p, "iperf -u -c %s -p 5060 -b 8K -l 300 -t %d" % (self.ip("dc-pbx"), d))
        browse = {"fac": "dc-web", "adm": "dc-web", "lab": "dc-lms", "lap": "dc-lms", "kio": "dc-lms",
                  "brd": "dc-lms", "rws": "dc-web"}
        for t, srv in browse.items():
            for hname in self.by_type(t):
                self._bg("normal", hname,
                         "end=$((SECONDS+%d)); while [ $SECONDS -lt $end ]; do "
                         "curl -s -o /dev/null --max-time 3 http://%s/; sleep $((RANDOM %% 4 + 2)); done"
                         % (d, self.ip(srv)))
        for hname in self.by_type("lap"):
            self._bg("normal", hname,
                     "end=$((SECONDS+%d)); while [ $SECONDS -lt $end ]; do "
                     "curl -s -o /dev/null --max-time 3 http://%s/; sleep 3; done" % (d, self.ip("dc-inet")))
        for r in self.by_type("rws"):
            self._bg("normal", r, "iperf -c %s -p 5001 -b 3M -t %d" % (self.ip("dc-store"), d))
        return "normal campus traffic started for %ds (%d processes)" % (d, len(self.jobs.get("normal", [])))

    def sc_congestion(self, duration=90):
        """Research backups load the AB4 uplink while a VoIP call crosses it."""
        self.stop("congestion", quiet=True)
        d = int(duration)
        for r in self.by_type("rws"):
            for _ in range(2):
                self._bg("congestion", r, "iperf -c %s -p 5001 -b 15M -t %d" % (self.ip("dc-store"), d))
        self._bg("congestion", "ab4-fac1", "iperf -c %s -p 5001 -b 12M -t %d" % (self.ip("dc-store"), d))
        self._bg("congestion", "ab4-phn1", "iperf -u -c %s -p 5004 -b 90K -l 200 -t %d" % (self.ip("ab1-phn1"), d))
        return ("congestion scenario: ~70 Mbps of AB4 backups toward dc-store (uplinks are 40 Mbps) + a VoIP "
                "call AB4->AB1 for %ds. Watch the controller move bulk flows to core2 and keep VoIP on core1." % d)

    def sc_exam(self, duration=60):
        """Online exam from AB2 labs while bulk traffic competes - exam is 'critical' class."""
        self.stop("exam", quiet=True)
        d = int(duration)
        for r in self.by_type("rws") + ["ab1-fac1"]:
            self._bg("exam", r, "iperf -c %s -p 5001 -b 20M -t %d" % (self.ip("dc-store"), d))
        for lab in self.by_type("lab"):
            self._bg("exam", lab,
                     "end=$((SECONDS+%d)); while [ $SECONDS -lt $end ]; do "
                     "curl -s -o /dev/null -w '%%{time_total}\\n' --max-time 3 http://%s/; sleep 1; done"
                     % (d, self.ip("dc-exam")), log=os.path.join(LOG_DIR, "exam-%s.times" % lab))
        return "exam scenario running %ds: lab PCs poll dc-exam (critical QoS) under backup load; " \
               "run 'examreport' afterwards" % d

    def exam_report(self):
        lines = []
        for lab in self.by_type("lab"):
            path = os.path.join(LOG_DIR, "exam-%s.times" % lab)
            try:
                vals = [float(x) for x in open(path).read().split() if re.match(r"^[0-9.]+$", x)]
            except OSError:
                vals = []
            ok = [v for v in vals if v > 0]
            if ok:
                lines.append("%-9s requests=%3d  avg=%.1f ms  max=%.1f ms" %
                             (lab, len(ok), 1000 * sum(ok) / len(ok), 1000 * max(ok)))
            else:
                lines.append("%-9s no successful requests" % lab)
        return "\n".join(lines) or "no exam data - run 'scenario exam' first"

    def sc_byod(self, duration=60):
        """Student laptops pull Internet bandwidth (the BYOD slice is metered by the controller)."""
        self.stop("byod", quiet=True)
        d = int(duration)
        for lap in self.by_type("lap"):
            self._bg("byod", lap, "iperf -c %s -p 8080 -t %d -i 5" % (self.ip("dc-inet"), d),
                     log=os.path.join(LOG_DIR, "byod-%s.log" % lap))
        return "BYOD scenario: %d student laptops uploading for %ds - the controller's meter caps the slice" \
               % (len(self.by_type("lap")), d)

    # ------------------------------------------------------------ IDS test-probes
    # Bounded, benign traffic that lets the zero-trust policy and anomaly
    # detector demonstrate detection on your own emulated campus.
    def probe(self, kind, *args):
        a = list(args)
        if kind == "sweep":
            # A host sequentially pings many campus IPs. The controller's IDS
            # flags this as a host sweep once it crosses the configured count.
            src = a[0] if a else "ab3-lap1"
            if src not in self.net:
                return "unknown host %s" % src
            targets = " ".join(h["ip"] for h in self.model.hosts.values())
            # Fire the pings concurrently so the whole sweep lands inside the
            # detector's 10s window (denied pings would otherwise each block for
            # their full timeout and stretch the sweep over ~40s).
            self._bg("probe", src,
                     "for ip in %s; do ping -c1 -W1 $ip >/dev/null 2>&1 & done; wait; echo sweep-done" % targets)
            return ("%s is sweeping campus hosts with one ping each. This is zero-trust test traffic: the "
                    "controller detects the sweep and (if auto-quarantine is on) isolates %s fabric-wide." % (src, src))
        if kind == "denied":
            # A host repeatedly attempts a connection the policy forbids
            # (e.g. a student laptop toward the admin/exam servers). Each
            # attempt is blocked; enough of them trips 'policy probing'.
            src = a[0] if a else "ab3-lap1"
            dst = a[1] if len(a) > 1 else "dc-exam"
            if src not in self.net or dst not in self.model.hosts:
                return "usage: probe denied <src-host> <dst-host>"
            self._bg("probe", src,
                     "for i in $(seq 1 80); do curl -s -o /dev/null --max-time 1 http://%s/ ; "
                     "sleep 0.1; done; echo denied-done" % self.ip(dst))
            return ("%s is making repeated connection attempts to %s that the zero-trust policy denies. "
                    "The controller logs each denied attempt and raises a 'policy probing' alert." % (src, dst))
        if kind == "overrate":
            # An IoT sensor transmits far above its device profile, so the
            # behaviour-profile detector flags it (a stand-in for a
            # compromised/misbehaving sensor).
            src = a[0] if a else "ab2-iot1"
            if src not in self.net:
                return "unknown host %s" % src
            self._bg("probe", src, "iperf -u -c %s -p 1883 -b 8M -t 20" % self.ip("dc-iot"))
            return ("%s (an IoT sensor, profiled at ~0.5 Mbps) is now sending ~8 Mbps to the IoT hub. "
                    "The anomaly detector flags it as a profile violation." % src)
        return "unknown probe '%s' (sweep|denied|overrate)" % kind
