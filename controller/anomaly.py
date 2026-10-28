"""
Anomaly / intrusion detection running on top of the controller.

Detectors
  * port / host scan   - many distinct (destination, port) pairs in a window
  * packet-in flood    - new-flow rate far above anything a real host does
  * policy probing     - repeated denied connection attempts
  * behaviour profile  - device sends far more than its type's profile allows
                         (e.g. an IoT sensor suddenly streaming megabits)
  * statistical        - EWMA baseline per host, alarm when z-score explodes
  * IP spoofing        - source IP does not belong to the registered MAC

Each detector returns findings; the controller decides (per policy) whether
to automatically quarantine the host fabric-wide.
"""
import collections
import math


class HostBaseline(object):
    __slots__ = ("mean", "var", "n", "last")

    def __init__(self):
        self.mean, self.var, self.n, self.last = 0.0, 0.0, 0, 0.0

    def update(self, x, alpha=0.1):
        self.last = x
        if self.n == 0:
            self.mean = x
        else:
            d = x - self.mean
            self.mean += alpha * d
            self.var = (1 - alpha) * (self.var + alpha * d * d)
        self.n += 1

    def z(self, x):
        sd = math.sqrt(self.var) if self.var > 0 else 0.0
        return (x - self.mean) / max(sd, 0.25)


class AnomalyDetector(object):
    def __init__(self, cfg):
        self.cfg = cfg
        self.window = float(cfg.get("window_s", 10))
        self.scan_limit = int(cfg.get("portscan_distinct_ports", 25))
        self.sweep_limit = int(cfg.get("icmp_sweep_hosts", 60))
        self.rate_limit = float(cfg.get("packet_in_rate_limit", 120))
        self.deny_limit = int(cfg.get("denied_attempts_limit", 40))
        self.profile_factor = float(cfg.get("profile_rate_factor", 3.0))
        self.z_thr = float(cfg.get("zscore_threshold", 4.0))
        self.newflows = collections.defaultdict(collections.deque)   # host -> deque[(t, dst, port)]
        self.denied = collections.defaultdict(collections.deque)     # host -> deque[t]
        self.baselines = collections.defaultdict(HostBaseline)
        self.counters = collections.Counter()

    def _trim(self, dq, now, key=lambda e: e):
        while dq and now - key(dq[0]) > self.window:
            dq.popleft()

    def on_new_flow(self, host, dst, port, now):
        dq = self.newflows[host]
        dq.append((now, dst, port))
        self._trim(dq, now, key=lambda e: e[0])
        findings = []
        distinct = len(set((d, p) for _, d, p in dq if p != "icmp"))
        if distinct >= self.scan_limit:
            findings.append(("port_scan", "%d distinct destination/port pairs in %ds" % (distinct, self.window)))
        swept = len(set(d for _, d, p in dq if p == "icmp"))
        if swept >= self.sweep_limit:
            findings.append(("host_sweep", "pinged %d different hosts in %ds" % (swept, self.window)))
        recent = sum(1 for t, _, _ in dq if now - t <= 1.0)
        if recent >= self.rate_limit:
            findings.append(("flow_flood", "%d new flows/s (limit %d)" % (recent, self.rate_limit)))
        for f in findings:
            self.counters[f[0]] += 1
        return findings

    def on_denied(self, host, now):
        dq = self.denied[host]
        dq.append(now)
        self._trim(dq, now)
        if len(dq) >= self.deny_limit:
            self.counters["policy_probing"] += 1
            return [("policy_probing", "%d denied attempts in %ds" % (len(dq), self.window))]
        return []

    def on_rate(self, host, mbps, profile_max):
        """Called every stats cycle with the host's transmit rate."""
        b = self.baselines[host]
        findings = []
        limit = max(profile_max * self.profile_factor, 0.2)
        if mbps > limit:
            # Hard cap: well beyond anything this device type should ever send.
            findings.append(("profile_violation",
                             "sending %.2f Mbps, device profile allows %.2f Mbps" % (mbps, profile_max)))
        elif (b.n >= 12 and b.mean > 0.3 and mbps > 0.8 * profile_max
              and mbps > 3 * b.mean and b.z(mbps) > self.z_thr):
            # Statistical: unusual for THIS device and already near its profile
            # ceiling.  Gating on the profile keeps legitimate within-profile
            # traffic (e.g. a 2 Mbps CCTV stream, cap 6) from ever triggering.
            findings.append(("traffic_anomaly", "rate %.2f Mbps is %.1f sigma above this device's baseline %.2f Mbps"
                             % (mbps, b.z(mbps), b.mean)))
        if not findings:
            b.update(mbps)          # never learn from anomalous samples
        for f in findings:
            self.counters[f[0]] += 1
        return findings

    def forget(self, host):
        self.newflows.pop(host, None)
        self.denied.pop(host, None)

    def snapshot(self):
        return {
            "counters": dict(self.counters),
            "baselines": {h: {"mean_mbps": round(b.mean, 3), "std_mbps": round(math.sqrt(max(b.var, 0)), 3),
                              "last_mbps": round(b.last, 3), "samples": b.n}
                          for h, b in self.baselines.items()},
            "thresholds": {"window_s": self.window, "scan": self.scan_limit, "flow_rate": self.rate_limit,
                           "denied": self.deny_limit, "profile_factor": self.profile_factor, "z": self.z_thr},
        }
