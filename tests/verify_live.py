#!/usr/bin/env python3
"""
Live verification against a running controller REST API (default :8080).
Run while the Mininet emulation is up.  Exits non-zero if a check fails.
"""
import json
import sys
import time
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
fails = []


def get(path):
    with urllib.request.urlopen(BASE + path, timeout=15) as r:
        return json.load(r)


def post(path, body):
    req = urllib.request.Request(BASE + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def check(name, cond, detail=""):
    print("  [%s] %s%s" % ("PASS" if cond else "FAIL", name, ("  -> " + detail) if detail else ""))
    if not cond:
        fails.append(name)


print("=== twin sync ===")
s = get("/api/twin/status")
print("  switches=%d/%d  links_up=%d/%d  lldp_verified=%d  hosts=%d/%d  score=%.0f%%  in_sync=%s" % (
    s["switches_connected"], s["switches_expected"], s["links_up"], s["links_expected"],
    s["links_lldp_verified"], s["hosts_seen"], s["hosts_expected"], s["sync_score"], s["in_sync"]))
check("all switches connected", s["switches_connected"] == s["switches_expected"])
check("all links up", s["links_up"] == s["links_expected"])
check("LLDP verified the inventory (twin == network)", s["links_lldp_verified"] == s["links_expected"],
      "%d/%d" % (s["links_lldp_verified"], s["links_expected"]))
check("no unexpected links / drift", not s["unexpected_links"])

print("=== zero-trust data-plane policy ===")
cases = [
    ("student laptop -> LMS", {"src": "ab3-lap1", "dst": "dc-lms", "proto": "tcp", "port": 80}, True, None),
    ("student laptop -> EXAM", {"src": "ab3-lap1", "dst": "dc-exam", "proto": "tcp", "port": 80}, False, None),
    ("lab PC -> EXAM", {"src": "ab2-lab1", "dst": "dc-exam", "proto": "tcp", "port": 80}, True, "critical"),
    ("IoT sensor -> CCTV", {"src": "ab2-iot1", "dst": "ab2-cam1", "proto": "tcp", "port": 80}, False, None),
    ("IoT sensor -> IoT hub", {"src": "ab2-iot1", "dst": "dc-iot", "proto": "udp", "port": 1883}, True, None),
    ("VoIP phone -> PBX", {"src": "ab1-phn1", "dst": "dc-pbx", "proto": "udp", "port": 5060}, True, "realtime"),
    ("CCTV -> NVR", {"src": "ab2-cam1", "dst": "dc-nvr", "proto": "udp", "port": 554}, True, "video"),
    ("CCTV -> Internet", {"src": "ab2-cam1", "dst": "dc-inet", "proto": "udp", "port": 80}, False, None),
]
for name, body, expect, qos in cases:
    r = post("/api/policy/check", body)
    ok = r["allowed"] == expect and (qos is None or r.get("qos") == qos)
    detail = "allowed=%s qos=%s path=%s" % (r["allowed"], r.get("qos"),
                                            "-".join(r["path"]) if r.get("path") else None)
    check(name, ok, detail)

print("=== intents (compliance) ===")
it = get("/api/twin/intents?fresh=1")
for i in it["intents"]:
    check("intent %s %s" % (i["id"], i["name"]), i["ok"],
          "violations: %s" % i["violations"][:2] if not i["ok"] else "")
check("overall compliant", it["compliant"])

print("=== what-if link failure ===")
r = post("/api/twin/whatif/failure", {"links": ["core1-ab4d"], "synthetic": True})
print("  core1-ab4d (AB4 dual-homed): verdict=%s isolated=%s rerouted=%d cut=%d" % (
    r["verdict"], r["isolated_blocks"], r["rerouted_count"], r["cut_count"]))
check("single core uplink failure does not isolate AB4", "AB4" not in r["isolated_blocks"])
r2 = post("/api/twin/whatif/failure", {"links": ["ab4d-ab4f1"], "synthetic": True})
print("  ab4d-ab4f1 (single access link): verdict=%s cut=%d" % (r2["verdict"], r2["cut_count"]))
check("access-link failure cuts single-homed hosts", r2["cut_count"] > 0 or r2["verdict"] != "safe")

print("=== routing comparison (2.5x synthetic stress) ===")
c = get("/api/twin/compare?synthetic=1&stress=2.5")
for m, x in c["modes"].items():
    print("  %-9s peak_util=%.2f  avg_lat=%s ms  reduction_vs_hop=%s%%  unroutable=%d" % (
        m, x["max_util"], x.get("avg_latency_ms"), x.get("latency_reduction_pct_vs_hop"), x["unroutable"]))
check("congestion-aware routing <= shortest-hop peak",
      c["modes"]["load"]["max_util"] <= c["modes"]["hop"]["max_util"] + 1e-6)

print("=== AI Q-routing ===")
q = get("/api/ai/qlearning")
print("  episodes=%d epsilon=%.3f agents=%d td_error=%s" % (
    q["stats"]["episodes"], q["stats"]["epsilon"], q["stats"]["agents"], q["stats"]["mean_td_error_ms"]))
check("q-learning trained on all switch-agents", q["stats"]["agents"] == s["switches_expected"])

print("=== security / quarantine round-trip ===")
post("/api/quarantine", {"host": "ab3-lap2", "reason": "verify_live test"})
sec = get("/api/security")
check("manual quarantine installed fabric-wide", "ab3-lap2" in sec["quarantine"])
post("/api/release", {"host": "ab3-lap2"})
check("release works", "ab3-lap2" not in get("/api/security")["quarantine"])

print("=== summary ===")
sm = get("/api/summary")
print("  flows=%d denied=%d installed=%d arp_proxy=%d quarantined=%d peak_util=%.2f routing=%s" % (
    sm["flows"], sm["counters"].get("denied", 0), sm["counters"].get("flows_installed", 0),
    sm["counters"].get("arp_proxy", 0), sm["quarantined"], sm["peak_link_util"], sm["routing_mode"]))

print()
if fails:
    print("RESULT: %d checks FAILED: %s" % (len(fails), ", ".join(fails)))
    sys.exit(1)
print("RESULT: all live checks passed")
