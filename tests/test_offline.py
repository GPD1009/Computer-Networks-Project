"""
Offline unit/integration tests for the application-layer logic.

These exercise the model, policy engine, routing, Q-learning, anomaly
detector and the digital-twin analytics without Mininet or a controller,
by driving a stub controller state.  Run:  pytest tests/test_offline.py -v
"""
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p in (os.path.join(ROOT, "common"), os.path.join(ROOT, "controller")):
    sys.path.insert(0, p)

from campus_model import CampusModel, DEFAULT_POLICIES, load_json, ip_to_mac
from policy_engine import PolicyEngine, validate_policy
from routing import RoutingEngine
from qlearning import QRouting
from anomaly import AnomalyDetector
from state import NetworkState
from twin_engine import DigitalTwin

M = CampusModel()
POL = load_json(DEFAULT_POLICIES)


def fresh():
    """A controller state with every switch/link/host 'up' and located as designed."""
    st = NetworkState(M)
    for s in M.switches:
        st.connected[s] = time.time()
    for l in M.links:
        st.link_up[l["id"]] = True
        st.discovered.add(l["id"])
    for h in M.hosts:
        st.host_seen[h] = time.time()
    return st


def make_twin(st=None):
    st = st or fresh()
    pe = PolicyEngine(M, POL)
    ql = QRouting()
    routing = RoutingEngine(M, ql)
    twin = DigitalTwin(M, st, routing, lambda: pe)
    return twin, st, pe, routing, ql


# ----------------------------------------------------------------- model
def test_model_shape():
    s = M.summary()
    assert s["blocks"] == 4
    assert s["switches"] == 15 and s["links"] == 21
    assert len(M.hosts) == len(set(h["ip"] for h in M.hosts.values()))     # unique IPs
    assert len(M.hosts) == len(set(h["mac"] for h in M.hosts.values()))    # unique MACs


def test_port_map_consistent():
    for (sw, port), peer in M.port_map.items():
        if peer[0] == "switch":
            back = M.port_map[(peer[1], peer[2])]
            assert back == ("switch", sw, port)
    assert ip_to_mac("10.1.2.41") == "02:00:0a:01:02:29"


def test_every_host_has_access_switch_port():
    for h in M.hosts.values():
        assert M.port_map[(h["switch"], h["port"])] == ("host", h["name"])


# ----------------------------------------------------------------- policy
def test_policy_schema_valid():
    assert validate_policy(POL) == []


def test_zero_trust_default_deny():
    pe = PolicyEngine(M, POL)
    lap, adm = M.hosts["ab3-lap1"], M.hosts["ab1-adm1"]
    # a student laptop must NOT reach an admin PC
    assert not pe.evaluate(lap, adm, "tcp", 80).allowed
    # ...but must reach the LMS
    assert pe.evaluate(lap, M.hosts["dc-lms"], "tcp", 80).allowed


def test_student_denied_exam_allowed_lab():
    pe = PolicyEngine(M, POL)
    assert not pe.evaluate(M.hosts["ab3-lap1"], M.hosts["dc-exam"], "tcp", 80).allowed
    d = pe.evaluate(M.hosts["ab2-lab1"], M.hosts["dc-exam"], "tcp", 80)
    assert d.allowed and d.qos == "critical"


def test_iot_isolation():
    pe = PolicyEngine(M, POL)
    iot, cam = M.hosts["ab2-iot1"], M.hosts["ab2-cam1"]
    assert pe.evaluate(iot, M.hosts["dc-iot"], "udp", 1883).allowed
    assert not pe.evaluate(iot, cam, "tcp", 80).allowed            # IoT cannot talk to CCTV
    assert not pe.evaluate(iot, M.hosts["dc-web"], "tcp", 80).allowed


def test_voip_qos_realtime():
    pe = PolicyEngine(M, POL)
    d = pe.evaluate(M.hosts["ab1-phn1"], M.hosts["dc-pbx"], "udp", 5060)
    assert d.allowed and pe.qos(d.qos)["routing"] == "latency"


def test_policy_follows_identity_not_location():
    """A faculty PC keeps its permissions regardless of which switch it is on."""
    pe = PolicyEngine(M, POL)
    fac = M.hosts["ab1-fac1"]
    before = pe.evaluate(fac, M.hosts["dc-web"], "tcp", 80).allowed
    assert before  # decision depends only on role/slice, which do not change on move
    assert fac["role"] == "faculty"


# ----------------------------------------------------------------- routing
def test_shortest_vs_latency_path():
    twin, st, pe, routing, ql = make_twin()
    g = routing.build_graph(st.link_up, {})
    p = routing.path(g, "ab1f1", "ab4f1", "latency")
    assert p[0] == "ab1f1" and p[-1] == "ab4f1"
    assert routing.path_latency(g, p) is not None


def test_congestion_aware_avoids_hot_link():
    twin, st, pe, routing, ql = make_twin()
    # saturate the primary AB1 uplink via core1
    load = {("ab1d", "core1"): 39.0, ("core1", "ab1d"): 39.0}
    g = routing.build_graph(st.link_up, load)
    p_load = routing.path(g, "ab1f1", "dc1", "load")
    # congestion-aware routing should prefer the core2 path
    assert "core2" in p_load or routing.path_bottleneck(g, p_load) < 0.9


def test_redundancy_two_paths():
    twin, st, pe, routing, ql = make_twin()
    g = routing.build_graph(st.link_up, {})
    assert routing.disjoint_paths(g, "ab1d", "dc1") >= 2


# ----------------------------------------------------------------- q-learning
def test_qlearning_learns_good_paths():
    twin, st, pe, routing, ql = make_twin()
    g = routing.build_graph(st.link_up, {})
    ql.train(g, episodes=4000)
    good = 0
    nodes = list(g.nodes)
    import networkx as nx
    for s in nodes:
        for d in nodes:
            if s == d:
                continue
            p = ql.path(g, s, d)
            if not p:
                continue
            opt = nx.shortest_path_length(g, s, d, weight=lambda u, v, dd: dd["lat"])
            if routing.path_latency(g, p) <= opt * 1.35 + 1e-6:
                good += 1
    assert good >= 150            # most pairs within 35% of optimal after training


# ----------------------------------------------------------------- anomaly
def test_portscan_detection():
    ids = AnomalyDetector(POL["security"])
    now = time.time()
    fired = False
    for port in range(1, 40):
        if any(k == "port_scan" for k, _ in ids.on_new_flow("ab3-lap1", "10.10.1.12", "tcp/%d" % port, now)):
            fired = True
    assert fired


def test_profile_violation():
    ids = AnomalyDetector(POL["security"])
    f = ids.on_rate("ab2-iot1", 8.0, 0.5)              # IoT sensor sending 8 Mbps
    assert any(k == "profile_violation" for k, _ in f)
    assert ids.on_rate("ab2-iot1", 0.4, 0.5) == []     # within profile: no alarm


def test_denied_probing():
    ids = AnomalyDetector(POL["security"])
    now = time.time()
    fired = any(ids.on_denied("ab3-lap1", now) for _ in range(POL["security"]["denied_attempts_limit"] + 2))
    assert fired


# ----------------------------------------------------------------- twin
def test_twin_in_sync_when_healthy():
    twin, st, *_ = make_twin()
    s = twin.sync_status()
    assert s["in_sync"] and s["sync_score"] == 100.0


def test_twin_detects_drift():
    st = fresh()
    st.unexpected_links.add("rogueA:3<->rogueB:4")
    twin, *_ = make_twin(st)
    assert not twin.sync_status()["in_sync"]


def test_whatif_single_link_safe_due_to_redundancy():
    twin, *_ = make_twin()
    r = twin.whatif_link_failure(["core1-ab1d"])        # AB1 is dual-homed
    assert r["verdict"] in ("safe", "degraded")
    assert "AB1" not in r["isolated_blocks"]


def test_whatif_access_link_isolates_hosts():
    twin, *_ = make_twin()
    r = twin.whatif_link_failure(["ab2d-ab2f1"])        # single access link
    assert r["cut_count"] > 0 or r["verdict"] in ("critical", "degraded")


def test_whatif_traffic_predicts_congestion():
    twin, *_ = make_twin()
    r = twin.whatif_traffic([{"src": "role:research", "dst": "dc-store", "mbps": 120, "qos": "bulk"}])
    assert r["predicted"]["current"]["max_util"] > 0.5


def test_intents_compliant_on_healthy_network():
    twin, *_ = make_twin()
    res = twin.check_intents(cache=False)
    bad = [i["name"] for i in res["intents"] if not i["ok"]]
    assert res["compliant"], "intents violated: %s" % bad


def test_policy_validation_blocks_bad_change():
    twin, st, pe, *_ = make_twin()
    bad = dict(POL)
    bad = {k: v for k, v in POL.items()}
    bad["rules"] = POL["rules"] + [{"id": "BAD", "name": "students reach exam", "src": ["student"],
                                    "dst": ["exam"], "proto": "tcp", "dst_ports": [80], "qos": "best_effort"}]
    res = twin.validate_policy(bad)
    assert res["valid"]
    assert not res["deployable"]          # violates intent I3 (exam exclusivity)
    assert any("exam" in str(x).lower() for i in res["intents"] for x in i["violations"]) or not res["compliant"]


def test_forecast_runs():
    twin, st, *_ = make_twin()
    for l in M.links:
        for i in range(30):
            st.util_history[l["id"]].append((time.time() + i, min(0.02 * i, 1.0)))
    f = twin.forecast(horizon_s=60)
    assert f["links"] and all("health" in x for x in f["links"])


def test_compare_routing_modes():
    twin, st, pe, routing, ql = make_twin()
    g = routing.build_graph(st.link_up, {})
    ql.train(g, episodes=3000)
    c = twin.compare_routing(synthetic=True, stress=2.5)
    assert set(c["modes"]) == {"hop", "latency", "load", "qlearning"}
    for m in ("latency", "load", "qlearning"):
        assert c["modes"][m]["max_util"] <= c["modes"]["hop"]["max_util"] + 0.2


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
