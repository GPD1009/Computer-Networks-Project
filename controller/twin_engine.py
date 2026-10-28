"""
Digital Twin engine.

The Mininet emulation is a high-fidelity replica of the campus; this module
is the analytical twin that the controller keeps synchronised with it in
real time (topology, link state, utilisation, active flows, policies).
It lets operators *safely* ask "what if" before touching the live network:

  * sync_status()          - is the twin in sync with the network? (drift)
  * whatif_link_failure()  - impact of losing links: rerouted / cut flows,
                             predicted utilisation, latency, isolated blocks
  * whatif_traffic()       - add traffic load, predict congestion & delay
  * compare_routing()      - predict KPIs for every routing strategy
  * validate_policy()      - verify a candidate policy against intents
  * check_intents()        - continuous compliance of the live network
  * forecast()             - utilisation trend, time-to-congestion and
                             predictive-maintenance health scores
"""
import copy
import time

from policy_engine import PolicyEngine, validate_policy
from routing import link_latency_ms

# typical demand per device type when no live traffic is present (Mbps)
SYNTHETIC_PROFILE = {
    "fac": ("web", 1.0, "best_effort"),
    "adm": ("web", 0.5, "best_effort"),
    "lab": ("lms", 1.5, "best_effort"),
    "kio": ("lms", 0.5, "best_effort"),
    "lap": ("internet", 2.0, "byod"),
    "rws": ("storage", 6.0, "bulk"),
    "phn": ("pbx", 0.1, "realtime"),
    "cam": ("nvr", 2.0, "video"),
    "iot": ("iothub", 0.02, "best_effort"),
    "brd": ("lms", 1.0, "best_effort"),
}
PRIORITY = {"realtime": 0, "critical": 1, "video": 2, "best_effort": 3, "byod": 4, "bulk": 5}


class DigitalTwin(object):
    def __init__(self, model, state, routing, get_policy):
        self.model = model
        self.state = state
        self.routing = routing
        self.get_policy = get_policy          # callable -> live PolicyEngine
        self._intent_cache = (0, None)

    # ============================================================ helpers
    def mode_for(self, qos, routing_mode=None):
        routing_mode = routing_mode or self.state.routing_mode
        pe = self.get_policy()
        if routing_mode != "policy":
            return routing_mode
        m = pe.qos(qos).get("routing", "default")
        if m == "default":
            m = pe.te.get("default_routing", "latency")
        return m

    def graph(self, down=(), load=None):
        return self.routing.build_graph(self.state.link_up,
                                        self.state.link_load if load is None else load, down)

    def _add_path_load(self, load, path, mbps):
        for a, b in zip(path, path[1:]):
            load[(a, b)] = load.get((a, b), 0.0) + mbps

    def demand_set(self, synthetic=None):
        """Live flows (with measured rates) or a synthetic campus traffic matrix."""
        flows = [f for f in self.state.flows.values() if f.get("path")]
        use_synth = synthetic if synthetic is not None else not flows
        if not use_synth:
            return [dict(src=f["src"], dst=f["dst"], src_sw=f["path"][0], dst_sw=f["path"][-1],
                         mbps=max(f.get("rate_mbps", 0.0), 0.01), qos=f.get("qos", "best_effort"),
                         path=list(f["path"]), live=True) for f in flows], False
        demands = []
        for h in self.model.hosts.values():
            prof = SYNTHETIC_PROFILE.get(h["type"])
            if not prof:
                continue
            role, mbps, qos = prof
            targets = self.model.hosts_by_role(role)
            if not targets:
                continue
            t = targets[0]
            if t["name"] == h["name"]:
                continue
            demands.append(dict(src=h["name"], dst=t["name"], src_sw=self.state.host_loc[h["name"]][0],
                                dst_sw=self.state.host_loc[t["name"]][0], mbps=mbps, qos=qos, path=None, live=False))
        return demands, True

    def _route_demands(self, demands, down=(), routing_mode=None, base_load=None):
        """Incrementally route demands (high priority first). Returns (paths, load, cut)."""
        load = dict(base_load or {})
        paths, cut = {}, []
        g0 = self.graph(down=down, load=load)
        order = sorted(range(len(demands)), key=lambda i: PRIORITY.get(demands[i]["qos"], 9))
        for i in order:
            d = demands[i]
            keep = d.get("path")
            if keep and routing_mode is None and all(g0.has_edge(a, b) for a, b in zip(keep, keep[1:])):
                p = keep
            else:
                g = self.graph(down=down, load=load)
                p = self.routing.path(g, d["src_sw"], d["dst_sw"], self.mode_for(d["qos"], routing_mode))
            if p is None:
                cut.append(i)
                continue
            paths[i] = p
            self._add_path_load(load, p, d["mbps"])
        return paths, load, cut

    def _kpis(self, demands, paths, load, down=()):
        g = self.graph(down=down, load=load)
        utils = {}
        for l in self.model.links:
            if g.has_edge(l["a"], l["b"]):
                utils[l["id"]] = round(g[l["a"]][l["b"]]["util"], 3)
        lat_all, lat_rt = [], []
        for i, p in paths.items():
            lat = sum(link_latency_ms(g[a][b]["delay"], g[a][b]["bw"], max(load.get((a, b), 0), 0))
                      for a, b in zip(p, p[1:]))
            lat_all.append(lat)
            if demands[i]["qos"] in ("realtime", "critical"):
                lat_rt.append(lat)
        return {
            "max_util": max(utils.values()) if utils else 0.0,
            "congested_links": sorted([k for k, v in utils.items() if v > 0.9]),
            "link_util": utils,
            "avg_latency_ms": round(sum(lat_all) / len(lat_all), 2) if lat_all else None,
            "avg_realtime_latency_ms": round(sum(lat_rt) / len(lat_rt), 2) if lat_rt else None,
            "max_realtime_latency_ms": round(max(lat_rt), 2) if lat_rt else None,
        }

    def _residual_load(self, demands):
        """Measured load not explained by tracked flows (background, LLDP...)."""
        tracked = {}
        for d in demands:
            if d.get("live") and d.get("path"):
                self._add_path_load(tracked, d["path"], d["mbps"])
        return {k: max(0.0, v - tracked.get(k, 0.0)) for k, v in self.state.link_load.items()}

    # ============================================================ sync / drift
    def sync_status(self):
        st, m = self.state, self.model
        missing_sw = [s for s in m.switches if s not in st.connected]
        missing_links = [l["id"] for l in m.links if not st.link_up.get(l["id"])]
        undiscovered = [l["id"] for l in m.links if st.link_up.get(l["id"]) and l["id"] not in st.discovered]
        moved = [{"host": h, "expected": "%s:%d" % (m.hosts[h]["switch"], m.hosts[h]["port"]),
                  "actual": "%s:%d" % loc} for h, loc in st.host_loc.items()
                 if loc != (m.hosts[h]["switch"], m.hosts[h]["port"])]
        total = len(m.switches) + len(m.links)
        ok = total - len(missing_sw) - len(missing_links)
        return {
            "in_sync": not (missing_sw or missing_links or st.unexpected_links or st.unknown_devices),
            "sync_score": round(100.0 * ok / total, 1) if total else 100.0,
            "switches_connected": len(st.connected), "switches_expected": len(m.switches),
            "links_up": len(m.links) - len(missing_links), "links_expected": len(m.links),
            "links_lldp_verified": len(st.discovered),
            "hosts_seen": len(st.host_seen), "hosts_expected": len(m.hosts),
            "missing_switches": missing_sw, "down_links": missing_links,
            "lldp_unverified_links": undiscovered,
            "unexpected_links": sorted(st.unexpected_links),
            "unregistered_devices": list(st.unknown_devices.values()),
            "relocated_hosts": moved,
        }

    # ============================================================ what-if: failure
    def whatif_link_failure(self, link_ids, synthetic=None):
        link_ids = [l for l in link_ids if any(x["id"] == l for x in self.model.links)]
        demands, synth = self.demand_set(synthetic)
        base_paths, base_load, _ = self._route_demands(demands, base_load=self._residual_load(demands) if not synth else {})
        before = self._kpis(demands, base_paths, base_load)

        residual = self._residual_load(demands) if not synth else {}
        for lid in link_ids:                    # residual on failed links disappears/reroutes: drop it
            l = next(x for x in self.model.links if x["id"] == lid)
            residual.pop((l["a"], l["b"]), None)
            residual.pop((l["b"], l["a"]), None)
        failed = set(link_ids)
        new_paths, new_load, cut = self._route_demands(
            [dict(d, path=(d["path"] if d.get("path") and not (set(self.routing.path_links(self.model, d["path"])) & failed) else None))
             for d in demands], down=failed, base_load=residual)
        after = self._kpis(demands, new_paths, new_load, down=failed)

        rerouted = []
        for i, d in enumerate(demands):
            old = base_paths.get(i)
            if old and set(self.routing.path_links(self.model, old)) & failed and i in new_paths:
                rerouted.append({"src": d["src"], "dst": d["dst"], "qos": d["qos"],
                                 "old_path": old, "new_path": new_paths[i]})
        cut_flows = [{"src": demands[i]["src"], "dst": demands[i]["dst"], "qos": demands[i]["qos"]} for i in cut]

        g = self.graph(down=failed)
        isolated, spof = [], []
        for b in [b for b in self.model.blocks if b.startswith("AB")]:
            dist = next(s for s, v in self.model.switches.items() if v["block"] == b and v["tier"] == "distribution")
            if not g.has_node(dist) or not self._connected(g, dist, "dc1"):
                isolated.append(b)
            elif self.routing.disjoint_paths(g, dist, "dc1") < 2:
                spof.append(b)

        lat_bound = self._intent_param("latency", "max_ms", 25)
        issues, recs = [], []
        if isolated:
            issues.append("Blocks isolated from the data centre: %s" % ", ".join(isolated))
            recs.append("Do NOT apply: schedule maintenance only after adding a temporary bypass link.")
        if cut_flows:
            issues.append("%d flows would lose connectivity" % len(cut_flows))
        if after["congested_links"]:
            issues.append("Links predicted above 90%%: %s" % ", ".join(after["congested_links"]))
            recs.append("Switch routing to 'load' (congestion-aware) or rate-limit bulk/BYOD before the change.")
        if after["max_realtime_latency_ms"] and after["max_realtime_latency_ms"] > lat_bound:
            issues.append("Real-time latency %.1f ms exceeds %d ms bound" % (after["max_realtime_latency_ms"], lat_bound))
        if spof:
            issues.append("Blocks left without redundancy: %s" % ", ".join(spof))
            recs.append("Keep the maintenance window short - %s become single-homed." % ", ".join(spof))
        verdict = "critical" if (isolated or cut_flows) else ("degraded" if issues else "safe")
        if verdict == "safe":
            recs.append("Change is safe: traffic re-converges onto redundant paths with no SLA violation.")
        return {"failed_links": link_ids, "synthetic_traffic": synth, "verdict": verdict,
                "issues": issues, "recommendations": recs, "before": before, "after": after,
                "rerouted": rerouted[:50], "rerouted_count": len(rerouted),
                "cut": cut_flows[:50], "cut_count": len(cut_flows),
                "isolated_blocks": isolated, "single_homed_blocks": spof, "demands": len(demands)}

    @staticmethod
    def _connected(g, a, b):
        import networkx as nx
        return nx.has_path(g, a, b)

    # ============================================================ what-if: load
    def _resolve_switches(self, spec):
        spec = str(spec)
        if spec in self.model.hosts:
            return [self.state.host_loc[spec][0]]
        if spec in self.model.switches:
            return [spec]
        if spec in self.model.blocks:
            sws = [s for s, v in self.model.switches.items() if v["block"] == spec and v["tier"] in ("access",)]
            return sws or [s for s, v in self.model.switches.items() if v["block"] == spec]
        if spec.startswith("role:"):
            return sorted(set(self.state.host_loc[h["name"]][0] for h in self.model.hosts_by_role(spec[5:])))
        return []

    def whatif_traffic(self, extra, routing_mode=None, synthetic=None):
        """extra: [{src, dst, mbps, qos}] - src/dst may be host, switch, block or role:<r>."""
        demands, synth = self.demand_set(synthetic)
        residual = self._residual_load(demands) if not synth else {}
        base_paths, base_load, _ = self._route_demands(demands, base_load=residual)
        before = self._kpis(demands, base_paths, base_load)
        added = []
        for e in extra:
            srcs, dsts = self._resolve_switches(e.get("src")), self._resolve_switches(e.get("dst"))
            pairs = [(s, d) for s in srcs for d in dsts if s != d]
            if not pairs:
                continue
            share = float(e.get("mbps", 1)) / len(pairs)
            for s, d in pairs:
                added.append(dict(src=e.get("src"), dst=e.get("dst"), src_sw=s, dst_sw=d, mbps=share,
                                  qos=e.get("qos", "best_effort"), path=None, live=False))
        allp = demands + added
        results = {}
        for mode in ([routing_mode] if routing_mode else [None, "hop", "load"]):
            paths, load, cut = self._route_demands(allp, routing_mode=mode, base_load=residual)
            k = self._kpis(allp, paths, load)
            k["unroutable"] = len(cut)
            results[mode or "current"] = k
        cur = results.get("current") or next(iter(results.values()))
        recs = []
        if cur["congested_links"]:
            recs.append("Predicted congestion on %s." % ", ".join(cur["congested_links"]))
            if "load" in results and results["load"]["max_util"] < cur["max_util"] - 0.05:
                recs.append("Congestion-aware routing would cut peak utilisation from %.0f%% to %.0f%%."
                            % (cur["max_util"] * 100, results["load"]["max_util"] * 100))
            recs.append("Consider metering BYOD/bulk classes or upgrading the hottest uplink.")
        else:
            recs.append("Network can absorb this load (peak %.0f%%)." % (cur["max_util"] * 100))
        if "hop" in results and cur["max_util"] < results["hop"]["max_util"]:
            recs.append("A static shortest-hop network would peak at %.0f%% for the same load."
                        % (results["hop"]["max_util"] * 100))
        return {"added_demands": len(added), "synthetic_traffic": synth, "before": before,
                "predicted": results, "recommendations": recs}

    def compare_routing(self, synthetic=None, stress=1.0):
        demands, synth = self.demand_set(synthetic)
        if stress != 1.0:
            demands = [dict(d, mbps=d["mbps"] * stress, path=None) for d in demands]
        out = {}
        for mode in ("hop", "latency", "load", "qlearning"):
            paths, load, cut = self._route_demands([dict(d, path=None) for d in demands], routing_mode=mode)
            k = self._kpis(demands, paths, load)
            k.pop("link_util", None)
            k["unroutable"] = len(cut)
            out[mode] = k
        base = out["hop"]["avg_latency_ms"]
        for mode, k in out.items():
            if base and k["avg_latency_ms"]:
                k["latency_reduction_pct_vs_hop"] = round(100.0 * (base - k["avg_latency_ms"]) / base, 1)
        return {"synthetic_traffic": synth, "stress": stress, "demands": len(demands), "modes": out}

    # ============================================================ intents
    def _intent_param(self, itype, key, default):
        for i in self.get_policy().intents:
            if i.get("type") == itype:
                return i.get(key, default)
        return default

    def check_intents(self, pe=None, down=(), cache=True):
        if pe is None and cache and time.time() - self._intent_cache[0] < 10 and not down:
            return self._intent_cache[1]
        live = pe is None
        pe = pe or self.get_policy()
        g = self.graph(down=down)
        hosts = list(self.model.hosts.values())
        reach = pe.reachability(hosts)
        results = []
        for it in pe.intents:
            t, viol = it.get("type"), []
            if t == "isolation":
                for (s, d), svc in reach.items():
                    hs, hd = self.model.hosts[s], self.model.hosts[d]
                    if pe.matches(it["src"], hs) and not pe.matches(it.get("allowed_dst", []), hd):
                        viol.append("%s -> %s (%s)" % (s, d, ",".join(svc)))
            elif t == "exclusive":
                for (s, d), svc in reach.items():
                    hs, hd = self.model.hosts[s], self.model.hosts[d]
                    if pe.matches(it["dst"], hd) and not pe.matches(it.get("allowed_src", []), hs):
                        viol.append("%s -> %s (%s)" % (s, d, ",".join(svc)))
            elif t == "reachability":
                for hs in hosts:
                    if not pe.matches(it["src"], hs):
                        continue
                    for hd in hosts:
                        if hd is hs or not pe.matches(it["dst"], hd):
                            continue
                        ok = pe.evaluate(hs, hd, it.get("proto", "icmp"), it.get("port")).allowed
                        a, b = self.state.host_loc[hs["name"]][0], self.state.host_loc[hd["name"]][0]
                        if ok and not self._connected(g, a, b):
                            ok = False
                        if not ok:
                            viol.append("%s cannot reach %s" % (hs["name"], hd["name"]))
            elif t == "latency":
                bound = it.get("max_ms", 25)
                rt_sw = sorted(set(self.state.host_loc[h["name"]][0] for h in hosts if h["role"] in ("voip", "faculty", "smartboard")))
                for a in rt_sw:
                    for b in rt_sw + ["dc1"]:
                        if a >= b:
                            continue
                        p = self.routing.path(g, a, b, "latency")
                        lat = self.routing.path_latency(g, p) if p else None
                        if lat is None or lat > bound:
                            viol.append("%s <-> %s: %s ms" % (a, b, "unreachable" if lat is None else round(lat, 1)))
            elif t == "capacity":
                mu = it.get("max_util", 0.9)
                for l in self.model.links:
                    u = self.state.link_util(l)
                    if u > mu:
                        viol.append("%s at %.0f%%" % (l["id"], u * 100))
            elif t == "redundancy":
                need = it.get("min_paths", 2)
                for b in [b for b in self.model.blocks if b.startswith("AB")]:
                    dist = next(s for s, v in self.model.switches.items() if v["block"] == b and v["tier"] == "distribution")
                    n = self.routing.disjoint_paths(g, dist, "dc1") if g.has_node(dist) else 0
                    if n < need:
                        viol.append("%s has %d disjoint path(s) to DC" % (b, n))
            results.append({"id": it.get("id"), "name": it.get("name"), "type": t, "ok": not viol,
                            "violations": viol[:12], "violation_count": len(viol)})
        out = {"ts": time.time(), "compliant": all(r["ok"] for r in results), "intents": results,
               "allowed_pairs": len(reach)}
        if live and not down:
            self._intent_cache = (time.time(), out)
        return out

    def validate_policy(self, candidate):
        errors = validate_policy(candidate)
        if errors:
            return {"valid": False, "errors": errors, "deployable": False}
        cur = self.get_policy()
        new = PolicyEngine(self.model, candidate)
        res = self.check_intents(pe=new, cache=False)
        old_r, new_r = cur.reachability(), new.reachability()

        def flat(r):
            return set((s, d, svc) for (s, d), svcs in r.items() for svc in svcs)
        a, b = flat(old_r), flat(new_r)

        def summarise(items):
            agg = {}
            for s, d, svc in items:
                k = (self.model.hosts[s]["role"], self.model.hosts[d]["role"], svc)
                agg[k] = agg.get(k, 0) + 1
            return [{"src_role": k[0], "dst_role": k[1], "service": k[2], "host_pairs": v}
                    for k, v in sorted(agg.items(), key=lambda kv: -kv[1])][:40]
        return {"valid": True, "errors": [], "intents": res["intents"], "compliant": res["compliant"],
                "deployable": res["compliant"],
                "newly_allowed": summarise(b - a), "newly_denied": summarise(a - b),
                "allowed_pairs_before": len(old_r), "allowed_pairs_after": len(new_r)}

    # ============================================================ forecasting
    @staticmethod
    def _holt(series, alpha=0.5, beta=0.3):
        if not series:
            return 0.0, 0.0
        level, trend = series[0], 0.0
        for x in series[1:]:
            prev = level
            level = alpha * x + (1 - alpha) * (level + trend)
            trend = beta * (level - prev) + (1 - beta) * trend
        return level, trend

    def forecast(self, horizon_s=60, sample_s=2.0, threshold=0.9):
        out = []
        steps = horizon_s / sample_s
        for l in self.model.links:
            hist = [u for _, u in self.state.util_history[l["id"]]]
            level, trend = self._holt(hist[-60:])
            pred = max(0.0, level + trend * steps)
            tt = None
            if trend > 1e-4 and level < threshold:
                tt = round((threshold - level) / trend * sample_s, 1)
            elif level >= threshold:
                tt = 0.0
            flaps = self.state.link_flaps.get(l["id"], 0)
            health = 100.0
            health -= min(40.0, max(0.0, level - 0.6) * 100)          # sustained high load
            health -= min(30.0, flaps * 10.0)                         # instability
            health -= 20.0 if (tt is not None and tt < horizon_s) else 0.0
            if not self.state.link_up.get(l["id"]):
                health = 0.0
            status = "ok" if health >= 75 else ("watch" if health >= 45 else "action")
            out.append({"link": l["id"], "util_now": round(level, 3), "trend_per_min": round(trend * 60 / sample_s, 3),
                        "util_forecast": round(min(pred, 2.0), 3), "seconds_to_congestion": tt,
                        "flaps": flaps, "health": round(max(health, 0.0), 1), "status": status,
                        "samples": len(hist)})
        out.sort(key=lambda r: r["health"])
        return {"horizon_s": horizon_s, "threshold": threshold, "links": out}

    # ============================================================ snapshot
    def snapshot(self):
        st = self.state
        return {
            "ts": time.time(),
            "model": self.model.summary(),
            "routing_mode": st.routing_mode,
            "link_up": dict(st.link_up),
            "link_load": {"%s>%s" % k: round(v, 3) for k, v in st.link_load.items()},
            "host_loc": {h: "%s:%d" % v for h, v in st.host_loc.items()},
            "quarantine": copy.deepcopy(st.quarantine),
            "flows": [{k: v for k, v in f.items() if k not in ("match",)} for f in st.flows.values()],
            "policy": self.get_policy().policy,
        }
