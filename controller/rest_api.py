"""
Northbound REST API (application <-> control layer interface) and dashboard
web server.  Runs inside the controller as an eventlet WSGI green thread.
"""
import json
import mimetypes
import os
import re
import time
import traceback
from urllib.parse import parse_qs

from os_ken.lib import hub

HERE = os.path.dirname(os.path.abspath(__file__))
DASHBOARD = os.path.join(os.path.dirname(HERE), "dashboard")


class HttpError(Exception):
    def __init__(self, code, msg):
        super(HttpError, self).__init__(msg)
        self.code, self.msg = code, msg


class RestApi(object):
    def __init__(self, ctl, port=8080):
        self.ctl = ctl
        self.port = port
        self.routes = []
        r = self.route
        r("GET", r"/api/summary", self.summary)
        r("GET", r"/api/topology", self.topology)
        r("GET", r"/api/flows", self.flows)
        r("GET", r"/api/links", self.links)
        r("GET", r"/api/alerts", self.alerts)
        r("GET", r"/api/events", self.events)
        r("GET", r"/api/policy", self.get_policy)
        r("GET", r"/api/policy/matrix", self.policy_matrix)
        r("GET", r"/api/policy/history", self.policy_history)
        r("POST", r"/api/policy/check", self.policy_check)
        r("POST", r"/api/policy/validate", self.policy_validate)
        r("POST", r"/api/policy/apply", self.policy_apply)
        r("POST", r"/api/policy/rollback", self.policy_rollback)
        r("GET", r"/api/security", self.security)
        r("POST", r"/api/quarantine", self.quarantine)
        r("POST", r"/api/release", self.release)
        r("GET", r"/api/routing", self.get_routing)
        r("POST", r"/api/routing", self.set_routing)
        r("GET", r"/api/qos", self.qos)
        r("GET", r"/api/twin/status", self.twin_status)
        r("GET", r"/api/twin/intents", self.twin_intents)
        r("POST", r"/api/twin/whatif/failure", self.whatif_failure)
        r("POST", r"/api/twin/whatif/traffic", self.whatif_traffic)
        r("GET", r"/api/twin/compare", self.twin_compare)
        r("GET", r"/api/twin/forecast", self.twin_forecast)
        r("GET", r"/api/twin/snapshot", self.twin_snapshot)
        r("GET", r"/api/ai/qlearning", self.ai_qlearning)
        r("GET", r"/api/ai/anomaly", self.ai_anomaly)

    def route(self, method, pattern, fn):
        self.routes.append((method, re.compile("^%s$" % pattern), fn))

    def serve(self):
        hub.sleep(1)
        try:
            server = hub.WSGIServer(("0.0.0.0", self.port), self)
            self.ctl.logger.info("Dashboard + REST API on http://localhost:%d", self.port)
            server.serve_forever()
        except Exception as e:
            self.ctl.logger.error("REST API failed to start: %s", e)

    # ------------------------------------------------------------- WSGI
    def __call__(self, environ, start_response):
        method = environ["REQUEST_METHOD"]
        path = environ.get("PATH_INFO", "/")
        cors = [("Access-Control-Allow-Origin", "*"), ("Access-Control-Allow-Headers", "Content-Type"),
                ("Access-Control-Allow-Methods", "GET, POST, OPTIONS")]
        if method == "OPTIONS":
            start_response("204 No Content", cors)
            return [b""]
        if not path.startswith("/api/"):
            return self._static(path, start_response)
        query = {k: v[-1] for k, v in parse_qs(environ.get("QUERY_STRING", "")).items()}
        body = None
        if method == "POST":
            try:
                n = int(environ.get("CONTENT_LENGTH") or 0)
                raw = environ["wsgi.input"].read(n) if n else b""
                body = json.loads(raw.decode() or "{}")
            except ValueError:
                return self._json(start_response, 400, {"error": "invalid JSON body"}, cors)
        for m, rx, fn in self.routes:
            if m == method and rx.match(path):
                try:
                    return self._json(start_response, 200, fn(query, body or {}), cors)
                except HttpError as e:
                    return self._json(start_response, e.code, {"error": e.msg}, cors)
                except Exception as e:
                    self.ctl.logger.error("API %s %s failed: %s", method, path, traceback.format_exc())
                    return self._json(start_response, 500, {"error": str(e)}, cors)
        return self._json(start_response, 404, {"error": "no such endpoint"}, cors)

    @staticmethod
    def _json(start_response, code, obj, headers):
        data = json.dumps(obj, default=_default).encode()
        status = {200: "200 OK", 400: "400 Bad Request", 404: "404 Not Found", 409: "409 Conflict",
                  500: "500 Internal Server Error"}.get(code, "%d" % code)
        start_response(status, [("Content-Type", "application/json"), ("Cache-Control", "no-store")] + headers)
        return [data]

    def _static(self, path, start_response):
        if path in ("/", ""):
            path = "/index.html"
        full = os.path.normpath(os.path.join(DASHBOARD, path.lstrip("/")))
        if not full.startswith(DASHBOARD) or not os.path.isfile(full):
            start_response("404 Not Found", [("Content-Type", "text/plain")])
            return [b"not found"]
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        with open(full, "rb") as f:
            data = f.read()
        start_response("200 OK", [("Content-Type", ctype), ("Cache-Control", "no-cache")])
        return [data]

    # ------------------------------------------------------------- views
    def summary(self, q, b):
        c = self.ctl
        st, m = c.state, c.model
        sync = c.twin.sync_status()
        crit = sum(1 for a in st.alerts if a["severity"] == "critical" and time.time() - a["ts"] < 600)
        return {
            "campus": m.name, "uptime_s": round(time.time() - st.started),
            "switches": {"up": len(st.connected), "total": len(m.switches)},
            "links": {"up": sum(1 for v in st.link_up.values() if v), "total": len(m.links)},
            "hosts": {"online": len(st.online_hosts()), "total": len(m.hosts)},
            "flows": len(st.flows), "quarantined": len(st.quarantine),
            "unregistered": len(st.unknown_devices), "critical_alerts_10min": crit,
            "routing_mode": st.routing_mode, "byod_meter_kbps": st.byod_meter_kbps,
            "policy_version": c.policy.version, "twin_sync_score": sync["sync_score"],
            "twin_in_sync": sync["in_sync"], "counters": dict(st.counters),
            "peak_link_util": round(max([st.link_util(l) for l in m.links] or [0]), 3),
        }

    def topology(self, q, b):
        c = self.ctl
        st, m = c.state, c.model
        sw = [dict(v, connected=v["name"] in st.connected) for v in m.switches.values()]
        links = []
        for l in m.links:
            links.append(dict(l, up=st.link_up.get(l["id"], False), lldp=l["id"] in st.discovered,
                              util=round(st.link_util(l), 3),
                              load_ab=round(st.link_load.get((l["a"], l["b"]), 0), 3),
                              load_ba=round(st.link_load.get((l["b"], l["a"]), 0), 3),
                              flows=len(st.flows_on_link(l["id"]))))
        now = time.time()
        hosts = []
        for h in m.hosts.values():
            loc = st.host_loc[h["name"]]
            seen = st.host_seen.get(h["name"])
            hosts.append(dict(h, switch=loc[0], port=loc[1], online=bool(seen and now - seen < 120),
                              last_seen=seen, rate_mbps=round(st.host_rate.get(h["name"], 0), 3),
                              quarantined=h["name"] in st.quarantine,
                              moved=loc != (h["switch"], h["port"])))
        return {"switches": sw, "links": links, "hosts": hosts, "blocks": m.blocks, "slices": m.slices,
                "unregistered": list(st.unknown_devices.values())}

    def flows(self, q, b):
        out = []
        for f in self.ctl.state.flows.values():
            d = {k: v for k, v in f.items() if k != "key"}
            d["age_s"] = round(time.time() - f["created"], 1)
            out.append(d)
        out.sort(key=lambda f: -f.get("rate_mbps", 0))
        return {"flows": out[: int(q.get("limit", 300))], "total": len(out)}

    def links(self, q, b):
        st, m = self.ctl.state, self.ctl.model
        return {"links": [{"id": l["id"], "bw": l["bw"], "delay_ms": l["delay_ms"], "up": st.link_up.get(l["id"]),
                           "util": round(st.link_util(l), 3), "drops": st.link_drops.get(l["id"], 0),
                           "flaps": st.link_flaps.get(l["id"], 0),
                           "history": [round(u, 3) for _, u in list(st.util_history[l["id"]])[-60:]]}
                          for l in m.links]}

    def alerts(self, q, b):
        since = int(q.get("since", 0))
        return {"alerts": [a for a in self.ctl.state.alerts if a["id"] > since][:100]}

    def events(self, q, b):
        return {"events": list(self.ctl.state.events)[:100]}

    def get_policy(self, q, b):
        return self.ctl.policy.policy

    def policy_matrix(self, q, b):
        return self.ctl.policy.role_matrix()

    def policy_history(self, q, b):
        return {"history": [{"index": i, "version": h["version"], "ts": h["ts"], "source": h["source"]}
                            for i, h in enumerate(self.ctl.state.policy_history)]}

    def policy_check(self, q, b):
        m = self.ctl.model
        s, d = m.hosts.get(b.get("src")), m.hosts.get(b.get("dst"))
        if not s or not d:
            raise HttpError(400, "src and dst must be host names")
        port = b.get("port")
        dec = self.ctl.policy.evaluate(s, d, b.get("proto", "tcp"), int(port) if port not in (None, "") else None)
        out = dec.to_dict()
        if dec.allowed:
            qc = self.ctl.policy.qos(dec.qos)
            out["qos_detail"] = qc
            g = self.ctl.routing.build_graph(self.ctl.state.link_up, self.ctl.state.link_load)
            mode = self.ctl.twin.mode_for(dec.qos)
            p = self.ctl.routing.path(g, self.ctl.state.host_loc[s["name"]][0], self.ctl.state.host_loc[d["name"]][0], mode)
            out["path"], out["routing"] = p, mode
            out["latency_ms"] = round(self.ctl.routing.path_latency(g, p), 2) if p else None
        return out

    def policy_validate(self, q, b):
        return self.ctl.twin.validate_policy(b.get("policy", b))

    def policy_apply(self, q, b):
        cand = b.get("policy")
        if not isinstance(cand, dict):
            raise HttpError(400, "body must be {\"policy\": {...}, \"force\": false}")
        res = self.ctl.twin.validate_policy(cand)
        if not res.get("valid"):
            raise HttpError(400, "invalid policy: %s" % "; ".join(res["errors"]))
        if not res["deployable"] and not b.get("force"):
            return {"applied": False, "reason": "twin validation failed - intents violated", "validation": res}
        self.ctl.apply_policy(cand, source="dashboard" if not b.get("force") else "forced")
        return {"applied": True, "validation": res}

    def policy_rollback(self, q, b):
        hist = self.ctl.state.policy_history
        idx = b.get("index", len(hist) - 2)
        if not 0 <= idx < len(hist):
            raise HttpError(400, "nothing to roll back to")
        self.ctl.apply_policy(hist[idx]["policy"], source="rollback to #%d" % idx)
        return {"applied": True, "version": hist[idx]["version"]}

    def security(self, q, b):
        st = self.ctl.state
        return {"quarantine": st.quarantine, "unregistered": list(st.unknown_devices.values()),
                "denied": list(st.denied_log)[:60], "ids": self.ctl.ids.snapshot(),
                "auto_quarantine": self.ctl.policy.security.get("auto_quarantine", True)}

    def quarantine(self, q, b):
        h = b.get("host")
        if h not in self.ctl.model.hosts:
            raise HttpError(400, "unknown host")
        return {"ok": self.ctl.quarantine(h, b.get("reason", "manual quarantine by operator"), auto=False)}

    def release(self, q, b):
        return {"ok": self.ctl.release(b.get("host"))}

    def get_routing(self, q, b):
        return {"mode": self.ctl.state.routing_mode, "modes": list(self.ctl.routing.MODES)}

    def set_routing(self, q, b):
        mode = b.get("mode")
        if mode not in self.ctl.routing.MODES:
            raise HttpError(400, "mode must be one of %s" % (self.ctl.routing.MODES,))
        self.ctl.state.routing_mode = mode
        self.ctl.flush_all_flows()
        self.ctl.state.alert("info", "routing", "Routing strategy changed to '%s' - flows re-routed on demand" % mode)
        return {"mode": mode}

    def qos(self, q, b):
        st = self.ctl.state
        by_class = {}
        for f in st.flows.values():
            c = by_class.setdefault(f["qos"], {"flows": 0, "mbps": 0.0})
            c["flows"] += 1
            c["mbps"] = round(c["mbps"] + f.get("rate_mbps", 0), 3)
        return {"classes": self.ctl.policy.qos_classes, "live": by_class,
                "byod_meter_kbps": st.byod_meter_kbps,
                "meters_supported": sum(1 for v in self.ctl.meter_ok.values() if v),
                "queues": {"0": "best effort (min 30%)", "1": "real-time (min 50%, highest priority)",
                           "2": "bulk / BYOD (min 20%, lowest priority)"}}

    def twin_status(self, q, b):
        return self.ctl.twin.sync_status()

    def twin_intents(self, q, b):
        return self.ctl.twin.check_intents(cache=q.get("fresh") != "1")

    def whatif_failure(self, q, b):
        links = b.get("links") or []
        if not links:
            raise HttpError(400, "give {\"links\": [\"core1-ab1d\", ...]}")
        return self.ctl.twin.whatif_link_failure(links, synthetic=b.get("synthetic"))

    def whatif_traffic(self, q, b):
        return self.ctl.twin.whatif_traffic(b.get("demands", []), routing_mode=b.get("routing_mode"),
                                            synthetic=b.get("synthetic"))

    def twin_compare(self, q, b):
        synth = {"1": True, "0": False}.get(q.get("synthetic"))
        return self.ctl.twin.compare_routing(synthetic=synth, stress=float(q.get("stress", 1.0)))

    def twin_forecast(self, q, b):
        return self.ctl.twin.forecast(horizon_s=int(q.get("horizon", 60)))

    def twin_snapshot(self, q, b):
        return self.ctl.twin.snapshot()

    def ai_qlearning(self, q, b):
        node = q.get("node", "core1")
        return {"stats": self.ctl.qrouting.stats(), "node": node, "table": self.ctl.qrouting.table(node),
                "benchmark": self.ctl.ql_benchmark}

    def ai_anomaly(self, q, b):
        return self.ctl.ids.snapshot()


def _default(o):
    if isinstance(o, (set, tuple)):
        return list(o)
    return str(o)
