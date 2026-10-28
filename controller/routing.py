"""
Path computation for the campus fabric.

Modes
  hop       - fewest hops (what a static/legacy IGP would do)
  latency   - minimum estimated end-to-end delay (propagation + queueing)
  load      - congestion-aware: steers traffic away from hot links
  qlearning - multi-agent Q-routing (see qlearning.py)
  policy    - per-QoS-class strategy (real-time -> latency, bulk -> load ...)
"""
import networkx as nx

PKT_BITS = 1500 * 8


def link_latency_ms(delay_ms, bw_mbps, load_mbps):
    """Propagation + transmission + M/M/1 queueing delay estimate (one direction)."""
    bw = max(bw_mbps, 0.001)
    u = min(max(load_mbps, 0.0) / bw, 0.99)
    service_ms = PKT_BITS / (bw * 1e6) * 1000.0
    queue_ms = service_ms * u / (1.0 - u)
    if u > 0.95:                       # buffers filling up: netem/htb queue build-up
        queue_ms += 40.0 * (u - 0.95) / 0.04
    return delay_ms + service_ms + queue_ms


class RoutingEngine(object):
    MODES = ("policy", "hop", "latency", "load", "qlearning")

    def __init__(self, model, qlearner=None):
        self.model = model
        self.qlearner = qlearner

    # ------------------------------------------------------------ graph
    def build_graph(self, link_up, link_load, down_extra=(), extra_load=None):
        """
        link_up   : {link_id: bool}
        link_load : {(a, b): Mbps in direction a->b}
        down_extra: link ids to treat as failed (what-if)
        extra_load: {(a, b): Mbps} additional load (what-if)
        """
        g = nx.Graph()
        g.add_nodes_from(self.model.switches)
        extra_load = extra_load or {}
        for l in self.model.links:
            if not link_up.get(l["id"], True) or l["id"] in down_extra:
                continue
            a, b = l["a"], l["b"]
            ab = link_load.get((a, b), 0.0) + extra_load.get((a, b), 0.0)
            ba = link_load.get((b, a), 0.0) + extra_load.get((b, a), 0.0)
            load = max(ab, ba)
            util = load / l["bw"]
            g.add_edge(a, b, id=l["id"], bw=l["bw"], delay=l["delay_ms"], load=load, util=util,
                       lat=link_latency_ms(l["delay_ms"], l["bw"], load))
        return g

    @staticmethod
    def edge_cost(mode):
        if mode == "hop":
            return lambda u, v, d: 1.0
        if mode == "load":
            return lambda u, v, d: 1.0 + 25.0 * d["util"] ** 2 + (200.0 if d["util"] > 0.9 else 0.0) + d["lat"] / 10.0
        return lambda u, v, d: d["lat"]          # latency (default)

    def path(self, g, src, dst, mode="latency"):
        if src == dst:
            return [src]
        if src not in g or dst not in g:
            return None
        if mode == "qlearning" and self.qlearner is not None:
            p = self.qlearner.path(g, src, dst)
            if p:
                return p
            mode = "latency"
        try:
            return nx.shortest_path(g, src, dst, weight=self.edge_cost(mode))
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    @staticmethod
    def path_latency(g, path):
        if not path:
            return None
        return sum(g[a][b]["lat"] for a, b in zip(path, path[1:]))

    @staticmethod
    def path_bottleneck(g, path):
        if not path or len(path) < 2:
            return 0.0
        return max(g[a][b]["util"] for a, b in zip(path, path[1:]))

    @staticmethod
    def path_links(model, path):
        out = []
        for a, b in zip(path or [], (path or [])[1:]):
            l = model.link_between(a, b)
            if l:
                out.append(l["id"])
        return out

    def disjoint_paths(self, g, src, dst):
        try:
            return len(list(nx.edge_disjoint_paths(g, src, dst)))
        except Exception:
            return 0
