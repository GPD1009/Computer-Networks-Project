"""
Live network state shared by the controller, the applications and the twin.
(Everything runs in eventlet green threads, so no locking is needed.)
"""
import collections
import time


class NetworkState(object):
    HISTORY = 150                     # samples kept per link (~5 min at 2 s)

    def __init__(self, model):
        self.model = model
        self.started = time.time()
        self.connected = {}           # switch name -> connect timestamp
        self.port_up = {}             # (switch, port) -> bool
        self.link_up = {l["id"]: False for l in model.links}
        self.link_load = {}           # (a, b) -> Mbps in direction a->b
        self.util_history = {l["id"]: collections.deque(maxlen=self.HISTORY) for l in model.links}
        self.link_flaps = collections.Counter()
        self.link_drops = collections.Counter()
        self.discovered = set()       # link ids confirmed by LLDP
        self.unexpected_links = set() # LLDP links that are not in the inventory
        self.host_loc = {n: (h["switch"], h["port"]) for n, h in model.hosts.items()}
        self.host_seen = {}           # host -> last packet timestamp
        self.host_rate = {}           # host -> Mbps transmitted
        self.flows = {}               # flow key -> record dict
        self.quarantine = {}          # host -> {reason, ts, auto}
        self.unknown_devices = {}     # mac -> info
        self.alerts = collections.deque(maxlen=300)
        self.events = collections.deque(maxlen=300)
        self.denied_log = collections.deque(maxlen=200)
        self.counters = collections.Counter()
        self.routing_mode = "policy"
        self.byod_meter_kbps = None
        self.policy_history = []
        self._alert_seq = 0

    # -------------------------------------------------------------- logging
    def alert(self, severity, category, message, host=None):
        self._alert_seq += 1
        a = {"id": self._alert_seq, "ts": time.time(), "severity": severity,
             "category": category, "message": message, "host": host}
        self.alerts.appendleft(a)
        return a

    def event(self, category, message, **extra):
        e = {"ts": time.time(), "category": category, "message": message}
        e.update(extra)
        self.events.appendleft(e)
        return e

    # -------------------------------------------------------------- queries
    def link_util(self, link):
        a, b = link["a"], link["b"]
        load = max(self.link_load.get((a, b), 0.0), self.link_load.get((b, a), 0.0))
        return load / link["bw"]

    def flows_on_link(self, link_id):
        return [f for f in self.flows.values() if link_id in f.get("links", ())]

    def online_hosts(self, horizon=120):
        now = time.time()
        return [h for h, t in self.host_seen.items() if now - t < horizon]
