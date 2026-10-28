"""
Campus model - the single source of truth for the digital twin.

Both the Mininet emulation (infrastructure layer) and the SDN controller
(control layer) load config/campus.json through this module, so switch
DPIDs, port numbers, IP and MAC addresses are derived identically on
both sides.  Pure Python, no third-party dependencies.
"""
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CAMPUS = os.path.join(ROOT, "config", "campus.json")
DEFAULT_POLICIES = os.path.join(ROOT, "config", "policies.json")


def ip_to_mac(ip):
    """10.1.2.41 -> 02:00:0a:01:02:29 (locally administered, derived from IP)."""
    return "02:00:" + ":".join("%02x" % int(o) for o in ip.split("."))


def load_json(path):
    with open(path) as f:
        return json.load(f)


class CampusModel(object):
    def __init__(self, path=DEFAULT_CAMPUS):
        self.path = path
        self.raw = load_json(path)
        self.name = self.raw.get("campus", "Campus")
        self.blocks = self.raw["blocks"]
        self.slices = self.raw["slices"]
        self.device_types = self.raw["device_types"]
        self.controller = self.raw.get("controller", {})
        self.emulator_api_port = self.raw.get("emulator_api_port", 8081)
        self.host_link = self.raw.get("host_link", {"bw": 100, "delay_ms": 0.5})

        self.switches = {}          # name -> dict
        self.dpid_to_name = {}
        for s in self.raw["switches"]:
            sw = dict(s)
            sw.setdefault("floor", None)
            self.switches[sw["name"]] = sw
            self.dpid_to_name[sw["dpid"]] = sw["name"]

        # Deterministic port numbering: inter-switch links first, then hosts.
        next_port = {name: 1 for name in self.switches}
        self.links = []             # list of dict
        self.port_map = {}          # (switch, port) -> ("switch", peer, peer_port) | ("host", host)
        for i, l in enumerate(self.raw["links"]):
            a, b = l["a"], l["b"]
            ap, bp = next_port[a], next_port[b]
            next_port[a] += 1
            next_port[b] += 1
            link = {
                "id": "%s-%s" % (a, b), "a": a, "b": b, "a_port": ap, "b_port": bp,
                "bw": float(l.get("bw", 100)), "delay_ms": float(l.get("delay_ms", 1)),
            }
            self.links.append(link)
            self.port_map[(a, ap)] = ("switch", b, bp)
            self.port_map[(b, bp)] = ("switch", a, ap)

        self.hosts = {}
        self.ip_to_host = {}
        self.mac_to_host = {}
        for idx, h in enumerate(self.raw["hosts"]):
            dtype = self.device_types[h["type"]]
            sw = self.switches[h["switch"]]
            host = {
                "name": h["name"],
                "id": idx + 1,
                "type": h["type"],
                "type_label": dtype["label"],
                "label": h.get("label", dtype["label"]),
                "role": h.get("role", dtype["role"]),
                "slice": h.get("slice", dtype["slice"]),
                "icon": dtype.get("icon", "pc"),
                "max_mbps": float(h.get("max_mbps", dtype.get("max_mbps", 100))),
                "ip": h["ip"],
                "mac": h.get("mac", ip_to_mac(h["ip"])),
                "block": sw["block"],
                "switch": h["switch"],
                "port": next_port[h["switch"]],
            }
            next_port[h["switch"]] += 1
            self.hosts[host["name"]] = host
            self.ip_to_host[host["ip"]] = host["name"]
            self.mac_to_host[host["mac"]] = host["name"]
            self.port_map[(h["switch"], host["port"])] = ("host", host["name"])

        self.link_by_ports = {}     # (switch, port) -> link dict
        for l in self.links:
            self.link_by_ports[(l["a"], l["a_port"])] = l
            self.link_by_ports[(l["b"], l["b_port"])] = l

    # ------------------------------------------------------------------ helpers
    def dpid(self, switch_name):
        return self.switches[switch_name]["dpid"]

    def switch_name(self, dpid):
        return self.dpid_to_name.get(dpid, "dpid:%s" % dpid)

    def link_between(self, a, b):
        for l in self.links:
            if (l["a"], l["b"]) in ((a, b), (b, a)):
                return l
        return None

    def port_towards(self, a, b):
        """Port on switch a that connects to neighbour switch b."""
        l = self.link_between(a, b)
        if l is None:
            return None
        return l["a_port"] if l["a"] == a else l["b_port"]

    def neighbours(self, sw):
        out = []
        for l in self.links:
            if l["a"] == sw:
                out.append(l["b"])
            elif l["b"] == sw:
                out.append(l["a"])
        return out

    def hosts_by_role(self, role):
        return [h for h in self.hosts.values() if h["role"] == role]

    def roles(self):
        return sorted(set(h["role"] for h in self.hosts.values()))

    def summary(self):
        return {
            "campus": self.name,
            "blocks": len([b for b in self.blocks if b.startswith("AB")]),
            "switches": len(self.switches),
            "links": len(self.links),
            "hosts": len(self.hosts),
        }


if __name__ == "__main__":
    m = CampusModel()
    print(m.summary())
    for h in m.hosts.values():
        print("%-9s %-22s %-11s %-13s %-6s %s:%d" % (h["name"], h["type_label"], h["role"],
                                                     h["slice"], h["block"], h["switch"], h["port"]))
