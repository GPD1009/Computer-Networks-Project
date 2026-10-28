"""
Zero-Trust policy engine (SDN application layer).

* Default deny: nothing is reachable unless a rule allows it.
* Rules are written against *identities* (device role, role group, slice or
  host name) - never against switch ports or locations - so a policy
  "follows" a device wherever it connects on campus.
* Every allow decision carries a QoS class, which the controller turns into
  a DSCP mark, an egress queue, an optional meter and a routing strategy.
"""

PROTO_NUM = {"icmp": 1, "tcp": 6, "udp": 17}
NUM_PROTO = {v: k for k, v in PROTO_NUM.items()}


class Decision(object):
    __slots__ = ("allowed", "rule_id", "rule_name", "qos", "reason")

    def __init__(self, allowed, rule_id=None, rule_name=None, qos=None, reason=""):
        self.allowed = allowed
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.qos = qos
        self.reason = reason

    def to_dict(self):
        return {"allowed": self.allowed, "rule_id": self.rule_id, "rule_name": self.rule_name,
                "qos": self.qos, "reason": self.reason}


def _port_in(port, specs):
    for s in specs:
        if isinstance(s, int):
            if port == s:
                return True
        else:
            lo, _, hi = str(s).partition("-")
            if hi and int(lo) <= port <= int(hi):
                return True
            if not hi and port == int(lo):
                return True
    return False


def validate_policy(policy):
    """Return a list of schema problems (empty list == valid)."""
    errors = []
    if not isinstance(policy, dict):
        return ["policy must be a JSON object"]
    rules = policy.get("rules")
    if not isinstance(rules, list) or not rules:
        errors.append("'rules' must be a non-empty list")
        rules = []
    classes = policy.get("qos_classes", {})
    groups = policy.get("groups", {})
    seen = set()
    for i, r in enumerate(rules):
        rid = r.get("id", "#%d" % i)
        if rid in seen:
            errors.append("duplicate rule id %s" % rid)
        seen.add(rid)
        for f in ("src", "dst"):
            if not isinstance(r.get(f), list) or not r.get(f):
                errors.append("%s: '%s' must be a non-empty list" % (rid, f))
            else:
                for spec in r[f]:
                    if isinstance(spec, str) and spec.startswith("@") and spec[1:] not in groups:
                        errors.append("%s: unknown group %s" % (rid, spec))
        if r.get("proto", "any") not in ("any", "tcp", "udp", "icmp"):
            errors.append("%s: proto must be any/tcp/udp/icmp" % rid)
        if r.get("qos") and r["qos"] not in classes:
            errors.append("%s: unknown qos class %s" % (rid, r["qos"]))
    return errors


class PolicyEngine(object):
    def __init__(self, model, policy):
        self.model = model
        self.policy = policy
        self.version = policy.get("version", 1)
        self.groups = policy.get("groups", {})
        self.rules = policy.get("rules", [])
        self.qos_classes = policy.get("qos_classes", {})
        self.intents = policy.get("intents", [])
        self.security = policy.get("security", {})
        self.te = policy.get("traffic_engineering", {})

    # ------------------------------------------------------------- matching
    def _match_spec(self, spec, host):
        if spec == "*":
            return True
        if spec.startswith("@"):
            return host["role"] in self.groups.get(spec[1:], [])
        if spec.startswith("slice:"):
            return host["slice"] == spec[6:]
        if spec.startswith("host:"):
            return host["name"] == spec[5:]
        if spec.startswith("block:"):
            return host["block"] == spec[6:]
        return host["role"] == spec

    def matches(self, specs, host):
        return any(self._match_spec(s, host) for s in specs)

    def evaluate(self, src, dst, proto, dst_port=None):
        """src/dst are host dicts from CampusModel; proto is 'tcp'|'udp'|'icmp'."""
        if src["name"] == dst["name"]:
            return Decision(False, reason="loopback")
        for r in self.rules:
            rp = r.get("proto", "any")
            if rp != "any" and rp != proto:
                continue
            ports = r.get("dst_ports")
            if ports and proto in ("tcp", "udp"):
                if dst_port is None or not _port_in(dst_port, ports):
                    continue
            if not self.matches(r["src"], src) or not self.matches(r["dst"], dst):
                continue
            ss = r.get("same_slice")
            if ss is not None:
                if src["slice"] != dst["slice"]:
                    continue
                if isinstance(ss, list) and src["slice"] not in ss:
                    continue
            return Decision(True, r.get("id"), r.get("name"), r.get("qos", "best_effort"),
                            "allowed by %s (%s)" % (r.get("id"), r.get("name")))
        return Decision(False, reason="default deny (zero trust): no rule allows %s/%s %s -> %s"
                        % (proto, dst_port if dst_port is not None else "-", src["role"], dst["role"]))

    def qos(self, name):
        return self.qos_classes.get(name or "best_effort", {"queue": 0, "dscp": 0, "routing": "default"})

    # ------------------------------------------------------------- analysis
    def probes(self):
        """Representative (proto, port) services used for reachability analysis."""
        out = {("icmp", None)}
        for r in self.rules:
            p = r.get("proto", "any")
            ports = r.get("dst_ports") or []
            protos = ["tcp", "udp"] if p == "any" else [p]
            for pr in protos:
                if pr == "icmp":
                    continue
                if ports:
                    for port in ports:
                        if isinstance(port, int):
                            out.add((pr, port))
                        else:
                            out.add((pr, int(str(port).split("-")[0])))
                else:
                    out.add((pr, 80))
        return sorted(out, key=lambda x: (x[0], x[1] or 0))

    def reachability(self, hosts=None):
        """{(src, dst): [ 'tcp/80', ... ]} for every allowed service between two hosts."""
        hosts = hosts or list(self.model.hosts.values())
        probes = self.probes()
        by_name = any(str(spec).startswith("host:") for r in self.rules for spec in r["src"] + r["dst"])

        def sig(h):  # decisions only depend on these attributes
            return h["name"] if by_name else (h["role"], h["slice"], h["block"])
        cache, res = {}, {}
        for s in hosts:
            for d in hosts:
                if s is d:
                    continue
                key = (sig(s), sig(d))
                allowed = cache.get(key)
                if allowed is None:
                    allowed = []
                    for proto, port in probes:
                        if self.evaluate(s, d, proto, port).allowed:
                            allowed.append("%s/%s" % (proto, port) if port else proto)
                    cache[key] = allowed
                if allowed:
                    res[(s["name"], d["name"])] = allowed
        return res

    def role_matrix(self):
        """Role x role summary of allowed services (for the dashboard)."""
        reps = {}
        for h in self.model.hosts.values():
            reps.setdefault(h["role"], h)
        roles = sorted(reps)
        probes = self.probes()
        matrix = {}
        for sr in roles:
            row = {}
            for dr in roles:
                svc = []
                s = reps[sr]
                # pick a destination different from the source when the role has 2+ hosts
                cands = [h for h in self.model.hosts.values() if h["role"] == dr and h["name"] != s["name"]]
                if not cands:
                    row[dr] = []
                    continue
                d = cands[0]
                for proto, port in probes:
                    if self.evaluate(s, d, proto, port).allowed:
                        svc.append("%s/%s" % (proto, port) if port else proto)
                row[dr] = svc
            matrix[sr] = row
        return {"roles": roles, "matrix": matrix}
