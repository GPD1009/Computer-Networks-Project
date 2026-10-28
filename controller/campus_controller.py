"""
Campus SDN Controller  (control layer of the three-tier SDN architecture)

    Application layer : policy_engine (Zero Trust / slicing), anomaly (IDS),
                        twin_engine (digital twin), qlearning (AI routing),
                        rest_api + dashboard (northbound interface)
    Control layer     : this os-ken application - global view, path
                        computation, flow programming, QoS, monitoring
    Infrastructure    : Open vSwitch switches emulated by Mininet

Run with:
    osken-manager --observe-links controller/campus_controller.py
"""
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for p in (HERE, os.path.join(ROOT, "common")):
    if p not in sys.path:
        sys.path.insert(0, p)

from os_ken.base import app_manager                                  # noqa: E402
from os_ken.controller import ofp_event                              # noqa: E402
from os_ken.controller.handler import (CONFIG_DISPATCHER, DEAD_DISPATCHER,  # noqa: E402
                                       MAIN_DISPATCHER, set_ev_cls)
from os_ken.lib import hub                                           # noqa: E402
from os_ken.lib.packet import arp, ethernet, ether_types, icmp, ipv4, packet, tcp, udp  # noqa: E402
from os_ken.ofproto import ofproto_v1_3                              # noqa: E402
from os_ken.topology import event as topo_event                      # noqa: E402

from campus_model import DEFAULT_CAMPUS, DEFAULT_POLICIES, CampusModel, load_json  # noqa: E402
from policy_engine import PROTO_NUM, PolicyEngine                    # noqa: E402
from routing import RoutingEngine                                    # noqa: E402
from qlearning import QRouting                                       # noqa: E402
from anomaly import AnomalyDetector                                  # noqa: E402
from state import NetworkState                                       # noqa: E402
from twin_engine import DigitalTwin                                  # noqa: E402
from rest_api import RestApi                                         # noqa: E402

app_manager.require_app("os_ken.topology.switches", api_style=False)

PRIO_QUARANTINE = 65000
PRIO_ROGUE = 60000
PRIO_DENY = 25000
PRIO_FLOW = 20000
PRIO_IPV6 = 100

T_MASK = 0xFF << 56
C_FLOW = 0x01 << 56
C_DENY = 0x02 << 56
C_QUAR = 0x03 << 56
C_ROGUE = 0x04 << 56
C_BASE = 0x05 << 56

IDLE_FLOW = 20
IDLE_ICMP = 10
IDLE_DENY = 10
BYOD_METER = 1


class CampusController(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(CampusController, self).__init__(*args, **kwargs)
        self.model = CampusModel(os.environ.get("CAMPUS_CONFIG", DEFAULT_CAMPUS))
        pol = load_json(os.environ.get("CAMPUS_POLICY", DEFAULT_POLICIES))
        self.policy = PolicyEngine(self.model, pol)
        self.state = NetworkState(self.model)
        self.state.policy_history.append({"version": pol.get("version", 1), "ts": time.time(),
                                          "source": "startup", "policy": pol})
        self.qrouting = QRouting()
        self.routing = RoutingEngine(self.model, self.qrouting)
        self.twin = DigitalTwin(self.model, self.state, self.routing, lambda: self.policy)
        self.ids = AnomalyDetector(self.policy.security)
        self.datapaths = {}
        self.meter_ok = {}
        self.port_prev = {}
        self.flow_prev = {}
        self.ql_benchmark = None
        self.state.byod_meter_kbps = self.policy.te.get("byod_meter_kbps", {}).get("normal", 10000)
        self.rest = RestApi(self, int(self.model.controller.get("rest_port", 8080)))
        self.threads = [hub.spawn(self._monitor_loop), hub.spawn(self._te_loop),
                        hub.spawn(self._ml_loop), hub.spawn(self.rest.serve)]
        self.logger.info("Campus SDN controller ready: %s", self.model.summary())

    # ================================================================ helpers
    def _dp(self, sw):
        return self.datapaths.get(self.model.dpid(sw))

    def host(self, name):
        return self.model.hosts.get(name)

    def _add_flow(self, dp, priority, match, actions=None, inst=None, idle=0, hard=0, cookie=0, flags=0):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        if inst is None:
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)] if actions else []
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=priority, match=match, instructions=inst,
                                      idle_timeout=idle, hard_timeout=hard, cookie=cookie, flags=flags))

    def _del_flows(self, dp, cookie, mask, match=None, strict=False, priority=0):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        dp.send_msg(parser.OFPFlowMod(datapath=dp, cookie=cookie, cookie_mask=mask, table_id=ofp.OFPTT_ALL,
                                      command=ofp.OFPFC_DELETE_STRICT if strict else ofp.OFPFC_DELETE,
                                      priority=priority, out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                                      match=match or parser.OFPMatch()))

    def _packet_out(self, dp, msg, in_port, port=None):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        actions = [parser.OFPActionOutput(port if port is not None else ofp.OFPP_TABLE)]
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
                                        actions=actions, data=data))

    def _for_host_cookies(self, base, hid):
        return [(base | (hid << 16), T_MASK | (0xFFFF << 16)), (base | hid, T_MASK | 0xFFFF)]

    # ================================================================ switch lifecycle
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        name = self.model.switch_name(dp.id)
        self.datapaths[dp.id] = dp
        self.state.connected[name] = time.time()
        for c in (C_FLOW, C_DENY, C_QUAR, C_ROGUE, C_BASE):          # stale state from a previous run
            self._del_flows(dp, c, T_MASK)
        self._add_flow(dp, 0, parser.OFPMatch(),
                       [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)], cookie=C_BASE)
        self._add_flow(dp, PRIO_IPV6, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6), [], cookie=C_BASE)
        if self.model.switches.get(name, {}).get("tier") in ("access", "distribution"):
            self.meter_ok[dp.id] = True
            self._set_meter(dp, self.state.byod_meter_kbps, ofp.OFPMC_ADD)
        for h in self.state.quarantine:
            self._install_quarantine(dp, h)
        dp.send_msg(parser.OFPPortDescStatsRequest(dp, 0))
        self.state.event("switch", "Switch %s (dpid %d) connected" % (name, dp.id))

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change(self, ev):
        dp = ev.datapath
        if ev.state == DEAD_DISPATCHER and dp.id in self.datapaths:
            name = self.model.switch_name(dp.id)
            del self.datapaths[dp.id]
            self.state.connected.pop(name, None)
            self.state.alert("critical", "topology", "Switch %s disconnected from controller" % name)
            self._update_links()

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def _port_desc(self, ev):
        dp = ev.msg.datapath
        name = self.model.switch_name(dp.id)
        ofp = dp.ofproto
        for p in ev.msg.body:
            if p.port_no > ofp.OFPP_MAX:
                continue
            self.state.port_up[(name, p.port_no)] = not (p.state & ofp.OFPPS_LINK_DOWN) and \
                not (p.config & ofp.OFPPC_PORT_DOWN)
        self._update_links()

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status(self, ev):
        msg = ev.msg
        dp, ofp, p = msg.datapath, msg.datapath.ofproto, msg.desc
        name = self.model.switch_name(dp.id)
        up = msg.reason != ofp.OFPPR_DELETE and not (p.state & ofp.OFPPS_LINK_DOWN) and \
            not (p.config & ofp.OFPPC_PORT_DOWN)
        self.state.port_up[(name, p.port_no)] = up
        self._update_links()

    def _update_links(self):
        st = self.state
        for l in self.model.links:
            up = (l["a"] in st.connected and l["b"] in st.connected and
                  st.port_up.get((l["a"], l["a_port"]), False) and st.port_up.get((l["b"], l["b_port"]), False))
            if up != st.link_up.get(l["id"]):
                was_known = l["a"] in st.connected and l["b"] in st.connected
                st.link_up[l["id"]] = up
                if not up:
                    st.link_load.pop((l["a"], l["b"]), None)
                    st.link_load.pop((l["b"], l["a"]), None)
                    if was_known or st.flows_on_link(l["id"]):
                        st.link_flaps[l["id"]] += 1
                        self._on_link_down(l)
                else:
                    st.event("topology", "Link %s is UP" % l["id"])
                    if st.link_flaps.get(l["id"]):
                        st.alert("info", "topology", "Link %s restored - traffic engineering will re-optimise" % l["id"])

    # LLDP discovery (os_ken.topology.switches) - used to verify the twin
    @set_ev_cls(topo_event.EventLinkAdd)
    def _lldp_link_add(self, ev):
        s, d = ev.link.src, ev.link.dst
        a, b = self.model.switch_name(s.dpid), self.model.switch_name(d.dpid)
        l = self.model.link_by_ports.get((a, s.port_no))
        if l and {l["a"], l["b"]} == {a, b}:
            if l["id"] not in self.state.discovered:
                self.state.discovered.add(l["id"])
        else:
            key = "%s:%d<->%s:%d" % (a, s.port_no, b, d.port_no)
            if key not in self.state.unexpected_links:
                self.state.unexpected_links.add(key)
                self.state.alert("warning", "twin", "Discovered link %s is not in the digital-twin inventory (drift)" % key)

    @set_ev_cls(topo_event.EventLinkDelete)
    def _lldp_link_del(self, ev):
        s = ev.link.src
        l = self.model.link_by_ports.get((self.model.switch_name(s.dpid), s.port_no))
        if l:
            self.state.discovered.discard(l["id"])

    # ================================================================ meters (dynamic bandwidth)
    def _set_meter(self, dp, kbps, command):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        bands = [parser.OFPMeterBandDrop(rate=int(kbps), burst_size=int(kbps // 8) or 1)]
        dp.send_msg(parser.OFPMeterMod(datapath=dp, command=command, flags=ofp.OFPMF_KBPS | ofp.OFPMF_BURST,
                                       meter_id=BYOD_METER, bands=bands))

    @set_ev_cls(ofp_event.EventOFPErrorMsg, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def _error(self, ev):
        msg = ev.msg
        ofp = msg.datapath.ofproto
        if msg.type == ofp.OFPET_METER_MOD_FAILED:
            if msg.code != ofp.OFPMMFC_METER_EXISTS:
                self.meter_ok[msg.datapath.id] = False
                self.logger.warning("meters unsupported on dpid %s - BYOD metering disabled there", msg.datapath.id)
            else:
                self._set_meter(msg.datapath, self.state.byod_meter_kbps, ofp.OFPMC_MODIFY)
            return
        self.logger.warning("OpenFlow error from %s: type=%s code=%s", self.model.switch_name(msg.datapath.id),
                            msg.type, msg.code)

    # ================================================================ packet-in
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype in (ether_types.ETH_TYPE_LLDP, ether_types.ETH_TYPE_IPV6):
            return
        self.state.counters["packet_in"] += 1
        sw = self.model.switch_name(dp.id)
        edge = (sw, in_port) not in self.model.link_by_ports
        src = self.model.mac_to_host.get(eth.src)
        now = time.time()

        if edge:
            if src is None:
                return self._rogue_device(dp, sw, in_port, eth, pkt)
            self._learn(src, sw, in_port, now)
        elif src is None:
            return
        if src in self.state.quarantine:
            return

        a = pkt.get_protocol(arp.arp)
        if a is not None:
            return self._handle_arp(dp, in_port, eth, a, src, edge)
        ip = pkt.get_protocol(ipv4.ipv4)
        if ip is not None:
            return self._handle_ipv4(msg, dp, sw, in_port, pkt, ip, src, edge, now)

    def _learn(self, host, sw, port, now):
        st = self.state
        old = st.host_loc.get(host)
        st.host_seen[host] = now
        if old != (sw, port):
            st.host_loc[host] = (sw, port)
            self._flush_host_flows(host)
            h = self.host(host)
            st.alert("info", "mobility",
                     "%s (%s) moved %s:%d -> %s:%d - identity-based policy (%s / %s slice) follows the device"
                     % (host, h["label"], old[0], old[1], sw, port, h["role"], h["slice"]), host=host)

    def _rogue_device(self, dp, sw, port, eth, pkt):
        st = self.state
        if not self.policy.security.get("block_unregistered_devices", True):
            return
        info = st.unknown_devices.get(eth.src)
        if info is None:
            ip = pkt.get_protocol(ipv4.ipv4) or pkt.get_protocol(arp.arp)
            claimed = getattr(ip, "src", None) or getattr(ip, "src_ip", None)
            info = {"mac": eth.src, "switch": sw, "port": port, "block": self.model.switches[sw]["block"],
                    "claimed_ip": claimed, "first_seen": time.time(), "packets": 0}
            st.unknown_devices[eth.src] = info
            st.alert("critical", "zero-trust",
                     "Unregistered device %s (claims %s) on %s port %d blocked - not in identity inventory"
                     % (eth.src, claimed, sw, port))
            parser = dp.ofproto_parser
            self._add_flow(dp, PRIO_ROGUE, parser.OFPMatch(in_port=port, eth_src=eth.src), [],
                           cookie=C_ROGUE, hard=300)
        info["packets"] += 1

    # ---------------------------------------------------------------- ARP (proxy)
    def _handle_arp(self, dp, in_port, eth, a, src, edge):
        h = self.host(src)
        if edge and a.src_ip != h["ip"] and a.src_ip != "0.0.0.0":
            self._security_event(src, "arp_spoofing", "ARP claims %s but %s is registered as %s"
                                 % (a.src_ip, src, h["ip"]))
            return
        if a.opcode != arp.ARP_REQUEST or not edge:
            return
        tgt = self.model.ip_to_host.get(a.dst_ip)
        if tgt is None:
            return
        th = self.host(tgt)
        self.state.counters["arp_proxy"] += 1
        p = packet.Packet()
        p.add_protocol(ethernet.ethernet(dst=eth.src, src=th["mac"], ethertype=ether_types.ETH_TYPE_ARP))
        p.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=th["mac"], src_ip=th["ip"],
                               dst_mac=a.src_mac, dst_ip=a.src_ip))
        p.serialize()
        ofp, parser = dp.ofproto, dp.ofproto_parser
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=ofp.OFPP_CONTROLLER,
                                        actions=[parser.OFPActionOutput(in_port)], data=p.data))

    # ---------------------------------------------------------------- IPv4
    def _handle_ipv4(self, msg, dp, sw, in_port, pkt, ip, src, edge, now):
        st = self.state
        sh = self.host(src)
        if edge and ip.src != sh["ip"]:
            return self._security_event(src, "ip_spoofing", "sent packets with forged source %s (registered %s)"
                                        % (ip.src, sh["ip"]))
        dst = self.model.ip_to_host.get(ip.dst)
        if dst is None:
            return
        dh = self.host(dst)
        proto = {1: "icmp", 6: "tcp", 17: "udp"}.get(ip.proto)
        sport = dport = 0
        icmp_type = None
        if proto == "tcp":
            t = pkt.get_protocol(tcp.tcp)
            sport, dport = t.src_port, t.dst_port
        elif proto == "udp":
            u = pkt.get_protocol(udp.udp)
            sport, dport = u.src_port, u.dst_port
        elif proto == "icmp":
            ic = pkt.get_protocol(icmp.icmp)
            icmp_type = ic.type if ic else 8
        key = (ip.src, ip.dst, ip.proto, sport, dport)
        rkey = (ip.dst, ip.src, ip.proto, dport, sport)
        if key in st.flows or rkey in st.flows:          # flow being installed / transit race
            return self._packet_out(dp, msg, in_port)
        if not edge:
            return
        if proto is None:
            return
        if proto == "icmp" and icmp_type == 0:            # stray echo-reply: never opens a flow
            return

        findings = self.ids.on_new_flow(src, ip.dst, "%s/%s" % (proto, dport) if proto != "icmp" else "icmp", now)
        if findings:
            for kind, detail in findings:
                self._security_event(src, kind, detail)
            if src in st.quarantine:
                return

        if dst in st.quarantine:
            decision_allowed, reason = False, "destination %s is quarantined" % dst
            dec = None
        else:
            dec = self.policy.evaluate(sh, dh, proto, dport if proto != "icmp" else None)
            decision_allowed, reason = dec.allowed, dec.reason
        match = self._match(ip.src, ip.dst, ip.proto, sport, dport, icmp_type)
        if not decision_allowed:
            st.counters["denied"] += 1
            st.denied_log.appendleft({"ts": now, "src": src, "dst": dst, "proto": proto,
                                      "port": dport if proto != "icmp" else None, "reason": reason})
            parser = dp.ofproto_parser
            self._add_flow(dp, PRIO_DENY, parser.OFPMatch(**match), [], idle=IDLE_DENY,
                           cookie=C_DENY | (sh["id"] << 16) | dh["id"])
            for kind, detail in self.ids.on_denied(src, now):
                self._security_event(src, kind, detail)
            return

        mode = self.twin.mode_for(dec.qos)
        g = self.routing.build_graph(st.link_up, st.link_load)
        s_sw, d_sw = st.host_loc[src][0], st.host_loc[dst][0]
        path = self.routing.path(g, s_sw, d_sw, mode)
        if path is None:
            st.alert("warning", "routing", "No path %s -> %s (%s -> %s)" % (src, dst, s_sw, d_sw))
            return
        rec = {"key": key, "id": "%s:%s>%s:%s/%s" % (ip.src, sport, ip.dst, dport, proto),
               "src": src, "dst": dst, "src_ip": ip.src, "dst_ip": ip.dst, "proto": proto,
               "sport": sport, "dport": dport, "icmp_type": icmp_type, "qos": dec.qos, "rule": dec.rule_id,
               "rule_name": dec.rule_name, "mode": mode, "path": path,
               "links": self.routing.path_links(self.model, path), "created": now, "rate_mbps": 0.0,
               "rev_rate_mbps": 0.0, "bytes": 0, "reroutes": 0,
               "latency_ms": round(self.routing.path_latency(g, path) or 0, 2)}
        st.flows[key] = rec
        self._install_microflow(rec)
        st.counters["flows_installed"] += 1
        self._packet_out(dp, msg, in_port)

    @staticmethod
    def _match(src_ip, dst_ip, proto_num, sport, dport, icmp_type=None):
        m = {"eth_type": ether_types.ETH_TYPE_IP, "ipv4_src": src_ip, "ipv4_dst": dst_ip, "ip_proto": proto_num}
        if proto_num == 6:
            m.update(tcp_src=sport, tcp_dst=dport)
        elif proto_num == 17:
            m.update(udp_src=sport, udp_dst=dport)
        elif proto_num == 1 and icmp_type is not None:
            m["icmpv4_type"] = icmp_type
        return m

    def _matches_for(self, rec):
        pn = PROTO_NUM[rec["proto"]]
        it = rec.get("icmp_type")
        fwd = self._match(rec["src_ip"], rec["dst_ip"], pn, rec["sport"], rec["dport"], it)
        rev = self._match(rec["dst_ip"], rec["src_ip"], pn, rec["dport"], rec["sport"],
                          0 if it == 8 else (None if it is None else it))
        return fwd, rev

    def _install_microflow(self, rec, old_path=None):
        q = self.policy.qos(rec["qos"])
        sh, dh = self.host(rec["src"]), self.host(rec["dst"])
        cookie = C_FLOW | (sh["id"] << 16) | dh["id"]
        idle = IDLE_ICMP if rec["proto"] == "icmp" else IDLE_FLOW
        fwd, rev = self._matches_for(rec)
        path = rec["path"]
        meter = bool(q.get("meter"))
        self._install_path(path, fwd, self.state.host_loc[rec["dst"]][1], q, cookie, idle, meter, notify=True)
        self._install_path(path[::-1], rev, self.state.host_loc[rec["src"]][1], q, cookie, idle, False)
        if old_path:
            stale = [s for s in old_path if s not in path]
            for sw in stale:
                dp = self._dp(sw)
                if dp:
                    for m in (fwd, rev):
                        self._del_flows(dp, cookie, T_MASK | 0xFFFFFFFF, dp.ofproto_parser.OFPMatch(**m),
                                        strict=True, priority=PRIO_FLOW)

    def _install_path(self, path, match, last_port, q, cookie, idle, meter, notify=False):
        n = len(path)
        for i in range(n - 1, -1, -1):              # egress first so the path is ready end-to-end
            sw = path[i]
            dp = self._dp(sw)
            if dp is None:
                continue
            ofp, parser = dp.ofproto, dp.ofproto_parser
            out = self.model.port_towards(sw, path[i + 1]) if i < n - 1 else last_port
            actions = []
            if i == 0 and q.get("dscp"):
                actions.append(parser.OFPActionSetField(ip_dscp=int(q["dscp"])))
            if q.get("queue") and i < n - 1:
                actions.append(parser.OFPActionSetQueue(int(q["queue"])))
            actions.append(parser.OFPActionOutput(out))
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            if i == 0 and meter and self.meter_ok.get(dp.id):
                inst.insert(0, parser.OFPInstructionMeter(BYOD_METER, ofp.OFPIT_METER))
            flags = ofp.OFPFF_SEND_FLOW_REM if (i == 0 and notify) else 0
            self._add_flow(dp, PRIO_FLOW, parser.OFPMatch(**match), inst=inst, idle=idle,
                           cookie=cookie, flags=flags)

    def _remove_microflow(self, rec):
        sh, dh = self.host(rec["src"]), self.host(rec["dst"])
        cookie = C_FLOW | (sh["id"] << 16) | dh["id"]
        fwd, rev = self._matches_for(rec)
        for sw in rec["path"]:
            dp = self._dp(sw)
            if dp:
                for m in (fwd, rev):
                    self._del_flows(dp, cookie, T_MASK | 0xFFFFFFFF, dp.ofproto_parser.OFPMatch(**m),
                                    strict=True, priority=PRIO_FLOW)
        self.state.flows.pop(rec["key"], None)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def _flow_removed(self, ev):
        msg = ev.msg
        ofp = msg.datapath.ofproto
        if (msg.cookie & T_MASK) != C_FLOW or msg.reason == ofp.OFPRR_DELETE:
            return
        m = msg.match
        pn = m.get("ip_proto")
        sport = m.get("tcp_src", m.get("udp_src", 0))
        dport = m.get("tcp_dst", m.get("udp_dst", 0))
        key = (m.get("ipv4_src"), m.get("ipv4_dst"), pn, sport, dport)
        rec = self.state.flows.get(key)
        if rec and rec["path"] and self.model.dpid(rec["path"][0]) == msg.datapath.id:
            self.state.flows.pop(key, None)
            self.state.counters["flows_expired"] += 1

    def _flush_host_flows(self, host):
        h = self.host(host)
        for dp in list(self.datapaths.values()):
            for base in (C_FLOW, C_DENY):
                for c, mask in self._for_host_cookies(base, h["id"]):
                    self._del_flows(dp, c, mask)
        for k in [k for k, f in self.state.flows.items() if host in (f["src"], f["dst"])]:
            self.state.flows.pop(k, None)

    def flush_all_flows(self):
        for dp in list(self.datapaths.values()):
            for c in (C_FLOW, C_DENY):
                self._del_flows(dp, c, T_MASK)
        self.state.flows.clear()

    # ================================================================ security
    def _security_event(self, host, kind, detail):
        st = self.state
        if host in st.quarantine:
            return
        auto = self.policy.security.get("auto_quarantine", True)
        h = self.host(host)
        msg = "%s detected from %s (%s, %s): %s" % (kind.replace("_", " "), host, h["label"], h["block"], detail)
        if auto:
            self.quarantine(host, "%s: %s" % (kind, detail), auto=True)
        else:
            st.alert("warning", "ids", msg, host=host)

    def _install_quarantine(self, dp, host):
        h = self.host(host)
        parser = dp.ofproto_parser
        for m in (parser.OFPMatch(eth_src=h["mac"]), parser.OFPMatch(eth_dst=h["mac"])):
            self._add_flow(dp, PRIO_QUARANTINE, m, [], cookie=C_QUAR | h["id"])

    def quarantine(self, host, reason, auto=False):
        st = self.state
        if host not in self.model.hosts or host in st.quarantine:
            return False
        t0 = time.time()
        st.quarantine[host] = {"reason": reason, "ts": t0, "auto": auto,
                               "location": "%s:%d" % st.host_loc[host]}
        for dp in list(self.datapaths.values()):
            self._install_quarantine(dp, host)
        self._flush_host_flows(host)
        h = self.host(host)
        st.alert("critical", "quarantine",
                 "%s %s (%s in %s) quarantined fabric-wide on %d switches in %.1f ms - %s"
                 % ("AUTO:" if auto else "Operator:", host, h["label"], h["block"], len(self.datapaths),
                    (time.time() - t0) * 1000, reason), host=host)
        return True

    def release(self, host):
        st = self.state
        if host not in st.quarantine:
            return False
        h = self.host(host)
        for dp in list(self.datapaths.values()):
            self._del_flows(dp, C_QUAR | h["id"], T_MASK | 0xFFFFFFFF)
        st.quarantine.pop(host, None)
        self.ids.forget(host)
        st.alert("info", "quarantine", "%s released from quarantine" % host, host=host)
        return True

    # ================================================================ policy deployment
    def apply_policy(self, candidate, source="api"):
        self.policy = PolicyEngine(self.model, candidate)
        self.ids = AnomalyDetector(self.policy.security) if candidate.get("security") else self.ids
        self.flush_all_flows()
        self.twin._intent_cache = (0, None)
        self.state.policy_history.append({"version": candidate.get("version"), "ts": time.time(),
                                          "source": source, "policy": candidate})
        rt = os.path.join(ROOT, "runtime")
        try:
            os.makedirs(rt, exist_ok=True)
            with open(os.path.join(rt, "policy_v%d.json" % len(self.state.policy_history)), "w") as f:
                json.dump(candidate, f, indent=2)
        except OSError:
            pass
        self.state.alert("info", "policy", "Policy v%s deployed to the live network (%s); all flows re-evaluated"
                         % (candidate.get("version"), source))

    # ================================================================ fast failover
    def _on_link_down(self, link):
        st = self.state
        t0 = time.time()
        affected = st.flows_on_link(link["id"])
        g = self.routing.build_graph(st.link_up, st.link_load)
        moved = cut = 0
        for rec in affected:
            p = self.routing.path(g, rec["path"][0], rec["path"][-1], rec["mode"])
            if p is None:
                self._remove_microflow(rec)
                cut += 1
                continue
            self._reroute(rec, p, "failover around %s" % link["id"], log=False)
            moved += 1
        st.alert("warning", "failover", "Link %s DOWN - %d flows rerouted, %d unreachable, in %.1f ms"
                 % (link["id"], moved, cut, (time.time() - t0) * 1000))

    def _reroute(self, rec, new_path, why, log=True):
        old = rec["path"]
        if new_path == old:
            return
        rec["path"] = new_path
        rec["links"] = self.routing.path_links(self.model, new_path)
        rec["reroutes"] += 1
        g = self.routing.build_graph(self.state.link_up, self.state.link_load)
        rec["latency_ms"] = round(self.routing.path_latency(g, new_path) or 0, 2)
        self._install_microflow(rec, old_path=old)
        self.state.counters["reroutes"] += 1
        if log:
            self.state.event("te", "Rerouted %s -> %s [%s] %s => %s (%s)"
                             % (rec["src"], rec["dst"], rec["qos"], "-".join(old), "-".join(new_path), why))

    # ================================================================ monitoring
    def _monitor_loop(self):
        tick = 0
        while True:
            hub.sleep(2)
            tick += 1
            now = time.time()
            for l in self.model.links:
                self.state.util_history[l["id"]].append((now, round(self.state.link_util(l), 4)
                                                         if self.state.link_up.get(l["id"]) else 0.0))
            for dp in list(self.datapaths.values()):
                ofp, parser = dp.ofproto, dp.ofproto_parser
                dp.send_msg(parser.OFPPortStatsRequest(dp, 0, ofp.OFPP_ANY))
                if tick % 2 == 0 and self.model.switches.get(self.model.switch_name(dp.id), {}).get("tier") != "core":
                    dp.send_msg(parser.OFPFlowStatsRequest(dp, 0, ofp.OFPTT_ALL, ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                           C_FLOW, T_MASK, parser.OFPMatch()))

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats(self, ev):
        st = self.state
        sw = self.model.switch_name(ev.msg.datapath.id)
        now = time.time()
        U64 = 0xFFFFFFFFFFFFFFFF            # OVS reports this for an unsupported counter
        for s in ev.msg.body:
            k = (sw, s.port_no)
            if s.tx_bytes == U64 or s.rx_bytes == U64:
                continue
            prev = self.port_prev.get(k)
            self.port_prev[k] = (now, s.tx_bytes, s.rx_bytes, s.tx_dropped)
            if not prev or now - prev[0] < 0.5 or s.tx_bytes < prev[1] or s.rx_bytes < prev[2]:
                continue                      # first sample, too soon, or a counter reset
            dt = now - prev[0]
            tx = (s.tx_bytes - prev[1]) * 8 / dt / 1e6
            rx = (s.rx_bytes - prev[2]) * 8 / dt / 1e6
            if tx > 2000 or rx > 2000:        # faster than any campus link: a measurement glitch
                continue
            peer = self.model.port_map.get(k)
            if peer and peer[0] == "switch":
                st.link_load[(sw, peer[1])] = tx
                l = self.model.link_by_ports[k]
                st.link_drops[l["id"]] += max(0, s.tx_dropped - prev[3])
            else:
                host = next((h for h, loc in st.host_loc.items() if loc == k), None)
                if host:
                    st.host_rate[host] = rx
                    if rx > 0.001:
                        st.host_seen[host] = now
                    if host not in st.quarantine:
                        for kind, detail in self.ids.on_rate(host, rx, self.host(host)["max_mbps"]):
                            self._security_event(host, kind, detail)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats(self, ev):
        st = self.state
        dpid = ev.msg.datapath.id
        now = time.time()
        for s in ev.msg.body:
            m = s.match
            if "ipv4_src" not in m:
                continue
            pn = m.get("ip_proto")
            sport = m.get("tcp_src", m.get("udp_src", 0))
            dport = m.get("tcp_dst", m.get("udp_dst", 0))
            key = (m["ipv4_src"], m["ipv4_dst"], pn, sport, dport)
            rkey = (m["ipv4_dst"], m["ipv4_src"], pn, dport, sport)
            rec, field = st.flows.get(key), "rate_mbps"
            if rec is None:
                rec, field = st.flows.get(rkey), "rev_rate_mbps"
                if rec is None or self.model.dpid(rec["path"][-1]) != dpid:
                    continue
            elif self.model.dpid(rec["path"][0]) != dpid:
                continue
            pk = (dpid, key)
            prev = self.flow_prev.get(pk)
            self.flow_prev[pk] = (now, s.byte_count)
            if prev and now > prev[0] and s.byte_count >= prev[1]:
                rec[field] = round((s.byte_count - prev[1]) * 8 / (now - prev[0]) / 1e6, 3)
            if field == "rate_mbps":
                rec["bytes"] = s.byte_count
        if len(self.flow_prev) > 5000:
            self.flow_prev.clear()

    # ================================================================ traffic engineering
    def _te_loop(self):
        while True:
            hub.sleep(float(self.policy.te.get("te_interval_s", 5)))
            try:
                self._te_cycle()
            except Exception as e:                         # never let TE kill the controller
                self.logger.exception("TE cycle failed: %s", e)

    def _te_cycle(self):
        st = self.state
        thr = float(self.policy.te.get("reroute_util_threshold", 0.75))
        mode = st.routing_mode
        if mode in ("policy", "load"):
            for l in sorted(self.model.links, key=lambda x: -st.link_util(x)):
                u = st.link_util(l)
                if u < thr:
                    break
                cands = [f for f in st.flows_on_link(l["id"]) if f["qos"] not in ("realtime", "critical")
                         and f.get("rate_mbps", 0) > 0.3]
                cands.sort(key=lambda f: -f.get("rate_mbps", 0))
                for rec in cands[:2]:
                    load = dict(st.link_load)
                    for a, b in zip(rec["path"], rec["path"][1:]):
                        load[(a, b)] = max(0.0, load.get((a, b), 0) - rec["rate_mbps"])
                    g = self.routing.build_graph(st.link_up, load)
                    p = self.routing.path(g, rec["path"][0], rec["path"][-1], "load")
                    if not p or p == rec["path"]:
                        continue
                    for a, b in zip(p, p[1:]):
                        load[(a, b)] = load.get((a, b), 0) + rec["rate_mbps"]
                    g2 = self.routing.build_graph(st.link_up, load)
                    if self.routing.path_bottleneck(g2, p) < u - 0.05:
                        self._reroute(rec, p, "%s at %.0f%% utilisation" % (l["id"], u * 100))
                        st.alert("info", "te", "Congestion on %s (%.0f%%): moved %s->%s %s flow (%.1f Mbps) to %s"
                                 % (l["id"], u * 100, rec["src"], rec["dst"], rec["qos"], rec["rate_mbps"],
                                    "-".join(p)))
        if mode in ("policy", "latency"):
            bound = self.twin._intent_param("latency", "max_ms", 25)
            g = self.routing.build_graph(st.link_up, st.link_load)
            for rec in [f for f in st.flows.values() if f["qos"] in ("realtime", "critical")]:
                cur = self.routing.path_latency(g, rec["path"]) if all(
                    g.has_edge(a, b) for a, b in zip(rec["path"], rec["path"][1:])) else None
                best = self.routing.path(g, rec["path"][0], rec["path"][-1], "latency")
                bl = self.routing.path_latency(g, best)
                if best and best != rec["path"] and (cur is None or bl < cur * 0.7 or (cur > bound and bl < cur)):
                    self._reroute(rec, best, "real-time SLA: %.1f ms -> %.1f ms" % (cur or -1, bl))
                elif cur is not None:
                    rec["latency_ms"] = round(cur, 2)
        self._dynamic_bandwidth()

    def _dynamic_bandwidth(self):
        """Dynamic bandwidth allocation: resize the BYOD meter with campus uplink load."""
        st = self.state
        tiers = self.policy.te.get("byod_meter_kbps", {})
        uplinks = [l for l in self.model.links if "core" in (l["a"] + l["b"]) and
                   self.model.switches[l["b"]]["tier"] == "distribution" and l["b"] != "dc1"]
        peak = max([st.link_util(l) for l in uplinks] or [0])
        tier = "relaxed" if peak < 0.5 else ("normal" if peak < 0.75 else "congested")
        kbps = tiers.get(tier)
        if kbps and kbps != st.byod_meter_kbps:
            st.byod_meter_kbps = kbps
            for dp in list(self.datapaths.values()):
                if self.meter_ok.get(dp.id):
                    self._set_meter(dp, kbps, dp.ofproto.OFPMC_MODIFY)
            st.event("qos", "BYOD slice meter set to %d kbps (peak uplink %.0f%% - %s)" % (kbps, peak * 100, tier))

    # ================================================================ AI loop
    def _ml_loop(self):
        while True:
            hub.sleep(10)
            try:
                g = self.routing.build_graph(self.state.link_up, self.state.link_load)
                if g.number_of_edges():
                    self.qrouting.train(g, episodes=2500)
                    hub.sleep(0)
                    self.ql_benchmark = self.twin.compare_routing(stress=1.0)
            except Exception as e:
                self.logger.exception("ML loop failed: %s", e)
