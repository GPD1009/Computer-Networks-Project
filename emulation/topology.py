"""
Campus topology for Mininet (infrastructure layer of the digital twin).

Builds the exact switches, links (with bandwidth + delay via TCLink), hosts,
IPs and MAC addresses described in config/campus.json, so the emulated
network is a faithful replica of what the controller and twin model.

Run through run_campus.py (handles sudo, OVS, QoS queues and cleanup).
"""
import os
import sys

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "common"))
from campus_model import CampusModel  # noqa: E402


class CampusTopo(Topo):
    def build(self, model):
        self.model = model
        for s in model.switches.values():
            # protocols pinned to OpenFlow13; DPIDs match the inventory
            self.addSwitch(s["name"], dpid="%016x" % s["dpid"], protocols="OpenFlow13")
        for l in model.links:
            self.addLink(l["a"], l["b"], port1=l["a_port"], port2=l["b_port"],
                         bw=l["bw"], delay="%gms" % l["delay_ms"], max_queue_size=2000, use_htb=True)
        hl = model.host_link
        # One flat L2 fabric: every host is in 10.0.0.0/8 so any campus host is
        # "local" and ARPs directly (the controller proxy-answers ARP and programs
        # the path).  The 10.<block>.<floor>.<id> structure stays human-readable.
        for h in model.hosts.values():
            self.addHost(h["name"], ip="%s/8" % h["ip"], mac=h["mac"])
            self.addLink(h["name"], h["switch"], port2=h["port"],
                         bw=hl["bw"], delay="%gms" % hl["delay_ms"], use_htb=True)


def build_net(config_path):
    model = CampusModel(config_path)
    ctl = model.controller
    net = Mininet(topo=CampusTopo(model), switch=OVSSwitch, link=TCLink,
                  controller=lambda name: RemoteController(name, ip=ctl.get("ip", "127.0.0.1"),
                                                           port=ctl.get("port", 6653)),
                  autoSetMacs=False, autoStaticArp=False, build=True, waitConnected=False)
    return net, model


def setup_qos_queues(model):
    """
    Create three HTB queues per inter-switch port so OFPActionSetQueue works:
      q0 best-effort, q1 real-time (highest), q2 bulk/BYOD (lowest).
    Uses ovs-vsctl directly (Mininet's TCLink already attached an HTB qdisc).
    """
    import subprocess
    for l in model.links:
        for sw, port, bw in ((l["a"], l["a_port"], l["bw"]), (l["b"], l["b_port"], l["bw"])):
            iface = "%s-eth%d" % (sw, port)
            rate = int(bw * 1_000_000)
            q0 = max(int(rate * 0.3), 1_000_000)
            q1 = max(int(rate * 0.5), 1_000_000)
            q2 = max(int(rate * 0.2), 1_000_000)
            cmd = [
                "ovs-vsctl", "--", "set", "Port", iface, "qos=@newqos", "--",
                "--id=@newqos", "create", "QoS", "type=linux-htb",
                "other-config:max-rate=%d" % rate,
                "queues:0=@q0", "queues:1=@q1", "queues:2=@q2", "--",
                "--id=@q0", "create", "Queue", "other-config:min-rate=%d" % q0, "other-config:max-rate=%d" % rate, "--",
                "--id=@q1", "create", "Queue", "other-config:min-rate=%d" % q1, "other-config:max-rate=%d" % rate, "--",
                "--id=@q2", "create", "Queue", "other-config:min-rate=%d" % q2, "other-config:max-rate=%d" % rate,
            ]
            subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
