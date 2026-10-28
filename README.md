# Campus Network SDN Digital Twin

A working **digital twin of a campus network** built with **Mininet** + **Open vSwitch**
and a custom **os-ken (Ryu-successor) SDN controller**, with a live web dashboard.

The campus has **4 academic blocks — AB1, AB2, AB3, AB4** — plus a redundant core and a
data centre, wired to **one central SDN controller**, and populated with realistic devices
(faculty/lab/admin PCs, student laptops & kiosks, research workstations, VoIP phones, CCTV
cameras, IoT sensors, smart boards, printers and campus servers).

It implements every idea from the project brief (*SDN Digital twin project.pptx*):
decoupled control/data planes, a central controller with a global view, the three-tier
SDN architecture, agility/automation, zero-trust security with micro-segmentation,
dynamic bandwidth & QoS, real-time traffic optimisation, the smart-campus IoT/CCTV fabric,
AI-driven (multi-agent Q-learning) traffic engineering, and a **real-time virtual replica
(the digital twin) that safely simulates loads, tests configurations and predicts
behaviour before changes touch the live network.**

---

## 1. Architecture (three-tier SDN)

```
          ┌───────────────────────────────────────────────────────────────┐
          │  APPLICATION LAYER                                              │
          │  zero-trust policy · network slicing · digital twin · anomaly   │
          │  IDS · multi-agent Q-routing · REST API + dashboard             │
          └───────────────▲───────────────────────────────┬───────────────┘
                 northbound REST (:8080)                   │ global view
          ┌───────────────┴───────────────────────────────▼───────────────┐
          │  CONTROL LAYER   (controller/campus_controller.py, os-ken)      │
          │  path computation · flow programming · QoS/meters · monitoring  │
          └───────────────▲───────────────────────────────┬───────────────┘
                 OpenFlow 1.3 (:6653)                      │ flow rules
          ┌───────────────┴───────────────────────────────▼───────────────┐
          │  INFRASTRUCTURE LAYER  (emulation/, Mininet + Open vSwitch)     │
          │  15 switches · 44 hosts · AB1–AB4 + redundant core + DC         │
          └───────────────────────────────────────────────────────────────┘
```

* **Decoupled planes** — the "dumb" OVS switches only forward; all decisions come from the
  controller over OpenFlow 1.3.
* **Centralised intelligence** — the controller keeps a global view (topology, link load,
  flows, hosts) and programs forwarding, replacing distributed routing protocols.
* **One shared model** — both Mininet and the controller read `config/campus.json` through
  `common/campus_model.py`, so DPIDs, ports, IPs and MACs are identical on both sides.

### The physical topology

| Tier | Switches | Notes |
|------|----------|-------|
| Core | `core1`, `core2` | redundant fibre core (every block is dual-homed) |
| Data centre | `dc1` | web, LMS, exam, NVR, IoT-hub, PBX, DNS, storage, Internet GW |
| Distribution | `ab1d`…`ab4d` | one per block, two uplinks (to core1 **and** core2) |
| Access | `ab1f1/ab1f2` … | two floors per block, hosts attach here |

Links use `TCLink` with real **bandwidth + delay** (core 100 Mbps/1 ms, uplinks 40 Mbps,
access 100 Mbps), and each inter-switch port has **three HTB queues** (real-time / best-effort / bulk).

---

## 2. Install (Windows + WSL2)

Mininet needs a real Linux kernel, so everything runs inside **WSL2 Ubuntu** (already
present on this machine). From a WSL terminal:

```bash
# system packages (Mininet + Open vSwitch + tools) — run once
sudo apt-get update
sudo apt-get install -y mininet openvswitch-switch openvswitch-testcontroller \
     iperf iperf3 net-tools tcpdump curl python3-venv python3-pip

# controller virtual-env (os-ken + networkx)
python3 -m venv /opt/sdn-venv
/opt/sdn-venv/bin/pip install -r requirements.txt
```

> Already provisioned in this project's WSL: venv at `/opt/sdn-venv`, os-ken **3.1.1**
> (4.x removed the runnable manager), Mininet 2.3.0, OVS 3.3.

---

## 3. Run

### The single command (`campus-twin`, Mininet-style)

Install the command once, then launch the whole twin with one line — it starts the
controller, builds the Mininet campus, serves the dashboard, and drops you into an
interactive CLI (just like `sudo mn`):

```bash
sudo scripts/install.sh        # one-time: deps + put `campus-twin` on PATH

sudo campus-twin               # bring it all up, interactive CLI
sudo campus-twin --services    # also start the campus servers
sudo campus-twin --scenario normal   # start with a traffic scenario already running
sudo campus-twin --test        # self-test (7 zero-trust checks) and exit
sudo campus-twin --help        # all options
```

On exit it tears the network down **and** stops the controller it launched.
From **Windows** you can also run `campus-twin.bat` (it calls the WSL command).

### Two-terminal workflow (controller and network separately)

```bash
# terminal 1 — controller (control + application layers, serves the dashboard)
sudo scripts/start_controller.sh
# terminal 2 — the campus emulation, pointed at that controller
sudo scripts/start_network.sh --services
```

Either way, open the **dashboard** at <http://localhost:8080>.

Generate traffic from the Mininet CLI (terminal 2) or from the dashboard's *Emulation* tab:

```
mininet> services                 # start all campus servers
mininet> scenario normal          # a typical campus day (CCTV, VoIP, LMS, backups…)
mininet> scenario congestion      # saturate an uplink — watch the controller reroute
mininet> scenario exam 60 ; examreport   # online-exam latency under load (critical QoS)
mininet> scenario byod            # student-laptop surge (metered slice)
mininet> linkdown core1 ab4d      # fail a link — watch fast failover
mininet> probe sweep ab3-lap1     # bounded IDS test traffic (host sweep)
mininet> checkpolicy ab3-lap1 dc-exam   # zero-trust check from the data plane
```

### One-command demo / tests

```bash
scripts/demo_fg.sh 600       # bring the whole stack up with traffic for 10 min
scripts/e2e_test.sh          # automated end-to-end verification (controller+Mininet+REST)
/opt/sdn-venv/bin/python -m pytest tests/test_offline.py -v    # 25 offline unit tests
/opt/sdn-venv/bin/python tests/verify_live.py                  # live checks vs a running stack
```

---

## 4. How each project-brief feature is implemented

| Brief (PPT) theme | Where | What it does |
|---|---|---|
| **Decoupled control/data planes** | `campus_controller.py` | dumb OVS switches, all logic in the controller over OpenFlow 1.3 |
| **Central controller, global view** | `state.py`, `campus_controller.py` | live topology, link-load, host and flow state; LLDP link discovery |
| **Three-tier architecture** | whole repo | application / control / infrastructure layers (see §1) |
| **Agility & automation** | `campus_controller.py` | hosts & links auto-discovered; flows installed on demand; policy re-applied live; no per-switch CLI |
| **Zero-Trust security** | `policy_engine.py`, `config/policies.json` | default-deny; rules written against **identity** (role/slice), so policy follows a device when it moves (micro-segmentation) |
| **Rapid isolation of compromised nodes** | `campus_controller.py` + `anomaly.py` | IDS detects scans/floods/spoofing/over-rate; controller quarantines a host **fabric-wide** in milliseconds |
| **Micro-segmentation / slicing** | `policy_engine.py` | 10 slices (Academic, Admin, Student/BYOD, Research, Voice, Surveillance, IoT, Smart-class, Services, DC); IoT & CCTV isolated to their hubs |
| **Dynamic bandwidth / QoS** | `campus_controller.py` (`_dynamic_bandwidth`, meters, `OFPActionSetQueue`) | DSCP marks + HTB queues per class; BYOD slice metered, meter resized with live uplink load |
| **Traffic optimisation / reroute latency-sensitive flows** | `routing.py`, TE loop | congestion-aware & latency routing; real-time flows kept on the low-delay core path; bulk moved off hot links |
| **Reduction in routing time (efficiency)** | `twin_engine.compare_routing` | twin benchmarks hop vs latency vs load vs Q-routing (dashboard → *AI Routing* / *Digital Twin*) |
| **Multi-Agent Q-Learning** | `qlearning.py` | Boyan-&-Littman Q-routing, one agent per switch, retrained every 10 s on live link delays |
| **Smart campus (IoT, CCTV, smart boards)** | `config/campus.json`, `emulation/traffic.py` | IoT→MQTT hub, CCTV→NVR, smart-board casting, VoIP↔PBX, all as isolated slices |
| **Zero-trust admission** | `campus_controller._rogue_device` | unregistered MACs are blocked at the edge (not in the identity inventory) |
| **DIGITAL TWIN — safe simulation** | `twin_engine.py` | what-if link failure & added load, routing comparison, **predict before you touch the live network** |
| **…test configurations safely** | `twin_engine.validate_policy` | a candidate policy is checked against all intents on the twin and **blocked if it breaks one** |
| **…predict network behaviour** | `twin_engine.forecast` | Holt trend on utilisation → time-to-congestion + predictive-maintenance health per link |
| **AI-driven anomaly detection** | `anomaly.py` | port-scan, flood, policy-probing, device-profile and statistical (z-score) detectors |
| **Drift detection (twin vs reality)** | `twin_engine.sync_status` | LLDP-verifies the real fabric against the inventory; flags unexpected links / relocated / unregistered devices |

### Intents (continuously verified by the twin)

IoT & surveillance isolation · exam-server exclusivity · admin-PC shielding · VoIP→PBX and
student→LMS reachability · real-time latency bound (≤25 ms) · link-capacity headroom (≤90 %) ·
dual-homed blocks (≥2 disjoint paths). All **COMPLIANT** on the healthy network.

---

## 5. The dashboard (`:8080`)

* **Overview** — three-tier status, live tiles, alerts, busiest links.
* **Topology** — the campus map, links coloured by live utilisation, click any node to inspect.
* **Flows & QoS** — every installed micro-flow with its rule, QoS class, path and rate.
* **Zero-Trust Policy** — interactive check, rule list, role×role reachability matrix, and a
  **policy editor that validates against the twin before deploying** (with rollback).
* **Digital Twin** — what-if link failure, what-if added load, intent compliance, routing
  comparison, congestion/health forecast.
* **Security** — quarantine (auto & manual), unregistered devices, denied attempts, IDS baselines.
* **AI Routing** — switch the fabric's routing strategy; inspect per-agent Q-tables and the
  learned-vs-classic latency benchmark.
* **Emulation** — drive Mininet (scenarios, IDS probes, link up/down) from the browser.

---

## 6. Layout

```
config/        campus.json (topology & devices) · policies.json (zero-trust + QoS + intents)
common/        campus_model.py           shared model (single source of truth)
controller/    campus_controller.py      os-ken app: packet-in, flows, QoS, TE, security
               policy_engine.py          zero-trust evaluation + reachability analysis
               routing.py                hop / latency / load path computation
               qlearning.py              multi-agent Q-routing
               anomaly.py                intrusion / anomaly detection
               twin_engine.py            digital-twin analytics (what-if, intents, forecast)
               state.py                  live network state
               rest_api.py               northbound REST + dashboard web server
emulation/     topology.py               Mininet topology (TCLink bw/delay, HTB queues)
               run_campus.py             runner + extended CLI + control bridge (:8081)
               traffic.py                campus services, scenarios, bounded IDS probes
dashboard/     index.html · style.css · app.js     single-page NOC dashboard
bin/           campus-twin               the single executable (controller + network + CLI)
campus-twin.bat                          Windows launcher (calls the WSL command)
scripts/       install.sh (installs `campus-twin`) · start_controller.sh · start_network.sh
               demo_fg.sh · e2e_test.sh
tests/         test_offline.py (25 unit tests) · verify_live.py (live checks)
```

---

## 7. Notes & safety

* The emulation is a **self-contained lab on your own machine**; the "IDS probes"
  (`probe sweep|denied|overrate`) are small, bounded and benign — they exist only to give the
  controller's zero-trust policy and anomaly detector something to react to. There is no
  flooding/DoS tooling.
* The whole campus is one flat L2 fabric (`10.0.0.0/8`) with the controller doing proxy-ARP
  and identity-based forwarding — that is what lets a device's policy follow it anywhere.
* `runtime/` holds deployed policy versions written by the controller (for rollback/audit).
