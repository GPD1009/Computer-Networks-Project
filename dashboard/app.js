"use strict";
const API = location.origin.replace(/\/$/, "");
const EMU = location.protocol + "//" + location.hostname + ":8081";
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const SVGNS = "http://www.w3.org/2000/svg";
const esc = s => String(s == null ? "" : s).replace(/[&<>]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
const fx = (n, d = 1) => (n == null ? "–" : Number(n).toFixed(d));
const pct = u => (u == null ? "–" : Math.round(u * 100) + "%");

async function get(p) { const r = await fetch(API + "/api" + p); if (!r.ok) throw new Error(r.status); return r.json(); }
async function post(p, b) {
  const r = await fetch(API + "/api" + p, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b || {}) });
  return r.json();
}
async function emu(p, b) {
  const r = await fetch(EMU + p, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b || {}) });
  if (!r.ok) throw new Error(r.status); return r.json();
}

let STATE = { topo: null, paused: false, tab: "overview", lastAlert: 0, selNode: null };

/* ---------------- tabs ---------------- */
$$("#tabs button").forEach(b => b.onclick = () => {
  $$("#tabs button").forEach(x => x.classList.toggle("active", x === b));
  $$(".view").forEach(v => v.classList.toggle("active", v.id === b.dataset.v));
  STATE.tab = b.dataset.v;
  refreshTab();
});
$("#btn-pause").onclick = e => {
  STATE.paused = !STATE.paused;
  e.target.textContent = STATE.paused ? "▶ resume" : "⏸ pause";
};

function utilColor(u, up = true) {
  if (!up) return "#3b1113";
  if (u == null) return "#27314a";
  if (u < 0.5) return "#2f6f4f";
  if (u < 0.75) return "#b58a1b";
  if (u < 0.9) return "#c2622a";
  return "#d6453f";
}
const SLICE_VAR = s => "var(--" + s.toLowerCase() + ")";

/* ---------------- header + polling ---------------- */
async function tick() {
  if (STATE.paused) return;
  try {
    const sm = await get("/summary");
    header(sm);
    if (["overview"].includes(STATE.tab)) await overview(sm);
    if (STATE.tab === "topology") await topology();
    if (STATE.tab === "flows") await flows();
    if (STATE.tab === "security") await security();
    if (STATE.tab === "ai") await aiLive();
    await alerts();
    $("#p-ctl").className = "pill ok"; $("#p-ctl").textContent = "controller online";
  } catch (e) {
    $("#p-ctl").className = "pill bad"; $("#p-ctl").textContent = "controller offline";
  }
}
function header(sm) {
  $("#p-sync").className = "pill " + (sm.twin_in_sync ? "ok" : "warn");
  $("#p-sync").textContent = "twin " + fx(sm.twin_sync_score, 0) + "% " + (sm.twin_in_sync ? "in-sync" : "drift");
  $("#p-route").className = "pill"; $("#p-route").textContent = "routing: " + sm.routing_mode;
  const q = sm.quarantined, u = sm.unregistered;
  $("#p-sec").className = "pill " + (q + u ? "bad" : "ok");
  $("#p-sec").textContent = q + u ? (q + " quarantined, " + u + " blocked") : "no active threats";
}
setInterval(() => $("#clock").textContent = new Date().toLocaleTimeString(), 1000);

function refreshTab() {
  const map = { topology, flows, security, policy: policyInit, twin: twinInit, ai: aiInit, emulation: emuInit };
  (map[STATE.tab] || (() => { }))();
  tick();
}

/* ---------------- overview ---------------- */
async function overview(sm) {
  const tiles = [
    ["Switches", sm.switches.up + "<small>/" + sm.switches.total + "</small>", "OpenFlow 1.3 datapaths"],
    ["Links up", sm.links.up + "<small>/" + sm.links.total + "</small>", "peak util " + pct(sm.peak_link_util)],
    ["Hosts online", sm.hosts.online + "<small>/" + sm.hosts.total + "</small>", "campus devices"],
    ["Active flows", sm.flows, (sm.counters.flows_installed || 0) + " installed"],
    ["Denied (zero-trust)", sm.counters.denied || 0, "default-deny blocks"],
    ["Quarantined", sm.quarantined, "isolated fabric-wide"],
    ["Reroutes", sm.counters.reroutes || 0, "traffic-engineering moves"],
    ["Uptime", fx(sm.uptime_s / 60, 0) + "<small>m</small>", "controller"]
  ];
  $("#tiles").className = "grid g4";
  $("#tiles").innerHTML = tiles.map(t =>
    `<div class="stat"><div class="k">${t[0]}</div><div class="v">${t[1]}</div><div class="s">${t[2]}</div></div>`).join("");
  $("#arch").innerHTML = archHtml(sm);

  const topo = await get("/topology");
  const busy = [...topo.links].filter(l => l.up).sort((a, b) => b.util - a.util).slice(0, 8);
  $("#ov-links").innerHTML = `<table><tbody>${busy.map(l =>
    `<tr><td class="mono">${l.id}</td><td>${l.bw} Mbps</td>
     <td style="width:40%"><div class="bar"><span style="width:${Math.min(100, l.util * 100)}%;background:${utilColor(l.util)}"></span></div></td>
     <td class="r">${pct(l.util)}</td><td class="r">${l.flows} flows</td></tr>`).join("")}</tbody></table>`;
  const ev = await get("/events");
  $("#ov-events").innerHTML = ev.events.slice(0, 12).map(e =>
    `<div class="alert info"><span class="t">${new Date(e.ts * 1000).toLocaleTimeString()}</span> [${e.category}] ${esc(e.message)}</div>`).join("") || "<div class='tip'>no events yet</div>";
}
function archHtml(sm) {
  const L = (t, items, c) => `<div style="border:1px solid var(--line);border-radius:8px;padding:10px;margin-bottom:8px;background:var(--panel2)">
    <div style="color:${c};font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.5px">${t}</div>
    <div class="tip" style="margin-top:4px">${items}</div></div>`;
  return L("Application layer", "Zero-trust policy · slicing · digital twin · anomaly IDS · Q-routing · REST/dashboard", "var(--accent2)")
    + `<div style="text-align:center;color:var(--faint)">▲ northbound REST · ▼ global view</div>`
    + L("Control layer", `os-ken controller — global topology view, path computation, flow programming, QoS, monitoring (routing: <b>${sm.routing_mode}</b>)`, "var(--accent)")
    + `<div style="text-align:center;color:var(--faint)">▲ OpenFlow 1.3 · ▼ flow rules</div>`
    + L("Infrastructure layer", `${sm.switches.total} Open vSwitch switches · ${sm.hosts.total} hosts across AB1–AB4 + data centre (Mininet)`, "var(--ok)");
}

/* ---------------- alerts ---------------- */
async function alerts() {
  const a = await get("/alerts?since=0");
  const html = a.alerts.slice(0, 40).map(x =>
    `<div class="alert ${x.severity}"><span class="t">${new Date(x.ts * 1000).toLocaleTimeString()} · ${x.category}</span><br>${esc(x.message)}</div>`).join("");
  if ($("#ov-alerts")) $("#ov-alerts").innerHTML = html || "<div class='tip'>no alerts</div>";
}

/* ---------------- topology ---------------- */
function layout(topo) {
  const pos = {};
  const blockX = { AB1: 170, AB2: 450, AB3: 730, AB4: 1010 };
  pos.core1 = [500, 60]; pos.core2 = [680, 60]; pos.dc1 = [590, 140];
  for (const b in blockX) {
    const x = blockX[b];
    const dist = topo.switches.find(s => s.block === b && s.tier === "distribution");
    const acc = topo.switches.filter(s => s.block === b && s.tier === "access");
    if (dist) pos[dist.name] = [x, 250];
    acc.forEach((s, i) => pos[s.name] = [x - 70 + i * 140, 350]);
  }
  // hosts: grid under their access switch (or beside dc1)
  const bySw = {};
  topo.hosts.forEach(h => (bySw[h.switch] = bySw[h.switch] || []).push(h));
  for (const sw in bySw) {
    const base = pos[sw];
    const list = bySw[sw];
    if (sw === "dc1") { list.forEach((h, i) => pos[h.name] = [430 + (i % 5) * 68, 180 + Math.floor(i / 5) * 26]); continue; }
    if (!base) continue;
    list.forEach((h, i) => pos[h.name] = [base[0] - (list.length - 1) * 15 + i * 30, 430 + (i % 2) * 34]);
  }
  return pos;
}
async function topology() {
  const topo = await get("/topology"); STATE.topo = topo;
  const svg = $("#topo"); const pos = layout(topo);
  let s = "";
  // block backdrops
  const bx = { AB1: 170, AB2: 450, AB3: 730, AB4: 1010 };
  for (const b in bx) s += `<rect class="blk" x="${bx[b] - 125}" y="225" width="250" height="285" rx="12"/>
    <text class="blklbl" x="${bx[b]}" y="245" text-anchor="middle">${b} · ${esc((topo.blocks[b] || {}).name || "")}</text>`;
  s += `<rect class="blk" x="410" y="40" width="360" height="160" rx="12"/><text class="blklbl" x="590" y="38" text-anchor="middle">CORE + DATA CENTRE</text>`;
  // links
  for (const l of topo.links) {
    const a = pos[l.a], b = pos[l.b]; if (!a || !b) continue;
    const col = utilColor(l.util, l.up);
    const dash = l.up ? "" : 'stroke-dasharray="6 5"';
    s += `<line class="lnk" x1="${a[0]}" y1="${a[1]}" x2="${b[0]}" y2="${b[1]}" stroke="${col}" ${dash}>
      <title>${l.id} — ${l.bw}Mbps, ${pct(l.util)} util, ${l.flows} flows${l.up ? "" : " (DOWN)"}</title></line>`;
  }
  // host links (thin) + hosts
  for (const h of topo.hosts) {
    const p = pos[h.name], sw = pos[h.switch]; if (!p) continue;
    if (sw) s += `<line x1="${p[0]}" y1="${p[1]}" x2="${sw[0]}" y2="${sw[1]}" stroke="#1d2740" stroke-width="1"/>`;
    const cls = "host" + (h.quarantined ? " q" : "") + (h.online ? "" : " off");
    s += `<circle class="${cls}" data-host="${h.name}" cx="${p[0]}" cy="${p[1]}" r="6" fill="${SLICE_VAR(h.slice)}">
      <title>${h.name} · ${esc(h.label)} · ${h.role}/${h.slice} · ${h.ip}${h.quarantined ? " · QUARANTINED" : ""}</title></circle>`;
  }
  // switches
  for (const sw of topo.switches) {
    const p = pos[sw.name]; if (!p) continue;
    const cls = "sw" + (sw.tier === "core" ? " core" : "") + (sw.connected ? "" : " down");
    s += `<g class="switch" data-sw="${sw.name}" style="cursor:pointer">
      <rect class="${cls}" x="${p[0] - 26}" y="${p[1] - 14}" width="52" height="28" rx="6"/>
      <text x="${p[0]}" y="${p[1] + 4}" text-anchor="middle">${sw.name}</text></g>`;
  }
  svg.innerHTML = s;
  $$("[data-sw]", svg).forEach(g => g.onclick = () => selSwitch(g.dataset.sw));
  $$("[data-host]", svg).forEach(c => c.onclick = () => selHost(c.dataset.host));

  $("#topo-legend").innerHTML =
    ['<b>Util:</b>', ['<50%', '#2f6f4f'], ['50-75%', '#b58a1b'], ['75-90%', '#c2622a'], ['>90%', '#d6453f'], ['down', '#d6453f']]
      .map(x => Array.isArray(x) ? `<span><span class="sl" style="background:${x[1]}"></span>${x[0]}</span>` : `<span>${x}</span>`).join("")
    + ' &nbsp; <b>Slices:</b> ' + Object.entries(topo.slices).map(([k, v]) =>
      `<span><span class="sl" style="background:${SLICE_VAR(k)}"></span>${v.label}</span>`).join("");

  // link table
  $("#link-table").innerHTML = `<table><thead><tr><th>link</th><th>bw</th><th>util</th><th>flows</th><th>flaps</th><th>state</th></tr></thead><tbody>${
    topo.links.map(l => `<tr><td class="mono">${l.id}</td><td>${l.bw}</td>
      <td style="width:28%"><div class="bar"><span style="width:${Math.min(100, l.util * 100)}%;background:${utilColor(l.util, l.up)}"></span></div></td>
      <td class="r">${l.flows}</td><td class="r">${l.flaps || 0}</td>
      <td>${l.up ? '<span class="badge ok">up</span>' : '<span class="badge bad">down</span>'}${l.lldp ? '<span class="tag">LLDP✓</span>' : ''}</td></tr>`).join("")}</tbody></table>`;
}
function selSwitch(name) {
  const t = STATE.topo; const sw = t.switches.find(s => s.name === name);
  const links = t.links.filter(l => l.a === name || l.b === name);
  const hosts = t.hosts.filter(h => h.switch === name);
  $("#sel-title").textContent = "Switch " + name + " (" + sw.tier + ")";
  $("#sel-body").innerHTML = `<div class="tip">${esc(sw.label)} · dpid ${sw.dpid} · block ${sw.block} · ${sw.connected ? "connected" : "DISCONNECTED"}</div>
    <div class="sep"></div><b>Links</b><table><tbody>${links.map(l =>
    `<tr><td class="mono">${l.id}</td><td>${pct(l.util)}</td><td>${l.up ? "up" : "down"}</td></tr>`).join("")}</tbody></table>
    ${hosts.length ? `<div class="sep"></div><b>Attached hosts (${hosts.length})</b><div class="tip">${hosts.map(h => esc(h.name)).join(", ")}</div>` : ""}`;
}
function selHost(name) {
  const h = STATE.topo.hosts.find(x => x.name === name);
  $("#sel-title").textContent = "Host " + name;
  $("#sel-body").innerHTML = `<div class="tip">${esc(h.label)}</div><div class="sep"></div>
    <table><tbody>
    <tr><td>role / slice</td><td><span class="sl" style="background:${SLICE_VAR(h.slice)}"></span>${h.role} · ${h.slice}</td></tr>
    <tr><td>IP / MAC</td><td class="mono">${h.ip} · ${h.mac}</td></tr>
    <tr><td>attached</td><td>${h.switch} port ${h.port} ${h.moved ? '<span class="badge warn">moved</span>' : ''}</td></tr>
    <tr><td>block</td><td>${h.block}</td></tr>
    <tr><td>status</td><td>${h.online ? '<span class="badge ok">online</span>' : '<span class="badge">idle</span>'} ${h.quarantined ? '<span class="badge bad">quarantined</span>' : ''}</td></tr>
    <tr><td>tx rate</td><td>${fx(h.rate_mbps, 2)} Mbps</td></tr></tbody></table>
    <div class="sep"></div>
    ${h.quarantined ? `<button class="btn sm" onclick="releaseHost('${h.name}')">Release</button>`
      : `<button class="btn danger sm" onclick="quarantineHost('${h.name}')">Quarantine</button>`}`;
}
window.quarantineHost = async n => { await post("/quarantine", { host: n, reason: "manual (topology)" }); topology(); };
window.releaseHost = async n => { await post("/release", { host: n }); topology(); };

/* ---------------- flows + qos ---------------- */
async function flows() {
  const q = await get("/qos"); const f = await get("/flows?limit=200");
  const classes = q.classes;
  $("#qos-tiles").className = "grid g4";
  $("#qos-tiles").innerHTML = Object.entries(classes).map(([k, c]) => {
    const live = q.live[k] || { flows: 0, mbps: 0 };
    return `<div class="stat"><div class="k">${esc(c.label)}</div>
      <div class="v">${live.flows}<small> flows</small></div>
      <div class="s">${fx(live.mbps, 1)} Mbps · DSCP ${c.dscp} · q${c.queue} · ${c.routing}${c.meter ? " · metered" : ""}</div></div>`;
  }).join("") + `<div class="stat"><div class="k">BYOD meter</div><div class="v">${fx(q.byod_meter_kbps / 1000, 0)}<small> Mbps</small></div>
      <div class="s">dynamic · ${q.meters_supported} switches</div></div>`;
  $("#flow-table").innerHTML = `<table><thead><tr><th>src</th><th>dst</th><th>proto</th><th>qos</th><th>rule</th><th>path</th><th>mode</th><th class="r">lat</th><th class="r">Mbps</th><th class="r">age</th></tr></thead><tbody>${
    f.flows.map(x => `<tr><td>${x.src}</td><td>${x.dst}</td><td>${x.proto}${x.dport ? "/" + x.dport : ""}</td>
      <td><span class="sl" style="background:${qosColor(x.qos)}"></span>${x.qos}</td>
      <td title="${esc(x.rule_name || "")}">${x.rule || "–"}</td>
      <td class="mono">${(x.path || []).join("‑")}${x.reroutes ? ` <span class="tag">↻${x.reroutes}</span>` : ""}</td>
      <td>${x.mode}</td><td class="r">${fx(x.latency_ms)}</td><td class="r">${fx(x.rate_mbps, 2)}</td><td class="r">${fx(x.age_s, 0)}s</td></tr>`).join("")
    || `<tr><td colspan="10" class="tip">no active flows — run a traffic scenario in the Emulation tab</td></tr>`}</tbody></table>`;
}
const QOSC = { realtime: "#d6457b", critical: "#ef4444", video: "#6b7280", best_effort: "#3b82f6", bulk: "#8a8f2e", byod: "#e08a00" };
const qosColor = q => QOSC[q] || "#3b82f6";

/* ---------------- policy ---------------- */
let POLICY = null;
async function policyInit() {
  const topo = STATE.topo || await get("/topology");
  const hosts = topo.hosts.map(h => h.name).sort();
  fillSel("#pc-src", hosts); fillSel("#pc-dst", hosts, "dc-lms");
  POLICY = await get("/policy");
  $("#pol-ver").textContent = "v" + POLICY.version + " · default " + POLICY.default_action;
  $("#rule-table").innerHTML = `<table><thead><tr><th>id</th><th>name</th><th>src→dst</th><th>svc</th><th>qos</th></tr></thead><tbody>${
    POLICY.rules.map(r => `<tr><td>${r.id}</td><td>${esc(r.name)}</td>
      <td class="tip">${(r.src || []).join(",")} → ${(r.dst || []).join(",")}</td>
      <td>${r.proto || "any"}${r.dst_ports ? "/" + r.dst_ports.join(",") : ""}</td><td>${r.qos || ""}</td></tr>`).join("")}</tbody></table>`;
  matrix();
}
$("#pc-go").onclick = async () => {
  const b = { src: $("#pc-src").value, dst: $("#pc-dst").value, proto: $("#pc-proto").value, port: +$("#pc-port").value };
  const r = await post("/policy/check", b);
  $("#pc-out").textContent = (r.allowed ? "✅ ALLOWED" : "⛔ DENIED") + "\n" +
    (r.reason ? "reason : " + r.reason + "\n" : "") +
    (r.allowed ? `qos    : ${r.qos}  (DSCP ${r.qos_detail?.dscp}, queue ${r.qos_detail?.queue}, ${r.qos_detail?.routing})\n` +
      `path   : ${(r.path || []).join(" → ")}\nlatency: ${fx(r.latency_ms)} ms (routing ${r.routing})` : "");
};
async function matrix() {
  const m = await get("/policy/matrix");
  const roles = m.roles;
  let s = `<table class="matrix"><thead><tr><th></th>${roles.map(r => `<th>${r}</th>`).join("")}</tr></thead><tbody>`;
  for (const sr of roles) {
    s += `<tr><td class="hdr">${sr}</td>` + roles.map(dr => {
      const svc = m.matrix[sr][dr] || [];
      return svc.length ? `<td class="y" title="${svc.join(", ")}">●</td>` : `<td class="n">·</td>`;
    }).join("") + "</tr>";
  }
  $("#matrix").innerHTML = s + "</tbody></table><div class='tip' style='margin-top:6px'>rows = source identity, columns = destination identity; ● = at least one service allowed (hover for details).</div>";
}
$("#pe-load").onclick = async () => { $("#pe-text").value = JSON.stringify(await get("/policy"), null, 2); };
$("#pe-validate").onclick = async () => {
  let pol; try { pol = JSON.parse($("#pe-text").value); } catch (e) { $("#pe-out").textContent = "JSON error: " + e.message; return; }
  const r = await post("/policy/validate", { policy: pol });
  $("#pe-out").textContent = renderValidation(r);
};
$("#pe-apply").onclick = async () => {
  let pol; try { pol = JSON.parse($("#pe-text").value); } catch (e) { $("#pe-out").textContent = "JSON error: " + e.message; return; }
  const r = await post("/policy/apply", { policy: pol });
  if (r.applied) { $("#pe-out").textContent = "✅ deployed to the live network.\n\n" + renderValidation(r.validation); policyInit(); }
  else $("#pe-out").textContent = "⛔ blocked by twin — " + (r.reason || "") + "\n\n" + renderValidation(r.validation) +
    "\n\n(use the console / force flag to override.)";
};
$("#pe-rollback").onclick = async () => { const r = await post("/policy/rollback", {}); $("#pe-out").textContent = JSON.stringify(r, null, 2); policyInit(); };
function renderValidation(r) {
  if (!r) return "";
  if (!r.valid) return "INVALID policy:\n - " + r.errors.join("\n - ");
  let s = (r.compliant ? "✅ intents satisfied — safe to deploy" : "⚠ intents VIOLATED — deploy blocked") + "\n";
  s += "allowed host-pairs: " + r.allowed_pairs_before + " → " + r.allowed_pairs_after + "\n";
  (r.intents || []).filter(i => !i.ok).forEach(i => s += `  ✗ ${i.id} ${i.name}: ${i.violations.slice(0, 3).join("; ")}\n`);
  if (r.newly_allowed?.length) s += "\nnewly ALLOWED:\n" + r.newly_allowed.slice(0, 8).map(x => `  + ${x.src_role}→${x.dst_role} ${x.service} (${x.host_pairs})`).join("\n");
  if (r.newly_denied?.length) s += "\nnewly DENIED:\n" + r.newly_denied.slice(0, 8).map(x => `  - ${x.src_role}→${x.dst_role} ${x.service} (${x.host_pairs})`).join("\n");
  return s;
}

/* ---------------- twin ---------------- */
async function twinInit() {
  const topo = STATE.topo || await get("/topology");
  fillSel("#wf-links", topo.links.map(l => l.id), null, true);
  const places = [...topo.hosts.map(h => h.name), ...Object.keys(topo.blocks), ...[...new Set(topo.hosts.map(h => "role:" + h.role))]];
  fillSel("#wt-src", places, "role:research"); fillSel("#wt-dst", places, "dc-store");
  POLICY = POLICY || await get("/policy");
  fillSel("#wt-qos", Object.keys(POLICY.qos_classes), "bulk");
  intents();
}
$("#wf-go").onclick = async () => {
  const links = $$("#wf-links option:checked").map(o => o.value);
  if (!links.length) { $("#wf-out").textContent = "select at least one link"; return; }
  $("#wf-out").textContent = "simulating…";
  const r = await post("/twin/whatif/failure", { links, synthetic: true });
  let s = `VERDICT: ${r.verdict.toUpperCase()}   (failing ${links.join(", ")})\n\n`;
  s += `rerouted flows : ${r.rerouted_count}\ncut off        : ${r.cut_count}\n`;
  s += `isolated blocks: ${r.isolated_blocks.join(", ") || "none"}\nsingle-homed   : ${r.single_homed_blocks.join(", ") || "none"}\n`;
  s += `peak util      : ${pct(r.before.max_util)} → ${pct(r.after.max_util)}\n`;
  s += `real-time lat  : ${fx(r.before.max_realtime_latency_ms)}ms → ${fx(r.after.max_realtime_latency_ms)}ms\n`;
  if (r.issues.length) s += "\nISSUES:\n" + r.issues.map(i => " • " + i).join("\n");
  if (r.recommendations.length) s += "\n\nRECOMMENDATION:\n" + r.recommendations.map(i => " → " + i).join("\n");
  if (r.rerouted.length) s += "\n\nexample reroutes:\n" + r.rerouted.slice(0, 6).map(x =>
    `  ${x.src}→${x.dst} [${x.qos}]  ${x.old_path.join("-")}  ⇒  ${x.new_path.join("-")}`).join("\n");
  $("#wf-out").textContent = s;
};
$("#wt-go").onclick = async () => {
  const b = { demands: [{ src: $("#wt-src").value, dst: $("#wt-dst").value, mbps: +$("#wt-mbps").value, qos: $("#wt-qos").value }], synthetic: true };
  $("#wt-out").textContent = "predicting…";
  const r = await post("/twin/whatif/traffic", b);
  let s = `added ${r.added_demands} demand(s)\n\n`;
  for (const [m, k] of Object.entries(r.predicted))
    s += `${m.padEnd(9)} peak_util ${pct(k.max_util).padStart(4)}  avg_lat ${fx(k.avg_latency_ms)}ms  congested:${k.congested_links.join(",") || "none"}\n`;
  s += "\n" + r.recommendations.map(x => " → " + x).join("\n");
  $("#wt-out").textContent = s;
};
async function intents() {
  const it = await get("/twin/intents?fresh=1");
  $("#intents").innerHTML = `<div style="margin-bottom:8px">${it.compliant ? '<span class="badge ok">COMPLIANT</span>' : '<span class="badge bad">VIOLATIONS</span>'} <span class="tip">${it.allowed_pairs} allowed host-pairs</span></div>` +
    it.intents.map(i => `<div class="row" style="justify-content:space-between;border-bottom:1px solid var(--line);padding:5px 0">
      <span>${i.ok ? "✅" : "⛔"} <b>${i.id}</b> ${esc(i.name)} <span class="tag">${i.type}</span></span>
      <span class="tip">${i.ok ? "" : i.violations.slice(0, 2).join("; ") + (i.violation_count > 2 ? " +" + (i.violation_count - 2) : "")}</span></div>`).join("");
}
$("#cmp-go").onclick = async () => {
  const r = await get("/twin/compare?synthetic=1&stress=" + (+$("#cmp-stress").value || 1));
  const modes = r.modes;
  $("#cmp-out").innerHTML = `<table><thead><tr><th>strategy</th><th>peak util</th><th>avg latency</th><th>vs hop</th><th>unroutable</th></tr></thead><tbody>${
    Object.entries(modes).map(([m, k]) => `<tr><td><b>${m}</b></td>
      <td><div class="bar"><span style="width:${Math.min(100, k.max_util * 100)}%;background:${utilColor(k.max_util)}"></span></div> ${pct(k.max_util)}</td>
      <td>${fx(k.avg_latency_ms)} ms</td><td class="${k.latency_reduction_pct_vs_hop > 0 ? '' : ''}">${k.latency_reduction_pct_vs_hop != null ? k.latency_reduction_pct_vs_hop + "%" : "–"}</td>
      <td>${k.unroutable}</td></tr>`).join("")}</tbody></table>
      <div class="tip" style="margin-top:6px">${r.demands} demands at ${r.stress}× load. Lower peak-util & latency is better; the PPT's "reduction in routing time" is the <b>vs hop</b> column.</div>`;
};
async function forecast() {
  const f = await get("/twin/forecast?horizon=60");
  $("#forecast").innerHTML = `<table><thead><tr><th>link</th><th>util now</th><th>trend/min</th><th>forecast 60s</th><th>time→congestion</th><th>flaps</th><th>health</th></tr></thead><tbody>${
    f.links.map(l => `<tr><td class="mono">${l.link}</td><td>${pct(l.util_now)}</td>
      <td>${l.trend_per_min > 0 ? "+" : ""}${pct(l.trend_per_min)}</td><td>${pct(l.util_forecast)}</td>
      <td>${l.seconds_to_congestion == null ? "–" : l.seconds_to_congestion + "s"}</td><td class="r">${l.flaps}</td>
      <td><span class="badge ${l.status === 'ok' ? 'ok' : l.status === 'watch' ? 'warn' : 'bad'}">${fx(l.health, 0)}</span></td></tr>`).join("")}</tbody></table>`;
}

/* ---------------- security ---------------- */
async function security() {
  const s = await get("/security"); const topo = STATE.topo || await get("/topology");
  const ids = s.ids;
  $("#sec-tiles").className = "grid g3";
  const c = ids.counters || {};
  const tiles = [
    ["Quarantined", Object.keys(s.quarantine).length, "isolated fabric-wide"],
    ["Unregistered blocked", s.unregistered.length, "zero-trust admission"],
    ["Denied attempts", (await get("/summary")).counters.denied || 0, "policy drops"],
    ["Port scans", c.port_scan || 0, "IDS"],
    ["Profile violations", c.profile_violation || 0, "device over-rate"],
    ["Spoofing / probing", (c.ip_spoofing || 0) + (c.arp_spoofing || 0) + (c.policy_probing || 0), "IDS"]
  ];
  $("#sec-tiles").innerHTML = tiles.map(t => `<div class="stat"><div class="k">${t[0]}</div><div class="v">${t[1]}</div><div class="s">${t[2]}</div></div>`).join("");
  $("#quar").innerHTML = Object.keys(s.quarantine).length ? Object.entries(s.quarantine).map(([h, q]) =>
    `<div class="alert critical"><b>${h}</b> <span class="tag">${q.auto ? "AUTO" : "manual"}</span> @ ${q.location}<br>
     <span class="tip">${esc(q.reason)}</span> <button class="btn sm ghost" onclick="releaseHost('${h}')">release</button></div>`).join("")
    : "<div class='tip'>no quarantined devices</div>";
  fillSel("#q-host", topo.hosts.map(h => h.name).sort());
  $("#rogue").innerHTML = s.unregistered.length ? `<table><thead><tr><th>MAC</th><th>claimed IP</th><th>switch</th><th>pkts</th></tr></thead><tbody>${
    s.unregistered.map(r => `<tr><td class="mono">${r.mac}</td><td>${r.claimed_ip || "–"}</td><td>${r.switch}:${r.port}</td><td>${r.packets}</td></tr>`).join("")}</tbody></table>`
    : "<div class='tip'>no unregistered devices seen</div>";
  $("#denied").innerHTML = `<table><thead><tr><th>time</th><th>src</th><th>dst</th><th>svc</th><th>reason</th></tr></thead><tbody>${
    s.denied.map(d => `<tr><td>${new Date(d.ts * 1000).toLocaleTimeString()}</td><td>${d.src}</td><td>${d.dst}</td>
      <td>${d.proto}${d.port ? "/" + d.port : ""}</td><td class="tip">${esc((d.reason || "").slice(0, 60))}</td></tr>`).join("")
    || "<tr><td colspan=5 class='tip'>none</td></tr>"}</tbody></table>`;
  const bl = ids.baselines || {};
  $("#ids").innerHTML = `<div class="tip">window ${ids.thresholds.window_s}s · scan≥${ids.thresholds.scan} ports · profile×${ids.thresholds.profile_factor} · z≥${ids.thresholds.z}</div>
    <table style="margin-top:8px"><thead><tr><th>device</th><th>mean</th><th>last</th><th>σ</th><th>samples</th></tr></thead><tbody>${
    Object.entries(bl).sort((a, b) => b[1].last_mbps - a[1].last_mbps).slice(0, 10).map(([h, v]) =>
      `<tr><td>${h}</td><td>${fx(v.mean_mbps, 2)}</td><td>${fx(v.last_mbps, 2)}</td><td>${fx(v.std_mbps, 2)}</td><td>${v.samples}</td></tr>`).join("")
    || "<tr><td colspan=5 class='tip'>no telemetry yet</td></tr>"}</tbody></table>`;
}
$("#q-go").onclick = async () => { await post("/quarantine", { host: $("#q-host").value, reason: $("#q-reason").value || "manual" }); security(); };

/* ---------------- ai ---------------- */
async function aiInit() {
  const r = await get("/routing");
  $("#route-modes").innerHTML = r.modes.map(m =>
    `<button class="btn ${m === r.mode ? "" : "ghost"} sm" data-mode="${m}">${m}</button>`).join("");
  $$("#route-modes [data-mode]").forEach(b => b.onclick = async () => {
    await post("/routing", { mode: b.dataset.mode }); aiInit();
  });
  const desc = {
    policy: "Per-QoS-class strategy: real-time/critical → latency-optimal, bulk/BYOD → load-balanced. (default)",
    hop: "Classic shortest-hop — what a legacy static network does. Oversubscribes busy uplinks.",
    latency: "Minimum end-to-end delay (propagation + queueing).",
    load: "Congestion-aware: steers around hot links. Dynamic bandwidth utilisation.",
    qlearning: "Multi-agent Q-routing: each switch learns delivery-time estimates and adapts to live congestion."
  };
  $("#route-desc").textContent = desc[r.mode] || "";
  const topo = STATE.topo || await get("/topology");
  fillSel("#ql-node", topo.switches.map(s => s.name), "core1");
  $("#ql-node").onchange = aiLive;
  aiLive();
}
async function aiLive() {
  if (STATE.tab !== "ai") return;
  const node = $("#ql-node") ? $("#ql-node").value : "core1";
  const q = await get("/ai/qlearning?node=" + node);
  const st = q.stats;
  $("#ql-stats").innerHTML = [
    ["episodes", st.episodes], ["ε (explore)", fx(st.epsilon, 3)], ["agents", st.agents],
    ["TD error", st.mean_td_error_ms == null ? "–" : fx(st.mean_td_error_ms, 3) + " ms"]
  ].map(x => `<div><div class="n">${x[1]}</div><div class="l">${x[0]}</div></div>`).join("");
  const tbl = q.table || {};
  $("#ql-table").innerHTML = `<div class="tip">agent <b>${node}</b> — estimated delivery time (ms) to each destination switch, per next-hop (best first):</div>
    <table style="margin-top:6px"><thead><tr><th>destination</th><th>next-hop → est. ms (ranked)</th></tr></thead><tbody>${
    Object.entries(tbl).map(([d, nb]) => `<tr><td class="mono">${d}</td><td>${
      Object.entries(nb).map(([y, v], i) => `${i === 0 ? "<b>" : ""}${y}:${v}${i === 0 ? "</b>" : ""}`).join(" · ")}</td></tr>`).join("")
    || "<tr><td colspan=2 class='tip'>training…</td></tr>"}</tbody></table>`;
  if (q.benchmark) {
    const m = q.benchmark.modes;
    $("#ql-bench").innerHTML = `<table><thead><tr><th>strategy</th><th>avg latency</th><th>reduction vs hop</th><th>peak util</th></tr></thead><tbody>${
      Object.entries(m).map(([k, v]) => `<tr><td><b>${k}</b></td><td>${fx(v.avg_latency_ms)} ms</td>
        <td>${v.latency_reduction_pct_vs_hop != null ? v.latency_reduction_pct_vs_hop + "%" : "–"}</td><td>${pct(v.max_util)}</td></tr>`).join("")}</tbody></table>
      <div class="tip" style="margin-top:6px">Benchmarked by the digital twin on the live topology (retrained every 10 s).</div>`;
  } else $("#ql-bench").innerHTML = "<div class='tip'>benchmark pending (first ML cycle)…</div>";
}

/* ---------------- emulation ---------------- */
function emuInit() {
  const topo = STATE.topo;
  if (topo) fillSel("#emu-link", topo.links.map(l => l.id));
  $$("#emulation [data-sc]").forEach(b => b.onclick = async () => {
    try { const r = await emu("/emu/scenario", { name: b.dataset.sc, duration: 300 }); out(r.message); }
    catch (e) { out("bridge unreachable (" + e.message + ") — is the emulation running?"); }
  });
  $$("#emulation [data-pr]").forEach(b => b.onclick = async () => {
    try { const r = await emu("/emu/probe", { kind: b.dataset.pr }); out(r.message); }
    catch (e) { out("bridge unreachable (" + e.message + ")"); }
  });
  $("#emu-services").onclick = async () => { try { out((await emu("/emu/services", {})).message); } catch (e) { out("bridge unreachable"); } };
  $("#emu-down").onclick = () => emuLink("down");
  $("#emu-up").onclick = () => emuLink("up");
  function out(m) { $("#emu-out").textContent = "[" + new Date().toLocaleTimeString() + "] " + m; }
  window.__emuOut = out;
}
async function emuLink(state) {
  const id = $("#emu-link").value; const [a, b] = id.split("-");
  try { const r = await emu("/emu/link", { a, b, state }); window.__emuOut(r.message); }
  catch (e) { window.__emuOut("bridge unreachable (" + e.message + ")"); }
}

/* ---------------- helpers ---------------- */
function fillSel(sel, items, selected, multi) {
  const el = $(sel); if (!el) return;
  el.innerHTML = items.map(v => `<option ${v === selected ? "selected" : ""}>${v}</option>`).join("");
}

/* twin tab extras on open */
const _twinInit = twinInit;
twinInit = async function () { await _twinInit(); forecast(); };
$$("#tabs button").forEach(b => { if (b.dataset.v === "twin") b.addEventListener("click", () => setTimeout(forecast, 100)); });

/* boot */
tick();
setInterval(tick, 2500);
