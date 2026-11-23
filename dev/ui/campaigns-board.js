/* Campaign Builder board: an in-app, animated network-zone FLOW MAP that replays a capture's campaign on a clock.
 * OGC.board.render(container, summaryCampaign, campaignFile, feedback) -> {destroy()}.
 * Hosts are grouped into zone lanes (External / DMZ / Internal servers / Internal users / OT) by address class
 * and name; each action is an edge from->to, labelled with its protocol, coloured by kill-chain stage, that draws
 * itself as the shared clock reaches the action's time. The kept stage strip, clock and inbound-threat list are
 * driven by the same clock. Everything is rendered client-side as inline SVG (dark-theme native via CSS tokens),
 * regenerated from the run report on every render. No libraries, no network calls, no geolocation. Vanilla ES5. */
(function () {
  'use strict';

  var root = (typeof window !== 'undefined') ? window : globalThis;
  root.OGC = root.OGC || {};
  var OGC = root.OGC;

  var ARC_SECONDS = 4;          // clock seconds an edge takes to draw itself
  var SPEEDS = [1, 10, 60];
  var SVGNS = 'http://www.w3.org/2000/svg';

  /* ------------------------------------------------------------------ pure logic */

  function clamp(v, lo, hi) { return v < lo ? lo : (v > hi ? hi : v); }
  function isNum(v) { return typeof v === 'number' && isFinite(v); }

  /* 'mapped' = benchmark range 198.18.0.0/15; 'private' = not routable on the internet; 'public' = internet-routable;
     'none' = not an IPv4 address (domain, url, IPv6, empty). Used to place a host in the External lane vs inside. */
  function classifyAddress(addr) {
    var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(addr == null ? '' : addr).trim());
    if (!m) return 'none';
    var a = +m[1], b = +m[2], c = +m[3], d = +m[4];
    if (a > 255 || b > 255 || c > 255 || d > 255) return 'none';
    if (a === 198 && (b === 18 || b === 19)) return 'mapped';
    if (a === 0 || a === 10 || a === 127 || a >= 224) return 'private';
    if (a === 169 && b === 254) return 'private';
    if (a === 172 && b >= 16 && b <= 31) return 'private';
    if (a === 192 && b === 168) return 'private';
    if (a === 100 && b >= 64 && b <= 127) return 'private';
    return 'public';
  }

  /* Which zone lane a host belongs to. External is decided by address; internal hosts are bucketed by name hints,
     defaulting to the servers lane. Lanes without any host are dropped from the drawing. */
  function zoneOf(host) {
    host = host || {};
    var ip = String(host.ip == null ? '' : host.ip);
    var name = String(host.name == null ? '' : host.name).toLowerCase();
    var cls = classifyAddress(ip);
    if (cls === 'public' || cls === 'mapped') return 'external';
    if (/(plc|scada|hmi|ics|rtu|historian|modbus|dnp3|s7comm|\bot\b|sensoric|actuator)/.test(name)) return 'ot';
    if (/(dmz|proxy|waf|vpn|gw|gateway|edge|bastion|jump|\blb\b|reverse|perimeter)/.test(name)) return 'dmz';
    if (/(ws|wks|workstation|\bpc\b|laptop|desktop|client|user|employee|\bemp\b|staff|kiosk)/.test(name)) return 'users';
    return 'servers';
  }

  function fmtClock(sec) {
    var s = Math.max(0, Math.floor(Number(sec) || 0));
    var h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), r = s % 60;
    function p(n) { return n < 10 ? '0' + n : String(n); }
    return 'T+' + (h ? h + ':' + p(m) : p(m)) + ':' + p(r);
  }

  /* Clock model from entries[].ts: t0 is the earliest action start, every event time is relative to it. */
  function clockModel(entries) {
    var list = Array.isArray(entries) ? entries : [], events = [], t0 = Infinity, t1 = -Infinity, i;
    for (i = 0; i < list.length; i++) {
      var e = list[i] || {};
      var ts = isNum(e.ts) ? e.ts : (isNum(e.first_ts) ? e.first_ts : null);
      if (ts == null) continue;
      var last = isNum(e.last_ts) ? Math.max(e.last_ts, ts) : ts;
      if (ts < t0) t0 = ts;
      if (last > t1) t1 = last;
      events.push({ i: i, ts: ts, last: last });
    }
    if (!events.length) return { t0: 0, duration: 0, events: [] };
    events.forEach(function (ev) { ev.t = ev.ts - t0; ev.end = ev.last - t0; });
    events.sort(function (a, b) { return a.t - b.t || a.i - b.i; });
    return { t0: t0, duration: Math.max(1, t1 - t0), events: events };
  }

  /* entries whose action has started at clock time t (indexes into entries). */
  function reached(model, t) {
    var out = [];
    for (var k = 0; k < model.events.length; k++) if (model.events[k].t <= t) out.push(model.events[k].i);
    return out;
  }

  function arcProgress(t, start, dur, reduced) {
    if (!isNum(start) || !isNum(t) || t < start) return 0;
    if (reduced) return 1;
    var d = dur > 0 ? dur : ARC_SECONDS;
    return clamp((t - start) / d, 0, 1);
  }

  /* One row per indicator: which entries use it and when the clock first reaches it. */
  function iocTimeline(iocs, entries, model) {
    var list = Array.isArray(iocs) ? iocs : [], ents = Array.isArray(entries) ? entries : [];
    var startOf = {};
    model.events.forEach(function (ev) { startOf[ev.i] = ev.t; });
    return list.map(function (ioc, pos) {
      ioc = ioc || {};
      var idx = (ioc.index != null) ? ioc.index : pos, used = [], first = null;
      ents.forEach(function (e, i) {
        if (e && Array.isArray(e.ioc) && e.ioc.indexOf(idx) >= 0 && startOf[i] != null) {
          used.push(i);
          if (first == null || startOf[i] < first) first = startOf[i];
        }
      });
      var addr = ioc.address != null ? String(ioc.address) : '';
      var value = String(ioc.value == null ? '' : ioc.value), kind = classifyAddress(addr);
      return { index: idx, n: pos + 1, value: value, role: String(ioc.role || ''),
               address: addr, kind: kind, firstSeen: first, entries: used };
    });
  }

  /* A geo-free scope label for an indicator (its address class). */
  function kindLabel(kind) {
    if (kind === 'public') return 'external';
    if (kind === 'mapped') return 'external (mapped)';
    if (kind === 'private') return 'internal';
    if (kind === 'none') return 'non-address';
    return '';
  }

  /* Stage strip: pending / active / done by the clock, or "no traffic" when nothing ran in the stage. */
  function stageStates(campaignFile, entries, model, t) {
    var stages = (campaignFile && Array.isArray(campaignFile.stages)) ? campaignFile.stages.slice() : [];
    var ents = Array.isArray(entries) ? entries : [];
    if (!stages.length) {
      var seen = {};
      ents.forEach(function (e) {
        if (!e || e.stage == null || seen[e.stage]) return;
        seen[e.stage] = true;
        stages.push({ id: e.stage, name: e.stage_name || String(e.stage), tactic: '' });
      });
    }
    var timeOf = {};
    model.events.forEach(function (ev) { timeOf[ev.i] = ev; });
    return stages.map(function (s) {
      s = s || {};
      var first = null, last = null, count = 0, ok = 0;
      ents.forEach(function (e, i) {
        if (!e || !timeOf[i]) return;
        if (String(e.stage) !== String(s.id) && !(s.name && e.stage_name === s.name && e.stage == null)) return;
        count++; if (e.status === 'ok') ok++;
        if (first == null || timeOf[i].t < first) first = timeOf[i].t;
        if (last == null || timeOf[i].end > last) last = timeOf[i].end;
      });
      var state = 'none';
      if (count) state = (t >= last) ? 'done' : (t >= first ? 'active' : 'pending');
      return { id: String(s.id == null ? '' : s.id), name: String(s.name || s.id || ''), tactic: String(s.tactic || ''),
               state: state, count: count, ok: ok, start: first, end: last };
    });
  }

  var STATE_LABEL = { none: 'no traffic', pending: 'pending', active: 'running', done: 'done' };

  /* Ordered distinct stage ids (campaign order first, then any extra stages seen in entries) + their display names. */
  function stageOrder(campaignFile, entries) {
    var ids = [], name = {}, seen = {};
    var cs = (campaignFile && Array.isArray(campaignFile.stages)) ? campaignFile.stages : [];
    cs.forEach(function (s) {
      if (!s || s.id == null) return;
      var id = String(s.id);
      if (!seen[id]) { seen[id] = 1; ids.push(id); }
      name[id] = String(s.name || id);
    });
    (Array.isArray(entries) ? entries : []).forEach(function (e) {
      if (!e || e.stage == null) return;
      var id = String(e.stage);
      if (!seen[id]) { seen[id] = 1; ids.push(id); }
      if (!name[id]) name[id] = String(e.stage_name || id);
    });
    return { ids: ids, name: name };
  }

  /* An evenly spread, dark-and-light friendly colour per stage id. */
  function stagePalette(ids) {
    var map = {}, n = Math.max(1, ids.length);
    ids.forEach(function (id, i) { map[id] = 'hsl(' + Math.round((360 * i / n + 8) % 360) + ' 68% 55%)'; });
    return map;
  }

  /* Detection pins: only detections the feedback result flagged as matched, at the first matched action. */
  function detectionPins(feedback, entries, model) {
    var dets = (feedback && Array.isArray(feedback.detections)) ? feedback.detections : [];
    var startOf = {};
    model.events.forEach(function (ev) { startOf[ev.i] = ev.t; });
    var pins = [], n = 0;
    dets.forEach(function (d) {
      if (!d || !d.matched || !Array.isArray(d.matched_actions)) return;
      var acts = d.matched_actions.filter(function (i) { return startOf[i] != null; });
      if (!acts.length) return;
      acts.sort(function (a, b) { return startOf[a] - startOf[b] || a - b; });
      var ent = acts[0];
      n++;
      pins.push({ n: n, id: d.id == null ? '' : String(d.id), title: String(d.title || d.type || 'detection'),
                  risk: isNum(d.risk) ? d.risk : null, t: startOf[ent], entry: ent,
                  techniques: Array.isArray(d.techniques) ? d.techniques.map(String) : [] });
    });
    return pins;
  }

  /* The text alternative: every action in clock order. */
  function buildEventTable(entries, model, timeline) {
    var ents = Array.isArray(entries) ? entries : [];
    var byEntry = {};
    timeline.forEach(function (tl) { tl.entries.forEach(function (i) { (byEntry[i] = byEntry[i] || []).push(tl.n); }); });
    function host(h) { h = h || {}; return String(h.name || h.ip || ''); }
    var rows = model.events.map(function (ev) {
      var e = ents[ev.i] || {};
      return { time: fmtClock(ev.t), stage: String(e.stage_name || e.stage || ''), action: String(e.action || ''),
               status: String(e.status || ''), from: host(e.from_host), to: host(e.to_host),
               proto: Array.isArray(e.protocols) ? e.protocols.join(', ') : '',
               indicators: (byEntry[ev.i] || []).join(', '),
               techniques: Array.isArray(e.techniques) ? e.techniques.join(', ') : '' };
    });
    return { headers: ['Clock', 'Stage', 'Action', 'Status', 'From', 'To', 'Protocol', 'Indicators', 'Techniques'],
             keys: ['time', 'stage', 'action', 'status', 'from', 'to', 'proto', 'indicators', 'techniques'], rows: rows };
  }

  /* ------------------------------------------------------------------ DOM / SVG helpers */

  function h(tag, attrs) {
    var el = document.createElement(tag), k, i;
    if (attrs) {
      for (k in attrs) {
        if (!Object.prototype.hasOwnProperty.call(attrs, k) || attrs[k] == null || attrs[k] === false) continue;
        if (k === 'class') el.className = attrs[k];
        else if (k === 'text') el.textContent = attrs[k];
        else if (k.slice(0, 2) === 'on' && typeof attrs[k] === 'function') el.addEventListener(k.slice(2), attrs[k]);
        else el.setAttribute(k, attrs[k] === true ? '' : String(attrs[k]));
      }
    }
    function add(c) {
      if (c == null || c === false) return;
      if (Array.isArray(c)) { c.forEach(add); return; }
      el.appendChild(typeof c === 'object' ? c : document.createTextNode(String(c)));
    }
    for (i = 2; i < arguments.length; i++) add(arguments[i]);
    return el;
  }

  function sv(tag, attrs) {
    var el = document.createElementNS(SVGNS, tag), k, i;
    if (attrs) {
      for (k in attrs) {
        if (!Object.prototype.hasOwnProperty.call(attrs, k) || attrs[k] == null || attrs[k] === false) continue;
        if (k === 'text') el.textContent = attrs[k];
        else el.setAttribute(k, attrs[k] === true ? '' : String(attrs[k]));
      }
    }
    for (i = 2; i < arguments.length; i++) {
      var c = arguments[i];
      if (c == null || c === false) continue;
      if (Array.isArray(c)) { c.forEach(function (x) { if (x) el.appendChild(x); }); }
      else el.appendChild(typeof c === 'object' ? c : document.createTextNode(String(c)));
    }
    return el;
  }

  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }

  function tableOf(spec, caption) {
    var head = h('tr', null, spec.headers.map(function (t) { return h('th', { scope: 'col', text: t }); }));
    var body = spec.rows.map(function (r) { return h('tr', null, spec.keys.map(function (k) { return h('td', { text: r[k] }); })); });
    return h('table', { 'class': 'ogc-table' }, h('caption', { text: caption }), h('thead', null, head), h('tbody', null, body));
  }

  function prefersReduced() {
    try { return !!(root.matchMedia && root.matchMedia('(prefers-reduced-motion: reduce)').matches); } catch (e) { return false; }
  }

  /* ------------------------------------------------------------------ flow-map geometry */

  var LANES = [['external', 'External'], ['dmz', 'DMZ'], ['servers', 'Internal servers'],
               ['users', 'Internal users'], ['ot', 'OT']];
  var GUT = 132, NW = 132, NH = 50, GAPX = 28, LANE_H = 128, PAD_T = 18, PAD_B = 18;
  var MAX_COLS = 8, SUBROW_H = NH + 30;   // wrap a lane's hosts into rows of at most MAX_COLS

  function qpoint(a, c, b, u) {
    var v = 1 - u;
    return { x: v * v * a.x + 2 * v * u * c.x + u * u * b.x, y: v * v * a.y + 2 * v * u * c.y + u * u * b.y };
  }

  /* Build the node/edge model and the SVG for a campaign. Returns { el, nodes, edges, lanes, paint(t) }. */
  function buildFlow(entries, model, stageColor, stageNameMap, reduced) {
    var nodes = {}, order = [];
    function nodeFor(host) {
      host = host || {};
      var key = String(host.ip || host.name || '?') || '?';
      if (!nodes[key]) {
        nodes[key] = { key: key, name: String(host.name || host.ip || key), ip: String(host.ip || ''),
                       zone: zoneOf(host), firstT: Infinity };
        order.push(key);
      }
      return nodes[key];
    }

    var edges = [], pairCount = {};
    model.events.forEach(function (ev) {
      var e = entries[ev.i] || {};
      var a = nodeFor(e.from_host), b = nodeFor(e.to_host);
      if (ev.t < a.firstT) a.firstT = ev.t;
      if (ev.t < b.firstT) b.firstT = ev.t;
      var pk = a.key + '\u0001' + b.key;
      var fan = pairCount[pk] || 0; pairCount[pk] = fan + 1;
      var proto = (Array.isArray(e.protocols) && e.protocols.length) ? String(e.protocols[0]) : String(e.action || '');
      var sid = String(e.stage == null ? '' : e.stage);
      edges.push({ from: a.key, to: b.key, t: ev.t, stage: sid, stageName: String(e.stage_name || stageNameMap[sid] || sid),
                   proto: proto, action: String(e.action || ''), packets: e.packets || 0, bytes: e.bytes || 0,
                   status: String(e.status || ''), fan: fan, color: stageColor[sid] || 'var(--gray)' });
    });

    /* lanes that actually have hosts, nodes ordered left-to-right by first appearance */
    var byZone = {};
    order.forEach(function (k) { (byZone[nodes[k].zone] = byZone[nodes[k].zone] || []).push(k); });
    var lanes = LANES.filter(function (L) { return (byZone[L[0]] || []).length; }).map(function (L) {
      var keys = (byZone[L[0]] || []).slice().sort(function (x, y) {
        return (nodes[x].firstT - nodes[y].firstT) || (nodes[x].name < nodes[y].name ? -1 : 1);
      });
      return { id: L[0], label: L[1], keys: keys };
    });
    var maxLane = lanes.reduce(function (m, l) { return Math.max(m, l.keys.length); }, 1);
    var usedCols = Math.min(MAX_COLS, maxLane);
    var top = PAD_T;
    lanes.forEach(function (lane) {
      var subRows = Math.max(1, Math.ceil(lane.keys.length / usedCols));
      lane.top = top;
      lane.height = Math.max(LANE_H, subRows * SUBROW_H + 14);
      lane.keys.forEach(function (k, idx) {
        var col = idx % usedCols, rw = Math.floor(idx / usedCols);
        nodes[k].x = GUT + col * (NW + GAPX) + NW / 2;
        nodes[k].y = lane.top + 12 + rw * SUBROW_H + NH / 2;
      });
      top += lane.height;
    });
    var W = GUT + usedCols * NW + (usedCols - 1) * GAPX + 24;
    var H = top + PAD_B;

    var svg = sv('svg', { 'class': 'ogcb-flow', viewBox: '0 0 ' + W + ' ' + H, preserveAspectRatio: 'xMidYMid meet',
      role: 'img', 'aria-label': 'Network flow map. Hosts are grouped into zone lanes; each campaign action is an arrow ' +
      'from one host to another, coloured by kill-chain stage, that draws itself as the replay clock reaches it. ' +
      'The same actions are listed in the text table below.' });

    /* lane bands + labels */
    var gLanes = sv('g', null);
    lanes.forEach(function (lane, li) {
      var y = lane.top, lh = lane.height;
      gLanes.appendChild(sv('rect', { x: 0, y: y, width: W, height: lh,
        fill: (li % 2) ? 'var(--surface-2)' : 'var(--surface)', opacity: (li % 2) ? '0.5' : '0.25' }));
      gLanes.appendChild(sv('line', { x1: GUT - 14, y1: y, x2: GUT - 14, y2: y + lh, stroke: 'var(--line)', 'stroke-width': 1 }));
      gLanes.appendChild(sv('text', { x: 12, y: y + lh / 2, fill: 'var(--gray)', 'font-size': 12,
        'font-weight': 600, 'dominant-baseline': 'middle', 'class': 'ogcb-lane-label', text: lane.label }));
    });
    svg.appendChild(gLanes);

    /* edges (track + arrowhead + travelling dot + protocol label) */
    var gEdges = sv('g', null);
    edges.forEach(function (ed) {
      var a = nodes[ed.from], b = nodes[ed.to];
      if (!a || !b || !isNum(a.x) || !isNum(b.x)) { ed.skip = true; return; }
      var mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
      var dx = b.x - a.x, dy = b.y - a.y, len = Math.sqrt(dx * dx + dy * dy) || 1;
      var base = (a.y === b.y) ? -Math.min(46, len * 0.32) : 16;
      var off = base * (1 + 0.55 * ed.fan) * (ed.fan % 2 ? -1 : 1);
      var cx, cy;
      if (a.y === b.y) { cx = mx; cy = my + off; }
      else { cx = mx + (-dy / len) * off; cy = my + (dx / len) * off; }
      ed.a = { x: a.x, y: a.y }; ed.b = { x: b.x, y: b.y }; ed.ctrl = { x: cx, y: cy };

      var track = sv('path', { d: 'M' + a.x + ' ' + a.y + ' Q' + cx + ' ' + cy + ' ' + b.x + ' ' + b.y,
        fill: 'none', stroke: ed.color, 'stroke-width': 2.2, 'stroke-linecap': 'round', 'class': 'ogcb-edge', opacity: 0 });
      track.appendChild(sv('title', { text: a.name + '  →  ' + b.name + '  ·  ' + ed.proto +
        '  ·  ' + ed.stageName + '  ·  ' + fmtClock(ed.t) +
        (ed.packets ? '  ·  ' + ed.packets + ' pkts' : '') + (ed.status && ed.status !== 'ok' ? '  ·  ' + ed.status : '') }));
      var len2 = 0;
      try { len2 = track.getTotalLength(); } catch (e2) { len2 = len * 1.15; }
      ed.len = len2 > 0 ? len2 : (len * 1.15);
      track.setAttribute('stroke-dasharray', ed.len);
      track.setAttribute('stroke-dashoffset', ed.len);

      /* arrowhead at the target, oriented along the final tangent */
      var ang = Math.atan2(b.y - cy, b.x - cx), ah = 7;
      var axp = b.x - 10 * Math.cos(ang), ayp = b.y - 10 * Math.sin(ang);
      var p1x = axp - ah * Math.cos(ang - 0.5), p1y = ayp - ah * Math.sin(ang - 0.5);
      var p2x = axp - ah * Math.cos(ang + 0.5), p2y = ayp - ah * Math.sin(ang + 0.5);
      var head = sv('path', { d: 'M' + (b.x - 10 * Math.cos(ang)) + ' ' + (b.y - 10 * Math.sin(ang)) +
        ' L' + p1x + ' ' + p1y + ' L' + p2x + ' ' + p2y + ' Z', fill: ed.color, opacity: 0 });
      var dot = sv('circle', { r: 3.6, fill: ed.color, opacity: 0 });
      var label = sv('text', { 'font-size': 10.5, fill: 'var(--ink)', 'text-anchor': 'middle',
        'dominant-baseline': 'middle', 'class': 'ogcb-edge-label', opacity: 0, text: ed.proto });
      ed.trackEl = track; ed.headEl = head; ed.dotEl = dot; ed.labelEl = label;
      gEdges.appendChild(track); gEdges.appendChild(head); gEdges.appendChild(dot); gEdges.appendChild(label);
    });
    svg.appendChild(gEdges);

    /* nodes */
    var gNodes = sv('g', null);
    order.forEach(function (k) {
      var nd = nodes[k];
      if (!isNum(nd.x)) return;
      var rect = sv('rect', { x: nd.x - NW / 2, y: nd.y - NH / 2, width: NW, height: NH, rx: 7,
        fill: 'var(--surface)', stroke: 'var(--line)', 'stroke-width': 1.3, 'class': 'ogcb-node' });
      var nm = String(nd.name).length > 18 ? String(nd.name).slice(0, 17) + '…' : nd.name;
      var t1 = sv('text', { x: nd.x, y: nd.y - 5, fill: 'var(--ink)', 'font-size': 12, 'font-weight': 600,
        'text-anchor': 'middle', 'class': 'ogcb-node-name', text: nm });
      var t2 = sv('text', { x: nd.x, y: nd.y + 11, fill: 'var(--gray)', 'font-size': 10,
        'text-anchor': 'middle', 'class': 'ogcb-node-ip', text: nd.ip });
      var g = sv('g', null, rect, t1, t2);
      g.appendChild(sv('title', { text: nd.name + (nd.ip ? '  (' + nd.ip + ')' : '') }));
      nd.rectEl = rect;
      gNodes.appendChild(g);
    });
    svg.appendChild(gNodes);

    function paint(t) {
      order.forEach(function (k) {
        var nd = nodes[k];
        if (!nd.rectEl) return;
        var lit = nd.firstT <= t;
        nd.rectEl.setAttribute('stroke', lit ? 'var(--ink)' : 'var(--line)');
        nd.rectEl.setAttribute('stroke-width', lit ? 1.8 : 1.3);
        nd.rectEl.setAttribute('fill', lit ? 'var(--surface-2)' : 'var(--surface)');
      });
      edges.forEach(function (ed) {
        if (ed.skip) return;
        if (t < ed.t) {
          ed.trackEl.setAttribute('opacity', 0);
          ed.headEl.setAttribute('opacity', 0);
          ed.dotEl.setAttribute('opacity', 0);
          ed.labelEl.setAttribute('opacity', 0);
          ed.trackEl.setAttribute('stroke-dashoffset', ed.len);
          return;
        }
        var u = reduced ? 1 : clamp((t - ed.t) / ARC_SECONDS, 0, 1);
        ed.trackEl.setAttribute('opacity', u < 1 ? 0.95 : 0.5);
        ed.trackEl.setAttribute('stroke-dashoffset', ed.len * (1 - u));
        ed.headEl.setAttribute('opacity', u >= 0.85 ? (u < 1 ? 1 : 0.7) : 0);
        if (u < 1) {
          var p = qpoint(ed.a, ed.ctrl, ed.b, u);
          ed.dotEl.setAttribute('cx', p.x); ed.dotEl.setAttribute('cy', p.y); ed.dotEl.setAttribute('opacity', 1);
          ed.labelEl.setAttribute('x', p.x); ed.labelEl.setAttribute('y', p.y - 9); ed.labelEl.setAttribute('opacity', 0.95);
        } else {
          ed.dotEl.setAttribute('opacity', 0); ed.labelEl.setAttribute('opacity', 0);
        }
      });
    }

    return { el: svg, nodes: nodes, edges: edges, lanes: lanes, paint: paint,
             count: { hosts: order.length, lanes: lanes.length, flows: edges.length } };
  }

  /* ------------------------------------------------------------------ render */

  function render(container, summaryCampaign, campaignFile, feedback) {
    if (!container) return { destroy: function () {} };
    clear(container);
    var summary = summaryCampaign || {};
    var entries = Array.isArray(summary.entries) ? summary.entries : [];
    var model = clockModel(entries);
    var timeline = iocTimeline(summary.iocs, entries, model);
    var pins = detectionPins(feedback, entries, model);
    var reduced = prefersReduced();
    var ord = stageOrder(campaignFile, entries);
    var stageColor = stagePalette(ord.ids);
    var S = { t: 0, playing: false, speed: 1, destroyed: false, raf: null, last: 0,
              sig: { stages: null, threats: null, pins: null } };

    var root_ = h('div', { 'class': 'ogc-board' });
    container.appendChild(root_);
    root_.appendChild(h('h4', { 'class': 'ogcb-title', text: 'Campaign board' }));

    if (!entries.length || !model.events.length) {
      root_.appendChild(h('p', { 'class': 'ogcb-note', text: 'There is no campaign traffic in this capture, so there is nothing to show on the board.' }));
      return { destroy: function () {} };
    }

    var stripEl = h('ol', { 'class': 'ogcb-stages', 'aria-label': 'Stage progress' });
    var flow = buildFlow(entries, model, stageColor, ord.name, reduced);
    var mapWrap = h('div', { 'class': 'ogcb-mapwrap ogcb-flowwrap' }, flow.el);
    var flowNote = h('p', { 'class': 'ogcb-note', role: 'status',
      text: flow.count.hosts + ' hosts across ' + flow.count.lanes + ' zone' + (flow.count.lanes === 1 ? '' : 's') +
            ', ' + flow.count.flows + ' flow' + (flow.count.flows === 1 ? '' : 's') + '. Press Play to replay them in order.' });

    /* stage colour legend (only stages that produced a flow) */
    var flowStages = {};
    flow.edges.forEach(function (e) { if (e.stage) flowStages[e.stage] = true; });
    var legendItems = ord.ids.filter(function (id) { return flowStages[id]; }).map(function (id) {
      return h('span', { 'class': 'ogcb-legend-item' },
        h('span', { 'class': 'ogcb-legend-sw', 'aria-hidden': 'true', style: 'background:' + stageColor[id] }),
        h('span', { text: ord.name[id] || id }));
    });
    var legend = legendItems.length ? h('div', { 'class': 'ogcb-legend', 'aria-label': 'Flow colour by stage' }, legendItems) : null;

    var playBtn = h('button', { type: 'button', 'class': 'btn ogc-sm ogcb-play', 'aria-label': 'Play the clock', text: 'Play' });
    var speedBtns = SPEEDS.map(function (sp) {
      return h('button', { type: 'button', 'class': 'ogc-chip ogcb-speed' + (sp === 1 ? ' is-on' : ''), 'aria-pressed': sp === 1 ? 'true' : 'false',
        'aria-label': 'Speed ' + sp + ' times', 'data-speed': sp, text: sp + 'x' });
    });
    var scrub = h('input', { type: 'range', 'class': 'ogcb-scrub', min: 0, max: Math.ceil(model.duration), step: 1, value: 0,
      'aria-label': 'Replay clock position' });
    var clockEl = h('span', { 'class': 'ogcb-clock', 'aria-hidden': 'true' });
    var threatBox = h('div', { 'class': 'ogcb-threats' });
    var pinBox = h('div', { 'class': 'ogcb-pins' });

    root_.appendChild(stripEl);
    if (legend) root_.appendChild(legend);
    root_.appendChild(mapWrap);
    root_.appendChild(flowNote);
    root_.appendChild(h('div', { 'class': 'ogcb-controls' }, playBtn,
      h('span', { 'class': 'ogcb-speeds', role: 'group', 'aria-label': 'Playback speed' }, speedBtns), scrub, clockEl));
    if (reduced) root_.appendChild(h('p', { 'class': 'ogcb-note', text: 'Reduced motion is on: playback is off, drag the clock to move through the campaign.' }));
    root_.appendChild(threatBox);
    if (feedback) root_.appendChild(pinBox);
    root_.appendChild(h('details', { 'class': 'ogcb-alt' }, h('summary', { text: 'Text alternative: every action in clock order' }),
      tableOf(buildEventTable(entries, model, timeline), 'Campaign actions in clock order')));
    if (reduced) playBtn.setAttribute('disabled', '');

    /* ---- state -> view */
    function updateStrip() {
      var st = stageStates(campaignFile, entries, model, S.t);
      var sig = st.map(function (s) { return s.state; }).join(',');
      if (sig === S.sig.stages) return;
      S.sig.stages = sig;
      clear(stripEl);
      st.forEach(function (s) {
        var col = stageColor[s.id];
        var li = h('li', { 'class': 'ogcb-stage is-' + s.state },
          h('span', { 'class': 'ogcb-stage-name', text: s.name }),
          s.tactic ? h('span', { 'class': 'ogcb-stage-tactic', text: s.tactic }) : null,
          h('span', { 'class': 'ogcb-stage-state', text: STATE_LABEL[s.state] }));
        if (col && s.count) li.style.borderLeft = '3px solid ' + col;
        stripEl.appendChild(li);
      });
    }

    function updateThreats() {
      var sig = timeline.map(function (tl) { return tl.firstSeen != null && tl.firstSeen <= S.t ? 1 : 0; }).join('');
      if (sig === S.sig.threats) return;
      S.sig.threats = sig;
      clear(threatBox);
      if (!timeline.length) { threatBox.appendChild(h('p', { 'class': 'ogcb-note', text: 'This campaign lists no indicators.' })); return; }
      var rows = timeline.map(function (tl) {
        var seen = tl.firstSeen != null && tl.firstSeen <= S.t;
        return h('tr', { 'class': seen ? 'is-seen' : 'is-waiting' },
          h('td', { text: String(tl.n) }), h('td', { text: tl.value }), h('td', { text: tl.role }),
          h('td', { text: kindLabel(tl.kind) }),
          h('td', { text: tl.firstSeen == null ? 'not used' : (seen ? fmtClock(tl.firstSeen) : 'not yet') }));
      });
      threatBox.appendChild(h('table', { 'class': 'ogc-table ogcb-threat-table' }, h('caption', { text: 'Inbound threat list (indicator, role, scope, first seen on the clock)' }),
        h('thead', null, h('tr', null, ['No.', 'Indicator', 'Role', 'Scope', 'First seen'].map(function (t) { return h('th', { scope: 'col', text: t }); }))),
        h('tbody', null, rows)));
    }

    function updatePins() {
      if (!feedback) return;
      var sig = pins.map(function (p) { return p.t <= S.t ? 1 : 0; }).join('');
      if (sig === S.sig.pins) return;
      S.sig.pins = sig;
      clear(pinBox);
      if (!pins.length) { pinBox.appendChild(h('p', { 'class': 'ogcb-note', text: 'The supplied detection result has no detections matched to an action.' })); return; }
      var rows = pins.map(function (p) {
        var on = p.t <= S.t;
        return h('tr', { 'class': on ? 'is-seen' : 'is-waiting' }, h('td', { text: 'D' + p.n }), h('td', { text: p.title }),
          h('td', { text: p.risk == null ? '' : String(p.risk) }), h('td', { text: p.techniques.join(', ') }),
          h('td', { text: on ? fmtClock(p.t) : 'not yet' }));
      });
      pinBox.appendChild(h('table', { 'class': 'ogc-table ogcb-pin-table' }, h('caption', { text: 'Detections supplied with the sensor result, matched to an action' }),
        h('thead', null, h('tr', null, ['Pin', 'Detection', 'Risk', 'Techniques', 'Shown at'].map(function (t) { return h('th', { scope: 'col', text: t }); }))),
        h('tbody', null, rows)));
    }

    function refresh() {
      scrub.value = String(Math.floor(S.t));
      scrub.setAttribute('aria-valuetext', fmtClock(S.t) + ' of ' + fmtClock(model.duration));
      clockEl.textContent = fmtClock(S.t) + ' / ' + fmtClock(model.duration);
      updateStrip(); updateThreats(); updatePins(); flow.paint(S.t);
    }

    function setPlaying(on) {
      if (reduced) on = false;
      S.playing = !!on;
      playBtn.textContent = S.playing ? 'Pause' : 'Play';
      playBtn.setAttribute('aria-label', S.playing ? 'Pause the clock' : 'Play the clock');
      if (S.playing) {
        if (S.t >= model.duration) S.t = 0;
        S.last = 0; schedule();
      }
    }
    function schedule() {
      if (S.raf != null || !root.requestAnimationFrame) return;
      S.raf = root.requestAnimationFrame(tick);
    }
    function tick(now) {
      S.raf = null;
      if (S.destroyed || (container.isConnected === false)) return;
      if (!S.playing) return;
      var dt = S.last ? Math.min(0.25, (now - S.last) / 1000) : 0;
      S.last = now;
      S.t = Math.min(model.duration, S.t + dt * S.speed);
      refresh();
      if (S.t >= model.duration) { setPlaying(false); return; }
      schedule();
    }

    playBtn.addEventListener('click', function () { setPlaying(!S.playing); });
    speedBtns.forEach(function (b) {
      b.addEventListener('click', function () {
        S.speed = Number(b.getAttribute('data-speed')) || 1;
        speedBtns.forEach(function (o) { var on = o === b; o.setAttribute('aria-pressed', on ? 'true' : 'false'); o.className = 'ogc-chip ogcb-speed' + (on ? ' is-on' : ''); });
      });
    });
    function onScrub() { S.t = clamp(Number(scrub.value) || 0, 0, model.duration); refresh(); }
    scrub.addEventListener('input', onScrub);
    scrub.addEventListener('change', onScrub);

    refresh();
    return { destroy: function () {
      S.destroyed = true; S.playing = false;
      if (S.raf != null && root.cancelAnimationFrame) root.cancelAnimationFrame(S.raf);
    } };
  }

  OGC.board = { render: render, _test: {
    classifyAddress: classifyAddress, zoneOf: zoneOf, fmtClock: fmtClock, clockModel: clockModel, reached: reached,
    arcProgress: arcProgress, iocTimeline: iocTimeline, kindLabel: kindLabel, stageStates: stageStates,
    stageOrder: stageOrder, stagePalette: stagePalette, detectionPins: detectionPins, buildEventTable: buildEventTable,
    ARC_SECONDS: ARC_SECONDS
  } };
})();
