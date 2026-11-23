/* Animated explainer and zone map for the scenario card and the chooser (Phase 3).
   Pure builders over a document object so they run under a fake DOM in node. Strings from the data are
   only ever inserted with textContent. The zone paths and captions are the draft metadata: the UI labels them so. */
(function (root) {
  'use strict';

  var SVGNS = 'http://www.w3.org/2000/svg';
  /* Fixed layout in a 360 x 210 box. Centres are used for links and the packet. */
  var ZONES = [
    {key: 'user',   label: 'User network',  x: 12,  y: 70,  w: 100, h: 70, hint: 'Workstations and laptops'},
    {key: 'server', label: 'Servers',       x: 130, y: 70,  w: 100, h: 70, hint: 'Directory, files, applications'},
    {key: 'edge',   label: 'Internet edge', x: 248, y: 12,  w: 100, h: 70, hint: 'Firewall, proxy, outside hosts'},
    {key: 'ot',     label: 'OT network',    x: 248, y: 128, w: 100, h: 70, hint: 'Industrial controllers'}
  ];
  var LINKS = [['user', 'server'], ['server', 'edge'], ['server', 'ot'], ['user', 'edge']];

  function zoneInfo(key) { for (var i = 0; i < ZONES.length; i++) if (ZONES[i].key === key) return ZONES[i]; return null; }
  function center(z) { return {x: z.x + z.w / 2, y: z.y + z.h / 2}; }

  /* Which hop (index into the zone path) step i of n sits on. A one-zone path has no hop: returns -1. */
  function hopForStep(i, n, pathLen) {
    if (pathLen < 2) return -1;
    if (n < 2) return 0;
    var hops = pathLen - 1;
    return Math.min(hops - 1, Math.floor(i * hops / n));
  }
  function hasLink(a, b) {
    for (var i = 0; i < LINKS.length; i++) if ((LINKS[i][0] === a && LINKS[i][1] === b) || (LINKS[i][0] === b && LINKS[i][1] === a)) return true;
    return false;
  }
  function cleanPath(path) {
    var out = [];
    (path || []).forEach(function (k) { if (zoneInfo(k) && out[out.length - 1] !== k) out.push(k); });
    return out;
  }
  /* Count scenarios per zone for the map: a scenario counts once for each zone it touches. */
  function zoneCounts(mods) {
    var c = {user: 0, server: 0, edge: 0, ot: 0};
    (mods || []).forEach(function (m) {
      var seen = {};
      cleanPath(m && m.meta && m.meta.zone_path).forEach(function (k) { if (!seen[k]) { seen[k] = 1; c[k]++; } });
    });
    return c;
  }
  function touchesZone(m, zone) {
    return cleanPath(m && m.meta && m.meta.zone_path).indexOf(zone) >= 0;
  }

  function svgEl(doc, tag, attrs, kids) {
    var n = doc.createElementNS ? doc.createElementNS(SVGNS, tag) : doc.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) { n.setAttribute(k, attrs[k]); });
    (kids || []).forEach(function (k) { if (k) n.appendChild(k); });
    return n;
  }
  function el(doc, tag, cls, text, attrs) {
    var n = doc.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    Object.keys(attrs || {}).forEach(function (k) { n.setAttribute(k, attrs[k]); });
    return n;
  }

  /* Draw the four zones and links. opts: {hot, active:[a,b]|null, ping, interactive, counts, onZone, selected, label}
     Returns {svg, zones: {key: node}, packet}. */
  function drawMap(doc, opts) {
    opts = opts || {};
    var hot = opts.hot || [];
    var svg = svgEl(doc, 'svg', {viewBox: '0 0 360 210', 'class': 'mm', role: opts.interactive ? 'group' : 'img',
      'aria-label': opts.label || 'Map of the network zones', focusable: 'false'});
    LINKS.forEach(function (l) {
      var a = center(zoneInfo(l[0])), b = center(zoneInfo(l[1]));
      var on = opts.active && ((opts.active[0] === l[0] && opts.active[1] === l[1]) || (opts.active[0] === l[1] && opts.active[1] === l[0]));
      var n = svgEl(doc, 'line', {x1: a.x, y1: a.y, x2: b.x, y2: b.y, 'class': 'mm-link' + (on ? ' act' : '')});
      n.dataset.link = l[0] + '-' + l[1];
      svg.appendChild(n);
    });
    var zones = {};
    ZONES.forEach(function (z) {
      var isHot = hot.indexOf(z.key) >= 0;
      var g = svgEl(doc, 'g', {'class': 'mm-zone-g'});
      g.dataset.zone = z.key;
      var cls = 'mm-zone' + (isHot ? ' hot' : (hot.length ? ' off' : ''));
      if (opts.selected === z.key) cls += ' sel';
      g.appendChild(svgEl(doc, 'rect', {x: z.x, y: z.y, width: z.w, height: z.h, rx: 3, 'class': cls}));
      var lab = svgEl(doc, 'text', {x: z.x + 8, y: z.y + 16, 'class': 'mm-lab'});
      lab.textContent = z.label;
      g.appendChild(lab);
      if (opts.counts) {
        var cnt = svgEl(doc, 'text', {x: z.x + 8, y: z.y + z.h - 10, 'class': 'mm-count'});
        cnt.textContent = (opts.counts[z.key] || 0) + ' scenarios';
        g.appendChild(cnt);
      }
      var c = center(z);
      if (isHot || opts.interactive) g.appendChild(svgEl(doc, 'circle', {cx: c.x, cy: c.y + 4, r: 5, 'class': 'mm-host' + (isHot ? ' hot' : '')}));
      if (opts.ping === z.key) g.appendChild(svgEl(doc, 'circle', {cx: c.x, cy: c.y + 4, r: 8, 'class': 'mm-ring'}));
      if (opts.interactive) {
        g.setAttribute('role', 'button'); g.setAttribute('tabindex', '0');
        g.setAttribute('aria-pressed', opts.selected === z.key ? 'true' : 'false');
        g.setAttribute('aria-label', z.label + ', ' + ((opts.counts && opts.counts[z.key]) || 0) + ' scenarios');
        g.addEventListener('click', function () { if (opts.onZone) opts.onZone(z.key); });
        g.addEventListener('keydown', function (ev) {
          if (ev.key === 'Enter' || ev.key === ' ') { if (ev.preventDefault) ev.preventDefault(); if (opts.onZone) opts.onZone(z.key); }
        });
      }
      zones[z.key] = g; svg.appendChild(g);
    });
    var packet = null;
    if (opts.active) {
      var pa = center(zoneInfo(opts.active[0])), pb = center(zoneInfo(opts.active[1]));
      packet = svgEl(doc, 'circle', {cx: pa.x, cy: pa.y, r: 3.5, 'class': 'mm-pkt'});
      if (packet.style && packet.style.setProperty) {
        packet.style.setProperty('--dx', (pb.x - pa.x) + 'px');
        packet.style.setProperty('--dy', (pb.y - pa.y) + 'px');
      }
      svg.appendChild(packet);
    }
    return {svg: svg, zones: zones, packet: packet};
  }

  /* The explainer. opts: {steps, zonePath, reduced, autoplay, interval, listEl, setTimer, clearTimer}
     Returns {el, goto, next, prev, play, pause, index, playing, stop}. */
  function buildExplainer(doc, opts) {
    var steps = opts.steps || [];
    var path = cleanPath(opts.zonePath);
    var n = steps.length;
    var reduced = !!opts.reduced;
    var interval = opts.interval || 3200;
    var setT = opts.setTimer || (root.setInterval ? root.setInterval.bind(root) : null);
    var clrT = opts.clearTimer || (root.clearInterval ? root.clearInterval.bind(root) : null);
    var idx = 0, timer = null;

    var wrap = el(doc, 'div', 'xplain', null, {'data-explainer': '1'});
    var stage = el(doc, 'div', 'xplain-stage');
    var caption = el(doc, 'p', 'xplain-cap', '', {role: 'status', 'aria-live': 'polite', 'aria-atomic': 'true'});
    var count = el(doc, 'span', 'xplain-count', '');
    var btnPlay = el(doc, 'button', 'btn secondary sm', 'Play', {type: 'button', 'data-act': 'xplay'});
    var btnPrev = el(doc, 'button', 'btn secondary sm', 'Back', {type: 'button', 'data-act': 'xprev'});
    var btnNext = el(doc, 'button', 'btn secondary sm', 'Next step', {type: 'button', 'data-act': 'xnext'});
    var ctrl = el(doc, 'div', 'xplain-ctl');
    [btnPrev, btnPlay, btnNext, count].forEach(function (b) { ctrl.appendChild(b); });
    wrap.appendChild(stage); wrap.appendChild(caption); wrap.appendChild(ctrl);
    if (reduced) wrap.setAttribute('data-reduced', '1');

    function render() {
      while (stage.firstChild) stage.removeChild(stage.firstChild);
      var hop = hopForStep(idx, n, path.length);
      var active = hop >= 0 ? [path[hop], path[hop + 1]] : null;
      var ping = path.length === 1 ? path[0] : null;
      var map = drawMap(doc, {hot: path.slice(), active: active, ping: ping,
        label: 'Where the traffic goes: ' + path.map(function (k) { return zoneInfo(k).label; }).join(', then ')});
      stage.appendChild(map.svg);
      caption.textContent = n ? steps[idx] : '';
      count.textContent = n ? 'Step ' + (idx + 1) + ' of ' + n : '';
      btnPrev.disabled = idx <= 0;
      btnNext.disabled = idx >= n - 1;
      if (opts.listEl && opts.listEl.children) {
        for (var i = 0; i < opts.listEl.children.length; i++) {
          var li = opts.listEl.children[i];
          li.className = 'stp2' + (i === idx ? ' cur' : '');
        }
      }
    }
    function goto(i) { if (!n) return; idx = Math.max(0, Math.min(n - 1, i)); render(); }
    function stop() {
      if (timer != null && clrT) clrT(timer);
      timer = null; caption.setAttribute('aria-live', 'polite'); btnPlay.textContent = 'Play';
    }
    function tick() {
      if (wrap.isConnected === false || idx >= n - 1) { stop(); return; }   // play once through, rest on the last step
      goto(idx + 1);
    }
    function play() {
      if (reduced || !setT || n < 2 || timer != null) return;
      if (idx >= n - 1) goto(0);
      caption.setAttribute('aria-live', 'off');   // do not read every auto-advance aloud; manual steps are announced
      timer = setT(tick, interval);
      btnPlay.textContent = 'Pause';
    }
    btnPlay.addEventListener('click', function () { if (timer != null) stop(); else play(); });
    btnNext.addEventListener('click', function () { stop(); goto(idx + 1); });
    btnPrev.addEventListener('click', function () { stop(); goto(idx - 1); });
    render();
    if (n < 2 || reduced) btnPlay.disabled = true;
    if (opts.autoplay) play();
    return {el: wrap, goto: goto, next: function () { goto(idx + 1); }, prev: function () { goto(idx - 1); }, play: play, pause: stop,
      index: function () { return idx; }, playing: function () { return timer != null; }, stop: stop};
  }

  var api = {ZONES: ZONES, LINKS: LINKS, zoneInfo: zoneInfo, hopForStep: hopForStep, hasLink: hasLink, cleanPath: cleanPath,
    zoneCounts: zoneCounts, touchesZone: touchesZone, drawMap: drawMap, buildExplainer: buildExplainer};
  root.OGExplainer = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : this);
