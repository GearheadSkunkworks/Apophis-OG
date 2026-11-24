/* Timeline of the capture day (Phase 4). One lane per family, a marker per scenario placed by its start window on the
   16 hours of traffic, an always-on normal-day lane, and a Timeline/List switch. Markers are buttons: click opens the scenario
   card, arrow keys move along a lane. Labels are elapsed hours, never clock times. Pure layout is exported for tests;
   text from data is only set with textContent. Needs OGCards (parseWindow, familyOf, FAMILIES). */
(function (root) {
  'use strict';
  var TRACK_MIN = 16 * 60;
  var LANES = ['SEC', 'PERF', 'CRYP', 'REPLAY'];
  var GAP = 0.6;     // percent of the track kept clear after a block, so blocks that end and start together never touch

  /* items: [{name, left, width}] in percent. Greedy packing into sub-rows so markers never overlap.
     Returns {items: [{name, left, width, row}] sorted by left, rows}. */
  function layout(items) {
    var sorted = items.slice().sort(function (a, b) { return a.left - b.left || a.name.localeCompare(b.name); });
    var rowEnds = [];
    var out = sorted.map(function (it) {
      var r = 0;
      while (r < rowEnds.length && rowEnds[r] > it.left + 0.0001) r++;
      rowEnds[r] = it.left + it.width + GAP;
      return {name: it.name, left: it.left, width: it.width, row: r};
    });
    return {items: out, rows: Math.max(1, rowEnds.length)};
  }

  /* Dragging a marker by dx pixels along a track `width` pixels wide moves it dx/width of the 16 hours, in whole minutes,
     held to its limits [min, max]. */
  function dragShift(base, dx, width, limits) {
    var d = base + (width > 0 ? Math.round(dx * TRACK_MIN / width) : 0);
    return limits ? Math.max(limits[0], Math.min(limits[1], d)) : base;
  }
  var DRAG_PX = 4;        // a press that moves less than this is a click, not a drag
  var NUDGE = 1, NUDGE_BIG = 15;

  function rulerLabels() {
    var out = [];
    for (var h = 0; h <= 16; h += 2) out.push({text: h === 0 ? 'start' : h + ' h', left: 100 * h / 16});
    return out;
  }

  function el(doc, tag, cls, text, attrs) {
    var n = doc.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    Object.keys(attrs || {}).forEach(function (k) { n.setAttribute(k, attrs[k]); });
    return n;
  }
  function setPct(n, prop, v) { if (n.style) n.style[prop] = v + '%'; }

  /* cfg: {doc, host, cards: OGCards, getModules(): visible modules, getSelected(): Set, open(name, opener)} */
  function create(cfg) {
    var doc = cfg.doc || root.document;
    var C = cfg.cards;
    var playhead = null, phNode = null, tipNode = null, bandNode = null, gridNode = null;
    function applyPlayhead() {
      if (!phNode) return;
      if (playhead == null) { phNode.hidden = true; return; }
      phNode.hidden = false;
      if (phNode.style) phNode.style.left = 'calc(140px + (100% - 140px) * ' + (playhead / 100) + ')';
      phNode.setAttribute('aria-label', 'Build progress, about ' + Math.round(playhead) + ' percent');
    }
    function setPlayhead(pct) { playhead = pct == null ? null : Math.max(0, Math.min(100, pct)); applyPlayhead(); }
    /* Hover or focus: dim the other blocks, shade the block's span across every lane, and float its name above it.
       Nothing here changes the layout, so the graphic never moves under the pointer. */
    function showTip(b, text, left, width) {
      if (!tipNode) return;
      gridNode.classList.add('tlx-focus');
      var prev = gridNode.querySelector('.tlx-mk.hot'); if (prev) prev.classList.remove('hot');
      b.classList.add('hot');
      bandNode.hidden = false;
      if (bandNode.style) { bandNode.style.left = 'calc(140px + (100% - 140px) * ' + (left / 100) + ')'; bandNode.style.width = 'calc((100% - 140px) * ' + (width / 100) + ')'; }
      tipNode.textContent = text; tipNode.hidden = false;
      if (b.getBoundingClientRect && gridNode.getBoundingClientRect) {
        var g = gridNode.getBoundingClientRect(), r = b.getBoundingClientRect();
        var x = r.left - g.left + r.width / 2, tw = tipNode.offsetWidth || 0;
        x = Math.max(tw / 2 + 4, Math.min(g.width - tw / 2 - 4, x));       // keep the tip inside the graphic
        tipNode.style.left = x + 'px';
        tipNode.style.top = (r.top - g.top - 6) + 'px';
      }
    }
    function hideTip() {
      if (!tipNode) return;
      gridNode.classList.remove('tlx-focus');
      var h = gridNode.querySelector('.tlx-mk.hot'); if (h) h.classList.remove('hot');
      bandNode.hidden = true; tipNode.hidden = true;
    }
    var marks = {}, suppressClick = false;
    /* After a move: tell the page (autosave, lists, card) and redraw, which re-packs the lanes. */
    function commit(name) {
      if (cfg.onShift) cfg.onShift(name);
      render();
      var again = cfg.host.querySelector && cfg.host.querySelector('[data-mod="' + name + '"]');
      if (again && again.focus) again.focus();
    }
    /* Press and drag a marker along its track. The lanes stay as they are while the pointer is down and re-pack on release;
       Escape puts everything back. */
    function wireDrag(b, m, trk) {
      b.addEventListener('pointerdown', function (ev) {
        if (ev.button !== undefined && ev.button !== 0) return;
        var x0 = ev.clientX, base = m.shift || 0, dragging = false, before = C.collectShifts(cfg.getModules());
        var width = trk.getBoundingClientRect ? trk.getBoundingClientRect().width : 0;
        var lim = C.shiftLimits(m);
        function place(name) {
          var mm = cfg.getModules().filter(function (x) { return x.name === name; })[0], mk = marks[name];
          if (!mm || !mk) return;
          var cw = C.winOf(mm); setPct(mk, 'left', cw.left); setPct(mk, 'width', cw.width);
        }
        function move(e) {
          var dx = e.clientX - x0;
          if (!dragging && Math.abs(dx) < DRAG_PX) return;
          if (!dragging) { dragging = true; if (b.setPointerCapture && e.pointerId !== undefined) { try { b.setPointerCapture(e.pointerId); } catch (x) { /* no capture: the window listeners still follow */ } } }
          C.setShift(cfg.getModules(), m.name, dragShift(base, dx, width, lim), cfg.getSelected());
          place(m.name); if (m.shift_partner) place(m.shift_partner);
          showTip(b, (m.title || m.name) + ' ' + C.winOf(m).text, C.winOf(m).left, C.winOf(m).width);
        }
        function end(e, cancel) {
          root.removeEventListener('pointermove', move); root.removeEventListener('pointerup', up); root.removeEventListener('keydown', esc, true);
          if (!dragging) return;
          suppressClick = true; setTimeout(function () { suppressClick = false; }, 0);
          if (cancel) { C.loadShifts(cfg.getModules(), before); render(); return; }
          commit(m.name);
        }
        function up(e) { end(e, false); }
        function esc(e) { if (e.key === 'Escape') { e.stopPropagation(); end(e, true); } }
        root.addEventListener('pointermove', move); root.addEventListener('pointerup', up); root.addEventListener('keydown', esc, true);
      });
    }
    function render() {
      marks = {};
      while (cfg.host.firstChild) cfg.host.removeChild(cfg.host.firstChild);
      var mods = cfg.getModules(), sel = cfg.getSelected();
      var grid = el(doc, 'div', 'tlx', null, {role: 'group', 'aria-label': 'Scenarios placed on the 16 hours of traffic. Press Enter on a marker to open its card.'});
      var placed = 0, unplaced = 0;
      var ruler = el(doc, 'div', 'tlx-ruler', null, {'aria-hidden': 'true'});
      rulerLabels().forEach(function (l) { var s = el(doc, 'span', null, l.text); setPct(s, 'left', l.left); ruler.appendChild(s); });
      var rr = el(doc, 'div', 'tlx-row tlx-head'); rr.appendChild(el(doc, 'div', 'tlx-lab', '')); rr.appendChild(ruler);
      grid.appendChild(rr);
      LANES.forEach(function (fam) {
        var inLane = mods.filter(function (m) { return C.familyOf(m) === fam; });   // every scenario sets the lane's height and each block's place, so nothing moves when the selection changes
        if (!inLane.length) return;
        var pos = [], byName = {};
        inLane.forEach(function (m) {
          var w = C.winOf(m);
          byName[m.name] = m;
          if (w) pos.push({name: m.name, left: w.left, width: w.width}); else unplaced++;
        });
        var lay = layout(pos);
        var info = C.FAMILIES.filter(function (f) { return f.key === fam; })[0];
        var row = el(doc, 'div', 'tlx-row');
        var lab = el(doc, 'div', 'tlx-lab', info.heading);
        lab.appendChild(el(doc, 'small', null, inLane.filter(function (m) { return sel.has(m.name); }).length + ' in capture'));
        var trk = el(doc, 'div', 'tlx-trk', null, {role: 'group', 'aria-label': info.heading + ' scenarios'});
        trk.style.setProperty('--c', 'var(' + info.token + ')');
        trk.style.height = 'calc(' + lay.rows + ' * var(--tlrow, 10px) + 4px)';      // one block thickness in every lane
        var btns = [], k = 0;
        lay.items.forEach(function (it) {
          var m = byName[it.name], on = sel.has(it.name);
          if (!on) return;                                  // drawn only when in the capture
          var w = C.winOf(m), canMove = !!C.shiftLimits(m);
          if (m.shift && canMove) {                         // a faint tick where it would be without the move
            var g = el(doc, 'span', 'tlx-ghost', null, {'aria-hidden': 'true'});
            var w0 = C.winOf(Object.assign({}, m, {shift: 0}));
            setPct(g, 'left', w0.left); setPct(g, 'width', w0.width);
            if (g.style) g.style.top = 'calc(3px + ' + it.row + ' * var(--tlrow, 10px))';
            trk.appendChild(g);
          }
          var b = el(doc, 'button', 'tlx-mk' + (on ? ' on' : '') + (k++ % 2 ? ' alt' : '') + (m.shift ? ' moved' : ''), '', {type: 'button', 'aria-pressed': on ? 'true' : 'false',
            'aria-label': (m.title || m.name) + ', ' + (on ? 'in capture' : 'not in capture') + ', ' + w.text + (m.shift ? ', moved ' + (m.shift > 0 ? 'later' : 'earlier') + ' by ' + Math.abs(m.shift) + ' minutes' : '')});
          b.dataset.mod = m.name;
          setPct(b, 'left', it.left); setPct(b, 'width', it.width);
          if (b.style) b.style.top = 'calc(3px + ' + it.row + ' * var(--tlrow, 10px))';
          marks[m.name] = b;
          var say = function () { var cw = C.winOf(m); showTip(b, (m.title || m.name) + (canMove ? ' ' + cw.text : ''), cw.left, cw.width); };
          b.addEventListener('mouseenter', say); b.addEventListener('focus', say);
          b.addEventListener('mouseleave', hideTip); b.addEventListener('blur', hideTip);
          b.addEventListener('click', function () { if (suppressClick) { suppressClick = false; return; } cfg.open(m.name, b); });
          if (canMove) wireDrag(b, m, trk);
          b.addEventListener('keydown', function (ev) {
            if (ev.altKey && canMove && (ev.key === 'ArrowRight' || ev.key === 'ArrowLeft')) {   // Alt+Arrow moves the scenario, bare Arrow moves focus
              if (ev.preventDefault) ev.preventDefault();
              var step = (ev.shiftKey ? NUDGE_BIG : NUDGE) * (ev.key === 'ArrowRight' ? 1 : -1);
              C.setShift(cfg.getModules(), m.name, (m.shift || 0) + step, cfg.getSelected());
              commit(m.name);
              return;
            }
            var i = btns.indexOf(b), j = -1;
            if (ev.key === 'ArrowRight') j = Math.min(btns.length - 1, i + 1);
            else if (ev.key === 'ArrowLeft') j = Math.max(0, i - 1);
            else if (ev.key === 'Home') j = 0; else if (ev.key === 'End') j = btns.length - 1;
            if (j >= 0) { if (ev.preventDefault) ev.preventDefault(); btns[j].focus(); }
          });
          btns.push(b); trk.appendChild(b); placed++;
        });
        row.appendChild(lab); row.appendChild(trk); grid.appendChild(row);
      });
      var nd = el(doc, 'div', 'tlx-row');
      nd.appendChild(el(doc, 'div', 'tlx-lab', 'Normal day'));
      nd.appendChild(el(doc, 'div', 'tlx-normal', 'always on, the whole 16 hours'));
      grid.appendChild(nd);
      bandNode = el(doc, 'div', 'tlx-band', null, {'aria-hidden': 'true'}); bandNode.hidden = true; grid.appendChild(bandNode);
      tipNode = el(doc, 'div', 'tlx-tip', null, {'aria-hidden': 'true'}); tipNode.hidden = true; grid.appendChild(tipNode);
      gridNode = grid;
      phNode = el(doc, 'div', 'tlx-ph', null, {role: 'img'}); phNode.hidden = true; grid.appendChild(phNode);
      applyPlayhead();
      cfg.host.appendChild(grid);
      cfg.host.appendChild(el(doc, 'p', 'hint tlx-key', placed + ' placed on the timeline.' +
        (unplaced ? ' ' + unplaced + ' have no start window and appear in the list only.' : '')));
      return {placed: placed, unplaced: unplaced};
    }
    return {render: render, setPlayhead: setPlayhead};
  }

  var api = {layout: layout, dragShift: dragShift, rulerLabels: rulerLabels, create: create, LANES: LANES, TRACK_MIN: TRACK_MIN};
  root.OGTimeline = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : this);
