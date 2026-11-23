/* Timeline of the capture day (Phase 4). One lane per family, a marker per scenario placed by its start window on the
   16 hours of traffic, an always-on normal-day lane, and a Timeline/List switch. Markers are buttons: click opens the scenario
   card, arrow keys move along a lane. Labels are elapsed hours, never clock times. Pure layout is exported for tests;
   text from data is only set with textContent. Needs OGCards (parseWindow, familyOf, FAMILIES). */
(function (root) {
  'use strict';
  var TRACK_MIN = 16 * 60;
  var LANES = ['SEC', 'PERF', 'CRYP', 'REPLAY'];

  /* items: [{name, left, width}] in percent. Greedy packing into sub-rows so markers never overlap.
     Returns {items: [{name, left, width, row}] sorted by left, rows}. */
  function layout(items) {
    var sorted = items.slice().sort(function (a, b) { return a.left - b.left || a.name.localeCompare(b.name); });
    var rowEnds = [];
    var out = sorted.map(function (it) {
      var r = 0;
      while (r < rowEnds.length && rowEnds[r] > it.left + 0.0001) r++;
      rowEnds[r] = it.left + it.width;
      return {name: it.name, left: it.left, width: it.width, row: r};
    });
    return {items: out, rows: Math.max(1, rowEnds.length)};
  }

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
    var playhead = null, phNode = null;
    function applyPlayhead() {
      if (!phNode) return;
      if (playhead == null) { phNode.hidden = true; return; }
      phNode.hidden = false;
      if (phNode.style) phNode.style.left = 'calc(140px + (100% - 140px) * ' + (playhead / 100) + ')';
      phNode.setAttribute('aria-label', 'Build progress, about ' + Math.round(playhead) + ' percent');
    }
    function setPlayhead(pct) { playhead = pct == null ? null : Math.max(0, Math.min(100, pct)); applyPlayhead(); }
    function render() {
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
          var w = C.parseWindow(m.window);
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
        trk.style.height = 'calc(' + lay.rows + ' * var(--tlrow, 10px) + 6px)';      // one block thickness in every lane
        var btns = [];
        lay.items.forEach(function (it) {
          var m = byName[it.name], on = sel.has(it.name);
          if (!on) return;                                  // drawn only when in the capture
          var b = el(doc, 'button', 'tlx-mk' + (on ? ' on' : ''), '', {type: 'button', 'aria-pressed': on ? 'true' : 'false',
            'aria-label': (m.title || m.name) + ', ' + (on ? 'in capture' : 'not in capture') + ', ' + m.window,
            title: (m.title || m.name) + ' (' + m.window + ')'});
          b.dataset.mod = m.name;
          setPct(b, 'left', it.left); setPct(b, 'width', it.width);
          if (b.style) b.style.top = 'calc(3px + ' + it.row + ' * var(--tlrow, 10px))';
          b.addEventListener('click', function () { cfg.open(m.name, b); });
          b.addEventListener('keydown', function (ev) {
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
      phNode = el(doc, 'div', 'tlx-ph', null, {role: 'img'}); phNode.hidden = true; grid.appendChild(phNode);
      applyPlayhead();
      cfg.host.appendChild(grid);
      cfg.host.appendChild(el(doc, 'p', 'hint tlx-key', placed + ' placed on the timeline.' +
        (unplaced ? ' ' + unplaced + ' have no start window and appear in the list only.' : '')));
      return {placed: placed, unplaced: unplaced};
    }
    return {render: render, setPlayhead: setPlayhead};
  }

  var api = {layout: layout, rulerLabels: rulerLabels, create: create, LANES: LANES, TRACK_MIN: TRACK_MIN};
  root.OGTimeline = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : this);
