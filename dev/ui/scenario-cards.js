/* Category rail, chooser tools and scenario cards for the Build view.

   Two layers. The top half is pure data logic (grouping, counts, coverage, filtering, window parsing, tab-trap
   maths) with no DOM access, so it can be tested under node. The bottom half builds elements with createElement and
   textContent only (never markup strings, because titles, notes and metadata come from the server) and a controller that
   wires them to the existing checkboxes through callbacks. The page owns the checkboxes; this file never keeps its
   own copy of the selection.

   window.OGCards (and module.exports under node). */
(function (root) {
  'use strict';

  var UNCAT = 'Uncategorised';
  var FAMILY_OF_PREFIX = {NDR: 'SEC', NPM: 'PERF', CRP: 'CRYP', IR: 'REPLAY', CUSTOM: 'CUSTOM', CAMPAIGN: 'CUSTOM'};
  var FAMILIES = [
    {key: 'SEC', heading: 'Security', token: '--c-sec', label: 'Security'},
    {key: 'PERF', heading: 'Performance', token: '--c-perf', label: 'Performance'},
    {key: 'CRYP', heading: 'Crypto posture', token: '--c-cryp', label: 'Crypto posture'},
    {key: 'REPLAY', heading: 'Incident replays', token: '--c-rep', label: 'Incident replays', single: true},
    {key: 'CUSTOM', heading: 'Custom recipes', token: '--c-cus', label: 'Custom recipes', single: true}
  ];
  var COVERAGE_FAMILIES = ['SEC', 'PERF', 'CRYP'];
  var TRACK_MIN = 16 * 60;               // the start-window strip spans the 16 hours of traffic
  var DRAFT_LINE = 'Scenario descriptions are drafts and are being verified.';

  function familyInfo(key) {
    for (var i = 0; i < FAMILIES.length; i++) if (FAMILIES[i].key === key) return FAMILIES[i];
    return {key: key, heading: key, token: '--ac', label: key};
  }
  function familyOf(m) { return FAMILY_OF_PREFIX[m && m.prefix] || String((m && m.prefix) || 'OTHER'); }
  function categoryOf(m) { return (m && m.meta && m.meta.category) || UNCAT; }
  function isSingle(famKey) { return !!familyInfo(famKey).single; }
  // Filter key of a scenario's category. REPLAY and CUSTOM are one entry each, whatever their meta says.
  function categoryKey(m) {
    var f = familyOf(m);
    return f + '|' + (isSingle(f) ? '*' : categoryOf(m));
  }

  /* Scenarios the chooser lists: real, selectable scenarios only. OT-only ones count only while the OT zone is on. */
  function shownModules(mods, opts) {
    var ot = !!(opts && opts.otLive);
    return (mods || []).filter(function (m) { return m && !m.pinned && !m.recipe_driven && (!m.ot_only || ot); });
  }

  /* Group scenarios into families and categories. Category order follows the taxonomy; categories with no scenario
     are left out (a category exists only for the shown scenarios); anything without meta falls into "Uncategorised"
     at the end of its family. REPLAY and CUSTOM are a single entry each. */
  function buildModel(mods, taxonomy, opts) {
    var tax = (taxonomy && taxonomy.families) || {};
    var byFam = {}, order = [];
    (mods || []).forEach(function (m) {
      var f = familyOf(m);
      if (!byFam[f]) { byFam[f] = []; }
      byFam[f].push(m);
    });
    FAMILIES.forEach(function (f) { order.push(f.key); });
    Object.keys(byFam).forEach(function (k) { if (order.indexOf(k) < 0) order.push(k); });
    var customRecipes = (opts && opts.customRecipes) | 0;
    var out = [];
    order.forEach(function (fk) {
      var items = byFam[fk] || [];
      var info = familyInfo(fk);
      var cats = [];
      if (info.single) {
        if (items.length) cats.push({key: fk + '|*', name: info.label, family: fk, items: items});
      } else {
        var seen = {};
        (tax[fk] || []).forEach(function (name) { seen[name] = {key: fk + '|' + name, name: name, family: fk, items: []}; });
        items.forEach(function (m) {
          var name = categoryOf(m);
          if (!seen[name]) seen[name] = {key: fk + '|' + name, name: name, family: fk, items: []};
          seen[name].items.push(m);
        });
        var names = (tax[fk] || []).concat(Object.keys(seen).filter(function (n) { return (tax[fk] || []).indexOf(n) < 0 && n !== UNCAT; }));
        if (seen[UNCAT]) names.push(UNCAT);
        names.forEach(function (n) { if (seen[n] && seen[n].items.length) cats.push(seen[n]); });
      }
      if (fk === 'CUSTOM' && customRecipes > 0) {
        cats = [{key: 'CUSTOM|*', name: info.label, family: fk, items: [], recipes: customRecipes, static: true}];
      }
      if (cats.length) out.push({key: fk, heading: info.heading, token: info.token, categories: cats, total: items.length});
    });
    return out;
  }

  function countsFor(items, selected) {
    var sel = 0;
    items.forEach(function (m) { if (selected && selected.has(m.name)) sel++; });
    return {selected: sel, available: items.length};
  }

  /* Coverage = categories (of SEC, PERF and CRYP, excluding the fallback bucket) with at least one selected
     scenario, out of the categories that exist for the shown scenarios. Replays and custom recipes are reported
     separately and are not part of the total. */
  function coverage(model, selected) {
    var covered = 0, total = 0, replay = null, custom = null;
    model.forEach(function (f) {
      f.categories.forEach(function (c) {
        if (COVERAGE_FAMILIES.indexOf(f.key) >= 0 && c.name !== UNCAT) {
          total++;
          // a multi-stage chain also covers the categories it passes through (meta.also_categories)
          var hit = countsFor(c.items, selected).selected > 0;
          if (!hit && selected) model.forEach(function (g) { g.categories.forEach(function (o) { o.items.forEach(function (m) {
            if (!hit && selected.has(m.name) && g.key === f.key && m.meta && (m.meta.also_categories || []).indexOf(c.name) >= 0) hit = true; }); }); });
          if (hit) covered++;
        }
        if (f.key === 'REPLAY') replay = countsFor(c.items, selected);
        if (f.key === 'CUSTOM') custom = {selected: c.recipes || 0, available: c.recipes || 0};
      });
    });
    var pct = total ? Math.round(100 * covered / total) : 0;
    return {
      covered: covered, total: total, pct: pct, replay: replay, custom: custom,
      text: total ? covered + ' of ' + total + ' categories covered' : 'No categories to cover'
    };
  }

  function haystack(m) {
    var meta = m.meta || {};
    return [m.title, m.name, m.note, categoryOf(m), (meta.protocols || []).join(' ')].join(' ').toLowerCase();
  }
  /* state = {text, family ('ALL' or a key), category (a category key or null)} */
  function filterModules(mods, state) {
    var st = state || {};
    var toks = String(st.text || '').toLowerCase().split(/\s+/).filter(Boolean);
    var fam = st.family && st.family !== 'ALL' ? st.family : null;
    return (mods || []).filter(function (m) {
      if (fam === 'SELECTED') { if (!(st.selected && st.selected.has(m.name))) return false; }
      else if (fam === 'OT') { if (!m.ot_only) return false; }
      else if (fam && familyOf(m) !== fam) return false;
      if (st.category && categoryKey(m) !== st.category) return false;
      if (st.zone && !(root.OGExplainer && root.OGExplainer.touchesZone(m, st.zone))) return false;
      if (toks.length) { var h = haystack(m); for (var i = 0; i < toks.length; i++) if (h.indexOf(toks[i]) < 0) return false; }
      return true;
    });
  }
  function familyCounts(mods, selected) {
    var c = {ALL: (mods || []).length, SELECTED: 0, OT: 0};
    (mods || []).forEach(function (m) {
      var f = familyOf(m); c[f] = (c[f] || 0) + 1;
      if (selected && selected.has(m.name)) c.SELECTED++;
      if (m && m.ot_only) c.OT++;
    });
    return c;
  }

  /* "Start +8:05 → +8:20", "+8h", "+45m" -> {startMin, endMin, left, width} on the 16-hour track, else null. */
  function parseWindow(text) {
    var re = /\+(\d+)(?::(\d{2})|(h|m))/g, v = [], mm;
    var s = String(text || '');
    while ((mm = re.exec(s))) {
      var n = parseInt(mm[1], 10);
      v.push(mm[2] !== undefined ? n * 60 + parseInt(mm[2], 10) : (mm[3] === 'h' ? n * 60 : n));
    }
    if (v.length < 2 || !(v[1] > v[0])) return null;
    var start = Math.min(v[0], TRACK_MIN), end = Math.min(v[1], TRACK_MIN);
    if (end <= start) return null;
    return {startMin: v[0], endMin: v[1], left: 100 * start / TRACK_MIN, width: Math.max(1.2, 100 * (end - start) / TRACK_MIN)};
  }


  /* ---- timeline slider: a scenario's shift is whole minutes on the module record (m.shift). The server sends the
     default window as numbers (start_min/end_min, offsets from the 05:00 start) and how far it may move (shift_limits). ---- */
  function fmtOffset(m) {
    if (m < 60) return '+' + m + 'm';
    var h = Math.floor(m / 60), mm = m % 60;
    return mm === 0 ? '+' + h + 'h' : '+' + h + ':' + (mm < 10 ? '0' : '') + mm;
  }
  function formatWindow(startMin, endMin) { return 'Start ' + fmtOffset(startMin) + ' \u2192 ' + fmtOffset(endMin); }
  function shiftLimits(m) { var l = m && m.shift_limits; return l && l.length === 2 ? l : null; }
  /* The window the capture will use: default plus shift, as {startMin, endMin, left, width, text}; null without a window. */
  function winOf(m) {
    if (!m) return null;
    var d = m.shift || 0;
    if (typeof m.start_min === 'number' && typeof m.end_min === 'number' && m.end_min > m.start_min) {
      var s = m.start_min + d, e = m.end_min + d, a = Math.max(0, Math.min(s, TRACK_MIN)), b = Math.max(0, Math.min(e, TRACK_MIN));
      return {startMin: s, endMin: e, left: 100 * a / TRACK_MIN, width: Math.max(1.2, 100 * (b - a) / TRACK_MIN), text: formatWindow(s, e)};
    }
    var w = parseWindow(m.window);
    if (w) w.text = m.window;
    return w;
  }
  /* Move `name` by `d` minutes, held to its limits and, for a linked pair that is also in the capture, to the pair's shared range.
     Returns the shift that was applied (0 when it cannot move). */
  function setShift(mods, name, d, selected) {
    var m = null, partner = null;
    mods.forEach(function (x) { if (x.name === name) m = x; });
    var lim = shiftLimits(m);
    if (!lim) return 0;
    mods.forEach(function (x) { if (m.shift_partner && x.name === m.shift_partner && (!selected || selected.has(x.name)) && shiftLimits(x)) partner = x; });
    var lo = lim[0], hi = lim[1];
    if (partner) { var pl = shiftLimits(partner); lo = Math.max(lo, pl[0]); hi = Math.min(hi, pl[1]); }
    var v = Math.max(lo, Math.min(hi, Math.round(Number(d) || 0)));
    m.shift = v; if (partner) partner.shift = v;
    return v;
  }
  /* {name: minutes} for the scenarios in `selected` (all when omitted) that have moved. */
  function collectShifts(mods, selected) {
    var out = {};
    mods.forEach(function (m) { if (m.shift && (!selected || selected.has(m.name))) out[m.name] = m.shift; });
    return out;
  }
  /* Put a saved {name: minutes} back, every value held to its limits; scenarios not named return to their default. */
  function loadShifts(mods, saved) {
    mods.forEach(function (m) { var v = saved && saved[m.name]; m.shift = shiftLimits(m) && typeof v === 'number' ? Math.max(shiftLimits(m)[0], Math.min(shiftLimits(m)[1], Math.round(v))) : 0; });
  }

  /* Tab-trap maths. */
  function wrapIndex(len, idx, shift) {
    if (!len) return -1;
    if (idx < 0) return shift ? len - 1 : 0;
    return shift ? (idx === 0 ? len - 1 : idx - 1) : (idx === len - 1 ? 0 : idx + 1);
  }
  function isFocusable(n) {
    if (!n || n.nodeType !== 1 || n.disabled || n.hidden) return false;
    var tag = String(n.tagName || '').toUpperCase();
    var ti = n.getAttribute && n.getAttribute('tabindex');
    if (ti !== null && ti !== undefined) return parseInt(ti, 10) >= 0;
    if (tag === 'A') return !!(n.getAttribute && n.getAttribute('href') !== null);
    if (tag === 'INPUT') return !(n.getAttribute && n.getAttribute('type') === 'hidden');
    return tag === 'BUTTON' || tag === 'SELECT' || tag === 'TEXTAREA';
  }
  function focusables(container, out) {
    out = out || [];
    var kids = container && container.children ? Array.prototype.slice.call(container.children) : [];
    kids.forEach(function (k) {
      if (k.hidden) return;
      if (isFocusable(k)) out.push(k);
      focusables(k, out);
    });
    return out;
  }
  /* Keep Tab inside container. Returns true when it handled the event. */
  function trapTab(container, ev, doc) {
    if (!ev || ev.key !== 'Tab') return false;
    var list = focusables(container);
    if (!list.length) { ev.preventDefault(); return true; }
    var active = doc && doc.activeElement;
    var i = list.indexOf(active);
    var inside = i >= 0;
    var next = wrapIndex(list.length, i, !!ev.shiftKey);
    // only intervene at the edges (or when focus has left the dialog); the browser handles the middle
    var atEdge = !inside || (ev.shiftKey ? i === 0 : i === list.length - 1);
    if (atEdge) { ev.preventDefault(); list[next].focus(); return true; }
    return false;
  }

  /* ---------------------------------------------------------------- DOM builders (no markup strings) */
  function el(doc, tag, opts, kids) {
    var n = doc.createElement(tag);
    opts = opts || {};
    if (opts.cls) n.className = opts.cls;
    if (opts.text !== undefined && opts.text !== null) n.textContent = String(opts.text);
    if (opts.attrs) Object.keys(opts.attrs).forEach(function (k) { n.setAttribute(k, opts.attrs[k]); });
    if (opts.data) Object.keys(opts.data).forEach(function (k) { n.dataset[k] = String(opts.data[k]); });
    if (opts.on) Object.keys(opts.on).forEach(function (k) { n.addEventListener(k, opts.on[k]); });
    (kids || []).forEach(function (k) { if (k) n.appendChild(k); });
    return n;
  }
  // After a rebuild, scroll so the item the user acted on is back at the same place on screen (design-language.md, rule 4).
  function keepAnchored(doc, node, before) {
    if (before == null || !node || !node.getBoundingClientRect || !doc.defaultView || !doc.defaultView.scrollBy) return;
    var d = node.getBoundingClientRect().top - before;
    if (Math.abs(d) > 0.5) doc.defaultView.scrollBy(0, d);
  }
  function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); }
  function famVar(token) { return 'var(' + token + ')'; }
  function setColor(n, token) { if (n.style && n.style.setProperty) n.style.setProperty('--c', famVar(token)); }

  /* Category rail. state = {category, selected:Set}; cbs = {onCategory(key|null), onSelectAll(cat), onClear(cat)} */
  function renderRail(doc, host, model, state, cbs) {
    clear(host);
    var all = [];
    model.forEach(function (f) { f.categories.forEach(function (c) { all = all.concat(c.items); }); });
    var tot = countsFor(all, state.selected);
    var allBtn = el(doc, 'button', {
      cls: 'cat cat-all' + (!state.category ? ' on' : ''), attrs: {type: 'button', 'aria-pressed': state.category ? 'false' : 'true'},
      data: {key: ''}, on: {click: function () { cbs.onCategory(null); }}
    }, [el(doc, 'b', {text: 'All scenarios'}), el(doc, 'span', {text: tot.selected + ' selected of ' + tot.available})]);
    host.appendChild(allBtn);
    model.forEach(function (f) {
      var group = el(doc, 'div', {cls: 'cat-group', attrs: {role: 'group', 'aria-label': f.heading}});
      group.appendChild(el(doc, 'div', {cls: 'cat-h', text: f.heading}));
      f.categories.forEach(function (c) {
        var cnt = c.static ? {selected: c.recipes, available: c.recipes} : countsFor(c.items, state.selected);
        var active = state.category === c.key;
        var pct = cnt.available ? Math.round(100 * cnt.selected / cnt.available) : 0;
        var u = el(doc, 'u'); if (u.style) u.style.width = pct + '%';
        var label = c.static
          ? [el(doc, 'b', {text: c.name}), el(doc, 'span', {text: cnt.available + (cnt.available === 1 ? ' recipe' : ' recipes')})]
          : [el(doc, 'b', {text: c.name}), el(doc, 'span', {text: cnt.selected + ' selected of ' + cnt.available}), el(doc, 'i', {attrs: {'aria-hidden': 'true'}}, [u])];
        var row;
        if (c.static) {
          row = el(doc, 'div', {cls: 'cat cat-static', data: {key: c.key}}, label);
        } else {
          row = el(doc, 'button', {
            cls: 'cat' + (active ? ' on' : ''),
            attrs: {type: 'button', 'aria-pressed': active ? 'true' : 'false',
                    'aria-label': c.name + ', ' + cnt.selected + ' of ' + cnt.available + ' selected'},
            data: {key: c.key}, on: {click: function () { cbs.onCategory(active ? null : c.key); }}
          }, label);
        }
        setColor(row, f.token);
        group.appendChild(row);
        if (active && !c.static) {
          var acts = el(doc, 'div', {cls: 'cat-act'}, [
            el(doc, 'button', {cls: 'cat-actbtn', attrs: {type: 'button', 'aria-label': 'Select all ' + c.items.length + ' in ' + c.name},
              data: {act: 'all', key: c.key}, text: 'Select all (' + c.items.length + ')', on: {click: function () { cbs.onSelectAll(c); }}}),
            el(doc, 'button', {cls: 'cat-actbtn', attrs: {type: 'button', 'aria-label': 'Clear selection in ' + c.name},
              data: {act: 'clear', key: c.key}, text: 'Clear', on: {click: function () { cbs.onClear(c); }}})
          ]);
          group.appendChild(acts);
          // the category opens downward into its scenarios, each with its own tick box
          var sub = el(doc, 'ul', {cls: 'catsub', attrs: {'aria-label': c.name + ' scenarios'}});
          c.items.forEach(function (m) {
            var on = !!(state.selected && state.selected.has(m.name));
            var box = el(doc, 'input', {attrs: {type: 'checkbox', 'aria-label': 'Include ' + (m.title || m.name)}, data: {item: m.name}});
            box.checked = on;
            box.addEventListener('change', function () { cbs.onItem(m.name, box.checked); });
            var t = el(doc, 'button', {cls: 'catsub-t', attrs: {type: 'button', title: 'Open the scenario card'}, text: m.title || m.name,
              on: {click: function () { cbs.onOpen(m.name, t); }}});
            sub.appendChild(el(doc, 'li', {cls: on ? 'on' : ''}, [box, t]));
          });
          setColor(sub, f.token);
          group.appendChild(sub);
        }
      });
      host.appendChild(group);
    });
  }

  function renderCoverage(doc, host, cov) {
    clear(host);
    host.setAttribute('role', 'group');
    host.setAttribute('aria-label', cov.text);
    var inner = el(doc, 'div', {text: cov.total ? cov.covered + '/' + cov.total : '-', attrs: {'aria-hidden': 'true'}});
    var ring = el(doc, 'div', {cls: 'cring', attrs: {'aria-hidden': 'true'}}, [inner]);
    if (ring.style && ring.style.setProperty) ring.style.setProperty('--v', String(cov.pct));
    var bits = [el(doc, 'b', {text: cov.text})];
    var extra = [];
    if (cov.replay) extra.push('Incident replays: ' + cov.replay.selected + ' of ' + cov.replay.available);
    if (cov.custom) extra.push('Custom recipes: ' + cov.custom.available);
    bits.push(el(doc, 'span', {cls: 'cov-sub', text: extra.length ? extra.join(' | ') : 'Pick scenarios to widen what your sensor is tested on.'}));
    host.appendChild(ring);
    host.appendChild(el(doc, 'div', {cls: 'cov-txt'}, bits));
  }

  /* Search field and family chips, built once. Returns {update(counts, state), input}. */
  function renderTools(doc, host, cfg) {
    clear(host);
    var input = el(doc, 'input', {cls: 'ctools-search', attrs: {type: 'search', id: 'card-search', placeholder: 'Title, id, protocol or category', autocomplete: 'off'}});
    input.addEventListener('input', function () { cfg.onText(input.value); });
    var lab = el(doc, 'label', {cls: 'ctools-lab', attrs: {'for': 'card-search'}, text: 'Search scenarios'});
    var chipsHost = el(doc, 'div', {cls: 'fchips', attrs: {role: 'group', 'aria-label': 'Filter by family'}});
    var status = el(doc, 'span', {cls: 'ctools-status', attrs: {role: 'status'}});
    var draft = cfg.draft ? el(doc, 'p', {cls: 'hint ctools-draft', text: DRAFT_LINE}) : null;
    host.appendChild(el(doc, 'div', {cls: 'ctools-row'}, [el(doc, 'div', {cls: 'ctools-fld'}, [lab, input]), status]));
    host.appendChild(chipsHost);
    var mapBtn = el(doc, 'button', {cls: 'fchip fchip-map', attrs: {type: 'button', 'aria-pressed': 'false', 'aria-expanded': 'false', 'aria-controls': 'card-zonemap'},
      data: {act: 'map'}, text: 'Map'});
    var mapHost = el(doc, 'div', {cls: 'zonemap', attrs: {id: 'card-zonemap'}});
    mapHost.hidden = true;
    var mapOpen = false;
    mapBtn.addEventListener('click', function () {
      mapOpen = !mapOpen; mapHost.hidden = !mapOpen;
      mapBtn.setAttribute('aria-pressed', mapOpen ? 'true' : 'false'); mapBtn.setAttribute('aria-expanded', mapOpen ? 'true' : 'false');
      if (!mapOpen && cfg.onZone) cfg.onZone(null);
    });
    if (draft) host.appendChild(draft);
    var btns = {};
    var keys = ['ALL', 'SELECTED', 'SEC', 'PERF', 'CRYP', 'REPLAY', 'OT', 'CUSTOM'];
    var SPECIAL = {ALL: {label: 'All scenarios', text: 'All', token: '--ac'}, SELECTED: {label: 'Selected scenarios', text: 'Selected', token: '--ac'},
                   OT: {label: 'OT scenarios', text: 'OT', token: '--c-rep'}};
    keys.forEach(function (k) {
      var b = el(doc, 'button', {cls: 'fchip', attrs: {type: 'button', 'aria-pressed': k === 'ALL' ? 'true' : 'false'}, data: {family: k},
        on: {click: function () { cfg.onFamily(k); }}});
      btns[k] = b; chipsHost.appendChild(b);
    });
    function update(counts, st) {
      keys.forEach(function (k) {
        var n = counts[k] || 0;
        var info = SPECIAL[k] || familyInfo(k);
        btns[k].textContent = (SPECIAL[k] ? SPECIAL[k].text : k) + ' ' + n;
        btns[k].setAttribute('aria-label', info.label + ', ' + n);
        btns[k].setAttribute('aria-pressed', (st.family || 'ALL') === k ? 'true' : 'false');
        btns[k].hidden = k !== 'ALL' && k !== 'SELECTED' && n === 0 && (st.family || 'ALL') !== k;
        setColor(btns[k], info.token);
      });
      status.textContent = st.shown + ' of ' + st.total + ' shown';
      var refocus = doc.activeElement && doc.activeElement.dataset && mapHost.contains && mapHost.contains(doc.activeElement) ? doc.activeElement.dataset.zone : null;
      clear(mapHost);
      if (root.OGExplainer && st.zoneCounts) {
        var m = root.OGExplainer.drawMap(doc, {interactive: true, counts: st.zoneCounts, selected: st.zone || null,
          label: 'Pick a network zone to list the scenarios that touch it', onZone: function (z) { cfg.onZone(st.zone === z ? null : z); }});
        mapHost.appendChild(m.svg);
        mapHost.appendChild(el(doc, 'p', {cls: 'hint', text: st.zone ? 'Showing scenarios that touch the ' + root.OGExplainer.zoneInfo(st.zone).label.toLowerCase() + '. Select it again to clear.'
          : 'Select a zone to list the scenarios that touch it. Zone paths are a draft.'}));
        if (refocus && m.zones[refocus] && m.zones[refocus].focus) m.zones[refocus].focus();
      }
    }
    return {update: update, input: input, mapBtn: mapBtn, mapHost: mapHost};
  }

  /* The scenario card content for one scenario. ctx = {family, selected, canVisualize, pos, count, hasPrev, hasNext}
     cbs = {onClose, onPrev, onNext, onVisualize, onToggle}. Returns the dialog element. */
  function buildCard(doc, mod, ctx, cbs) {
    var meta = mod.meta || null;
    var fam = familyInfo(ctx.family || familyOf(mod));
    var dlg = el(doc, 'div', {cls: 'scard', attrs: {role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'scard-title'},
      data: {scenario: mod.name, family: fam.key}});
    setColor(dlg, fam.token);
    var closeBtn = el(doc, 'button', {cls: 'btn secondary sm scard-close', attrs: {type: 'button'}, text: 'Close', data: {act: 'close'},
      on: {click: function () { cbs.onClose(); }}});
    var chips = [el(doc, 'span', {cls: 'cchip cchip-fam', text: fam.key}),
                 el(doc, 'span', {cls: 'cchip', text: categoryOf(mod)})];
    if (mod.ot_only) chips.push(el(doc, 'span', {cls: 'cchip', text: 'OT', attrs: {title: 'Only runs when the OT zone is switched on'}}));
    var sb = meta && meta.scale && meta.scale.behaviour;
    if (sb) chips.push(el(doc, 'span', {cls: 'cchip', text: sb === 'fixed' ? 'Fixed size' : 'Grows with size',
      attrs: {title: sb === 'fixed' ? 'The same traffic at every size setting'
        : 'More traffic at larger size settings; a small capture may be too small for volume-based detections'}}));
    var pc = meta && meta.protocols_check;
    if (pc && (pc.status === 'checked' || pc.status === 'partial')) {
      chips.push(el(doc, 'span', {cls: 'cchip cchip-ok', text: pc.status === 'checked' ? 'Protocols checked' : 'Protocols partly checked',
        attrs: {title: 'The protocols listed below were looked for in a capture built from this scenario alone'}}));
    }
    if (meta && meta.confidence && meta.confidence !== 'high') {
      chips.push(el(doc, 'span', {cls: 'cchip cchip-warn', text: 'Needs verification',
        attrs: {title: 'This description is a draft that has not been confirmed against the capture'}}));
    }
    var cover = el(doc, 'div', {cls: 'cover'}, [closeBtn,
      el(doc, 'div', {cls: 'ttl'}, [el(doc, 'div', {cls: 'cchips'}, chips),
        el(doc, 'h2', {cls: 'scard-title', text: mod.title || mod.name, attrs: {id: 'scard-title', tabindex: '-1'}})])]);
    dlg.appendChild(cover);

    var body = el(doc, 'div', {cls: 'scard-body'});
    if (mod.note) body.appendChild(el(doc, 'p', {cls: 'scard-desc', text: mod.note}));
    if (meta && meta.expected_observation) {
      body.appendChild(el(doc, 'div', {cls: 'prove'}, [el(doc, 'b', {text: 'Your sensor should show'}), el(doc, 'p', {text: meta.expected_observation})]));
    }
    if (meta && meta.protocols && meta.protocols.length) {
      body.appendChild(el(doc, 'div', {cls: 'scard-protos', attrs: {role: 'list', 'aria-label': 'Protocols'}},
        meta.protocols.map(function (p) {
          var un = pc && pc.unverified && pc.unverified.indexOf(p) >= 0;
          return el(doc, 'span', {cls: 'pchip' + (un ? ' pchip-un' : ''), text: p, attrs: {role: 'listitem', title: un ? 'Not confirmed in a capture yet' : ''}});
        })));
    }
    if (meta && meta.hosts && meta.hosts.length) {
      body.appendChild(el(doc, 'p', {cls: 'scard-hosts'}, [el(doc, 'b', {text: 'Hosts: '}), doc.createTextNode(meta.hosts.join(', '))]));
    }
    var w = winOf(mod);
    if (w) {
      var win = el(doc, 'div', {cls: 'scard-win'}, [el(doc, 'b', {text: 'When it happens: '}), doc.createTextNode(w.text)]);
      var bar = el(doc, 'i'); if (bar.style) { bar.style.left = w.left + '%'; bar.style.width = w.width + '%'; }
      win.appendChild(el(doc, 'div', {cls: 'wstrip', attrs: {role: 'img', 'aria-label': 'Position within the 16 hours of traffic: ' + w.text}}, [bar]));
      win.appendChild(el(doc, 'div', {cls: 'wstrip-ends', attrs: {'aria-hidden': 'true'}}, [el(doc, 'span', {text: 'start'}), el(doc, 'span', {text: '16 h'})]));
      var lim = shiftLimits(mod);
      if (lim && cbs.onShift) {
        var inp = el(doc, 'input', {cls: 'scard-shift', attrs: {type: 'number', step: '1', min: String(lim[0]), max: String(lim[1]),
          value: String(mod.shift || 0), 'aria-label': 'Minutes to move this scenario (' + lim[0] + ' to ' + lim[1] + '), later is positive'}, data: {act: 'shift'}});
        var apply = function () { cbs.onShift(inp.value === '' ? 0 : Number(inp.value)); };
        inp.addEventListener('change', apply);
        var reset = el(doc, 'button', {cls: 'btn secondary sm', attrs: {type: 'button'}, text: 'Reset', data: {act: 'shift-reset'},
          on: {click: function () { cbs.onShift(0); }}});
        if (!mod.shift) reset.disabled = true;
        win.appendChild(el(doc, 'div', {cls: 'scard-shiftrow'}, [el(doc, 'label', {text: 'Move by (min) '}, [inp]), reset]));
      }
      body.appendChild(win);
    } else if (mod.window) {
      body.appendChild(el(doc, 'div', {cls: 'scard-win'}, [el(doc, 'b', {text: 'When it happens: '}), doc.createTextNode(mod.window)]));
    }
    if (meta && meta.steps && meta.steps.length) {
      var stepList = el(doc, 'ol', {cls: 'scard-steps'}, meta.steps.map(function (s, i) {
        return el(doc, 'li', {cls: 'stp2 on'}, [el(doc, 'em', {text: i + 1, attrs: {'aria-hidden': 'true'}}), el(doc, 'span', {text: s})]);
      }));
      var slot = el(doc, 'div', {cls: 'scard-explainer-slot', data: {scenario: mod.name, family: fam.key,
        zonePath: meta.zone_path ? meta.zone_path.join(',') : '', steps: meta.steps.length}});
      if (root.OGExplainer && meta.zone_path && meta.zone_path.length) {
        var reduced = !!(root.matchMedia && root.matchMedia('(prefers-reduced-motion: reduce)').matches) || !!ctx.reduced;
        var ex = root.OGExplainer.buildExplainer(doc, {steps: meta.steps, zonePath: meta.zone_path, reduced: reduced, autoplay: !!ctx.autoplay,
          listEl: stepList});
        slot.appendChild(ex.el);
        if (cbs.onExplainer) cbs.onExplainer(ex);
      }
      body.appendChild(el(doc, 'h3', {cls: 'scard-h', text: 'What happens, step by step'}));
      body.appendChild(slot);
      body.appendChild(stepList);
      body.appendChild(el(doc, 'p', {cls: 'hint', text: 'The last step may describe something that is not visible on the wire.'}));
    }
    dlg.appendChild(body);

    var prev = el(doc, 'button', {cls: 'btn secondary md', attrs: {type: 'button'}, data: {act: 'prev'}, text: 'Previous',
      on: {click: function () { cbs.onPrev(); }}});
    prev.disabled = !ctx.hasPrev;
    var next = el(doc, 'button', {cls: 'btn secondary md', attrs: {type: 'button'}, data: {act: 'next'}, text: 'Next',
      on: {click: function () { cbs.onNext(); }}});
    next.disabled = !ctx.hasNext;
    var viz = el(doc, 'button', {cls: 'btn secondary md', attrs: {type: 'button'}, data: {act: 'viz'}, text: 'Visualize',
      on: {click: function () { cbs.onVisualize(); }}});
    viz.disabled = !ctx.canVisualize;
    if (!ctx.canVisualize) viz.setAttribute('title', 'No diagram registered for this scenario yet');
    var tog = el(doc, 'button', {cls: 'btn md', attrs: {type: 'button'}, data: {act: 'toggle'},
      text: ctx.selected ? 'Remove from capture' : 'Add to capture', on: {click: function () { cbs.onToggle(); }}});
    if (ctx.disabledToggle) tog.disabled = true;
    dlg.appendChild(el(doc, 'div', {cls: 'scard-foot'}, [
      el(doc, 'div', {cls: 'scard-nav'}, [prev, el(doc, 'span', {cls: 'scard-pos', text: ctx.pos + ' of ' + ctx.count, attrs: {role: 'status'}}), next]),
      el(doc, 'div', {cls: 'scard-act'}, [viz, tog])]));
    return dlg;
  }

  /* ---------------------------------------------------------------- controller (page glue) */
  /* cfg: {doc, els:{rail, tools, coverage, list, empty}, getModules(), getTaxonomy(), metaStatus,
           getSelected():Set, otLive(), customRecipes(), setSelected(name,on), setMany(names,on),
           visualize(name), canVisualize(name), toggleDisabled(name)} */
  function createController(cfg) {
    var doc = cfg.doc || root.document;
    var state = {text: '', family: 'ALL', category: null, zone: null};
    var model = [], shown = [], open = null;

    function recompute() {
      shown = shownModules(cfg.getModules(), {otLive: cfg.otLive()});
      model = buildModel(shown, cfg.getTaxonomy(), {customRecipes: cfg.customRecipes()});
    }
    function visible() { return filterModules(shown, {text: state.text, family: state.family, category: state.category, zone: state.zone, selected: cfg.getSelected()}); }

    function applyRows() {
      var vis = {};
      visible().forEach(function (m) { vis[m.name] = true; });
      var filtering = !!(state.text.trim() || state.category || state.zone);
      var otherFam = state.family !== 'ALL' && state.family !== 'SELECTED' && state.family !== 'OT';
      var specialFam = state.family === 'SELECTED' || state.family === 'OT';
      var rows = cfg.els.list.querySelectorAll('.mod');
      Array.prototype.forEach.call(rows, function (row) {
        var cb = row.querySelector('input[type=checkbox]');
        if (!cb) return;
        var isPin = !!(cb.classList && cb.classList.contains('modpin'));
        var name = cb.value, mod = null;
        var all = cfg.getModules();
        for (var i = 0; i < all.length; i++) if (all[i].name === name) { mod = all[i]; break; }
        var show;
        if (isPin) show = !filtering && !specialFam && (!otherFam || (mod && familyOf(mod) === state.family));
        else show = !!vis[name];
        row.hidden = !show;
      });
      Array.prototype.forEach.call(cfg.els.list.querySelectorAll('.grp'), function (g) {
        var any = Array.prototype.some.call(g.querySelectorAll('.mod'), function (r) { return !r.hidden && r.style.display !== 'none'; });
        g.hidden = !any;
      });
      var n = visible().length;
      cfg.els.empty.hidden = n > 0;
    }

    function firstIn(host, pred) {
      if (host.find) return host.find(pred)[0] || null;                 // the fake DOM used by the unit tests
      var all = host.querySelectorAll('*');
      for (var i = 0; i < all.length; i++) if (pred(all[i])) return all[i];
      return null;
    }
    function renderAll() {
      recompute();
      var sel = cfg.getSelected();
      var focusKey = null, focusAct = null, focusItem = null, ae = doc.activeElement;
      var anchorTop = (ae && cfg.els.rail.contains && cfg.els.rail.contains(ae) && ae.getBoundingClientRect) ? ae.getBoundingClientRect().top : null;   // where the clicked item is on screen
      if (ae && cfg.els.rail.contains && cfg.els.rail.contains(ae)) { focusKey = ae.dataset.key || null; focusAct = ae.dataset.act || null; focusItem = ae.dataset.item || null; }
      renderRail(doc, cfg.els.rail, model, {category: state.category, selected: sel}, {
        onCategory: function (key) { state.category = key; refresh(); },
        onSelectAll: function (c) { cfg.setMany(c.items.map(function (m) { return m.name; }), true); },
        onClear: function (c) { cfg.setMany(c.items.map(function (m) { return m.name; }), false); },
        onItem: function (name, on) { cfg.setSelected(name, on); },
        onOpen: function (name, opener) { openCard(name, opener); }
      });
      if (focusItem || focusKey !== null) {
        var target = firstIn(cfg.els.rail, function (n) {
          if (focusItem) return n.dataset && n.dataset.item === focusItem && n.tagName && String(n.tagName).toLowerCase() === 'input';
          return n.dataset && n.dataset.key === focusKey && (focusAct ? n.dataset.act === focusAct : !n.dataset.act && !n.dataset.item);
        });
        if (target && target.focus) target.focus();
        keepAnchored(doc, target, anchorTop);
      }
      renderCoverage(doc, cfg.els.coverage, coverage(model, sel));
      if (tools) tools.update(familyCounts(shown.concat(customStub()), sel), {family: state.family, shown: visible().length, total: shown.length,
        zone: state.zone, zoneCounts: root.OGExplainer ? root.OGExplainer.zoneCounts(shown) : null});
      applyRows();
      if (cfg.onRender) cfg.onRender();
    }
    function customStub() { var n = cfg.customRecipes() | 0; var a = []; for (var i = 0; i < n; i++) a.push({prefix: 'CUSTOM'}); return a; }
    var tools = renderTools(doc, cfg.els.tools, {
      draft: cfg.metaStatus === 'draft-unverified',
      onText: function (v) { state.text = v; refresh(); },
      onZone: function (z) { state.zone = z; refresh(); },
      onFamily: function (k) { setFamily(k); }
    });
    function refresh() { renderAll(); }
    function setFamily(k) { state.family = k; if (state.category && state.category.split('|')[0] !== k) state.category = null; refresh(); }
    function clearFilters() { state.text = ''; state.family = 'ALL'; state.category = null; state.zone = null; tools.input.value = ''; refresh(); }

    /* ---- row enhancement: category tag + Details button (the row's checkbox and Visualize stay as they are) */
    function enhanceRows() {
      var all = cfg.getModules();
      Array.prototype.forEach.call(cfg.els.list.querySelectorAll('.mod'), function (row) {
        var cb = row.querySelector('input[type=checkbox]');
        if (!cb || (cb.classList && cb.classList.contains('modpin')) || row.querySelector('.ctag')) return;
        var mod = null; for (var i = 0; i < all.length; i++) if (all[i].name === cb.value) { mod = all[i]; break; }
        if (!mod) return;
        var fam = familyInfo(familyOf(mod));
        var title = row.querySelector('.mtitle');
        var tag = el(doc, 'span', {cls: 'ctag', text: categoryOf(mod)});
        setColor(tag, fam.token);
        if (title && title.parentNode) title.parentNode.insertBefore(tag, title.nextSibling);
        if (mod.ot_only && title && title.parentNode) {
          var ot = el(doc, 'span', {cls: 'ctag ctag-ot', text: 'OT', attrs: {title: 'Only runs when the OT zone is switched on'}});
          title.parentNode.insertBefore(ot, tag.nextSibling);
        }
        var side = row.querySelector('.mside');
        var btn = el(doc, 'button', {cls: 'detbtn', attrs: {type: 'button', 'aria-label': 'Details for ' + (mod.title || mod.name)},
          data: {mod: mod.name}, text: 'Details', on: {click: function (ev) { ev.preventDefault(); ev.stopPropagation(); openCard(mod.name, btn); }}});
        if (side) side.appendChild(btn);
      });
    }

    /* ---- the card */
    var onKey = null;
    function listForCard() { return visible(); }
    function openCard(name, opener) {
      var list = listForCard();
      var idx = -1; list.forEach(function (m, i) { if (m.name === name) idx = i; });
      if (idx < 0) { list = shown.slice(); list.forEach(function (m, i) { if (m.name === name) idx = i; }); }
      if (idx < 0) return;
      close(true);
      var backdrop = el(doc, 'div', {cls: 'scard-backdrop'});
      var inerted = [];
      open = {backdrop: backdrop, list: list, idx: idx, opener: opener || null, name: name, inerted: inerted, dlg: null};
      backdrop.addEventListener('mousedown', function (ev) { if (ev.target === backdrop) close(); });
      doc.body.appendChild(backdrop);
      Array.prototype.forEach.call(doc.body.children, function (c) { if (c !== backdrop) { inerted.push([c, c.inert]); c.inert = true; } });
      if (doc.body.classList) doc.body.classList.toggle('scard-open', true);
      onKey = function (ev) {
        if (!open) return;
        if (ev.key === 'Escape') { ev.preventDefault(); ev.stopPropagation(); close(); return; }
        trapTab(open.dlg, ev, doc);
      };
      doc.addEventListener('keydown', onKey, true);
      show(null, true);
    }
    function show(focusAct, first) {
      if (!open) return;
      var m = open.list[open.idx];
      open.name = m.name;
      var fam = familyOf(m);
      var dlg = buildCard(doc, m, {
        family: fam, selected: cfg.getSelected().has(m.name), canVisualize: cfg.canVisualize(m.name),
        pos: open.idx + 1, count: open.list.length, hasPrev: open.idx > 0, hasNext: open.idx < open.list.length - 1,
        disabledToggle: cfg.toggleDisabled ? cfg.toggleDisabled(m.name) : false, autoplay: true
      }, {
        onExplainer: function (ex) { if (open) { if (open.ex) open.ex.stop(); open.ex = ex; } },
        onClose: function () { close(); },
        onPrev: function () { open.idx--; show('prev'); },
        onNext: function () { open.idx++; show('next'); },
        onVisualize: function () { cfg.visualize(m.name); },
        onToggle: function () { cfg.setSelected(m.name, !cfg.getSelected().has(m.name)); show('toggle'); },
        onShift: cfg.setShift ? function (d) { cfg.setShift(m.name, d); show(d ? 'shift' : 'shift-reset'); } : null
      });
      if (open.dlg && open.dlg.parentNode) open.dlg.parentNode.removeChild(open.dlg);
      open.dlg = dlg;
      open.backdrop.appendChild(dlg);
      if (first && open.opener && open.opener.getBoundingClientRect && dlg.getBoundingClientRect) {
        // the card grows out of the control that opened it, so where it came from is obvious
        var a = open.opener.getBoundingClientRect(), b = dlg.getBoundingClientRect();
        dlg.style.transformOrigin = (a.left + a.width / 2 - b.left) + 'px ' + (a.top + a.height / 2 - b.top) + 'px';
        dlg.classList.add('scard-enter');
      }
      var target = null;
      if (focusAct) target = dlg.find ? dlg.find(function (n) { return n.dataset && n.dataset.act === focusAct && !n.disabled; })[0] : null;
      if (!target && focusAct && dlg.querySelector) target = dlg.querySelector('[data-act="' + focusAct + '"]:not(:disabled)');
      if (!target) target = dlg.querySelector ? dlg.querySelector('#scard-title') : null;
      if (target && target.focus) target.focus();
    }
    function close(silent) {
      if (!open) return;
      var o = open; open = null;
      if (o.ex) o.ex.stop();
      if (onKey) { doc.removeEventListener('keydown', onKey, true); onKey = null; }
      if (o.backdrop.parentNode) o.backdrop.parentNode.removeChild(o.backdrop);
      o.inerted.forEach(function (p) { p[0].inert = !!p[1]; });
      if (doc.body.classList) doc.body.classList.toggle('scard-open', false);
      if (silent) return;
      var back = o.opener && o.opener.isConnected !== false && doc.contains && doc.contains(o.opener) ? o.opener : null;
      if (!back) back = cfg.els.list.querySelector('.detbtn[data-mod="' + String(o.name).replace(/"/g, '') + '"]');
      if (back && back.focus) back.focus();
    }

    return {
      state: state, refresh: refresh, setFamily: setFamily, enhanceRows: enhanceRows, clearFilters: clearFilters, openCard: openCard, close: close,
      isOpen: function () { return !!open; }, rerenderCard: function () { if (open) show(null); },
      visibleNames: function () { return visible().map(function (m) { return m.name; }); }, visibleModules: function () { return visible(); }, model: function () { return model; }
    };
  }

  var api = {
    keepAnchored: keepAnchored, UNCAT: UNCAT, FAMILIES: FAMILIES, DRAFT_LINE: DRAFT_LINE,
    familyOf: familyOf, categoryOf: categoryOf, categoryKey: categoryKey, shownModules: shownModules,
    buildModel: buildModel, countsFor: countsFor, coverage: coverage, filterModules: filterModules,
    familyCounts: familyCounts, parseWindow: parseWindow,
    formatWindow: formatWindow, winOf: winOf, shiftLimits: shiftLimits, setShift: setShift, collectShifts: collectShifts, loadShifts: loadShifts,
    wrapIndex: wrapIndex, focusables: focusables, trapTab: trapTab,
    renderRail: renderRail, renderCoverage: renderCoverage, renderTools: renderTools, buildCard: buildCard,
    createController: createController
  };
  root.OGCards = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : this);
