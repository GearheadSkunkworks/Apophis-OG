/* Compose options: the "Network options" and "Exports" sections, driven by the table in build-options.json.
   One row per option (id, label, help, control, default, api, params, est). The pure functions (defaults, collect,
   extras, summary) are exported for tests; mount() builds the controls with DOM calls only, so nothing from data is
   ever parsed as HTML. The page calls OGOptionsCore.mount(), then reads collect() when it builds the generate body. */
(function (root) {
  'use strict';

  function whenOk(p, vals) {
    if (!p.when) return true;
    return Object.keys(p.when).every(function (k) { return vals[k] === p.when[k]; });
  }

  /* state: {rowId: {on: bool, p: {paramId: value}}}, every option off, every parameter at its default. */
  function defaults(table) {
    var st = {};
    table.options.forEach(function (r) {
      var p = {};
      (r.params || []).forEach(function (q) { p[q.id] = q.default; });
      st[r.id] = {on: !!r.default, p: p};
    });
    return st;
  }

  /* -> {network_options: {...}, exports: [...]} holding only what is switched on; {} when everything is off, so a
     default build sends nothing new. */
  function collect(table, state) {
    var out = {};
    table.options.forEach(function (r) {
      var s = state[r.id];
      if (!s || !s.on) return;
      if (r.api.field === 'exports') {
        (out.exports = out.exports || []).push(r.api.key);
        return;
      }
      var o = {};
      (r.params || []).forEach(function (q) {
        if (q.api && whenOk(q, s.p)) o[q.api] = q.control === 'number' ? Number(s.p[q.id]) : s.p[q.id];
      });
      (out[r.api.field] = out[r.api.field] || {})[r.api.key] = o;
    });
    if (out.exports) out.exports.sort();
    return out;
  }

  /* The estimate's addition for the chosen options, from the measured figures in each row's est block:
     bytes_per_packet (per frame), pcap_ratio (output bytes per pcap byte), seconds_per_mpackets (build time).
     pk in millions of packets, gb in gigabytes. -> {gb, seconds, files, names} */
  function extras(table, state, pk, gb) {
    var add = {gb: 0, seconds: 0, files: 0, names: []};
    table.options.forEach(function (r) {
      var s = state[r.id];
      if (!s || !s.on) return;
      var e = r.est || {};
      add.gb += (e.bytes_per_packet || 0) * pk * 1e6 / 1e9 + (e.pcap_ratio || 0) * gb;
      add.seconds += (e.seconds_per_mpackets || 0) * pk;
      add.files += (r.files || []).length;
      add.names.push(r.label);
    });
    return add;
  }

  /* One short line for a section header: "Off", "On: VLAN tagging" or "2 on". */
  function summary(table, state, group) {
    var on = table.options.filter(function (r) { return r.group === group && state[r.id] && state[r.id].on; });
    if (!on.length) return 'Off';
    return on.length === 1 ? 'On: ' + on[0].label : on.length + ' on';
  }

  function el(doc, tag, attrs, kids) {
    var n = doc.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === 'text') n.textContent = attrs[k]; else n.setAttribute(k, attrs[k]);
    });
    (kids || []).forEach(function (c) { n.appendChild(c); });
    return n;
  }

  /* Build every group into mounts[group.id] (an element) and keep state current. onChange(state) fires after any edit. */
  function mount(doc, table, mounts, state, onChange) {
    var shown = [];                                   // [{node, row, param}] re-shown or hidden on each change
    function refresh() {
      shown.forEach(function (x) {
        x.node.hidden = !(state[x.row.id].on && (!x.param || whenOk(x.param, state[x.row.id].p)));
      });
    }
    function changed() { refresh(); if (onChange) onChange(state); }
    table.groups.forEach(function (g) {
      var host = mounts[g.id];
      if (!host) return;
      host.textContent = '';
      host.appendChild(el(doc, 'p', {class: 'hint', text: g.lead}));
      table.options.filter(function (r) { return r.group === g.id; }).forEach(function (r) {
        var s = state[r.id], hid = 'opt-' + r.id + '-help';
        var box = el(doc, 'div', {class: 'optrow'});
        var cb = el(doc, 'input', {type: 'checkbox', class: 'sw', id: 'opt-' + r.id, 'aria-describedby': hid});
        cb.checked = s.on;
        cb.addEventListener('change', function () { s.on = cb.checked; changed(); });
        box.appendChild(el(doc, 'label', {for: 'opt-' + r.id}, [cb, el(doc, 'span', {text: r.label})]));
        box.appendChild(el(doc, 'p', {class: 'hint', id: hid, text: r.help}));
        var sub = el(doc, 'div', {class: 'optparams fgrid', role: 'group', 'aria-label': r.label + ' settings'});
        (r.params || []).forEach(function (q) {
          var id = 'opt-' + r.id + '-' + q.id, ctl, fld;
          if (q.control === 'select') {
            ctl = el(doc, 'select', {id: id}, q.options.map(function (o) { return el(doc, 'option', {value: o.value, text: o.label}); }));
            ctl.value = s.p[q.id];
            ctl.addEventListener('change', function () { s.p[q.id] = ctl.value; changed(); });
          } else if (q.control === 'number') {
            ctl = el(doc, 'input', {type: 'number', id: id, min: q.min, max: q.max, step: 1});
            ctl.value = s.p[q.id];
            ctl.addEventListener('input', function () {
              var v = parseInt(ctl.value, 10);
              s.p[q.id] = isNaN(v) ? q.default : Math.max(q.min, Math.min(q.max, v));
              changed();
            });
          } else {
            ctl = el(doc, 'input', {type: 'checkbox', class: 'sw', id: id});
            ctl.checked = !!s.p[q.id];
            ctl.addEventListener('change', function () { s.p[q.id] = ctl.checked; changed(); });
          }
          if (q.control === 'toggle') fld = el(doc, 'div', {class: 'fld'}, [el(doc, 'label', {for: id, class: 'inl'}, [ctl, el(doc, 'span', {text: q.label})])]);
          else fld = el(doc, 'div', {class: 'fld'}, [el(doc, 'label', {for: id, text: q.label}), ctl]);
          if (q.help) {
            ctl.setAttribute('aria-describedby', id + '-help');
            fld.appendChild(el(doc, 'p', {class: 'hint', id: id + '-help', text: q.help}));
          }
          sub.appendChild(fld);
          shown.push({node: fld, row: r, param: q});
        });
        if (r.params && r.params.length) { box.appendChild(sub); shown.push({node: sub, row: r}); }
        if (r.note) box.appendChild(el(doc, 'p', {class: 'hint optnote', text: r.note}));
        host.appendChild(box);
      });
    });
    refresh();
  }

  var api = {defaults: defaults, collect: collect, extras: extras, summary: summary, mount: mount, whenOk: whenOk};
  root.OGOptionsCore = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : this);
