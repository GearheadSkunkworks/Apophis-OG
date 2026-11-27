/* Campaign Builder, step 4 "Save & run" and the results renderer.
 * Check + summary, save/download, library list, address mode, "use in next capture" toggle,
 * and OGC.renderResults(summary, container) for the capture-results card.
 * Vanilla ES2019. All dynamic text goes through textContent; nothing is evaluated.
 * The campaign describes network behaviour used to test a sensor; nothing here sends traffic. */
(function () {
  'use strict';

  var root = (typeof window !== 'undefined') ? window : globalThis;
  root.OGC = root.OGC || {};
  var OGC = root.OGC;

  /* ------------------------------------------------------------------ pure logic */

  var OBSERVABLE = ['ipv4', 'ipv6', 'domain', 'url'];

  function slugify(s) {
    var t = String(s == null ? '' : s).toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/-+/g, '-').replace(/^[-_]+|[-_]+$/g, '');
    t = t.slice(0, 64).replace(/[-_]+$/g, '');
    return t || 'campaign';
  }

  function safeFilename(name) { return slugify(name) + '.campaign.json'; }

  function relativeTime(modified, now) {
    var t;
    if (typeof modified === 'number') t = modified < 1e12 ? modified * 1000 : modified;
    else if (typeof modified === 'string' && modified) t = Date.parse(modified);
    else return '';
    if (!isFinite(t)) return '';
    var n = (typeof now === 'number') ? now : Date.now();
    var d = Math.round((n - t) / 1000);
    if (d < 0) d = 0;
    if (d < 45) return 'just now';
    if (d < 90) return '1 minute ago';
    var m = Math.round(d / 60);
    if (m < 60) return m + ' minutes ago';
    var h = Math.round(m / 60);
    if (h < 24) return h + (h === 1 ? ' hour ago' : ' hours ago');
    var dd = Math.round(h / 24);
    if (dd < 30) return dd + (dd === 1 ? ' day ago' : ' days ago');
    var mo = Math.round(dd / 30);
    if (mo < 12) return mo + (mo === 1 ? ' month ago' : ' months ago');
    var y = Math.round(dd / 365);
    return y + (y === 1 ? ' year ago' : ' years ago');
  }

  function realConfirmed(text) { return text === 'REAL'; }

  function fmtBytes(n) {
    n = Number(n) || 0;
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MB';
    return (n / 1073741824).toFixed(2) + ' GB';
  }

  function num(n) { return (Number(n) || 0).toLocaleString('en-US'); }

  function applyMeta(campaign, name, description) {
    if (!campaign) return null;
    var c = JSON.parse(JSON.stringify(campaign));
    c.meta = c.meta || {};
    if (name != null && String(name).trim()) c.meta.name = String(name).trim().slice(0, 120);
    if (description != null) c.meta.description = String(description).slice(0, 1000);
    return c;
  }

  /* what POST /api/generate gets. s: {armed, check:{errors}|null, campaign, mode, confirmed} */
  function buildExtras(s) {
    if (!s || !s.armed || !s.campaign) return {};
    if (s.check && s.check.errors && s.check.errors.length) return {};
    var real = s.mode === 'real';
    return { campaigns: [s.campaign], address_mode: real ? 'real' : 'mapped',
             confirm_real_addresses: !!(real && s.confirmed) };
  }

  function campaignSummary(c, est) {
    var stages = (c && c.stages) || [], actions = 0, tech = {}, i, j;
    for (i = 0; i < stages.length; i++) {
      actions += ((stages[i] && stages[i].actions) || []).length;
      var ts = (stages[i] && stages[i].techniques) || [];
      for (j = 0; j < ts.length; j++) tech[ts[j]] = 1;
    }
    return { stages: stages.length, actions: actions, iocs: ((c && c.iocs) || []).length,
             techniques: Object.keys(tech).length, estimate: est || null };
  }

  function ref(v) { return v == null ? '' : String(v); }

  /* entries: the runner's records when the summary carries them, else rebuilt from console lines */
  function parseConsole(lines) {
    var out = [], stage = null, cur = null, m, i;
    lines = Array.isArray(lines) ? lines : [];
    for (i = 0; i < lines.length; i++) {
      var L = String(lines[i]);
      if ((m = /^\[[\d:]+\] Stage (\d+)\/\d+: (.*?)(?: \(([^)]*)\))? \[([^\]]*)\]\s*$/.exec(L))) {
        stage = { id: 's' + m[1], name: m[2], tactic: m[4] }; cur = null; continue;
      }
      if ((m = /^\s+\[[\d:]+\] \$ (\S+)\s*(.*)$/.exec(L))) {
        var rest = m[2], ar = /^(.*?)(\S+ \([^)]*\)|\S+) -> (\S+(?: \([^)]*\))?)(?: \(.*\))?\s*$/.exec(rest);
        cur = { stage: stage ? stage.id : '', stage_name: stage ? stage.name : '', action: m[1],
                from: ar ? ar[2] : '', to: ar ? ar[3] : rest, packets: 0, bytes: 0, protocols: [], status: 'unknown' };
        out.push(cur); continue;
      }
      if (cur && (m = /^\s+(\d+) packets?, ([\d.,]+ \S+), ?(.*)$/.exec(L))) {
        cur.packets = Number(m[1]); cur.status = 'ok';
        cur.protocols = m[3] ? m[3].split('/') : []; cur = null; continue;
      }
      if (cur && /skipped|failed|error/i.test(L)) { cur.status = /failed/i.test(L) ? 'failed' : 'skipped'; cur.error = L.trim(); }
    }
    return out;
  }

  function endpointText(e, side) {
    var h = e[side + '_host'];
    var raw = ref(e[side]);
    if (h && (h.name || h.ip)) return (raw && raw !== h.name ? raw + ' ' : '') + '(' + (h.name || '') + (h.name && h.ip ? ' ' : '') + (h.ip || '') + ')';
    return raw;
  }

  function actionRows(summary) {
    var camp = (summary && summary.campaign) || {};
    var entries = Array.isArray(camp.entries) ? camp.entries : null;
    if (!entries) entries = parseConsole(summary && summary.campaign_console);
    return entries.map(function (e) {
      var status = e.status === 'ok' ? 'ok' : (e.status === 'failed' ? 'failed' : (e.status === 'skipped' || e.status === 'scheduled' ? 'skipped' : (e.status || 'unknown')));
      return { stage: ref(e.stage_name || e.stage), stageId: ref(e.stage), action: ref(e.action),
               from: endpointText(e, 'from'), to: endpointText(e, 'to'),
               packets: Number(e.packets) || 0, bytes: Number(e.bytes) || 0,
               protocols: Array.isArray(e.protocols) ? e.protocols.map(String) : [],
               status: status, error: e.error ? String(e.error) : '' };
    });
  }

  /* one row per (observable indicator, emitting action). Needs summary.campaign.iocs + entries. */
  function iocRows(summary, campaign) {
    var camp = (summary && summary.campaign) || {};
    var entries = Array.isArray(camp.entries) ? camp.entries : [];
    var table = {}, i;
    (Array.isArray(camp.iocs) ? camp.iocs : []).forEach(function (r) { if (r && r.index != null) table[r.index] = r; });
    var rows = [];
    entries.forEach(function (e) {
      if (e.status !== 'ok') return;
      (Array.isArray(e.ioc) ? e.ioc : []).forEach(function (idx) {
        var r = table[idx];
        if (!r && campaign && campaign.iocs && campaign.iocs[idx]) {
          var c = campaign.iocs[idx]; r = { type: c.type, value: c.value, role: c.role, address: '' };
        }
        if (!r || OBSERVABLE.indexOf(r.type) < 0) return;
        rows.push({ indicator: ref(r.value), role: ref(r.role), address: ref(r.address || r.value),
                    stage: ref(e.stage_name || e.stage), action: ref(e.action), packets: Number(e.packets) || 0 });
      });
    });
    return rows;
  }

  function coverage(summary, campaign) {
    var camp = (summary && summary.campaign) || {};
    var entries = Array.isArray(camp.entries) ? camp.entries : null;
    var expect = (campaign && Array.isArray(campaign.expect)) ? campaign.expect : [];
    var ran = {};
    if (entries) {
      entries.forEach(function (e) {
        if (e.status === 'ok') (e.techniques || []).forEach(function (t) { ran[t] = true; });
      });
    }
    var rows = expect.map(function (x) {
      var t = x && x.technique;
      return { technique: ref(t), stage: ref(x && x.stage), state: !entries ? 'unknown' : (ran[t] ? 'covered' : 'missing') };
    });
    return { known: !!entries, rows: rows,
             covered: rows.filter(function (r) { return r.state === 'covered'; }).length,
             missing: rows.filter(function (r) { return r.state === 'missing'; }).length,
             ran: Object.keys(ran).sort() };
  }

  function headline(summary) {
    var c = (summary && summary.campaign) || {};
    if (c.error) return 'The campaign could not be added: ' + c.error;
    var emitted = c.emitted, total = c.actions;
    if (emitted == null || total == null) {
      var rows = actionRows(summary);
      total = rows.length; emitted = rows.filter(function (r) { return r.status === 'ok'; }).length;
    }
    var pk = 0, by = 0;
    actionRows(summary).forEach(function (r) { pk += r.packets; by += r.bytes; });
    var tail = pk ? ', ' + num(pk) + ' packets' + (by ? ' (' + fmtBytes(by) + ')' : '') : '';
    return emitted + ' of ' + total + ' actions emitted' + tail;
  }

  function exportList(summary) {
    var ex = ((summary && summary.campaign) || {}).exports || {};
    var labels = { campaign: 'Campaign JSON', stix: 'STIX indicator bundle', navigator: 'ATT&CK Navigator layer', report: 'Report',
      html: 'Report (web page)', csv: 'Indicators (CSV)', misp: 'MISP event' };
    var out = [];
    Object.keys(ex).forEach(function (id) {
      var set = ex[id] || {};
      ['campaign', 'stix', 'navigator', 'report', 'html', 'csv', 'misp'].forEach(function (k) {
        if (set[k]) out.push({ campaign: id, kind: labels[k], path: String(set[k]) });
      });
    });
    return out;
  }

  function errorList(summary) {
    var e = ((summary && summary.campaign) || {}).errors;
    return (Array.isArray(e) ? e : []).map(function (x) {
      if (typeof x === 'string') return x;
      var s = (x && (x.error || x.message)) || JSON.stringify(x);
      if (x && x.stage) s = 'stage ' + x.stage + (x.action ? ', ' + x.action : '') + ': ' + s;
      if (x && Array.isArray(x.details) && x.details.length) s += ' (' + x.details.join('; ') + ')';
      return s;
    });
  }

  OGC._test = Object.assign(OGC._test || {}, {
    slugify: slugify, safeFilename: safeFilename, relativeTime: relativeTime, realConfirmed: realConfirmed,
    buildExtras: buildExtras, armedAfterCampaign: armedAfterCampaign, applyMeta: applyMeta, campaignSummary: campaignSummary, parseConsole: parseConsole,
    actionRows: actionRows, iocRows: iocRows, coverage: coverage, headline: headline, exportList: exportList,
    errorList: errorList, fmtBytes: fmtBytes
  });

  /* ------------------------------------------------------------------ DOM (browser only) */

  if (typeof document === 'undefined' || !document.createElement) return;

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

  /* Library, preview and arm styles: tokens only (theme.css). Buttons are styled in campaigns.css. */
  var STYLE = [
    '#ogc-card .ogcl{display:flex;flex-direction:column;gap:14px;font-family:var(--font-ui)}',
    '#ogc-card .ogcl-panel{border:1px solid var(--ln);border-radius:4px;padding:14px 16px;background:var(--p1)}',
    '#ogc-card .ogcl-panel h4{margin:0 0 8px;font-size:1rem;font-weight:600;color:var(--ink)}',
    '#ogc-card .ogcl-row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:6px 0;padding-bottom:4px}',
    '#ogc-card .ogcl-row label{font-size:0.8125rem;font-weight:500;color:var(--mu)}',
    '#ogc-card .ogcl input[type=text],#ogc-card .ogcl textarea{font:inherit;font-size:0.8125rem;padding:5px 10px;border:1px solid var(--ln2);border-radius:3px;background:var(--p2);color:var(--ink);min-width:0;min-height:34px}',
    '#ogc-card .ogcl textarea{width:100%;min-height:56px;box-sizing:border-box}',
    '#ogc-card .ogcl input[type=checkbox]{accent-color:var(--cy)}',
    '#ogc-card .ogcl-note{font-size:0.75rem;color:var(--mu);margin:4px 0}',
    '#ogc-card .ogcl-ok{font-weight:600;color:var(--ok)}',
    '#ogc-card .ogcl-bad{font-weight:600;color:var(--er)}',
    '#ogc-card .ogcl-warn{border:1px solid color-mix(in srgb,var(--wr) 45%,var(--p1));border-left:3px solid var(--wr);background:color-mix(in srgb,var(--wr-fill) 12%,var(--p1));border-radius:0 3px 3px 0;padding:6px 10px;font-size:0.8125rem;margin:6px 0}',
    '#ogc-card .ogcl-errs{margin:6px 0 0;padding-left:18px;font-size:0.8125rem;color:var(--er)}',
    '#ogc-card .ogcl-stats{display:flex;flex-wrap:wrap;gap:18px;font-size:0.75rem;color:var(--mu);margin:6px 0}',
    '#ogc-card .ogcl-stats b{font-size:1.375rem;font-weight:600;display:block;color:var(--ink);font-variant-numeric:tabular-nums}',
    '#ogc-card .ogcl-tbl-wrap{overflow:auto;max-width:100%;max-height:340px;border:1px solid var(--ln);border-radius:3px}',
    '#ogc-card .ogcl-tbl{border-collapse:collapse;width:100%;font-size:0.8125rem}',
    '#ogc-card .ogcl-tbl th,#ogc-card .ogcl-tbl td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--ln);vertical-align:top}',
    '#ogc-card .ogcl-tbl td.n{text-align:right;font-variant-numeric:tabular-nums}',
    '#ogc-card .ogcl-mono{font-family:var(--font-mono);font-size:0.75rem}',
    '#ogc-card .ogcl-console{max-height:260px;overflow:auto;white-space:pre-wrap;word-break:break-word;background:var(--log-bg);color:var(--log-ink);border:1px solid var(--ln);border-radius:3px;padding:10px 12px;margin:6px 0;line-height:1.6}',
    /* armed badge and status tags */
    '#ogc-card .ogcl-badge,.ogcl-results .ogcl-badge,#ogc-armed-badge{display:inline-flex;align-items:center;height:24px;font-size:0.75rem;font-weight:500;padding:0 9px;border-radius:3px;border:1px solid color-mix(in srgb,var(--cy) 55%,transparent);color:var(--cy-tx);background:color-mix(in srgb,var(--cy) 10%,transparent);margin-left:8px;box-shadow:0 0 12px color-mix(in srgb,var(--cy) 22%,transparent)}',
    '#ogc-card .ogcl-tag{display:inline-block;font-size:0.75rem;padding:0 7px;border:1px solid currentColor;border-radius:3px}',
    '#ogc-card .ogcl-btn,#ogc-card .ogcl button{font-family:var(--font-ui)}',
    '#ogc-card .ogcl :is(button,input,textarea,select):focus-visible{outline:2px solid var(--cy);outline-offset:2px}',
    '#ogc-card .ogcl input[type=text]:focus,#ogc-card .ogcl textarea:focus{border-color:var(--cy);box-shadow:0 0 0 3px color-mix(in srgb,var(--cy) 18%,transparent)}',
    '.ogcl-results{display:flex;flex-direction:column;gap:12px;margin-top:12px;font-family:var(--font-ui);color:var(--ink)}',
    '.ogcl-results .ogcl-panel{border:1px solid var(--ln);border-radius:4px;padding:14px 16px;background:var(--p1)}',
    '.ogcl-results .ogcl-panel h4{margin:0 0 8px;font-size:1rem;font-weight:600}',
    '.ogcl-results .ogcl-tbl{border-collapse:collapse;width:100%;font-size:0.8125rem}',
    '.ogcl-results .ogcl-tbl th,.ogcl-results .ogcl-tbl td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--ln);vertical-align:top}',
    '.ogcl-results .ogcl-tbl td.n{text-align:right;font-variant-numeric:tabular-nums}',
    '.ogcl-results .ogcl-tbl-wrap{overflow:auto;max-width:100%;max-height:340px}',
    '.ogcl-results .ogcl-mono{font-family:var(--font-mono);font-size:0.75rem}',
    '.ogcl-results .ogcl-console{max-height:260px;overflow:auto;white-space:pre-wrap;word-break:break-word;background:var(--log-bg);color:var(--log-ink);border:1px solid var(--ln);border-radius:3px;padding:10px 12px;margin:6px 0}',
    '.ogcl-results .ogcl-note{font-size:0.75rem;color:var(--mu)}',
    '.ogcl-results .ogcl-tag{display:inline-block;font-size:0.75rem;padding:0 7px;border:1px solid currentColor;border-radius:3px}',
    /* in-page confirmation dialog */
    '.ogcl-dlg-back{position:fixed;inset:0;background:color-mix(in srgb,var(--bg) 72%,transparent);backdrop-filter:blur(3px);z-index:10000;display:flex;align-items:center;justify-content:center}',
    '.ogcl-dlg{background:var(--p1);color:var(--ink);max-width:520px;width:calc(100% - 32px);border-radius:4px;padding:20px 22px;box-shadow:0 30px 70px -20px rgba(0,0,0,.7);border:1px solid var(--ln2);font-family:var(--font-ui)}',
    '.ogcl-dlg h3{margin:0 0 8px;font-size:1.0625rem;font-weight:600}',
    '.ogcl-dlg p{font-size:0.875rem;margin:6px 0;color:var(--mu)}',
    '.ogcl-dlg input{font:inherit;font-size:0.875rem;padding:0 10px;min-height:34px;width:100%;box-sizing:border-box;margin-top:6px;background:var(--p2);color:var(--ink);border:1px solid var(--ln2);border-radius:3px}',
    '.ogcl-dlg .ogcl-actions{display:flex;gap:12px;justify-content:flex-end;margin-top:16px;padding-bottom:12px}',
    '@media (prefers-reduced-motion:reduce){#ogc-card .ogcl *,.ogcl-dlg *{transition:none !important;animation:none !important}}'
  ].join('\n');

  function injectStyle() {
    if (document.getElementById('ogc-library-style')) return;
    var s = h('style', { id: 'ogc-library-style' });
    s.textContent = STYLE;
    (document.head || document.documentElement).appendChild(s);
  }

  /* in-page dialog (no alert/confirm). Resolves true on confirm. opts.expect = word that must be typed. */
  function dialog(opts) {
    return new Promise(function (resolve) {
      var prev = document.activeElement, input = null;
      var ok = h('button', { type: 'button', class: 'ogcl-btn', text: opts.confirmText || 'OK' });
      var cancel = h('button', { type: 'button', class: 'ogcl-btn', text: opts.cancelText || 'Cancel' });
      var body = (opts.body || []).map(function (t) { return h('p', { text: t }); });
      if (opts.expect) {
        input = h('input', { type: 'text', 'aria-label': 'Type ' + opts.expect + ' to confirm', autocomplete: 'off', spellcheck: 'false' });
        ok.disabled = true;
        input.addEventListener('input', function () { ok.disabled = !realConfirmed(input.value); });
      }
      var box = h('div', { class: 'ogcl-dlg ogc-dialog', role: 'dialog', 'aria-modal': 'true', 'aria-label': opts.title || 'Confirm' },
        h('h3', { text: opts.title || 'Confirm' }), body, input, h('div', { class: 'ogcl-actions' }, cancel, ok));
      var back = h('div', { class: 'ogcl-dlg-back' }, box);
      function done(v) {
        document.removeEventListener('keydown', onKey, true);
        if (back.parentNode) back.parentNode.removeChild(back);
        try { if (prev && prev.focus) prev.focus(); } catch (e) { /* ignore */ }
        resolve(v);
      }
      function onKey(ev) {
        if (ev.key === 'Escape') { ev.stopPropagation(); done(false); }
        else if (ev.key === 'Enter' && input && ev.target === input && !ok.disabled) { ev.preventDefault(); done(true); }
        else if (ev.key === 'Tab') {
          var f = Array.prototype.filter.call(box.querySelectorAll('input,button'), function (x) { return !x.disabled; });
          if (!f.length) return;
          var first = f[0], last = f[f.length - 1];
          if (ev.shiftKey && document.activeElement === first) { ev.preventDefault(); last.focus(); }
          else if (!ev.shiftKey && document.activeElement === last) { ev.preventDefault(); first.focus(); }
        }
      }
      ok.addEventListener('click', function () { if (!ok.disabled) done(true); });
      cancel.addEventListener('click', function () { done(false); });
      back.addEventListener('mousedown', function (ev) { if (ev.target === back) done(false); });
      document.addEventListener('keydown', onKey, true);
      document.body.appendChild(back);
      (input || cancel).focus();
    });
  }

  function toast(msg, kind) { if (OGC.toast) OGC.toast(msg, kind || 'info'); }
  function api(method, path, body) {
    if (!OGC.api) return Promise.reject(new Error('The page is not ready yet.'));
    return method === 'GET' ? OGC.api.get(path) : OGC.api.post(path, body);
  }
  function msg(e) { return (e && e.message) ? e.message : String(e); }

  function table(cols, rows, cellFn) {
    var head = h('tr', null, cols.map(function (c) { return h('th', { scope: 'col', text: c.label }); }));
    var body = rows.map(function (r) {
      return h('tr', null, cols.map(function (c) {
        var v = cellFn(r, c);
        return h('td', { class: c.num ? 'n' : null }, v);
      }));
    });
    return h('div', { class: 'ogcl-tbl-wrap' }, h('table', { class: 'ogcl-tbl ogc-table' },
      h('thead', null, head), h('tbody', null, body)));
  }

  function copyText(text, label) {
    function fallback() {
      var ta = h('textarea', { 'aria-hidden': 'true' }); ta.value = text;
      ta.style.cssText = 'position:fixed;left:-9999px;top:0';
      document.body.appendChild(ta); ta.select();
      var ok = false; try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
      document.body.removeChild(ta);
      toast(ok ? (label || 'Copied') : 'Copy failed. Select the text and copy it by hand.', ok ? 'ok' : 'error');
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { toast(label || 'Copied', 'ok'); }, fallback);
    } else fallback();
  }

  /* ------------------------------------------------------------------ step 4 state */

  var S = { armed: false, restored: false, mode: 'mapped', confirmed: false, check: null, checkFor: '', est: null,
            library: null, libError: '', busy: false, mounted: false, timer: null, seq: 0 };
  var ui = {};

  function stateCampaign() { return (OGC.state && OGC.state.campaign) || null; }

  function currentCampaign() {
    var c = stateCampaign();
    if (!c) return null;
    return applyMeta(c, ui.name ? ui.name.value : null, ui.desc ? ui.desc.value : null);
  }

  OGC.generateExtras = function () {
    var c = currentCampaign();
    var key = c ? JSON.stringify(c) : '';
    var check = (S.check && S.checkFor === key) ? S.check : null;
    return buildExtras({ armed: S.armed, check: check, campaign: c, mode: S.mode, confirmed: S.confirmed });
  };

  /* The armed flag is part of the saved session: the page reads and sets it here (a campaign itself is not saved). */
  OGC.getArmed = function () { return S.armed; };
  /* A flag restored with a session, before any campaign is open, is dropped when the first campaign appears, so a
     campaign you load is never armed by surprise. Returns the new {armed, restored}. */
  function armedAfterCampaign(armed, restored, hasCampaign) {
    return restored && hasCampaign ? { armed: false, restored: false } : { armed: armed, restored: restored };
  }
  OGC.setArmed = function (on) {
    S.armed = !!on; S.restored = S.armed && !stateCampaign();
    var tg = document.getElementById('ogcl-arm'); if (tg) tg.checked = S.armed && !tg.disabled;
    try { renderRun(); updateBadge(); refreshCaptureEstimate(); } catch (e) { /* the step is not drawn yet */ }
  };
  if (typeof window !== 'undefined' && typeof window.__ogPendingArmed === 'boolean') { S.armed = window.__ogPendingArmed; S.restored = S.armed; window.__ogPendingArmed = undefined; }

  function updateBadge() {
    var sum = document.querySelector('#ogc-card > summary') || document.querySelector('#ogc-card summary');
    if (!sum) return;
    var b = document.getElementById('ogc-armed-badge');
    var c = S.armed ? currentCampaign() : null;
    if (!c) { if (b && b.parentNode) b.parentNode.removeChild(b); return; }
    if (!b) { b = h('span', { id: 'ogc-armed-badge', class: 'ogcl-badge ogc-chip' }); sum.appendChild(b); }
    b.textContent = 'In next capture: ' + (c.meta && c.meta.name || 'campaign');
  }

  function armedText() {
    var c = currentCampaign();
    return 'Campaign "' + ((c && c.meta && c.meta.name) || 'untitled') + '" will be added to the next capture';
  }

  /* ---- check panel */

  function scheduleCheck() {
    if (S.timer) clearTimeout(S.timer);
    S.timer = setTimeout(runCheck, 300);
  }

  function runCheck() {
    S.timer = null;
    var c = currentCampaign();
    if (!ui.check) return;
    if (!c) { S.check = null; S.est = null; renderCheck(); renderRun(); updateBadge(); return; }
    var key = JSON.stringify(c), my = ++S.seq;
    api('POST', '/api/campaign/validate', { campaign: c }).then(function (r) {
      if (my !== S.seq) return;
      S.check = { errors: (r && r.errors) || [] }; S.checkFor = key;
      renderCheck(); renderRun();
      return api('POST', '/api/campaign/estimate', { campaign: c, scale: 1.0 }).then(function (e) {
        if (my !== S.seq) return;
        S.est = e && !(e.errors && e.errors.length) ? e : null; renderCheck();
      }, function () { /* estimate is optional */ });
    }, function (e) {
      if (my !== S.seq) return;
      S.check = { errors: [], unavailable: msg(e) }; S.checkFor = key; renderCheck();
    });
  }

  function renderCheck() {
    var box = ui.check; if (!box) return;
    box.textContent = '';
    box.appendChild(h('h4', { text: '1. Check' }));
    var c = stateCampaign();
    if (!c) {
      box.appendChild(h('p', { class: 'ogcl-note', text: 'There is no campaign yet. Build one from indicators, open a saved one, or start from scratch.' }));
      return;
    }
    var sm = campaignSummary(c, S.est);
    var st = h('div', { 'aria-live': 'polite' });
    if (!S.check) st.appendChild(h('span', { text: 'Checking...' }));
    else if (S.check.unavailable) st.appendChild(h('span', { class: 'ogcl-bad', text: 'The check could not run: ' + S.check.unavailable }));
    else if (S.check.errors.length) {
      st.appendChild(h('span', { class: 'ogcl-bad', text: 'Not valid: ' + S.check.errors.length + (S.check.errors.length === 1 ? ' problem to fix' : ' problems to fix') }));
      st.appendChild(h('ul', { class: 'ogcl-errs' }, S.check.errors.slice(0, 30).map(function (e) { return h('li', { text: String(e) }); })));
      if (S.check.errors.length > 30) st.appendChild(h('p', { class: 'ogcl-note', text: '... and ' + (S.check.errors.length - 30) + ' more.' }));
    } else st.appendChild(h('span', { class: 'ogcl-ok', text: 'Valid. This campaign can be saved and added to a capture.' }));
    box.appendChild(st);
    var stats = [['Stages', sm.stages], ['Actions', sm.actions], ['Indicators', sm.iocs], ['Techniques', sm.techniques]];
    if (sm.estimate) {
      if (sm.estimate.flows != null) stats.push(['Flows (est.)', num(sm.estimate.flows)]);
      if (sm.estimate.minutes_realistic != null) stats.push(['Minutes, realistic', sm.estimate.minutes_realistic]);
      if (sm.estimate.minutes_fast != null) stats.push(['Minutes, fast', sm.estimate.minutes_fast]);
    }
    box.appendChild(h('div', { class: 'ogcl-stats' }, stats.map(function (x) {
      return h('div', null, h('b', { text: String(x[1]) }), x[0]);
    })));
  }

  /* ---- save panel */

  function syncFields() {
    var c = stateCampaign(), m = (c && c.meta) || {};
    if (ui.name && document.activeElement !== ui.name) ui.name.value = m.name || '';
    if (ui.desc && document.activeElement !== ui.desc) ui.desc.value = m.description || '';
  }

  function setMsg(text, kind) {
    if (!ui.msg) return;
    ui.msg.textContent = text || '';
    ui.msg.className = 'ogcl-note ' + (kind === 'ok' ? 'ogcl-ok' : kind === 'error' ? 'ogcl-bad' : '');
  }

  function needCampaign() {
    var c = currentCampaign();
    if (!c) { setMsg('There is no campaign to save yet.', 'error'); return null; }
    if (!c.meta || !c.meta.name) { setMsg('Give the campaign a name first.', 'error'); if (ui.name) ui.name.focus(); return null; }
    return c;
  }

  function saveToLibrary() {
    var c = needCampaign(); if (!c) return;
    c.meta.id = slugify(c.meta.name);
    S.busy = true; setMsg('Saving...');
    api('POST', '/api/campaign/library/save', { campaign: c, overwrite: false }).then(function (r) {
      return saved(c, r);
    }, function (e) {
      var m = msg(e);
      if (/exist|409|already/i.test(m)) {
        return dialog({ title: 'Replace the saved campaign?', body: ['A saved campaign named "' + c.meta.id + '" already exists. Saving will replace it.'], confirmText: 'Replace' }).then(function (yes) {
          if (!yes) { setMsg('Not saved. Change the name to keep both.'); return; }
          return api('POST', '/api/campaign/library/save', { campaign: c, overwrite: true }).then(function (r) { return saved(c, r); });
        });
      }
      setMsg('Could not save: ' + m, 'error'); toast('Could not save: ' + m, 'error');
    }).then(function () { S.busy = false; }, function (e) {
      S.busy = false; setMsg('Could not save: ' + msg(e), 'error'); toast('Could not save: ' + msg(e), 'error');
    });
  }

  function saved(c, r) {
    setMsg('Saved to the library' + (r && r.path ? ' at ' + r.path : '') + '.', 'ok');
    toast('Saved "' + c.meta.name + '"', 'ok');
    if (OGC.setCampaign) OGC.setCampaign(c, { source: 'edit' });
    return loadLibrary();
  }

  function downloadJson() {
    var c = needCampaign(); if (!c) return;
    try {
      var blob = new Blob([JSON.stringify(c, null, 2) + '\n'], { type: 'application/json' });
      var url = URL.createObjectURL(blob);
      var a = h('a', { href: url, download: safeFilename(c.meta.name) });
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
      setMsg('Downloaded ' + safeFilename(c.meta.name) + '.', 'ok');
    } catch (e) { setMsg('Could not download: ' + msg(e), 'error'); }
  }

  /* ---- library panel */

  function loadLibrary() {
    return api('GET', '/api/campaign/library').then(function (r) {
      S.library = (r && r.campaigns) || []; S.libDir = (r && r.dir) || ''; S.libError = ''; renderLibrary();
    }, function (e) { S.library = null; S.libError = msg(e); renderLibrary(); });
  }

  function openSaved(id) {
    api('POST', '/api/campaign/library/load', { id: id }).then(function (r) {
      if (!r || !r.campaign) throw new Error('The server returned no campaign.');
      OGC.setCampaign(r.campaign, { source: 'load' });
      toast('Opened "' + ((r.campaign.meta || {}).name || id) + '"', 'ok');
      if (OGC.goto) OGC.goto('build');
    }).catch(function (e) { toast('Could not open: ' + msg(e), 'error'); });
  }

  function duplicate(id) {
    api('POST', '/api/campaign/library/load', { id: id }).then(function (r) {
      var c = r && r.campaign; if (!c) throw new Error('The server returned no campaign.');
      c.meta = c.meta || {};
      c.meta.name = String(c.meta.name || id).slice(0, 110) + ' copy';
      c.meta.id = slugify(c.meta.name);
      return api('POST', '/api/campaign/library/save', { campaign: c, overwrite: false });
    }).then(function () { toast('Duplicated', 'ok'); return loadLibrary(); })
      .catch(function (e) { toast('Could not duplicate: ' + msg(e), 'error'); });
  }

  function remove(row) {
    dialog({ title: 'Delete this campaign?', body: ['"' + (row.name || row.id) + '" will be removed from the library. This cannot be undone.'], confirmText: 'Delete' }).then(function (yes) {
      if (!yes) return;
      return api('POST', '/api/campaign/library/delete', { id: row.id }).then(function () { toast('Deleted', 'ok'); return loadLibrary(); });
    }).catch(function (e) { toast('Could not delete: ' + msg(e), 'error'); });
  }

  function importFile(file) {
    if (!file) return;
    if (file.size > 2 * 1024 * 1024) { setLibMsg('That file is larger than 2 MB.', 'error'); return; }
    var fr = new FileReader();
    fr.onerror = function () { setLibMsg('The file could not be read.', 'error'); };
    fr.onload = function () {
      api('POST', '/api/campaign/library/import', { text: String(fr.result || '') }).then(function (r) {
        var errs = (r && r.errors) || [];
        if (errs.length || !r.campaign) {
          setLibMsg('Not imported. ' + (errs.slice(0, 5).join(' ') || 'The file is not a campaign.') + (errs.length > 5 ? ' (+' + (errs.length - 5) + ' more)' : ''), 'error');
          return;
        }
        OGC.setCampaign(r.campaign, { source: 'import' });
        setLibMsg('Imported "' + ((r.campaign.meta || {}).name || file.name) + '". It is open but not saved to the library yet.', 'ok');
      }).catch(function (e) { setLibMsg('Not imported: ' + msg(e), 'error'); });
    };
    fr.readAsText(file);
  }

  function setLibMsg(t, kind) {
    if (!ui.libMsg) return;
    ui.libMsg.textContent = t || ''; ui.libMsg.className = 'ogcl-note ' + (kind === 'ok' ? 'ogcl-ok' : kind === 'error' ? 'ogcl-bad' : '');
  }

  function renderLibrary() {
    var box = ui.lib; if (!box) return;
    var keep = ui.libMsg ? ui.libMsg.textContent : '', keepCls = ui.libMsg ? ui.libMsg.className : '';
    box.textContent = '';
    var file = h('input', { type: 'file', accept: '.json,application/json', hidden: true, 'aria-label': 'Campaign file to import' });
    file.addEventListener('change', function () { importFile(file.files && file.files[0]); file.value = ''; });
    var importBtn = h('button', { type: 'button', class: 'ogcl-btn', id: 'ogcl-import', text: 'Import file...', onclick: function () { file.click(); } });
    box.appendChild(h('h4', { text: '3. Saved campaigns' }));
    box.appendChild(h('div', { class: 'ogcl-row' }, importBtn, file,
      h('button', { type: 'button', class: 'ogcl-btn', text: 'Refresh', onclick: loadLibrary }),
      S.libDir ? h('span', { class: 'ogcl-note ogcl-mono', text: S.libDir }) : null));
    ui.libMsg = h('div', { class: keepCls || 'ogcl-note', 'aria-live': 'polite', text: keep });
    box.appendChild(ui.libMsg);
    if (S.libError) { box.appendChild(h('p', { class: 'ogcl-bad', text: 'The library could not be read: ' + S.libError })); return; }
    if (S.library == null) { box.appendChild(h('p', { class: 'ogcl-note', text: 'Loading...' })); return; }
    if (!S.library.length) {
      box.appendChild(h('p', { class: 'ogcl-note', text: 'No saved campaigns yet. Save the current campaign above, or import a campaign file.' }));
      return;
    }
    var cols = [{ k: 'name', label: 'Name' }, { k: 'stages', label: 'Stages', num: true }, { k: 'iocs', label: 'Indicators', num: true },
                { k: 'modified', label: 'Modified' }, { k: 'act', label: 'Actions' }];
    box.appendChild(table(cols, S.library, function (r, c) {
      if (c.k === 'name') return h('span', null, h('b', { text: r.name || r.id }), r.description ? h('div', { class: 'ogcl-note', text: r.description }) : null);
      if (c.k === 'stages') return String(r.stages == null ? '' : r.stages);
      if (c.k === 'iocs') return String(r.iocs == null ? '' : r.iocs);
      if (c.k === 'modified') return relativeTime(r.modified);
      var nm = r.name || r.id;
      return h('span', { class: 'ogcl-row' },
        h('button', { type: 'button', class: 'ogcl-btn', 'aria-label': 'Open ' + nm, text: 'Open', onclick: function () { openSaved(r.id); } }),
        h('button', { type: 'button', class: 'ogcl-btn', 'aria-label': 'Duplicate ' + nm, text: 'Duplicate', onclick: function () { duplicate(r.id); } }),
        h('a', { class: 'ogcl-btn', href: '/campaign/export?id=' + encodeURIComponent(r.id), 'aria-label': 'Export ' + nm, text: 'Export' }),
        h('button', { type: 'button', class: 'ogcl-btn', 'aria-label': 'Delete ' + nm, text: 'Delete', onclick: function () { remove(r); } }));
    }));
  }

  /* ---- run panel */

  function setMode(want) {
    if (want === 'mapped') { S.mode = 'mapped'; S.confirmed = false; renderRun(); updateBadge(); return; }
    dialog({
      title: 'Use real indicator addresses?',
      body: ['Real mode writes the actual indicator IP addresses into the capture instead of re-addressing them into 198.18.0.0/15.',
             'If that capture is replayed on a routed network, packets can reach real hosts on the internet. Only choose this for an isolated lab with no route out.',
             'Type REAL to confirm.'],
      expect: 'REAL', confirmText: 'Use real addresses'
    }).then(function (yes) {
      S.mode = yes ? 'real' : 'mapped'; S.confirmed = !!yes;
      renderRun(); updateBadge();
    });
  }

  function mainSettings() {
    var get = function (id) { var e = document.getElementById(id); return e ? e.value : ''; };
    var parts = [], s = get('scale'), co = get('company');
    if (s) parts.push('scale ' + s);
    if (co) parts.push('company ' + co);
    return parts;
  }

  function renderRun() {
    var box = ui.run; if (!box) return;
    box.textContent = '';
    box.appendChild(h('h4', { text: '4. Run it' }));
    var grp = h('div', { role: 'radiogroup', 'aria-label': 'Address mode' });
    [['mapped', 'Mapped (default, safe)'], ['real', 'Real addresses']].forEach(function (o) {
      var id = 'ogcl-mode-' + o[0];
      var r = h('input', { type: 'radio', name: 'ogcl-mode', id: id, value: o[0], onchange: function () { setMode(o[0]); } });
      r.checked = S.mode === o[0];
      grp.appendChild(h('div', { class: 'ogcl-row' }, r, h('label', { for: id, text: o[1] })));
    });
    box.appendChild(grp);
    box.appendChild(h('p', { class: 'ogcl-note', text: 'Mapped mode re-addresses every indicator IP into 198.18.0.0/15, a range reserved for network benchmarking that is not routed on the internet. The sensor still sees the same behaviour, and a replay cannot reach the real indicator hosts.' }));
    if (S.mode === 'real') box.appendChild(h('div', { class: 'ogcl-warn', role: 'note', text: 'Real addresses are on. Replaying the capture on a routed network can send packets to real hosts. Use an isolated lab only.' }));

    var tg = h('input', { type: 'checkbox', id: 'ogcl-arm', onchange: function () { S.armed = this.checked; S.restored = false; renderRun(); updateBadge(); refreshCaptureEstimate(); } });
    tg.checked = S.armed;
    var c = stateCampaign();
    if (!c) tg.disabled = true;
    box.appendChild(h('div', { class: 'ogcl-row' }, tg, h('label', { for: 'ogcl-arm', text: 'Use this campaign in the next capture' })));
    if (S.armed && c) {
      var bad = S.check && S.check.errors && S.check.errors.length;
      box.appendChild(h('div', { class: 'ogcl-warn', role: 'status', 'aria-live': 'polite',
        text: bad ? 'This campaign has problems, so it will not be added until they are fixed (see Check).' : armedText() + '. Press Generate on the main page.' }));
    }
    var ms = mainSettings();
    box.appendChild(h('p', { class: 'ogcl-note', text: 'The capture still uses the main page settings for scale, company, networks and scenarios' + (ms.length ? ' (now: ' + ms.join(', ') + ')' : '') + '. The campaign is added on top of the scenarios you selected.' }));
  }

  // --- Board preview: the campaign's world map / clock / order, built from the engine with no
  //     replay and no generated capture. POST /api/campaign/run returns the real records; the
  //     board module renders them. Toggles in place under the Name-and-save card.
  var _boardCtl = null;
  function previewBoard(btn) {
    if (_boardCtl) { try { _boardCtl.destroy(); } catch (e) {} _boardCtl = null; ui.board.textContent = ''; btn.textContent = 'Preview board'; return; }
    if (!OGC.board || !OGC.board.render) { toast('The board module is not available.', 'error'); return; }
    var c = currentCampaign();
    if (!c) { toast('Build or load a campaign first.', 'error'); return; }
    var scEl = document.getElementById('scale');
    var sc = (scEl && parseFloat(scEl.value)) || 1;
    var old = btn.textContent; btn.disabled = true; btn.textContent = 'Building…';
    OGC.api.post('/api/campaign/run', { campaign: c, scale: sc }).then(function (res) {
      btn.disabled = false;
      var run = res && res.run;
      if (!run || !(run.entries || []).length) { btn.textContent = old; toast('The campaign produced no traffic to map.', 'error'); return; }
      ui.board.textContent = '';
      // The board reads indicators from summary.iocs and records from summary.entries. /api/campaign/run
      // returns the whole report {campaigns:[...], entries:[...]}; the per-campaign object carries all
      // three (iocs, entries, stages) — the shape the board expects (same as the post-generate flow).
      var summary = (run.campaigns && run.campaigns[0]) || run;
      try { _boardCtl = OGC.board.render(ui.board, summary, c, null); btn.textContent = 'Hide board'; }
      catch (e) { btn.textContent = old; ui.board.textContent = 'The board could not be drawn.'; }
    }, function (err) { btn.disabled = false; btn.textContent = old; toast((err && err.message) || 'The board could not be built.', 'error'); });
  }

  // --- Capture-size estimate: when a campaign is armed for the next capture, measure its exact
  //     traffic once (engine, campaign-only) and stash it on OGC.state.captureEst so the main-page
  //     estimate (estLabel) adds it. Cleared when disarmed, invalid, or absent.
  function refreshCaptureEstimate() {
    if (!OGC.state) return;
    var c = S.armed ? stateCampaign() : null;
    var bad = S.check && S.check.errors && S.check.errors.length;
    if (!c || bad) { OGC.state.captureEst = null; if (window.ogEstRefresh) window.ogEstRefresh(); return; }
    OGC.api.post('/api/campaign/run', { campaign: c, scale: 1 }).then(function (res) {
      OGC.state.captureEst = res ? { packets: res.packets || 0, bytes: res.bytes || 0 } : null;
      if (window.ogEstRefresh) window.ogEstRefresh();
    }, function () { /* leave the estimate unchanged on failure */ });
  }

  /* ---- step wiring */

  function mount(container) {
    injectStyle();
    container.textContent = '';
    ui.check = h('div', { class: 'ogcl-panel' });
    ui.name = h('input', { type: 'text', id: 'ogcl-name', maxlength: '120', 'aria-label': 'Campaign name', onchange: function () { scheduleCheck(); updateBadge(); } });
    ui.desc = h('textarea', { id: 'ogcl-desc', maxlength: '1000', 'aria-label': 'Campaign description', onchange: scheduleCheck });
    ui.msg = h('div', { class: 'ogcl-note', 'aria-live': 'polite' });
    ui.board = h('div', { class: 'ogcl-board', id: 'ogcl-boardhost' });
    var save = h('div', { class: 'ogcl-panel' },
      h('h4', { text: '2. Name and save' }),
      h('div', { class: 'ogcl-row' }, h('label', { for: 'ogcl-name', text: 'Name' }), ui.name),
      h('div', null, h('label', { for: 'ogcl-desc', text: 'Description' }), ui.desc),
      h('div', { class: 'ogcl-row' },
        h('button', { type: 'button', class: 'ogcl-btn', id: 'ogcl-save', text: 'Save to library', onclick: saveToLibrary }),
        h('button', { type: 'button', class: 'ogcl-btn', id: 'ogcl-download', text: 'Download JSON', onclick: downloadJson }),
        h('button', { type: 'button', class: 'ogcl-btn', id: 'ogcl-diagram', text: 'Preview diagram', title: 'A plan-mode picture of this campaign, before anything is generated', onclick: function (ev) { var c = currentCampaign(); if (c) openDiagram(c, null, ev.currentTarget); } }),
        h('button', { type: 'button', class: 'ogcl-btn', id: 'ogcl-board', text: 'Preview board', title: 'A world map, clock and the order the campaign reaches each indicator — built from the campaign, no replay', onclick: function (ev) { previewBoard(ev.currentTarget); } })),
      ui.msg, ui.board);
    ui.lib = h('div', { class: 'ogcl-panel', id: 'ogcl-library' });
    ui.run = h('div', { class: 'ogcl-panel' });
    container.appendChild(h('div', { class: 'ogcl' }, ui.check, save, ui.lib, ui.run));
    S.mounted = true;
    syncFields(); renderCheck(); renderLibrary(); renderRun();
  }

  function wantsOpen() {
    var st = OGC.state || {};
    return st.intent === 'open' || st.startIntent === 'open' || st.type === 'open' || st.mode === 'open';
  }

  function onEnter() {
    if (!S.mounted) return;
    syncFields(); renderCheck(); renderRun(); runCheck(); loadLibrary().then(function () {
      if (wantsOpen() && ui.lib) {
        try { ui.lib.scrollIntoView({ block: 'start' }); } catch (e) { /* ignore */ }
        var b = ui.lib.querySelector('button, a'); if (b) b.focus();
      }
    });
  }

  /* ------------------------------------------------------------------ results */

  function textBlock(tag, text, cls) { return h(tag, { class: cls || null, text: text }); }

  function panel(title) { return h('section', { class: 'ogcl-panel' }, h('h4', { text: title })); }

  // Campaign diagram: POST the campaign (plus the run summary and the sensor score when there are any) and open
  // the returned static page in a new tab from a Blob URL. Plan mode when no summary is passed.
  function openDiagram(campaign, summaryCampaign, btn) {
    var body = { campaign: campaign };
    if (summaryCampaign) body.summary = summaryCampaign;
    if (summaryCampaign && OGC.state && OGC.state.lastScore) body.score = OGC.state.lastScore;
    var co = document.getElementById('company');
    if (co && co.value && co.value.trim()) body.company = co.value.trim().slice(0, 80);
    if (btn) { btn.disabled = true; }
    // lint-ok: the blank window must stay scriptable until the diagram is ready, so the handle is kept and its opener is cleared at once
    var win = window.open('', '_blank');
    if (win) { win.opener = null; }
    return OGC.api.post('/api/campaign/diagram', body).then(function (res) {
      if (btn) btn.disabled = false;
      if (!res || !res.html) { if (win) win.close(); toast('The diagram could not be made.', 'error'); return; }
      var themed = window.ogThemeHtml ? window.ogThemeHtml(res.html) : Promise.resolve(res.html);
      return themed.then(function (html) {
        var url = URL.createObjectURL(new Blob([html], { type: 'text/html' }));
        if (win) { win.location.href = url; } else { window.open(url, '_blank', 'noopener'); }
      });
    }, function (err) {
      if (btn) btn.disabled = false;
      if (win) win.close();
      toast((err && err.message) || 'The diagram could not be made.', 'error');
    });
  }

  function renderResults(summary, container) {
    injectStyle();
    if (!container || !summary || !summary.campaign) return;
    var old = container.querySelector('.ogcl-results'); if (old) old.parentNode.removeChild(old);
    var wrap = h('div', { class: 'ogcl-results', 'aria-label': 'Campaign results' });
    var camp = summary.campaign, campaign = stateCampaign();

    var p1 = panel('Campaign result');
    p1.appendChild(h('p', { class: camp.error ? 'ogcl-bad' : 'ogcl-ok', text: headline(summary) }));
    errorList(summary).forEach(function (e) { p1.appendChild(h('p', { class: 'ogcl-note', text: 'Note: ' + e })); });
    wrap.appendChild(p1);

    var lines = Array.isArray(summary.campaign_console) ? summary.campaign_console.map(String) : [];
    if (lines.length) {
      var p2 = panel('Console');
      var pre = h('pre', { class: 'ogcl-console ogcl-mono', tabindex: '0', 'aria-label': 'Campaign console output' });
      pre.textContent = lines.join('\n');
      p2.appendChild(h('div', { class: 'ogcl-row' }, h('button', { type: 'button', class: 'ogcl-btn', text: 'Copy', onclick: function () { copyText(lines.join('\n'), 'Console copied'); } })));
      p2.appendChild(pre);
      wrap.appendChild(p2);
    }

    var rows = actionRows(summary);
    if (rows.length) {
      var p3 = panel('Stages and actions');
      p3.appendChild(table([{ k: 'stage', label: 'Stage' }, { k: 'action', label: 'Action' }, { k: 'route', label: 'From to' },
        { k: 'packets', label: 'Packets', num: true }, { k: 'protocols', label: 'Protocols' }, { k: 'status', label: 'Result' }], rows, function (r, c) {
        if (c.k === 'route') return (r.from || '?') + ' to ' + (r.to || '?');
        if (c.k === 'packets') return num(r.packets);
        if (c.k === 'protocols') return r.protocols.join(', ');
        if (c.k === 'status') return h('span', { class: 'ogcl-tag' }, r.status === 'ok' ? 'ok' : (r.status === 'failed' ? 'failed' : r.status === 'skipped' ? 'not run' : r.status), r.error ? ': ' + r.error : '');
        return r[c.k];
      }));
      wrap.appendChild(p3);
    }

    var irows = iocRows(summary, campaign);
    var p4 = panel('Indicators in the capture');
    if (irows.length) {
      p4.appendChild(table([{ k: 'indicator', label: 'Indicator' }, { k: 'role', label: 'Role' }, { k: 'address', label: 'On the wire as' },
        { k: 'stage', label: 'Stage' }, { k: 'action', label: 'Action' }, { k: 'packets', label: 'Packets', num: true }], irows, function (r, c) {
        return c.k === 'packets' ? num(r.packets) : r[c.k];
      }));
    } else {
      p4.appendChild(h('p', { class: 'ogcl-note', text: Array.isArray(camp.entries) ? 'No address, domain or URL indicator was placed in the capture. Hashes, file names and CVE ids are kept for traceability only.' : 'The per-indicator table is not available for this build. The report file listed below has it.' }));
    }
    wrap.appendChild(p4);

    var cov = coverage(summary, campaign);
    if (cov.rows.length) {
      var p5 = panel('Technique coverage against the expected list');
      p5.appendChild(h('p', { class: 'ogcl-note', text: cov.known ? (cov.covered + ' covered, ' + cov.missing + ' missing.') : 'Coverage cannot be computed because the build summary has no per-action records.' }));
      p5.appendChild(table([{ k: 'technique', label: 'Technique' }, { k: 'stage', label: 'Stage' }, { k: 'state', label: 'Coverage' }], cov.rows, function (r, c) {
        if (c.k === 'state') return h('span', { class: 'ogcl-tag', text: r.state === 'covered' ? 'covered' : r.state === 'missing' ? 'missing' : 'unknown' });
        return r[c.k];
      }));
      wrap.appendChild(p5);
    }

    var files = exportList(summary);
    if (files.length) {
      var p6 = panel('Files written');
      p6.appendChild(h('p', { class: 'ogcl-note', text: 'These were written next to the capture on this computer.' }));
      files.forEach(function (f) {
        p6.appendChild(h('div', { class: 'ogcl-row' }, h('span', { text: f.kind + ': ' }),
          h('span', { class: 'ogcl-mono', text: f.path }),
          h('button', { type: 'button', class: 'ogcl-btn', 'aria-label': 'Copy path of ' + f.kind, text: 'Copy path', onclick: function () { copyText(f.path, 'Path copied'); } })));
      });
      wrap.appendChild(p6);
    }
    if (campaign && Array.isArray(camp.entries) && camp.entries.length) {
      var dp = panel('Campaign diagram');
      dp.appendChild(h('p', { class: 'ogcl-note', text: 'A picture of what this capture contains: timeline, flows, indicators, techniques and capture filters. Opens in a new tab.' }));
      dp.appendChild(h('div', { class: 'ogcl-row' }, h('button', { type: 'button', class: 'ogcl-btn', text: 'Open the campaign diagram', onclick: function (ev) { openDiagram(campaign, camp, ev.currentTarget); } })));
      wrap.appendChild(dp);
    }
    var sensorBox = h('div', { class: 'ogcl-panel ogcl-sensor' });
    wrap.appendChild(sensorBox);
    if (OGC.sensor && OGC.sensor.render) { try { OGC.sensor.render(sensorBox, camp, campaign); } catch (e) { sensorBox.appendChild(h('p', { class: 'ogcl-note', text: 'The sensor panel could not be drawn.' })); } }

    if (OGC.board && OGC.board.render && Array.isArray(camp.entries) && camp.entries.length) {
      var boardPanel = panel('Campaign board');
      var boardHost = h('div', { class: 'ogcl-board' });
      var boardCtl = null;
      var boardBtn = h('button', { type: 'button', class: 'ogcl-btn', text: 'Show the board', onclick: function () {
        if (boardCtl) { boardCtl.destroy(); boardCtl = null; boardHost.textContent = ''; boardBtn.textContent = 'Show the board'; return; }
        try { boardCtl = OGC.board.render(boardHost, camp, campaign, null); boardBtn.textContent = 'Hide the board'; }
        catch (e) { boardHost.textContent = 'The board could not be drawn.'; }
      } });
      boardPanel.appendChild(h('p', { class: 'ogcl-note', text: 'A map, a clock and the order the campaign reaches each indicator. It uses only this capture\'s records.' }));
      boardPanel.appendChild(h('div', { class: 'ogcl-row' }, boardBtn));
      boardPanel.appendChild(boardHost);
      wrap.appendChild(boardPanel);
    }
    container.appendChild(wrap);
  }

  OGC.renderResults = renderResults;
  OGC._test.dialogLogic = { realConfirmed: realConfirmed };

  function register() {
    if (OGC.registerStep) {
      OGC.registerStep({ id: 'save', title: 'Save & run', mount: mount, onEnter: onEnter,
        canLeave: function () { return true; } });
    }
    if (OGC.on) {
      OGC.on('campaign', function () {
        var r = armedAfterCampaign(S.armed, S.restored, !!stateCampaign());
        if (S.armed && !r.armed) { S.armed = false; var tg = document.getElementById('ogcl-arm'); if (tg) tg.checked = false; try { renderRun(); } catch (e) { /* step not drawn */ } refreshCaptureEstimate(); }
        S.restored = r.restored;
        if (S.mounted) { syncFields(); renderCheck(); scheduleCheck(); } updateBadge(); });
    }
  }
  register();
})();
