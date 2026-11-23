/* OpenGenerator Campaign Builder, step 3 "Build": the campaign editor.
 *
 * Edits a campaign file v1 (see docs/campaign-m1-contracts.md) in the browser. The campaign describes network
 * behaviour for testing a sensor with valid, replayable captures; nothing here builds or runs attack tooling.
 * Vanilla ES2019, strict mode, one IIFE attaching to window.OGC. All data reaches the page through textContent
 * or attribute values (never innerHTML). Pure logic is exported under OGC._test.editor for node tests.
 */
(function () {
  'use strict';

  var root = (typeof window !== 'undefined') ? window : this;

  /* ------------------------------------------------------------------ pure logic */

  var INTERNAL_ROLES = ['ws', 'ws2', 'server', 'dc', 'file', 'sql', 'web', 'fw', 'any_ws'];
  var EXTERNAL_PLAIN = ['attacker'];
  var EXTERNAL_INDEXED = ['c2', 'exfil', 'payload', 'scanner', 'phish', 'tor', 'brute', 'ioc'];
  var ROLE_LABEL = {
    ws: 'Workstation (compromised)', ws2: 'Second workstation', server: 'Application or file server',
    dc: 'Domain controller', file: 'File server', sql: 'Database server', web: 'Web server', fw: 'Firewall',
    any_ws: 'Any workstation', host: 'Named host (suffix)', attacker: 'Attacker',
    c2: 'C2 indicator', exfil: 'Exfil indicator', payload: 'Payload indicator', scanner: 'Scanner indicator',
    phish: 'Phishing indicator', tor: 'Tor indicator', brute: 'Brute-force indicator', ioc: 'Any indicator (by number)'
  };
  var TECH_RE = /^T\d{4}(\.\d{3})?$/;
  var MAX_SECONDS = 86400;

  function clone(o) { return o === undefined ? undefined : JSON.parse(JSON.stringify(o)); }
  function isObj(o) { return o !== null && typeof o === 'object' && !Array.isArray(o); }
  function clamp(v, lo, hi) { return Math.min(hi, Math.max(lo, v)); }

  /* Parse a number typed by a person; returns null when it is not a finite number. */
  function parseNum(raw) {
    if (typeof raw === 'number') return isFinite(raw) ? raw : null;
    var s = String(raw === undefined || raw === null ? '' : raw).trim();
    if (s === '' || !/^[-+]?(\d+\.?\d*|\.\d+)([eE][-+]?\d+)?$/.test(s)) return null;
    var n = Number(s);
    return isFinite(n) ? n : null;
  }

  /* Clamp seconds into 0..86400 (min 1 for durations); invalid text gives the fallback. */
  function clampSeconds(raw, min, fallback) {
    var n = parseNum(raw);
    if (n === null) return fallback;
    return Math.round(clamp(n, min, MAX_SECONDS) * 100) / 100;
  }

  /* ---- ids ---- */
  function nextStageId(stages) {
    var used = {}, max = 0;
    (stages || []).forEach(function (s) {
      if (s && typeof s.id === 'string') {
        used[s.id] = true;
        var m = /^s(\d+)$/.exec(s.id);
        if (m) max = Math.max(max, parseInt(m[1], 10));
      }
    });
    var n = max + 1;
    while (used['s' + n]) n++;
    return 's' + n;
  }

  /* ---- campaign construction and mutation (all operate in place on an already cloned campaign) ---- */
  function blankCampaign(name) {
    return {
      schema: 'opengenerator.campaign/1',
      meta: { name: name || 'New campaign', id: 'new-campaign', description: '', actor: 'Unattributed',
              origin_country: '', created: '', seed: 1, source: { kind: 'hand', feeds: [], ioc_count: 0 } },
      options: { address_mode: 'mapped', start: '10:00', speed: 'realistic', compromised: 'ws',
                 lateral_target: 'server', beacons_per_c2: 4, include: [] },
      iocs: [],
      stages: [],
      expect: []
    };
  }

  function tacticName(tactics, slug) {
    for (var i = 0; i < (tactics || []).length; i++) if (tactics[i].slug === slug) return tactics[i].name;
    return slug || '';
  }

  function newStage(c, tactic, tactics) {
    return { id: nextStageId(c.stages), name: tacticName(tactics, tactic) || 'New stage', tactic: tactic || '',
             techniques: [], narrative: '', duration_s: 60, fast_s: 20, actions: [] };
  }

  function addStage(c, tactic, tactics) {
    c.stages = c.stages || [];
    var st = newStage(c, tactic, tactics);
    c.stages.push(st);
    return c.stages.length - 1;
  }

  /* Move arr[i] by delta (-1 up, +1 down); returns the new index or -1 when it cannot move. */
  function moveItem(arr, i, delta) {
    var j = i + delta;
    if (!Array.isArray(arr) || i < 0 || i >= arr.length || j < 0 || j >= arr.length) return -1;
    var t = arr[i]; arr[i] = arr[j]; arr[j] = t;
    return j;
  }

  function duplicateStage(c, si) {
    var src = c.stages[si];
    if (!src) return -1;
    var cp = clone(src);
    cp.id = nextStageId(c.stages);
    cp.name = String(src.name || 'Stage') + ' (copy)';
    c.stages.splice(si + 1, 0, cp);
    return si + 1;
  }

  function removeStage(c, si) {
    var st = c.stages[si];
    if (!st) return false;
    c.stages.splice(si, 1);
    if (Array.isArray(c.expect)) c.expect = c.expect.filter(function (e) { return !(e && e.stage === st.id); });
    return true;
  }

  function addAction(c, si, action) {
    var st = c.stages[si];
    if (!st) return -1;
    st.actions = st.actions || [];
    st.actions.push(action);
    return st.actions.length - 1;
  }

  function duplicateAction(c, si, ai) {
    var st = c.stages[si];
    if (!st || !st.actions[ai]) return -1;
    st.actions.splice(ai + 1, 0, clone(st.actions[ai]));
    return ai + 1;
  }

  function removeAction(c, si, ai) {
    var st = c.stages[si];
    if (!st || !st.actions[ai]) return false;
    st.actions.splice(ai, 1);
    return true;
  }

  function moveAction(c, si, ai, ti) {
    var from = c.stages[si], to = c.stages[ti];
    if (!from || !to || si === ti || !from.actions[ai]) return false;
    to.actions = to.actions || [];
    to.actions.push(from.actions.splice(ai, 1)[0]);
    return true;
  }

  function addTechnique(st, id) {
    id = String(id || '').trim().toUpperCase();
    if (!id) return false;
    st.techniques = st.techniques || [];
    if (st.techniques.indexOf(id) >= 0) return false;
    st.techniques.push(id);
    return true;
  }

  function removeTechnique(st, id) {
    var i = (st.techniques || []).indexOf(id);
    if (i < 0) return false;
    st.techniques.splice(i, 1);
    return true;
  }

  function validTechniqueId(id) { return TECH_RE.test(String(id || '')); }

  function totalActions(c) {
    var n = 0;
    ((c && c.stages) || []).forEach(function (s) { n += ((s && s.actions) || []).length; });
    return n;
  }

  /* ---- endpoint references ---- */
  function parseRef(s) {
    var out = { valid: false, raw: s, base: '', scope: null, index: null, suffix: '' };
    if (typeof s !== 'string' || !s) return out;
    if (INTERNAL_ROLES.indexOf(s) >= 0) { out.valid = true; out.base = s; out.scope = 'internal'; return out; }
    if (EXTERNAL_PLAIN.indexOf(s) >= 0) { out.valid = true; out.base = s; out.scope = 'external'; return out; }
    var m = /^([a-z0-9_]+):(.+)$/.exec(s);
    if (!m) return out;
    if (m[1] === 'host' && /^[A-Za-z0-9_.-]{1,40}$/.test(m[2])) {
      out.valid = true; out.base = 'host'; out.scope = 'internal'; out.suffix = m[2]; return out;
    }
    if (EXTERNAL_INDEXED.indexOf(m[1]) >= 0 && /^\d{1,4}$/.test(m[2])) {
      out.valid = true; out.base = m[1]; out.scope = 'external'; out.index = parseInt(m[2], 10); return out;
    }
    return out;
  }

  function formatRef(base, extra) {
    if (base === 'host') return 'host:' + String(extra || '').trim();
    if (EXTERNAL_INDEXED.indexOf(base) >= 0) {
      var n = parseNum(extra);
      return base + ':' + (n === null ? 0 : Math.max(0, Math.floor(n)));
    }
    return base;
  }

  /* Choices for an endpoint picker: kind is 'internal' | 'external' | 'any'. param: none | index | suffix. */
  function refChoices(kind) {
    var out = [];
    function add(base, param, scope) { out.push({ base: base, label: ROLE_LABEL[base] || base, param: param, scope: scope }); }
    if (kind !== 'external') {
      INTERNAL_ROLES.forEach(function (r) { add(r, 'none', 'internal'); });
      add('host', 'suffix', 'internal');
    }
    if (kind !== 'internal') {
      EXTERNAL_PLAIN.forEach(function (r) { add(r, 'none', 'external'); });
      EXTERNAL_INDEXED.forEach(function (r) { add(r, 'index', 'external'); });
    }
    return out;
  }

  function refMatches(kind, ref) {
    var p = parseRef(ref);
    if (!p.valid) return false;
    return kind === 'any' || !kind || p.scope === kind;
  }

  /* A sensible endpoint for a new action: side is 'from' or 'to'. */
  function defaultEndpoint(kind, side, options) {
    options = options || {};
    if (kind === 'external') return 'attacker';
    if (side === 'from') {
      var comp = options.compromised;
      if (kind === 'any') return refMatches('any', comp) ? comp : 'ws';
      return refMatches('internal', comp) ? comp : 'ws';
    }
    if (kind === 'any') return 'attacker';
    var lt = options.lateral_target;
    if (typeof lt === 'string' && lt) {
      if (INTERNAL_ROLES.indexOf(lt) >= 0) return lt;
      if (/^[A-Za-z0-9_.-]{1,40}$/.test(lt)) return 'host:' + lt;
    }
    return 'server';
  }

  function newActionFor(spec, options) {
    return { action: spec.token, from: defaultEndpoint(spec.src || 'any', 'from', options),
             to: defaultEndpoint(spec.dst || 'any', 'to', options), params: {}, explain: '' };
  }

  /* ---- params ---- */
  function paramDefault(def) { return def ? def.default : undefined; }

  function paramToText(def, value) {
    if (value === undefined || value === null) value = paramDefault(def);
    if (Array.isArray(value)) return value.join(', ');
    if (value === undefined || value === null) return '';
    return String(value);
  }

  /* Coerce raw input against a spec param {type, default, help}. Returns {ok, value, reset, error}. */
  function coerceParam(def, raw) {
    var type = (def && def.type) || 'str';
    var dflt = def ? def.default : undefined;
    var minZero = !(typeof dflt === 'number' && dflt < 0);
    if (type === 'bool') return { ok: true, value: !!raw };
    var s = typeof raw === 'string' ? raw.trim() : raw;
    if (type === 'int' || type === 'float') {
      if (s === '' || s === null || s === undefined) return { ok: true, reset: true };
      var n = parseNum(s);
      if (n === null) return { ok: false, error: 'Enter a number.' };
      if (type === 'int' && Math.floor(n) !== n) return { ok: false, error: 'Enter a whole number.' };
      if (minZero && n < 0) return { ok: false, error: 'Must be 0 or more.' };
      if (Math.abs(n) > 1e9) return { ok: false, error: 'Too large (limit 1,000,000,000).' };
      return { ok: true, value: n };
    }
    if (type === 'list') {
      if (s === '' || s === null || s === undefined) return { ok: true, reset: true };
      var items = String(s).split(',').map(function (x) { return x.trim(); }).filter(function (x) { return x !== ''; });
      if (items.length > 100) return { ok: false, error: 'At most 100 items.' };
      if (Array.isArray(dflt) && dflt.length && typeof dflt[0] === 'number') {
        var nums = items.map(parseNum);
        if (nums.some(function (x) { return x === null; })) return { ok: false, error: 'All items must be numbers.' };
        return { ok: true, value: nums };
      }
      return { ok: true, value: items };
    }
    // str
    if (s === '' || s === null || s === undefined) return { ok: true, reset: true };
    if (String(s).length > 500) return { ok: false, error: 'At most 500 characters.' };
    // eslint-disable-next-line no-control-regex
    if (/[\u0000-\u001f]/.test(String(s))) return { ok: false, error: 'No control characters.' };
    return { ok: true, value: String(s) };
  }

  /* ---- catalog ---- */
  function normCatalog(x) {
    if (Array.isArray(x)) return { actions: x, tactics: [] };
    if (isObj(x)) return { actions: Array.isArray(x.actions) ? x.actions : [], tactics: Array.isArray(x.tactics) ? x.tactics : [] };
    return { actions: [], tactics: [] };
  }

  function specByToken(actions, token) {
    for (var i = 0; i < (actions || []).length; i++) if (actions[i].token === token) return actions[i];
    return null;
  }

  /* Filter and group the catalog for the picker; the preferred tactic (the stage's) comes first. */
  function pickerGroups(actions, tactics, query, preferTactic) {
    var q = String(query || '').trim().toLowerCase();
    var list = (actions || []).filter(function (a) {
      if (!q) return true;
      var hay = [a.token, a.title, a.summary, a.tactic].concat(a.protocols || [], a.techniques || []).join(' ').toLowerCase();
      return q.split(/\s+/).every(function (w) { return hay.indexOf(w) >= 0; });
    });
    var order = (tactics || []).map(function (t) { return t.slug; });
    var groups = {}, keys = [];
    list.forEach(function (a) {
      var k = a.tactic || 'other';
      if (!groups[k]) { groups[k] = []; keys.push(k); }
      groups[k].push(a);
    });
    keys.sort(function (a, b) {
      if (a === preferTactic) return -1;
      if (b === preferTactic) return 1;
      var ia = order.indexOf(a), ib = order.indexOf(b);
      return (ia < 0 ? 999 : ia) - (ib < 0 ? 999 : ib) || (a < b ? -1 : 1);
    });
    return keys.map(function (k) {
      return { tactic: k, name: tacticName(tactics, k), actions: groups[k].slice().sort(function (a, b) { return (a.title || a.token) < (b.title || b.token) ? -1 : 1; }) };
    });
  }

  /* ---- timeline ---- */
  function parseStart(s) {
    var m = /^(\d{1,2}):(\d{2})$/.exec(String(s || ''));
    if (!m) return 10 * 3600;
    var h = parseInt(m[1], 10), mi = parseInt(m[2], 10);
    if (h > 23 || mi > 59) return 10 * 3600;
    return h * 3600 + mi * 60;
  }

  function fmtClock(sec) {
    sec = Math.round(sec) % MAX_SECONDS;
    var h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
    function p(n) { return n < 10 ? '0' + n : String(n); }
    return p(h) + ':' + p(m) + (s ? ':' + p(s) : '');
  }

  function fmtDuration(sec) {
    sec = Math.round(Number(sec) || 0);
    if (sec < 60) return sec + ' s';
    if (sec < 3600) { var m = Math.floor(sec / 60), s = sec % 60; return m + ' min' + (s ? ' ' + s + ' s' : ''); }
    var h = Math.floor(sec / 3600), mm = Math.round((sec % 3600) / 60);
    return h + ' h' + (mm ? ' ' + mm + ' min' : '');
  }

  function stageSeconds(st, speed) {
    var d = speed === 'fast' && st.fast_s > 0 ? st.fast_s : st.duration_s;
    return d > 0 ? d : 60;
  }

  /* Stages laid out one after another from options.start. */
  function timeline(c) {
    var opts = (c && c.options) || {};
    var speed = opts.speed === 'fast' ? 'fast' : 'realistic';
    var t0 = parseStart(opts.start);
    var cursor = 0, segs = [];
    ((c && c.stages) || []).forEach(function (st, i) {
      var d = stageSeconds(st || {}, speed);
      segs.push({ index: i, id: st.id, name: st.name || st.id || ('Stage ' + (i + 1)), tactic: st.tactic || '',
                  offset_s: cursor, dur_s: d, start_clock: fmtClock(t0 + cursor), end_clock: fmtClock(t0 + cursor + d) });
      cursor += d;
    });
    var total = cursor;
    segs.forEach(function (s) {
      s.left_pct = total ? s.offset_s / total * 100 : 0;
      s.width_pct = total ? s.dur_s / total * 100 : 0;
    });
    return { start_s: t0, total_s: total, speed: speed, segments: segs, start_clock: fmtClock(t0), end_clock: fmtClock(t0 + total) };
  }

  /* ---- ATT&CK coverage ---- */
  function tacticCoverage(c, tactics, actionCatalog) {
    var map = {};
    function note(slug, tech) {
      if (!slug) return;
      if (!map[slug]) map[slug] = [];
      if (tech && map[slug].indexOf(tech) < 0) map[slug].push(tech);
    }
    ((c && c.stages) || []).forEach(function (st) {
      note(st.tactic);
      (st.techniques || []).forEach(function (t) { note(st.tactic, t); });
      (st.actions || []).forEach(function (a) {
        var sp = specByToken(actionCatalog, a && a.action);
        if (sp && sp.tactic) { note(sp.tactic); (sp.techniques || []).forEach(function (t) { note(sp.tactic, t); }); }
      });
    });
    return (tactics || []).map(function (t) {
      var techs = map[t.slug] ? map[t.slug].slice().sort() : [];
      return { slug: t.slug, name: t.name, id: t.id, covered: !!map[t.slug], techniques: techs };
    });
  }

  /* ---- validation messages ---- */
  /* Locate a server message. Conservative: only "stages[i]" / "stages[i].actions[j]" prefixes, or an explicit
     existing stage id after the word "stage". Everything else is general. */
  function parseErrorLocation(msg, c) {
    var text = String(msg === undefined || msg === null ? '' : msg);
    var m = /^\s*stages\[(\d+)\](?:\.actions\[(\d+)\])?/.exec(text);
    if (m) {
      var si = parseInt(m[1], 10), ai = m[2] === undefined ? null : parseInt(m[2], 10);
      var st = c && c.stages ? c.stages[si] : null;
      if (c && !st) return { stage: null, action: null, text: text };
      if (ai !== null && c && !(st.actions && st.actions[ai])) ai = null;
      return { stage: si, action: ai, text: text };
    }
    var m2 = /^\s*stage\s+['"]?([A-Za-z0-9_-]{1,64})['"]?\s*(?::|\b)/i.exec(text);
    if (m2 && c && c.stages) {
      for (var i = 0; i < c.stages.length; i++) if (c.stages[i].id === m2[1]) {
        var m3 = /\baction\s+#?(\d+)\b/i.exec(text);
        var aj = m3 ? parseInt(m3[1], 10) : null;
        if (aj !== null && !(c.stages[i].actions && c.stages[i].actions[aj])) aj = null;
        return { stage: i, action: aj, text: text };
      }
    }
    return { stage: null, action: null, text: text };
  }

  function groupErrors(errors, c) {
    var g = { general: [], stages: {}, actions: {}, count: 0 };
    (errors || []).forEach(function (e) {
      var loc = parseErrorLocation(e, c);
      g.count++;
      if (loc.stage === null) { g.general.push(loc.text); return; }
      if (loc.action === null) { (g.stages[loc.stage] = g.stages[loc.stage] || []).push(loc.text); return; }
      var k = loc.stage + ':' + loc.action;
      (g.actions[k] = g.actions[k] || []).push(loc.text);
    });
    return g;
  }

  function linkedIocs(c, action) {
    var out = [];
    ((action && action.ioc) || []).forEach(function (i) {
      var ioc = c && c.iocs ? c.iocs[i] : null;
      if (ioc) out.push({ index: i, value: String(ioc.value), type: ioc.type, role: ioc.role, why: ioc.why || '' });
    });
    return out;
  }

  function estimateLine(est, c) {
    if (!est) return null;
    function n(v) { return (typeof v === 'number' && isFinite(v)) ? v : null; }
    return { stages: n(est.stages) !== null ? est.stages : ((c && c.stages) || []).length,
             actions: n(est.actions) !== null ? est.actions : totalActions(c),
             flows: n(est.flows), minutes_realistic: n(est.minutes_realistic), minutes_fast: n(est.minutes_fast) };
  }

  var pure = {
    clone: clone, parseNum: parseNum, clampSeconds: clampSeconds, nextStageId: nextStageId,
    blankCampaign: blankCampaign, newStage: newStage, addStage: addStage, moveItem: moveItem,
    duplicateStage: duplicateStage, removeStage: removeStage, addAction: addAction,
    duplicateAction: duplicateAction, removeAction: removeAction, moveAction: moveAction,
    addTechnique: addTechnique, removeTechnique: removeTechnique, validTechniqueId: validTechniqueId,
    totalActions: totalActions, parseRef: parseRef, formatRef: formatRef, refChoices: refChoices,
    refMatches: refMatches, defaultEndpoint: defaultEndpoint, newActionFor: newActionFor,
    paramToText: paramToText, coerceParam: coerceParam, normCatalog: normCatalog, specByToken: specByToken,
    pickerGroups: pickerGroups, parseStart: parseStart, fmtClock: fmtClock, fmtDuration: fmtDuration,
    timeline: timeline, tacticCoverage: tacticCoverage, parseErrorLocation: parseErrorLocation,
    groupErrors: groupErrors, linkedIocs: linkedIocs, estimateLine: estimateLine, tacticName: tacticName
  };

  /* ------------------------------------------------------------------ browser UI */

  /* Editor styles: tokens only (theme.css), scoped under #ogc-card. The glowing buttons are styled in campaigns.css. */
  var CSS = [
    '#ogc-card .oge{font-size:0.875rem;font-family:var(--font-ui);color:var(--ink);}',
    '#ogc-card .oge *{box-sizing:border-box;}',
    '#ogc-card .oge h3,#ogc-card .oge h4{margin:0;}',
    '#ogc-card .oge h3{margin:16px 0 6px;font-size:1rem;font-weight:600;}',
    '#ogc-card .oge input[type=text],#ogc-card .oge input[type=number],#ogc-card .oge select,#ogc-card .oge textarea{font:inherit;font-size:0.8125rem;border:1px solid var(--ln2);border-radius:3px;padding:4px 10px;background:var(--p2);color:var(--ink);min-height:32px;max-width:100%;}',
    '#ogc-card .oge textarea{width:100%;resize:vertical;}',
    '#ogc-card .oge label.oge-f{display:flex;flex-direction:column;gap:4px;font-size:0.8125rem;font-weight:500;color:var(--mu);min-width:0;}',
    '#ogc-card .oge label.oge-f input,#ogc-card .oge label.oge-f select{font-weight:400;color:var(--ink);}',
    '#ogc-card .oge .oge-row{display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end;}',
    '#ogc-card .oge .oge-row > .grow{flex:1 1 180px;}',
    '#ogc-card .oge .oge-hdr{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:0 0 12px;}',
    '#ogc-card .oge .oge-muted{color:var(--mu);font-size:0.8125rem;}',
    '#ogc-card .oge .oge-chip,#ogc-card .oge .ogc-chip.oge-chip{display:inline-flex;align-items:center;gap:4px;height:auto;font-size:0.75rem;font-weight:500;border:1px solid var(--ln2);border-radius:3px;padding:2px 8px;background:var(--p2);color:var(--ink);margin:0 4px 4px 0;}',
    '#ogc-card .oge .oge-chip.bad{border-color:var(--er);color:var(--er);background:color-mix(in srgb,var(--er-fill) 12%,var(--p1));}',
    '#ogc-card .oge .oge-chip.ot{border-color:var(--wr);background:color-mix(in srgb,var(--wr-fill) 14%,var(--p1));color:var(--wr);font-weight:600;}',
    '#ogc-card .oge .oge-chip button{border:0;background:transparent;color:inherit;padding:0 2px;min-height:0;height:auto;font-size:0.875rem;line-height:1;cursor:pointer;}',
    '#ogc-card .oge .oge-card{border:1px solid var(--ln);border-radius:4px;background:var(--p1);margin:0 0 12px;}',
    '#ogc-card .oge .oge-card.has-err{border-color:var(--er);}',
    '#ogc-card .oge .oge-cardhead{display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:10px 12px;background:var(--p2);border-bottom:1px solid var(--ln);border-radius:4px 4px 0 0;}',
    '#ogc-card .oge .oge-cardhead .oge-title{font-weight:600;flex:1 1 160px;min-width:0;}',
    '#ogc-card .oge .oge-cardbody{padding:12px 14px;}',
    '#ogc-card .oge .oge-cardbody[hidden]{display:none;}',
    '#ogc-card .oge .oge-act{border:1px solid var(--ln);border-left:3px solid var(--cy);border-radius:3px;margin:8px 0;background:var(--p1);}',
    '#ogc-card .oge .oge-act.has-err{border-left-color:var(--er);}',
    '#ogc-card .oge .oge-params{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;margin-top:8px;}',
    '#ogc-card .oge .oge-param .oge-help{font-weight:400;font-size:0.75rem;color:var(--mu);}',
    '#ogc-card .oge .oge-err{color:var(--er);font-size:0.8125rem;margin:3px 0;}',
    '#ogc-card .oge .oge-errs{margin:8px 0;padding:8px 12px;border:1px solid color-mix(in srgb,var(--er) 45%,var(--p1));border-left:3px solid var(--er);border-radius:0 3px 3px 0;background:color-mix(in srgb,var(--er-fill) 12%,var(--p1));color:var(--ink);font-size:0.8125rem;}',
    '#ogc-card .oge .oge-errs ul{margin:0;padding-left:18px;}',
    '#ogc-card .oge .oge-status{font-weight:600;font-size:0.8125rem;color:var(--mu);}',
    '#ogc-card .oge .oge-status.ok{color:var(--ok);}',
    '#ogc-card .oge .oge-status.bad{color:var(--er);}',
    '#ogc-card .oge .oge-est{display:flex;flex-wrap:wrap;gap:6px 22px;font-size:0.8125rem;padding:10px 14px;border:1px solid var(--ln);border-radius:4px;background:var(--p1);margin:8px 0;color:var(--mu);}',
    '#ogc-card .oge .oge-est b{font-weight:600;color:var(--ink);font-variant-numeric:tabular-nums;}',
    /* stage timeline: fills mix the family or tactic colour into the card surface, so they read in dark and light */
    '#ogc-card .oge .oge-bar{position:relative;height:32px;border:1px solid var(--ln2);border-radius:3px;background:var(--p2);overflow:hidden;margin:8px 0 4px;}',
    '#ogc-card .oge .oge-seg{position:absolute;top:0;bottom:0;min-width:3px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;font-size:0.75rem;font-weight:600;line-height:30px;padding:0 6px;color:var(--ink);border-right:1px solid var(--bg);border-top:2px solid var(--sc,var(--cy));}',
    '#ogc-card .oge .oge-legend{display:flex;flex-wrap:wrap;gap:2px 16px;font-size:0.75rem;color:var(--mu);margin:6px 0 10px;}',
    '#ogc-card .oge .oge-swatch{display:inline-block;width:10px;height:10px;border:1px solid var(--sc,var(--ln2));border-radius:2px;margin-right:6px;vertical-align:-1px;}',
    '#ogc-card .oge .oge-tactics{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0 12px;}',
    '#ogc-card .oge .oge-tac{font-size:0.75rem;border:1px solid var(--ln);border-radius:3px;padding:4px 9px;color:var(--mu);background:var(--p1);max-width:200px;}',
    '#ogc-card .oge .oge-tac.on{background:color-mix(in srgb,var(--cy) 14%,var(--p1));border-color:var(--cy);color:var(--ink);font-weight:600;box-shadow:0 0 12px color-mix(in srgb,var(--cy) 25%,transparent);}',
    '#ogc-card .oge .oge-tac small{display:block;font-weight:400;font-family:var(--font-mono);overflow-wrap:anywhere;}',
    '#ogc-card .oge .oge-picker{border:1px solid var(--ln2);border-radius:4px;padding:10px;margin:8px 0;background:var(--p1);}',
    '#ogc-card .oge .oge-picklist{max-height:320px;overflow:auto;margin-top:6px;}',
    '#ogc-card .oge .oge-pickgroup{font-size:0.8125rem;font-weight:600;color:var(--mu);margin:10px 0 4px;}',
    '#ogc-card .oge .oge-pick{display:block;width:100%;text-align:left;margin:0 0 4px;padding:6px 10px;border:1px solid var(--ln);border-radius:3px;background:var(--p2);color:var(--ink);font:inherit;font-size:0.8125rem;cursor:pointer;min-height:32px;}',
    '#ogc-card .oge .oge-pick:hover{border-color:var(--ac-tx);background:var(--p3);}',
    '#ogc-card .oge .oge-pick span{display:block;font-weight:400;font-size:0.75rem;color:var(--mu);}',
    '#ogc-card .oge .oge-empty{border:1px dashed var(--ln2);border-radius:4px;padding:18px;text-align:center;color:var(--mu);margin:8px 0;}',
    '#ogc-card .oge .oge-techres{border:1px solid var(--ln2);border-radius:3px;background:var(--p2);max-height:200px;overflow:auto;margin-top:3px;}',
    '#ogc-card .oge .oge-techres button{display:block;width:100%;text-align:left;border:0;border-radius:0;background:transparent;color:var(--ink);font:inherit;font-size:0.8125rem;padding:6px 10px;cursor:pointer;min-height:30px;}',
    '#ogc-card .oge .oge-techres button:hover{background:var(--p3);}',
    '#ogc-card .oge code{font-family:var(--font-mono);font-size:0.75rem;}',
    '#ogc-card .oge details.oge-explain{margin:10px 0;border:1px solid var(--ln);border-radius:4px;padding:8px 12px;background:var(--p1);}',
    '#ogc-card .oge details.oge-explain summary{cursor:pointer;font-weight:500;}',
    '#ogc-card .oge details.oge-explain ol{margin:6px 0 0;padding-left:20px;font-size:0.8125rem;}',
    '#ogc-card .oge :is(input,select,textarea,button,summary):focus-visible{outline:2px solid var(--cy);outline-offset:2px;}',
    '#ogc-card .oge :is(input,select,textarea):focus{border-color:var(--cy);}',
    '@media (prefers-reduced-motion:reduce){#ogc-card .oge *{transition:none !important;animation:none !important;}}'
  ].join('\n');

  /* DOM helper: attrs class/text/on<event>/value/checked + attribute strings; children text-safe. */
  function h(tag, attrs) {
    var e = document.createElement(tag), v, k;
    var late = null;
    if (attrs) {
      for (k in attrs) {
        v = attrs[k];
        if (v === undefined || v === null || v === false) continue;
        if (k === 'class') e.className = v;
        else if (k === 'text') e.textContent = String(v);
        else if (k === 'value') late = v;
        else if (k === 'checked') e.checked = !!v;
        else if (k.slice(0, 2) === 'on' && typeof v === 'function') e.addEventListener(k.slice(2), v);
        else e.setAttribute(k, v === true ? '' : String(v));
      }
    }
    for (var i = 2; i < arguments.length; i++) appendKid(e, arguments[i]);
    if (late !== null) e.value = late;
    return e;
  }
  function appendKid(e, c) {
    if (c === undefined || c === null || c === false) return;
    if (Array.isArray(c)) { c.forEach(function (x) { appendKid(e, x); }); return; }
    if (typeof c === 'string' || typeof c === 'number') { e.appendChild(document.createTextNode(String(c))); return; }
    e.appendChild(c);
  }
  function clear(e) { while (e.firstChild) e.removeChild(e.firstChild); }
  function debounce(fn, ms) {
    var t = null;
    var w = function () { var a = arguments, self = this; clearTimeout(t); t = setTimeout(function () { fn.apply(self, a); }, ms); };
    w.cancel = function () { clearTimeout(t); };
    return w;
  }

  /* stage fills: a token colour mixed into the card surface (--p1), so they read correctly in dark and light */
  var PALETTE_BASE = ['var(--c-sec)', 'var(--c-perf)', 'var(--c-cryp)', 'var(--c-rep)', 'var(--c-cus)', 'var(--cy)', 'var(--ac-tx)', 'var(--ok)', 'var(--wr)', 'var(--er)', 'var(--vi)', 'var(--c-rep)', 'var(--c-perf)', 'var(--c-cryp)'];
  var PALETTE = PALETTE_BASE.map(function (b) { return 'color-mix(in srgb, ' + b + ' 38%, var(--p1))'; });
  function tacticIndex(slug, tactics) {
    var i = (tactics || []).map(function (t) { return t.slug; }).indexOf(slug);
    if (i < 0) { var s = 0; String(slug || '').split('').forEach(function (ch) { s += ch.charCodeAt(0); }); i = s; }
    return i % PALETTE.length;
  }
  function tacticColour(slug, tactics) { return PALETTE[tacticIndex(slug, tactics)]; }
  /* the solid token colour behind a stage fill (used for the segment's top rule and the legend swatch) */
  function tacticBase(slug, tactics) { return PALETTE_BASE[tacticIndex(slug, tactics)]; }

  function attach(OGC) {
    var ui = null;              // refs of the current render
    var catalog = { actions: [], tactics: [] };
    var catalogLoading = false, catalogFailed = false;
    var techNames = {};
    var pickerFor = null;       // stage index whose action picker is open
    var pickerQuery = '';
    var collapsed = {};         // stage id -> true
    var selfEdit = false;
    var mounted = null;
    var errors = [], validity = 'idle';   // idle | checking | done | unavailable
    var valSeq = 0, estimate = null, estimateNote = '';

    function st() { return OGC.state || (OGC.state = {}); }
    function camp() { return st().campaign || null; }

    function syncCatalog() {
      var c = pure.normCatalog(st().actions);
      if (c.actions.length) catalog.actions = c.actions;
      if (c.tactics.length) catalog.tactics = c.tactics;
    }

    function loadCatalog() {
      syncCatalog();
      if ((catalog.actions.length && catalog.tactics.length) || catalogLoading) return;
      if (!OGC.api || typeof OGC.api.get !== 'function') return;
      catalogLoading = true;
      OGC.api.get('/api/campaign/actions').then(function (res) {
        catalogLoading = false; catalogFailed = false;
        var c = pure.normCatalog(res);
        if (c.actions.length) catalog.actions = c.actions;
        if (c.tactics.length) catalog.tactics = c.tactics;
        if (!st().actions) { st().actions = res; if (OGC.emit) OGC.emit('actions', res); }
        if (mounted) render();
      }).catch(function () {
        catalogLoading = false; catalogFailed = true;
        if (mounted) render();
      });
    }

    /* ---- edit plumbing ---- */
    function edit(fn, opts) {
      opts = opts || {};
      var cur = camp();
      if (!cur) return;
      var copy = pure.clone(cur);
      fn(copy);
      selfEdit = true;
      try { OGC.setCampaign(copy, { source: 'edit' }); } finally { selfEdit = false; }
      st().dirty = true;
      if (opts.structural) render(opts.focus);
      else refreshInfo();
      scheduleValidate();
    }

    var scheduleValidate = debounce(function () { validateNow(); }, 500);

    function validateNow() {
      var c = camp();
      if (!c || !OGC.api) return;
      var seq = ++valSeq;
      validity = 'checking';
      setStatus();
      OGC.api.post('/api/campaign/validate', { campaign: c }).then(function (res) {
        if (seq !== valSeq) return;
        errors = (res && Array.isArray(res.errors)) ? res.errors.map(String) : [];
        validity = 'done';
        showErrors();
        setStatus();
        if (!errors.length) runEstimate(seq, c); else { estimate = null; estimateNote = 'Fix the problems to see the estimate.'; showEstimate(); }
      }).catch(function (e) {
        if (seq !== valSeq) return;
        validity = 'unavailable';
        errors = [];
        showErrors(); setStatus();
        estimate = null; estimateNote = 'Estimate unavailable.';
        showEstimate();
        void e;
      });
    }

    function runEstimate(seq, c) {
      OGC.api.post('/api/campaign/estimate', { campaign: c, scale: 1.0 }).then(function (res) {
        if (seq !== valSeq) return;
        if (res && Array.isArray(res.errors) && res.errors.length) { estimate = null; estimateNote = 'Estimate unavailable.'; }
        else { estimate = pure.estimateLine(res, c); estimateNote = ''; }
        showEstimate();
      }).catch(function () {
        if (seq !== valSeq) return;
        estimate = null; estimateNote = 'Estimate unavailable.'; showEstimate();
      });
    }

    /* ---- rendering ---- */
    function ensureStyle() {
      if (document.getElementById('ogc-editor-style')) return;
      var s = document.createElement('style');
      s.id = 'ogc-editor-style';
      s.textContent = CSS;
      (document.head || document.body).appendChild(s);
    }

    function render(focusKey) {
      if (!mounted) return;
      ensureStyle();
      var c = camp();
      clear(mounted);
      ui = { stageErr: {}, actErr: {}, stageEls: {} };
      var wrap = h('div', { class: 'oge', role: 'region', 'aria-label': 'Campaign editor' });
      mounted.appendChild(wrap);

      if (!c) { wrap.appendChild(emptyNoCampaign()); return; }
      syncCatalog();

      wrap.appendChild(headerSection(c));
      ui.status = h('div', { class: 'oge-status', role: 'status', 'aria-live': 'polite' });
      ui.errBox = h('div');
      ui.estBox = h('div', { class: 'oge-est', 'aria-label': 'Estimate' });
      wrap.appendChild(h('div', { class: 'oge-row' }, ui.status));
      wrap.appendChild(ui.errBox);
      wrap.appendChild(ui.estBox);
      ui.timeBox = h('div');
      ui.tacBox = h('div');
      wrap.appendChild(ui.timeBox);
      wrap.appendChild(ui.tacBox);
      wrap.appendChild(explainPanel());
      wrap.appendChild(h('h3', { text: 'Stages' }));
      if (catalogFailed) wrap.appendChild(h('p', { class: 'oge-err', text: 'The action catalog could not be loaded. Stages can still be edited, but actions cannot be added until it is available.' }));
      var list = h('div', { class: 'oge-stages' });
      if (!c.stages || !c.stages.length) {
        list.appendChild(h('div', { class: 'oge-empty' },
          h('p', { text: 'This campaign has no stages yet.' }),
          h('p', { class: 'oge-muted', text: 'A stage is one step of the behaviour you want the sensor to see, such as "Execution" or "Command and control". Add a stage, then add one or more actions to it. Each action generates a short, realistic network exchange.' })));
      } else {
        c.stages.forEach(function (stage, si) { list.appendChild(stageCard(c, stage, si)); });
      }
      wrap.appendChild(list);
      wrap.appendChild(addStageRow(c));
      refreshInfo();
      showErrors(); setStatus(); showEstimate();
      if (focusKey) {
        var el = wrap.querySelector('[data-fk="' + focusKey + '"]');
        if (el && el.focus) el.focus();
      }
    }

    function emptyNoCampaign() {
      return h('div', { class: 'oge-empty' },
        h('h3', { text: 'No campaign to edit yet' }),
        h('p', { text: 'Build one from indicators, open a saved campaign, or start from scratch. A campaign is a short story of network behaviour that OpenGenerator turns into a valid capture for testing a sensor.' }),
        h('div', { class: 'oge-row', style: 'justify-content:center' },
          h('button', { type: 'button', class: 'oge-primary', text: 'Start from scratch', onclick: function () {
            selfEdit = true;
            try { OGC.setCampaign(pure.blankCampaign(), { source: 'edit' }); } finally { selfEdit = false; }
            st().dirty = true; render(); scheduleValidate();
          } }),
          h('button', { type: 'button', text: 'Back to the first step', onclick: function () { if (OGC.goto) OGC.goto('type'); } })));
    }

    function field(label, input, cls) {
      return h('label', { class: 'oge-f ' + (cls || '') }, label, input);
    }

    function headerSection(c) {
      var meta = c.meta || {};
      ui.counts = h('p', { class: 'oge-muted' });
      var name = h('input', { type: 'text', value: meta.name || '', maxlength: 200, 'aria-label': 'Campaign name' });
      name.addEventListener('input', function () {
        edit(function (cc) { cc.meta = cc.meta || {}; cc.meta.name = name.value; });
        name.setAttribute('aria-invalid', name.value.trim() ? 'false' : 'true');
      });
      var actor = h('input', { type: 'text', value: meta.actor || '', maxlength: 200, 'aria-label': 'Actor' });
      actor.addEventListener('input', function () { edit(function (cc) { cc.meta = cc.meta || {}; cc.meta.actor = actor.value; }); });
      var desc = h('textarea', { rows: 2, maxlength: 2000, 'aria-label': 'Description' });
      desc.value = meta.description || '';
      desc.addEventListener('input', function () { edit(function (cc) { cc.meta = cc.meta || {}; cc.meta.description = desc.value; }); });
      var seed = h('input', { type: 'text', value: String(meta.seed === undefined ? '' : meta.seed), readonly: true, 'aria-label': 'Seed (read-only)' });
      return h('div', null,
        h('div', { class: 'oge-hdr' }, field('Campaign name', name, ''), field('Actor', actor, ''), field('Seed (read-only)', seed, '')),
        field('Description', desc, ''), ui.counts);
    }

    function explainPanel() {
      var lines = Array.isArray(st().explain) ? st().explain : [];
      var d = h('details', { class: 'oge-explain' }, h('summary', { text: 'Explain: how the indicators became stages (' + lines.length + ')' }));
      if (!lines.length) d.appendChild(h('p', { class: 'oge-muted', text: 'No explanation yet. It appears after you compile a campaign from indicators; a campaign built by hand has none.' }));
      else d.appendChild(h('ol', null, lines.slice(0, 500).map(function (l) { return h('li', { text: String(l) }); })));
      return d;
    }

    /* The parts that depend on campaign content and can refresh without losing input focus. */
    function refreshInfo() {
      var c = camp();
      if (!ui || !c) return;
      if (ui.counts) {
        var meta = c.meta || {};
        ui.counts.textContent = (c.stages || []).length + ' stages, ' + pure.totalActions(c) + ' actions, ' + (c.iocs || []).length + ' indicators' +
          (meta.id ? '. File id: ' + meta.id : '') + '.';
      }
      if (ui.timeBox) drawTimeline(c);
      if (ui.tacBox) drawTactics(c);
    }

    function drawTimeline(c) {
      clear(ui.timeBox);
      var tl = pure.timeline(c);
      ui.timeBox.appendChild(h('h3', { text: 'Timeline' }));
      if (!tl.segments.length) { ui.timeBox.appendChild(h('p', { class: 'oge-muted', text: 'Stages appear here once you add them, laid out one after another from the start time.' })); return; }
      var bar = h('div', { class: 'oge-bar', role: 'img', 'aria-label': 'Stage timeline from ' + tl.start_clock + ' to ' + tl.end_clock + ' (' + tl.speed + ' speed)' });
      var legend = h('div', { class: 'oge-legend' });
      tl.segments.forEach(function (s) {
        var col = tacticColour(s.tactic, catalog.tactics);
        var tname = pure.tacticName(catalog.tactics, s.tactic) || 'no tactic';
        var tip = s.name + ' (' + tname + '): ' + s.start_clock + ' to ' + s.end_clock + ', ' + pure.fmtDuration(s.dur_s);
        bar.appendChild(h('div', { class: 'oge-seg', style: 'left:' + s.left_pct.toFixed(3) + '%;width:' + s.width_pct.toFixed(3) + '%;background:' + col + ';--sc:' + tacticBase(s.tactic, catalog.tactics), title: tip, text: s.name }));
        legend.appendChild(h('span', { title: tip }, h('span', { class: 'oge-swatch', style: 'background:' + col + ';--sc:' + tacticBase(s.tactic, catalog.tactics) }), s.name + ' - ' + tname + ', ' + s.start_clock + ' to ' + s.end_clock));
      });
      ui.timeBox.appendChild(bar);
      ui.timeBox.appendChild(h('div', { class: 'oge-muted' }, 'Starts ' + tl.start_clock + ', ends ' + tl.end_clock + ' (' + pure.fmtDuration(tl.total_s) + ' at ' + tl.speed + ' speed).'));
      ui.timeBox.appendChild(legend);
    }

    function drawTactics(c) {
      clear(ui.tacBox);
      ui.tacBox.appendChild(h('h3', { text: 'ATT&CK tactics covered' }));
      var cov = pure.tacticCoverage(c, catalog.tactics, catalog.actions);
      if (!cov.length) { ui.tacBox.appendChild(h('p', { class: 'oge-muted', text: 'The tactic list loads with the action catalog.' })); return; }
      var strip = h('div', { class: 'oge-tactics', role: 'list' });
      cov.forEach(function (t) {
        strip.appendChild(h('div', { class: 'oge-tac' + (t.covered ? ' on' : ''), role: 'listitem', title: t.id + ' ' + t.name + (t.covered ? ' (covered)' : ' (not covered)') },
          t.name + (t.covered ? ' (covered)' : ''), t.techniques.length ? h('small', { text: t.techniques.join(', ') }) : null));
      });
      ui.tacBox.appendChild(strip);
    }

    function setStatus() {
      if (!ui || !ui.status) return;
      var cls = 'oge-status', txt;
      if (validity === 'checking') txt = 'Checking...';
      else if (validity === 'unavailable') txt = 'Validation is unavailable right now.';
      else if (validity === 'done') {
        if (errors.length) { cls += ' bad'; txt = errors.length + (errors.length === 1 ? ' problem' : ' problems'); }
        else { cls += ' ok'; txt = 'valid'; }
      } else txt = 'Not checked yet';
      ui.status.className = cls;
      ui.status.textContent = txt;
    }

    function showErrors() {
      if (!ui || !ui.errBox) return;
      clear(ui.errBox);
      var c = camp();
      var g = pure.groupErrors(errors, c);
      if (g.general.length) {
        ui.errBox.appendChild(h('div', { class: 'oge-errs' }, h('strong', { text: 'Problems with the campaign' }),
          h('ul', null, g.general.slice(0, 50).map(function (e) { return h('li', { text: e }); }))));
      }
      Object.keys(ui.stageErr).forEach(function (si) {
        var box = ui.stageErr[si]; clear(box);
        var list = g.stages[si] || [];
        list.forEach(function (e) { box.appendChild(h('div', { class: 'oge-err', role: 'alert', text: e })); });
        if (ui.stageEls[si]) ui.stageEls[si].className = 'oge-card' + (list.length || stageHasActionErr(g, si) ? ' has-err' : '');
      });
      Object.keys(ui.actErr).forEach(function (k) {
        var box = ui.actErr[k]; clear(box);
        var list = g.actions[k] || [];
        list.forEach(function (e) { box.appendChild(h('div', { class: 'oge-err', role: 'alert', text: e })); });
        if (box.parentNode) box.parentNode.className = 'oge-act' + (list.length ? ' has-err' : '');
      });
    }
    function stageHasActionErr(g, si) {
      return Object.keys(g.actions).some(function (k) { return k.indexOf(si + ':') === 0; });
    }

    function showEstimate() {
      if (!ui || !ui.estBox) return;
      clear(ui.estBox);
      var c = camp();
      if (!estimate) {
        ui.estBox.appendChild(h('span', { class: 'oge-muted', text: (estimateNote || 'Estimate appears once the campaign is valid.') + ' ' + (c ? (c.stages || []).length + ' stages, ' + pure.totalActions(c) + ' actions.' : '') }));
        return;
      }
      function item(label, v) { return h('span', null, label + ': ', h('b', { text: v === null || v === undefined ? 'n/a' : String(v) })); }
      function mins(v) { return v === null ? null : (Math.round(v * 10) / 10) + ' min'; }
      ui.estBox.appendChild(item('Stages', estimate.stages));
      ui.estBox.appendChild(item('Actions', estimate.actions));
      ui.estBox.appendChild(item('Flows', estimate.flows));
      ui.estBox.appendChild(item('Realistic', mins(estimate.minutes_realistic)));
      ui.estBox.appendChild(item('Fast', mins(estimate.minutes_fast)));
    }

    /* ---- stages ---- */
    function addStageRow(c) {
      var sel = h('select', { 'aria-label': 'Tactic for the new stage' });
      var tactics = catalog.tactics;
      if (!tactics.length) sel.appendChild(h('option', { value: '', text: 'Tactics are loading...' }));
      tactics.forEach(function (t) { sel.appendChild(h('option', { value: t.slug, text: t.name })); });
      var dflt = tactics.some(function (t) { return t.slug === 'execution'; }) ? 'execution' : (tactics[0] && tactics[0].slug);
      if (dflt) sel.value = dflt;
      return h('div', { class: 'oge-row' }, field('Tactic', sel, ''),
        h('button', { type: 'button', class: 'oge-primary', text: 'Add stage', onclick: function () {
          var idx = (camp().stages || []).length;
          pickerFor = idx;   // open the action picker so the new stage is not left empty
          pickerQuery = '';
          edit(function (cc) { pure.addStage(cc, sel.value, catalog.tactics); }, { structural: true, focus: 'st-name-' + idx });
        } }));
    }

    function iconBtn(label, text, fn, fk, disabled, cls) {
      return h('button', { type: 'button', 'aria-label': label, title: label, text: text, 'data-fk': fk, disabled: disabled ? true : null, class: cls || '', onclick: fn });
    }

    function stageCard(c, stage, si) {
      var n = c.stages.length;
      var card = h('div', { class: 'oge-card' });
      ui.stageEls[si] = card;
      var isCollapsed = !!collapsed[stage.id];
      var body = h('div', { class: 'oge-cardbody' });
      if (isCollapsed) body.setAttribute('hidden', '');
      var toggle = h('button', { type: 'button', 'aria-expanded': isCollapsed ? 'false' : 'true', 'aria-label': 'Show or hide stage ' + (si + 1) + ' details', text: isCollapsed ? '▸' : '▾' });
      toggle.addEventListener('click', function () {
        var hide = !body.hasAttribute('hidden');
        if (hide) body.setAttribute('hidden', ''); else body.removeAttribute('hidden');
        collapsed[stage.id] = hide;
        toggle.setAttribute('aria-expanded', hide ? 'false' : 'true');
        toggle.textContent = hide ? '▸' : '▾';
      });
      var nameIn = h('input', { type: 'text', class: 'oge-title', value: stage.name || '', maxlength: 200, 'aria-label': 'Stage ' + (si + 1) + ' name', 'data-fk': 'st-name-' + si });
      nameIn.addEventListener('input', function () { edit(function (cc) { cc.stages[si].name = nameIn.value; }); });
      var head = h('div', { class: 'oge-cardhead' }, toggle, h('span', { class: 'oge-chip', text: stage.id || '' }), nameIn,
        iconBtn('Move stage ' + (si + 1) + ' up', '↑', function () { edit(function (cc) { pure.moveItem(cc.stages, si, -1); }, { structural: true, focus: 'st-up-' + stage.id }); }, 'st-up-' + stage.id, si === 0),
        iconBtn('Move stage ' + (si + 1) + ' down', '↓', function () { edit(function (cc) { pure.moveItem(cc.stages, si, 1); }, { structural: true, focus: 'st-down-' + stage.id }); }, 'st-down-' + stage.id, si === n - 1),
        iconBtn('Duplicate stage ' + (si + 1), 'Duplicate', function () { edit(function (cc) { pure.duplicateStage(cc, si); }, { structural: true }); }, 'st-dup-' + stage.id),
        iconBtn('Delete stage ' + (si + 1), 'Delete', function () { edit(function (cc) { pure.removeStage(cc, si); }, { structural: true }); }, 'st-del-' + stage.id, false, 'oge-danger'));
      card.appendChild(head);
      ui.stageErr[si] = h('div');
      body.appendChild(ui.stageErr[si]);

      // tactic, duration, fast duration
      var tacSel = h('select', { 'aria-label': 'Stage ' + (si + 1) + ' tactic' });
      var known = false;
      catalog.tactics.forEach(function (t) { if (t.slug === stage.tactic) known = true; tacSel.appendChild(h('option', { value: t.slug, text: t.name })); });
      if (!known) tacSel.insertBefore(h('option', { value: stage.tactic || '', text: stage.tactic ? stage.tactic + ' (unknown)' : '(choose a tactic)' }), tacSel.firstChild);
      tacSel.value = stage.tactic || '';
      tacSel.addEventListener('change', function () { edit(function (cc) { cc.stages[si].tactic = tacSel.value; }); });
      function secField(key, label, min) {
        var inp = h('input', { type: 'number', min: min, max: MAX_SECONDS, step: 'any', value: stage[key] === undefined ? '' : stage[key], 'aria-label': 'Stage ' + (si + 1) + ' ' + label });
        inp.addEventListener('change', function () {
          var v = pure.clampSeconds(inp.value, min, stage[key] === undefined ? 60 : stage[key]);
          inp.value = v;
          edit(function (cc) { cc.stages[si][key] = v; });
        });
        return field(label, inp, '');
      }
      body.appendChild(h('div', { class: 'oge-row' }, field('Tactic', tacSel, 'grow'), secField('duration_s', 'Duration (s, realistic)', 1), secField('fast_s', 'Duration (s, fast)', 1)));

      var narr = h('textarea', { rows: 2, maxlength: 2000, 'aria-label': 'Stage ' + (si + 1) + ' narrative' });
      narr.value = stage.narrative || '';
      narr.addEventListener('input', function () { edit(function (cc) { cc.stages[si].narrative = narr.value; }); });
      body.appendChild(field('Narrative (what happens in this stage)', narr, ''));
      body.appendChild(techniqueEditor(stage, si));

      // actions
      body.appendChild(h('h4', { text: 'Actions' }));
      var acts = stage.actions || [];
      if (!acts.length) body.appendChild(h('p', { class: 'oge-muted', text: 'No actions yet. A stage needs at least one action; each one writes a short network exchange between two hosts.' }));
      acts.forEach(function (a, ai) { body.appendChild(actionCard(c, stage, si, a, ai)); });
      body.appendChild(h('div', { class: 'oge-row' },
        h('button', { type: 'button', class: 'oge-primary', 'data-fk': 'st-addact-' + si, text: pickerFor === si ? 'Close action list' : 'Add action', 'aria-expanded': pickerFor === si ? 'true' : 'false',
          onclick: function () { pickerFor = pickerFor === si ? null : si; pickerQuery = ''; render('st-addact-' + si); } })));
      if (pickerFor === si) body.appendChild(actionPicker(c, stage, si));
      card.appendChild(body);
      return card;
    }

    function techniqueEditor(stage, si) {
      var chips = h('div');
      function drawChips() {
        clear(chips);
        (stage.techniques || []).forEach(function (id) {
          var bad = !pure.validTechniqueId(id);
          chips.appendChild(h('span', { class: 'oge-chip' + (bad ? ' bad' : ''), title: bad ? 'Not a valid ATT&CK technique id' : (techNames[id] || id) },
            id + (techNames[id] ? ' ' + techNames[id] : '') + (bad ? ' (invalid)' : ''),
            h('button', { type: 'button', 'aria-label': 'Remove technique ' + id, text: '×', onclick: function () {
              edit(function (cc) { pure.removeTechnique(cc.stages[si], id); }, { structural: true, focus: 'tech-' + si });
            } })));
        });
        if (!(stage.techniques || []).length) chips.appendChild(h('span', { class: 'oge-muted', text: 'No techniques yet.' }));
      }
      drawChips();
      var results = h('div', { 'aria-live': 'polite' });
      var seq = 0;
      var input = h('input', { type: 'text', 'data-fk': 'tech-' + si, placeholder: 'Search, e.g. T1071 or beacon', 'aria-label': 'Search ATT&CK techniques for stage ' + (si + 1), autocomplete: 'off' });
      function add(id) {
        edit(function (cc) { pure.addTechnique(cc.stages[si], id); }, { structural: true, focus: 'tech-' + si });
      }
      var search = debounce(function () {
        var q = input.value.trim();
        clear(results);
        if (q.length < 2) return;
        var my = ++seq;
        OGC.api.get('/api/campaign/attack?q=' + encodeURIComponent(q)).then(function (res) {
          if (my !== seq) return;
          clear(results);
          var items = (res && res.techniques) || [];
          if (!items.length) { results.appendChild(h('div', { class: 'oge-muted', text: 'No match. Press Enter to add a technique id typed in full, e.g. T1071.001.' })); return; }
          var box = h('div', { class: 'oge-techres' });
          items.slice(0, 40).forEach(function (t) {
            techNames[t.id] = t.name;
            box.appendChild(h('button', { type: 'button', text: t.id + '  ' + t.name + (t.tactic ? '  (' + t.tactic + ')' : ''), onclick: function () { add(t.id); } }));
          });
          results.appendChild(box);
        }).catch(function () {
          if (my !== seq) return;
          clear(results);
          results.appendChild(h('div', { class: 'oge-muted', text: 'Technique search is unavailable. Type an id such as T1071.001 and press Enter.' }));
        });
      }, 250);
      input.addEventListener('input', search);
      input.addEventListener('keydown', function (ev) {
        if (ev.key === 'Enter') {
          ev.preventDefault();
          var v = input.value.trim().toUpperCase();
          if (pure.validTechniqueId(v)) add(v);
          else { clear(results); results.appendChild(h('div', { class: 'oge-err', text: 'That is not a technique id. Ids look like T1071 or T1071.001.' })); }
        }
      });
      return h('div', null, h('div', { class: 'oge-f' }, h('span', { class: 'oge-muted', text: 'ATT&CK techniques' })), chips, input, results);
    }

    /* ---- action picker ---- */
    function actionPicker(c, stage, si) {
      var box = h('div', { class: 'oge-picker' });
      var list = h('div', { class: 'oge-picklist' });
      var q = h('input', { type: 'text', placeholder: 'Search actions, protocols or techniques', 'aria-label': 'Search actions', value: pickerQuery });
      function draw() {
        clear(list);
        if (!catalog.actions.length) { list.appendChild(h('p', { class: 'oge-muted', text: catalogLoading ? 'Loading the action catalog...' : 'The action catalog is not available.' })); return; }
        var groups = pure.pickerGroups(catalog.actions, catalog.tactics, q.value, stage.tactic);
        if (!groups.length) list.appendChild(h('p', { class: 'oge-muted', text: 'No action matches that search.' }));
        groups.forEach(function (g) {
          list.appendChild(h('div', { class: 'oge-pickgroup', text: g.name || g.tactic }));
          g.actions.forEach(function (a) {
            var b = h('button', { type: 'button', class: 'oge-pick' },
              h('strong', { text: a.title || a.token }), ' ',
              a.ot ? h('span', { class: 'oge-chip ot', text: 'needs OT' }) : null,
              (a.protocols || []).map(function (p) { return h('span', { class: 'oge-chip', text: p }); }),
              h('span', { text: a.summary || '' }));
            b.addEventListener('click', function () {
              var idx = (stage.actions || []).length;
              pickerFor = null;
              edit(function (cc) { pure.addAction(cc, si, pure.newActionFor(a, cc.options)); }, { structural: true, focus: 'ac-title-' + si + '-' + idx });
            });
            list.appendChild(b);
          });
        });
      }
      q.addEventListener('input', function () { pickerQuery = q.value; draw(); });
      box.appendChild(q);
      box.appendChild(list);
      draw();
      setTimeout(function () { if (q.focus && !(document.activeElement && document.activeElement !== document.body && /INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName))) q.focus(); }, 0);
      return box;
    }

    /* ---- action card ---- */
    function endpointPicker(label, kind, value, onChange, fk) {
      var choices = pure.refChoices(kind);
      var parsed = pure.parseRef(value);
      var sel = h('select', { 'aria-label': label });
      var currentBase = parsed.valid ? parsed.base : '';
      if (!parsed.valid) sel.appendChild(h('option', { value: '', text: value ? String(value) + ' (invalid)' : '(choose)' }));
      var seenScope = false;
      var mismatch = parsed.valid && kind !== 'any' && parsed.scope !== kind;
      if (mismatch) sel.appendChild(h('option', { value: currentBase, text: (ROLE_LABEL[currentBase] || currentBase) + ' (wrong kind)' }));
      choices.forEach(function (ch) { sel.appendChild(h('option', { value: ch.base, text: ch.label + (ch.param === 'index' ? ' (Nth)' : '') + (kind === 'any' ? ' [' + ch.scope + ']' : '') })); });
      void seenScope;
      sel.value = currentBase;
      var extra = h('input', { type: parsed.base === 'host' ? 'text' : 'number', min: 0, step: 1, 'aria-label': label + ' detail',
        value: parsed.base === 'host' ? parsed.suffix : (parsed.index === null ? 0 : parsed.index), size: 8 });
      function syncExtra() {
        var ch = choices.filter(function (x) { return x.base === sel.value; })[0];
        var p = ch ? ch.param : 'none';
        extra.style.display = p === 'none' ? 'none' : '';
        extra.type = p === 'suffix' ? 'text' : 'number';
        extra.setAttribute('placeholder', p === 'suffix' ? 'e.g. FILE1' : 'index');
        extra.setAttribute('aria-label', label + (p === 'suffix' ? ' host suffix' : ' indicator number'));
        return p;
      }
      syncExtra();
      function commit() {
        var p = syncExtra();
        if (!sel.value) return;
        if (p === 'suffix' && !/^[A-Za-z0-9_.-]{1,40}$/.test(extra.value.trim())) { extra.setAttribute('aria-invalid', 'true'); return; }
        extra.removeAttribute('aria-invalid');
        onChange(pure.formatRef(sel.value, extra.value));
      }
      sel.addEventListener('change', function () {
        if (syncExtra() === 'suffix' && !extra.value.trim()) extra.value = 'FILE1';
        commit();
      });
      extra.addEventListener('change', commit);
      if (fk) sel.setAttribute('data-fk', fk);
      return h('label', { class: 'oge-f grow' }, label, h('span', { class: 'oge-row', style: 'gap:4px;flex-wrap:nowrap' }, sel, extra));
    }

    function actionCard(c, stage, si, a, ai) {
      var spec = pure.specByToken(catalog.actions, a.action);
      var card = h('div', { class: 'oge-act' });
      var nAct = stage.actions.length;
      var title = h('span', { class: 'oge-title', tabindex: '-1', 'data-fk': 'ac-title-' + si + '-' + ai }, h('strong', { text: spec ? spec.title : a.action }), ' ', h('code', { text: a.action }));
      var head = h('div', { class: 'oge-cardhead' }, title,
        spec && spec.tactic ? h('span', { class: 'oge-chip', text: pure.tacticName(catalog.tactics, spec.tactic) }) : null,
        spec && spec.ot ? h('span', { class: 'oge-chip ot', text: 'needs OT' }) : null,
        iconBtn('Move action ' + (ai + 1) + ' of stage ' + (si + 1) + ' up', '↑', function () { edit(function (cc) { pure.moveItem(cc.stages[si].actions, ai, -1); }, { structural: true, focus: 'ac-up-' + si + '-' + (ai - 1) }); }, 'ac-up-' + si + '-' + ai, ai === 0),
        iconBtn('Move action ' + (ai + 1) + ' of stage ' + (si + 1) + ' down', '↓', function () { edit(function (cc) { pure.moveItem(cc.stages[si].actions, ai, 1); }, { structural: true, focus: 'ac-down-' + si + '-' + (ai + 1) }); }, 'ac-down-' + si + '-' + ai, ai === nAct - 1),
        iconBtn('Duplicate action ' + (ai + 1), 'Duplicate', function () { edit(function (cc) { pure.duplicateAction(cc, si, ai); }, { structural: true }); }, 'ac-dup-' + si + '-' + ai),
        iconBtn('Delete action ' + (ai + 1), 'Delete', function () { edit(function (cc) { pure.removeAction(cc, si, ai); }, { structural: true }); }, 'ac-del-' + si + '-' + ai, false, 'oge-danger'));
      card.appendChild(head);
      var errBox = h('div');
      ui.actErr[si + ':' + ai] = errBox;
      var body = h('div', { class: 'oge-cardbody' }, errBox);
      card.appendChild(body);
      if (spec && spec.summary) body.appendChild(h('p', { class: 'oge-muted', text: spec.summary + (spec.needs && spec.needs.length ? ' Needs host: ' + spec.needs.join(', ') + '.' : '') }));
      if (!spec && catalog.actions.length) body.appendChild(h('p', { class: 'oge-err', text: 'This action token is not in the catalog.' }));

      var atIn = h('input', { type: 'number', min: 0, max: MAX_SECONDS, step: 'any', value: a.at === undefined ? '' : a.at, placeholder: 'auto', 'aria-label': 'Offset in seconds from the stage start' });
      atIn.addEventListener('change', function () {
        var raw = atIn.value.trim();
        if (raw === '') { edit(function (cc) { delete cc.stages[si].actions[ai].at; }); return; }
        var v = pure.clampSeconds(raw, 0, 0);
        atIn.value = v;
        edit(function (cc) { cc.stages[si].actions[ai].at = v; });
      });
      var row = h('div', { class: 'oge-row' },
        endpointPicker('From', spec ? spec.src || 'any' : 'any', a.from, function (v) { edit(function (cc) { cc.stages[si].actions[ai].from = v; }, { structural: true, focus: 'ep-from-' + si + '-' + ai }); }, 'ep-from-' + si + '-' + ai),
        endpointPicker('To', spec ? spec.dst || 'any' : 'any', a.to, function (v) { edit(function (cc) { cc.stages[si].actions[ai].to = v; }, { structural: true, focus: 'ep-to-' + si + '-' + ai }); }, 'ep-to-' + si + '-' + ai),
        field('Offset (s)', atIn, ''));
      if (c.stages.length > 1) {
        var mv = h('select', { 'aria-label': 'Move this action to another stage' }, h('option', { value: '', text: 'Move to...' }));
        c.stages.forEach(function (s2, ti) { if (ti !== si) mv.appendChild(h('option', { value: String(ti), text: (s2.name || s2.id) + ' (' + s2.id + ')' })); });
        mv.addEventListener('change', function () {
          if (mv.value === '') return;
          var ti = parseInt(mv.value, 10);
          edit(function (cc) { pure.moveAction(cc, si, ai, ti); }, { structural: true });
        });
        row.appendChild(field('Stage', mv, ''));
      }
      body.appendChild(row);

      // params form from the spec
      if (spec && spec.params && Object.keys(spec.params).length) {
        var form = h('div', { class: 'oge-params' });
        Object.keys(spec.params).forEach(function (pn) { form.appendChild(paramField(spec, pn, a, si, ai)); });
        body.appendChild(form);
      }

      // linked indicators
      var links = pure.linkedIocs(c, a);
      if (links.length) {
        body.appendChild(h('div', { class: 'oge-muted', style: 'margin-top:8px', text: 'Caused by indicators:' }));
        links.forEach(function (l) {
          body.appendChild(h('span', { class: 'oge-chip', title: l.why || '' }, '#' + l.index + ' ', h('code', { text: l.value }), ' ' + (l.role || '') + (l.why ? ' - ' + l.why : '')));
        });
      }
      var ex = h('input', { type: 'text', value: a.explain || '', maxlength: 500, 'aria-label': 'Explanation sentence' });
      ex.addEventListener('input', function () { edit(function (cc) { cc.stages[si].actions[ai].explain = ex.value; }); });
      body.appendChild(field('Explain (one sentence)', ex, ''));
      return card;
    }

    function paramField(spec, pn, a, si, ai) {
      var def = spec.params[pn] || {};
      var has = isObj(a.params) && Object.prototype.hasOwnProperty.call(a.params, pn);
      var cur = has ? a.params[pn] : def.default;
      var type = def.type || 'str';
      var msg = h('div', { class: 'oge-err', role: 'alert' });
      var input;
      if (type === 'bool') {
        input = h('input', { type: 'checkbox', checked: !!cur, 'aria-label': pn });
        input.addEventListener('change', function () { edit(function (cc) { setParam(cc, si, ai, pn, !!input.checked, false); }, { structural: true, focus: 'pf-' + si + '-' + ai + '-' + pn }); });
      } else {
        input = h('input', { type: (type === 'int' || type === 'float') ? 'number' : 'text', step: type === 'int' ? 1 : 'any',
          value: pure.paramToText(def, cur), placeholder: pure.paramToText(def, def.default), 'aria-label': pn, title: def.help || '' });
        input.addEventListener('change', function () {
          var r = pure.coerceParam(def, input.value);
          if (!r.ok) { msg.textContent = r.error; input.setAttribute('aria-invalid', 'true'); return; }
          msg.textContent = ''; input.removeAttribute('aria-invalid');
          edit(function (cc) { setParam(cc, si, ai, pn, r.value, !!r.reset); }, { structural: true, focus: 'pf-' + si + '-' + ai + '-' + pn });
        });
      }
      input.setAttribute('data-fk', 'pf-' + si + '-' + ai + '-' + pn);
      var reset = has ? h('button', { type: 'button', text: 'Reset', 'aria-label': 'Reset ' + pn + ' to its default', onclick: function () { edit(function (cc) { setParam(cc, si, ai, pn, undefined, true); }, { structural: true }); } }) : null;
      return h('label', { class: 'oge-f oge-param', title: def.help || '' }, pn + (type === 'list' ? ' (comma separated)' : ''),
        h('span', { class: 'oge-row', style: 'gap:4px;flex-wrap:nowrap' }, input, reset),
        def.help ? h('span', { class: 'oge-help', text: def.help }) : null, msg);
    }

    function setParam(cc, si, ai, pn, value, reset) {
      var act = cc.stages[si].actions[ai];
      if (!isObj(act.params)) act.params = {};
      if (reset) delete act.params[pn]; else act.params[pn] = value;
    }

    /* ---- registration and lifecycle ---- */
    function mount(container) {
      mounted = container;
      ensureStyle();
      render();
    }

    function onEnter() {
      loadCatalog();
      render();
      if (camp()) validateNow();
    }

    function canLeave() { return true; }

    if (typeof OGC.on === 'function') {
      OGC.on('campaign', function () {
        if (selfEdit || !mounted) return;
        errors = []; validity = 'idle'; estimate = null; estimateNote = '';
        pickerFor = null;
        render();
        if (camp()) scheduleValidate();
      });
      OGC.on('actions', function () { syncCatalog(); if (mounted && pickerFor !== null) render(); });
    }

    OGC.editor = { refresh: function () { render(); }, validateNow: validateNow };
    OGC.registerStep({ id: 'build', title: 'Build', mount: mount, onEnter: onEnter, canLeave: canLeave });
    OGC._test = OGC._test || {};
    OGC._test.editor = pure;
    return pure;
  }

  /* Register when the shell exists; wait for it if this script loaded first. */
  function boot(tries) {
    if (root.OGC && typeof root.OGC.registerStep === 'function') { attach(root.OGC); return; }
    if (tries > 200) return;
    setTimeout(function () { boot(tries + 1); }, 25);
  }
  if (root.OGC && typeof root.OGC.registerStep === 'function') {
    attach(root.OGC);
  } else {
    // Expose the pure helpers right away for tests, then wait for the shell.
    if (root.OGC) { root.OGC._test = root.OGC._test || {}; root.OGC._test.editor = pure; }
    boot(0);
  }
})();
