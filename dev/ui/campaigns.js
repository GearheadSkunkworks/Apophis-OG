/* OpenGenerator Campaign Builder: shell and steps 1-2 (Type, Indicators).
 *
 * Defines window.OGC (see dev/docs/campaign-m2-contracts.md section 2). campaigns-editor.js and
 * campaigns-library.js attach to it. Everything that comes from a feed or a pasted file is inserted
 * with textContent (OGC.el / OGC.esc), never innerHTML. API keys live only in the `keys` variable
 * of this closure and are sent only in the body of the one fetch request that needs them.
 *
 * The campaign builder drives the traffic generator: it writes valid, replayable captures so a
 * network sensor can be tested. It does not exploit anything.
 */
(function () {
  'use strict';

  var OGC = window.OGC = window.OGC || {};

  // ------------------------------------------------------------------ small helpers

  var ESC_MAP = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'};
  function esc(text) {
    return String(text == null ? '' : text).replace(/[&<>"']/g, function (c) { return ESC_MAP[c]; });
  }

  // el(tag, attrs, ...children). attrs: class, text, style (string), dataset (object), on<event>
  // functions, true/false booleans (set as properties), value, anything else via setAttribute.
  // Children: strings and numbers become text nodes, arrays are flattened, null/false are skipped.
  var BOOL_PROPS = {disabled: 1, checked: 1, hidden: 1, selected: 1, multiple: 1, readOnly: 1,
                    required: 1, open: 1, autofocus: 1};
  function appendChildren(node, list) {
    for (var i = 0; i < list.length; i++) {
      var c = list[i];
      if (c == null || c === false || c === true) continue;
      if (Array.isArray(c)) { appendChildren(node, c); continue; }
      if (typeof c === 'object' && c.nodeType) node.appendChild(c);
      else node.appendChild(document.createTextNode(String(c)));
    }
  }
  function el(tag, attrs) {
    var node = document.createElement(tag);
    if (attrs && typeof attrs === 'object' && !attrs.nodeType && !Array.isArray(attrs)) {
      Object.keys(attrs).forEach(function (k) {
        var v = attrs[k];
        if (v == null) return;
        if (k === 'class') node.className = v;
        else if (k === 'text') node.textContent = String(v);
        else if (k === 'style') node.setAttribute('style', v);
        else if (k === 'dataset') Object.keys(v).forEach(function (d) { node.dataset[d] = String(v[d]); });
        else if (k === 'value') node.value = v;
        else if (k.slice(0, 2) === 'on' && typeof v === 'function') node.addEventListener(k.slice(2), v);
        else if (BOOL_PROPS[k]) { if (v) node[k] = true; }
        else node.setAttribute(k, String(v));
      });
      appendChildren(node, Array.prototype.slice.call(arguments, 2));
    } else {
      appendChildren(node, Array.prototype.slice.call(arguments, 1));
    }
    return node;
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
  function $(sel, root) { return (root || document).querySelector(sel); }

  var _uid = 0;
  function uid(prefix) { _uid += 1; return (prefix || 'ogc') + '-' + _uid; }

  // ------------------------------------------------------------------ events

  var listeners = {};
  function on(event, fn) {
    (listeners[event] = listeners[event] || []).push(fn);
    return function off() {
      listeners[event] = (listeners[event] || []).filter(function (f) { return f !== fn; });
    };
  }
  function emit(event, detail) {
    (listeners[event] || []).slice().forEach(function (fn) {
      try { fn(detail); } catch (e) { if (window.console) console.error('OGC listener for ' + event + ' failed', e); }
    });
  }

  // ------------------------------------------------------------------ api

  function request(method, path, body) {
    var opts = {method: method, headers: {'Accept': 'application/json'}};
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    return fetch(path, opts).then(function (res) {
      return res.text().then(function (text) {
        var data = null, parsed = true;
        if (text) { try { data = JSON.parse(text); } catch (e) { parsed = false; } }
        if (!res.ok) {
          var msg = (data && typeof data === 'object' && data.error)
            ? String(data.error)
            : res.status === 404 ? 'This feature is not available in this build (HTTP 404).'
              : 'The server answered HTTP ' + res.status + '.';
          var err = new Error(msg); err.status = res.status; throw err;
        }
        if (!parsed) { var e2 = new Error('The server sent a reply that is not valid JSON.'); e2.status = res.status; throw e2; }
        return data == null ? {} : data;
      });
    }, function () {
      var e3 = new Error('Could not reach the OpenGenerator server.'); e3.status = 0; throw e3;
    });
  }
  OGC.api = {
    get: function (path) { return request('GET', path); },
    post: function (path, body) { return request('POST', path, body === undefined ? {} : body); }
  };
  OGC.esc = esc;
  OGC.el = el;
  OGC.on = on;
  OGC.emit = emit;

  // ------------------------------------------------------------------ toast

  var toastRegion = null;
  function toast(message, kind) {
    kind = kind || 'info';
    if (!toastRegion) {
      toastRegion = el('div', {'class': 'ogc-toasts', role: 'status', 'aria-live': 'polite', 'aria-atomic': 'false'});
      document.body.appendChild(toastRegion);
    }
    var item = el('div', {'class': 'ogc-toast ogc-toast-' + kind}, String(message));
    toastRegion.appendChild(item);
    var gone = false;
    function dismiss() {
      if (gone) return; gone = true;
      if (item.parentNode) item.parentNode.removeChild(item);
    }
    item.addEventListener('click', dismiss);
    setTimeout(dismiss, kind === 'error' ? 9000 : 5000);
  }
  OGC.toast = toast;

  // ------------------------------------------------------------------ dialog

  var FOCUSABLE = 'a[href],button:not([disabled]),input:not([disabled]):not([type=hidden]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';

  // OGC.dialog({title, body, buttons}) -> Promise<value>.
  //   body: string or Node. buttons: [{label, value, kind:'primary'|'danger'|'secondary', disabled}].
  //   Resolves with the clicked button's value; Escape, the close button or a click on the backdrop
  //   resolve null. The returned promise also carries .close(value), .el (the dialog element) and
  //   .buttons (array of the button elements, so a caller can enable one after validating input).
  function dialog(opts) {
    opts = opts || {};
    var previous = document.activeElement;
    var resolveFn, closed = false;
    var promise = new Promise(function (resolve) { resolveFn = resolve; });
    var titleId = uid('ogc-dlg-title');
    var buttons = (opts.buttons && opts.buttons.length) ? opts.buttons : [{label: 'OK', value: true, kind: 'primary'}];

    var backdrop = el('div', {'class': 'ogc-dialog-backdrop'});
    var box = el('div', {'class': 'ogc-dialog', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': titleId, tabindex: '-1'});
    var bodyEl = el('div', {'class': 'ogc-dialog-body'});
    if (opts.body && typeof opts.body === 'object' && opts.body.nodeType) bodyEl.appendChild(opts.body);
    else if (opts.body != null) bodyEl.appendChild(el('p', {}, String(opts.body)));
    var btnEls = buttons.map(function (b) {
      var cls = 'btn ogc-btn' + (b.kind === 'primary' || b.kind === 'danger' ? '' : ' secondary') +
                (b.kind === 'danger' ? ' ogc-danger' : '');
      return el('button', {type: 'button', 'class': cls, disabled: !!b.disabled,
                           onclick: function () { close(b.value); }}, b.label);
    });
    box.appendChild(el('h3', {id: titleId, 'class': 'ogc-dialog-title'}, opts.title || ''));
    box.appendChild(bodyEl);
    box.appendChild(el('div', {'class': 'ogc-dialog-buttons'}, btnEls));
    backdrop.appendChild(box);

    function close(value) {
      if (closed) return; closed = true;
      document.removeEventListener('keydown', onKey, true);
      if (backdrop.parentNode) backdrop.parentNode.removeChild(backdrop);
      if (previous && typeof previous.focus === 'function') { try { previous.focus(); } catch (e) { /* gone */ } }
      resolveFn(value === undefined ? null : value);
    }
    function onKey(ev) {
      if (ev.key === 'Escape') { ev.stopPropagation(); ev.preventDefault(); close(null); return; }
      if (ev.key !== 'Tab') return;
      var items = Array.prototype.filter.call(box.querySelectorAll(FOCUSABLE), function (n) { return !n.hidden; });
      if (!items.length) { ev.preventDefault(); box.focus(); return; }
      var first = items[0], last = items[items.length - 1], active = document.activeElement;
      if (!box.contains(active)) { ev.preventDefault(); first.focus(); }
      else if (ev.shiftKey && (active === first || active === box)) { ev.preventDefault(); last.focus(); }
      else if (!ev.shiftKey && active === last) { ev.preventDefault(); first.focus(); }
    }
    backdrop.addEventListener('mousedown', function (ev) { if (ev.target === backdrop) close(null); });
    document.addEventListener('keydown', onKey, true);
    document.body.appendChild(backdrop);
    var firstField = box.querySelector('input:not([disabled]),select,textarea');
    var primary = btnEls[0];
    (firstField || primary || box).focus();

    promise.close = close;
    promise.el = box;
    promise.buttons = btnEls;
    return promise;
  }
  OGC.dialog = dialog;

  // ------------------------------------------------------------------ state

  var ROLES = ['c2', 'payload', 'exfil', 'scanner', 'brute', 'phishing', 'tor', 'compromised', 'vulnerability', 'unknown'];
  var INCLUDE_CORE = ['discovery', 'credential_access', 'lateral_movement', 'exfiltration', 'impact'];
  var INCLUDE_MORE = ['reconnaissance', 'resource_development', 'initial_access', 'execution', 'persistence',
                      'privilege_escalation', 'stealth', 'defense_impairment', 'collection'];
  var INCLUDE_ALL = INCLUDE_CORE.concat(INCLUDE_MORE);

  function defaultOptions() {
    return {address_mode: 'mapped', start: '10:00', speed: 'realistic', compromised: 'ws',
            lateral_target: 'server', beacons_per_c2: 4,
            include: ['discovery', 'credential_access', 'lateral_movement', 'exfiltration']};
  }
  function defaultState() {
    return {iocs: [], dropped: [], name: '', options: defaultOptions(), campaign: null, dirty: false,
            actions: null, step: 'type'};
  }
  OGC.state = defaultState();
  OGC.state.intent = null;       // 'open' when the user chose "Open a saved campaign"; read by the Save & run step
  OGC.state.explain = [];        // explain lines from the last compile (IOC -> stage -> action)

  function slug(text) {
    var s = String(text == null ? '' : text).toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '');
    return s.slice(0, 64);
  }
  function todayIso() {
    var d = new Date();
    function p(n) { return n < 10 ? '0' + n : '' + n; }
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate());
  }
  function cloneOptions(o) {
    var c = JSON.parse(JSON.stringify(o || defaultOptions()));
    if (!Array.isArray(c.include)) c.include = [];
    return c;
  }
  function emptyCampaign(state) {
    state = state || OGC.state;
    var name = (state.name || '').trim() || 'Untitled campaign';
    return {
      schema: 'opengenerator.campaign/1',
      meta: {name: name, id: slug(name) || 'untitled-campaign', description: '', actor: 'Unattributed',
             origin_country: '', created: todayIso(), seed: 1,
             source: {kind: 'hand', feeds: [], ioc_count: 0}},
      options: cloneOptions(state.options),
      iocs: [], stages: [], expect: []
    };
  }

  OGC.setCampaign = function (campaign, opts) {
    opts = opts || {};
    var source = opts.source || 'edit';
    OGC.state.campaign = campaign || null;
    OGC.state.dirty = (source === 'edit');
    if (source === 'compile') OGC.state.explain = Array.isArray(opts.explain) ? opts.explain : [];
    else if (source === 'load' || source === 'import') OGC.state.explain = [];
    emit('campaign', {campaign: OGC.state.campaign, source: source, explain: OGC.state.explain});
  };

  // ------------------------------------------------------------------ IOC logic (pure)

  var LOWER_TYPES = {ipv6: 1, domain: 1, md5: 1, sha1: 1, sha256: 1, email: 1, cve: 1};
  function iocKey(ioc) {
    var v = String(ioc && ioc.value != null ? ioc.value : '');
    var t = String(ioc && ioc.type || '');
    return t + '\u0000' + (LOWER_TYPES[t] ? v.toLowerCase() : v);
  }
  function unionList(a, b) {
    var out = [], seen = {};
    (a || []).concat(b || []).forEach(function (x) {
      if (x != null && !seen[x]) { seen[x] = 1; out.push(x); }
    });
    return out;
  }
  function normaliseIoc(raw) {
    var i = {};
    Object.keys(raw || {}).forEach(function (k) { i[k] = raw[k]; });
    i.type = String(i.type || '');
    i.value = String(i.value == null ? '' : i.value);
    i.role = ROLES.indexOf(i.role) >= 0 ? i.role : 'unknown';
    var c = Number(i.confidence);
    i.confidence = isFinite(c) ? Math.max(0, Math.min(100, Math.round(c))) : 0;
    i.source = i.source == null ? '' : String(i.source);
    i.why = i.why == null ? '' : String(i.why);
    i.tags = Array.isArray(i.tags) ? i.tags : [];
    i.techniques = Array.isArray(i.techniques) ? i.techniques : [];
    if (i._include === undefined) i._include = true;
    return i;
  }
  // Merge incoming into existing (a new array is returned; existing records are not mutated).
  // Duplicates (same type + value) keep the highest-confidence record; the user's include choice
  // and any role the user set by hand are kept either way.
  function mergeIocs(existing, incoming) {
    var list = (existing || []).slice();
    var index = {};
    list.forEach(function (x, n) { index[iocKey(x)] = n; });
    var added = 0, updated = 0, skipped = 0;
    (incoming || []).forEach(function (raw) {
      if (!raw || raw.value == null || String(raw.value) === '') { skipped += 1; return; }
      var inc = normaliseIoc(raw);
      var k = iocKey(inc);
      if (index[k] === undefined) { index[k] = list.length; list.push(inc); added += 1; return; }
      var cur = list[index[k]];
      if (inc.confidence > cur.confidence) {
        var merged = {};
        Object.keys(cur).forEach(function (f) { merged[f] = cur[f]; });
        Object.keys(inc).forEach(function (f) { merged[f] = inc[f]; });
        merged._include = cur._include;
        if (cur._roleEdited) { merged.role = cur.role; merged._roleEdited = true; }
        merged.tags = unionList(cur.tags, inc.tags);
        merged.techniques = unionList(cur.techniques, inc.techniques);
        list[index[k]] = merged;
        updated += 1;
      } else {
        var tags = unionList(cur.tags, inc.tags), techs = unionList(cur.techniques, inc.techniques);
        if (tags.length !== (cur.tags || []).length || techs.length !== (cur.techniques || []).length) {
          var copy = {};
          Object.keys(cur).forEach(function (f) { copy[f] = cur[f]; });
          copy.tags = tags; copy.techniques = techs;
          list[index[k]] = copy;
        }
        skipped += 1;
      }
    });
    return {list: list, added: added, updated: updated, skipped: skipped};
  }
  function mergeDropped(existing, incoming) {
    var seen = {}, out = [];
    (existing || []).concat(incoming || []).forEach(function (d) {
      if (!d) return;
      var item = {value: String(d.value == null ? '' : d.value), reason: String(d.reason == null ? '' : d.reason)};
      var k = item.value + '\u0000' + item.reason;
      if (!seen[k]) { seen[k] = 1; out.push(item); }
    });
    return out;
  }
  function filterIocs(iocs, f) {
    f = f || {};
    var text = String(f.text || '').trim().toLowerCase();
    return (iocs || []).filter(function (i) {
      if (f.role && i.role !== f.role) return false;
      if (f.type && i.type !== f.type) return false;
      if (text) {
        var hay = (i.value + ' ' + (i.source || '') + ' ' + (i.why || '') + ' ' + (i.tags || []).join(' ')).toLowerCase();
        if (hay.indexOf(text) < 0) return false;
      }
      return true;
    });
  }
  function countsByRole(iocs) {
    var c = {};
    ROLES.forEach(function (r) { c[r] = 0; });
    (iocs || []).forEach(function (i) { c[i.role] = (c[i.role] || 0) + 1; });
    return c;
  }
  // The shape POST /api/campaign/compile wants: included records only, UI-only fields removed.
  function stripIoc(i) {
    var o = {};
    Object.keys(i).forEach(function (k) { if (k.charAt(0) !== '_') o[k] = i[k]; });
    return o;
  }
  function includedIocs(iocs) {
    return (iocs || []).filter(function (i) { return i._include !== false; }).map(stripIoc);
  }
  function fileSizeWarning(bytes) {
    if (bytes > 1048576) {
      return 'This file is ' + (bytes / 1048576).toFixed(1) + ' MB. The server accepts up to 1 MB of text per request, so it may be refused; split it if it is.';
    }
    return '';
  }
  function fmtCount(n, word) { return n + ' ' + word + (n === 1 ? '' : 's'); }

  OGC._test = {
    esc: esc, defaultOptions: defaultOptions, defaultState: defaultState, emptyCampaign: emptyCampaign,
    slug: slug, iocKey: iocKey, mergeIocs: mergeIocs, mergeDropped: mergeDropped, filterIocs: filterIocs,
    countsByRole: countsByRole, includedIocs: includedIocs, stripIoc: stripIoc, normaliseIoc: normaliseIoc,
    fileSizeWarning: fileSizeWarning, ROLES: ROLES
  };

  // ------------------------------------------------------------------ catalog (lazy)

  var actionsPromise = null;
  OGC.loadActions = function () {
    if (OGC.state.actions) return Promise.resolve(OGC.state.actions);
    if (actionsPromise) return actionsPromise;
    actionsPromise = OGC.api.get('/api/campaign/actions').then(function (data) {
      OGC.state.actions = data;
      actionsPromise = null;
      emit('actions', data);
      return data;
    }, function (err) {
      actionsPromise = null;           // allow a retry on the next call
      OGC.state.actionsError = err.message;
      return null;
    });
    return actionsPromise;
  };

  // ------------------------------------------------------------------ generate / results hooks

  // index.html merges this into the POST /api/generate body. campaigns-library.js replaces it.
  OGC.generateExtras = function () { return {}; };
  // OGC.renderResults(summary, container) is defined by campaigns-library.js.

  // ------------------------------------------------------------------ steps and stepper

  var STEPS = [{id: 'type', title: 'Type'}, {id: 'indicators', title: 'Indicators'},
               {id: 'build', title: 'Build'}, {id: 'save', title: 'Save & run'}];
  var registered = {};       // id -> {id,title,mount,onEnter,canLeave,container}
  var stepperEl = null, panelsEl = null, fold = null;

  function renderStepper() {
    if (!stepperEl) return;
    clear(stepperEl);
    STEPS.forEach(function (s, n) {
      var reg = registered[s.id];
      var cur = OGC.state.step === s.id;
      var btn = el('button', {type: 'button',
        'class': 'ogc-step' + (cur ? ' is-current' : '') + (reg ? '' : ' is-off'),
        disabled: !reg,
        title: reg ? '' : 'Not available in this build',
        'aria-current': cur ? 'step' : null,
        onclick: function () { OGC.goto(s.id); }},
        el('span', {'class': 'ogc-step-n', 'aria-hidden': 'true'}, String(n + 1)),
        el('span', {'class': 'ogc-step-t'}, (reg && reg.title) || s.title));
      stepperEl.appendChild(el('li', {}, btn));
    });
  }

  function ensurePanel(def) {
    if (!panelsEl || def.container) return;
    def.container = el('section', {'class': 'ogc-panel', id: 'ogc-step-' + def.id});
    def.container.hidden = OGC.state.step !== def.id;
    panelsEl.appendChild(def.container);
    // keep panels in step order
    STEPS.forEach(function (s) { var r = registered[s.id]; if (r && r.container) panelsEl.appendChild(r.container); });
    try { if (typeof def.mount === 'function') def.mount(def.container); }
    catch (e) { def.container.appendChild(el('p', {'class': 'ogc-row-err'}, 'This step failed to load: ' + e.message)); }
  }

  // Modules call this when they load. Scripts that load before the page is ready are mounted by init().
  OGC.registerStep = function (def) {
    if (!def || !def.id) return;
    var known = STEPS.some(function (s) { return s.id === def.id; });
    if (!known) STEPS.push({id: def.id, title: def.title || def.id});
    registered[def.id] = def;
    ensurePanel(def);
    renderStepper();
  };

  function stayOrLeave(message) {
    return OGC.dialog({
      title: 'Leave this step?',
      body: el('p', {}, String(message)),
      buttons: [{label: 'Stay', value: false, kind: 'primary'}, {label: 'Leave anyway', value: true, kind: 'secondary'}]
    }).then(function (v) { return v === true; });
  }

  // goto resolves true when the step changed (or was already current), false when it was refused.
  OGC.goto = function (stepId) {
    var target = registered[stepId];
    if (!target) { toast('That step is not available in this build.', 'error'); return Promise.resolve(false); }
    if (OGC.state.step === stepId) { return Promise.resolve(true); }
    var cur = registered[OGC.state.step];
    var verdict = true;
    if (cur && typeof cur.canLeave === 'function') {
      try { verdict = cur.canLeave(); } catch (e) { verdict = true; }
    }
    var gate = (typeof verdict === 'string' && verdict) ? stayOrLeave(verdict) : Promise.resolve(verdict !== false);
    return gate.then(function (ok) {
      if (!ok) return false;
      var from = OGC.state.step;
      OGC.state.step = stepId;
      STEPS.forEach(function (s) { var r = registered[s.id]; if (r && r.container) r.container.hidden = (s.id !== stepId); });
      if (fold && !fold.open) fold.open = true;
      renderStepper();
      if (stepperEl && from && from !== stepId) { try { stepperEl.scrollIntoView({block: 'nearest', behavior: 'smooth'}); } catch (e) {} }
      if (stepId !== 'type') OGC.loadActions();
      emit('step', {step: stepId, from: from, intent: OGC.state.intent});
      try { if (typeof target.onEnter === 'function') target.onEnter(); }
      catch (e) { if (window.console) console.error('onEnter failed', e); }
      return true;
    });
  };

  // ------------------------------------------------------------------ step 1: Type

  function tipEl(text) {
    return el('span', {'class': 'tiptag', 'data-tip': text, tabindex: '0', role: 'note'}, '?');
  }

  function mountType(box) {
    function choice(title, text, label, handler) {
      return el('div', {'class': 'ogc-choice'},
        el('h3', {}, title), el('p', {'class': 'hint'}, text),
        el('button', {type: 'button', 'class': 'btn secondary ogc-btn', onclick: handler}, label));
    }
    box.appendChild(el('div', {'class': 'ogc-grid ogc-grid-3'},
      choice('Build from indicators',
        'Start from threat indicators (addresses, domains, hashes) from a public feed, a pasted list or a file. ' +
        'The builder sorts them into roles and drafts the stages for you to edit.',
        'Choose indicators', function () { OGC.goto('indicators'); }),
      choice('Open a saved campaign',
        'Reload a campaign you saved before, or import a campaign file, and continue from where you stopped.',
        'Open the library', function () {
          OGC.state.intent = 'open';
          OGC.goto('save').then(function (ok) { if (!ok) OGC.state.intent = null; });
        }),
      choice('Start from scratch',
        'Begin with an empty campaign and add the stages and actions yourself in the editor.',
        'Start empty', function () {
          OGC.setCampaign(emptyCampaign(OGC.state), {source: 'edit'});
          OGC.state.explain = [];      // a fresh campaign has nothing to explain from an earlier compile
          OGC.state.dirty = false;
          OGC.state.intent = null;
          OGC.goto('build');
        })));
  }

  // ------------------------------------------------------------------ step 2: Indicators

  var IOC_TYPES = ['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'email', 'cve', 'filename', 'cidr'];
  var ROW_CAP = 500;
  var GROUP_ORDER = ['abuse.ch', 'C2', 'MISP feeds', 'Community', 'Reputation', 'Brute force', 'Phishing',
                     'Anonymisation', 'Vulnerabilities', 'Custom'];

  function mountIndicators(box) {
    var keys = {};                       // feed id -> API key; lives only here, never stored or logged
    var ctl = {limit: 50, offline: false};
    var filter = {role: '', type: '', text: ''};
    var shown = ROW_CAP;
    var busy = false;
    var fetchButtons = [];               // {btn, feed} so labels follow the limit selector
    var allButtons = [];
    // optional macOS Keychain storage, shown only when the server says it is available
    var vault = {available: false, stored: []};
    var vaultWatchers = [];
    function vaultId(feed) { return 'feed:' + feed.id; }
    function vaultHas(feed) { return vault.stored.indexOf(vaultId(feed)) >= 0; }
    function vaultChanged() { vaultWatchers.forEach(function (f) { f(); }); }

    // ---- section A: get indicators
    var statusLine = el('p', {'class': 'ogc-status', role: 'status', 'aria-live': 'polite'});
    function say(text, kind) {
      statusLine.className = 'ogc-status' + (kind === 'err' ? ' ogc-row-err' : kind === 'ok' ? ' ogc-ok' : '');
      statusLine.textContent = text;
    }
    function setBusy(b) {
      busy = b;
      allButtons.forEach(function (x) { x.disabled = b; });
      box.classList.toggle('is-busy', b);
      renderSummary();
    }

    var limitSel = el('select', {id: 'ogc-limit', onchange: function () {
      ctl.limit = parseInt(limitSel.value, 10) || 50;
      fetchButtons.forEach(function (fb) { fb.btn.textContent = 'Fetch ' + ctl.limit; });
    }}, [25, 50, 100, 250, 500].map(function (n) {
      return el('option', {value: String(n), selected: n === 50}, String(n));
    }));
    var offlineBox = el('input', {type: 'checkbox', id: 'ogc-offline', onchange: function () { ctl.offline = offlineBox.checked; }});
    var feedsBox = el('div', {'class': 'ogc-feeds'}, el('p', {'class': 'hint'}, 'Loading the feed list\u2026'));

    function absorb(res, label) {
      if (res.error) { say(label + ': ' + res.error, 'err'); return; }
      var incoming = Array.isArray(res.iocs) ? res.iocs : [];
      var m = mergeIocs(OGC.state.iocs, incoming);
      OGC.state.iocs = m.list;
      OGC.state.dropped = mergeDropped(OGC.state.dropped, res.dropped);
      var parts = [label + ': ' + fmtCount(incoming.length, 'indicator') + ' received'];
      parts.push(m.added + ' new');
      if (m.updated) parts.push(m.updated + ' replaced by a higher-confidence copy');
      if (m.skipped) parts.push(m.skipped + ' already listed');
      if (res.formats) parts.push('format: ' + res.formats);
      if (res.dropped && res.dropped.length) parts.push(res.dropped.length + ' dropped');
      say(parts.join('; ') + '.', incoming.length ? 'ok' : 'info');
      shown = ROW_CAP;
      emit('iocs', {iocs: OGC.state.iocs});
      renderAll();
    }

    function fetchFeed(feed, ui) {
      if (busy) return;
      var body = {feed: feed.id, limit: ctl.limit, q: '', url: '', days: 0, key: '', offline: ctl.offline};
      if (feed.needs_key && !ctl.offline) {
        var k = keys[feed.id] || '';
        if (!k && ui.vaultHas && ui.vaultHas()) body.use_stored = true;       // the server reads the saved key
        else if (!k) { say(feed.title + ' needs an API key. Type it in the key box next to the button; it stays in this page and is sent only with this request.', 'err'); ui.key.focus(); return; }
        if (k) body.key = k;
      }
      if (ui.q) body.q = ui.q.value.trim();
      if (ui.days) body.days = parseInt(ui.days.value, 10) || 0;
      if (ui.url) {
        body.url = ui.url.value.trim();
        if (!body.url) { say('Type the https:// address of a list first.', 'err'); ui.url.focus(); return; }
      }
      setBusy(true); say('Fetching ' + feed.title + '\u2026');
      var saved = Promise.resolve();
      if (body.key && ui.remember && ui.remember.checked && vault.available && !vaultHas(feed)) {
        saved = OGC.api.post('/api/keys/save', {id: vaultId(feed), key: body.key}).then(function () {
          vault.stored.push(vaultId(feed)); keys[feed.id] = ''; if (ui.key) ui.key.value = ''; ui.remember.checked = false;
          vaultChanged();
        }, function (err) {
          say(String(err && err.message || 'The key was not saved.').split(body.key).join('[key]') + ' The typed key is used this time only.', 'err');
        });
      }
      saved.then(function () { return OGC.api.post('/api/intel/fetch', body); }).then(function (res) {
        absorb(res, feed.title);
      }, function (err) {
        say(feed.title + ': ' + err.message, 'err'); toast(err.message, 'error');
      }).then(function () { setBusy(false); });
    }

    function feedRow(feed) {
      var ui = {};
      var lab = el('span', {'class': 'ogc-feed-title'}, feed.title);
      var btn = el('button', {type: 'button', 'class': 'btn secondary ogc-btn ogc-sm',
        title: feed.note || '', onclick: function () { fetchFeed(feed, ui); }}, 'Fetch ' + ctl.limit);
      fetchButtons.push({btn: btn, feed: feed}); allButtons.push(btn);
      var extras = [];
      if (feed.needs_key) {
        ui.key = el('input', {type: 'password', autocomplete: 'off', spellcheck: 'false', 'class': 'ogc-key',
          placeholder: 'API key' + (feed.key_env ? ' (' + feed.key_env + ')' : ''),
          'aria-label': 'API key for ' + feed.title,
          oninput: function () { keys[feed.id] = ui.key.value; }});
        extras.push(ui.key);
        ui.vaultHas = function () { return vaultHas(feed); };
        ui.remember = el('input', {type: 'checkbox', id: uid('ogc-rem'), 'aria-label': 'Remember the key for ' + feed.title + ' in the macOS Keychain'});
        ui.vaultBox = el('span', {'class': 'ogc-vault'});
        var refreshVault = function () {
          clear(ui.vaultBox);
          if (!vault.available) return;
          if (vaultHas(feed)) {
            ui.vaultBox.appendChild(el('span', {'class': 'hint'}, 'Using the saved key. '));
            ui.vaultBox.appendChild(el('button', {type: 'button', 'class': 'ogc-link', 'aria-label': 'Forget the saved key for ' + feed.title, onclick: function () {
              OGC.api.post('/api/keys/forget', {id: vaultId(feed)}).then(function () {
                vault.stored = vault.stored.filter(function (x) { return x !== vaultId(feed); }); vaultChanged();
              }, function (err) { say(err.message, 'err'); });
            }}, 'Forget'));
          } else {
            ui.vaultBox.appendChild(ui.remember);
            ui.vaultBox.appendChild(el('label', {'for': ui.remember.getAttribute('id'), 'class': 'hint'}, ' Remember in the macOS Keychain'));
          }
        };
        vaultWatchers.push(refreshVault);
        refreshVault();
        extras.push(ui.vaultBox);
      }
      if (feed.id === 'otx') {
        ui.q = el('input', {type: 'text', 'class': 'ogc-q', placeholder: 'search pulses (optional)', 'aria-label': 'Search ' + feed.title,
          onkeydown: function (ev) { if (ev.key === 'Enter') fetchFeed(feed, ui); }});
        extras.push(ui.q);
      }
      if (feed.id === 'threatfox') {
        ui.days = el('input', {type: 'number', min: '0', max: '90', 'class': 'ogc-days', placeholder: 'days', 'aria-label': 'Days back (0 = default)'});
        extras.push(ui.days);
      }
      if (feed.id === 'url') {
        ui.url = el('input', {type: 'text', 'class': 'ogc-url', placeholder: 'https://example.org/list.txt', 'aria-label': 'Address of a list',
          onkeydown: function (ev) { if (ev.key === 'Enter') fetchFeed(feed, ui); }});
        extras.push(ui.url);
      }
      // the verification note is an info badge beside the title, not a line under every feed
      var lead = el('span', {'class': 'ogc-feed-lead'}, lab, feed.note ? tipEl(feed.note) : null);
      return el('div', {'class': 'ogc-feed'},
        el('div', {'class': 'ogc-feed-head'}, lead, btn),
        extras.length ? el('div', {'class': 'ogc-feed-extra'}, extras) : null);
    }

    function renderFeeds(feeds) {
      clear(feedsBox);
      if (!feeds.some(function (f) { return f.id === 'url'; })) {
        feeds = feeds.concat([{id: 'url', title: 'From a URL', group: 'Custom', needs_key: false, note: 'Any https:// list or feed file.'}]);
      }
      var groups = {};
      feeds.forEach(function (f) { var g = f.group || 'Other'; (groups[g] = groups[g] || []).push(f); });
      var names = Object.keys(groups).sort(function (a, b) {
        var ia = GROUP_ORDER.indexOf(a), ib = GROUP_ORDER.indexOf(b);
        return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib) || (a < b ? -1 : a > b ? 1 : 0);
      });
      names.forEach(function (g) {
        feedsBox.appendChild(el('fieldset', {'class': 'ogc-group'},
          el('legend', {}, g), groups[g].map(feedRow)));
      });
    }

    var feedsFold = el('details', {'class': 'ogc-sub', open: true},
      el('summary', {}, 'Public feeds'),
      el('div', {'class': 'ogc-feedctl'},
        el('label', {'for': 'ogc-limit', 'class': 'ogc-inline'}, 'Indicators per fetch ', limitSel),
        el('label', {'class': 'ogc-check', 'for': 'ogc-offline'}, offlineBox, ' Offline (cache only)')),
      feedsBox);

    // paste + file
    var pasteArea = el('textarea', {id: 'ogc-paste', rows: '5', spellcheck: 'false', 'class': 'ogc-paste',
      placeholder: 'Paste addresses, domains, URLs, hashes, or a CSV / STIX / MISP / OTX / ThreatFox export. The format is detected.',
      'aria-label': 'Paste indicators'});
    var fileInput = el('input', {type: 'file', 'class': 'ogc-hidden', accept: '.txt,.csv,.json,.stix,.xml,.tsv,.ioc,text/*,application/json',
      'aria-label': 'Load indicators from a file', tabindex: '-1',
      onchange: function () {
        var f = fileInput.files && fileInput.files[0];
        if (!f) return;
        var warn = fileSizeWarning(f.size);
        var reader = new FileReader();
        reader.onload = function () {
          sendParse(String(reader.result || ''), f.name, f.name, warn);
        };
        reader.onerror = function () { say('Could not read ' + f.name + '.', 'err'); };
        reader.readAsText(f);
        fileInput.value = '';
      }});
    function sendParse(text, filename, source, warn) {
      if (busy) return;
      if (!text.trim()) { say('There is nothing to parse yet. Paste a list or load a file.', 'err'); return; }
      setBusy(true); say('Reading indicators\u2026' + (warn ? ' ' + warn : ''));
      OGC.api.post('/api/intel/parse', {text: text, filename: filename || '', source: source || 'paste'}).then(function (res) {
        absorb(res, filename || 'Pasted text');
        var nIn = Array.isArray(res.iocs) ? res.iocs.length : 0;
        var nLines = String(text).split(/\r?\n/).filter(function (l) { var t = l.trim(); return t && t.charAt(0) !== '#'; }).length;
        if (!res.error && !filename && nLines > nIn) say(statusLine.textContent + ' ' + (nLines - nIn) + ' of ' + nLines + ' pasted lines were not recognised as indicators and were left out.', 'info');
        if (warn) say(statusLine.textContent + ' ' + warn, 'info');
      }, function (err) {
        say((filename || 'Pasted text') + ': ' + err.message + (warn ? ' ' + warn : ''), 'err'); toast(err.message, 'error');
      }).then(function () { setBusy(false); });
    }
    var addBtn = el('button', {type: 'button', 'class': 'btn secondary ogc-btn ogc-sm', onclick: function () {
      sendParse(pasteArea.value, '', 'paste', '');
    }}, 'Add pasted indicators');
    var loadBtn = el('button', {type: 'button', 'class': 'btn secondary ogc-btn ogc-sm', onclick: function () { fileInput.click(); }}, 'Load file\u2026');
    allButtons.push(addBtn, loadBtn);
    var pasteFold = el('details', {'class': 'ogc-sub', open: true},
      el('summary', {}, 'Paste or load a file'),
      pasteArea,
      el('div', {'class': 'ogc-actions'}, addBtn, loadBtn, fileInput,
        tipEl('Text files only. Defanged values such as hxxp:// and [.] are cleaned up.')));

    // ---- section B: the table
    var chipsBox = el('div', {'class': 'ogc-chips', role: 'group', 'aria-label': 'Indicators per role'});
    var summaryEl = el('p', {'class': 'ogc-summary', role: 'status', 'aria-live': 'polite'});
    var roleFilter = el('select', {id: 'ogc-f-role', 'aria-label': 'Filter by role', onchange: function () { filter.role = roleFilter.value; shown = ROW_CAP; renderTable(); }},
      el('option', {value: ''}, 'All roles'), ROLES.map(function (r) { return el('option', {value: r}, r); }));
    var typeFilter = el('select', {id: 'ogc-f-type', 'aria-label': 'Filter by type', onchange: function () { filter.type = typeFilter.value; shown = ROW_CAP; renderTable(); }},
      el('option', {value: ''}, 'All types'), IOC_TYPES.map(function (t) { return el('option', {value: t}, t); }));
    var textFilter = el('input', {type: 'text', id: 'ogc-f-text', placeholder: 'filter text', 'aria-label': 'Filter by text',
      oninput: function () { filter.text = textFilter.value; shown = ROW_CAP; renderTable(); }});
    var tbody = el('tbody');
    var moreBtn = el('button', {type: 'button', 'class': 'btn secondary ogc-btn ogc-sm', onclick: function () { shown += ROW_CAP; renderTable(); }}, 'Show more');
    var moreBox = el('div', {'class': 'ogc-more'}, moreBtn);
    var emptyNote = el('p', {'class': 'hint ogc-empty'}, 'No indicators yet. Fetch a feed or paste a list above.');
    var droppedBox = el('details', {'class': 'ogc-sub ogc-dropped'});

    function filtered() { return filterIocs(OGC.state.iocs, filter); }

    function selectShown(flag) {
      filtered().forEach(function (i) { i._include = flag; });
      emit('iocs', {iocs: OGC.state.iocs}); renderTable();
    }
    function removeWhere(pred, what) {
      var n = OGC.state.iocs.filter(pred).length;
      if (!n) { toast('Nothing to remove.', 'info'); return; }
      OGC.dialog({title: 'Remove indicators?',
        body: 'Remove ' + fmtCount(n, 'indicator') + ' (' + what + ') from this list? They can be fetched again later.',
        buttons: [{label: 'Remove', value: true, kind: 'danger'}, {label: 'Cancel', value: false, kind: 'secondary'}]
      }).then(function (ok) {
        if (ok !== true) return;
        OGC.state.iocs = OGC.state.iocs.filter(function (i) { return !pred(i); });
        emit('iocs', {iocs: OGC.state.iocs}); renderAll();
      });
    }
    var barBtns = [
      el('button', {type: 'button', 'class': 'btn secondary ogc-btn ogc-sm', onclick: function () { selectShown(true); }}, 'Select all shown'),
      el('button', {type: 'button', 'class': 'btn secondary ogc-btn ogc-sm', onclick: function () { selectShown(false); }}, 'Select none shown'),
      el('button', {type: 'button', 'class': 'btn secondary ogc-btn ogc-sm', onclick: function () {
        var set = {}; filtered().forEach(function (i) { set[iocKey(i)] = 1; });
        removeWhere(function (i) { return set[iocKey(i)] && i._include !== false; }, 'selected and shown');
      }}, 'Remove selected'),
      el('button', {type: 'button', 'class': 'btn secondary ogc-btn ogc-sm', onclick: function () {
        removeWhere(function () { return true; }, 'all of them');
      }}, 'Clear all')
    ];

    var table = el('table', {'class': 'ogc-table ogc-iocs'},
      el('thead', {}, el('tr', {},
        el('th', {scope: 'col', 'class': 'ogc-c-use'}, 'Use'), el('th', {scope: 'col'}, 'Role'),
        el('th', {scope: 'col', 'class': 'ogc-c-wire'}, 'Wire'), el('th', {scope: 'col'}, 'Type'),
        el('th', {scope: 'col'}, 'Value'), el('th', {scope: 'col', 'class': 'ogc-c-num'}, 'Conf.'), el('th', {scope: 'col'}, 'Source'),
        el('th', {scope: 'col'}, 'Why'))),
      tbody);

    function renderChips() {
      clear(chipsBox);
      var counts = countsByRole(OGC.state.iocs);
      ROLES.forEach(function (r) {
        if (!counts[r]) return;
        chipsBox.appendChild(el('button', {type: 'button', 'class': 'ogc-chip' + (filter.role === r ? ' is-on' : ''),
          'aria-pressed': filter.role === r ? 'true' : 'false',
          title: 'Show only ' + r,
          onclick: function () {
            filter.role = (filter.role === r) ? '' : r; roleFilter.value = filter.role; shown = ROW_CAP; renderTable();
          }}, r + ' ', el('b', {}, String(counts[r]))));
      });
    }
    function renderSummary() {
      var total = OGC.state.iocs.length;
      var used = OGC.state.iocs.filter(function (i) { return i._include !== false; }).length;
      summaryEl.textContent = total
        ? fmtCount(total, 'indicator') + ' listed, ' + used + ' selected for the campaign.'
        : '';
      compileBtn.disabled = busy || used === 0;
      compileHint.textContent = used === 0 ? 'Select at least one indicator to compile.' : '';
    }
    // ---- observability: will each indicator actually put packets on the wire? The verdict is the
    //      engine's (POST /api/campaign/observability, debounced on edits); a tiny static fallback
    //      covers the kinds that never produce traffic so the badge is right instantly. SSOT:
    //      compiler.observability. A vulnerability/CVE or a bare hash is carried, not generated.
    var obsCache = {}, obsTimer = null;
    function obsKey(i) { return i.type + '\u0000' + String(i.value == null ? '' : i.value).toLowerCase(); }
    function staticVerdict(i) {
      if (i.type === 'cve' || i.role === 'vulnerability')
        return {observable: false, reason: 'a vulnerability is a detection expectation, not traffic: only its exploitation would be observable'};
      if (i.type !== 'ipv4' && i.type !== 'domain' && i.type !== 'url')
        return {observable: false, reason: 'a ' + i.type + ' is carried for traceability only: only an action that uses it is observable'};
      return null;                                  // wire-capable: wait for the engine verdict
    }
    function obsVerdict(i) { return obsCache[obsKey(i)] || staticVerdict(i); }
    function wireBadge(i) {
      var v = obsVerdict(i);
      if (!v) return el('span', {'class': 'ogc-wire is-pending', title: 'Checking whether this produces traffic…'}, '…');
      return el('span', {'class': 'ogc-wire ' + (v.observable ? 'is-yes' : 'is-no'), title: v.reason || ''},
        v.observable ? '● on the wire' : '○ no traffic');
    }
    function scheduleObservability() { if (obsTimer) clearTimeout(obsTimer); obsTimer = setTimeout(refreshObservability, 450); }
    function refreshObservability() {
      obsTimer = null;
      var inc = includedIocs(OGC.state.iocs);
      if (!inc.length) { obsCache = {}; renderTable(); return; }
      OGC.api.post('/api/campaign/observability', {iocs: inc, options: cloneOptions(OGC.state.options)}).then(function (res) {
        var m = {};
        ((res && res.observability) || []).forEach(function (v) {
          m[v.type + '\u0000' + String(v.value == null ? '' : v.value).toLowerCase()] = {observable: !!v.observable, reason: v.reason};
        });
        obsCache = m; renderTable();
      }, function () { /* keep the last good verdicts on a transient error */ });
    }
    function renderTable() {
      renderChips(); renderSummary();
      var rows = filtered();
      clear(tbody);
      var slice = rows.slice(0, shown);
      slice.forEach(function (i) {
        var cb = el('input', {type: 'checkbox', checked: i._include !== false, 'aria-label': 'Use ' + i.value,
          onchange: function () { i._include = cb.checked; renderChips(); renderSummary(); emit('iocs', {iocs: OGC.state.iocs}); scheduleObservability(); }});
        var sel = el('select', {'aria-label': 'Role of ' + i.value, onchange: function () {
          i.role = sel.value; i._roleEdited = true; renderChips(); emit('iocs', {iocs: OGC.state.iocs}); scheduleObservability();
        }}, ROLES.map(function (r) { return el('option', {value: r, selected: r === i.role}, r); }));
        tbody.appendChild(el('tr', {},
          el('td', {'class': 'ogc-c-use'}, cb), el('td', {}, sel),
          el('td', {'class': 'ogc-c-wire'}, wireBadge(i)), el('td', {}, i.type),
          el('td', {'class': 'ogc-value', title: i.value}, i.value),
          el('td', {'class': 'ogc-c-num'}, String(i.confidence)),
          el('td', {'class': 'ogc-trunc', title: i.source}, i.source),
          el('td', {'class': 'ogc-trunc ogc-why', title: i.why}, i.why)));
      });
      table.hidden = OGC.state.iocs.length === 0;
      emptyNote.hidden = OGC.state.iocs.length !== 0;
      moreBox.hidden = rows.length <= shown;
      if (rows.length > shown) moreBtn.textContent = 'Show more (' + (rows.length - shown) + ' not shown)';
      if (OGC.state.iocs.length && !rows.length) { tbody.appendChild(el('tr', {}, el('td', {colspan: '8', 'class': 'hint'}, 'No indicator matches the filters.'))); }
    }
    function renderDropped() {
      clear(droppedBox);
      var d = OGC.state.dropped;
      droppedBox.hidden = d.length === 0;
      if (!d.length) return;
      droppedBox.appendChild(el('summary', {}, 'Dropped (' + d.length + ')'));
      droppedBox.appendChild(el('p', {'class': 'hint'}, 'Removed before listing: private or reserved addresses, allow-listed names and duplicates.'));
      var list = el('ul', {'class': 'ogc-droplist'});
      d.slice(0, 200).forEach(function (x) {
        list.appendChild(el('li', {}, el('code', {title: x.value}, x.value.length > 80 ? x.value.slice(0, 80) + '\u2026' : x.value), ' \u2013 ' + x.reason));
      });
      droppedBox.appendChild(list);
      if (d.length > 200) droppedBox.appendChild(el('p', {'class': 'hint'}, (d.length - 200) + ' more not shown.'));
    }
    function renderAll() { renderTable(); renderDropped(); scheduleObservability(); }

    // ---- section C: compile
    var opts = OGC.state.options;
    function optSelect(id, values, key, labelOf) {
      return el('select', {id: id, onchange: function (ev) { opts[key] = ev.target.value; }},
        values.map(function (v) { return el('option', {value: v, selected: opts[key] === v}, labelOf ? labelOf(v) : v); }));
    }
    var nameInput = el('input', {type: 'text', id: 'ogc-name', maxlength: '80', placeholder: 'Untitled campaign', value: OGC.state.name,
      oninput: function () { OGC.state.name = nameInput.value; }});
    var compromised = optSelect('ogc-o-comp', ['ws', 'ws2', 'any_ws', 'server', 'file', 'sql', 'web', 'dc'], 'compromised');
    var lateral = el('input', {type: 'text', id: 'ogc-o-lat', list: 'ogc-lat-list', value: opts.lateral_target, maxlength: '40',
      oninput: function () { opts.lateral_target = lateral.value.trim() || 'server'; }});
    var latList = el('datalist', {id: 'ogc-lat-list'}, ['server', 'dc', 'file', 'sql', 'web', 'ws2', 'host:FILE1'].map(function (v) { return el('option', {value: v}); }));
    var beacons = el('input', {type: 'number', id: 'ogc-o-beac', min: '1', max: '50', value: String(opts.beacons_per_c2),
      oninput: function () { var n = parseInt(beacons.value, 10); if (isFinite(n)) opts.beacons_per_c2 = Math.max(1, Math.min(50, n)); }});
    var startTime = el('input', {type: 'time', id: 'ogc-o-start', value: opts.start,
      oninput: function () { if (/^\d\d:\d\d$/.test(startTime.value)) opts.start = startTime.value; }});
    var speed = optSelect('ogc-o-speed', ['realistic', 'fast'], 'speed', function (v) { return v === 'realistic' ? 'realistic (hours)' : 'fast (minutes)'; });
    var INC_LABELS = {discovery: 'Discovery', credential_access: 'Credential access', lateral_movement: 'Lateral movement', exfiltration: 'Exfiltration', impact: 'Impact',
      reconnaissance: 'Reconnaissance', resource_development: 'Resource development', initial_access: 'Initial access', execution: 'Execution',
      persistence: 'Persistence', privilege_escalation: 'Privilege escalation', stealth: 'Stealth', defense_impairment: 'Defense impairment', collection: 'Collection'};
    function incGroup(keys) {
      return el('div', {'class': 'ogc-checks'}, keys.map(function (k) {
        var cb = el('input', {type: 'checkbox', checked: opts.include.indexOf(k) >= 0, onchange: function () {
          var s = opts.include.filter(function (x) { return x !== k; });
          if (cb.checked) s.push(k);
          opts.include = INCLUDE_ALL.filter(function (x) { return s.indexOf(x) >= 0; });
          scheduleObservability();
        }});
        return el('label', {'class': 'ogc-check'}, cb, ' ' + INC_LABELS[k]);
      }));
    }
    var incBoxes = el('div', {}, incGroup(INCLUDE_CORE),
      el('p', {'class': 'ogc-sub'}, 'More tactics (off by default, each adds its own stage):'), incGroup(INCLUDE_MORE));
    var familySel = el('select', {id: 'ogc-o-family', onchange: function (ev) { opts.family = ev.target.value; }});
    function fillFamilies(data) {
      var cur = opts.family || 'auto';
      familySel.textContent = '';
      familySel.appendChild(el('option', {value: 'auto'}, 'Automatic (from indicator tags)'));
      familySel.appendChild(el('option', {value: 'none'}, 'None (generic beacon look)'));
      ((data && data.families) || []).forEach(function (f) { familySel.appendChild(el('option', {value: f.id}, f.name + ' look-alike')); });
      familySel.value = cur;
      if (familySel.value !== cur) familySel.value = 'auto';
    }
    fillFamilies(OGC.state.actions);
    OGC.loadActions().then(fillFamilies);
    var realNote = el('p', {'class': 'ogc-warn', hidden: true, role: 'status'},
      'Real addresses recorded. Indicators keep their true public addresses in the capture. You will be asked to confirm this on the Save & run step, and nothing is written with real addresses until then.');
    function addrRadio(value, text) {
      var r = el('input', {type: 'radio', name: 'ogc-addr', value: value, checked: opts.address_mode === value, onchange: function () {
        if (r.checked) { opts.address_mode = value; realNote.hidden = value !== 'real'; scheduleObservability(); }
      }});
      return el('label', {'class': 'ogc-check'}, r, ' ' + text);
    }
    realNote.hidden = opts.address_mode !== 'real';
    var addrBox = el('div', {'class': 'ogc-checks'},
      addrRadio('mapped', 'Mapped (indicator addresses are moved into a benchmark range; recommended)'),
      addrRadio('real', 'Real addresses'));

    var compileMsg = el('div', {'class': 'ogc-compile-out', role: 'status', 'aria-live': 'polite'});
    var compileHint = el('span', {'class': 'hint'});
    var compileBtn = el('button', {type: 'button', 'class': 'btn ogc-btn', onclick: function () { compile(); }}, 'Compile campaign');
    allButtons.push(compileBtn);

    function showCompile(res, campaign) {
      clear(compileMsg);
      var errs = Array.isArray(res.errors) ? res.errors : [];
      var s = res.summary || {};
      if (errs.length) {
        compileMsg.appendChild(el('div', {'class': 'ogc-row-err'}, el('b', {}, 'The compile reported problems'),
          el('ul', {}, errs.slice(0, 50).map(function (e) { return el('li', {}, String(e)); }))));
      }
      if (campaign) {
        compileMsg.appendChild(el('p', {'class': 'ogc-ok'}, 'Drafted ' + fmtCount(s.stages != null ? s.stages : (campaign.stages || []).length, 'stage') +
          ', ' + fmtCount(s.actions != null ? s.actions : 0, 'action') + ' from ' + fmtCount(s.iocs != null ? s.iocs : (campaign.iocs || []).length, 'indicator') +
          (s.skipped ? ' (' + s.skipped + ' not used)' : '') + '.'));
      }
      var ex = Array.isArray(res.explain) ? res.explain : [];
      if (ex.length) {
        compileMsg.appendChild(el('details', {'class': 'ogc-sub'}, el('summary', {}, 'How the indicators were used (' + ex.length + ')'),
          el('ul', {'class': 'ogc-explain'}, ex.slice(0, 300).map(function (l) { return el('li', {}, String(l)); }))));
      }
    }
    function compile() {
      if (busy) return;
      var inc = includedIocs(OGC.state.iocs);
      if (!inc.length) { say('Select at least one indicator first.', 'err'); return; }
      setBusy(true); clear(compileMsg); compileMsg.appendChild(el('p', {'class': 'hint'}, 'Compiling\u2026'));
      OGC.api.post('/api/campaign/compile', {iocs: inc, options: cloneOptions(OGC.state.options), name: (OGC.state.name || '').trim()}).then(function (res) {
        var campaign = res.campaign || null;
        showCompile(res, campaign);
        var errs = Array.isArray(res.errors) ? res.errors : [];
        if (campaign && !errs.length) {
          OGC.setCampaign(campaign, {source: 'compile', explain: res.explain});
          OGC.goto('build');
        } else if (campaign) {
          compileMsg.appendChild(el('button', {type: 'button', 'class': 'btn secondary ogc-btn ogc-sm', onclick: function () {
            OGC.setCampaign(campaign, {source: 'compile', explain: res.explain}); OGC.goto('build');
          }}, 'Open it in the editor anyway'));
        }
      }, function (err) {
        clear(compileMsg);
        compileMsg.appendChild(el('p', {'class': 'ogc-row-err'}, err.message));
        toast(err.message, 'error');
      }).then(function () { setBusy(false); renderSummary(); });
    }

    var compilePanel = el('div', {'class': 'ogc-compile'},
      el('h3', {}, 'Compile a campaign'),
      el('div', {'class': 'ogc-grid ogc-grid-3'},
        el('div', {}, el('label', {'for': 'ogc-name'}, 'Campaign name'), nameInput),
        el('div', {}, el('label', {'for': 'ogc-o-comp'}, 'Compromised host'), compromised),
        el('div', {}, el('label', {'for': 'ogc-o-lat'}, 'Lateral movement target'), lateral, latList),
        el('div', {}, el('label', {'for': 'ogc-o-beac'}, 'Beacons per C2'), beacons),
        el('div', {}, el('label', {'for': 'ogc-o-start'}, 'Start time'), startTime),
        el('div', {}, el('label', {'for': 'ogc-o-speed'}, 'Speed'), speed),
        el('div', {}, el('label', {'for': 'ogc-o-family'}, 'Beacon look (malware family)'), familySel)),
      el('fieldset', {'class': 'ogc-fs'}, el('legend', {}, 'Stages to include'), incBoxes),
      el('fieldset', {'class': 'ogc-fs'}, el('legend', {}, 'Address mode'), addrBox, realNote),
      el('div', {'class': 'ogc-actions'}, compileBtn, compileHint),
      compileMsg);

    box.appendChild(el('p', {'class': 'ogc-lead'}, 'Public feeds are fetched by the OpenGenerator server, not by this page.'));
    box.appendChild(statusLine);
    box.appendChild(feedsFold);
    box.appendChild(pasteFold);
    box.appendChild(el('h3', {'class': 'ogc-h3'}, 'Indicators'));
    box.appendChild(chipsBox);
    box.appendChild(el('div', {'class': 'ogc-filters'},
      el('label', {'for': 'ogc-f-role', 'class': 'ogc-inline'}, 'Role ', roleFilter),
      el('label', {'for': 'ogc-f-type', 'class': 'ogc-inline'}, 'Type ', typeFilter),
      el('label', {'for': 'ogc-f-text', 'class': 'ogc-inline'}, 'Text ', textFilter)));
    box.appendChild(summaryEl);
    box.appendChild(el('div', {'class': 'ogc-actions'}, barBtns));
    box.appendChild(emptyNote);
    box.appendChild(el('div', {'class': 'ogc-tablewrap'}, table));
    box.appendChild(moreBox);
    box.appendChild(droppedBox);
    box.appendChild(compilePanel);

    barBtns.forEach(function (b) { allButtons.push(b); });
    renderAll();

    OGC.on('iocs', function () { renderSummary(); });

    try {
      Promise.resolve(OGC.api.post('/api/keys/status', {})).then(function (res) {
        vault.available = !!(res && res.available);
        vault.stored = Array.isArray(res && res.stored) ? res.stored.map(String) : [];
        vaultChanged();
      }, function () {});
    } catch (e) { /* no key storage: keys stay in memory only */ }

    OGC.api.get('/api/intel/feeds').then(function (res) {
      renderFeeds(Array.isArray(res.feeds) ? res.feeds : []);
    }, function (err) {
      renderFeeds([]);
      feedsBox.insertBefore(el('p', {'class': 'ogc-row-err'}, 'The feed list is not available (' + err.message + '). You can still paste a list or load a file.'), feedsBox.firstChild);
    });
  }

  // ------------------------------------------------------------------ init

  function init() {
    var root = document.getElementById && document.getElementById('ogc-root');
    if (!root) return;
    fold = document.getElementById('ogc-fold');
    clear(root);
    stepperEl = el('ol', {'class': 'ogc-stepper', 'aria-label': 'Campaign steps'});
    panelsEl = el('div', {'class': 'ogc-panels'});
    root.appendChild(stepperEl);
    root.appendChild(panelsEl);
    OGC.registerStep({id: 'type', title: 'Type', mount: mountType});
    OGC.registerStep({id: 'indicators', title: 'Indicators', mount: mountIndicators});
    // modules that loaded before the page finished parsing registered without a panel; mount them now
    STEPS.forEach(function (s) { if (registered[s.id]) ensurePanel(registered[s.id]); });
    renderStepper();
  }
  OGC._init = init;
  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
  }
})();
