/* Campaign Builder, "Check the sensor" panel for the capture-results card (M4).
 * OGC.sensor.render(container, summaryCampaign, campaignFile) asks the sensor which detections fired after a replay
 * and scores the campaign against them. The response shape is documented, not verified against a live sensor.
 * Vanilla ES5-style. All dynamic text goes through textContent. The API key lives only in the field and in memory
 * for the one request; it is never stored, never written to a download, and a page reload clears it. */
(function () {
  'use strict';

  var root = (typeof window !== 'undefined') ? window : globalThis;
  root.OGC = root.OGC || {};
  var OGC = root.OGC;

  /* ------------------------------------------------------------------ pure logic */

  var STATUS_LABEL = { detected: 'Detected', related: 'Related detection', missed: 'Missed', not_run: 'Not run' };

  function statusLabel(s) {
    return Object.prototype.hasOwnProperty.call(STATUS_LABEL, s) ? STATUS_LABEL[s] : 'Unknown';
  }

  function toInt(n) { n = Math.round(Number(n)); return isFinite(n) ? n : 0; }

  function parseOffset(text) {
    var t = String(text == null ? '' : text).trim();
    if (t === '') return { ok: true, value: 0 };
    if (!/^[+-]?\d+(\.\d+)?$/.test(t)) return { ok: false, value: 0, error: 'Replay offset must be a number of seconds, for example 0 or -3600.' };
    return { ok: true, value: Number(t) };
  }

  function validSensor(text) {
    var t = String(text == null ? '' : text).trim();
    if (!t) return 'Enter the sensor address, a host name or IP with an optional port.';
    if (/[\/\\@\s]/.test(t) || /^[a-z][a-z0-9+.-]*:\/\//i.test(t)) return 'Enter only a host name or IP address with an optional port, no http://, path or credentials.';
    return '';
  }

  function arr(x) { return Array.isArray(x) ? x : []; }

  /* body for POST /api/campaign/feedback. The key goes in the request only. */
  function buildRequest(form, summaryCampaign, campaignFile) {
    var sc = summaryCampaign || {}, cf = campaignFile || {};
    var stages = arr(cf.stages).map(function (s) {
      return { id: String((s && s.id) || ''), name: String((s && s.name) || ''), tactic: String((s && s.tactic) || '') };
    });
    var useStored = !form.key && form.use_stored === true;
    var req = {
      sensor: String(form.sensor || '').trim(), key: String(form.key || ''),
      entries: arr(sc.entries), iocs: arr(sc.iocs), expect: arr(cf.expect), stages: stages,
      offset_s: Number(form.offset_s) || 0, slack_s: 600, lookahead_s: 1800, min_risk: 0
    };
    if (useStored) req.use_stored = true;       // the server reads the saved key; the page never has it
    return req;
  }

  /* Keychain item id for a sensor address, or '' when the address cannot be a valid id. */
  function keyItemId(sensor) {
    var t = String(sensor == null ? '' : sensor).trim().toLowerCase();
    if (!t) return '';
    var id = 'sensor:' + t;
    return /^[a-z0-9._:-]{1,64}$/.test(id) ? id : '';
  }

  function scoreLine(score) {
    if (!score) return '';
    var t = toInt(score.testable);
    if (!t) return 'Nothing in this campaign is testable against the sensor yet (0 techniques).';
    return toInt(score.percent) + '% coverage: ' + toInt(score.detected) + ' detected, ' + toInt(score.partial) +
      ' related, ' + toInt(score.missed) + ' missed, out of ' + t + ' testable techniques.';
  }

  function normaliseResult(res) {
    var r = res && typeof res === 'object' ? res : {};
    return {
      window: r.window || null, count: toInt(r.count), score: r.score || null,
      techniques: arr(r.techniques), actions: arr(r.actions), detections: arr(r.detections),
      vulnerabilities: r.vulnerabilities || null, unmatched: toInt(r.unmatched)
    };
  }

  /* CSV: quote everything, double the quotes, and neutralise spreadsheet formulas (cells starting = + - @, tab or CR). */
  function csvCell(v) {
    var s = v == null ? '' : (Array.isArray(v) ? v.map(String).join('; ') : String(v));
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return '"' + s.replace(/"/g, '""') + '"';
  }

  function csvRow(cells) { return cells.map(csvCell).join(','); }

  function buildCsv(result) {
    var r = normaliseResult(result), lines = [];
    lines.push(csvRow(['section', 'technique', 'name', 'tactic', 'status', 'stage', 'action', 'time', 'detections', 'note']));
    r.techniques.forEach(function (t) {
      lines.push(csvRow(['technique', t.technique, t.name, t.tactic, statusLabel(t.status), arr(t.stages), arr(t.actions), '', arr(t.detections), t.note]));
    });
    r.actions.forEach(function (a) {
      lines.push(csvRow(['action', '', '', '', statusLabel(a.status), a.stage, a.action, a.ts, arr(a.detections), '']));
    });
    r.detections.forEach(function (d) {
      if (d && d.matched) return;
      lines.push(csvRow(['unmatched_detection', arr(d.techniques), d.title, arr(d.tactics), 'Unmatched', '', '', d.start_ms, d.id, arr(d.participants)]));
    });
    return lines.join('\r\n') + '\r\n';
  }

  /* what the JSON download holds: the scored result only. No key, no sensor address. */
  function coverageJson(result) {
    var r = normaliseResult(result);
    return JSON.stringify({ window: r.window, count: r.count, score: r.score, techniques: r.techniques,
      actions: r.actions, vulnerabilities: r.vulnerabilities, detections: r.detections, unmatched: r.unmatched }, null, 2);
  }

  /* run one request; resolves {ok, error|result}. The key is scrubbed from any error text. */
  function callApi(api, path, body, key) {
    function scrub(t) {
      t = String(t == null ? '' : t);
      return key ? t.split(key).join('[key]') : t;
    }
    var p;
    try { p = api.post(path, body); } catch (e) { return Promise.resolve({ ok: false, error: scrub(e && e.message) }); }
    return Promise.resolve(p).then(function (res) {
      if (!res || res.ok === false) return { ok: false, error: scrub((res && res.error) || 'The sensor did not return a usable answer.') };
      return { ok: true, res: res };
    }, function (e) { return { ok: false, error: scrub((e && e.message) || 'Request failed.') }; });
  }

  function testConnection(api, form) {
    var bad = validSensor(form.sensor);
    if (bad) return Promise.resolve({ ok: false, error: bad });
    var stored = !form.key && form.use_stored === true;
    if (!String(form.key || '') && !stored) return Promise.resolve({ ok: false, error: 'Enter the API key for the sensor.' });
    var checkBody = stored ? { sensor: String(form.sensor).trim(), use_stored: true } : { sensor: String(form.sensor).trim(), key: String(form.key) };
    return callApi(api, '/api/sensor/check', checkBody, form.key).then(function (r) {
      if (!r.ok) return r;
      var id = r.res.identity || {};
      var parts = [id.hostname, id.platform, id.version].filter(Boolean).map(String);
      return { ok: true, identity: id, text: 'Connected' + (parts.length ? ': ' + parts.join(', ') : '') + '.' };
    });
  }

  function fetchScore(api, form, summaryCampaign, campaignFile) {
    var bad = validSensor(form.sensor);
    if (bad) return Promise.resolve({ ok: false, error: bad });
    if (!String(form.key || '') && form.use_stored !== true) return Promise.resolve({ ok: false, error: 'Enter the API key for the sensor.' });
    var off = parseOffset(form.offset_s);
    if (!off.ok) return Promise.resolve({ ok: false, error: off.error });
    if (!arr((summaryCampaign || {}).entries).length) return Promise.resolve({ ok: false, error: 'This capture has no per-action records to score. Build a capture with the campaign first.' });
    var body = buildRequest({ sensor: form.sensor, key: form.key, use_stored: form.use_stored, offset_s: off.value }, summaryCampaign, campaignFile);
    return callApi(api, '/api/campaign/feedback', body, form.key).then(function (r) {
      if (!r.ok) return r;
      return { ok: true, result: normaliseResult(r.res) };
    });
  }

  OGC.sensor = OGC.sensor || {};
  OGC.sensor._test = { statusLabel: statusLabel, parseOffset: parseOffset, validSensor: validSensor, buildRequest: buildRequest, keyItemId: keyItemId,
    scoreLine: scoreLine, normaliseResult: normaliseResult, csvCell: csvCell, buildCsv: buildCsv,
    coverageJson: coverageJson, testConnection: testConnection, fetchScore: fetchScore };

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

  var uid = 0;
  function listText(a) { return arr(a).map(String).join(', ') || 'none'; }

  function table(label, cols, rows) {
    var thead = h('tr', null, cols.map(function (c) { return h('th', { scope: 'col', text: c.label }); }));
    var body = rows.map(function (r) {
      return h('tr', null, cols.map(function (c) { return c.cell(r); }));
    });
    return h('div', { class: 'ogcs-tbl-wrap', tabindex: '0', role: 'region', 'aria-label': label },
      h('table', { class: 'ogc-table ogcs-table' }, h('caption', { class: 'ogcs-sr', text: label }), h('thead', null, thead), h('tbody', null, body)));
  }

  function badge(status) {
    return h('td', null, h('span', { class: 'ogcs-badge ogcs-' + (STATUS_LABEL[status] ? status : 'unknown'), text: statusLabel(status) }));
  }
  function txt(v) { return h('td', { text: v == null || v === '' ? '' : String(v) }); }

  function download(name, mime, text) {
    var blob = new Blob([text], { type: mime });
    var url = URL.createObjectURL(blob);
    var a = h('a', { href: url, download: name });
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  function renderResult(out, result) {
    out.textContent = '';
    var r = result;
    if (!r.techniques.length && !r.actions.length && !r.detections.length) {
      out.appendChild(h('p', { class: 'ogcs-note', text: r.count === 0 ? 'The sensor returned no detections in the window. Nothing to score yet; machine-learning detections can take minutes to appear.' : 'No scored items came back.' }));
    }
    if (r.score) out.appendChild(h('p', { class: 'ogcs-score', role: 'status', text: scoreLine(r.score) }));
    if (r.window) out.appendChild(h('p', { class: 'ogcs-note', text: 'Window: ' + new Date(toInt(r.window.from_ms)).toISOString() + ' to ' + new Date(toInt(r.window.until_ms)).toISOString() + '. Detections returned: ' + r.count + '.' }));
    if (r.score && r.score.by_tactic) {
      var tac = Object.keys(r.score.by_tactic).map(function (k) { var v = r.score.by_tactic[k] || {}; return k + ' ' + toInt(v.detected) + '/' + toInt(v.testable) + ' (' + toInt(v.percent) + '%)'; });
      if (tac.length) out.appendChild(h('p', { class: 'ogcs-note', text: 'By tactic: ' + tac.join('; ') + '.' }));
    }
    if (r.techniques.length) {
      out.appendChild(h('h5', { text: 'Techniques' }));
      out.appendChild(table('Technique coverage', [
        { label: 'Technique', cell: function (t) { return txt(t.technique); } },
        { label: 'Name', cell: function (t) { return txt(t.name); } },
        { label: 'Tactic', cell: function (t) { return txt(t.tactic); } },
        { label: 'Status', cell: function (t) { return badge(t.status); } },
        { label: 'Stages', cell: function (t) { return txt(listText(t.stages)); } },
        { label: 'Actions', cell: function (t) { return txt(listText(t.actions)); } },
        { label: 'Matched detections', cell: function (t) { return txt(listText(t.detections)); } },
        { label: 'Note', cell: function (t) { return txt(t.note); } }
      ], r.techniques));
    }
    if (r.actions.length) {
      out.appendChild(h('h5', { text: 'Actions' }));
      out.appendChild(table('Action results', [
        { label: 'Stage', cell: function (a) { return txt(a.stage); } },
        { label: 'Action', cell: function (a) { return txt(a.action); } },
        { label: 'Starts (epoch s)', cell: function (a) { return txt(a.ts); } },
        { label: 'Status', cell: function (a) { return badge(a.status); } },
        { label: 'Matched detections', cell: function (a) { return txt(listText(a.detections)); } }
      ], r.actions));
    }
    var un = r.detections.filter(function (d) { return d && !d.matched; });
    out.appendChild(h('h5', { text: 'Detections that matched no action' }));
    if (un.length) {
      out.appendChild(table('Unmatched detections', [
        { label: 'Title', cell: function (d) { return txt(d.title); } },
        { label: 'Type', cell: function (d) { return txt(d.type); } },
        { label: 'Risk', cell: function (d) { return txt(d.risk); } },
        { label: 'Techniques', cell: function (d) { return txt(listText(d.techniques)); } },
        { label: 'Participants', cell: function (d) { return txt(listText(d.participants)); } }
      ], un));
    } else {
      out.appendChild(h('p', { class: 'ogcs-note', text: r.unmatched ? r.unmatched + ' unmatched detections (details not returned).' : 'None.' }));
    }
    if (r.vulnerabilities) {
      out.appendChild(h('p', { class: 'ogcs-note', text: 'Vulnerability expectations: ' + toInt(r.vulnerabilities.count) + '. ' + String(r.vulnerabilities.note || 'Carried as expectations; no traffic exercises a CVE.') }));
    }
    out.appendChild(h('div', { class: 'ogcs-row' },
      h('button', { type: 'button', class: 'btn ogc-sm', text: 'Download coverage (JSON)', onclick: function () { download('campaign-coverage.json', 'application/json', coverageJson(r)); } }),
      h('button', { type: 'button', class: 'btn ogc-sm', text: 'Download coverage (CSV)', onclick: function () { download('campaign-coverage.csv', 'text/csv', buildCsv(r)); } })));
  }

  function render(container, summaryCampaign, campaignFile) {
    if (!container) return;
    var old = container.querySelector('.ogcs'); if (old && old.parentNode) old.parentNode.removeChild(old);
    var n = ++uid, busy = false;
    var sensor = h('input', { type: 'text', id: 'ogcs-sensor-' + n, autocomplete: 'off', spellcheck: 'false', placeholder: 'host or IP, optional :port' });
    var key = h('input', { type: 'password', id: 'ogcs-key-' + n, autocomplete: 'off', spellcheck: 'false' });
    var offset = h('input', { type: 'text', id: 'ogcs-off-' + n, inputmode: 'numeric', value: '0' });
    var msg = h('p', { class: 'ogcs-msg', role: 'status', 'aria-live': 'polite' });
    var out = h('div', { class: 'ogcs-out', 'aria-live': 'polite' });
    var bTest = h('button', { type: 'button', class: 'btn ogc-sm', text: 'Test connection' });
    var bRun = h('button', { type: 'button', class: 'btn ogc-sm', text: 'Fetch detections and score' });
    var hasEntries = arr((summaryCampaign || {}).entries).length > 0;

    function setBusy(b, text) {
      busy = b; bTest.disabled = b; bRun.disabled = b;
      if (b) { msg.className = 'ogcs-msg'; msg.textContent = text; out.setAttribute('aria-busy', 'true'); } else out.removeAttribute('aria-busy');
    }
    /* optional macOS Keychain storage: shown only when the server says it is available */
    var vault = { available: false, stored: [] };
    var keyBox = h('div', { class: 'ogcs-keyrow' });
    var remember = h('input', { type: 'checkbox', id: 'ogcs-rem-' + n });
    function itemId() { return keyItemId(sensor.value); }
    function isStored() { var id = itemId(); return !!id && vault.stored.indexOf(id) >= 0; }
    function refreshKeyUi() {
      keyBox.textContent = '';
      var id = itemId();
      if (!vault.available || !id) return;
      if (isStored()) {
        keyBox.appendChild(h('span', { class: 'ogcs-saved', text: 'Using the saved key. ' }));
        keyBox.appendChild(h('button', { type: 'button', class: 'ogcs-link', text: 'Forget',
          'aria-label': 'Forget the saved key for this sensor', onclick: function () {
            OGC.api.post('/api/keys/forget', { id: id }).then(function () {
              vault.stored = vault.stored.filter(function (x) { return x !== id; }); refreshKeyUi();
            }, function (e) { fail((e && e.message) || 'Could not forget the key.'); });
          } }));
      } else {
        keyBox.appendChild(remember);
        keyBox.appendChild(h('label', { for: 'ogcs-rem-' + n, class: 'ogcs-inline', text: 'Remember in the macOS Keychain' }));
      }
    }
    function form() { return { sensor: sensor.value, key: key.value, use_stored: isStored(), offset_s: offset.value }; }
    /* a typed key is saved first when asked; afterwards the field is emptied and the saved key is used */
    function maybeSave() {
      var id = itemId();
      if (!vault.available || !id || isStored() || !remember.checked || !key.value) return Promise.resolve();
      var k = key.value;
      return Promise.resolve().then(function () { return OGC.api.post('/api/keys/save', { id: id, key: k }); }).then(function () {
        vault.stored.push(id); key.value = ''; remember.checked = false; refreshKeyUi();
      }, function (e) { fail((e && e.message ? String(e.message).split(k).join('[key]') : 'The key was not saved.') + ' The typed key is used this time only.'); });
    }
    sensor.addEventListener('input', refreshKeyUi);
    try {
      Promise.resolve(OGC.api.post('/api/keys/status', {})).then(function (r) {
        vault.available = !!(r && r.available);
        vault.stored = Array.isArray(r && r.stored) ? r.stored.map(String) : [];
        refreshKeyUi();
      }, function () {});
    } catch (e) { /* no key storage: keys stay memory-only */ }
    function fail(t) { msg.className = 'ogcs-msg ogcs-err'; msg.textContent = 'Error: ' + t; }

    bTest.addEventListener('click', function () {
      if (busy) return; setBusy(true, 'Testing the connection...');
      maybeSave().then(function () { return testConnection(OGC.api, form()); }).then(function (r) {
        setBusy(false);
        if (r.ok) { msg.className = 'ogcs-msg ogcs-good'; msg.textContent = r.text; } else fail(r.error);
      });
    });
    bRun.addEventListener('click', function () {
      if (busy) return; setBusy(true, 'Fetching detections and scoring. This can take a little while...');
      out.textContent = '';
      maybeSave().then(function () { return fetchScore(OGC.api, form(), summaryCampaign, campaignFile); }).then(function (r) {
        setBusy(false);
        if (!r.ok) { fail(r.error); if (OGC.toast) OGC.toast(r.error, 'error'); return; }
        msg.className = 'ogcs-msg ogcs-good'; msg.textContent = 'Scored.';
        if (OGC.state) OGC.state.lastScore = r.result;        // the campaign diagram reads it (scored mode)
        renderResult(out, r.result);
      });
    });

    var wrap = h('section', { class: 'ogcs', 'aria-label': 'Check the sensor' },
      h('h4', { text: 'Check the sensor' }),
      h('p', { class: 'ogcs-note', text: 'After the capture has been replayed, ask the sensor which detections fired and score this campaign against them. The sensor is only read from; nothing is sent to it but the query.' }),
      hasEntries ? null : h('p', { class: 'ogcs-note', text: 'This capture has no per-action records yet, so there is nothing to score. Build a capture with the campaign first.' }),
      h('div', { class: 'ogcs-form' },
        h('div', null, h('label', { for: 'ogcs-sensor-' + n, text: 'Sensor address' }), sensor),
        h('div', null, h('label', { for: 'ogcs-key-' + n, text: 'API key' }), key, keyBox),
        h('div', null, h('label', { for: 'ogcs-off-' + n, text: 'Replay offset (seconds)' }), offset)),
      h('p', { class: 'ogcs-note', text: 'The API key is kept only on this page and sent with each request. Unless you choose to remember it in the macOS Keychain, it is not saved, and reloading the page clears it. It is never included in downloads. The offset shifts capture time onto replay time; leave 0 if the replay kept the original timestamps.' }),
      h('div', { class: 'ogcs-row' }, bTest, bRun),
      msg, out);
    container.appendChild(wrap);
  }

  OGC.sensor.render = render;
})();
