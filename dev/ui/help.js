/* In-app Help: plain-language search over a fixed set of how-to articles (workflows, Lab tool explainers, tech notes).
   Pure functions (parseBody, search) run under node for tests; create() builds the view with a document object and
   only ever inserts text with textContent. Article text lives in /ui/help-articles.json. */
(function (root) {
  'use strict';

  var KINDS = {workflow: 'Workflows', tool: 'Lab tools', note: 'Tech notes'};
  var KIND_ORDER = ['workflow', 'tool', 'note'];
  var STOP = {a:1, an:1, the:1, to:1, of:1, in:1, on:1, for:1, and:1, or:1, is:1, it:1, my:1, me:1, i:1, do:1, does:1, how:1,
    can:1, what:1, with:1, this:1, that:1, you:1, your:1, are:1, be:1, want:1, need:1, use:1, using:1, get:1, make:1, where:1};

  /* ---- search ---- */
  function stem(w) {
    if (w.length > 5 && /ing$/.test(w)) return w.slice(0, -3);
    if (w.length > 4 && /ies$/.test(w)) return w.slice(0, -3) + 'y';
    if (w.length > 4 && /(ed|es)$/.test(w)) return w.slice(0, -2);
    if (w.length > 3 && /s$/.test(w) && !/ss$/.test(w)) return w.slice(0, -1);
    return w;
  }
  function tokens(text) {
    var out = [];
    String(text || '').toLowerCase().split(/[^a-z0-9.]+/).forEach(function (w) {
      w = w.replace(/^\.+|\.+$/g, '');
      if (w && !STOP[w]) out.push(stem(w));
    });
    return out;
  }
  function hasTok(list, t) {
    for (var i = 0; i < list.length; i++) if (list[i] === t || (t.length > 2 && list[i].indexOf(t) === 0)) return true;
    return false;
  }
  function prepare(articles) {
    return articles.map(function (a) {
      return {a: a, title: tokens(a.title), kw: tokens((a.keywords || []).join(' ')), sum: tokens(a.summary), body: tokens(a.body)};
    });
  }
  /* Rank articles for a query. Title and keyword hits count most; every query word must hit somewhere,
     so a longer question narrows the list instead of widening it. Returns articles, best first. */
  function search(prepared, query) {
    var q = tokens(query);
    if (!q.length) return [];
    var hits = [];
    prepared.forEach(function (p) {
      var score = 0, all = true;
      q.forEach(function (t) {
        var s = (hasTok(p.title, t) ? 10 : 0) + (hasTok(p.kw, t) ? 6 : 0) + (hasTok(p.sum, t) ? 3 : 0) + (hasTok(p.body, t) ? 1 : 0);
        if (!s) all = false;
        score += s;
      });
      if (all) hits.push({a: p.a, score: score + (p.a.kind === 'workflow' ? 0.5 : 0)});
    });
    hits.sort(function (x, y) { return y.score - x.score || (x.a.title < y.a.title ? -1 : 1); });
    return hits.map(function (h) { return h.a; });
  }

  /* ---- body markup ---- */
  function inline(text) {
    var out = [], re = /\[\[([a-z0-9-]+)(?:\|([^\]]+))?\]\]|`([^`]+)`/g, last = 0, m;
    while ((m = re.exec(text))) {
      if (m.index > last) out.push({text: text.slice(last, m.index)});
      if (m[1]) out.push({link: m[1], text: m[2] || null}); else out.push({code: m[3]});
      last = re.lastIndex;
    }
    if (last < text.length) out.push({text: text.slice(last)});
    return out;
  }
  /* Blocks: {t:'h',text} {t:'p',runs} {t:'ol'|'ul',items:[runs]}. A line that does not start a block continues the one above. */
  function parseBody(body) {
    var blocks = [], cur = null;
    String(body || '').split('\n').forEach(function (raw) {
      var line = raw.replace(/\s+$/, ''), m;
      if (!line.trim()) { cur = null; return; }
      if ((m = /^##\s+(.*)$/.exec(line))) { cur = null; blocks.push({t: 'h', text: m[1]}); return; }
      if ((m = /^\d+\.\s+(.*)$/.exec(line))) {
        if (!cur || cur.t !== 'ol') { cur = {t: 'ol', src: []}; blocks.push(cur); }
        cur.src.push(m[1]); return;
      }
      if ((m = /^-\s+(.*)$/.exec(line))) {
        if (!cur || cur.t !== 'ul') { cur = {t: 'ul', src: []}; blocks.push(cur); }
        cur.src.push(m[1]); return;
      }
      if (cur && cur.t !== 'p') { cur.src[cur.src.length - 1] += ' ' + line.trim(); return; }
      if (cur) { cur.src += ' ' + line.trim(); return; }
      cur = {t: 'p', src: line.trim()}; blocks.push(cur);
    });
    blocks.forEach(function (b) {
      if (b.t === 'p') b.runs = inline(b.src);
      else if (b.t !== 'h') b.items = b.src.map(inline);
      delete b.src;
    });
    return blocks;
  }
  function articleLinks(blocks) {
    var ids = [];
    function scan(runs) { runs.forEach(function (r) { if (r.link) ids.push(r.link); }); }
    blocks.forEach(function (b) { if (b.runs) scan(b.runs); if (b.items) b.items.forEach(scan); });
    return ids;
  }

  /* ---- DOM ---- */
  function el(doc, tag, cls, text) {
    var e = doc.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  function create(cfg) {
    var doc = cfg.doc || root.document, host = cfg.host, byId = {}, prepared = null, articles = [];
    var state = {q: '', open: null};
    var searchBox, results, status, ctx = function () { return ''; };

    function title(id) { return byId[id] ? byId[id].title : id; }
    function openArticle(id) {
      if (!byId[id]) return;
      state.open = id; draw();
      if (host.scrollIntoView) host.scrollIntoView({block: 'start'});
    }
    function link(id, text, cls) {
      var b = el(doc, 'button', cls || 'hp-tk', text || title(id));
      b.type = 'button';
      b.addEventListener('click', function () { openArticle(id); });
      return b;
    }
    function runs(parent, rs) {
      rs.forEach(function (r) {
        if (r.link) { if (byId[r.link]) parent.appendChild(link(r.link, r.text)); else parent.appendChild(doc.createTextNode(r.text || r.link)); }
        else if (r.code) parent.appendChild(el(doc, 'code', 'hp-code', r.code));
        else parent.appendChild(doc.createTextNode(r.text));
      });
    }
    function card(a) {
      var li = el(doc, 'li', 'hp-card');
      var b = el(doc, 'button', 'hp-card-b');
      b.type = 'button';
      b.appendChild(el(doc, 'span', 'hp-card-t', a.title));
      b.appendChild(el(doc, 'span', 'hp-card-s', a.summary));
      b.addEventListener('click', function () { openArticle(a.id); });
      li.appendChild(b);
      return li;
    }
    function list(arr) {
      var ul = el(doc, 'ul', 'hp-list');
      arr.forEach(function (a) { ul.appendChild(card(a)); });
      return ul;
    }
    function section(label, arr) {
      var s = el(doc, 'section', 'hp-group');
      s.appendChild(el(doc, 'h2', 'hp-h2', label));
      s.appendChild(list(arr));
      return s;
    }
    function everything() {
      KIND_ORDER.forEach(function (k) {
        var arr = articles.filter(function (a) { return a.kind === k; });
        if (arr.length) results.appendChild(section(KINDS[k], arr));
      });
    }

    function drawHome() {
      results.textContent = '';
      var q = state.q.trim();
      if (q) {
        var found = search(prepared, q);
        status.textContent = found.length ? found.length + (found.length === 1 ? ' result' : ' results') : '';
        if (found.length) { results.appendChild(list(found)); return; }
        var none = el(doc, 'div', 'hp-none');
        none.appendChild(el(doc, 'p', 'hp-mu', 'No results. Try fewer words.'));
        results.appendChild(none);
        everything();
        return;
      }
      status.textContent = '';
      var here = ctx();
      if (here) {
        var mine = articles.filter(function (a) { return a.where && a.where.toLowerCase() === here.toLowerCase(); });
        if (mine.length) results.appendChild(section('On this screen: ' + here, mine));
      }
      everything();
    }

    function drawArticle() {
      var a = byId[state.open];
      results.textContent = '';
      status.textContent = '';
      var wrap = el(doc, 'article', 'hp-art');
      var back = el(doc, 'button', 'hp-back', '← All help');
      back.type = 'button';
      back.addEventListener('click', function () { state.open = null; draw(); searchBox.focus(); });
      wrap.appendChild(back);
      var h = el(doc, 'h2', 'hp-title', a.title);
      h.tabIndex = -1;
      wrap.appendChild(h);
      parseBody(a.body).forEach(function (b) {
        if (b.t === 'h') wrap.appendChild(el(doc, 'h3', 'hp-h3', b.text));
        else if (b.t === 'p') { var p = el(doc, 'p', 'hp-p'); runs(p, b.runs); wrap.appendChild(p); }
        else {
          var l = el(doc, b.t, 'hp-' + b.t);
          b.items.forEach(function (it) { var li = el(doc, 'li'); runs(li, it); l.appendChild(li); });
          wrap.appendChild(l);
        }
      });
      var rel = (a.related || []).filter(function (id) { return byId[id]; });
      if (rel.length) {
        var r = el(doc, 'div', 'hp-rel');
        r.appendChild(el(doc, 'h3', 'hp-h3', 'Related'));
        var row = el(doc, 'div', 'hp-relrow');
        rel.forEach(function (id) { row.appendChild(link(id)); });
        r.appendChild(row);
        wrap.appendChild(r);
      }
      results.appendChild(wrap);
      if (h.focus) h.focus({preventScroll: true});
    }
    function draw() { if (state.open && byId[state.open]) drawArticle(); else drawHome(); }

    function build() {
      host.textContent = '';
      host.appendChild(el(doc, 'h1', 'hp-hero', 'How can we help?'));
      var lbl = el(doc, 'label', 'hp-ask');
      lbl.appendChild(el(doc, 'span', 'sr-only', 'Search help'));
      searchBox = el(doc, 'input', 'hp-input');
      searchBox.type = 'search'; searchBox.id = 'help-q'; searchBox.autocomplete = 'off';
      searchBox.placeholder = 'Search help, for example: replay a capture';
      searchBox.addEventListener('input', function () { state.q = searchBox.value; state.open = null; draw(); });
      lbl.appendChild(searchBox);
      host.appendChild(lbl);
      status = el(doc, 'p', 'hp-status'); status.setAttribute('role', 'status'); status.setAttribute('aria-live', 'polite');
      host.appendChild(status);
      results = el(doc, 'div', 'hp-results');
      host.appendChild(results);
    }

    return {
      load: function (list) {
        articles = list; byId = {}; list.forEach(function (a) { byId[a.id] = a; });
        prepared = prepare(list); build(); draw();
      },
      open: openArticle,
      focusSearch: function () { if (searchBox) { searchBox.focus(); searchBox.select(); } },
      setContext: function (fn) { ctx = fn; if (prepared && !state.open && !state.q.trim()) draw(); }
    };
  }

  var api = {tokens: tokens, prepare: prepare, search: search, parseBody: parseBody, articleLinks: articleLinks, create: create, KINDS: KINDS};
  root.OGHelp = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : this);
