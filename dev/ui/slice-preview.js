/* Slice picker arithmetic: what a slice will contain, worked out from a scenario's block in the build manifest alone,
   before anything is cut. It mirrors tools/slice_pcap.py: spans are padded by ctx + 1 s on each side and overlapping
   ones merge. Pure functions, exported for tests; no DOM. */
(function (root) {
  'use strict';
  var PAD_S = 1.0;

  /* [[t0, t1, ...], ...] -> merged [[lo, hi], ...] padded by ctx + PAD_S. */
  function intervals(spans, ctx) {
    var out = [];
    spans.map(function (s) { return [s[0], s[1]]; }).sort(function (a, b) { return a[0] - b[0] || a[1] - b[1]; }).forEach(function (s) {
      var lo = s[0] - ctx - PAD_S, hi = s[1] + ctx + PAD_S, last = out[out.length - 1];
      if (last && lo <= last[1]) last[1] = Math.max(last[1], hi); else out.push([lo, hi]);
    });
    return out;
  }

  /* sc: a manifest scenario {observed:{packets,first_ts,last_ts}, active_spans:[[t0,t1,packets]...]}.
     -> {ok, reason, packets, exact, background, seconds, spans}. packets is the scenario's own count; exact is true when
     nothing else rides along (kind C with no background). Kinds B and C need active_spans (the build's tag sidecar). */
  function preview(sc, kind, ctx, baseline) {
    var ob = sc.observed || {};
    if (ob.first_ts == null) return {ok: false, reason: 'this scenario emitted no packets'};
    var spans;
    if (kind === 'A') spans = [[ob.first_ts, ob.last_ts]];
    else if (sc.active_spans && sc.active_spans.length) spans = sc.active_spans;
    else return {ok: false, reason: 'this build has no tag sidecar, so only the window slice (A) can be cut. Rebuild with an export switched on for B and C.'};
    var iv = intervals(spans, ctx);
    var base = baseline || (kind === 'C' ? 'none' : 'window');
    var seconds = iv.reduce(function (n, x) { return n + (x[1] - x[0]); }, 0);
    var own = kind === 'A' ? ob.packets : spans.reduce(function (n, s) { return n + (s[2] || 0); }, 0);
    var exact = kind !== 'A' && base === 'none';
    return {ok: true, packets: own, exact: exact, background: kind === 'A' ? 'everything in the window' : base, seconds: seconds, spans: iv.length};
  }

  function fmtDuration(s) {
    s = Math.round(s);
    if (s < 90) return s + ' seconds';
    if (s < 5400) return Math.round(s / 60) + ' minutes';
    return (s / 3600).toFixed(1) + ' hours';
  }

  var api = {intervals: intervals, preview: preview, fmtDuration: fmtDuration};
  root.OGSlice = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : this);
