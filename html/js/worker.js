/* The dashboard's parser and aggregator, off the main thread.

   main.js streams the raw bytes of /events here and gets back DELTAS: the threats touched since
   the last one, plus the day's totals. The page applies each delta to its own copy of the
   threats and paints when its pace allows; the seconds of parsing a million-event day happen
   where they cannot freeze the page. The whole aggregate is never posted - cloning it once
   measured slower than parsing it, and the live merges after a load would have paid it again
   on every tick.

   One worker per load: the page terminates the previous one when a new day starts, which hands
   that day's memory back at once (left to itself, V8 keeps a worker's heap for a minute after
   its last allocation). Every message carries `seq`, the page's load sequence number, and is
   answered with it, so a reply to a superseded navigation is ignored exactly like a late fetch.
     init  {sev, pace}       the severity regex the page was served, and its progressive repaint
                             policy (rows between paints, the floor, the duty factor)
     chunk {buf, off, len}   raw bytes, transferred; answered with ack {len} so the page keeps a
                             bounded number of bytes in flight instead of buffering the file
     paint {ms}              what the page's last delta cost it (apply + paint); deltas are spaced
                             at least that plus their own build time, times the duty factor,
                             apart - the way the page paces its own repaints. The worker paces
                             itself: a delta per chunk cost the page more than parsing had, and a
                             request from the page queued behind every chunk already posted.
     end                     the stream is over; answered with done {tail} after the last delta,
                             tail being the bytes of an incomplete final line the page must not
                             count as consumed
     text  {text}            lines to merge (live updates); answered with a delta and merged
   Engine and parser are the same files the page loads (js/engine.js, js/thirdparty.min.js), so
   both paths run one implementation. */
importScripts("thirdparty.min.js" + self.location.search, "engine.js" + self.location.search);
(function () {
  "use strict";
  var E = self.MT_ENGINE;
  var TOP_K = 32;         // the page draws at most 18 of the per-source / per-trail counts
  var agg = null, pending = null, touched = new Set(), sent = new Map(), sentN = 0;
  var pace = { every: 12000, minMs: 220, duty: 4 }, costMs = 0, buildMs = 0, lastDeltaT = 0, lastDeltaEvents = 0;
  var stats = { chunks: 0, bytes: 0, rows: 0, decodeMs: 0, parseMs: 0, mergeMs: 0, deltaMs: 0, deltas: 0, records: 0, updates: 0 };   // where the time went, reported with `done` (diagnostics)
  var dec = new TextDecoder();
  function now() { return (typeof performance !== "undefined" && performance.now) ? performance.now() : Date.now(); }

  // The engine collects what each merge touches straight into `touched`, emptied by each delta.
  // The first chunk is aggregated outright and marks nothing touched: every threat is new then,
  // which the delta covers by position (see below).
  function merge(rows) { agg = E.mergeRows(agg, rows, touched); }

  function join(u8) {
    if (!pending) return u8;
    var all = new Uint8Array(pending.length + u8.length);
    all.set(pending, 0); all.set(u8, pending.length);
    pending = null;
    return all;
  }

  function chunk(u8) {
    u8 = join(u8);
    var nl = u8.lastIndexOf(10);
    if (nl < 0) { pending = u8; return; }
    // whole lines only; a UTF-8 sequence never straddles a newline, so these decode on their own
    var t0 = now();
    var text = dec.decode(u8.subarray(0, nl + 1));
    if (nl + 1 < u8.length) pending = u8.slice(nl + 1);
    var t1 = now();
    var rows = E.parseEvents(text);
    var t2 = now();
    if (rows.length) merge(rows);
    stats.decodeMs += t1 - t0; stats.parseMs += t2 - t1; stats.mergeMs += now() - t2; stats.rows += rows.length;
  }

  // The TOP_K entries of a count map in one pass (a full sort of 80k sources per delta was most
  // of a delta's cost). Ties keep the map's insertion order, which is what the page's stable
  // topN sort yields over the same map, so the page sees the same top entries in the same order.
  function topK(m) {
    var top = [], n = 0, last = 0;
    m.forEach(function (v, k) {
      if (n === TOP_K && v <= last) return;
      var i = n;
      while (i > 0 && top[i - 1][1] < v) i--;   // after every entry with a count >= v
      top.splice(i, 0, [k, v]);
      if (n < TOP_K) n++; else top.pop();
      last = top[n - 1][1];
    });
    return top;
  }

  // The collected sets of a threat, flat: the values of all six back to back, and how many
  // belong to each (a nested array per set was seven allocations the page then had to walk).
  function sets(t) {
    var S = E.setList, v = [], n = [], all = [t.srcS, t.sportS, t.dstS, t.dportS, t.protoS, t.sensorS], i, j, l;
    for (i = 0; i < 6; i++) { l = S(all[i]); n.push(l.length); for (j = 0; j < l.length; j++) v.push(l[j]); }
    return [v, n];
  }
  function cap(t) {
    return (t.srcS.capped ? 1 : 0) | (t.sportS.capped ? 2 : 0) | (t.dstS.capped ? 4 : 0) | (t.dportS.capped ? 8 : 0) | (t.protoS.capped ? 16 : 0) | (t.sensorS.capped ? 32 : 0);
  }
  function sizes(t) { return [t.srcS.vals.size, t.sportS.vals.size, t.dstS.vals.size, t.dportS.vals.size, t.protoS.vals.size, t.sensorS.vals.size]; }

  // A delta carries the threats the page has not seen, whole, and for the ones it has, only what
  // moves: count, first, last, hours, the rows stored since, and the values the collected sets
  // gained since (a set only ever grows, in insertion order, so the page appends). Threats are
  // identified by their position in the aggregate's order, which the page's copy shares, and
  // the per-threat numbers travel in typed arrays that are transferred rather than cloned. A
  // day of a million events touches its threats some four hundred thousand times; an array and
  // a key string per touch, and the six sets rebuilt whole because a source port is new on
  // nearly every event, was most of what the page then spent its time on.
  function delta(seq) {
    if (!agg) agg = E.aggregateRows([]);
    var t0 = now(), order = agg.threats, recs = [], ups = [], i, j, t, info;
    for (i = sentN; i < order.length; i++) {
      t = order[i]; var sv = sets(t);
      sent.set(t, { idx: i, ev: t.events.length, sz: sizes(t), first: t.first, last: t.last });
      recs.push([t.key, t.kind, t.sensor, t.src, t.sport, t.dst, t.dport, t.proto, t.type, t.trail, t.info, t.ref,
                 t.count, t.first, t.last, t.sev, t.uidc, sv[0], sv[1], cap(t), t.events]);
    }
    touched.forEach(function (x) { var w = sent.get(x); if (w && w.idx < sentN) ups.push(x); });
    var n = recs.length, m = ups.length, hours = new Uint32Array(24 * (n + m)), uidx = new Int32Array(m), ucount = new Int32Array(m);
    var ufirst = new Array(m), ulast = new Array(m), uev = [], usets = [];
    for (i = 0; i < n; i++) { t = order[sentN + i]; for (j = 0; j < 24; j++) hours[i * 24 + j] = t.hours[j]; }
    for (i = 0; i < m; i++) {
      t = ups[i]; info = sent.get(t);
      uidx[i] = info.idx; ucount[i] = t.count;
      ufirst[i] = t.first !== info.first ? t.first : null; info.first = t.first;
      ulast[i] = t.last !== info.last ? t.last : null; info.last = t.last;
      for (j = 0; j < 24; j++) hours[(n + i) * 24 + j] = t.hours[j];
      if (t.events.length > info.ev) { uev.push([i, t.events.slice(info.ev)]); info.ev = t.events.length; }
      var all = [t.srcS, t.sportS, t.dstS, t.dportS, t.protoS, t.sensorS], added = null, addn = null, q, z, l;
      for (q = 0; q < 6; q++) {
        if (all[q].vals.size === info.sz[q]) continue;
        if (!added) { added = []; addn = [0, 0, 0, 0, 0, 0]; }
        l = E.setList(all[q]);
        for (z = info.sz[q]; z < l.length; z++) added.push(l[z]);
        addn[q] = l.length - info.sz[q]; info.sz[q] = l.length;
      }
      if (added) usets.push([i, added, addn, cap(t)]);
    }
    sentN = order.length; touched = new Set();
    lastDeltaT = now(); lastDeltaEvents = agg.events; buildMs = lastDeltaT - t0;
    self.postMessage({ op: "delta", seq: seq, recs: recs, uidx: uidx, ucount: ucount, ufirst: ufirst, ulast: ulast, hours: hours, uev: uev, usets: usets,
                       events: agg.events, sources: agg.sources, trailsN: agg.trailsN, dropped: agg._dropped || 0,
                       hoursAll: agg.hours, sevHours: agg.sevHours, sevCount: agg.sevCount, typeCounts: agg.typeCounts, typeHours: agg.typeHours,
                       srcTop: topK(agg.srcCounts), trailTop: topK(agg.trailCounts) },
                     [uidx.buffer, ucount.buffer, hours.buffer]);
    stats.deltaMs += buildMs; stats.deltas++; stats.records += n; stats.updates += m;
  }

  self.onmessage = function (e) {
    var m = e.data;
    if (m.op === "init") { E.setSeverity(m.sev || ""); if (m.pace) pace = m.pace; return; }
    if (m.op === "chunk") {
      stats.chunks++; stats.bytes += m.len;
      chunk(new Uint8Array(m.buf, m.off, m.len));
      self.postMessage({ op: "ack", seq: m.seq, len: m.len });
      // the page's own pacing, applied here: enough new rows, and not sooner after the last
      // delta than what it cost - building it here plus applying and painting it there - times
      // the duty factor, so deltas stay a fraction of the load wherever it runs (the first one
      // is held only by the rows)
      if (agg && agg.events - lastDeltaEvents >= pace.every &&
          (lastDeltaT === 0 || now() - lastDeltaT >= Math.max(pace.minMs, (costMs + buildMs) * pace.duty))) delta(m.seq);
      return;
    }
    if (m.op === "paint") { costMs = m.ms; return; }
    if (m.op === "end") {
      // a non-empty `pending` is an incomplete final line (EOF caught mid-append): not parsed,
      // and reported so the page's live baseline stops before it
      delta(m.seq);
      self.postMessage({ op: "done", seq: m.seq, tail: pending ? pending.length : 0, stats: stats });
      pending = null;
      return;
    }
    if (m.op === "text") {
      var rows = E.parseEvents(m.text);
      if (rows.length) merge(rows);
      delta(m.seq);
      self.postMessage({ op: "merged", seq: m.seq });
    }
  };
})();
