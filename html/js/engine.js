/* Maltrail dashboard engine: the event-log parser and the threat aggregator, and nothing that
   touches a document. The page loads it (index.html, before main.js) and so does js/worker.js,
   which runs the same functions off the main thread. Everything here must stay free of `window`
   and `document` - the worker has neither. */
(function (root) {
  "use strict";

  // ---- canonical murmurhash3 (Gary Court) — matches Maltrail's bundled murmurhash3_32_gc ----
  function murmur3(key, seed) {
    var remainder = key.length & 3, bytes = key.length - remainder,
        h1 = seed >>> 0, c1 = 0xcc9e2d51, c2 = 0x1b873593, i = 0, k1, h1b;
    while (i < bytes) {
      k1 = (key.charCodeAt(i) & 0xff) | ((key.charCodeAt(++i) & 0xff) << 8) |
           ((key.charCodeAt(++i) & 0xff) << 16) | ((key.charCodeAt(++i) & 0xff) << 24);
      ++i;
      k1 = (((k1 & 0xffff) * c1) + ((((k1 >>> 16) * c1) & 0xffff) << 16)) & 0xffffffff;
      k1 = (k1 << 15) | (k1 >>> 17);
      k1 = (((k1 & 0xffff) * c2) + ((((k1 >>> 16) * c2) & 0xffff) << 16)) & 0xffffffff;
      h1 ^= k1;
      h1 = (h1 << 13) | (h1 >>> 19);
      h1b = (((h1 & 0xffff) * 5) + ((((h1 >>> 16) * 5) & 0xffff) << 16)) & 0xffffffff;
      h1 = ((h1b & 0xffff) + 0x6b64) + ((((h1b >>> 16) + 0xe654) & 0xffff) << 16);
    }
    k1 = 0;
    switch (remainder) {
      case 3: k1 ^= (key.charCodeAt(i + 2) & 0xff) << 16;
      case 2: k1 ^= (key.charCodeAt(i + 1) & 0xff) << 8;
      case 1: k1 ^= (key.charCodeAt(i) & 0xff);
        k1 = (((k1 & 0xffff) * c1) + ((((k1 >>> 16) * c1) & 0xffff) << 16)) & 0xffffffff;
        k1 = (k1 << 15) | (k1 >>> 17);
        k1 = (((k1 & 0xffff) * c2) + ((((k1 >>> 16) * c2) & 0xffff) << 16)) & 0xffffffff;
        h1 ^= k1;
    }
    h1 ^= key.length;
    h1 ^= h1 >>> 16;
    h1 = (((h1 & 0xffff) * 0x85ebca6b) + ((((h1 >>> 16) * 0x85ebca6b) & 0xffff) << 16)) & 0xffffffff;
    h1 ^= h1 >>> 13;
    h1 = (((h1 & 0xffff) * 0xc2b2ae35) + ((((h1 >>> 16) * 0xc2b2ae35) & 0xffff) << 16)) & 0xffffffff;
    h1 ^= h1 >>> 16;
    return h1 >>> 0;
  }
  var DGA_INFIX = " dga ", DNS_EXH_INFIX = " dns exhaustion ", HEUR_INFIX = "heuristic", FLOOD_PREFIX = "...", FLOOD_THRESH = 50;
  var MAX_CONDENSED = 100;   // per-threat cap on distinct values collected per column (matches legacy)
  var MAX_STORED_EVENTS = 60000;   // global cap on retained raw event rows (drawer drill-down) — bounds memory at 100MB+ scale
  var MAX_THREATS = 120000;        // hard ceiling on distinct threats kept — prevents OOM on pathological high-cardinality logs

  // A threat compacts many events: each of these columns collects the DISTINCT values seen across the threat's events.
  // Per-threat distinct-value collector. vals is a Set (NOT a plain object): accum runs 5×/event and at 100MB scale
  // V8 demotes objects with many dynamic string keys (IPs) to dictionary mode -> slow lookups. Set is ~3× faster here.
  function newSet() { return { n: 0, capped: false, vals: new Set() }; }
  function accum(s, raw) {
    if (s.capped) return;
    var v = s.vals;
    if (v.has(raw)) return;       // fast path: already collected (the common case — a threat's src never changes, ports/proto are low-cardinality)
    raw = "" + raw;
    if (raw.indexOf(",") < 0) {   // single value
      if (!raw || v.has(raw)) return;
      if (s.n >= MAX_CONDENSED) { v.add("…"); s.capped = true; return; }
      v.add(raw); s.n++;
      return;
    }
    var parts = raw.split(",");   // condensed multi-value ("a,b,c")
    for (var i = 0; i < parts.length; i++) {
      var p = parts[i]; if (!p || v.has(p)) continue;
      if (s.n >= MAX_CONDENSED) { v.add("…"); s.capped = true; return; }
      v.add(p); s.n++;
    }
  }
  function setList(s) { return Array.from(s.vals); }
  function charTrim(s, ch) { while (s.substr(0, 1) === ch) s = s.substr(1); while (s.substr(s.length - 1) === ch) s = s.substr(0, s.length - 1); return s; }
  // normTrail runs per EVENT (×2 passes) but a trail is one of relatively few distinct values -> memoize (huge at 100MB scale)
  var _ntCache = {}, _ntCacheN = 0;
  // A web scan names the paths it tried ("/admin, /.env, ...", #18247); grouping, flood folding and
  // the whitelist treat every such list as the one indicator it used to be logged as: "*".
  var PATH_LIST_RE = /^\/\S*(?:, \/\S*){2,}$/;
  function normTrail(trail) { var c = _ntCache[trail]; if (c !== undefined) return c; if (_ntCacheN > 200000) { _ntCache = {}; _ntCacheN = 0; }  /* bound memory on pathological unique-trail (DGA) days */ c = PATH_LIST_RE.test(trail) ? "*" : charTrim(charTrim(("" + trail).replace(/\([^)]+\)/g, ""), " "), "."); _ntCache[trail] = c; _ntCacheN++; return c; }
  // A throttle summary line ends its info with " (+N more)" when it held more than it could carry;
  // the detection is the same, so grouping ignores the suffix (it used to open a second threat).
  function infoKey(info) { return ("" + info).replace(/ \(\+\d+ more\)$/, ""); }
  // What "the same trail from many sources" (flood) means. For a heuristic the normalized trail is
  // often just a TLD - "(label).com" -> "com" - so keyed on that alone, every heuristic on .com from
  // 50+ hosts folded into ONE threat (a DGA bot vanished inside 60 hosts' long-domain events);
  // the detection is part of the key for heuristics.
  function floodKey(trail, info, ref) { var n = normTrail(trail); return ("" + ref).indexOf(HEUR_INFIX) > -1 ? n + "\u001f" + infoKey(info) : n; }
  function padz(s, w) { s = "" + s; while (s.length < w) s = "0" + s; return s; }
  // legacy-exact getThreatUID: murmur3(threat_text, seed 13); 6-hex + N0/F0/D0 for dns-exhaustion/flood/dga, else 8-hex
  function threatUID(text, kind) {
    var hex = (murmur3(text, 13) >>> 0).toString(16);
    if (kind === "dnsx") return padz(hex, 6).substring(0, 6) + "N0";
    if (kind === "flood") return padz(hex, 6).substring(0, 6) + "F0";
    if (kind === "dga") return padz(hex, 6).substring(0, 6) + "D0";
    return padz(hex, 8);
  }

  // Severity — the legacy Maltrail ladder (main.js), with one deliberate addition below for the sensor's
  // own heuristics. Order matters; default is MEDIUM. Feed trails keep the legacy verdict, so
  // "ipinfo (suspicious)" is still MEDIUM (an earlier v2 demoted a whole invented list of them to LOW).
  // Severity is a POLICY, not a property of the event: it is whatever maltrail.conf's
  // REMOTE_SEVERITY_REGEX says, and an operator tunes that. This used to be a second
  // implementation of the same policy - a keyword table plus a handful of special cases - and the
  // two drifted twice. The dashboard ranked "long domain (suspicious)" LOW while the alert that
  // fired on it said MEDIUM, and after the IoT-dropper fix two green tests asserted opposite
  // severities for one event. So the page is served the regex itself (<meta name="mt-severity">,
  // core/httpd.py:_severity) and applies it, exactly as core/log.py:severity_of() and
  // sensor/src/output.rs:severity_for() do. One definition, three appliers.
  //
  // Matched against "<info> <reference>": whether a verdict was corroborated lives in the
  // reference - "(heuristic)" is the sensor's own guess, "(static)" is a feed hit - and the rule
  // that a guess ranks below a feed hit cannot be written without it.
  var SEVERITY_FALLBACK = "(?P<high>(remote )?custom\\)|malwaredomainlist|malware(?! (distribution|site))|adversary|ransomware)|(?P<medium>potential malware site|malware distribution|c2 cert|iot-malware|potential infection)|(?P<low>mass scanner|reputation|attacker|spammer|compromised|crawler|scanning|\\(suspicious\\) \\(heuristic\\))";
  var _sevRe = null;
  // The page hands over the regex it was served (<meta name="mt-severity">, read in main.js), and
  // the worker gets the same string in its first message. Python named groups (?P<x>) are a
  // syntax error in JS; (?P< is not valid JS either way, so rewriting it can only fix. A tuned
  // regex that does not compile falls back rather than taking the dashboard down with it.
  function setSeverity(raw) {
    _sevRe = null;
    for (var i = 0; i < 2; i++) {
      var src = (i === 0 ? raw : SEVERITY_FALLBACK);
      if (!src) continue;
      try { _sevRe = new RegExp(src.split("(?P<").join("(?<")); return; } catch (e) { }
    }
  }
  setSeverity("");
  function severityOf(info, ref) {
    if (!_sevRe) return 2;
    var m = ("" + (info || "") + " " + (ref || "")).match(_sevRe);
    if (!m || !m.groups) return 2;                 // unmatched is MEDIUM, as the server has it
    if (m.groups.low !== undefined) return 1;
    if (m.groups.medium !== undefined) return 2;
    if (m.groups.high !== undefined) return 3;
    return 2;
  }

  function hourOf(t) { var h = +("" + t).substr(11, 2); return h >= 0 && h < 24 ? h : 0; }   // "YYYY-MM-DD HH:.." -> HH (substr, no regex; per-event hot path)

  // Event-log fields, in the order every row here is indexed by (row[2] is src_ip, row[7] type,
  // row[8] trail). LOCAL_LOG_FORMAT lets the server write these lines as JSON, so a row can arrive
  // either way — and a single .log file can hold BOTH, because flipping the option and restarting
  // mid-day appends JSON after the text already written that morning.
  var EVENT_FIELDS = ["time", "sensor", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "type", "trail", "info", "reference"];

  function jsonEventRow(line) {
    var o, i, v, row = [];
    try { o = JSON.parse(line); } catch (e) { return null; }
    if (!o || typeof o !== "object") return null;
    for (i = 0; i < EVENT_FIELDS.length; i++) {
      v = o[EVENT_FIELDS[i]];
      // the wire form (LOGSTASH_SERVER) carries no "time"; the epoch keeps such a line readable
      if (v == null && EVENT_FIELDS[i] === "time") v = o.timestamp;
      if (v == null) return null;
      row.push(typeof v === "string" ? v : String(v));
    }
    return row;
  }

  // Rows from a chunk of event log, whichever format the lines are in.
  function parseEvents(text) {
    if (!text) return [];
    // Fast path: no JSON anywhere, so this is exactly the call it has always been.
    if (text.charAt(0) !== "{" && text.indexOf("\n{") === -1)
      return root.Papa.parse(text, { delimiter: " ", skipEmptyLines: true }).data;

    var lines = text.split("\n"), out = [], buf = [], i, line, row;
    function flush() {
      if (!buf.length) return;
      var d = root.Papa.parse(buf.join("\n"), { delimiter: " ", skipEmptyLines: true }).data;
      for (var k = 0; k < d.length; k++) out.push(d[k]);
      buf = [];
    }
    for (i = 0; i < lines.length; i++) {
      line = lines[i];
      if (!line) continue;
      if (line.charAt(0) === "{") {
        // text lines are batched through Papa rather than parsed one at a time: a day can be
        // 100k+ lines and per-line parser setup is what makes that slow
        flush();
        row = jsonEventRow(line);
        if (row) out.push(row);
      } else {
        buf.push(line);
      }
    }
    flush();
    return out;
  }

  function aggregate(csv) { return aggregateRows(parseEvents(csv)); }
  // NOTE: trail types are matched with /^[A-Z0-9]+$/, NOT /^[A-Z]+$/. The point of the test is to
  // reject a row whose field 7 is not a type at all (a shifted or truncated line), but JA3, JA3S
  // and JA4 carry a digit - and the sensor emits TRAIL::JA3 and TRAIL::JA4 - so the letters-only
  // form dropped every TLS-fingerprint detection here in silence: no error, no count, simply
  // missing from the table, the type breakdown and the charts.
  function aggregateRows(rows) {
    var r, row, type, nt;
    // pass 1: flood detection — a normalized trail seen from > FLOOD_THRESH distinct source IPs
    var trailSrcs = new Map();   // Map<floodKey, Set<src>> — Map/Set, not plain objects: V8 keeps these fast at 100k+ keys (objects degrade to dictionary mode)
    for (r = 0; r < rows.length; r++) {
      row = rows[r];
      if (!row || row.length < 11 || !/^[A-Z0-9]+$/.test(row[7])) continue;
      nt = floodKey(row[8], row[9], row[10]); var ts0 = trailSrcs.get(nt); if (!ts0) trailSrcs.set(nt, ts0 = new Set()); ts0.add(row[2]);
    }
    var flood = new Set(); trailSrcs.forEach(function (ts, fk) { if (ts.size > FLOOD_THRESH) flood.add(fk); });
    // pass 2: group into threats by legacy-exact threat_text
    var threats = new Map(), order = [], events = 0, evStored = 0, dropped = 0,
        hours = new Array(24).fill(0),
        sevHours = { 3: new Array(24).fill(0), 2: new Array(24).fill(0), 1: new Array(24).fill(0) },
        sevCount = { 3: 0, 2: 0, 1: 0 },
        typeCounts = {}, srcCounts = new Map(), trailCounts = new Map(), typeHours = {};
    for (r = 0; r < rows.length; r++) {
      row = rows[r];
      if (!row || row.length < 11) continue;
      var time = row[0], sensor = row[1], src = row[2], sport = row[3], dst = row[4],
          dport = row[5], proto = row[6], trail = row[8], info = row[9], ref = row[10];
      type = row[7];
      if (!/^[A-Z0-9]+$/.test(type)) continue;
      events++;
      var hr = hourOf(time); hours[hr]++;
      nt = normTrail(trail);
      srcCounts.set(src, (srcCounts.get(src) || 0) + 1);
      trailCounts.set(nt, (trailCounts.get(nt) || 0) + 1);   // distinct INDICATORS, not raw strings: normTrail strips the variable (...) part so heuristic families ((x).com, rDNS, UA detail) collapse — matches legacy semantics
      typeCounts[type] = (typeCounts[type] || 0) + 1;
      (typeHours[type] || (typeHours[type] = new Array(24).fill(0)))[hr]++;
      var ikey = infoKey(info), fk = floodKey(trail, info, ref);
      var dnsx = info.indexOf(DNS_EXH_INFIX) > -1, isFlood = flood.has(fk),
          dga = info.indexOf(DGA_INFIX) > -1, heur = ref.indexOf(HEUR_INFIX) > -1;
      var ttext, kind = null;
      if (dnsx) { ttext = ikey + "~>" + nt; kind = "dnsx"; }
      else if (isFlood) { ttext = FLOOD_PREFIX + "~>" + fk; kind = "flood"; }
      else if (dga) { ttext = src + "~>" + ikey; kind = "dga"; }
      else if (heur) { ttext = src + "~>" + nt + ikey; }
      else { ttext = src + "~>" + nt; }
      var t = threats.get(ttext);
      if (!t) {
        if (order.length >= MAX_THREATS) { dropped++; continue; }   // safeguard: don't create unbounded threat objects (OOM)
        t = { key: ttext, kind: kind, sensor: sensor, src: src, sport: sport, dst: dst, dport: dport, proto: proto,
              type: type, trail: trail, info: info, ref: ref, count: 0, first: time, last: time,
              hours: new Array(24).fill(0), sev: severityOf(info, ref),
              // uidc/_hay/_risk* are filled in later but are declared HERE so every threat leaves this
              // literal with the same shape. Adding them afterwards transitions the hidden class of each
              // of ~70k objects, and V8 then reads every property on them through a slower path - which
              // showed up as the filter pass getting measurably worse when the risk memo was introduced.
              uidc: "", _hay: null, _riskT: undefined, _riskN: -1, _risk: 0,
              srcS: newSet(), sportS: newSet(), dstS: newSet(), dportS: newSet(), protoS: newSet(), sensorS: newSet(), events: [] };
        threats.set(ttext, t); order.push(t);
      }
      t.count++; t.hours[hr]++;
      // a threat compacts many events: collect the distinct values seen per column
      accum(t.srcS, src); accum(t.sportS, sport); accum(t.dstS, dst); accum(t.dportS, dport); accum(t.protoS, proto); accum(t.sensorS, sensor);
      if (evStored < MAX_STORED_EVENTS && t.events.length < 500) { t.events.push(row); evStored++; }   // bounded total raw rows (drawer)
      if (time < t.first) t.first = time;
      if (time > t.last) t.last = time;
    }
    for (var i = 0; i < order.length; i++) {
      var th = order[i]; th.uidc = threatUID(th.key, th.kind); sevCount[th.sev]++;
      for (var h = 0; h < 24; h++) sevHours[th.sev][h] += th.hours[h];
      // _hay (search haystack) is built lazily on first free-text search, not here — see hay()
    }
    return { threats: order, events: events, sources: srcCounts.size,
             trailsN: trailCounts.size, hours: hours, sevHours: sevHours, sevCount: sevCount,
             typeCounts: typeCounts, srcCounts: srcCounts, trailCounts: trailCounts, typeHours: typeHours,
             // internal maps retained so live deltas can merge in O(new rows) instead of re-aggregating everything
             _byKey: threats, _trailSrcs: trailSrcs, _flood: flood, _evN: evStored, _dropped: dropped };
  }
  // Incremental merge: fold ONLY the newly-appended rows into an existing aggregate, in O(new rows).
  // Mirrors aggregateRows' per-event logic exactly so the result matches a full re-aggregate — except a
  // trail newly crossing the flood threshold reclassifies only NEW events (prior grouping self-corrects on
  // the next full load). This is what makes live cheap on a 50MB/day log: no full re-parse, no full re-walk.
  // `into`, when given, collects the touched threats across calls (the worker's deltas); it is
  // what agg._touched then refers to.
  function mergeRows(agg, rows, into) {
    if (!agg || !agg._byKey) return aggregateRows(rows);   // no baseline -> full
    var threats = agg._byKey, order = agg.threats, trailSrcs = agg._trailSrcs, flood = agg._flood;
    var touched = into || new Set();
    for (var r = 0; r < rows.length; r++) {
      var row = rows[r];
      if (!row || row.length < 11) continue;
      var type = row[7]; if (!/^[A-Z0-9]+$/.test(type)) continue;
      var time = row[0], sensor = row[1], src = row[2], sport = row[3], dst = row[4],
          dport = row[5], proto = row[6], trail = row[8], info = row[9], ref = row[10];
      agg.events++;
      var hr = hourOf(time); agg.hours[hr]++;
      var sc = agg.srcCounts.get(src); if (sc === undefined) { agg.sources++; agg.srcCounts.set(src, 1); } else agg.srcCounts.set(src, sc + 1);   // running distinct counters (avoid O(total) re-count per tick)
      var nt = normTrail(trail);
      var tc = agg.trailCounts.get(nt); if (tc === undefined) { agg.trailsN++; agg.trailCounts.set(nt, 1); } else agg.trailCounts.set(nt, tc + 1);   // distinct INDICATORS (normalized)
      agg.typeCounts[type] = (agg.typeCounts[type] || 0) + 1;
      (agg.typeHours[type] || (agg.typeHours[type] = new Array(24).fill(0)))[hr]++;
      var fk0 = floodKey(trail, info, ref), tset = trailSrcs.get(fk0); if (tset === undefined) trailSrcs.set(fk0, tset = new Set());
      if (!tset.has(src)) { tset.add(src); if (!flood.has(fk0) && tset.size > FLOOD_THRESH) flood.add(fk0); }   // count distinct srcs only when a NEW one appears
      var ikey = infoKey(info), fk = floodKey(trail, info, ref);
      var dnsx = info.indexOf(DNS_EXH_INFIX) > -1, isFlood = flood.has(fk),
          dga = info.indexOf(DGA_INFIX) > -1, heur = ref.indexOf(HEUR_INFIX) > -1;
      var ttext, kind = null;
      if (dnsx) { ttext = ikey + "~>" + nt; kind = "dnsx"; }
      else if (isFlood) { ttext = FLOOD_PREFIX + "~>" + fk; kind = "flood"; }
      else if (dga) { ttext = src + "~>" + ikey; kind = "dga"; }
      else if (heur) { ttext = src + "~>" + nt + ikey; }
      else { ttext = src + "~>" + nt; }
      var t = threats.get(ttext);
      if (!t) {
        if (order.length >= MAX_THREATS) { agg._dropped = (agg._dropped || 0) + 1; continue; }   // OOM safeguard
        t = { key: ttext, kind: kind, sensor: sensor, src: src, sport: sport, dst: dst, dport: dport, proto: proto,
              type: type, trail: trail, info: info, ref: ref, count: 0, first: time, last: time,
              hours: new Array(24).fill(0), sev: severityOf(info, ref),
              // uidc/_hay/_risk* are filled in later but are declared HERE so every threat leaves this
              // literal with the same shape. Adding them afterwards transitions the hidden class of each
              // of ~70k objects, and V8 then reads every property on them through a slower path - which
              // showed up as the filter pass getting measurably worse when the risk memo was introduced.
              uidc: "", _hay: null, _riskT: undefined, _riskN: -1, _risk: 0,
              srcS: newSet(), sportS: newSet(), dstS: newSet(), dportS: newSet(), protoS: newSet(), sensorS: newSet(), events: [] };
        t.uidc = threatUID(ttext, kind);
        threats.set(ttext, t); order.push(t); agg.sevCount[t.sev]++;
      }
      t.count++; t.hours[hr]++; agg.sevHours[t.sev][hr]++;
      accum(t.srcS, src); accum(t.sportS, sport); accum(t.dstS, dst); accum(t.dportS, dport); accum(t.protoS, proto); accum(t.sensorS, sensor);
      if ((agg._evN || 0) < MAX_STORED_EVENTS && t.events.length < 500) { t.events.push(row); agg._evN = (agg._evN || 0) + 1; }
      if (time < t.first) t.first = time;
      if (time > t.last) t.last = time;
      touched.add(t);
    }
    if (!into) touched.forEach(function (t) { t._hay = null; });   // INVALIDATE haystack (cheap); rebuilt lazily in hay() only if a free-text search needs it — avoids rebuilding a long string for every touched threat on every chunk during a 100MB load
    agg._touched = touched;   // what changed (since `into` was last emptied): the worker ships exactly these to the page
    return agg;   // sources / trailsN already maintained as running counters above
  }

  root.MT_ENGINE = {
    murmur3: murmur3, padz: padz, threatUID: threatUID, hourOf: hourOf,
    newSet: newSet, accum: accum, setList: setList, charTrim: charTrim, normTrail: normTrail, infoKey: infoKey, floodKey: floodKey,
    SEVERITY_FALLBACK: SEVERITY_FALLBACK, setSeverity: setSeverity, severityOf: severityOf,
    EVENT_FIELDS: EVENT_FIELDS, jsonEventRow: jsonEventRow, parseEvents: parseEvents, aggregate: aggregate, aggregateRows: aggregateRows, mergeRows: mergeRows,
    DGA_INFIX: DGA_INFIX, DNS_EXH_INFIX: DNS_EXH_INFIX, HEUR_INFIX: HEUR_INFIX, FLOOD_PREFIX: FLOOD_PREFIX, FLOOD_THRESH: FLOOD_THRESH,
    MAX_CONDENSED: MAX_CONDENSED, MAX_STORED_EVENTS: MAX_STORED_EVENTS, MAX_THREATS: MAX_THREATS
  };
})(typeof self !== "undefined" ? self : this);
