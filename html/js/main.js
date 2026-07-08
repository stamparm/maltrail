/* Maltrail v2 — vanilla presentation layer (no jQuery/DataTables).
   Parses the event log (same space-delimited 11-col contract), aggregates into threats, renders an interactive
   grid + stat tiles. Threat-UID uses canonical murmur3 (verify byte-compat with thirdparty.min.js before
   production integration — see journal). */
(function () {
  "use strict";

  // Server-injected IP→alias map (httpd.py rewrites this exact line for /js/main.js when config.IP_ALIASES is set).
  // Keep the declaration on its own line and byte-for-byte matchable by /\bvar IP_ALIASES =.+/.
  var IP_ALIASES = {};

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
  function normTrail(trail) { var c = _ntCache[trail]; if (c !== undefined) return c; if (_ntCacheN > 200000) { _ntCache = {}; _ntCacheN = 0; }  /* bound memory on pathological unique-trail (DGA) days */ c = charTrim(charTrim(("" + trail).replace(/\([^)]+\)/g, ""), " "), "."); _ntCache[trail] = c; _ntCacheN++; return c; }
  // CSS-escape a value used inside an attribute selector ([data-ip="..."]); raw log fields can contain "/]/\ which throw
  function cssEsc(s) { s = "" + s; return (window.CSS && CSS.escape) ? CSS.escape(s) : s.replace(/["\\\]\[]/g, "\\$&"); }
  function padz(s, w) { s = "" + s; while (s.length < w) s = "0" + s; return s; }
  // legacy-exact getThreatUID: murmur3(threat_text, seed 13); 6-hex + N0/F0/D0 for dns-exhaustion/flood/dga, else 8-hex
  function threatUID(text, kind) {
    var hex = (murmur3(text, 13) >>> 0).toString(16);
    if (kind === "dnsx") return padz(hex, 6).substring(0, 6) + "N0";
    if (kind === "flood") return padz(hex, 6).substring(0, 6) + "F0";
    if (kind === "dga") return padz(hex, 6).substring(0, 6) + "D0";
    return padz(hex, 8);
  }

  // legacy Maltrail type colors (PREFERRED_TRAIL_COLORS + Google palette for the rest): blue DNS, red IP, etc.
  var TYPE_COLORS = { DNS: "#3366cc", IP: "#dc3912", URL: "#ff9900", UA: "#990099", HTTP: "#109618", TCP: "#0099c6", UDP: "#dd4477" };
  // Severity — ported EXACTLY from the legacy Maltrail UI (main.js) so evaluations match what users expect.
  // Order matters; default is MEDIUM. (Earlier v2 wrongly added ipinfo/scanning/crawler/onion/tor to a LOW
  // list that never existed, forcing e.g. "ipinfo (suspicious)" to LOW — it must be MEDIUM.)
  var INFO_SEVERITY_KEYWORDS = [["malware", 3], ["adversary", 3], ["ransomware", 3],
    ["reputation", 1], ["attacker", 1], ["spammer", 1], ["compromised", 1], ["crawler", 1], ["scanning", 1]];
  function severityOf(info, ref) {
    info = (info || "").toLowerCase(); ref = (ref || "").toLowerCase();
    if (ref.indexOf("(custom)") >= 0) return 3;
    if (ref.indexOf("(remote custom)") >= 0) return 3;
    if (info.indexOf("potential malware site") >= 0) return 2;
    if (ref.indexOf("malwaredomainlist") >= 0) return 3;
    if (info.indexOf("malware distribution") >= 0) return 2;
    if (info.indexOf("mass scanner") >= 0) return 1;
    for (var i = 0; i < INFO_SEVERITY_KEYWORDS.length; i++)
      if (info.indexOf(INFO_SEVERITY_KEYWORDS[i][0]) >= 0) return INFO_SEVERITY_KEYWORDS[i][1];
    return 2;   // default MEDIUM (legacy)
  }
  // Threat class = the trailing "(malware)|(malicious)|(suspicious)" in the info field, shown as a
  // color-coded icon (word in the tooltip) instead of raw paren text. Icons are the official Lucide set
  // (biohazard / skull / circle-question-mark), path data inlined so it stays offline/CSP-safe — currentColor per class.
  var _lucideTag = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">';
  var CLASS_ICON = {
    malware: _lucideTag + '<circle cx="12" cy="11.9" r="2"/><path d="M6.7 3.4c-.9 2.5 0 5.2 2.2 6.7C6.5 9 3.7 9.6 2 11.6"/><path d="m8.9 10.1 1.4.8"/><path d="M17.3 3.4c.9 2.5 0 5.2-2.2 6.7 2.4-1.2 5.2-.6 6.9 1.5"/><path d="m15.1 10.1-1.4.8"/><path d="M16.7 20.8c-2.6-.4-4.6-2.6-4.7-5.3-.2 2.6-2.1 4.8-4.7 5.2"/><path d="M12 13.9v1.6"/><path d="M13.5 5.4c-1-.2-2-.2-3 0"/><path d="M17 16.4c.7-.7 1.2-1.6 1.5-2.5"/><path d="M5.5 13.9c.3.9.8 1.8 1.5 2.5"/></svg>',
    malicious: _lucideTag + '<path d="m12.5 17-.5-1-.5 1h1z"/><path d="M15 22a1 1 0 0 0 1-1v-1a2 2 0 0 0 1.56-3.25 8 8 0 1 0-11.12 0A2 2 0 0 0 8 20v1a1 1 0 0 0 1 1z"/><circle cx="15" cy="12" r="1"/><circle cx="9" cy="12" r="1"/></svg>',
    suspicious: _lucideTag + '<circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><path d="M12 17h.01"/></svg>'
  };
  function classOf(info) {
    var m = ("" + info).match(/\(([^)]+)\)\s*$/); if (!m) return null;
    var c = m[1].toLowerCase().trim(); return CLASS_ICON[c] ? c : null;
  }
  // small "local network" icon (Lucide network) shown beside private/LAN IPs, like the legacy lan.gif
  var LAN_ICON = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="16" y="16" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="9" y="2" width="6" height="6" rx="1"/><path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3"/><path d="M12 12V8"/></svg>';
  function isPrivIP(ip) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(ip) && !isPubIP(ip); }   // valid IPv4 in a private/reserved range
  var sevName = function (s) { return s === 3 ? "high" : s === 2 ? "medium" : "low"; };
  var sevClass = function (s) { return s === 3 ? "h" : s === 2 ? "m" : "l"; };
  var sevColor = function (s) { return s === 3 ? "#F43F5E" : s === 2 ? "#F59E0B" : "#64748B"; };

  // contrast-aware label text for FILLED chips: pick whichever of white/near-black has the better WCAG contrast
  // against the fill (more correct than a YIQ threshold). Returns "#ffffff" or "#0b1220".
  function _lum(r, g, b) { function f(v) { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); } return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b); }
  function _bestText(r, g, b) { var L = _lum(r, g, b); return (1.05 / (L + 0.05)) >= ((L + 0.05) / 0.056) ? "#ffffff" : "#0b1220"; }
  function _hslRgb(h, s, l) {
    var c = (1 - Math.abs(2 * l - 1)) * s, x = c * (1 - Math.abs((h / 60) % 2 - 1)), m = l - c / 2, r, g, b;
    if (h < 60) { r = c; g = x; b = 0; } else if (h < 120) { r = x; g = c; b = 0; } else if (h < 180) { r = 0; g = c; b = x; }
    else if (h < 240) { r = 0; g = x; b = c; } else if (h < 300) { r = x; g = 0; b = c; } else { r = c; g = 0; b = x; }
    return [(r + m) * 255, (g + m) * 255, (b + m) * 255];
  }
  function hexText(hex) { hex = ("" + hex).replace("#", ""); return _bestText(parseInt(hex.substr(0, 2), 16), parseInt(hex.substr(2, 2), 16), parseInt(hex.substr(4, 2), 16)); }
  function hslText(h, s, l) { var c = _hslRgb(h, s, l); return _bestText(c[0], c[1], c[2]); }
  function ltClass(color) { return color === "#ffffff" ? "lt-w" : "lt-d"; }   // text-outline direction (legacy 4-way outline) for legibility on mid-tones
  // per-threat color (deterministic): used by the threat-id chip fill, the Threats donut, and the mini — kept identical
  function uidHue(uidc) { return (murmur3(uidc, 7) >>> 0) % 360; }
  function uidColor(uidc) { return "hsl(" + uidHue(uidc) + ",60%,48%)"; }
  function uidText(uidc) { return hslText(uidHue(uidc), 0.60, 0.48); }
  function otherColor() { return document.body.classList.contains("light") ? "#aeb9c7" : "#3a4a63"; }   // "other" donut slice — softer slate in light (dark gray clashed on white)
  function hourOf(t) { var h = +("" + t).substr(11, 2); return h >= 0 && h < 24 ? h : 0; }   // "YYYY-MM-DD HH:.." -> HH (substr, no regex; per-event hot path)
  function hms(t) { var m = /(\d{2}):(\d{2}):(\d{2})/.exec(t); return m ? m[0] : t; }
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) { return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]; }); }
  function ipKey(s) { return ((s || "").match(/\d+/g) || []).map(function (n) { return ("00" + n).slice(-3); }).join("."); }

  // Dense inline 24h activity sparkline for a table row — a string of <rect> bars (one per hour of the day)
  // as an SVG, so it drops straight into the row HTML with no per-row canvas. Empty hours draw nothing; the
  // busiest hour is drawn full-height. ~50×13px so it fits the events cell without widening the row height.
  function rowSpark(hours) {
    if (!hours) return "";
    var max = 1, i, total = 0;
    for (i = 0; i < 24; i++) { if (hours[i] > max) max = hours[i]; total += hours[i]; }
    if (!total) return "";
    var bw = 1.6, gap = 0.5, H = 13, W = 24 * (bw + gap), bars = "", peakH = 0, peakHr = 0;
    for (i = 0; i < 24; i++) {
      if (hours[i] > peakH) { peakH = hours[i]; peakHr = i; }
      var x = (i * (bw + gap)).toFixed(2);
      if (hours[i] <= 0) { bars += '<rect class="z" x="' + x + '" y="' + (H - 1.2).toFixed(1) + '" width="' + bw + '" height="1.2"/>'; continue; }   // empty hour: baseline dot so the full 0-24h axis always shows
      var bh = Math.max(2, hours[i] / max * (H - 1)), y = (H - bh).toFixed(2);
      bars += '<rect x="' + x + '" y="' + y + '" width="' + bw + '" height="' + bh.toFixed(2) + '"' + (hours[i] === max ? ' class="pk"' : '') + '/>';
    }
    var hh = (peakHr < 10 ? "0" : "") + peakHr;
    return '<svg class="rowspark" viewBox="0 0 ' + W.toFixed(1) + ' ' + H + '" width="' + Math.round(W) + '" height="' + H + '" aria-hidden="true"><title>24h activity — peak ' + peakH + '/h at ' + hh + ':00</title>' + bars + '</svg>';
  }

  function spark(cv, data, color) {
    var dpr = window.devicePixelRatio || 1, w = 64, h = 22;
    cv.width = w * dpr; cv.height = h * dpr; cv.style.width = w + "px"; cv.style.height = h + "px";
    var ctx = cv.getContext("2d"); ctx.scale(dpr, dpr);
    var max = Math.max.apply(null, data.concat([1])), bw = w / data.length;
    for (var i = 0; i < data.length; i++) {
      var bh = Math.max(2, (data[i] / max) * h);
      ctx.fillStyle = color; ctx.globalAlpha = 0.35 + 0.65 * (data[i] / max);
      ctx.fillRect(i * bw + 1, h - bh, Math.max(1, bw - 1.5), bh);
    }
  }

  // mini line sparkline — the minified form of a line chart (Events expands to a multi-line-by-type chart)
  function sparkLine(cv, data, color) {
    var dpr = window.devicePixelRatio || 1, w = 64, h = 22, pad = 2;
    cv.width = w * dpr; cv.height = h * dpr; cv.style.width = w + "px"; cv.style.height = h + "px";
    var ctx = cv.getContext("2d"); ctx.scale(dpr, dpr);
    var max = Math.max.apply(null, data.concat([1])), n = data.length, gx = (w - pad * 2) / (n - 1 || 1);
    ctx.strokeStyle = color; ctx.lineWidth = 1.5; ctx.lineJoin = "round"; ctx.beginPath();
    for (var i = 0; i < n; i++) { var x = pad + gx * i, y = h - pad - (h - pad * 2) * (data[i] / max); if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y); }
    ctx.stroke();
    ctx.lineTo(pad + gx * (n - 1), h); ctx.lineTo(pad, h); ctx.closePath(); ctx.globalAlpha = 0.13; ctx.fillStyle = color; ctx.fill();   // soft area fill
  }
  // mini multi-line — the minified form of the full Events chart: same per-type series + colors, shared y-scale,
  // and each line STOPS at the last hour with data (no flat-zero tail), exactly like drawLines.
  function sparkLines(cv, series) {
    var dpr = window.devicePixelRatio || 1, w = 64, h = 22, pad = 2;
    cv.width = w * dpr; cv.height = h * dpr; cv.style.width = w + "px"; cv.style.height = h + "px";
    var ctx = cv.getContext("2d"); ctx.scale(dpr, dpr);
    var max = 1, lastIdx = 0;
    series.forEach(function (s) { s.data.forEach(function (v, i) { if (v > max) max = v; if (v > 0) lastIdx = Math.max(lastIdx, i); }); });
    var gx = (w - pad * 2) / 23;   // x maps hours 0..23 across the width (matches the full chart)
    series.forEach(function (s, si) {
      ctx.strokeStyle = s.c || PALETTE[si % PALETTE.length]; ctx.lineWidth = 1; ctx.lineJoin = "round"; ctx.globalAlpha = 0.95; ctx.beginPath();
      for (var i = 0; i <= lastIdx; i++) { var x = pad + gx * i, y = h - pad - (h - pad * 2) * (s.data[i] / max); if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y); }
      ctx.stroke();
    });
  }
  // like spark() but each bar takes its own palette color — for categorical minis (Sources) that match a multicolor big chart
  function sparkMulti(cv, data) {
    var dpr = window.devicePixelRatio || 1, w = 64, h = 22;
    cv.width = w * dpr; cv.height = h * dpr; cv.style.width = w + "px"; cv.style.height = h + "px";
    var ctx = cv.getContext("2d"); ctx.scale(dpr, dpr);
    var max = Math.max.apply(null, data.concat([1])), bw = w / data.length;
    for (var i = 0; i < data.length; i++) {
      var bh = Math.max(2, (data[i] / max) * h);
      ctx.fillStyle = PALETTE[i % PALETTE.length]; ctx.globalAlpha = 0.55 + 0.45 * (data[i] / max);
      ctx.fillRect(i * bw + 1, h - bh, Math.max(1, bw - 1.5), bh);
    }
  }
  function aggregate(csv) { return aggregateRows(window.Papa.parse(csv, { delimiter: " ", skipEmptyLines: true }).data); }
  function aggregateRows(rows) {
    var r, row, type, nt;
    // pass 1: flood detection — a normalized trail seen from > FLOOD_THRESH distinct source IPs
    var trailSrcs = new Map();   // Map<nt, Set<src>> — Map/Set, not plain objects: V8 keeps these fast at 100k+ keys (objects degrade to dictionary mode)
    for (r = 0; r < rows.length; r++) {
      row = rows[r];
      if (!row || row.length < 11 || !/^[A-Z]+$/.test(row[7])) continue;
      nt = normTrail(row[8]); var ts0 = trailSrcs.get(nt); if (!ts0) trailSrcs.set(nt, ts0 = new Set()); ts0.add(row[2]);
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
      if (!/^[A-Z]+$/.test(type)) continue;
      events++;
      var hr = hourOf(time); hours[hr]++;
      nt = normTrail(trail);
      srcCounts.set(src, (srcCounts.get(src) || 0) + 1);
      trailCounts.set(nt, (trailCounts.get(nt) || 0) + 1);   // distinct INDICATORS, not raw strings: normTrail strips the variable (...) part so heuristic families ((x).com, rDNS, UA detail) collapse — matches legacy semantics
      typeCounts[type] = (typeCounts[type] || 0) + 1;
      (typeHours[type] || (typeHours[type] = new Array(24).fill(0)))[hr]++;
      var dnsx = info.indexOf(DNS_EXH_INFIX) > -1, isFlood = flood.has(nt),
          dga = info.indexOf(DGA_INFIX) > -1, heur = ref.indexOf(HEUR_INFIX) > -1;
      var ttext, kind = null;
      if (dnsx) { ttext = info + "~>" + nt; kind = "dnsx"; }
      else if (isFlood) { ttext = FLOOD_PREFIX + "~>" + nt; kind = "flood"; }
      else if (dga) { ttext = src + "~>" + info; kind = "dga"; }
      else if (heur) { ttext = src + "~>" + nt + info; }
      else { ttext = src + "~>" + nt; }
      var t = threats.get(ttext);
      if (!t) {
        if (order.length >= MAX_THREATS) { dropped++; continue; }   // safeguard: don't create unbounded threat objects (OOM)
        t = { key: ttext, kind: kind, sensor: sensor, src: src, sport: sport, dst: dst, dport: dport, proto: proto,
              type: type, trail: trail, info: info, ref: ref, count: 0, first: time, last: time,
              hours: new Array(24).fill(0), sev: severityOf(info, ref),
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
  function threatHay(th) {
    return (th.uidc + " " + setList(th.srcS).join(" ") + " " + setList(th.dstS).join(" ") + " " +
            setList(th.sportS).join(" ") + " " + setList(th.dportS).join(" ") + " " + setList(th.protoS).join(" ") + " " + setList(th.sensorS).join(" ") + " " +
            th.type + " " + th.trail + " " + th.info + " " + th.ref + " " + sevName(th.sev)).toLowerCase();
  }
  // Incremental merge: fold ONLY the newly-appended rows into an existing aggregate, in O(new rows).
  // Mirrors aggregateRows' per-event logic exactly so the result matches a full re-aggregate — except a
  // trail newly crossing the flood threshold reclassifies only NEW events (prior grouping self-corrects on
  // the next full load). This is what makes live cheap on a 50MB/day log: no full re-parse, no full re-walk.
  function mergeRows(agg, rows) {
    if (!agg || !agg._byKey) return aggregateRows(rows);   // no baseline -> full
    var threats = agg._byKey, order = agg.threats, trailSrcs = agg._trailSrcs, flood = agg._flood;
    var touched = new Set();
    for (var r = 0; r < rows.length; r++) {
      var row = rows[r];
      if (!row || row.length < 11) continue;
      var type = row[7]; if (!/^[A-Z]+$/.test(type)) continue;
      var time = row[0], sensor = row[1], src = row[2], sport = row[3], dst = row[4],
          dport = row[5], proto = row[6], trail = row[8], info = row[9], ref = row[10];
      agg.events++;
      var hr = hourOf(time); agg.hours[hr]++;
      var sc = agg.srcCounts.get(src); if (sc === undefined) { agg.sources++; agg.srcCounts.set(src, 1); } else agg.srcCounts.set(src, sc + 1);   // running distinct counters (avoid O(total) re-count per tick)
      var nt = normTrail(trail), tset = trailSrcs.get(nt); if (tset === undefined) trailSrcs.set(nt, tset = new Set());
      var tc = agg.trailCounts.get(nt); if (tc === undefined) { agg.trailsN++; agg.trailCounts.set(nt, 1); } else agg.trailCounts.set(nt, tc + 1);   // distinct INDICATORS (normalized)
      agg.typeCounts[type] = (agg.typeCounts[type] || 0) + 1;
      (agg.typeHours[type] || (agg.typeHours[type] = new Array(24).fill(0)))[hr]++;
      if (!tset.has(src)) { tset.add(src); if (!flood.has(nt) && tset.size > FLOOD_THRESH) flood.add(nt); }   // count distinct srcs only when a NEW one appears
      var dnsx = info.indexOf(DNS_EXH_INFIX) > -1, isFlood = flood.has(nt),
          dga = info.indexOf(DGA_INFIX) > -1, heur = ref.indexOf(HEUR_INFIX) > -1;
      var ttext, kind = null;
      if (dnsx) { ttext = info + "~>" + nt; kind = "dnsx"; }
      else if (isFlood) { ttext = FLOOD_PREFIX + "~>" + nt; kind = "flood"; }
      else if (dga) { ttext = src + "~>" + info; kind = "dga"; }
      else if (heur) { ttext = src + "~>" + nt + info; }
      else { ttext = src + "~>" + nt; }
      var t = threats.get(ttext);
      if (!t) {
        if (order.length >= MAX_THREATS) { agg._dropped = (agg._dropped || 0) + 1; continue; }   // OOM safeguard
        t = { key: ttext, kind: kind, sensor: sensor, src: src, sport: sport, dst: dst, dport: dport, proto: proto,
              type: type, trail: trail, info: info, ref: ref, count: 0, first: time, last: time,
              hours: new Array(24).fill(0), sev: severityOf(info, ref),
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
    touched.forEach(function (t) { t._hay = null; });   // INVALIDATE haystack (cheap); rebuilt lazily in hay() only if a free-text search needs it — avoids rebuilding a long string for every touched threat on every chunk during a 100MB load
    return agg;   // sources / trailsN already maintained as running counters above
  }

  function fmtK(n) { return n >= 1000 ? (n / 1000).toFixed(1).replace(/\.0$/, "") + "k" : "" + n; }
  // exact integer with thousands separators (deterministic "," grouping — no locale ambiguity); for the big stat counts
  function fmtN(n) { return ("" + n).replace(/\B(?=(\d{3})+(?!\d))/g, ","); }
  // Log timestamps are written in the SENSOR's local time. The server injects its UTC offset (minutes east) into
  // <body data-tz>, so "x ago" / spans are correct even when the viewer's timezone differs from the sensor's.
  // Unknown (demo / file:// / pre-token build) -> interpret as the viewer's local time (prior behavior, no drift vs itself).
  var _srvTz;
  function srvTz() { if (_srvTz !== undefined) return _srvTz; var v = null; try { var b = document.body && document.body.getAttribute("data-tz"); if (b && /^-?\d+$/.test(b.trim())) v = parseInt(b, 10); } catch (e) {} _srvTz = v; return v; }
  function parseTs(t) {
    var m = ("" + t).match(/(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})/); if (!m) return null;
    var tz = srvTz();
    if (tz == null) return new Date(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]).getTime();   // unknown -> viewer-local
    return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) - tz * 60000;                // sensor-local components -> true UTC epoch
  }
  function durationStr(a, b) {
    var pa = parseTs(a), pb = parseTs(b); if (pa == null || pb == null) return "";
    var s = Math.max(0, Math.round((pb - pa) / 1000));
    return s < 60 ? s + "s" : s < 3600 ? Math.round(s / 60) + "m" : (s / 3600).toFixed(1) + "h";
  }
  // "12s / 3m / 5h ago" for events within the last 24h (great for live); null => caller shows the absolute time
  function relAge(ts) {
    var p = parseTs(ts); if (p == null) return null;
    var now = (DEMO && state._demoNow) ? state._demoNow : +new Date();
    var s = Math.floor((now - p) / 1000); if (s < 0) s = 0;
    if (s < 60) return s + "s ago";
    if (s < 3600) return Math.floor(s / 60) + "m ago";
    if (s < 86400) return Math.floor(s / 3600) + "h ago";
    return null;
  }
  function refreshRelTimes() {   // tick the relative labels in place so live stays fresh between renders
    var els = document.querySelectorAll('#rows .reltime[data-ts]');
    for (var i = 0; i < els.length; i++) { var ts = els[i].getAttribute('data-ts'), a = relAge(ts); els[i].textContent = a || hms(ts); }
  }

  // severity mini bar: width of each segment is PROPORTIONAL to its count, and a ZERO count draws NO segment
  // (the old `count || 1` fallback drew a full-flex bar for 0 -> e.g. 2hi/1md/0lo wrongly showed a "low" segment).
  function sevPillrow(sev) {
    var cols = ["var(--sev-high)", "var(--sev-med)", "var(--sev-low)"], out = "";
    for (var i = 0; i < 3; i++) if (sev[i] > 0) out += '<i style="background:' + cols[i] + ';flex:' + sev[i] + '"></i>';
    return '<div class="sev-pillrow">' + (out || '<i style="background:var(--line-solid);flex:1"></i>') + "</div>";   // all-zero -> one muted bar (not empty)
  }
  function renderStats(d) {
    var domSev = d.sevCount[3] >= d.sevCount[2] && d.sevCount[3] >= d.sevCount[1] ? "high"
               : d.sevCount[2] >= d.sevCount[1] ? "medium" : "low";
    // each mini previews the chart its card opens: Threats/Sources/Trails => top-N magnitude bars
    // (the same data the big donut/bars chart draws), Events => 24h volume, Severity => hi/md/lo split.
    var vals = function (obj, n) { return topN(obj, n).items.map(function (x) { return x[1]; }); };
    // Each mini mirrors the chart its card opens: Threats/Trails = donut, Sources = multicolor bars,
    // Severity = hi/md/lo split pill-row, Events = the SAME multi-line-by-type series as its full chart.
    var topThreats = d.threats.slice().sort(function (a, b) { return b.count - a.count; });
    var threatSlices = topThreats.slice(0, 6).map(function (t) { return { v: t.count, c: uidColor(t.uidc) }; });
    var tOther = topThreats.slice(6).reduce(function (s, t) { return s + t.count; }, 0); if (tOther) threatSlices.push({ v: tOther, c: otherColor() });
    var trN = topN(d.trailCounts, 6), trailSlices = trN.items.map(function (x, i) { return { v: x[1], c: PALETTE[i % PALETTE.length] }; });
    if (trN.other) trailSlices.push({ v: trN.other, c: otherColor() });
    var etypes = Object.keys(d.typeHours).sort(function (a, b) { return d.typeCounts[b] - d.typeCounts[a]; }).slice(0, 5);
    var eseries = etypes.map(function (t, i) { return { data: d.typeHours[t], c: TYPE_COLORS[t] || PALETTE[i] }; });
    var cards = [
      { lbl: "Threats", num: fmtN(d.threats.length), sub: "distinct threats", donut: threatSlices.length ? threatSlices : null, color: "#38BDF8", data: vals(d.srcCounts, 18) },
      { lbl: "Events", num: fmtN(d.events), sub: "across 24h", lines: eseries.length ? eseries : null, color: "#6366F1", data: d.hours },
      { lbl: "Severity", num: domSev, sub: d.sevCount[3] + " hi · " + d.sevCount[2] + " md · " + d.sevCount[1] + " lo",
        sev: [d.sevCount[3], d.sevCount[2], d.sevCount[1]] },
      { lbl: "Sources", num: fmtN(d.sources), sub: "distinct src IPs", multi: true, color: "#34D399", data: vals(d.srcCounts, 18) },
      { lbl: "Trails", num: fmtN(d.trailsN), sub: "distinct indicators", donut: trailSlices.length ? trailSlices : null, color: "#A78BFA", data: vals(d.trailCounts, 18) }
    ];
    var sc = document.getElementById("stats"); sc.innerHTML = "";
    cards.forEach(function (s) {
      var el = document.createElement("div"); el.className = "card"; el.dataset.chart = s.lbl;
      el.onclick = function () { showChart(s.lbl); };
      el.innerHTML = '<span class="tick"></span><div class="lbl">' + s.lbl + '</div><div class="num">' + s.num +
        '</div><div class="sub">' + s.sub + '</div>' +
        (s.sev ? sevPillrow(s.sev) : '<canvas></canvas>');
      sc.appendChild(el);
      var cv = el.querySelector("canvas"); if (cv) { if (s.donut) miniDonut(cv, s.donut); else if (s.lines) sparkLines(cv, s.lines); else if (s.multi) sparkMulti(cv, s.data); else spark(cv, s.data, s.color); }
    });
  }

  // Rebuild the dashboard aggregate from a FILTERED threat list so the 5 cards + open chart report only what's
  // shown, not the whole day. Threats / Severity / Events / Trails are exact (rebuilt from each threat's stored
  // per-hour counts + trail). Sources are approximate: per-src event counts aren't kept per threat (srcS is a
  // capped distinct set), so events attribute to each threat's PRIMARY src; the distinct-source COUNT uses the union.
  function buildViewAgg(list) {
    var srcCounts = new Map(), trailCounts = new Map(), typeHours = {}, typeCounts = {},
        hours = new Array(24).fill(0), sevCount = { 1: 0, 2: 0, 3: 0 }, srcDistinct = new Set(), events = 0;
    for (var i = 0; i < list.length; i++) {
      var t = list[i], th = t.hours;
      events += t.count; sevCount[t.sev] = (sevCount[t.sev] || 0) + 1;
      for (var h = 0; h < 24; h++) hours[h] += th[h];
      typeCounts[t.type] = (typeCounts[t.type] || 0) + t.count;
      var tph = typeHours[t.type] || (typeHours[t.type] = new Array(24).fill(0));
      for (var h2 = 0; h2 < 24; h2++) tph[h2] += th[h2];
      var nt = normTrail(t.trail); trailCounts.set(nt, (trailCounts.get(nt) || 0) + t.count);
      srcCounts.set(t.src, (srcCounts.get(t.src) || 0) + t.count);
      if (t.srcS && t.srcS.vals) t.srcS.vals.forEach(function (x) { srcDistinct.add(x); });
    }
    return { threats: list, events: events, hours: hours, srcCounts: srcCounts, sources: srcDistinct.size || srcCounts.size,
             trailCounts: trailCounts, trailsN: trailCounts.size, typeHours: typeHours, typeCounts: typeCounts, sevCount: sevCount, _view: true };
  }
  // signature of the active filter inputs — used to re-render the cards/chart only when the filtered SET changes
  function statsFilterSig() {
    return (state.input || "") + "" + (state.sev == null ? "" : state.sev) + "" +
           (state.filters || []).join("") + "" + (state.showHidden ? "1" : "0") + "" +
           wlCount() + "" + Object.keys(state.hidden || {}).length;
  }

  // ---- canvas charts (no D3 / Chart.js) ----
  var PALETTE = ["#38BDF8", "#A78BFA", "#34D399", "#F472B6", "#FBBF24", "#22D3EE", "#F43F5E", "#818CF8", "#FB923C", "#2DD4BF"];
  function topN(m, n) {   // m is a Map<key,count> (srcCounts / trailCounts)
    var arr = []; m.forEach(function (v, k) { arr.push([k, v]); }); arr.sort(function (a, b) { return b[1] - a[1]; });
    if (arr.length <= n) return { items: arr, other: 0 };
    return { items: arr.slice(0, n), other: arr.slice(n).reduce(function (s, x) { return s + x[1]; }, 0) };
  }
  function cctx(cv) { var dpr = window.devicePixelRatio || 1; cv.width = cv._w * dpr; cv.height = cv._h * dpr; cv.style.width = cv._w + "px"; cv.style.height = cv._h + "px"; var c = cv.getContext("2d"); c.scale(dpr, dpr); return c; }
  function themeColors() {
    var cs = getComputedStyle(document.body), g = function (n, fb) { var v = (cs.getPropertyValue(n) || "").trim(); return v || fb; };
    return { surface: g("--surface", "#161D2B"), text: g("--text", "#E6EDF3"), muted: g("--muted", "#8A97AD"), faint: g("--faint", "#5A6678"), line: g("--line-solid", "#273145") };
  }
  // centerNum/centerLabel: what the hole shows (e.g. 498 / "threats"). Slice ANGLES stay proportional to event
  // counts (s.v), but the center reflects the card's distinct metric — not the event total (which confused users).
  function drawDonut(cv, slices, centerNum, centerLabel) {
    var tc = themeColors();
    var w = cv._w, h = cv._h, ctx = cctx(cv), cx = h / 2 + 6, cy = h / 2, R = h / 2 - 12, r = R * 0.6, a = -Math.PI / 2,
        total = slices.reduce(function (s, x) { return s + x.v; }, 0) || 1;
    slices.forEach(function (s, i) { var ang = s.v / total * Math.PI * 2; ctx.beginPath(); ctx.moveTo(cx, cy); ctx.arc(cx, cy, R, a, a + ang); ctx.closePath(); ctx.fillStyle = s.c || PALETTE[i % PALETTE.length]; ctx.fill(); a += ang; });
    ctx.beginPath(); ctx.arc(cx, cy, r, 0, Math.PI * 2); ctx.fillStyle = tc.surface; ctx.fill();
    var centerVal = centerNum != null ? centerNum : total, centerTxt = centerLabel || "total";
    ctx.fillStyle = tc.text; ctx.font = "600 22px ui-monospace,monospace"; ctx.textAlign = "center"; ctx.textBaseline = "middle"; ctx.fillText(fmtN(centerVal), cx, cy - 6);
    ctx.fillStyle = tc.muted; ctx.font = "10px system-ui"; ctx.fillText(centerTxt, cx, cy + 12);
    var lx = cx + R + 26, ly = 18, hits = [];
    slices.slice(0, 11).forEach(function (s, i) { ctx.fillStyle = s.c || PALETTE[i % PALETTE.length]; ctx.fillRect(lx, ly - 7, 10, 10); ctx.fillStyle = tc.text; ctx.font = "12px ui-monospace,monospace"; ctx.textAlign = "left"; ctx.textBaseline = "middle"; var k = s.k.length > 24 ? s.k.slice(0, 23) + "…" : s.k, disp = k + "   " + s.v; ctx.fillText(disp, lx + 16, ly); if (s.token) hits.push({ x: lx - 4, y: ly - 11, w: 20 + ctx.measureText(disp).width, h: 16, token: s.token, label: s.k }); ly += 19; });   // include the trailing "other" slice (was cut at 9); hit fits the text
    return hits;
  }
  // Interactive donut: same look as drawDonut, but slices pop out + enlarge (with a soft glow) on hover,
  // a tooltip shows label · count · %, and slices are click-to-filter. Returns the legend hits (unchanged
  // contract) so showChart's overlay-button code keeps working. Respects prefers-reduced-motion (snaps).
  function drawInteractiveDonut(cv, slices, centerNum, centerLabel) {
    var reduce = false; try { reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches; } catch (e) { }
    var total = slices.reduce(function (s, x) { return s + x.v; }, 0) || 1;
    var a = -Math.PI / 2;   // slice ANGLES are fixed; hover only changes each slice's radius/offset (s._t: 0→1 eased)
    slices.forEach(function (s) { var ang = s.v / total * Math.PI * 2; s._a0 = a; s._a1 = a + ang; s._mid = a + ang / 2; s._t = 0; a = s._a1; });
    var hovered = -1, legendHits = [], raf = 0, tipEl = null;
    // reserve 16px so the hover pop/grow/glow (below) can't spill outside the canvas and get clipped
    function geo() { var h = cv._h; var R = h / 2 - 16; return { cx: h / 2 + 6, cy: h / 2, R: R, r: R * 0.6 }; }

    function paint() {
      var tc = themeColors(), ctx = cctx(cv), G = geo();
      slices.forEach(function (s, i) {
        var t = s._t, full = (s._a1 - s._a0) >= Math.PI * 2 - 0.001;   // a single (full-circle) slice must NOT pop — it would shift the whole disc off-center and clip
        var pop = full ? 0 : t * 7, oR = G.R + (full ? t * 2 : t * 5),
            ox = G.cx + Math.cos(s._mid) * pop, oy = G.cy + Math.sin(s._mid) * pop;
        ctx.beginPath(); ctx.moveTo(ox, oy); ctx.arc(ox, oy, oR, s._a0, s._a1); ctx.closePath();
        ctx.fillStyle = s.c || PALETTE[i % PALETTE.length];
        if (t > 0.01) { ctx.save(); ctx.shadowColor = ctx.fillStyle; ctx.shadowBlur = 12 * t; ctx.fill(); ctx.restore(); } else ctx.fill();
      });
      ctx.beginPath(); ctx.arc(G.cx, G.cy, G.r, 0, Math.PI * 2); ctx.fillStyle = tc.surface; ctx.fill();
      // center ALWAYS shows the card's distinct metric (e.g. "498 threats") — never the hovered slice's event
      // count, which is what confused people (hover said "47", filtering to that 1 threat then said "1"). The
      // per-slice event count + share lives in the hover tooltip, clearly labelled, instead.
      ctx.fillStyle = tc.text; ctx.font = "600 22px ui-monospace,monospace"; ctx.textAlign = "center"; ctx.textBaseline = "middle"; ctx.fillText(fmtN(centerNum != null ? centerNum : total), G.cx, G.cy - 6);
      ctx.fillStyle = tc.muted; ctx.font = "10px system-ui"; ctx.fillText(centerLabel || "total", G.cx, G.cy + 12);
      var lx = G.cx + G.R + 26, ly = 18, hits = [];
      slices.slice(0, 11).forEach(function (s, i) {
        ctx.fillStyle = s.c || PALETTE[i % PALETTE.length]; ctx.fillRect(lx, ly - 7, 10, 10);
        ctx.fillStyle = tc.text; ctx.font = (i === hovered ? "600 " : "") + "12px ui-monospace,monospace"; ctx.textAlign = "left"; ctx.textBaseline = "middle";
        var k = s.k.length > 24 ? s.k.slice(0, 23) + "…" : s.k, disp = k + "   " + s.v;
        ctx.fillText(disp, lx + 16, ly);
        if (s.token) hits.push({ x: lx - 4, y: ly - 11, w: 20 + ctx.measureText(disp).width, h: 16, token: s.token, label: s.k });
        ly += 19;
      });
      legendHits = hits;
    }
    function tick() {
      raf = 0; var moving = false;
      slices.forEach(function (s, i) {
        var tgt = i === hovered ? 1 : 0;
        if (reduce) { s._t = tgt; } else if (Math.abs(tgt - s._t) < 0.01) { s._t = tgt; } else { s._t += (tgt - s._t) * 0.28; moving = true; }
      });
      paint();
      if (moving && document.body.contains(cv)) raf = requestAnimationFrame(tick);
    }
    function kick() { if (!raf) raf = requestAnimationFrame(tick); }
    function sliceAt(mx, my) {
      var G = geo(), dx = mx - G.cx, dy = my - G.cy, dist = Math.sqrt(dx * dx + dy * dy);
      if (dist < G.r * 0.85 || dist > G.R + 18) return -1;
      var ang = Math.atan2(dy, dx); while (ang < -Math.PI / 2) ang += Math.PI * 2;
      for (var i = 0; i < slices.length; i++) if (ang >= slices[i]._a0 && ang < slices[i]._a1) return i;
      return -1;
    }
    function tip(i, mx, my) {
      var host = cv.parentNode; if (!host) return;
      if (!tipEl) { tipEl = document.createElement("div"); tipEl.className = "donut-tip"; host.appendChild(tipEl); }
      var s = slices[i], pct = Math.round(s.v / total * 100);
      tipEl.innerHTML = "<b>" + esc(s.k) + "</b><span>" + fmtN(s.v) + " event" + (s.v === 1 ? "" : "s") + " · " + pct + "%</span>";
      tipEl.style.display = "block"; tipEl.style.left = (mx + 14) + "px"; tipEl.style.top = (my + 14) + "px";
    }
    cv.onmousemove = function (e) {
      var p = evXY(cv, e), mx = p[0], my = p[1], i = sliceAt(mx, my);
      cv.style.cursor = (i >= 0 && slices[i].token) ? "pointer" : "default";
      if (i >= 0) tip(i, mx, my); else if (tipEl) tipEl.style.display = "none";
      if (i !== hovered) { hovered = i; kick(); }
    };
    cv.onmouseleave = function () { if (tipEl) tipEl.style.display = "none"; if (hovered !== -1) { hovered = -1; cv.style.cursor = "default"; kick(); } };
    cv.onclick = function () { if (hovered >= 0 && slices[hovered].token) { hideChart(); addFilter(slices[hovered].token); } };
    paint();   // initial static frame (also populates legendHits)
    return legendHits;
  }
  function drawLines(cv, series) {
    var tc = themeColors();
    var w = cv._w, h = cv._h, ctx = cctx(cv), pad = 30, gw = w - pad * 2 - 96, gh = h - pad * 2, max = 1;
    var lastIdx = 0;   // last hour that actually has data — the line ends here "in the air" (no flat-zero tail)
    series.forEach(function (s) { s.data.forEach(function (v, i) { if (v > max) max = v; if (v > 0) lastIdx = Math.max(lastIdx, i); }); });
    ctx.fillStyle = tc.faint; ctx.font = "10px ui-monospace,monospace"; ctx.textBaseline = "middle";
    for (var g = 0; g <= 4; g++) { var yy = pad + gh - gh * g / 4; ctx.strokeStyle = tc.line; ctx.beginPath(); ctx.moveTo(pad, yy); ctx.lineTo(pad + gw, yy); ctx.stroke(); ctx.textAlign = "right"; ctx.fillText(Math.round(max * g / 4), pad - 6, yy); }
    var lastX = pad + gw * lastIdx / 23;
    if (lastIdx < 23) { ctx.strokeStyle = tc.line; ctx.setLineDash([3, 4]); ctx.beginPath(); ctx.moveTo(lastX, pad); ctx.lineTo(lastX, pad + gh); ctx.stroke(); ctx.setLineDash([]); }  // "data ends here" marker
    series.forEach(function (s, si) {
      var col = s.c || PALETTE[si % PALETTE.length];
      ctx.strokeStyle = col; ctx.lineWidth = 2; ctx.beginPath();
      for (var i = 0; i <= lastIdx; i++) { var x = pad + gw * i / 23, y = pad + gh - gh * s.data[i] / max; if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y); }
      ctx.stroke();
      var ey = pad + gh - gh * s.data[lastIdx] / max; ctx.fillStyle = col; ctx.beginPath(); ctx.arc(lastX, ey, 2.6, 0, Math.PI * 2); ctx.fill();   // endpoint dot
    });
    ctx.fillStyle = tc.faint; ctx.textAlign = "center"; for (var hh = 0; hh < 24; hh += 4) { var x = pad + gw * hh / 23; ctx.fillText((hh < 10 ? "0" : "") + hh + "h", x, pad + gh + 12); }
    var lx = pad + gw + 18, ly = pad + 4, hits = []; series.forEach(function (s, i) { ctx.fillStyle = s.c || PALETTE[i % PALETTE.length]; ctx.fillRect(lx, ly - 5, 12, 3); ctx.fillStyle = tc.text; ctx.font = "11px ui-monospace,monospace"; ctx.textAlign = "left"; ctx.fillText(s.name, lx + 18, ly); if (s.token) hits.push({ x: lx - 4, y: ly - 9, w: 24 + ctx.measureText(s.name).width, h: 15, token: s.token, label: s.name }); ly += 18; });
    return hits;
  }
  function drawBars(cv, items) {
    var tc = themeColors();
    var w = cv._w, h = cv._h, ctx = cctx(cv), pad = 30, gh = h - pad * 2 - 18, n = items.length || 1, gap = (w - pad * 2) / n, bw = gap * 0.6, max = 1;
    items.forEach(function (it) { if (it[1] > max) max = it[1]; });
    for (var g = 0; g <= 4; g++) { var yy = pad + gh - gh * g / 4; ctx.strokeStyle = tc.line; ctx.beginPath(); ctx.moveTo(pad, yy); ctx.lineTo(w - pad, yy); ctx.stroke(); }
    var hits = [];
    items.forEach(function (it, i) { var bh = gh * it[1] / max, x = pad + gap * i + (gap - bw) / 2, y = pad + gh - bh; ctx.fillStyle = PALETTE[i % PALETTE.length]; ctx.fillRect(x, y, bw, bh); ctx.save(); ctx.translate(x + bw / 2, pad + gh + 6); ctx.rotate(Math.PI / 5); ctx.fillStyle = tc.muted; ctx.font = "9px ui-monospace,monospace"; ctx.textAlign = "left"; ctx.fillText(it[0].length > 18 ? it[0].slice(0, 17) + "…" : it[0], 0, 0); ctx.restore(); hits.push({ x: pad + gap * i, y: pad, w: gap, h: gh + 18, token: "src:" + it[0], label: it[0] }); });
    return hits;
  }
  // mini donut for the Threats/Trails stat cards — same shape as their big chart, scaled to the card corner
  function miniDonut(cv, slices) {
    var dpr = window.devicePixelRatio || 1, w = 56, h = 30;
    cv.width = w * dpr; cv.height = h * dpr; cv.style.width = w + "px"; cv.style.height = h + "px";
    var ctx = cv.getContext("2d"); ctx.scale(dpr, dpr);
    var cx = w - 15, cy = h / 2, R = 14, r = 7.5, a = -Math.PI / 2, tc = themeColors();
    var total = slices.reduce(function (s, x) { return s + x.v; }, 0) || 1;
    slices.forEach(function (s, i) { var ang = s.v / total * Math.PI * 2; ctx.beginPath(); ctx.moveTo(cx, cy); ctx.arc(cx, cy, R, a, a + ang); ctx.closePath(); ctx.fillStyle = s.c || PALETTE[i % PALETTE.length]; ctx.fill(); a += ang; });
    ctx.beginPath(); ctx.arc(cx, cy, r, 0, Math.PI * 2); ctx.fillStyle = tc.surface; ctx.fill();
  }
  // horizontal stacked split bar (severity breakdown) — the expanded form of the card's sev-pillrow
  function drawSplitBar(cv, segs) {
    var tc = themeColors(), w = cv._w, h = cv._h, ctx = cctx(cv);
    var pad = 44, bw = w - pad * 2, by = h / 2 - 40, bh = 34, x = pad;
    var total = segs.reduce(function (s, v) { return s + v.v; }, 0) || 1;
    ctx.fillStyle = tc.muted; ctx.font = "12px ui-monospace,monospace"; ctx.textAlign = "left"; ctx.textBaseline = "alphabetic"; ctx.fillText(total + " threats", pad, by - 12);
    segs.forEach(function (s) { var sw = bw * s.v / total; if (sw > 0) { ctx.fillStyle = s.c; ctx.fillRect(x, by, sw, bh); } x += sw; });
    // legend row, evenly spaced
    var ly = by + bh + 34, slot = bw / segs.length, hits = [];
    segs.forEach(function (s, i) {
      var lx = pad + slot * i, pct = Math.round(s.v / total * 100);
      ctx.fillStyle = s.c; ctx.fillRect(lx, ly - 10, 12, 12);
      ctx.fillStyle = tc.text; ctx.font = "13px ui-monospace,monospace"; ctx.textAlign = "left"; ctx.textBaseline = "middle";
      ctx.fillText(s.k, lx + 18, ly - 4);
      var sub = s.v + " · " + pct + "%"; ctx.fillStyle = tc.muted; ctx.font = "11px ui-monospace,monospace"; ctx.fillText(sub, lx + 18, ly + 10);
      if (s.token) hits.push({ x: lx - 4, y: ly - 18, w: 24 + Math.max(ctx.measureText(s.k).width, ctx.measureText(sub).width), h: 36, token: s.token, label: s.k });
    });
    return hits;
  }
  // ---- shared interactive-chart helpers (used by the donut/bars/split hover) ----
  function prefersReduced() { try { return window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches; } catch (e) { return false; } }
  // Mouse position in the canvas's LOGICAL coordinate space (0.._w × 0.._h). Uses getBoundingClientRect ratios,
  // not e.offsetX/offsetY — the latter is wrong under the accessibility CSS `zoom`, so the hit-test would light
  // up the wrong slice/bar at any zoom ≠ 1. The ratio is measured in one consistent space, so zoom cancels out.
  function evXY(cv, e) { var r = cv.getBoundingClientRect(); return [(e.clientX - r.left) / (r.width || 1) * cv._w, (e.clientY - r.top) / (r.height || 1) * cv._h]; }
  function chartTip(cv, html, mx, my) {
    var host = cv.parentNode; if (!host) return;
    var el = host.querySelector(".donut-tip"); if (!el) { el = document.createElement("div"); el.className = "donut-tip"; host.appendChild(el); }
    if (html == null) { el.style.display = "none"; return; }
    el.innerHTML = html; el.style.display = "block"; el.style.left = (mx + 14) + "px"; el.style.top = (my + 14) + "px";
  }
  // Sources bars: hovered bar brightens + widens + glows (others dim), tooltip shows count · %, whole column
  // is click-to-filter. Handles all interaction on the canvas -> returns [] so showChart lays no blocking overlay.
  function drawInteractiveBars(cv, items) {
    var reduce = prefersReduced(), hovered = -1, raf = 0, total = items.reduce(function (s, x) { return s + x[1]; }, 0) || 1;
    items.forEach(function (it) { it._t = 0; });
    function paint() {
      var tc = themeColors(), ctx = cctx(cv), w = cv._w, h = cv._h, pad = 30, gh = h - pad * 2 - 18,
          n = items.length || 1, gap = (w - pad * 2) / n, bw = gap * 0.6, max = 1;
      items.forEach(function (it) { if (it[1] > max) max = it[1]; });
      for (var g = 0; g <= 4; g++) { var yy = pad + gh - gh * g / 4; ctx.strokeStyle = tc.line; ctx.beginPath(); ctx.moveTo(pad, yy); ctx.lineTo(w - pad, yy); ctx.stroke(); }
      items.forEach(function (it, i) {
        var t = it._t, bh = gh * it[1] / max, gw = bw + t * 6, x = pad + gap * i + (gap - gw) / 2, y = pad + gh - bh, col = PALETTE[i % PALETTE.length];
        ctx.globalAlpha = (hovered < 0 || i === hovered) ? 1 : 0.4; ctx.fillStyle = col;
        if (t > 0.01) { ctx.save(); ctx.shadowColor = col; ctx.shadowBlur = 16 * t; ctx.fillRect(x, y, gw, bh); ctx.restore(); } else ctx.fillRect(x, y, gw, bh);
        ctx.globalAlpha = 1;
        ctx.save(); ctx.translate(x + gw / 2, pad + gh + 6); ctx.rotate(Math.PI / 5); ctx.fillStyle = i === hovered ? tc.text : tc.muted; ctx.font = "9px ui-monospace,monospace"; ctx.textAlign = "left"; ctx.fillText(it[0].length > 18 ? it[0].slice(0, 17) + "…" : it[0], 0, 0); ctx.restore();
      });
    }
    function tick() { raf = 0; var moving = false; items.forEach(function (it, i) { var tgt = i === hovered ? 1 : 0; if (reduce) it._t = tgt; else if (Math.abs(tgt - it._t) < 0.01) it._t = tgt; else { it._t += (tgt - it._t) * 0.3; moving = true; } }); paint(); if (moving && document.body.contains(cv)) raf = requestAnimationFrame(tick); }
    function kick() { if (!raf) raf = requestAnimationFrame(tick); }
    function barAt(mx, my) { var w = cv._w, pad = 30, n = items.length || 1, gap = (w - pad * 2) / n; if (mx < pad || mx > w - pad || my < pad) return -1; var i = Math.floor((mx - pad) / gap); return (i >= 0 && i < items.length) ? i : -1; }
    cv.onmousemove = function (e) {
      var p = evXY(cv, e), mx = p[0], my = p[1], i = barAt(mx, my); cv.style.cursor = i >= 0 ? "pointer" : "default";
      if (i >= 0) { var it = items[i]; chartTip(cv, "<b>" + esc(it[0]) + "</b><span>" + fmtN(it[1]) + " event" + (it[1] === 1 ? "" : "s") + " · " + Math.round(it[1] / total * 100) + "%</span>", mx, my); } else chartTip(cv, null);
      if (i !== hovered) { hovered = i; kick(); }
    };
    cv.onmouseleave = function () { chartTip(cv, null); if (hovered !== -1) { hovered = -1; cv.style.cursor = "default"; kick(); } };
    cv.onclick = function () { if (hovered >= 0) { hideChart(); addFilter("src:" + items[hovered][0]); } };
    paint(); return [];
  }
  // Severity split bar: hovered segment brightens + expands + glows (others dim), tooltip shows count · %,
  // click-to-filter. The bottom legend stays as overlay hits (keyboard-clickable; it doesn't overlap the bar).
  function drawInteractiveSplit(cv, segs) {
    var reduce = prefersReduced(), hovered = -1, raf = 0, hits = [], total = segs.reduce(function (s, x) { return s + x.v; }, 0) || 1;
    segs.forEach(function (s) { s._t = 0; s._x = 0; s._w = 0; });
    function geom() { var w = cv._w, h = cv._h, pad = 44; return { w: w, h: h, pad: pad, bw: w - pad * 2, by: h / 2 - 40, bh: 34 }; }
    function paint() {
      var tc = themeColors(), ctx = cctx(cv), G = geom();
      ctx.fillStyle = tc.muted; ctx.font = "12px ui-monospace,monospace"; ctx.textAlign = "left"; ctx.textBaseline = "alphabetic"; ctx.fillText(total + " threats", G.pad, G.by - 12);
      var x = G.pad;
      segs.forEach(function (s, i) {
        var sw = G.bw * s.v / total, t = s._t, exp = t * 7;
        if (sw > 0) { ctx.globalAlpha = (hovered < 0 || i === hovered) ? 1 : 0.4; ctx.fillStyle = s.c;
          if (t > 0.01) { ctx.save(); ctx.shadowColor = s.c; ctx.shadowBlur = 18 * t; ctx.fillRect(x, G.by - exp, sw, G.bh + exp * 2); ctx.restore(); } else ctx.fillRect(x, G.by, sw, G.bh);
          ctx.globalAlpha = 1; }
        s._x = x; s._w = sw; x += sw;
      });
      var ly = G.by + G.bh + 34, slot = G.bw / segs.length; hits = [];
      segs.forEach(function (s, i) {
        var lx = G.pad + slot * i, pct = Math.round(s.v / total * 100);
        ctx.fillStyle = s.c; ctx.fillRect(lx, ly - 10, 12, 12);
        ctx.fillStyle = tc.text; ctx.font = (i === hovered ? "600 " : "") + "13px ui-monospace,monospace"; ctx.textAlign = "left"; ctx.textBaseline = "middle"; ctx.fillText(s.k, lx + 18, ly - 4);
        var sub = s.v + " · " + pct + "%"; ctx.fillStyle = tc.muted; ctx.font = "11px ui-monospace,monospace"; ctx.fillText(sub, lx + 18, ly + 10);
        if (s.token) hits.push({ x: lx - 4, y: ly - 18, w: 24 + Math.max(ctx.measureText(s.k).width, ctx.measureText(sub).width), h: 36, token: s.token, label: s.k });
      });
    }
    function tick() { raf = 0; var moving = false; segs.forEach(function (s, i) { var tgt = i === hovered ? 1 : 0; if (reduce) s._t = tgt; else if (Math.abs(tgt - s._t) < 0.01) s._t = tgt; else { s._t += (tgt - s._t) * 0.3; moving = true; } }); paint(); if (moving && document.body.contains(cv)) raf = requestAnimationFrame(tick); }
    function kick() { if (!raf) raf = requestAnimationFrame(tick); }
    function segAt(mx, my) { var G = geom(); if (my < G.by - 12 || my > G.by + G.bh + 12) return -1; for (var i = 0; i < segs.length; i++) if (segs[i]._w > 0 && mx >= segs[i]._x && mx < segs[i]._x + segs[i]._w) return i; return -1; }
    cv.onmousemove = function (e) {
      var p = evXY(cv, e), mx = p[0], my = p[1], i = segAt(mx, my); cv.style.cursor = (i >= 0 && segs[i].token) ? "pointer" : "default";
      if (i >= 0) { var s = segs[i]; chartTip(cv, "<b>" + esc(s.k) + "</b><span>" + fmtN(s.v) + " threat" + (s.v === 1 ? "" : "s") + " · " + Math.round(s.v / total * 100) + "%</span>", mx, my); } else chartTip(cv, null);
      if (i !== hovered) { hovered = i; kick(); }
    };
    cv.onmouseleave = function () { chartTip(cv, null); if (hovered !== -1) { hovered = -1; cv.style.cursor = "default"; kick(); } };
    cv.onclick = function () { if (hovered >= 0 && segs[hovered].token) { hideChart(); addFilter(segs[hovered].token); } };
    paint(); return hits;
  }
  function showChart(type) {
    var area = document.getElementById("chart_area"), d = state.viewAgg || state.agg; if (!area || !d) return;   // follow the filtered set
    if (state.chart === type) { hideChart(); return; }
    state.chart = type; state._openChart = type; syncHash();   // keep the URL's chart= in sync (bookmarkable)
    document.querySelectorAll(".card").forEach(function (c) { c.classList.toggle("active", c.dataset.chart === type); });
    area.innerHTML = '<div class="chart-panel"><div class="chart-head"><span>' + esc(type) + ' breakdown</span><span class="chart-x">✕</span></div><div class="chart-cv"><canvas id="bigchart"></canvas></div></div>';   // esc(): `type` can come from the attacker-controlled #chart= URL fragment (parseHash) -> DOM XSS if raw
    area.querySelector(".chart-x").onclick = hideChart;
    var cv = document.getElementById("bigchart"); cv._w = Math.min(980, (area.clientWidth || 940) - 34); cv._h = 250;
    var hits = [];
    if (type === "Severity") hits = drawInteractiveSplit(cv, [{ k: "high", v: d.sevCount[3], c: "#F43F5E", token: "sev:high" }, { k: "medium", v: d.sevCount[2], c: "#F59E0B", token: "sev:medium" }, { k: "low", v: d.sevCount[1], c: "#64748B", token: "sev:low" }]);
    else if (type === "Trails") { var tn = topN(d.trailCounts, 9), sl = tn.items.map(function (x) { return { k: x[0], v: x[1], token: "trail:" + x[0] }; }); if (tn.other) sl.push({ k: "other", v: tn.other, c: otherColor() }); hits = drawInteractiveDonut(cv, sl, d.trailsN, "trails"); }
    else if (type === "Threats") { var ts = (d.threats || state.all).slice().sort(function (a, b) { return b.count - a.count; }), sl = ts.slice(0, 9).map(function (t) { return { k: t.uidc, v: t.count, c: uidColor(t.uidc), token: "uid:" + t.uidc }; }); var oth = ts.slice(9).reduce(function (s, t) { return s + t.count; }, 0); if (oth) sl.push({ k: "other", v: oth, c: otherColor() }); hits = drawInteractiveDonut(cv, sl, d.threats.length, "threats"); }   // include "other" so the big donut matches the mini (like Trails)
    else if (type === "Sources") hits = drawInteractiveBars(cv, topN(d.srcCounts, 14).items);
    else { var types = Object.keys(d.typeHours).sort(function (a, b) { return d.typeCounts[b] - d.typeCounts[a]; }).slice(0, 5); hits = drawLines(cv, types.map(function (t, i) { return { name: t, data: d.typeHours[t], c: TYPE_COLORS[t] || PALETTE[i], token: "type:" + t }; })); }
    // overlay transparent clickable buttons on the painted legend (canvas text isn't clickable) -> apply that filter
    var ov = area.querySelector(".chart-cv");
    hits.forEach(function (hit) {
      var bt = document.createElement("button"); bt.className = "chart-hit"; bt.title = "filter: " + hit.token;
      bt.style.left = hit.x + "px"; bt.style.top = hit.y + "px"; bt.style.width = hit.w + "px"; bt.style.height = hit.h + "px";
      bt.setAttribute("aria-label", "filter by " + hit.label);
      bt.onclick = function () { hideChart(); addFilter(hit.token); };
      ov.appendChild(bt);
    });
  }
  function hideChart() { state.chart = null; state._openChart = ""; var a = document.getElementById("chart_area"); if (a) a.innerHTML = ""; document.querySelectorAll(".card").forEach(function (c) { c.classList.remove("active"); }); syncHash(); }

  // ---- interactive view state ----
  // ---- local persistence (hidden threats, UID-keyed; UID is byte-compatible with the legacy frontend) ----
  var LS_HIDDEN = "mt_hidden_v2";
  function lsGet(k, d) { try { var v = localStorage.getItem(k); return v ? JSON.parse(v) : d; } catch (e) { return d; } }
  function lsSet(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) { } }
  function loadHidden() { var o = lsGet(LS_HIDDEN, {}); return (o && typeof o === "object") ? o : {}; }
  function saveHidden() { lsSet(LS_HIDDEN, state.hidden); }
  function toggleHide(uid) { if (!uid) return; if (state.hidden[uid]) delete state.hidden[uid]; else state.hidden[uid] = 1; saveHidden(); refresh(); }
  function unhideAll() { state.hidden = {}; saveHidden(); refresh(); }

  // ===== Triage: whitelist rules + right-click context menu + OSINT lookups =====
  var LS_WL = "mt_whitelist_v2";
  function loadWL() { var o = lsGet(LS_WL, null); o = (o && typeof o === "object") ? o : {}; o.src = o.src || {}; o.trail = o.trail || {}; return o; }
  function saveWL() { lsSet(LS_WL, state.wl); }
  function wlCount() { return Object.keys(state.wl.src).length + Object.keys(state.wl.trail).length; }
  function isWL(t) {
    var w = state.wl;
    if (w.src[t.src]) return true;
    if (w.trail[normTrail(t.trail)]) return true;
    var ss = setList(t.srcS); for (var i = 0; i < ss.length; i++) if (w.src[ss[i]]) return true;
    return false;
  }
  function whitelistSrc(ip) { if (ip) { state.wl.src[ip] = 1; saveWL(); state.page = 0; refresh(); } }
  function whitelistTrail(tr) { tr = normTrail(tr); if (tr) { state.wl.trail[tr] = 1; saveWL(); state.page = 0; refresh(); } }
  function unWL(kind, val) { if (state.wl[kind]) delete state.wl[kind][val]; saveWL(); refresh(); }
  function clearWL() { state.wl = { src: {}, trail: {} }; saveWL(); refresh(); }
  function openLookup(kind, val) {
    if (!val) return;
    var u = kind === "vt-ip" ? "https://www.virustotal.com/gui/ip-address/" + encodeURIComponent(val)
      : kind === "abuse" ? "https://www.abuseipdb.com/check/" + encodeURIComponent(val)
      : kind === "shodan" ? "https://www.shodan.io/host/" + encodeURIComponent(val)
      : kind === "vt-dom" ? "https://www.virustotal.com/gui/domain/" + encodeURIComponent(val)
      : kind === "urlscan" ? "https://urlscan.io/search/#" + encodeURIComponent(val) : null;
    if (u) window.open(u, "_blank", "noopener");
  }
  // ===== Export: current filtered view -> CSV / JSON / defanged IOCs (client-side download) =====
  function csvCell(v) { v = "" + (v == null ? "" : v); if (/^[=+\-@\t\r]/.test(v)) v = "'" + v; /* neutralize spreadsheet formula injection (=cmd…, @SUM…) from attacker-controlled trail/info/tag fields opened in Excel/Sheets */ return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }
  function buildCSV() {
    var rows = viewList();
    var out = ["severity,uid,events,first_seen,last_seen,sensors,sources,destinations,ports,protocols,type,trail,info,reference,tags"];
    rows.forEach(function (t) {
      out.push([sevName(t.sev), t.uidc, t.count, t.first, t.last, setList(t.sensorS).join("|"), setList(t.srcS).join("|"), setList(t.dstS).join("|"),
        setList(t.dportS).join("|"), setList(t.protoS).join("|"), t.type, t.trail, t.info, t.ref, (state.tags[t.uidc] || "")].map(csvCell).join(","));
    });
    return out.join("\n");
  }
  function buildJSON() {
    return JSON.stringify(viewList().map(function (t) {
      return { severity: sevName(t.sev), uid: t.uidc, events: t.count, first_seen: t.first, last_seen: t.last,
        sensors: setList(t.sensorS), sources: setList(t.srcS), destinations: setList(t.dstS), ports: setList(t.dportS), protocols: setList(t.protoS),
        type: t.type, trail: t.trail, info: t.info, reference: t.ref, tags: tagsOf(t.uidc) };
    }), null, 2);
  }
  function defang(s) { return ("" + s).replace(/http/gi, "hxxp").replace(/:\/\//g, "[://]").replace(/\./g, "[.]"); }
  function buildIOC() {
    var rows = viewList(), set = {};
    rows.forEach(function (t) {
      // IOC = the real domain/IP. Decode escaped parens, drop a TRAILING " (annotation)" (reverse-DNS / UA detail),
      // then strip the remaining (embedded) paren chars so a heuristic "(sld).tld" yields "sld.tld" — the old
      // remove-parens-AND-content turned "(btmaq).com" into the useless bare suffix "com".
      var bare = charTrim(charTrim(("" + t.trail).replace(/\\\(/g, "(").replace(/\\\)/g, ")").replace(/\s*\([^()]*\)\s*$/, "").replace(/[()]/g, ""), " "), ".");
      if (bare) set[bare] = 1;
      setList(t.dstS).forEach(function (ip) { if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) set[ip] = 1; });
    });
    var list = Object.keys(set).sort();
    return "# Maltrail IOC export · " + list.length + " indicators (defanged) · " + (currentDate() || todayStr()) +
      "\n" + list.map(defang).join("\n");
  }
  function download(name, text, mime) {
    try {
      var blob = new Blob([text], { type: mime || "text/plain" }), url = URL.createObjectURL(blob);
      var a = document.createElement("a"); a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
      setTimeout(function () { URL.revokeObjectURL(url); }, 1500);
    } catch (e) { }
  }
  function exportAs(kind) {
    var date = currentDate() || todayStr();
    if (kind === "csv") download("maltrail-threats-" + date + ".csv", buildCSV(), "text/csv");
    else if (kind === "json") download("maltrail-threats-" + date + ".json", buildJSON(), "application/json");
    else if (kind === "ioc") download("maltrail-iocs-" + date + ".txt", buildIOC(), "text/plain");
  }
  // ===== Saved views / filter presets (localStorage) =====
  function loadViews() { var a = lsGet("mt_views", null); return Array.isArray(a) ? a : []; }
  function saveViews() { lsSet("mt_views", savedViews); }
  var savedViews = loadViews();
  function applyView(v) {
    state.filters = (v.filters || []).slice(); state.sev = (v.sev == null ? null : v.sev);
    state.sortKey = v.sortKey || "first"; state.sortDir = v.sortDir || -1; state.input = v.input || "";
    state.page = 0; var f = document.getElementById("filter"); if (f) f.value = state.input; refresh();
  }
  function deleteView(i) { savedViews.splice(i, 1); saveViews(); }
  function openSaveView() {
    closeCtx();
    if (document.getElementById("sv_overlay")) return;
    var o = document.createElement("div"); o.id = "sv_overlay"; o.className = "modal-overlay";
    o.innerHTML = '<div class="modal"><div class="modal-h">Save current view</div>' +
      '<label for="sv_name">View name</label><input id="sv_name" autocomplete="off" placeholder="e.g. High malware \u00b7 external">' +
      '<div class="modal-actions"><button class="btn-ghost" id="sv_cancel">Cancel</button><button class="btn-primary" id="sv_save">Save</button></div></div>';
    document.body.appendChild(o);
    var inp = o.querySelector("#sv_name"); inp.focus();
    o.onclick = function (e) { if (e.target === o) o.remove(); };
    o.querySelector("#sv_cancel").onclick = function () { o.remove(); };
    function save() {
      var n = inp.value.trim(); if (!n) { inp.focus(); return; }
      savedViews.push({ name: n.slice(0, 40), filters: state.filters.slice(), sev: state.sev, sortKey: state.sortKey, sortDir: state.sortDir, input: state.input.trim() });
      saveViews(); o.remove();
    }
    o.querySelector("#sv_save").onclick = save;
    inp.onkeydown = function (e) { if (e.key === "Enter") { e.preventDefault(); save(); } else if (e.key === "Escape") { o.remove(); } };
  }
  // set / edit / clear a user alias for an IP (shown beside that IP everywhere it appears)
  function openAlias(ip) {
    closeCtx();
    if (document.getElementById("al_overlay")) return;
    var cur = (state.aliases && state.aliases[ip]) || "";
    var o = document.createElement("div"); o.id = "al_overlay"; o.className = "modal-overlay";
    o.innerHTML = '<div class="modal"><div class="modal-h">Alias for ' + esc(ip) + '</div>' +
      '<label for="al_name">Label (empty to clear)</label><input id="al_name" autocomplete="off" maxlength="40" placeholder="e.g. corp-proxy">' +
      '<div class="modal-actions"><button class="btn-ghost" id="al_cancel">Cancel</button><button class="btn-primary" id="al_save">Save</button></div></div>';
    document.body.appendChild(o);
    var inp = o.querySelector("#al_name"); inp.value = cur; inp.focus(); inp.select();
    function close() { o.remove(); }
    o.onclick = function (e) { if (e.target === o) close(); };
    o.querySelector("#al_cancel").onclick = close;
    function save() { setAlias(ip, inp.value); close(); }   // empty -> clears
    o.querySelector("#al_save").onclick = save;
    inp.onkeydown = function (e) { if (e.key === "Enter") { e.preventDefault(); save(); } else if (e.key === "Escape") { e.preventDefault(); close(); } };
  }
  function openViewsMenu(btn) {
    var m = document.getElementById("ctxmenu"); if (!m) return; m.innerHTML = "";
    var sv = document.createElement("button"); sv.type = "button"; sv.className = "ctxitem"; sv.textContent = "\uFF0B Save current view\u2026";
    sv.onclick = function (e) { e.stopPropagation(); openSaveView(); }; m.appendChild(sv);
    var sep = document.createElement("div"); sep.className = "ctxsep"; m.appendChild(sep);
    if (!savedViews.length) { var note = document.createElement("div"); note.className = "ctxnote"; note.textContent = "No saved views yet"; m.appendChild(note); }
    else savedViews.forEach(function (v, i) {
      var row = document.createElement("div"); row.className = "ctxview";
      var ap = document.createElement("button"); ap.type = "button"; ap.className = "ctxitem viewapply"; ap.textContent = "\u25B8 " + v.name;
      ap.onclick = function (e) { e.stopPropagation(); closeCtx(); applyView(v); };
      var del = document.createElement("button"); del.type = "button"; del.className = "viewdel"; del.title = "delete view"; del.textContent = "\u2715";
      del.onclick = function (e) { e.stopPropagation(); deleteView(i); openViewsMenu(btn); };
      row.appendChild(ap); row.appendChild(del); m.appendChild(row);
    });
    m.style.display = "block"; m.setAttribute("aria-hidden", "false");
    var r = btn.getBoundingClientRect(), mw = m.offsetWidth || 220;
    m.style.left = Math.max(6, Math.min(r.left, window.innerWidth - mw - 8)) + "px"; m.style.top = (r.bottom + 4) + "px";
  }
  // ===== Live mode: auto-refresh + new-threat detection + opt-in alerts =====
  var LIVE_MS = 5000;   // poll fallback cadence (only when SSE push is unavailable; merge is cheap so this is fine)
  // server's Range regex is bytes=(\d+)-(\d+) — it needs an explicit end; this large end means "to EOF"
  // (clamped server-side to total-1, i.e. a guaranteed newline boundary on an append-only log)
  var LIVE_MAX_END = 2147483647;
  function alertNew(list) {
    if (!getMuted()) {   // user can mute the new-threat beep (the desktop notification, if granted, still shows)
      try { var C = window.AudioContext || window.webkitAudioContext; if (C) { var ac = state._ac || (state._ac = new C()); if (ac.state === "suspended") ac.resume(); var o = ac.createOscillator(), g = ac.createGain(); o.type = "sine"; o.frequency.value = 880; g.gain.value = 0.05; o.connect(g); g.connect(ac.destination); o.start(); o.stop(ac.currentTime + 0.13); } } catch (e) { }
    }
    try { if ("Notification" in window && Notification.permission === "granted") new Notification("Maltrail \u00b7 " + list.length + " new high-severity", { body: list.slice(0, 3).map(function (t) { return t.src + " \u2192 " + t.trail; }).join("\n") }); } catch (e) { }
  }
  function clearNew() { state.newCount = 0; state.newUids = {}; refresh(); }
  function renderNewPill() {
    var el = document.getElementById("newpill"); if (!el) return;
    if (state.newCount > 0) { el.style.display = ""; el.textContent = state.newCount + " new"; el.onclick = clearNew; }
    else { el.style.display = "none"; }
  }
  function stopLive() {
    if (state._liveTimer) { clearInterval(state._liveTimer); state._liveTimer = null; }
    if (state._es) { try { state._es.close(); } catch (e) {} state._es = null; }
    if (state._liveFlush) { clearTimeout(state._liveFlush); state._liveFlush = null; }
    state._liveBuf = []; state._liveBufDate = null;   // discard any buffered lines so they can't merge into another day
  }
  function startPoll() {   // fallback when SSE is unavailable/broken
    if (state._liveTimer) return;
    state._liveTimer = setInterval(function () { if (state.live) liveTick(currentDate()); }, LIVE_MS);
  }
  // batch lines pushed over SSE and merge them in one render (handles bursts without re-rendering per line)
  // `date` = the day this stream is for; ignore anything that isn't the currently-viewed day (e.g. a late
  // message from the previous day's stream after you navigate) so events never bleed into the wrong date.
  function onLiveLine(line, id, date) {
    if (date !== currentDate()) return;
    if (state._liveBuf.length && state._liveBufDate !== date) state._liveBuf = [];   // day changed mid-batch
    state._liveBufDate = date;
    if (line) state._liveBuf.push(line);
    if (id) { var n = parseInt(id, 10); if (!isNaN(n)) state._liveBytes = n; }
    if (!state._liveFlush) state._liveFlush = setTimeout(flushLive, 100);
  }
  function flushLive() {
    state._liveFlush = null;
    var buf = state._liveBuf; state._liveBuf = [];
    if (!buf.length || state._liveBufDate !== currentDate()) return;   // navigated away before flush -> drop
    var rows = window.Papa.parse(buf.join("\n"), { delimiter: " ", skipEmptyLines: true }).data;
    if (state.agg && state.agg._byKey) render(mergeRows(state.agg, rows));
    else loadEvents(currentDate());   // no baseline yet -> full load
  }
  function openSSE(date) {
    if (typeof EventSource === "undefined") { startPoll(); return; }
    var url = "/live?date=" + encodeURIComponent(date) + (state._liveBytes != null && state._liveDate === date ? "&pos=" + state._liveBytes : "");
    var es;
    try { es = new EventSource(url); } catch (e) { startPoll(); return; }
    state._es = es; state._liveDate = date;
    es.onopen = function () { state._sseOk = true; if (state._liveTimer) { clearInterval(state._liveTimer); state._liveTimer = null; } };   // SSE up -> drop the poll fallback
    es.onmessage = function (e) { onLiveLine(e.data, e.lastEventId, date); };   // tag with this stream's day
    es.onerror = function () {
      // CLOSED (2): server rejected (no /live, 204 restricted, error) -> permanent fallback to polling.
      // CONNECTING (0): transient drop, EventSource auto-reconnects with Last-Event-ID; just ensure a poll safety net.
      if (es.readyState === 2) { state._es = null; if (state.live) { liveTick(currentDate()); startPoll(); } }
      else if (state.live && !state._sseOk) startPoll();
    };
  }
  function setLive(on) {
    state.live = on;
    var btn = document.getElementById("live_btn"); if (btn) { btn.classList.toggle("on", on); btn.setAttribute("aria-pressed", on ? "true" : "false"); }
    stopLive();
    if (on && !DEMO) {
      try { if ("Notification" in window && Notification.permission === "default") Notification.requestPermission(); } catch (e) { }
      state._sseOk = false;
      if (typeof EventSource !== "undefined") openSSE(currentDate());   // SSE streams everything since the last load (instant); no separate catch-up poll -> no double-delivery
      else { liveTick(currentDate()); startPoll(); }                    // no EventSource: catch up now, then poll
    }
  }
  function openQueryHelp(btn) {
    var m = document.getElementById("ctxmenu"); if (!m) return; m.innerHTML = "";
    var h = document.createElement("div"); h.className = "ctxnote qhelp-h"; h.textContent = "Search syntax \u00b7 space = AND \u00b7 click to try"; m.appendChild(h);
    [["sev:high", "high severity"], ["type:dns,http", "type (OR-list)"], ["port:443,8080", "port list"], ["port:1000-2000", "port range"], ["port:>1024", "port compare"],
     ["count:>=100", "noisy threats"], ["src:10.0.0.0/8", "source subnet (CIDR)"], ["dst:8.8.8.8", "destination"], ["dir:out", "flagged reply (→ out)"], ["dir:in", "flagged request (← in)"], ["trail:*.ru", "trail wildcard"], ["sensor:r2d2", "by sensor"], ["class:malware", "threat class"], ["tag:apt", "your tag"],
     ["type:dns sev:high", "both (AND)"], ["sev:high,med OR type:http", "OR / lists"], ["NOT type:dns", "negate (or -)"], ["(sev:high OR sev:med) type:http", "group ( )"], ['info:"cobalt strike"', "quoted phrase"]].forEach(function (e) {
      var b = document.createElement("button"); b.type = "button"; b.className = "ctxitem qhelp-i";
      b.innerHTML = '<span class="qk">' + e[0] + '</span><span class="qd">' + e[1] + '</span>';
      b.onclick = function (ev) { ev.stopPropagation(); closeCtx(); var f = document.getElementById("filter"); if (f) { f.value = e[0]; state.input = e[0]; state.page = 0; refresh(); f.focus(); } };
      m.appendChild(b);
    });
    m.style.display = "block"; m.setAttribute("aria-hidden", "false");
    var r = btn.getBoundingClientRect(), mw = m.offsetWidth || 230;
    m.style.left = Math.max(6, Math.min(r.left, window.innerWidth - mw - 8)) + "px";
    var _top = r.bottom + 5, _mh = m.offsetHeight;   // if the (capped) panel would run off the bottom, lift it up so it stays fully visible
    if (_top + _mh > window.innerHeight - 8) _top = Math.max(8, window.innerHeight - _mh - 8);
    m.style.top = _top + "px";
  }
  // far-left hamburger menu: the project links (docs/issues/github) that used to clutter the top bar. Inline SVGs
  // (no external assets — air-gap safe) matching the icons they replaced.
  function _strokeIcon(p) { return '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + p + '</svg>'; }
  var NAV_LINKS = [
    ["https://github.com/stamparm/maltrail#readme", _strokeIcon('<path d="M12 7v14"/><path d="M3 18a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h5a4 4 0 0 1 4 4 4 4 0 0 1 4-4h5a1 1 0 0 1 1 1v13a1 1 0 0 1-1 1h-6a3 3 0 0 0-3 3 3 3 0 0 0-3-3z"/>'), "Documentation"],
    ["https://github.com/stamparm/maltrail/issues", _strokeIcon('<circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 4.24 4.24"/><path d="m14.86 14.86 4.24 4.24"/><path d="m14.86 9.14 4.24-4.24"/><path d="m4.9 19.1 4.24-4.24"/><circle cx="12" cy="12" r="4"/>'), "Report an issue"],
    ["https://github.com/stamparm/maltrail", '<svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor" aria-hidden="true"><path d="M12 .3a12 12 0 0 0-3.8 23.4c.6.1.8-.3.8-.6v-2c-3.3.7-4-1.6-4-1.6-.6-1.4-1.3-1.8-1.3-1.8-1-.7.1-.7.1-.7 1.2 0 1.8 1.2 1.8 1.2 1 1.8 2.8 1.3 3.5 1 0-.8.4-1.3.7-1.6-2.7-.3-5.5-1.3-5.5-6 0-1.3.5-2.4 1.3-3.2-.2-.3-.6-1.6.1-3.2 0 0 1-.3 3.3 1.2a11.5 11.5 0 0 1 6 0c2.3-1.5 3.3-1.2 3.3-1.2.7 1.6.2 2.9.1 3.2.8.8 1.3 1.9 1.3 3.2 0 4.7-2.8 5.7-5.5 6 .4.4.8 1.1.8 2.2v3.3c0 .3.2.7.8.6A12 12 0 0 0 12 .3"/></svg>', "Source on GitHub"]
  ];
  function openNavMenu(btn) {
    var m = document.getElementById("ctxmenu"); if (!m) return; m.innerHTML = "";
    NAV_LINKS.forEach(function (e) {
      var a = document.createElement("a"); a.className = "ctxitem navitem";
      a.href = e[0]; a.target = "_blank"; a.rel = "noopener noreferrer";
      a.innerHTML = e[1] + '<span class="navlabel">' + e[2] + '</span>';
      m.appendChild(a);
    });
    m.style.display = "block"; m.setAttribute("aria-hidden", "false"); btn.setAttribute("aria-expanded", "true");
    var r = btn.getBoundingClientRect(), mw = m.offsetWidth || 212;
    m.style.left = Math.max(6, Math.min(r.left, window.innerWidth - mw - 8)) + "px";
    m.style.top = (r.bottom + 5) + "px";
  }



  function openExportMenu(btn) {
    var m = document.getElementById("ctxmenu"); if (!m) return;
    var n = viewList().length;
    m.innerHTML = "";
    [["Export CSV · " + n + " threats", "csv"], ["Export JSON", "json"], ["Export defanged IOCs", "ioc"]].forEach(function (it) {
      var b = document.createElement("button"); b.type = "button"; b.className = "ctxitem"; b.textContent = it[0];
      b.onclick = function (e) { e.stopPropagation(); closeCtx(); exportAs(it[1]); }; m.appendChild(b);
    });
    m.style.display = "block"; m.setAttribute("aria-hidden", "false");
    var r = btn.getBoundingClientRect(), mw = m.offsetWidth || 200;
    m.style.left = Math.max(6, Math.min(r.left, window.innerWidth - mw - 8)) + "px";
    m.style.top = (r.bottom + 4) + "px";
  }

  function closeCtx() { var m = document.getElementById("ctxmenu"); if (m) { m.style.display = "none"; m.setAttribute("aria-hidden", "true"); m.innerHTML = ""; } var hb = document.getElementById("nav_menu"); if (hb) hb.setAttribute("aria-expanded", "false"); }
  function closeDrawer() {
    var d = document.getElementById("drawer"), sc = document.getElementById("drawer_scrim");
    var wasOpen = d && d.classList.contains("open");
    if (d) d.classList.remove("open"); if (sc) sc.classList.remove("open");
    if (wasOpen && state._drawerReturn && state._drawerReturn.focus) { try { state._drawerReturn.focus(); } catch (e) {} }   // restore focus to the trigger
    state._drawerReturn = null;
  }
  function drawDwrSpark(cv, data, color) {
    cv._w = 308; cv._h = 46; var ctx = cctx(cv), w = cv._w, h = cv._h, pad = 13, n = data.length, bw = w / n;
    var max = Math.max.apply(null, data.concat([1])), tc = themeColors();
    for (var i = 0; i < n; i++) { var bh = Math.max(1, (data[i] / max) * (h - pad)); ctx.fillStyle = color; ctx.globalAlpha = 0.35 + 0.65 * (data[i] / max); ctx.fillRect(i * bw + 1, h - pad - bh, Math.max(1, bw - 1.5), bh); }
    ctx.globalAlpha = 1; ctx.fillStyle = tc.faint; ctx.font = "9px ui-monospace,monospace"; ctx.textBaseline = "bottom";
    for (var hh = 0; hh < 24; hh += 6) ctx.fillText((hh < 10 ? "0" : "") + hh + "h", hh * bw + 1, h);
  }
  function openDrawer(t) {
    var d = document.getElementById("drawer"), sc = document.getElementById("drawer_scrim"); if (!d || !t) return;
    var hue = (murmur3(t.uidc, 7) >>> 0) % 360, trg = state.triage[t.uidc];
    var srcs = setList(t.srcS), dsts = setList(t.dstS), ports = setList(t.dportS), ev = t.events || [];
    var _nt = normTrail(t.trail), relSrc = 0, relTrail = 0;
    for (var ri2 = 0; ri2 < state.all.length; ri2++) { var x = state.all[ri2]; if (x === t) continue; if (x.src === t.src || (x.srcS && x.srcS.vals.has(t.src))) relSrc++; if (normTrail(x.trail) === _nt) relTrail++; }
    function chips(arr) { return arr.length ? arr.map(function (v) { return '<span class="dchip">' + esc(v) + '</span>'; }).join("") : '<span class="dwr-none">none</span>'; }
    // source/dest IPs: data-ip so they get the same RIPE flag + country/ASN tooltip as the table cells
    function ipChips(arr) {
      if (!arr.length) return '<span class="dwr-none">none</span>';
      return arr.map(function (v) {
        var a = aliasOf(v);
        return '<span class="dchip ip" data-ip="' + esc(v) + '">' + (isPrivIP(v) ? '<span class="lan" title="local / private network">' + LAN_ICON + '</span>' : '') + (a ? '<span class="ipcat" title="alias">' + esc(a) + '</span>' : '') + esc(v) + '</span>';
      }).join("");
    }
    // ports: highlight notable/high-risk ones in the drawer too (consistent with the table)
    function portChips(arr) {
      if (!arr.length) return '<span class="dwr-none">none</span>';
      return arr.map(function (p) {
        var rk = riskyPort(p);
        return '<span class="dchip' + (rk ? ' risky" title="' + esc(rk) : '') + '">' + esc(portLabel(p)) + '</span>';
      }).join("");
    }
    var evShown = Math.min(200, ev.length);
    var evRows = ev.slice(0, 200).map(function (r) {
      return '<tr><td class="mono">' + esc(hms(r[0])) + '</td><td class="mono">' + esc(r[1]) + '</td><td class="mono">' + esc(r[2]) + ':' + esc(r[3]) + '</td><td class="mono">' + esc(r[4]) + ':' + esc(r[5]) + '</td><td>' + esc(r[6]) + '</td><td class="dwr-evtrail">' + esc(r[8]) + '</td></tr>';
    }).join("");
    var tcol = TYPE_COLORS[t.type] || "#8A97AD";
    d.innerHTML =
      '<div class="dwr-head ' + sevClass(t.sev) + '"><span class="sev-tag dwr-f" data-f="sev:' + sevName(t.sev) + '" title="filter: ' + sevName(t.sev) + ' severity">' + sevName(t.sev) + '</span>' +
        '<span class="uid dwr-f ' + ltClass(hslText(hue, 0.60, 0.48)) + '" data-f="uid:' + t.uidc + '" style="background:hsl(' + hue + ',60%,48%);color:' + hslText(hue, 0.60, 0.48) + '" title="filter: this threat id">' + t.uidc + '</span>' +
        '<span class="type dwr-f lt-w" data-f="type:' + esc(t.type) + '" style="background:' + tcol + ';color:#fff" title="filter: type ' + esc(t.type) + '">' + esc(t.type) + '</span>' +
        '<div class="spacer"></div><button class="dwr-close" id="dwr_close" aria-label="close detail">\u2715</button></div>' +
      '<div class="dwr-body">' +
        '<div class="dwr-trail" title="' + esc(t.trail) + '">' + esc(t.trail) + '</div>' +
        '<div class="dwr-info">' + esc(t.info) + (t.ref ? '  <span class="dwr-ref">' + esc(t.ref) + '</span>' : '') + '</div>' +
        '<div class="dwr-stats"><div><b>' + t.count + '</b><span>events</span></div><div><b>' + srcs.length + '</b><span>sources</span></div><div><b>' + dsts.length + '</b><span>dest</span></div><div><b>' + ports.length + '</b><span>ports</span></div></div>' +
        '<canvas class="dwr-spark"></canvas>' +
        '<div class="dwr-time">first ' + hms(t.first) + ' \u2192 last ' + hms(t.last) + ' \u00b7 span ' + durationStr(t.first, t.last) + '</div>' +
        '<div class="dwr-status">' + ['investigating', 'resolved', 'fp'].map(function (k) { return '<button data-st="' + k + '" class="trbtn tr-' + k + (trg === k ? ' on' : '') + '">' + TRIAGE_LABEL[k] + '</button>'; }).join('') + '</div>' +
        '<div class="dwr-actions"><button data-a="wls">whitelist src</button><button data-a="wlt">whitelist trail</button><button data-a="hide">' + (state.hidden[t.uidc] ? "unhide" : "hide") + '</button><button data-a="vt" class="ext">\u2197 VT</button><button data-a="abuse" class="ext">\u2197 AbuseIPDB</button><button data-a="shodan" class="ext">\u2197 Shodan</button><button data-a="copy">copy</button><button data-a="ioc">copy IOCs</button></div>' +
        '<div class="dwr-local" role="note">⚠ status, whitelist, hide, tags &amp; notes are saved in <b>this browser only</b> — not shared with the sensor or other users</div>' +
        '<div class="dwr-sec"><h4>note</h4><textarea class="dwr-note" id="dwr_note" aria-label="case note for this threat" placeholder="add a case note\u2026">' + esc(getNote(t.uidc)) + '</textarea></div>' +
        '<div class="dwr-sec dwr-related"><h4>related</h4>' + '<button class="relbtn" data-rel="src"><b>' + relSrc + '</b> other threats from this source</button>' + '<button class="relbtn" data-rel="trail"><b>' + relTrail + '</b> other threats on this trail</button></div>' +
        '<div class="dwr-sec"><h4>sources \u00b7 ' + srcs.length + '</h4><div class="dchips">' + ipChips(srcs) + '</div></div>' +
        '<div class="dwr-sec"><h4>destinations \u00b7 ' + dsts.length + '</h4><div class="dchips">' + ipChips(dsts) + '</div></div>' +
        '<div class="dwr-sec"><h4>ports \u00b7 ' + ports.length + '</h4><div class="dchips">' + portChips(ports) + '</div></div>' +
        '<div class="dwr-sec"><h4>raw events \u00b7 ' + ev.length + (ev.length >= 500 ? "+" : "") + (evShown < ev.length ? " (showing " + evShown + ")" : "") + '</h4><div class="dwr-events"><table><thead><tr><th>time</th><th>sensor</th><th>source</th><th>dest</th><th>proto</th><th>trail</th></tr></thead><tbody>' + evRows + '</tbody></table></div></div>' +
      '</div>';
    d.querySelector("#dwr_close").onclick = closeDrawer;
    // clickable header chips: filter the table by this severity / threat-id / type, then close the drawer
    d.querySelectorAll(".dwr-head .dwr-f").forEach(function (el) {
      el.style.cursor = "pointer";
      el.onclick = function () { var tok = el.getAttribute("data-f"); closeDrawer(); addFilter(tok); };
    });
    d.querySelector('[data-a="wls"]').onclick = function () { whitelistSrc(t.src); closeDrawer(); };
    d.querySelector('[data-a="wlt"]').onclick = function () { whitelistTrail(t.trail); closeDrawer(); };
    d.querySelector('[data-a="hide"]').onclick = function () { toggleHide(t.uidc); closeDrawer(); };
    d.querySelector('[data-a="vt"]').onclick = function () { openLookup("vt-ip", t.src); };
    d.querySelector('[data-a="abuse"]').onclick = function () { openLookup("abuse", t.src); };
    d.querySelector('[data-a="shodan"]').onclick = function () { openLookup("shodan", t.src); };
    d.querySelector('[data-a="copy"]').onclick = function () { copyText([t.uidc, t.src, setList(t.dstS).join("|"), t.type, t.trail, t.info].join("  "), null); };
    d.querySelector('[data-a="ioc"]').onclick = function () { var b = charTrim(charTrim(("" + t.trail).replace(/\([^)]*\)/g, "").replace(/\\\(/g, "").replace(/\\\)/g, ""), " "), "."); var arr = []; if (b) arr.push(b); setList(t.dstS).forEach(function (ip) { if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) arr.push(ip); }); copyText(arr.map(defang).join("\n"), null); };
    d.querySelectorAll('[data-st]').forEach(function (b) { b.onclick = function () { var k = b.getAttribute('data-st'); setTriage(t.uidc, state.triage[t.uidc] === k ? null : k); closeDrawer(); }; });
    var _na = d.querySelector('#dwr_note'); if (_na) _na.onblur = function () { setNote(t.uidc, _na.value); };
    var _rs = d.querySelector('[data-rel="src"]'); if (_rs) _rs.onclick = function () { closeDrawer(); state.filters = ['src:' + ('' + t.src).toLowerCase()]; state.input = ''; state.sev = null; state.page = 0; var f = document.getElementById('filter'); if (f) f.value = ''; refresh(); };
    var _rt = d.querySelector('[data-rel="trail"]'); if (_rt) _rt.onclick = function () { closeDrawer(); state.filters = ['trail:' + _nt.toLowerCase()]; state.input = ''; state.sev = null; state.page = 0; var f = document.getElementById('filter'); if (f) f.value = ''; refresh(); };
    var cv = d.querySelector(".dwr-spark"); if (cv) drawDwrSpark(cv, t.hours, sevColor(t.sev));
    state._drawerReturn = document.activeElement;                          // remember focus origin
    d.setAttribute("aria-modal", "true");
    d.classList.add("open"); if (sc) sc.classList.add("open");
    var _cl = d.querySelector("#dwr_close"); if (_cl) _cl.focus();          // move focus into the dialog
    enrichDrawerIPs();                                                       // country flags + ASN on source/dest chips
  }

  function openCtx(t, x, y) {
    var m = document.getElementById("ctxmenu"); if (!m || !t) return;
    var src = t.src, nt = normTrail(t.trail);
    var bare = ("" + t.trail).replace(/\([^)]*\)/g, "").replace(/\\\(/g, "").replace(/\\\)/g, "").trim();
    var domish = (/^[a-z0-9._-]+\.[a-z]{2,}$/i.test(bare)) ? bare : null;   // looks like a hostname
    var ntShort = nt.length > 26 ? nt.slice(0, 25) + "…" : nt;
    var items = [
      ["Hide this threat", function () { toggleHide(t.uidc); }, ""],
      "sep",
      ["◴ investigating", function () { setTriage(t.uidc, "investigating"); }, "tr-investigating"],
      ["✓ resolved", function () { setTriage(t.uidc, "resolved"); }, "tr-resolved"],
      ["⊘ false-positive", function () { setTriage(t.uidc, "fp"); }, "tr-fp"],
      ["clear status", function () { setTriage(t.uidc, null); }, ""],
      "sep",
      ["Whitelist source  " + src, function () { whitelistSrc(src); }, ""],
      ["Whitelist trail  " + ntShort, function () { whitelistTrail(t.trail); }, ""],
      "sep",
      ["Filter → only this source", function () { addFilter("src:" + src); }, ""],
      ["Filter → exclude this source", function () { addFilter("-src:" + src); }, ""],
      ["Filter → only this trail", function () { addFilter("trail:" + nt); }, ""],
      "sep",
      ["✎ Alias source  " + src, function () { openAlias(src); }, ""],
      ["Copy row", function () { copyText([t.uidc, src, setList(t.dstS).join("|"), setList(t.dportS).join("|"), t.type, t.trail, t.info].join("  "), null); }, ""],
      "sep",
      ["↗ VirusTotal · source", function () { openLookup("vt-ip", src); }, "ext"],
      ["↗ AbuseIPDB · source", function () { openLookup("abuse", src); }, "ext"],
      ["↗ Shodan · source", function () { openLookup("shodan", src); }, "ext"]
    ];
    if (domish) {
      items.push(["↗ VirusTotal · trail", function () { openLookup("vt-dom", domish); }, "ext"]);
      items.push(["↗ urlscan · trail", function () { openLookup("urlscan", domish); }, "ext"]);
    }
    m.innerHTML = "";
    items.forEach(function (it) {
      if (it === "sep") { var d = document.createElement("div"); d.className = "ctxsep"; m.appendChild(d); return; }
      var b = document.createElement("button"); b.type = "button"; b.className = "ctxitem" + (it[2] ? " " + it[2] : ""); b.textContent = it[0];
      b.onclick = function (e) { e.stopPropagation(); closeCtx(); it[1](); };
      m.appendChild(b);
    });
    m.style.display = "block"; m.setAttribute("aria-hidden", "false");
    var mw = m.offsetWidth || 230, mh = m.offsetHeight || 320;
    m.style.left = Math.max(6, Math.min(x, window.innerWidth - mw - 8)) + "px";
    m.style.top = Math.max(6, Math.min(y, window.innerHeight - mh - 8)) + "px";
  }
  function showWLManage() {
    closeCtx();
    if (document.getElementById("wl_overlay")) return;
    var o = document.createElement("div"); o.id = "wl_overlay"; o.className = "modal-overlay";
    var rows = "";
    Object.keys(state.wl.src).forEach(function (ip) { rows += '<div class="wlrow"><span class="wltag">src</span><span class="wlval">' + esc(ip) + '</span><button class="wlrm" data-k="src" data-v="' + esc(ip) + '">remove</button></div>'; });
    Object.keys(state.wl.trail).forEach(function (tr) { rows += '<div class="wlrow"><span class="wltag">trail</span><span class="wlval">' + esc(tr) + '</span><button class="wlrm" data-k="trail" data-v="' + esc(tr) + '">remove</button></div>'; });
    if (!rows) rows = '<div class="wlempty">No whitelist rules yet. Right-click a threat to add one.</div>';
    o.innerHTML = '<div class="modal"><div class="modal-h">Whitelist rules</div>' +
      '<div class="localwarn" role="note">⚠ <b>This browser only.</b> These rules just hide matching threats in <i>your</i> view — they are <b>not</b> sent to sensors and the sensor keeps detecting &amp; logging them. To suppress at the source, add them to the sensor whitelist (<code>misc/whitelist.txt</code> or <code>USER_WHITELIST</code>) instead.</div>' +
      '<div class="wllist">' + rows + '</div>' +
      '<div class="modal-actions"><button class="btn-ghost" id="wl_close">Close</button><button class="btn-primary" id="wl_clear">Clear all</button></div></div>';
    document.body.appendChild(o);
    o.onclick = function (e) { if (e.target === o) o.remove(); };
    o.querySelector("#wl_close").onclick = function () { o.remove(); };
    o.querySelector("#wl_clear").onclick = function () { clearWL(); o.remove(); };
    o.querySelectorAll(".wlrm").forEach(function (b) { b.onclick = function () { unWL(b.getAttribute("data-k"), b.getAttribute("data-v")); o.remove(); showWLManage(); }; });
  }

  // per-threat tags (UID-keyed; value is a comma-joined string, same shape as the legacy jStorage tagData)
  var LS_TAGS = "mt_tags_v2";
  function loadTags() { var o = lsGet(LS_TAGS, {}); return (o && typeof o === "object") ? o : {}; }
  function saveTags() { lsSet(LS_TAGS, state.tags); }
  // ---- triage status (New / Investigating / Resolved / False-positive) ----
  var LS_TRIAGE = "mt_triage_v2", TRIAGE_LABEL = { investigating: "investigating", resolved: "resolved", fp: "false-pos" };
  function loadTriage() { var o = lsGet(LS_TRIAGE, {}); return (o && typeof o === 'object') ? o : {}; }
  function saveTriage() { lsSet(LS_TRIAGE, state.triage); }
  function setTriage(uid, key) { if (!uid) return; if (key) state.triage[uid] = key; else delete state.triage[uid]; saveTriage(); refresh(); }
  // ---- per-threat notes ----
  var LS_NOTES = "mt_notes_v2";
  function loadNotes() { var o = lsGet(LS_NOTES, {}); return (o && typeof o === 'object') ? o : {}; }
  function saveNotes() { lsSet(LS_NOTES, state.notes); }
  function getNote(uid) { return state.notes[uid] || ''; }
  function setNote(uid, text) { text = ('' + text).trim(); if (text) state.notes[uid] = text.slice(0, 2000); else delete state.notes[uid]; saveNotes(); refresh(); }
  // user-defined IP aliases (localStorage). Merged with server-injected IP_ALIASES (user value wins).
  var LS_ALIAS = "mt_aliases_v2";
  function loadAliases() { var o = lsGet(LS_ALIAS, {}); return (o && typeof o === 'object') ? o : {}; }
  function saveAliases() { lsSet(LS_ALIAS, state.aliases); }
  function aliasOf(ip) { return (state.aliases && state.aliases[ip]) || IP_ALIASES[ip] || ''; }
  function setAlias(ip, name) { name = ('' + name).trim().slice(0, 40); if (name) state.aliases[ip] = name; else delete state.aliases[ip]; saveAliases(); refresh(); }
  function tagsOf(uid) { var s = state.tags[uid]; return s ? s.split(",").filter(Boolean) : []; }
  function addTag(uid, tag) {
    tag = ("" + tag).trim().replace(/[,|]/g, "").slice(0, 24);
    if (!uid || !tag) { refresh(); return; }
    var t = tagsOf(uid); if (t.indexOf(tag) < 0) { t.push(tag); state.tags[uid] = t.join(","); saveTags(); }
    refresh();
  }
  function removeTag(uid, tag) {
    var t = tagsOf(uid).filter(function (x) { return x !== tag; });
    if (t.length) state.tags[uid] = t.join(","); else delete state.tags[uid];
    saveTags(); refresh();
  }
  // One-time import of the legacy frontend's jStorage data (hidden threats + per-threat tags). Both are keyed by
  // threatUID, which is byte-identical to ours (verified), so an upgrading user keeps their hidden list and tags.
  function migrateLegacy() {
    try {
      if (localStorage.getItem("mt_migrated")) return;
      var raw = localStorage.getItem("jStorage");
      if (raw) {
        var js = JSON.parse(raw), uidRe = /^[0-9a-f]{8}$|^[0-9a-f]{6}(F0|D0|N0)$/;
        var hid = js["STORAGE_KEY_HIDDEN_THREATS"];
        if (hid && typeof hid === "object") { for (var h in hid) if (hid[h]) state.hidden[h] = 1; }
        for (var k in js) {
          if (k === "__jstorage_meta") continue;
          var v = js[k];
          if (uidRe.test(k) && v && typeof v === "object" && v.tagData != null) {
            var t = ("" + v.tagData).split(/[|,]/).filter(Boolean);
            if (t.length) state.tags[k] = t.join(",");
          }
        }
        saveHidden(); saveTags();
      }
      localStorage.setItem("mt_migrated", "1");
    } catch (e) { /* ignore malformed/absent legacy storage */ }
  }

  var state = { all: [], agg: null, chart: null, _openChart: "", filters: [], input: "", sev: null, sortKey: "sev", sortDir: -1, limit: 25, page: 0, hidden: loadHidden(), showHidden: false, tags: loadTags(), streaming: false, _loadSeq: 0, selIdx: -1, _pageRows: [] };
  state.wl = loadWL(); state.triage = loadTriage(); state.notes = loadNotes(); state.aliases = loadAliases();
  state.live = false; state.knownUids = {}; state.newUids = {}; state.newCount = 0; state._seenInit = false; state._liveTimer = null; state._ac = null;
  state._liveBytes = null; state._liveDate = null;   // incremental-live baseline: byte offset + date (aggregate itself carries _byKey for merging)
  state._connected = true; state._serverReachable = null;   // null=unknown -> fall back to navigator.onLine; true/false set by fetches
  state._es = null; state._liveBuf = []; state._liveBufDate = null; state._liveFlush = null; state._sseOk = false;   // SSE push stream + dated line batch

  function hay(t) {
    // _hay (all distinct values across the threat's events) is built lazily here on first free-text search and
    // cached; mergeRows invalidates it (null) when new events fold in. Tags are appended live (cheap).
    if (t._hay == null) t._hay = threatHay(t);
    return t._hay + " " + (state.tags[t.uidc] || "").toLowerCase();
  }

  // ===== query syntax: field-scoped tokens (src: dst: port: proto: type: trail: info: tag: uid: sev: dir: status:) + * wildcards =====
  function _lc(x) { return ("" + x).toLowerCase(); }
  // memoized: _fieldMatch is called per-threat, so a wildcard term (trail:*.ru) would otherwise recompile this
  // regex once PER ROW per keystroke (120k× at the threat cap). The pattern is identical across the whole pass.
  var _globCache = {}, _globN = 0;
  function _glob(v) { var r = _globCache[v]; if (r) return r; if (_globN > 500) { _globCache = {}; _globN = 0; } r = new RegExp("^" + v.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$"); _globCache[v] = r; _globN++; return r; }
  // lowercased text values for a field. null => not a known text field (numeric/enum fields handled in matchPos).
  function _fieldVals(f, t) {
    switch (f) {
      case "src": return setList(t.srcS).map(_lc);
      case "dst": return setList(t.dstS).map(_lc);
      case "port": return setList(displayPortSet(t));
      case "proto": return setList(t.protoS).map(_lc);
      case "type": return [_lc(t.type)];
      case "trail": return [_lc(t.trail)];
      case "info": return [_lc(t.info)];
      case "tag": return tagsOf(t.uidc).map(_lc);
      case "note": return [_lc(getNote(t.uidc))];
      case "uid": return [_lc(t.uidc)];
      case "sensor": return setList(t.sensorS).map(_lc);
      case "class": var m = ("" + t.info).match(/\(([^)]+)\)\s*$/); return [m ? m[1].toLowerCase().trim() : ""];   // the malware/suspicious/heuristic/... class in the info field
      default: return null;
    }
  }
  function _ip2int(ip) { var p = ("" + ip).split("."); if (p.length !== 4) return null; var n = 0; for (var i = 0; i < 4; i++) { if (p[i] === "" || !/^\d+$/.test(p[i])) return null; var o = +p[i]; if (o > 255) return null; n = n * 256 + o; } return n >>> 0; }
  // CIDR subnet match (src:10.0.0.0/8). returns null when `part` isn't CIDR syntax -> caller falls back to substring.
  function _cidr(part, ips) {
    var m = part.match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/); if (!m) return null;
    var base = _ip2int(m[1]), bits = +m[2]; if (base == null || bits > 32) return false;
    var mask = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0, net = (base & mask) >>> 0;
    return ips.some(function (ip) { var v = _ip2int(ip); return v != null && ((v & mask) >>> 0) === net; });
  }
  // numeric match for port/count/events: exact (443), range (1000-2000), compare (>1024,<=80,>=100,<5)
  function _cmpNum(part, nums) {
    var m;
    if (m = part.match(/^(>=|<=|>|<)(\d+)$/)) { var op = m[1], k = +m[2]; return nums.some(function (x) { return op === ">" ? x > k : op === "<" ? x < k : op === ">=" ? x >= k : x <= k; }); }
    if (m = part.match(/^(\d+)-(\d+)$/)) { var lo = +m[1], hi = +m[2]; return nums.some(function (x) { return x >= lo && x <= hi; }); }
    if (/^\d+$/.test(part)) { var n = +part; return nums.some(function (x) { return x === n; }); }
    return false;   // non-numeric part for a numeric field -> no match
  }
  function _matchText(f, part, vals) {
    if (part.indexOf("*") >= 0) { var re = _glob(part); return vals.some(function (x) { return re.test(x); }); }   // glob
    if (f === "src" || f === "dst") { var c = _cidr(part, vals); if (c !== null) return c; }                        // CIDR (else fall through)
    return vals.some(function (x) { return x.indexOf(part) >= 0; });                                                // substring
  }
  // a field-scoped token field:value. value may be a comma-OR list (type:dns,http); each part may be exact /
  // substring / glob / numeric range or compare / CIDR. quoted=true (info:"a, b") => literal phrase: no splitting.
  function matchPos(t, tok, quoted) {
    if (!tok) return true;
    var ci = tok.indexOf(":");
    if (ci > 0) {
      var f = tok.slice(0, ci), v = tok.slice(ci + 1); if (!v) return true;
      if (f === "sev") return v.split(",").some(function (p) { var m = { high: 3, hi: 3, "3": 3, med: 2, medium: 2, "2": 2, low: 1, lo: 1, "1": 1 }; return m[p] === t.sev; });
      if (f === "dir") { var d = portDir(t); if (!d) return false; return v.split(",").some(function (p) { var m = { out: "out", outbound: "out", egress: "out", resp: "out", response: "out", reply: "out", "in": "in", inbound: "in", ingress: "in", req: "in", request: "in" }; return m[p] === d; }); }   // flagged-traffic direction of the port cell (→ out / ← in)
      if (f === "status") return v.split(",").some(function (p) { var st = state.triage[t.uidc] || "new"; if (p === "false-positive" || p === "false-pos") p = "fp"; if (p === "untriaged" || p === "open") p = "new"; return st === p; });
      if (f === "port" || f === "count" || f === "events") { var nums = f === "port" ? setList(displayPortSet(t)).map(Number) : [t.count]; return v.split(",").some(function (p) { return _cmpNum(p, nums); }); }
      var vals = _fieldVals(f, t);
      if (vals !== null) {
        if (quoted) return vals.some(function (x) { return x.indexOf(v) >= 0; });               // literal quoted phrase
        return v.split(",").some(function (p) { return p && _matchText(f, p, vals); });         // comma-OR list
      }
      // unknown field -> fall through to whole-token substring (e.g. a bare "1.2.3.4:443")
    }
    return hay(t).indexOf(tok) >= 0;
  }
  function matchToken(t, raw, quoted) {
    if (raw.charAt(0) === "-") { var r = raw.slice(1); return r ? !matchPos(t, r, quoted) : true; }
    return matchPos(t, raw, quoted);
  }

  // ---- boolean search language ----
  // precedence (loosest first): OR  <  AND  <  NOT  <  primary
  //   or      := and ( ("OR" | "||") and )*
  //   and     := not ( ("AND" | "&&" | <adjacent term>) not )*    // adjacency = implicit AND
  //   not     := ("NOT" | "!") not | primary
  //   primary := "(" or ")" | TERM
  // TERM is a matchToken token: field:val, bare substring, wildcard; a leading "-" still negates
  // (back-compat). Double quotes group a phrase incl. spaces/operators: info:"command and control".
  function lexQuery(s) {
    var toks = [], i = 0, n = s.length, c, d, buf;
    while (i < n) {
      c = s.charAt(i);
      if (c === " " || c === "\t") { i++; continue; }
      if (c === "(" || c === ")") { toks.push(c); i++; continue; }
      if (c === "&" && s.charAt(i + 1) === "&") { toks.push("AND"); i += 2; continue; }
      if (c === "|" && s.charAt(i + 1) === "|") { toks.push("OR"); i += 2; continue; }
      if (c === "!" && s.charAt(i + 1) !== "=") { toks.push("NOT"); i++; continue; }
      buf = ""; var hadQuote = false;
      while (i < n) {
        d = s.charAt(i);
        if (d === '"') { hadQuote = true; i++; while (i < n && s.charAt(i) !== '"') { buf += s.charAt(i); i++; } if (i < n) i++; continue; }
        if (d === " " || d === "\t" || d === "(" || d === ")") break;
        if ((d === "&" && s.charAt(i + 1) === "&") || (d === "|" && s.charAt(i + 1) === "|")) break;
        buf += d; i++;
      }
      var up = buf.toUpperCase();
      if (!hadQuote && (up === "AND" || up === "OR" || up === "NOT")) toks.push(up);   // a quoted "AND" is a literal term, not an operator
      else if (buf) toks.push({ v: buf, q: hadQuote });
    }
    return toks;
  }
  function termFn(tk) { var tok = tk.v.toLowerCase(), q = tk.q; return function (t) { return matchToken(t, tok, q); }; }
  function andFn(a, b) { return !a ? b : !b ? a : function (t) { return a(t) && b(t); }; }
  function orFn(a, b)  { return !a ? b : !b ? a : function (t) { return a(t) || b(t); }; }
  function notFn(a)    { return !a ? null : function (t) { return !a(t); }; }
  // compile the query string into a single predicate t => bool (true-for-all when empty/blank)
  function compileQuery(str) {
    var toks = lexQuery(str || ""), pos = 0;
    function peek() { return toks[pos]; }
    function pOr() { var l = pAnd(); while (peek() === "OR") { pos++; l = orFn(l, pAnd()); } return l; }
    function pAnd() {
      var l = pNot();
      while (pos < toks.length && peek() !== "OR" && peek() !== ")") {
        if (peek() === "AND") pos++;
        l = andFn(l, pNot());
      }
      return l;
    }
    function pNot() { if (peek() === "NOT") { pos++; return notFn(pNot()); } return pPrimary(); }
    function pPrimary() {
      var tk = peek();
      if (tk === undefined) return null;
      if (tk === "(") { pos++; var e = pOr(); if (peek() === ")") pos++; return e; }
      if (tk === ")" || tk === "AND" || tk === "OR" || tk === "NOT") { pos++; return null; }
      pos++; return termFn(tk);
    }
    return pOr() || function () { return true; };
  }
  function viewList() {
    var chips = state.filters, q = compileQuery(state.input);
    var hidden = state.hidden, showH = state.showHidden;
    var sev = state.sev;
    var list = state.all.filter(function (t) {
      if (!showH && hidden[t.uidc]) return false;
      if (isWL(t)) return false;
      if (sev != null && t.sev !== sev) return false;
      for (var ci = 0; ci < chips.length; ci++) if (!matchToken(t, chips[ci])) return false;
      return q(t);
    });
    var k = state.sortKey, dir = state.sortDir;
    list.sort(function (a, b) {
      var c;
      if (k === "sev") c = riskOf(a) - riskOf(b);                // "severity" column = risk-ranked (severity-dominant, then compromise signal / volume within a band)
      else if (k === "count") c = a.count - b.count;
      else if (k === "dport") c = (parseInt(a.dport, 10) || 0) - (parseInt(b.dport, 10) || 0);
      else if (k === "src" || k === "dst") { var ak = ipKey(a[k]), bk = ipKey(b[k]); c = ak < bk ? -1 : ak > bk ? 1 : 0; }
      else { var av = (a[k] || "") + "", bv = (b[k] || "") + ""; c = av < bv ? -1 : av > bv ? 1 : 0; }
      if (c === 0) c = b.count - a.count;
      return c * dir;
    });
    return list;
  }
  function renderSevFilter() {
    var el = document.getElementById("sevfilter"); if (!el || !state.agg) return;
    var sc = state.agg.sevCount, defs = [[3, "high"], [2, "med"], [1, "low"]];
    var h = '<button class="sevpill' + (state.sev == null ? " on" : "") + '" data-sev="all">all</button>';
    defs.forEach(function (d) {
      h += '<button class="sevpill s' + d[0] + (state.sev === d[0] ? " on" : "") + '" data-sev="' + d[0] + '">' +
        d[1] + ' <b>' + (sc[d[0]] || 0) + '</b></button>';
    });
    el.innerHTML = h;
    el.querySelectorAll("[data-sev]").forEach(function (b) {
      b.onclick = function () { var v = b.getAttribute("data-sev"); state.sev = v === "all" ? null : +v; state.page = 0; refresh(); };
    });
  }
  function renderChips() {
    var c = document.getElementById("chips"); if (!c) return; c.innerHTML = "";
    state.filters.forEach(function (f, i) {
      var ex = f.charAt(0) === "-";
      var s = document.createElement("span"); s.className = "chip" + (ex ? " exclude" : "");
      s.innerHTML = (ex ? '≠ ' + esc(f.slice(1)) : esc(f)) + ' <span class="x">✕</span>';
      s.querySelector(".x").onclick = function () { state.filters.splice(i, 1); state.page = 0; refresh(); };
      c.appendChild(s);
    });
    if (state.filters.length + (state.sev != null ? 1 : 0) >= 2 || (state.filters.length && state.input.trim())) {
      var clr = document.createElement("button"); clr.className = "clearall"; clr.type = "button"; clr.textContent = "clear all";
      clr.onclick = function () {
        state.filters = []; state.input = ""; state.sev = null; state.page = 0;
        var f = document.getElementById("filter"); if (f) f.value = ""; refresh();
      };
      c.appendChild(clr);
    }
  }
  function renderRows(list) {
    var tb = document.getElementById("rows"); tb.innerHTML = "";
    var n = list.length, frag = document.createDocumentFragment();
    if (!n) {
      var active = state.filters.length || state.input.trim();
      tb.innerHTML = '<tr><td colspan="13" class="emptystate">' +
        (active ? 'No threats match the current filter. <a href="#" data-clear="1">clear filters</a>'
                : 'No threats for this day. ✓') + '</td></tr>';
      var cl = tb.querySelector("[data-clear]");
      if (cl) cl.onclick = function (e) { e.preventDefault(); state.filters = []; state.input = ""; var f = document.getElementById("filter"); if (f) f.value = ""; state.page = 0; refresh(); };
      return;
    }
    for (var i = 0; i < n; i++) {
      var t = list[i], tc = TYPE_COLORS[t.type] || "#8A97AD", isH = !!state.hidden[t.uidc];
      var cls = sevClass(t.sev) + (isH ? " ishidden" : "") + (state.newUids[t.uidc] ? " isnew" : "");
      var hue = (murmur3(t.uidc, 7) >>> 0) % 360; var trg = state.triage[t.uidc];                                 // deterministic per-threat color
      // condense only REAL grouping parens; escaped \\( \\) are literal chars (legacy main.js:634) — never condensed
      // escaped \( \) are literal chars (legacy main.js:634); placeholders keep them out of grouping-paren detection
      var ftrailPH = ("" + t.trail).replace(/\\\(/g, "\uE000").replace(/\\\)/g, "\uE001");
      var ftrail = ftrailPH.replace(/\uE000/g, "(").replace(/\uE001/g, ")");   // full value (tooltip + copy)
      var allTags = tagsOf(t.uidc), tagHtml = allTags.slice(0, 2).map(function (tg) {
        return '<span class="tag" data-f="tag:' + esc(tg) + '">' + esc(tg) +
          '<span class="tx" data-untag="' + t.uidc + '|' + esc(tg) + '" title="remove tag">×</span></span>';
      }).join("");
      if (allTags.length > 2) tagHtml += '<span class="tagmore" title="' + esc(allTags.join(", ")) + '">+' + (allTags.length - 2) + '</span>';
      var tr = document.createElement("tr"); tr.className = cls; tr.dataset.ri = i;
      tr.innerHTML =
        '<td data-l="threat"><div class="threatline"><span class="uid ' + ltClass(hslText(hue, 0.60, 0.48)) + '" data-f="uid:' + t.uidc + '" title="filter: this threat id" style="background:hsl(' + hue + ',60%,48%);color:' + hslText(hue, 0.60, 0.48) + '">' + t.uidc + '</span>' +
          (trg ? '<span class="trbadge tr-' + trg + '">' + TRIAGE_LABEL[trg] + '</span>' : '') +
          (getNote(t.uidc) ? '<span class="noteind" title="has a note">\u270E</span>' : '') +
          '<button class="rowhide" data-hide="' + t.uidc + '" title="' + (isH ? "restore threat" : "hide threat") +
          '" aria-label="' + (isH ? "restore threat" : "hide threat") + '">' + (isH ? "↺" : "✕") + '</button>' +
          '</div></td>' +
        '<td class="mono muted" data-l="sensor">' + sensorCellSet(t.sensorS) + '</td>' +
        '<td data-l="events"><span class="count">' + t.count + '×</span></td>' +
        '<td class="sev" data-l="severity"><span class="sev-bar"></span><span class="sev-tag" data-f="sev:' + sevName(t.sev) + '" title="filter: ' + sevName(t.sev) + ' severity">' + sevName(t.sev) + '</span></td>' +
        '<td class="sparkcol" data-l="sparkline">' + rowSpark(t.hours) + '</td>' +
        '<td data-l="source">' + ipCellSet(t.srcS) + '</td>' +
        '<td data-l="destination">' + ipCellSet(t.dstS) + '</td>' +
        '<td class="mono" data-l="port">' + portCellSet(displayPortSet(t)) + portDirHint(t) + '</td>' +
        '<td data-l="type"><span class="type lt-w" data-f="type:' + esc(t.type) + '" title="filter: type ' + esc(t.type) + '" style="background:' + tc + ';color:#fff">' + esc(t.type) + '</span></td>' +
        '<td data-l="trail"><span class="trail" data-tip="' + esc(ftrail) + '">' + trailCellHtml(ftrailPH, ftrail) + '</span></td>' +
        '<td class="mono muted" data-l="info">' +
          (function () { var ic = classOf(t.info), desc = ic ? ("" + t.info).replace(/\s*\([^)]*\)\s*$/, "") : t.info;
            return (ic ? '<span class="cls cls-' + ic + '" data-tip="' + ic + '" aria-label="' + ic + '">' + CLASS_ICON[ic] + '</span>' : '') +
                   '<span class="clip" data-tip="' + esc(t.info) + '">' + esc(desc) + '</span>'; })() + '</td>' +
        '<td class="mono muted" data-l="first seen" data-tip="first ' + hms(t.first) + ' → last ' + hms(t.last) +
          '  ·  span ' + durationStr(t.first, t.last) + '  ·  ' + t.count + ' events"><span class="reltime" data-ts="' + esc(t.first) + '">' + esc(relAge(t.first) || hms(t.first)) + '</span></td>' +
        '<td class="tagcol" data-l="tags"><div class="tagcell">' + tagHtml +
          '<button class="tagadd" data-tag="' + t.uidc + '" title="add tag">+tag</button></div></td>';
      frag.appendChild(tr);
    }
    tb.appendChild(frag);
    // click a severity tag or type chip -> add as filter
    tb.querySelectorAll("[data-f]").forEach(function (el) {
      el.style.cursor = "pointer";
      el.onclick = function () { addFilter(el.getAttribute("data-f")); };
    });
    // per-row hide / restore
    tb.querySelectorAll("[data-hide]").forEach(function (el) {
      el.onclick = function (e) { e.stopPropagation(); toggleHide(el.getAttribute("data-hide")); };
    });
    enrichIPs(); enrichFlags();
    // tags: remove (×) and add (+tag)
    tb.querySelectorAll("[data-untag]").forEach(function (el) {
      el.onclick = function (e) { e.stopPropagation(); var p = el.getAttribute("data-untag").split("|"); removeTag(p[0], p.slice(1).join("|")); };
    });
    tb.querySelectorAll("[data-tag]").forEach(function (btn) {
      btn.onclick = function (e) { e.stopPropagation(); openTagInput(btn); };
    });
    // ellipsis (collapsed multi-value) -> click copies the full list
    tb.querySelectorAll(".ell[data-copy]").forEach(function (el) {
      el.onclick = function (e) { e.stopPropagation(); copyText(el.getAttribute("data-copy"), el); };
      el.onkeydown = function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); e.stopPropagation(); copyText(el.getAttribute("data-copy"), el); } };
    });
  }
  function copyText(txt, el) {
    if (el) { el.classList.add("copied"); setTimeout(function () { el.classList.remove("copied"); }, 850); }  // instant feedback
    function execCopy() { try { var ta = document.createElement("textarea"); ta.value = txt; ta.style.position = "fixed"; ta.style.opacity = "0"; document.body.appendChild(ta); ta.focus(); ta.select(); document.execCommand("copy"); ta.remove(); } catch (e) { } }
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(txt).catch(execCopy); return; }
    } catch (e) { }
    execCopy();
  }
  function openTagInput(btn) {
    var uid = btn.getAttribute("data-tag");
    var inp = document.createElement("input");
    inp.className = "taginput"; inp.maxLength = 24; inp.placeholder = "tag…";
    btn.parentNode.replaceChild(inp, btn); inp.focus();
    function done(commit) { if (inp._done) return; inp._done = true; if (commit && inp.value.trim()) addTag(uid, inp.value); else refresh(); }
    inp.onkeydown = function (e) {
      if (e.key === "Enter") { e.preventDefault(); done(true); }
      else if (e.key === "Escape") { done(false); }
    };
    inp.onblur = function () { done(!!inp.value.trim()); };
  }
  function highlightSel() {
    var tb = document.getElementById('rows'); if (!tb) return;
    var rows = state._pageRows || [];
    if (state.selIdx >= rows.length) state.selIdx = rows.length - 1;
    var rs = tb.querySelectorAll('tr');
    for (var i = 0; i < rs.length; i++) rs[i].classList.toggle('selrow', i === state.selIdx);
    var sel = rs[state.selIdx]; if (sel && sel.scrollIntoView) sel.scrollIntoView({ block: 'nearest' });
  }
  function refresh() {
    renderChips(); renderSevFilter(); renderNewPill();
    var _sc = document.getElementById("search_clear"); if (_sc) _sc.style.display = state.input ? "" : "none";
    var list = viewList();
    // Cards + open chart follow the FILTERED set (filters only ever remove, so list < all == filtered). Rebuild the
    // aggregate from the filtered threats; skip the redraw when the filter set is unchanged (pagination / sort).
    var _filtered = list.length !== state.all.length;
    state.viewAgg = _filtered ? buildViewAgg(list) : state.agg;
    var _ssig = _filtered ? ("f" + statsFilterSig()) : ("all:" + (state.agg ? state.agg.threats.length : 0));
    if (_ssig !== state._statsSig) {
      state._statsSig = _ssig;
      if (state.viewAgg) renderStats(state.viewAgg);
      if (state.chart) { var _oc = state.chart; state.chart = null; showChart(_oc); }   // redraw the open chart on the new set
    }
    var total = list.length, size = state.limit;
    var pages = Math.max(1, Math.ceil(total / size));
    if (state.page >= pages) state.page = pages - 1;
    if (state.page < 0) state.page = 0;
    var startIdx = state.page * size;
    var pageRows = list.slice(startIdx, startIdx + size);
    var cnt = document.getElementById("count");
    var _dropped = state.agg && state.agg._dropped;
    if (cnt) cnt.textContent = (total === state.all.length ? state.all.length + " threats"
                                                           : total + " of " + state.all.length)
                               + (state.streaming ? " · streaming…" : "")
                               + (_dropped ? " · +" + fmtK(_dropped) + " ungrouped (threat limit)" : "");
    var _tbase = "Maltrail" + (DEMO ? " (demo)" : "");
    document.title = state.all.length ? _tbase + " \u00b7 " + (total === state.all.length ? state.all.length + " threats" : total + "/" + state.all.length) : _tbase;
    renderHiddenInfo(cnt);
    state._pageRows = pageRows;
    renderRows(pageRows);
    renderPager(total, pages, startIdx);
    highlightSel();
    document.querySelectorAll("thead th[data-key]").forEach(function (th) {
      var on = th.dataset.key === state.sortKey;
      th.classList.toggle("sort-asc", on && state.sortDir > 0);
      th.classList.toggle("sort-desc", on && state.sortDir < 0);
      th.setAttribute("aria-sort", on ? (state.sortDir > 0 ? "ascending" : "descending") : "none");
    });
    syncHash();
  }
  function pageSeq(cur, pages) {  // 1-based page numbers with "…" gaps around the current page + ends
    var set = {}, out = [], prev = 0;
    [1, 2, pages - 1, pages, cur, cur + 1, cur + 2].forEach(function (p) { if (p >= 1 && p <= pages) set[p] = 1; });
    Object.keys(set).map(Number).sort(function (a, b) { return a - b; }).forEach(function (p) {
      if (p - prev > 1) out.push("…"); out.push(p); prev = p;
    });
    return out;
  }
  // scroll: only when invoked from the pager buttons (which sit at the bottom of the table) — and only if the
  // table top isn't already visible. Keyboard ←/→ paging passes scroll=false so it never yanks the viewport.
  function gotoPage(p, scroll) {
    state.page = p; refresh();
    if (!scroll) return;
    var g = document.querySelector(".grid-wrap"); if (!g) return;
    var r = g.getBoundingClientRect();
    if (r.top < 0 || r.top > window.innerHeight) g.scrollIntoView({ block: "start" });
  }
  function renderPager(total, pages, startIdx) {
    var pg = document.getElementById("pager"); if (!pg) return;
    if (total <= state.limit) { pg.innerHTML = ""; pg.style.display = "none"; return; }
    pg.style.display = "";
    var cur = state.page, end = Math.min(total, startIdx + state.limit);
    var h = '<span class="pginfo">' + (startIdx + 1) + '–' + end + ' of ' + total + ' threats</span><span class="pgbtns">';
    h += '<button class="pgbtn" data-pg="prev"' + (cur <= 0 ? ' disabled' : '') + ' aria-label="previous page">‹</button>';
    pageSeq(cur + 1, pages).forEach(function (p) {
      h += p === "…" ? '<span class="pgdots">…</span>'
                     : '<button class="pgbtn pgnum' + (p - 1 === cur ? ' on' : '') + '" data-pg="' + (p - 1) + '">' + p + '</button>';
    });
    h += '<button class="pgbtn" data-pg="next"' + (cur >= pages - 1 ? ' disabled' : '') + ' aria-label="next page">›</button></span>';
    pg.innerHTML = h;
    pg.querySelectorAll("[data-pg]").forEach(function (b) {
      b.onclick = function () { var v = b.getAttribute("data-pg"); gotoPage(v === "prev" ? cur - 1 : v === "next" ? cur + 1 : +v, true); };
    });
  }
  // ---- IP enrichment via same-origin /check_ip (real mode only) ----
  // /check_ip returns {ipcat: "<provider/category>", worst_asns: "true|false"}; we tag each public IP cell with a
  // small category label + a malicious-ASN dot. Lazy + cached per IP so re-renders don't refetch.
  var ipInfo = {};   // ip -> {cat, worst} | "pending"
  function ipSpan(ip) {
    var a = aliasOf(ip);
    return '<span class="ip" data-ip="' + esc(ip) + '">' + (isPrivIP(ip) ? '<span class="lan" title="local / private network">' + LAN_ICON + '</span>' : '') + (a ? '<span class="ipcat">' + esc(a) + '</span>' : '') + esc(ip) + '</span>';
  }
  // a threat compacts many events -> multi-value columns collapse to an ellipsis with the full list on hover + copy
  var PORT_NAMES = { "21": "ftp", "22": "ssh", "23": "telnet", "25": "smtp", "53": "dns", "80": "http", "110": "pop3",
    "123": "ntp", "135": "rpc", "137": "netbios", "139": "netbios", "143": "imap", "161": "snmp", "389": "ldap",
    "443": "https", "445": "smb", "465": "smtps", "514": "syslog", "587": "smtp", "636": "ldaps", "993": "imaps",
    "995": "pop3s", "1080": "socks", "1433": "mssql", "1521": "oracle", "2049": "nfs", "3306": "mysql", "3389": "rdp",
    "4444": "metasploit", "5432": "postgres", "5900": "vnc", "6379": "redis", "8080": "http-alt", "8443": "https-alt",
    "9200": "elastic", "27017": "mongo" };
  function portLabel(p) { return PORT_NAMES[p] ? p + " (" + PORT_NAMES[p] + ")" : p; }
  // notable destination ports worth an eyeball in a threat alert: C2/RAT defaults + remote-access + cleartext
  var RISKY_PORTS = { "23": "Telnet — cleartext remote access", "445": "SMB — lateral movement", "1337": "common backdoor",
    "3389": "RDP — remote access", "4444": "Metasploit / Meterpreter default", "5900": "VNC — remote access",
    "6666": "IRC botnet", "6667": "IRC C2", "9001": "Tor", "12345": "NetBus backdoor", "31337": "\"elite\" backdoor" };
  function riskyPort(p) { return RISKY_PORTS[p] || ""; }
  // render a trail: literal text stays, each REAL grouping paren collapses to the SAME ".ell" copy token
  // used by the port/source/dest multi-value cells — one consistent "collapsed, click to copy" affordance.
  function trailCellHtml(withPH, full) {
    function lit(str) { return esc(str.replace(/\uE000/g, "(").replace(/\uE001/g, ")")); }
    var re = /\([^)]*\)/g, out = "", last = 0, m;
    while ((m = re.exec(withPH))) {
      out += lit(withPH.slice(last, m.index));
      out += '<span class="ell" role="button" tabindex="0" aria-label="copy full trail" data-tip="' + esc(full) + '" data-copy="' + esc(full) + '">\u2026</span>';
      last = re.lastIndex;
    }
    out += lit(withPH.slice(last));
    return out || esc(full);
  }
  function ellSpan(list, titleList) {
    var copy = list.join(", "), n = list.length;
    var title = n + (n === 1 ? " value:\n" : " values:\n") + (titleList || list).join(", ");   // count lives in the tooltip
    return '<span class="ell" role="button" tabindex="0" aria-label="copy ' + n + (n === 1 ? ' value' : ' values') + '" data-tip="' + esc(title) + '" data-copy="' + esc(copy) + '">…</span>';
  }
  function ipCellSet(s) { var l = setList(s); return !l.length ? "" : l.length === 1 ? ipSpan(l[0]) : ellSpan(l); }
  function sensorCellSet(s) { var l = setList(s); return !l.length ? "" : l.length === 1 ? '<span class="mono sensor" data-f="sensor:' + esc(l[0]) + '" title="filter: sensor ' + esc(l[0]) + '">' + esc(l[0]) + '</span>' : ellSpan(l); }
  // Which port to SHOW/FILTER for a threat + the direction the FLAGGED traffic flowed relative to it. The chosen
  // port is the SERVICE (triggering) side; the arrow is then FACTUAL — it just reports whether that port is the
  // dst of the logged packet (traffic went INTO it: a request/attack → "in", arrow ←) or the src (traffic came
  // OUT of it: a response → "out", arrow →). Service side is decided, in order of soundness:
  //   1) an IP:port trail names the exact triggering port + endpoint -> compare its IP to src/dst (any port size)
  //   2) a recognised well-known service port (53/80/443/8080/…) -> that side is the service
  //   3) fallback: the lower port number is the service (ephemeral ports are high)
  // Examples: SQL-inj request to 200:8080 -> "8080 ←"; sinkhole DNS *reply* from :53 -> "53 →"; malware-domain
  // DNS *query* to :53 -> "53 ←"; connection to C2 bad:54321 (IPORT trail) -> "54321 ←".
  var WELLKNOWN = { "20": 1, "21": 1, "22": 1, "23": 1, "25": 1, "53": 1, "67": 1, "68": 1, "69": 1, "80": 1, "110": 1, "123": 1, "135": 1, "137": 1, "138": 1, "139": 1, "143": 1, "161": 1, "162": 1, "389": 1, "443": 1, "445": 1, "465": 1, "514": 1, "587": 1, "636": 1, "993": 1, "995": 1, "1080": 1, "1433": 1, "1521": 1, "3128": 1, "3306": 1, "3389": 1, "5060": 1, "5432": 1, "5900": 1, "6379": 1, "6667": 1, "8000": 1, "8080": 1, "8118": 1, "8443": 1, "8888": 1, "9200": 1, "27017": 1 };
  var EPHEMERAL_MIN = 32768;   // OS-assigned client ports live here (Linux 32768-60999, IANA 49152+); a service port is below it
  function portInfo(t) {
    var sp = parseInt(t.sport, 10), dp = parseInt(t.dport, 10), haveS = sp > 0, haveD = dp > 0;
    if (!(haveS && haveD)) return { set: haveS ? t.sportS : t.dportS, dir: "" };   // one side portless (ICMP etc.)
    var IN = { set: t.dportS, dir: "in" }, OUT = { set: t.sportS, dir: "out" };
    // 1) IP:port trail names the exact triggering port + endpoint -> compare its IP to src/dst (exact, any port size)
    var m = ("" + t.trail).match(/^\[?(.*?)\]?:(\d+)$/);
    if (m) { if (m[1] === t.dst) return IN; if (m[1] === t.src) return OUT; }
    // 1b) a bare-IP trail equal to the destination = we connected TO that bad host -> traffic INTO its port
    //     (fixes a bad dst on a high, non-well-known port that the heuristics below can't disambiguate). Bad-SOURCE
    //     bare-IP trails are left to the heuristics, which correctly pick our (destination) service port.
    if (t.trail === t.dst) return IN;
    // 2) a privileged (<1024) or registered well-known port on exactly one side is the service
    var sSvc = sp < 1024 || WELLKNOWN[t.sport], dSvc = dp < 1024 || WELLKNOWN[t.dport];
    if (dSvc && !sSvc) return IN;
    if (sSvc && !dSvc) return OUT;
    // 3) ephemeral rule: the side that is NOT a high (ephemeral) port is the service — catches services on
    //    non-well-known mid-range ports (e.g. 8081) vs a real client ephemeral, without a lookup table
    var sEph = sp >= EPHEMERAL_MIN, dEph = dp >= EPHEMERAL_MIN;
    if (dEph && !sEph) return OUT;   // dst is ephemeral -> src is the service (traffic came OUT of it)
    if (sEph && !dEph) return IN;    // src is ephemeral -> dst is the service (traffic went INTO it)
    // 4) last resort (both/neither look like a service): lower port = service
    return dp <= sp ? IN : OUT;
  }
  function displayPortSet(t) { return portInfo(t).set; }
  function portDir(t) { return portInfo(t).dir; }
  // Risk score for the DEFAULT ("severity" column) ordering. Severity dominates (a band each 1000 wide) so a high
  // never sorts below a medium; WITHIN a band, active-compromise language lifts a quiet threat above loud ambient
  // noise (a scanner hammering a port shouldn't bury one C2 beacon). Volume is a log-scaled, capped tiebreak only.
  var RISK_HOT = /\b(c2|cnc|cobalt|beacon|trojan|ransom|sinkhole|dga|malware|infect(?:ed|ion)?|exfil|backdoor|rat|apt|stealer|botnet|loader|dropper|phish)\b/;
  var RISK_NOISE = /\b(scan|scanner|reputation|attacker|crawler|bruteforce|brute[-\s]?force|mass|spam|probe|honeypot)\b/;
  function riskOf(t) {
    var s = (t.sev || 1) * 1000;
    var hay = (("" + (t.type || "")) + " " + (t.info || "") + " " + (t.trail || "")).toLowerCase();
    if (RISK_HOT.test(hay)) s += 400;
    if (RISK_NOISE.test(hay)) s -= 250;
    s += Math.min(90, Math.log(1 + (t.count || 1)) * 15);
    return s;
  }
  // inline SVG arrows (not Unicode glyphs, whose vertical position is font-dependent — Firefox rendered → / ← below
  // the text's middle). An SVG is centered by construction, so vertical-align:middle aligns it on the port text in
  // every browser. ← = the traffic INTO this port was flagged; → = the traffic OUT of this port was flagged.
  function _arrowSVG(paths) { return '<svg class="dir-arrow" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.25" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + paths + '</svg>'; }
  var PORT_DIR = {
    out: [_arrowSVG('<line x1="4" y1="12" x2="18.5" y2="12"/><polyline points="13 6.5 19 12 13 17.5"/>'), "the traffic OUT of this port was flagged (e.g. a malicious response/reply)"],
    "in": [_arrowSVG('<line x1="20" y1="12" x2="5.5" y2="12"/><polyline points="11 6.5 5 12 11 17.5"/>'), "the traffic INTO this port was flagged (e.g. a malicious request/attack)"]
  };
  function portDirHint(t) { var d = portDir(t); return d ? '<span class="port-dir pd-' + d + '" data-f="dir:' + d + '" title="' + PORT_DIR[d][1] + ' — click to filter ' + d + '">' + PORT_DIR[d][0] + '</span>' : ""; }
  function portCellSet(s) {
    var l = setList(s); if (!l.length) return "";
    if (l.length === 1) {
      var rk = riskyPort(l[0]);
      return '<span class="mono port' + (rk ? ' risky" data-tip="' + esc(rk) : '') + '">' + esc(portLabel(l[0])) + '</span>';
    }
    var anyRisky = l.some(function (p) { return riskyPort(p); });
    return '<span' + (anyRisky ? ' class="riskyset"' : '') + '>' + ellSpan(l, l.map(portLabel)) + '</span>';   // ell handles the tooltip
  }
  function isPubIP(ip) {
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return false;          // IPv4 only (dst domains live in the trail col)
    if (/^(10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|22[4-9]\.|23\d\.|255\.)/.test(ip)) return false;
    return true;
  }
  function applyIPInfo(ip) {
    var info = ipInfo[ip]; if (!info || info === "pending") return;
    var sel = document.querySelectorAll('#rows .ip[data-ip="' + cssEsc(ip) + '"]');
    for (var i = 0; i < sel.length; i++) {
      var c = sel[i]; if (c._enriched) continue; c._enriched = true;
      if (info.cat && !c.querySelector(".ipcat")) { var s = document.createElement("span"); s.className = "ipcat"; s.textContent = info.cat; c.insertBefore(s, c.firstChild); }
      if (info.worst) { var w = document.createElement("span"); w.className = "worstasn"; w.title = "malicious ASN"; c.appendChild(w); }
    }
  }
  function enrichIPs() {
    if (DEMO) return;
    var cells = document.querySelectorAll("#rows .ip[data-ip]"), want = {};
    for (var i = 0; i < cells.length; i++) { var ip = cells[i].getAttribute("data-ip"); if (isPubIP(ip)) want[ip] = 1; }
    Object.keys(want).forEach(function (ip) {
      if (ipInfo[ip] !== undefined) { applyIPInfo(ip); return; }
      ipInfo[ip] = "pending";
      fetch("/check_ip?address=" + encodeURIComponent(ip), { credentials: "same-origin" })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (j) {
          ipInfo[ip] = j ? { cat: (j.ipcat || ""), worst: j.worst_asns === "true" } : { cat: "", worst: false };
          // offline GeoIP fallback: if RIPE hasn't supplied a country (air-gapped -> its JSONP is dead), use the
          // country from our local RIR table so the flag still shows. Same-origin /check_ip works air-gapped.
          if (j && j.country && !(ripe[ip] && ripe[ip].cc)) { ripe[ip] = ripe[ip] || { t: +new Date() }; ripe[ip].cc = j.country.toLowerCase(); applyRipe(ip); }
          applyIPInfo(ip); refreshTipFor(ip);
        })
        .catch(function () { ipInfo[ip] = { cat: "", worst: false }; });
    });
  }

  // ---- RIPE geolocation + ASN enrichment: country flags + hover tooltip (like the legacy UI) ----
  // The production CSP allows scripts from stat.ripe.net (script-src) but only same-origin fetch (connect-src 'self'),
  // so RIPEstat is queried via JSONP <script>, NOT fetch. Air-gapped installs: the script just fails -> no flag,
  // everything else keeps working. Results cached in localStorage for 7 days so we don't re-hit RIPE on every reload.
  var RIPE_TTL = 7 * 864e5, _ripeSeq = 0;
  var ripe = (function () {
    var o = lsGet("mt_ripe", {}); if (!o || typeof o !== "object") return {};
    var now = +new Date(), out = {};
    for (var k in o) if (o[k] && o[k].t && (now - o[k].t) < RIPE_TTL) out[k] = o[k];
    return out;
  })();
  function saveRipe() { lsSet("mt_ripe", ripe); }
  function flagEmoji(cc) {   // 2-letter country code -> regional-indicator emoji (zero assets, offline-friendly)
    if (!cc || !/^[a-z]{2}$/i.test(cc)) return "";
    cc = cc.toUpperCase();
    return String.fromCodePoint(0x1F1E6 + cc.charCodeAt(0) - 65) + String.fromCodePoint(0x1F1E6 + cc.charCodeAt(1) - 65);
  }
  var _regionNames;
  function countryName(cc) {
    if (!cc) return "";
    try {
      if (_regionNames === undefined) _regionNames = (typeof Intl !== "undefined" && Intl.DisplayNames) ? new Intl.DisplayNames(["en"], { type: "region" }) : null;
      if (_regionNames) return _regionNames.of(cc.toUpperCase()) || cc.toUpperCase();
    } catch (e) {}
    return cc.toUpperCase();
  }
  // capped JSONP: a dense page can want hundreds of distinct IPs; firing every lookup at once is a request storm
  // against stat.ripe.net and bloats <head> with hundreds of live <script> nodes. Queue + run RIPE_MAX at a time.
  var _ripeQ = [], _ripeActive = 0, RIPE_MAX = 6;
  // Air-gap circuit breaker: RIPEstat is unreachable on an isolated network, where failures are NOT
  // cached (only successful country codes are) -> every reload would re-storm stat.ripe.net with a
  // <script> per IP, each capable of hanging to the timeout (console spam + delayed/absent flags).
  // After a few consecutive failures we conclude "no internet" and stop trying for the session; a
  // single success resets it. Fully client-side -> zero config, auto-adapts online vs air-gapped.
  var _ripeFails = 0, _ripeDead = false, RIPE_FAIL_LIMIT = 3;
  function ripeJSONP(query, cb) { if (_ripeDead) { try { cb(null); } catch (e) {} return; } _ripeQ.push([query, cb]); _ripePump(); }
  function _ripePump() { while (!_ripeDead && _ripeActive < RIPE_MAX && _ripeQ.length) { var it = _ripeQ.shift(); _ripeActive++; _ripeRun(it[0], it[1]); } }
  function _ripeRun(query, cb) {
    var name = "__ripe_cb_" + (++_ripeSeq), s = document.createElement("script"), done = false, to;
    function cleanup() { clearTimeout(to); try { delete window[name]; } catch (e) { window[name] = undefined; } if (s.parentNode) s.parentNode.removeChild(s); _ripeActive--; _ripePump(); }
    function fail() {
      if (done) return; done = true;
      if (++_ripeFails >= RIPE_FAIL_LIMIT) { _ripeDead = true; _ripeQ.length = 0; }   // give up for this session (air-gapped)
      try { cb(null); } catch (e) {} cleanup();
    }
    window[name] = function (data) { done = true; _ripeFails = 0; try { cb(data); } catch (e) {} cleanup(); };   // success -> reset the breaker
    s.onerror = fail;
    to = setTimeout(fail, 8000);   // a hung lookup must not stall the queue (shorter: air-gapped should fail fast)
    s.src = "https://stat.ripe.net/data/" + query + (query.indexOf("?") < 0 ? "?" : "&") + "callback=" + name;
    (document.head || document.documentElement).appendChild(s);
  }
  var DEMO_CC = ["us","de","nl","ru","cn","ir","fr","gb","ua","br","in","kr","ca","se","sg","tr","ro","vn","pl","jp"];
  var _geoInflight = {}, _asnInflight = {};
  // proactive: country flag only (1 request per IP, cached). Demo fabricates so flags show offline/in the artifact.
  function ripeGeo(ip) {
    var r = ripe[ip]; if (r && r.cc != null) { applyRipe(ip); return; }
    if (_geoInflight[ip]) return; _geoInflight[ip] = 1;
    if (DEMO) { var h = murmur3(ip, 99) >>> 0; ripe[ip] = ripe[ip] || { t: +new Date() }; ripe[ip].cc = DEMO_CC[h % DEMO_CC.length]; applyRipe(ip); refreshTipFor(ip); return; }
    ripeJSONP("geoloc/data.json?resource=" + encodeURIComponent(ip), function (j) {
      var cc = ""; try { cc = (j.data.located_resources[0].locations[0].country || "").toLowerCase().split("-")[0]; } catch (e) {}
      ripe[ip] = ripe[ip] || {}; ripe[ip].cc = cc; ripe[ip].t = +new Date(); saveRipe(); applyRipe(ip); refreshTipFor(ip);
    });
  }
  // lazy: ASN + holder, fetched only when a tooltip opens for the IP (cached)
  function ripeAsn(ip) {
    var r = ripe[ip]; if (r && r.asn != null) return;
    if (_asnInflight[ip]) return; _asnInflight[ip] = 1;
    if (DEMO) { var h = murmur3(ip, 99) >>> 0; ripe[ip] = ripe[ip] || { t: +new Date() }; ripe[ip].asn = "AS" + (1000 + h % 64000); ripe[ip].holder = "Example Networks " + (100 + h % 900); refreshTipFor(ip); applyRipe(ip); return; }
    ripeJSONP("network-info/data.json?resource=" + encodeURIComponent(ip), function (j) {
      var asn = "", holder = ""; try { if (j.data.asns && j.data.asns.length) asn = "AS" + j.data.asns[0]; } catch (e) {}
      ripe[ip] = ripe[ip] || {}; ripe[ip].asn = asn; if (holder) ripe[ip].holder = holder; ripe[ip].t = +new Date(); saveRipe(); refreshTipFor(ip); applyRipe(ip);
    });
  }
  function applyRipe(ip) {
    var rec = ripe[ip]; if (!rec || !rec.cc) return;
    var fe = flagEmoji(rec.cc); if (!fe) return;
    var cn = countryName(rec.cc);
    var sel = document.querySelectorAll('#rows .ip[data-ip="' + cssEsc(ip) + '"], #drawer .dchip[data-ip="' + cssEsc(ip) + '"]');
    for (var i = 0; i < sel.length; i++) {
      var c = sel[i], isChip = c.className.indexOf("dchip") >= 0;
      if (isChip) c.title = cn + (rec.asn ? " · " + rec.asn + (rec.holder ? " " + rec.holder : "") : "");   // drawer chip: flag + country/ASN tooltip
      if (c.querySelector(".flag")) continue;
      var f = document.createElement("span"); f.className = "flag"; f.textContent = fe;   // country shown in the styled tooltip; no native title (would overlap it)
      c.insertBefore(f, c.firstChild);
    }
  }
  function enrichFlags() {   // fire RIPE lookups for visible public IPs (both modes; demo fabricates)
    var cells = document.querySelectorAll("#rows .ip[data-ip]"), want = {};
    for (var i = 0; i < cells.length; i++) { var ip = cells[i].getAttribute("data-ip"); if (isPubIP(ip)) want[ip] = 1; }
    Object.keys(want).forEach(function (ip) { applyRipe(ip); ripeGeo(ip); });
  }
  function enrichDrawerIPs() {   // flags + country/ASN tooltip on the drawer's source/dest chips
    var cells = document.querySelectorAll("#drawer .dchip[data-ip]"), want = {};
    for (var i = 0; i < cells.length; i++) { var ip = cells[i].getAttribute("data-ip"); if (isPubIP(ip)) want[ip] = 1; }
    Object.keys(want).forEach(function (ip) { applyRipe(ip); ripeGeo(ip); ripeAsn(ip); });
  }

  // ---- hover tooltip for IP cells: flag + country + ASN/holder + category ----
  var _tipEl, _tipIP = null;
  function tipEl() { if (!_tipEl) { _tipEl = document.createElement("div"); _tipEl.className = "hovertip"; _tipEl.style.display = "none"; document.body.appendChild(_tipEl); } return _tipEl; }
  function hideTip() { if (_tipEl) _tipEl.style.display = "none"; _tipIP = null; }
  function placeTip(x, y) {
    var t = tipEl(), w = t.offsetWidth, h = t.offsetHeight, vw = window.innerWidth, vh = window.innerHeight;
    var left = x + 14, top = y + 16;
    if (left + w > vw - 8) left = x - w - 14; if (left < 6) left = 6;
    if (top + h > vh - 8) top = y - h - 16; if (top < 6) top = 6;
    t.style.left = left + "px"; t.style.top = top + "px";
  }
  function ipTipHTML(ip) {
    var rec = ripe[ip], ci = ipInfo[ip], a = IP_ALIASES[ip], pub = isPubIP(ip), L = [];
    var geo = (rec && rec.cc) ? '<span class="tt-flag">' + flagEmoji(rec.cc) + "</span>" + esc(countryName(rec.cc))
            : (pub ? '<span class="tt-dim">locating…</span>' : "");
    L.push('<div class="tt-ip">' + esc(ip) + (geo ? ' <span class="tt-geo">' + geo + "</span>" : "") + "</div>");
    if (a) L.push('<div class="tt-row"><span>alias</span>' + esc(a) + "</div>");
    if (rec && rec.asn) L.push('<div class="tt-row"><span>ASN</span>' + esc(rec.asn) + (rec.holder ? " · " + esc(rec.holder) : "") + "</div>");
    if (ci && ci !== "pending" && ci.cat) L.push('<div class="tt-row"><span>category</span>' + esc(ci.cat) + "</div>");
    if (ci && ci !== "pending" && ci.worst) L.push('<div class="tt-row tt-warn">⚠ malicious ASN</div>');
    if (!pub) L.push('<div class="tt-row tt-dim">private / LAN address — no geolocation</div>');
    return L.join("");
  }
  function refreshTipFor(ip) { if (_tipIP === ip && _tipEl && _tipEl.style.display !== "none") _tipEl.innerHTML = ipTipHTML(ip); }
  // styled tooltip for the collapsed "…" cells (same look as the IP tooltip, not the native browser hint)
  function ellTipHTML(text) {
    var parts = ("" + text).split("\n");
    if (parts.length > 1) {   // ellSpan form: "N values:\nv, v, v" -> header + value list
      var vals = parts.slice(1).join("\n").split(", ");
      return '<div class="tt-ip">' + esc(parts[0]) + '</div><div class="tt-vals">' + vals.map(function (v) { return esc(v); }).join("<br>") + "</div>";
    }
    return '<div class="tt-vals">' + esc(text) + "</div>";   // single value (trail/info/etc.) — just the value, no header
  }
  function renderHiddenInfo(cnt) {
    var hc = 0; for (var k in state.hidden) hc++;
    var wc = wlCount();
    var hi = document.getElementById("hiddeninfo");
    if (!hi && cnt && cnt.parentNode) {
      hi = document.createElement("span"); hi.id = "hiddeninfo"; hi.className = "hiddeninfo";
      cnt.parentNode.insertBefore(hi, cnt.nextSibling);
    }
    if (!hi) return;
    if (!hc && !wc) { hi.style.display = "none"; hi.innerHTML = ""; return; }
    hi.style.display = "";
    var parts = [];
    if (hc) parts.push(hc + ' hidden · <a href="#" data-act="toggle">' + (state.showHidden ? "conceal" : "reveal") + '</a> · <a href="#" data-act="clear">clear</a>');
    if (wc) parts.push(wc + ' whitelisted · <a href="#" data-act="wl">manage</a>');
    hi.innerHTML = '· ' + parts.join(' · ');
    var _tg = hi.querySelector('[data-act="toggle"]'); if (_tg) _tg.onclick = function (e) { e.preventDefault(); state.showHidden = !state.showHidden; refresh(); };
    var _cl = hi.querySelector('[data-act="clear"]'); if (_cl) _cl.onclick = function (e) { e.preventDefault(); unhideAll(); };
    var _wm = hi.querySelector('[data-act="wl"]'); if (_wm) _wm.onclick = function (e) { e.preventDefault(); showWLManage(); };
  }
  function addFilter(tok) {
    tok = ("" + tok).toLowerCase();
    if (tok && state.filters.indexOf(tok) < 0) { state.filters.push(tok); state.page = 0; refresh(); }
  }
  // ---- light / dark theme (persisted) ----
  function getTheme() { try { return localStorage.getItem("mt_theme") || "dark"; } catch (e) { return "dark"; } }
  function applyTheme(t) {
    document.body.classList.toggle("light", t === "light");
    var b = document.getElementById("theme_toggle"); if (b) b.textContent = t === "light" ? "☀" : "☾";
  }
  function setTheme(t) {
    try { localStorage.setItem("mt_theme", t); } catch (e) { }
    applyTheme(t);
    // canvases bake in theme colors at draw time -> redraw the stat minis + any open chart so they match the new theme
    if (state.agg) { renderStats(state.viewAgg || state.agg); var oc = state.chart; if (oc) { state.chart = null; showChart(oc); } }
  }
  // ---- text size (accessibility): zoom the whole UI in discrete steps, persisted ----
  var FZ_STEPS = [0.9, 1, 1.1, 1.25, 1.4];
  function getScaleIdx() { var v = parseInt((function () { try { return localStorage.getItem("mt_scale"); } catch (e) { return null; } })(), 10); return (v >= 0 && v < FZ_STEPS.length) ? v : 1; }
  function applyScale(idx) { document.documentElement.style.zoom = FZ_STEPS[idx]; }
  function setScale(idx) { idx = Math.max(0, Math.min(FZ_STEPS.length - 1, idx)); try { localStorage.setItem("mt_scale", idx); } catch (e) { } applyScale(idx); }
  // ONE block above the table holds either the dashboard (cards + drill-down charts) OR the attack map. Two separate,
  // one-click intents: the VIEW toggle flips dashboard <-> map (mutually exclusive, always one of them), and the
  // COLLAPSE chevron hides/shows the whole block (full-height table when hidden). Persisted: mt_panel + mt_collapsed.
  function getView() { try { return localStorage.getItem("mt_panel") === "map" ? "map" : "dash"; } catch (e) { return "dash"; } }
  function getCollapsed() {
    try {
      var c = localStorage.getItem("mt_collapsed");
      if (c === "0" || c === "1") return c === "1";
      return localStorage.getItem("mt_cards") === "1";   // migrate the old "hide dashboard" flag
    } catch (e) { return false; }
  }
  function applyView() {
    var view = getView(), collapsed = getCollapsed();
    var dashShown = !collapsed && view === "dash", mapShown = !collapsed && view === "map";
    document.body.classList.toggle("cards-collapsed", !dashShown);   // hides .stats + #chart_area unless the dashboard is the shown view
    var wm = document.getElementById("worldmap"); if (wm) wm.hidden = !mapShown;   // .worldmap[hidden] actually hides it
    var vt = document.getElementById("view_toggle");
    if (vt) {
      var icD = vt.querySelector(".ic-dash"), icM = vt.querySelector(".ic-map"), toMap = (view !== "map");   // icon = the view you'll switch TO
      if (icD) icD.style.display = toMap ? "none" : "block";
      if (icM) icM.style.display = toMap ? "block" : "none";
      vt.title = toMap ? "show attack map" : "show dashboard"; vt.setAttribute("aria-label", vt.title);
    }
    var ct = document.getElementById("collapse_toggle");
    if (ct) { ct.setAttribute("aria-expanded", collapsed ? "false" : "true"); ct.title = collapsed ? "show panel" : "hide panel"; ct.setAttribute("aria-label", ct.title); }
    if (mapShown) renderWorldMap();
  }
  function setView(v) { try { localStorage.setItem("mt_panel", v); } catch (e) { } }
  function setCollapsed(c) { try { localStorage.setItem("mt_collapsed", c ? "1" : "0"); } catch (e) { } }
  function toggleView() { setView(getView() === "map" ? "dash" : "map"); setCollapsed(false); applyView(); }   // switching view always shows it
  function toggleCollapsed() { setCollapsed(!getCollapsed()); applyView(); }

  // ---- attack-origin world map (fed by /geo: trail IPs only, so mapped/unmapped is honest) ----
  var WM_BASE = ["#ffd24c", "#ffab2e", "#fd7a1e", "#f0431f", "#d1102e"];   // 5-step warm heat, few -> many (theme-independent, like the calendar)
  function wmBucket(n) { return !n ? 0 : n < 50 ? 1 : n < 500 ? 2 : n < 5000 ? 3 : n < 50000 ? 4 : 5; }
  function wmColor(n) { return WM_BASE[Math.max(0, wmBucket(n) - 1)]; }
  var _wmBuilt = false, _wmReqDate = null;
  function buildWmShell() {
    var host = document.getElementById("worldmap"); if (!host || _wmBuilt) return;
    host.innerHTML =
      '<div class="wm-map"><div class="wm-hd">Attack origins <small class="wm-sub"></small></div>' + (window.WORLD_SVG || "") +
      '<div class="wm-leg"><span>events</span><i style="width:5px;height:5px"></i><i style="width:9px;height:9px"></i><i style="width:14px;height:14px"></i></div></div>' +
      '<div class="wm-side"><h4>Top source countries</h4><div class="wm-list"></div></div>';
    var svg = host.querySelector("#wm");
    if (svg) svg.insertAdjacentHTML("afterbegin", '<defs><filter id="wmglow" x="-70%" y="-70%" width="240%" height="240%"><feGaussianBlur stdDeviation="3.2"/></filter></defs>');
    _wmBuilt = true;
  }
  function paintWm(data) {
    var host = document.getElementById("worldmap"); if (!host) return;
    var svg = host.querySelector("#wm"), C = window.WORLD_CENT || {}, counts = (data && data.counts) || {};
    var items = Object.keys(counts).filter(function (cc) { return C[cc]; }).map(function (cc) { return [cc, counts[cc]]; });
    items.sort(function (a, b) { return a[1] - b[1]; });   // small first so the big/hot dots paint on top
    if (svg) {
      var halos = "", cores = "", arcs = "", home = "";
      items.forEach(function (it) {
        var xy = C[it[0]], b = wmBucket(it[1]), r = 3 + b * 2, col = WM_BASE[Math.max(0, b - 1)];
        halos += '<circle cx="' + xy[0] + '" cy="' + xy[1] + '" r="' + (r * 1.8).toFixed(1) + '" fill="' + col + '"/>';
        cores += '<circle cx="' + xy[0] + '" cy="' + xy[1] + '" r="' + r + '" fill="' + col + '" stroke="#fff" stroke-opacity=".4" stroke-width=".6"><title>' + esc(it[0]) + ': ≈ ' + fmtN(it[1]) + ' events</title></circle>';
      });
      var hm = data && data.home;   // arcs + home only when HOME_LAT/LON is configured (air-gap can't auto-locate)
      if (hm && window.WORLD_LL2XY) {
        var hp = window.WORLD_LL2XY(hm.lon, hm.lat), hx = +hp[0].toFixed(1), hy = +hp[1].toFixed(1);
        items.forEach(function (it) {
          var xy = C[it[0]], mx = ((xy[0] + hx) / 2).toFixed(1), my = ((xy[1] + hy) / 2 - Math.hypot(hx - xy[0], hy - xy[1]) * 0.32).toFixed(1);
          arcs += '<path class="wm-arc" d="M' + xy[0] + ' ' + xy[1] + ' Q' + mx + ' ' + my + ' ' + hx + ' ' + hy + '" stroke-width="1" stroke-opacity=".5" stroke-linecap="round" stroke-dasharray="2 8"><animate attributeName="stroke-dashoffset" values="30;0" dur="1.4s" repeatCount="indefinite"/></path>';
        });
        home = '<g><circle cx="' + hx + '" cy="' + hy + '" r="4" fill="none" stroke="#34d399" stroke-width="1.4"><animate attributeName="r" values="4;13" dur="2.2s" repeatCount="indefinite"/><animate attributeName="opacity" values=".8;0" dur="2.2s" repeatCount="indefinite"/></circle><circle cx="' + hx + '" cy="' + hy + '" r="3.4" fill="#eafff5" stroke="#34d399" stroke-width="1.3"><title>Your network</title></circle></g>';
      }
      var olds = svg.querySelectorAll(".wm-dotlayer"); for (var i = 0; i < olds.length; i++) olds[i].parentNode.removeChild(olds[i]);
      svg.insertAdjacentHTML("beforeend", '<g class="wm-dotlayer">' + arcs + '</g><g class="wm-dotlayer" filter="url(#wmglow)" opacity=".5">' + halos + '</g><g class="wm-dotlayer">' + cores + home + '</g>');
    }
    var top = items.slice().sort(function (a, b) { return b[1] - a[1]; }).slice(0, 8), max = top.length ? top[0][1] : 1;
    var list = host.querySelector(".wm-list");
    if (list) list.innerHTML = top.length
      ? top.map(function (it) { return '<div class="wm-row"><span class="wm-cc">' + esc(it[0]) + '</span><span class="wm-bar" style="width:' + (10 + Math.round(86 * it[1] / max)) + '%;background:' + wmColor(it[1]) + '"></span><span class="wm-vn">' + fmtN(it[1]) + '</span></div>'; }).join("")
      : '<div class="wm-empty">No geolocatable sources for this day.</div>';
    var sub = host.querySelector(".wm-sub");
    if (sub) sub.textContent = "· " + fmtN((data && data.mapped) || 0) + " mapped · " + fmtN((data && data.unmapped) || 0) + " local/unmapped";
  }
  function demoCC(ip) { return DEMO_CC[(murmur3(ip, 99) >>> 0) % DEMO_CC.length].toUpperCase(); }   // same fabrication as the table flags -> map matches
  function demoGeo() {
    // build the showcase map from the demo events, geolocated with the SAME fabrication as the flags, so the map's
    // countries line up with the table's flags. a demo "home" is set so the arcs are visible in the public demo.
    var counts = {}, mapped = 0, unmapped = 0, d = state.agg;
    if (d && d.threats) for (var i = 0; i < d.threats.length; i++) {
      var t = d.threats[i], ss = setList(t.srcS), cc = "";
      for (var k = 0; k < ss.length; k++) { if (isPubIP(ss[k])) { cc = demoCC(ss[k]); break; } }
      if (cc) { counts[cc] = (counts[cc] || 0) + t.count; mapped += t.count; } else { unmapped += t.count; }
    }
    return { counts: counts, mapped: mapped, unmapped: unmapped, home: { lat: 45.815, lon: 15.9819 } };
  }
  function renderWorldMap() {
    buildWmShell();
    var date = currentDate(); _wmReqDate = date;
    if (DEMO) { paintWm(demoGeo()); return; }   // static build has no server -> fabricate from the demo events
    fetch("/geo?date=" + encodeURIComponent(date), { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (o) { if (_wmReqDate === date) paintWm(o || { counts: {}, mapped: 0, unmapped: 0 }); })
      .catch(function () { if (_wmReqDate === date) paintWm({ counts: {}, mapped: 0, unmapped: 0 }); });
  }
  // Keep the map current on live/new data like the dashboard does — but THROTTLED: the map is a /geo round-trip that
  // re-scans the (growing) day log, whereas the dashboard merges deltas client-side. No-op unless the map is shown.
  var _wmLast = 0, _wmTimer = null;
  function scheduleMapRefresh() {
    if (getView() !== "map" || getCollapsed()) return;
    var wait = 8000, now = +new Date(), since = now - _wmLast;
    if (since >= wait) { _wmLast = now; renderWorldMap(); }
    else if (!_wmTimer) _wmTimer = setTimeout(function () { _wmTimer = null; _wmLast = +new Date(); renderWorldMap(); }, wait - since);
  }
  // ---- mute the live new-threat beep (persisted) ----
  var _VOL_ON = '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M11 5 6 9H2v6h4l5 4z"/><path d="M15.5 8.5a5 5 0 0 1 0 7"/><path d="M19 5a9 9 0 0 1 0 14"/></svg>';
  var _VOL_OFF = '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M11 5 6 9H2v6h4l5 4z"/><line x1="22" y1="9" x2="16" y2="15"/><line x1="16" y1="9" x2="22" y2="15"/></svg>';
  function getMuted() { try { return localStorage.getItem("mt_mute") === "1"; } catch (e) { return false; } }
  function applyMuted(m) {
    var b = document.getElementById("mute_btn");
    if (b) { b.innerHTML = m ? _VOL_OFF : _VOL_ON; b.setAttribute("aria-pressed", m ? "true" : "false"); var lbl = (m ? "unmute" : "mute") + " new-threat beeps"; b.title = lbl; b.setAttribute("aria-label", lbl); }
  }
  function setMuted(m) { try { localStorage.setItem("mt_mute", m ? "1" : "0"); } catch (e) { } applyMuted(m); }
  function wire() {
    var _rows = document.getElementById('rows');
    if (_rows) _rows.addEventListener('contextmenu', function (e) {
      var tr = e.target.closest ? e.target.closest('tr') : null; if (!tr || tr.dataset.ri == null) return;
      var t = (state._pageRows || [])[+tr.dataset.ri]; if (!t) return;
      e.preventDefault(); openCtx(t, e.clientX, e.clientY);
    });
    document.addEventListener('click', function () { closeCtx(); closeDatePicker(); });   // datepop stops propagation on internal clicks, so this only fires for outside clicks
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') { closeCtx(); closeDrawer(); closeDatePicker(); } });
    window.addEventListener('scroll', function () { closeCtx(); closeDatePicker(); }, true);
    window.addEventListener('resize', function () { if (state._dpOpen) positionDatePop(); });
    if (_rows) _rows.addEventListener('click', function (e) {
      if (e.target.closest && e.target.closest('button, a, input, .ell, [data-f], [data-untag], .tx, .rowhide, .tagadd')) return;
      var tr = e.target.closest ? e.target.closest('tr') : null; if (!tr || tr.dataset.ri == null) return;
      var t = (state._pageRows || [])[+tr.dataset.ri]; if (t) openDrawer(t);
    });
    // hover an IP cell -> flag + country + ASN/holder + category tooltip (RIPE-enriched, lazy)
    if (_rows) {
      // ONE styled tooltip for all in-row hover info: IP cells (flag/country/ASN) + any [data-tip] (trail/info/ports/first-seen).
      // .ip wins over an ancestor [data-tip] so nested content shows the richer IP card, never a doubled native hint.
      var hoverSel = '.ip[data-ip], [data-tip]';
      _rows.addEventListener('mouseover', function (e) {
        if (!e.target.closest) return;
        var ipc = e.target.closest('.ip[data-ip]'), tc = e.target.closest('[data-tip]');
        var t = tipEl();
        if (ipc && (!tc || ipc.contains(tc))) { var ip = ipc.getAttribute('data-ip'); _tipIP = ip; if (isPubIP(ip)) { ripeGeo(ip); ripeAsn(ip); } t.innerHTML = ipTipHTML(ip); }
        else if (tc) { _tipIP = null; t.innerHTML = ellTipHTML(tc.getAttribute('data-tip')); }
        else return;
        t.style.display = 'block'; placeTip(e.clientX, e.clientY);
      });
      _rows.addEventListener('mousemove', function (e) {
        if (_tipEl && _tipEl.style.display !== 'none' && e.target.closest && e.target.closest(hoverSel)) placeTip(e.clientX, e.clientY);
      });
      _rows.addEventListener('mouseout', function (e) {
        var to = e.relatedTarget;
        if (!(to && to.closest && to.closest(hoverSel))) hideTip();
      });
    }
    var _scrim = document.getElementById('drawer_scrim'); if (_scrim) _scrim.addEventListener('click', closeDrawer);
    var _exp = document.getElementById('export_btn'); if (_exp) _exp.onclick = function (e) { e.stopPropagation(); openExportMenu(_exp); };
    var _vw = document.getElementById('views_btn'); if (_vw) _vw.onclick = function (e) { e.stopPropagation(); openViewsMenu(_vw); };
    var _lv = document.getElementById('live_btn'); if (_lv) _lv.onclick = function (e) { e.stopPropagation(); setLive(!state.live); };
    var _mt = document.getElementById('mute_btn'); if (_mt) _mt.onclick = function (e) { e.stopPropagation(); setMuted(!getMuted()); };
    var _qh = document.getElementById('qhelp'); if (_qh) _qh.onclick = function (e) { e.stopPropagation(); openQueryHelp(_qh); };
    var _nm = document.getElementById('nav_menu'); if (_nm) _nm.onclick = function (e) { e.stopPropagation(); if (_nm.getAttribute('aria-expanded') === 'true') closeCtx(); else openNavMenu(_nm); };
    var tt = document.getElementById("theme_toggle");
    if (tt) tt.onclick = function () { setTheme(getTheme() === "light" ? "dark" : "light"); };
    var _fzd = document.getElementById("fz_dec"); if (_fzd) _fzd.onclick = function () { setScale(getScaleIdx() - 1); };
    var _fzi = document.getElementById("fz_inc"); if (_fzi) _fzi.onclick = function () { setScale(getScaleIdx() + 1); };
    var _vt = document.getElementById("view_toggle"); if (_vt) _vt.onclick = toggleView;        // flip dashboard <-> attack map
    var _ct = document.getElementById("collapse_toggle"); if (_ct) _ct.onclick = toggleCollapsed;  // hide/show the whole block
    var f = document.getElementById("filter");
    if (f) {
      f.oninput = function () { state.input = f.value; state.page = 0; refresh(); };
      f.onkeydown = function (e) {
        if (e.key === "Enter" && f.value.trim()) { addFilter(f.value.trim()); f.value = ""; state.input = ""; refresh(); }
        else if (e.key === "Escape" && f.value) { e.preventDefault(); f.value = ""; state.input = ""; state.page = 0; refresh(); }
      };
    }
    var sclr = document.getElementById("search_clear");
    if (sclr) sclr.onclick = function () { var fi = document.getElementById("filter"); if (fi) { fi.value = ""; fi.focus(); } state.input = ""; state.page = 0; refresh(); };
    document.querySelectorAll("thead th[data-key]").forEach(function (th) {
      th.setAttribute("tabindex", "0"); th.setAttribute("role", "button");
      th.setAttribute("aria-label", "sort by " + (th.textContent || th.dataset.key).trim());
      function sortBy() {
        var k = th.dataset.key;
        if (state.sortKey === k) state.sortDir *= -1;
        else { state.sortKey = k; state.sortDir = (k === "sev" || k === "count" || k === "last" || k === "first") ? -1 : 1; }
        state.page = 0; refresh();
      }
      th.onclick = sortBy;
      th.onkeydown = function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); sortBy(); } };
    });
    var ss = document.getElementById("seg-size");
    if (ss) ss.querySelectorAll("button").forEach(function (b) {
      b.onclick = function () { state.limit = +b.dataset.size; state.page = 0; ss.querySelectorAll("button").forEach(function (x) { x.classList.remove("on"); }); b.classList.add("on"); savePrefs(); refresh(); };
    });
    var di = document.getElementById("date_input");
    if (di) {
      di.onchange = function () {
        // arrow-key nudging on the focused input still fires this; guard against an empty value just in case
        if (!di.value) { di.value = di.dataset.day || todayStr(); renderDateFace(); return; }
        di.dataset.day = di.value; renderDateFace(); navigate(di.value);
      };
      // click the readout -> our own themed calendar (not the OS popup, which renders a white box + a "Clear" on
      // some browsers). preventDefault + stopPropagation so the field doesn't open the native picker and the
      // outside-click closer doesn't immediately dismiss ours. Arrow keys still nudge the day natively.
      di.onclick = function (e) { e.preventDefault(); e.stopPropagation(); openDatePicker(); };
      di.onkeydown = function (e) {
        if (e.key === "Enter" || e.key === " " || (e.altKey && e.key === "ArrowDown")) { e.preventDefault(); openDatePicker(); }
      };
    }
    var pv = document.getElementById("prev_day"); if (pv) pv.onclick = function () { shiftDay(-1); };
    var nx = document.getElementById("next_day"); if (nx) nx.onclick = function () { shiftDay(1); };
    // keyboard nav (ignored while typing in a field):
    //   ←/→        previous/next TABLE PAGE (the frequent move)
    //   PageUp/Dn  previous/next DAY (real mode; the bigger jump)
    //   ↑/↓        move row selection   ·   Enter open drawer   ·   "/" focus search
    // focus trap: an open dialog (drawer / modal) has aria-modal="true"; keep Tab inside it (Esc + focus-restore already wired)
    document.addEventListener("keydown", function (e) {
      if (e.key !== "Tab") return;
      var dlg = null, ovs = document.querySelectorAll(".modal-overlay"); if (ovs.length) dlg = ovs[ovs.length - 1];   // topmost modal wins
      if (!dlg) { var dw = document.getElementById("drawer"); if (dw && dw.classList.contains("open")) dlg = dw; }
      if (!dlg) return;
      var nodes = dlg.querySelectorAll('a[href],button:not([disabled]),input:not([disabled]),textarea:not([disabled]),select:not([disabled]),[tabindex]:not([tabindex="-1"])'), f = [];
      for (var i = 0; i < nodes.length; i++) if (nodes[i].getClientRects().length) f.push(nodes[i]);
      if (!f.length) return;
      var first = f[0], last = f[f.length - 1], ae = document.activeElement;
      if (f.indexOf(ae) < 0) { e.preventDefault(); first.focus(); }                       // focus escaped the dialog -> pull back in
      else if (e.shiftKey && ae === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && ae === last) { e.preventDefault(); first.focus(); }
    });
    document.addEventListener("keydown", function (e) {
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      var ae = document.activeElement, tag = ae && ae.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || (ae && ae.isContentEditable)) return;
      if (e.key === "ArrowLeft") { e.preventDefault(); if (state.page > 0) gotoPage(state.page - 1); }
      else if (e.key === "ArrowRight") { e.preventDefault(); gotoPage(state.page + 1); }   // refresh() clamps to the last page
      else if (e.key === "PageUp") { if (!DEMO) { e.preventDefault(); shiftDay(-1); } }
      else if (e.key === "PageDown") { if (!DEMO) { e.preventDefault(); shiftDay(1); } }
      else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        var rows = state._pageRows || []; if (!rows.length) return; e.preventDefault();
        state.selIdx = e.key === "ArrowDown" ? Math.min(rows.length - 1, state.selIdx + 1) : Math.max(0, state.selIdx - 1);
        highlightSel();
      } else if (e.key === "Enter") {
        var r = (state._pageRows || [])[state.selIdx]; if (r) { e.preventDefault(); openDrawer(r); }   // match mouse-click affordance
      } else if (e.key === "/") {
        var fi = document.getElementById("filter"); if (fi) { e.preventDefault(); fi.focus(); }
      } else if (e.key === "?") {   // Shift+/ -> keyboard shortcuts overlay
        e.preventDefault(); openShortcuts();
      }
    });
    var _sc = document.getElementById("shortcuts_link"); if (_sc) _sc.onclick = function (e) { e.preventDefault(); openShortcuts(); };
  }
  function openShortcuts() {
    if (document.getElementById("kbd_overlay")) return;
    var KEYS = [
      ["←  →", "previous / next page"],
      ["Page Up / Down", "previous / next day"],
      ["↑  ↓", "select a row"],
      ["Enter", "open selected threat"],
      ["/", "focus search"],
      ["?", "this shortcut list"],
      ["Esc", "close panel / clear search"]
    ];
    var rows = KEYS.map(function (k) {
      var keys = k[0].split(/\s+/).map(function (kk) { return '<kbd>' + esc(kk) + '</kbd>'; }).join(" ");
      return '<div class="kbd-row"><span class="kbd-keys">' + keys + '</span><span class="kbd-desc">' + esc(k[1]) + '</span></div>';
    }).join("");
    var o = document.createElement("div"); o.id = "kbd_overlay"; o.className = "modal-overlay";
    o.innerHTML = '<div class="modal kbd-modal" role="dialog" aria-label="keyboard shortcuts" aria-modal="true">' +
      '<div class="modal-h">Keyboard shortcuts</div><div class="kbd-list">' + rows + '</div>' +
      '<div class="modal-actions"><button class="btn-primary" id="kbd_close">Got it</button></div></div>';
    document.body.appendChild(o);
    var ret = document.activeElement;
    function close() { o.remove(); if (ret && ret.focus) { try { ret.focus(); } catch (e) {} } }
    o.onclick = function (e) { if (e.target === o) close(); };
    var btn = o.querySelector("#kbd_close"); btn.focus();
    btn.onclick = close;
    o.onkeydown = function (e) { if (e.key === "Escape") { e.preventDefault(); close(); } };
  }
  // reflect the current view in the URL (shareable/bookmarkable; replaceState => no history spam, no hashchange listener => no loops)
  function syncHash() {
    var p = [];
    if (state.filters.length) p.push('filter=' + encodeURIComponent(state.filters.join(',')));
    if (state.input.trim()) p.push('q=' + encodeURIComponent(state.input.trim()));
    if (state.sev != null) p.push('sev=' + state.sev);
    if (state.sortKey !== 'sev') p.push('sort=' + encodeURIComponent(state.sortKey));
    if (state.sortDir > 0) p.push('dir=asc');
    if (state.limit !== 25) p.push('limit=' + state.limit);
    if (state.page > 0) p.push('page=' + (state.page + 1));
    if (state._openChart) p.push('chart=' + encodeURIComponent(state._openChart));
    var h = p.join('&');
    try { history.replaceState(null, '', h ? ('#' + h) : (location.pathname + location.search)); }
    catch (e) { try { if (h) location.hash = h; } catch (e2) { } }
  }
  function parseHash() {
    var h = location.hash.replace(/^#/, ""); if (!h) return;
    h.split("&").forEach(function (p) {
      var kv = p.split("="), k, v;
      try { k = decodeURIComponent(kv[0] || ""); v = decodeURIComponent(kv[1] || ""); }
      catch (e) { return; }   // a malformed %-escape (e.g. "#q=%") makes decodeURIComponent throw URIError; unguarded it propagates out of parseHash() and aborts boot() before wire()/applyPrefsUI() -> dead UI from a crafted/shared link. Skip just the bad pair.
      if (k === "filter" && v) v.split(",").forEach(function (x) { if (x) state.filters.push(x.toLowerCase()); });
      else if (k === "sort" && v) state.sortKey = v;
      else if (k === "dir" && v) state.sortDir = v === "asc" ? 1 : -1;
      else if (k === "limit" && v) state.limit = +v || 25;
      else if (k === "chart" && v) state._openChart = v;
      else if (k === "sev" && v) state.sev = (v === "1" || v === "2" || v === "3") ? +v : null;
      else if (k === "q" && v) state.input = v;
      else if (k === "page" && v) state.page = Math.max(0, (+v || 1) - 1);
    });
  }
  // DEMO when demo.js is present (file://, the github.io demo, the published artifact). The real server strips the
  // demo.js <script>, so getDemoCSV is undefined there -> live /events path.
  var DEMO = (typeof window.getDemoCSV === "function");
  function pad2(n) { return (n < 10 ? "0" : "") + n; }
  function todayStr() { var d = new Date(); return d.getFullYear() + "-" + pad2(d.getMonth() + 1) + "-" + pad2(d.getDate()); }
  function currentDate() { var d = document.getElementById("date_input"); return d && d.value ? d.value : todayStr(); }
  var MON_ABBR = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"];
  // keep the condensed two-row readout (MON DD / YYYY) in sync with the hidden native date input
  function renderDateFace() {
    var m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(currentDate()); if (!m) return;
    var top = document.getElementById("df_top"), bot = document.getElementById("df_bot");
    if (top) top.textContent = MON_ABBR[(+m[2] - 1) % 12] + " " + m[3];
    if (bot) bot.textContent = m[1];
  }
  function setDate(s) { var d = document.getElementById("date_input"); if (d) { d.value = s; d.dataset.day = s; } renderDateFace(); }

  // ---- day picker: a cal-heatmap–style event-density grid (GitHub-contributions look), rendered natively (no d3) ----
  // Shows the last few months as a grid of day-squares colored by that day's event volume (from /counts): an empty
  // day is a flat cell, a flooded day a bright one, so you see WHERE the noise was and click straight to it. Also
  // replaces the native OS date popup (white box + confusing "Clear" on some browsers).
  var MON_SHORT = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  var _counts = {};          // "YYYY-MM-DD" -> approx events that day
  var _countsSpans = {};     // "from..to" -> true, so each visible span is fetched at most once
  var HM_MONTHS = 4;         // months shown side by side
  function fmtYMD(d) { return d.getFullYear() + "-" + pad2(d.getMonth() + 1) + "-" + pad2(d.getDate()); }
  function heatBucket(n) { return !n ? 0 : n < 500 ? 1 : n < 1000 ? 2 : n < 5000 ? 3 : n < 10000 ? 4 : 5; }   // cal-heatmap-style thresholds
  function fetchCounts(fromStr, toStr) {
    if (DEMO) {   // no server -> fabricate deterministic per-day density across the visible span (some quiet days)
      var d = new Date(fromStr + "T00:00:00"), end = new Date(toStr + "T00:00:00");
      while (d <= end) { var ds = fmtYMD(d); if (!(ds in _counts)) { var hh = murmur3(ds, 7) >>> 0; _counts[ds] = (hh % 6 === 0) ? 0 : Math.floor(Math.pow(10, (hh % 1000) / 1000 * 4.3)); } d.setDate(d.getDate() + 1); }
      return;
    }
    var key = fromStr + ".." + toStr; if (_countsSpans[key]) return; _countsSpans[key] = true;
    fetch("/counts?from=" + fromStr + "&to=" + toStr, { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (o) { if (!o) return; for (var k in o) _counts[k] = o[k]; if (state._dpOpen) buildHeatmap(); })   // repaint once densities arrive
      .catch(function () { _countsSpans[key] = false; });   // let a transient failure retry on next open
  }
  function ensureDatePop() {
    var pop = document.getElementById("datepop"); if (pop) return pop;
    pop = document.createElement("div");
    pop.id = "datepop"; pop.className = "datepop"; pop.hidden = true;
    pop.setAttribute("role", "dialog"); pop.setAttribute("aria-label", "pick a day");
    var leg = ""; for (var q = 0; q <= 5; q++) leg += '<i class="ch-q' + q + '"></i>';
    pop.innerHTML =
      '<div class="dp-head"><button class="dp-nav" type="button" data-d="-1" aria-label="earlier months">‹</button>' +
      '<span class="dp-title"></span>' +
      '<button class="dp-nav" type="button" data-d="1" aria-label="later months">›</button></div>' +
      '<div class="ch-months"></div>' +
      '<div class="dp-foot"><span>fewer</span><span class="ch-legend">' + leg + '</span><span>more events</span></div>';
    document.body.appendChild(pop);
    pop.addEventListener("click", function (e) { e.stopPropagation(); });   // internal clicks never reach the outside-close handler
    pop.querySelectorAll(".dp-nav").forEach(function (b) { b.onclick = function () { shiftMonths(+b.dataset.d); }; });
    pop.addEventListener("keydown", function (e) { if (e.key === "Escape") { closeDatePicker(); var a = document.getElementById("date_input"); if (a) a.focus(); } });
    return pop;
  }
  function monthGrid(y, m, todayS, sel) {   // one month: 7 weekday rows × week columns of day-squares (Monday-start)
    var wrap = document.createElement("div"); wrap.className = "ch-month";
    var grid = document.createElement("div"); grid.className = "ch-grid";
    var lead = (new Date(y, m, 1).getDay() + 6) % 7, i;   // blank cells before the 1st so weekdays line up in rows
    for (i = 0; i < lead; i++) { var pad = document.createElement("span"); pad.className = "ch-d ch-pad"; grid.appendChild(pad); }
    var days = new Date(y, m + 1, 0).getDate();
    for (i = 1; i <= days; i++) {
      var ds = fmtYMD(new Date(y, m, i)), future = ds > todayS, n = future ? 0 : (_counts[ds] || 0);
      var c = document.createElement("span");
      c.className = "ch-d ch-q" + heatBucket(n) + (future ? " ch-fut" : "") + (ds === sel ? " ch-sel" : "");
      c.dataset.date = ds;
      c.title = MON_SHORT[m] + " " + i + " " + y + (future ? "" : " · " + (n ? (n >= 100 ? "≈ " : "") + fmtN(n) + " events" : "no events"));
      if (!future) c.onclick = function () { pickDay(this.dataset.date); };
      grid.appendChild(c);
    }
    wrap.appendChild(grid);
    var lab = document.createElement("div"); lab.className = "ch-mlabel"; lab.textContent = MON_SHORT[m] + " '" + ("" + y).slice(2);
    wrap.appendChild(lab);
    return wrap;
  }
  function buildHeatmap() {
    var pop = ensureDatePop();
    var t = new Date(); t.setHours(0, 0, 0, 0);
    var todayS = fmtYMD(t), sel = currentDate();
    var months = [], yy = state._dpY, mm = state._dpM, k;   // window ENDS at (_dpY,_dpM); walk HM_MONTHS back
    for (k = 0; k < HM_MONTHS; k++) { months.unshift([yy, mm]); mm--; if (mm < 0) { mm = 11; yy--; } }
    var a = months[0], b = months[HM_MONTHS - 1];
    pop.querySelector(".dp-title").textContent = MON_SHORT[a[1]] + " – " + MON_SHORT[b[1]] + " " + b[0];
    pop.querySelector('.dp-nav[data-d="1"]').disabled = (state._dpY > t.getFullYear()) || (state._dpY === t.getFullYear() && state._dpM >= t.getMonth());   // window can't end past this month
    fetchCounts(fmtYMD(new Date(a[0], a[1], 1)), fmtYMD(new Date(b[0], b[1] + 1, 0)));   // one request spans all visible months
    var host = pop.querySelector(".ch-months"); host.innerHTML = "";
    months.forEach(function (ym) { host.appendChild(monthGrid(ym[0], ym[1], todayS, sel)); });
  }
  function positionDatePop() {
    var pop = document.getElementById("datepop"), anchor = document.getElementById("dateface"); if (!pop || !anchor) return;
    var r = anchor.getBoundingClientRect(), pw = pop.offsetWidth || 420, ph = pop.offsetHeight || 200;
    pop.style.left = Math.max(8, Math.min(r.left, window.innerWidth - pw - 8)) + "px";
    var top = r.bottom + 6; if (top + ph > window.innerHeight - 8) top = Math.max(8, r.top - ph - 6);   // flip above if it would overflow the viewport
    pop.style.top = top + "px";
  }
  function openDatePicker() {
    var di = document.getElementById("date_input"); if (di && di.disabled && !DEMO) return;   // offline -> navigation unavailable
    closeCtx();
    var m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(currentDate()), now = new Date(), t = new Date();
    state._dpOpen = true;
    state._dpY = m ? +m[1] : now.getFullYear();
    state._dpM = m ? (+m[2] - 1) : now.getMonth();   // 0-based; window ends at the selected day's month
    if (state._dpY > t.getFullYear() || (state._dpY === t.getFullYear() && state._dpM > t.getMonth())) { state._dpY = t.getFullYear(); state._dpM = t.getMonth(); }
    buildHeatmap();
    var pop = document.getElementById("datepop"); pop.hidden = false; positionDatePop();
  }
  function closeDatePicker() { var pop = document.getElementById("datepop"); if (pop && !pop.hidden) { pop.hidden = true; state._dpOpen = false; } }
  function shiftMonths(delta) {
    var t = new Date(), y = state._dpY, m = state._dpM + delta;
    while (m < 0) { m += 12; y--; } while (m > 11) { m -= 12; y++; }
    if (y > t.getFullYear() || (y === t.getFullYear() && m > t.getMonth())) return;   // window can't end past the current month
    state._dpY = y; state._dpM = m; buildHeatmap(); positionDatePop();
  }
  function pickDay(ds) {
    var di = document.getElementById("date_input"); if (di && di.disabled && !DEMO) return;
    setDate(ds); closeDatePicker(); navigate(ds); if (di) di.focus();
  }
  // The demo's fixed 2024-01-11 timestamps are rebased to TODAY so the calendar and the "x ago" column agree
  // (otherwise the picker shows 2024 while rows claim "5m ago"). Single-day data; date appears only in the leading ts.
  var _demoCSVc;
  function demoCSV() { return _demoCSVc || (_demoCSVc = ("" + window.getDemoCSV()).replace(/"2024-01-11 /g, '"' + todayStr() + ' ')); }
  function navigate(date) {
    if (getView() === "map" && !getCollapsed()) renderWorldMap();   // keep the attack map on the viewed day
    if (DEMO) { render(aggregate(demoCSV())); return; }
    if (state.live) { stopLive(); }   // tear down the stream for the old day
    loadEvents(date);
    if (state.live) { state._sseOk = false; openSSE(date); }   // and re-open it for the new day
  }
  function shiftDay(delta) {
    var dt = new Date(currentDate() + "T00:00:00"); dt.setDate(dt.getDate() + delta);
    var ns = dt.getFullYear() + "-" + pad2(dt.getMonth() + 1) + "-" + pad2(dt.getDate());
    setDate(ns); navigate(ns);
  }

  function render(d) {
    state.all = d.threats; state.agg = d;
    if (DEMO) { var mx = 0; for (var di = 0; di < d.threats.length; di++) { var p = parseTs(d.threats[di].last); if (p > mx) mx = p; } state._demoNow = mx || null; }   // anchor demo "now" to its latest event so relative times demo correctly
    if (!state.streaming) {   // new-threat detection only on a COMPLETE load (not progressive partials)
      var newOnes = [];
      if (state._seenInit) { for (var qi = 0; qi < d.threats.length; qi++) if (!state.knownUids[d.threats[qi].uidc]) newOnes.push(d.threats[qi]); }
      for (var qj = 0; qj < d.threats.length; qj++) state.knownUids[d.threats[qj].uidc] = 1;
      state._seenInit = true;
      state.newUids = {}; for (var qk = 0; qk < newOnes.length; qk++) state.newUids[newOnes[qk].uidc] = 1;
      state.newCount += newOnes.length;
      var newHigh = newOnes.filter(function (t) { return t.sev === 3; });
      if (state.live && newHigh.length) alertNew(newHigh);
    }
    state._statsSig = null; refresh();   // refresh() owns stats rendering now (full or filtered); null forces a redraw on new data
    state.newUids = {};   // flash is one-time; the 'N new' pill (newCount) persists until cleared
    if (!state._intro) {   // one orchestrated reveal on first paint; removed so later renders/refreshes don't replay
      state._intro = true;
      var st = document.getElementById("stats"), gw = document.querySelector(".grid-wrap");
      if (st) st.classList.add("intro"); if (gw) gw.classList.add("intro");
      setTimeout(function () { if (st) st.classList.remove("intro"); if (gw) gw.classList.remove("intro"); }, 1000);
    }
    if (state._openChart) showChart(state._openChart);
    scheduleMapRefresh();   // attack map follows live/new data too (throttled; no-op unless the map view is open)
    window.__MT = d;
  }
  function setStatus(msg) {
    var tb = document.getElementById("rows");
    if (tb) tb.innerHTML = '<tr><td colspan="12" style="padding:48px;text-align:center;color:var(--muted);font-family:var(--mono)">' + esc(msg) + '</td></tr>';
  }
  // Connectivity → enables/disables Live + the day calendar. A DEMO build (demo.js present → opened via file://
  // or hosted statically) has NO backend at all, so Live can never stream and the day calendar can never load
  // another day: hard-disable both regardless of navigator.onLine (Firefox reports onLine=true for file:// when
  // the machine has internet, even though there is no server). In a real (server-served) build demo.js is stripped,
  // so the authoritative signal is whether a server fetch SUCCEEDED (covers air-gapped installs: server reachable
  // with no internet); fall back to navigator.onLine only until the first fetch result arrives.
  function setConnected(ok) { state._serverReachable = !!ok; applyConn(); }   // called from fetch success/failure
  function applyConn() {
    var ok = DEMO ? false                                    // static/demo build -> no server -> Live + calendar off
           : state._serverReachable === true ? true
           : state._serverReachable === false ? false
           : (navigator.onLine !== false);   // unknown (no fetch yet) -> trust the browser's online flag
    if (state._connected === ok) return;
    state._connected = ok;
    var lb = document.getElementById("live_btn");
    if (lb) { lb.disabled = !ok; lb.title = ok ? "live auto-refresh + alerts on new high-severity" : "offline / server unreachable — live unavailable"; }
    ["prev_day", "next_day", "date_input"].forEach(function (id) { var e = document.getElementById(id); if (e) e.disabled = !ok; });
    document.body.classList.toggle("offline", !ok);
    if (!ok && state.live) setLive(false);   // stop a running live stream when we go offline
  }
  function checkAuth() {
    fetch("/whoami", { credentials: "same-origin" })
      .then(function (r) { return r.status === 200 ? r.text() : ""; })
      .then(function (u) {
        var link = document.getElementById("login_link"); if (!link) return;
        if (u && u !== "?") { link.textContent = "Log out (" + u + ")"; link.onclick = function () { location.href = "logout"; }; }
        else if (u === "?") { link.style.display = "none"; }              // no auth configured
        else { link.textContent = "Log in"; link.onclick = showLogin; }   // anonymous, auth required
      }).catch(function () { });
  }

  // ---- SHA-256 (compact, UTF-8-safe, sync; works on plain http where SubtleCrypto's secure-context rule blocks) ----
  function sha256hex(str) {
    function rr(v, a) { return (v >>> a) | (v << (32 - a)); }
    var mp = Math.pow, mw = mp(2, 32), res = "", words = [], hash = [], k = [], pc = 0, comp = {},
        ascii = unescape(encodeURIComponent(str)), bitLen = ascii.length * 8;
    for (var c = 2; pc < 64; c++) { if (!comp[c]) { for (var i = 0; i < 313; i += c) comp[i] = c; hash[pc] = (mp(c, .5) * mw) | 0; k[pc++] = (mp(c, 1 / 3) * mw) | 0; } }
    ascii += "\x80"; while (ascii.length % 64 - 56) ascii += "\x00";
    for (var i = 0; i < ascii.length; i++) { var j = ascii.charCodeAt(i); if (j >> 8) return ""; words[i >> 2] |= j << ((3 - i) % 4) * 8; }
    words[words.length] = ((bitLen / mw) | 0); words[words.length] = (bitLen);
    for (var jj = 0; jj < words.length;) {
      var w = words.slice(jj, jj += 16), oh = hash; hash = hash.slice(0, 8);
      for (var i = 0; i < 64; i++) {
        var w15 = w[i - 15], w2 = w[i - 2], a = hash[0], e = hash[4];
        var t1 = hash[7] + (rr(e, 6) ^ rr(e, 11) ^ rr(e, 25)) + ((e & hash[5]) ^ ((~e) & hash[6])) + k[i] +
          (w[i] = (i < 16) ? w[i] : (w[i - 16] + (rr(w15, 7) ^ rr(w15, 18) ^ (w15 >>> 3)) + w[i - 7] + (rr(w2, 17) ^ rr(w2, 19) ^ (w2 >>> 10))) | 0);
        var t2 = (rr(a, 2) ^ rr(a, 13) ^ rr(a, 22)) + ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));
        hash = [(t1 + t2) | 0].concat(hash); hash[4] = (hash[4] + t1) | 0;
      }
      for (var i = 0; i < 8; i++) hash[i] = (hash[i] + oh[i]) | 0;
    }
    for (var i = 0; i < 8; i++) for (var j = 3; j + 1; j--) { var b = (hash[i] >> (j * 8)) & 255; res += ((b < 16) ? 0 : "") + b.toString(16); }
    return res;
  }
  function nonceStr(n) { var a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", s = ""; for (var i = 0; i < n; i++) s += a[(Math.random() * a.length) | 0]; return s; }

  function showLogin() {
    if (document.getElementById("login_overlay")) return;
    var o = document.createElement("div"); o.id = "login_overlay"; o.className = "modal-overlay";
    o.innerHTML = '<div class="modal"><div class="modal-h">Sign in to Maltrail</div>' +
      '<label for="li_user">Username</label><input id="li_user" autocomplete="username">' +
      '<label for="li_pass">Password</label><input id="li_pass" type="password" autocomplete="current-password">' +
      '<div id="li_err" class="modal-err"></div>' +
      '<div class="modal-actions"><button class="btn-ghost" id="li_cancel">Cancel</button><button class="btn-primary" id="li_go">Sign in</button></div></div>';
    document.body.appendChild(o);
    var pass = o.querySelector("#li_pass"), go = o.querySelector("#li_go"), err = o.querySelector("#li_err");
    o.querySelector("#li_cancel").onclick = function () { o.remove(); };
    o.onclick = function (e) { if (e.target === o) o.remove(); };
    function submit() {
      var u = o.querySelector("#li_user").value, p = pass.value;
      if (!u || !p) { err.textContent = "Enter username and password."; return; }
      var nc = nonceStr(12), h = sha256hex(sha256hex(p) + nc);
      go.disabled = true; err.textContent = "";
      fetch("/login", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: "username=" + encodeURIComponent(u) + "&hash=" + h + "&nonce=" + nc })
        .then(function (r) {
          if (r.status === 200) location.href = "/";
          else if (r.status === 401) { err.textContent = "Wrong username and/or password."; go.disabled = false; }
          else { err.textContent = "Login failed (HTTP " + r.status + ")."; go.disabled = false; }
        }).catch(function () { err.textContent = "Network connection issue."; go.disabled = false; });
    }
    go.onclick = submit; pass.onkeydown = function (e) { if (e.key === "Enter") submit(); };
    o.querySelector("#li_user").focus();
  }
  // Progressive load: stream /events and fold each chunk INCREMENTALLY into a running aggregate (mergeRows),
  // so a 100MB/850k-row day is O(n) total — NOT O(n²) (the old code re-aggregated all rows every chunk) —
  // and memory stays bounded (we never retain the full parsed-rows array, only the aggregate).
  var RENDER_EVERY = 12000; // rows between progressive repaints
  function parseRows(text) { return text ? window.Papa.parse(text, { delimiter: " ", skipEmptyLines: true }).data : []; }
  function loadEvents(date) {
    setStatus("loading events…");
    var seq = ++state._loadSeq;
    fetch("/events?date=" + encodeURIComponent(date), { credentials: "same-origin" })
      .then(function (r) {
        setConnected(true);                                          // server responded -> reachable
        if (seq !== state._loadSeq) return;                         // superseded by a newer navigation
        if (r.status === 401) { setStatus("authentication required — log in to view events"); showLogin(); return; }
        if (!r.ok) { setStatus("could not load events (HTTP " + r.status + ")"); return; }
        if (!r.body || !r.body.getReader) {                         // no streaming support -> one-shot
          return r.text().then(function (t) {
            if (seq !== state._loadSeq) return;
            var rows = window.Papa.parse(t, { delimiter: " ", skipEmptyLines: true }).data;
            state._liveBytes = byteLenFull(t, r); state._liveDate = date;   // byte baseline for incremental live
            render(aggregateRows(rows));   // agg retains _byKey so live deltas merge incrementally (rows array is freed)
          });
        }
        var reader = r.body.getReader(), dec = new TextDecoder(), buf = "", agg = null, seen = 0, lastRender = 0, bytes = 0;
        state.streaming = true;
        function pump() {
          return reader.read().then(function (res) {
            if (seq !== state._loadSeq) { try { reader.cancel(); } catch (e) { } return; }
            if (res.done) {
              buf += dec.decode();
              state.streaming = false;
              // maltrail always terminates event lines with "\n", so a non-empty `buf` here is an
              // INCOMPLETE final line (EOF caught mid-append). Do NOT parse it and do NOT count it in
              // the live baseline: otherwise _liveBytes jumps past a half-written line and its
              // completion is never re-read on the next tick (a silently lost/corrupted live event).
              var tail = 0; try { tail = new TextEncoder().encode(buf).length; } catch (e) { tail = buf.length; }
              state._liveBytes = bytes - tail; state._liveDate = date;   // baseline = end of last COMPLETE line
              render(agg || aggregateRows([]));
              return;
            }
            bytes += res.value.byteLength;                          // raw bytes, matches the server's file offsets
            buf += dec.decode(res.value, { stream: true });
            var nl = buf.lastIndexOf("\n");
            if (nl >= 0) {
              var chunk = parseRows(buf.slice(0, nl)); buf = buf.slice(nl + 1);
              if (chunk.length) { agg = mergeRows(agg, chunk); seen += chunk.length; }   // fold chunk in; chunk array is then freed (bounded memory)
            }
            if (agg && seen - lastRender >= RENDER_EVERY) { lastRender = seen; render(agg); }
            return pump();
          });
        }
        return pump();
      })
      .catch(function () { state.streaming = false; setConnected(false); setStatus("no connection to the server"); });
  }
  function byteLenFull(text, r) {
    var cl = r.headers && r.headers.get && r.headers.get("Content-Length");
    if (cl != null && cl !== "") { var n = parseInt(cl, 10); if (!isNaN(n)) return n; }
    try { return new TextEncoder().encode(text).length; } catch (e) { return text.length; }
  }
  // incremental live update: fetch ONLY the bytes appended since the last load (HTTP Range),
  // merge them into the retained row set, and re-aggregate in memory — never re-downloads the whole log.
  function liveTick(date) {
    if (DEMO) { render(aggregate(demoCSV())); return; }   // demo has no server; just repaint
    // need a byte baseline + a mergeable aggregate for THIS date; otherwise fall back to a normal full load
    if (state._liveBytes == null || state._liveBytes < 0 || state._liveDate !== date || !state.agg || !state.agg._byKey) { loadEvents(date); return; }
    var start = state._liveBytes, seq = ++state._loadSeq;
    fetch("/events?date=" + encodeURIComponent(date), { credentials: "same-origin", headers: { "Range": "bytes=" + start + "-" + LIVE_MAX_END } })
      .then(function (r) {
        setConnected(true);
        if (seq !== state._loadSeq) return;
        if (r.status === 401) { setStatus("authentication required — log in to view events"); showLogin(); return; }
        if (r.status === 416) { state._liveBytes = -1; loadEvents(date); return; }   // range past EOF => log rotated/shrank => rebuild
        if (r.status === 200) {                                                       // server ignored Range (e.g. filtered session) => full reload
          return r.text().then(function (t) {
            if (seq !== state._loadSeq) return;
            var rows = window.Papa.parse(t, { delimiter: " ", skipEmptyLines: true }).data;
            state._liveBytes = byteLenFull(t, r); state._liveDate = date;
            render(aggregateRows(rows));
          });
        }
        if (r.status !== 206) { if (!r.ok) setStatus("live update failed (HTTP " + r.status + ")"); return; }
        return r.arrayBuffer().then(function (ab) {                                    // raw bytes => exact offset accounting
          if (seq !== state._loadSeq) return;
          if (ab.byteLength > 0) {
            var u8 = new Uint8Array(ab), nl = -1, i;
            for (i = u8.length - 1; i >= 0; i--) { if (u8[i] === 10) { nl = i; break; } }   // last '\n' in the raw delta
            if (nl >= 0) {                                                              // consume ONLY complete lines
              var rows = window.Papa.parse(new TextDecoder().decode(ab.slice(0, nl + 1)), { delimiter: " ", skipEmptyLines: true }).data;
              state._liveBytes = start + nl + 1; state._liveDate = date;                // advance past complete lines only; a partial tail is re-fetched next tick (no dropped/split event)
              render(mergeRows(state.agg, rows));                                        // O(new rows) merge — no full re-parse/re-aggregate
            }
            // else: only a partial line appended so far => consume nothing, retry from `start` next tick
          }
          // empty delta => nothing changed; leave the table untouched (never overwrite it with a status line)
        });
      })
      .catch(function () { setConnected(false); /* transient live poll failure: keep showing current data, try again next tick */ });
  }
  // persist view preferences (page size) across reloads
  function savePrefs() { lsSet('mt_prefs', { limit: state.limit }); }
  function loadPrefs() {
    var p = lsGet('mt_prefs', null); if (!p || typeof p !== 'object') return;
    if ([25, 50, 100].indexOf(p.limit) >= 0) state.limit = p.limit;
  }
  function applyPrefsUI() {
    var ss = document.getElementById('seg-size'); if (ss) ss.querySelectorAll('button').forEach(function (b) { b.classList.toggle('on', +b.dataset.size === state.limit); });
  }
  function boot() {
    // <!LOGO!> is server-substituted to the maltrail logo (or config.HEADER_LOGO). When unsubstituted
    // (demo / file:// / artifact — no server), the token becomes a bogus comment -> inject the default logo.
    var _bl = document.querySelector(".brandlogo"); if (_bl && !_bl.querySelector("img")) _bl.innerHTML = '<img src="images/mlogo.png" alt="" style="width:24px">altrail';
    loadPrefs(); applyTheme(getTheme()); applyScale(getScaleIdx()); applyView(); applyMuted(getMuted()); migrateLegacy(); parseHash(); wire(); applyPrefsUI();
    setInterval(refreshRelTimes, 30000);   // keep "Xm ago" labels current between renders
    window.addEventListener("online", applyConn); window.addEventListener("offline", applyConn);
    applyConn();   // initial: an offline-opened page starts with Live + calendar disabled
    var _fi = document.getElementById('filter'); if (_fi && state.input) _fi.value = state.input;
    var ve = document.querySelector(".ver"); if (ve && DEMO) ve.textContent = "redesign prototype";  // real server fills <!VERSION!>
    if (DEMO) {
      document.title = "Maltrail (demo)";
      setDate(todayStr());   // controls stay live so the calendar/paging are demonstrably interactive
      render(aggregate(demoCSV()));
      if (getView() === "map" && !getCollapsed()) renderWorldMap();   // demo loaded straight into map view: state.agg is ready now
    } else {
      setDate(todayStr());
      checkAuth();
      loadEvents(todayStr());
      // ?refresh=N -> auto-reload the current day's events every N seconds (min 5; keeps filters/sort/hidden/tags)
      var rm = location.search.match(/[?&]refresh=(\d+)/);
      if (rm) { var n = Math.max(5, parseInt(rm[1], 10) || 0); if (n) setInterval(function () { liveTick(currentDate()); }, n * 1000); }
    }
    if (location.hash.indexOf("login") >= 0) showLogin();   // test/deep-link hook
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();
