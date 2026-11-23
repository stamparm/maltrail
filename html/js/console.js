/*
* Copyright (c) 2014-present Maltrail developers (https://github.com/stamparm/maltrail/)
* See the file 'LICENSE' for copying permission
*/

// The event console: `tail -f <day>.log | grep <words>`, in the page, for watching what arrives.
//
// A window onto the END of the log, never the whole day. The server sends at most TAIL lines
// (/tail, which also applies the session's scope and custom-trail masking before the grep), and
// this view keeps at most MAX, dropping the oldest. Memory is therefore the same for a 1k-event
// day and an 850k one - the reason the dashboard condenses events is not a reason this can't exist.
//
// Every field of an event is attacker-influenced (DNS names, URLs, user agents). It reaches the
// DOM through textContent only - no markup is ever built from a line.
(function () {
  "use strict";
  var UI = window.MT_UI, E = window.MT_ENGINE;
  if (!UI || !E) return;

  var MAX = 2000, POLL_MS = 1500, FOLLOW_SLACK = 40, DEMO_MS = 650, NS = [100, 500, 1000, 2000];
  var st = { n: 1000, on: false, date: null, q: "", offset: null, seq: 0, timer: 0, paused: false, follow: true, unseen: 0, total: null, demo: null, demoI: 0 };
  var el = {};

  function $(id) { return document.getElementById(id); }
  function fmt(n) { return (+n || 0).toLocaleString("en-US"); }
  function lastDay(d) { var m = /_(\d{4}-\d{2}-\d{2})$/.exec(d || ""); return m ? m[1] : d; }
  function live() { return !UI.DEMO && lastDay(st.date) === UI.todayStr(); }
  function words() { return st.q.toLowerCase().split(/\s+/).filter(Boolean).slice(0, 8); }
  // the server's grep, for the demo (which has no server): every word present, "-word" absent
  function matches(line, ws) {
    var low = line.toLowerCase();
    for (var i = 0; i < ws.length; i++) {
      var w = ws[i];
      if (w.charAt(0) === "-" && w.length > 1) { if (low.indexOf(w.slice(1)) >= 0) return false; }
      else if (low.indexOf(w) < 0) return false;
    }
    return true;
  }
  // "18558,18562,18563,..." -> "18558 +124": a port or address list is one field, and can be hundreds long
  function short(v) { var i = v.indexOf(","); return i < 0 ? v : v.slice(0, i) + " +" + (v.split(",").length - 1); }
  function infoClass(info) { var m = /\((malware|suspicious|malicious)\)/.exec(info); return m ? " i-" + m[1] : ""; }

  function span(parent, cls, text, title) {
    var s = document.createElement("span"); s.className = cls; s.textContent = text;
    if (title) s.title = title;
    parent.appendChild(s); return s;
  }
  function lineEl(row) {
    var d = document.createElement("div");
    if (!row || row.length < 11 || !/^[A-Z0-9]+$/.test(row[7])) {   // not an event line: shown as it is
      d.className = "cl raw"; d.textContent = row ? row.join(" ") : ""; return d;
    }
    d.className = "cl s" + E.severityOf(row[9], row[10]);
    d._row = row;
    span(d, "c-t", ("" + row[0]).substr(11, 8), row[0]);
    span(d, "c-sn", row[1], row[1]);
    span(d, "c-ip c-q", short(row[2]), row[2]).dataset.q = row[2].split(",")[0];
    span(d, "c-pt", short(row[3]), row[3].indexOf(",") > 0 ? row[3] : "");
    span(d, "c-ip c-q", short(row[4]), row[4]).dataset.q = row[4].split(",")[0];
    span(d, "c-pt", short(row[5]), row[5].indexOf(",") > 0 ? row[5] : "");
    span(d, "c-pr", row[6]);
    span(d, "c-ty", row[7]).style.background = UI.TYPE_COLORS[row[7]] || "#64748b";
    var rest = span(d, "c-rest", "");
    span(rest, "c-tr c-q", row[8]).dataset.q = row[8];
    span(rest, "c-in" + infoClass(row[9]), " " + row[9]);
    span(rest, "c-rf", " " + row[10]);
    rest.title = row[8] + "  " + row[9] + "  " + row[10];
    return d;
  }
  function markerEl(text) { var d = document.createElement("div"); d.className = "cl mk"; d.textContent = text; return d; }
  function marker(text) { el.out.appendChild(markerEl(text)); }

  // `note` (a burst: lines skipped between the last batch and this one) goes right above the batch
  function append(lines, note) {
    if (!lines.length) return;
    var rows = E.parseEvents(lines.join("\n")), frag = document.createDocumentFragment();
    if (note) frag.appendChild(markerEl(note));
    for (var i = 0; i < rows.length; i++) frag.appendChild(lineEl(rows[i]));
    var out = el.out, keep = Math.max(0, MAX - rows.length), h0 = out.scrollHeight;
    while (out.childElementCount > keep) out.removeChild(out.firstChild);   // the oldest go
    if (!st.follow) out.scrollTop -= h0 - out.scrollHeight;   // reading further up: those lines stay put
    out.appendChild(frag);
    if (st.follow) out.scrollTop = out.scrollHeight;
    else { st.unseen += rows.length; el.pill.textContent = fmt(st.unseen) + " new ↓"; el.pill.hidden = false; }
  }

  // "there is more above / below": a shadow on that edge, and our own scrollbar. The native one cannot
  // do it: with GTK overlay scrollbars (Firefox's default on GNOME) it is a ~6px floating thumb, hidden
  // until you scroll, and no CSS widens it. This one is always drawn while there is more to see.
  function edges() {
    var o = el.out, max = o.scrollHeight - o.clientHeight, up = o.scrollTop > 2, down = max - o.scrollTop > 2;
    el.view.classList.toggle("up", up); el.view.classList.toggle("down", down);
    var sb = el.sb, th = sb.firstChild, track = sb.clientHeight;
    sb.classList.toggle("idle", max <= 2);
    if (max <= 2) return;
    var h = Math.max(32, Math.round(track * o.clientHeight / o.scrollHeight));
    th.style.height = h + "px";
    th.style.transform = "translateY(" + Math.round((track - h) * Math.min(1, o.scrollTop / max)) + "px)";
  }
  function scrollbar() {
    var o = el.out, sb = el.sb, th = sb.firstChild;
    th.onpointerdown = function (e) {
      e.preventDefault(); e.stopPropagation(); th.setPointerCapture(e.pointerId); th.classList.add("drag");
      var y0 = e.clientY, s0 = o.scrollTop, k = (o.scrollHeight - o.clientHeight) / Math.max(1, sb.clientHeight - th.offsetHeight);
      th.onpointermove = function (m) { o.scrollTop = s0 + (m.clientY - y0) * k; };
      th.onpointerup = th.onpointercancel = function () { th.onpointermove = null; th.classList.remove("drag"); };
    };
    sb.onpointerdown = function (e) {   // on the track: a page towards the click
      if (e.target !== sb) return;
      o.scrollTop += (e.clientY < th.getBoundingClientRect().top ? -1 : 1) * o.clientHeight * 0.9;
    };
    sb.onwheel = function (e) {
      e.preventDefault(); o.scrollTop += e.deltaY * (e.deltaMode === 1 ? 18 : e.deltaMode === 2 ? o.clientHeight : 1);
    };
  }
  function status() {
    edges();
    var n = el.out.querySelectorAll(".cl:not(.mk)").length, txt, cls = "";
    if (UI.DEMO) { txt = st.paused ? "paused" : "replay · demo data"; cls = st.paused ? "" : "on"; }
    else if (st.paused) txt = "paused · " + fmt(n) + " lines";
    else if (live()) { txt = "live · " + fmt(n) + " lines"; cls = "on"; }
    else txt = st.total != null && st.total > n ? "last " + fmt(n) + " of " + fmt(st.total) : fmt(n) + " lines";
    if (!n && !st.paused) txt = st.q ? "no line matches" : (live() ? "live · waiting for events" : "no events this day");
    el.stat.textContent = txt; el.stat.className = "con-stat " + cls;
  }
  function note(text) { el.stat.textContent = text; el.stat.className = "con-stat err"; }

  function schedule(ms) {
    clearTimeout(st.timer); st.timer = 0;
    if (!st.on || st.paused) return;
    if (UI.DEMO) { st.timer = setTimeout(demoTick, ms || DEMO_MS); return; }
    if (live()) st.timer = setTimeout(function () { if (document.hidden) schedule(); else fetchTail(false); }, ms || POLL_MS);
  }
  function fetchTail(first) {
    var seq = st.seq;
    var url = "/tail?date=" + encodeURIComponent(st.date) + "&n=" + (first ? st.n : MAX) +
              (st.offset != null ? "&from=" + st.offset : "") + (st.q ? "&q=" + encodeURIComponent(st.q) : "");
    fetch(url, { credentials: "same-origin" }).then(function (r) {
      if (seq !== st.seq) return;
      if (r.status === 401) { note("log in to view events"); UI.showLogin(); return; }
      if (!r.ok) { note("tail failed (HTTP " + r.status + ")"); schedule(5000); return; }
      return r.json().then(function (d) {
        if (seq !== st.seq) return;
        if (d.reset) { el.out.textContent = ""; marker("— log rotated, reading it again —"); }
        if (first) st.total = d.matched;
        st.offset = d.offset;
        append(d.lines, !first && d.matched > d.lines.length ? "… " + fmt(d.matched - d.lines.length) + " lines not shown (burst)" : null);
        status(); schedule();
      });
    }).catch(function () { if (seq === st.seq) { note("no connection — retrying"); schedule(5000); } });
  }
  // The demo has no server: replay its day as if it were arriving, a few lines at a time, looping.
  function demoTick() {
    var ws = words(), lines = st.demo || (st.demo = UI.demoLines()), out = [], k = 1 + Math.floor(Math.random() * 3), guard = lines.length;
    while (out.length < k && guard-- > 0) { var l = lines[st.demoI++ % lines.length]; if (matches(l, ws)) out.push(l); }
    append(out); status(); schedule(DEMO_MS * (0.5 + Math.random()));
  }

  function reload() {
    st.seq++; clearTimeout(st.timer); st.timer = 0;
    st.date = UI.currentDate(); st.offset = null; st.total = null; st.unseen = 0; st.follow = true;
    el.out.textContent = ""; el.pill.hidden = true;
    el.f.hidden = !(UI.DEMO || live());   // -f only where something can still arrive
    el.file.textContent = lastDay(st.date) + ".log";
    if (UI.DEMO) {
      var ws = words(), lines = st.demo || (st.demo = UI.demoLines()), first = [];
      st.demoI = Math.floor(lines.length * 0.3);   // open part-way in: a screenful of history, the rest "arrives"
      for (var i = 0; i < st.demoI; i++) if (matches(lines[i], ws)) first.push(lines[i]);
      append(first.slice(-st.n)); status(); schedule();
      return;
    }
    status(); fetchTail(true);
  }
  function setPaused(p) {
    st.paused = p; el.pause.textContent = p ? "resume" : "pause"; el.pause.setAttribute("aria-pressed", p ? "true" : "false");
    status();
    if (!p) { if (UI.DEMO) schedule(); else if (live()) fetchTail(false); }   // catch up at once: from the offset, at most MAX lines
    else { clearTimeout(st.timer); st.timer = 0; }
  }
  function fit() {   // the console fills the window below its own top edge
    if (!st.on) return;
    var top = el.sec.getBoundingClientRect().top + window.pageYOffset;
    el.sec.style.height = Math.max(320, window.innerHeight - top - 14) + "px";
    if (st.follow) el.out.scrollTop = el.out.scrollHeight;   // a new height must not unpin the newest line
    edges();
  }
  function setOn(on) {
    st.on = on;
    try { localStorage.setItem("mt_console", on ? "1" : "0"); } catch (e) { }
    document.body.classList.toggle("console-on", on);
    el.sec.hidden = !on;
    el.btn.classList.toggle("on", on); el.btn.setAttribute("aria-pressed", on ? "true" : "false");
    if (on) { fit(); reload(); }
    else { st.seq++; clearTimeout(st.timer); st.timer = 0; el.out.textContent = ""; }   // nothing kept while hidden
  }
  function grep(q) { q = q.trim(); if (q === st.q) return; st.q = q; el.q.value = q; reload(); }

  function init() {
    el.sec = $("console"); el.btn = $("console_btn"); el.out = $("con_out"); el.stat = $("con_stat");
    el.q = $("con_q"); el.pause = $("con_pause"); el.pill = $("con_new"); el.f = $("con_f"); el.file = $("con_file"); el.n = $("con_n"); el.view = $("con_view"); el.sb = $("con_sb");
    if (!el.sec || !el.btn) return;
    try { var n = +localStorage.getItem("mt_con_n"); if (NS.indexOf(n) >= 0) st.n = n; } catch (e) { }
    el.n.value = String(st.n);
    el.n.onchange = function () {
      st.n = +el.n.value; try { localStorage.setItem("mt_con_n", st.n); } catch (e) { }
      el.n.blur(); reload();
    };
    el.btn.onclick = function () { setOn(!st.on); };
    el.pause.onclick = function () { setPaused(!st.paused); };
    $("con_clear").onclick = function () { el.out.textContent = ""; st.unseen = 0; el.pill.hidden = true; status(); };
    el.pill.onclick = function () { el.out.scrollTop = el.out.scrollHeight; };
    scrollbar();
    var deb = 0;
    el.q.oninput = function () { clearTimeout(deb); deb = setTimeout(function () { grep(el.q.value); }, 450); };
    el.q.onkeydown = function (e) {
      if (e.key === "Enter") { e.preventDefault(); clearTimeout(deb); grep(el.q.value); }
      else if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); clearTimeout(deb); grep(""); el.q.blur(); }
    };
    el.out.onscroll = function () {
      edges();
      var o = el.out; st.follow = o.scrollHeight - o.scrollTop - o.clientHeight < FOLLOW_SLACK;
      if (st.follow && st.unseen) { st.unseen = 0; el.pill.hidden = true; }
    };
    el.out.onclick = function (e) {
      if (String(window.getSelection ? window.getSelection() : "")) return;   // selecting text to copy is not a click
      var q = e.target.closest && e.target.closest(".c-q");
      if (q && q.dataset.q) { grep((st.q ? st.q + " " : "") + q.dataset.q); return; }
      var line = e.target.closest && e.target.closest(".cl");
      if (line && line._row && !UI.openThreatFor(line._row)) note("that threat is not in the day on screen");
    };
    window.addEventListener("resize", fit);
    // ...and whenever what sits above it changes height: the cards render after this runs, the
    // panel collapses, the map opens. Fitted once at start, the console overran the window.
    if (typeof ResizeObserver !== "undefined") {
      var ro = new ResizeObserver(function () { fit(); });
      ["stats", "chart_area", "worldmap"].forEach(function (id) { var x = $(id); if (x) ro.observe(x); });
      var tb = document.querySelector(".toolbar"); if (tb) ro.observe(tb);
    }
    var on = false; try { on = localStorage.getItem("mt_console") === "1"; } catch (e) { }
    if (on) setOn(true);
  }

  // Home (oldest) / End (newest) and the arrows move through the lines while the console is shown
  // (the grid they normally drive is hidden); PgUp/PgDn keep paging days
  function scroll(key) {
    var o = el.out, line = 18;
    if (key === "Home") o.scrollTop = 0;
    else if (key === "End") o.scrollTop = o.scrollHeight;
    else if (key === "ArrowUp") o.scrollTop -= line;
    else if (key === "ArrowDown") o.scrollTop += line;
  }
  window.MT_CONSOLE = {
    scroll: function (key) { if (st.on) scroll(key); },
    toggle: function () { if (el.btn) setOn(!st.on); },
    day: function () { if (st.on) setTimeout(reload, 0); }   // after the page has switched its date
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init); else init();
})();
