"use strict";
/*
 * app.js — Ebb Control Center frontend.
 *
 * Vanilla JS, no frameworks, no build step, zero external references.
 * The page is strictly read-only: the ONLY action anywhere is copying
 * ebb CLI command lines to the clipboard (navigator.clipboard with an
 * execCommand fallback). All data comes from same-origin GET endpoints
 * (/api/overview, /api/history, /api/tree).
 */
(() => {

  // ---------- tiny helpers -------------------------------------------------

  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  const ESC_MAP = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  // esc: every external string (names, roots, reasons, commands) is
  // HTML-escaped before landing in innerHTML — hostile workspace names
  // must never execute in this page.
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ESC_MAP[c]);

  const UNITS = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  // humanBytes mirrors the CLI's HumanBytes (IEC units, one decimal).
  function humanBytes(n) {
    if (typeof n !== "number" || !isFinite(n)) return "\u2014";
    if (n < 0) return n + " B";
    let f = n, i = 0;
    while (f >= 1024 && i < UNITS.length - 1) { f /= 1024; i += 1; }
    if (i === 0) return n + " B";
    let s = f.toFixed(1) + " " + UNITS[i];
    if (s.indexOf(".0 ") >= 0) s = s.replace(".0 ", " ");
    return s;
  }

  function fmtInt(n) {
    return typeof n === "number" && isFinite(n) ? n.toLocaleString("en-US") : "\u2014";
  }

  function fmtRatio(v) {
    if (typeof v !== "number" || !isFinite(v) || v < 0) return "\u2014";
    return v <= 1 ? (v * 100).toFixed(1) + "%" : v.toFixed(2) + "\u00d7";
  }

  function fmtWhen(ts) {
    if (!ts) return "never";
    const d = new Date(ts);
    if (isNaN(d.getTime())) return String(ts);
    return d.toLocaleString();
  }

  // shellQuote mirrors the CLI's POSIX-safe copyable-command quoting
  // (bare-safe tokens stay bare; anything else is single-quoted).
  function shellQuote(s) {
    s = String(s == null ? "" : s);
    if (s === "") return "''";
    if (/^[A-Za-z0-9@%+=:,./_-]+$/.test(s)) return s;
    return "'" + s.replace(/'/g, "'\\''") + "'";
  }

  function cap(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

  function noteBox(msg) { return "<div class='note'>" + msg + "</div>"; }
  function errBox(msg) { return "<div class='errbox'>" + msg + "</div>"; }
  function loadingBox() { return "<div class='note'>Loading\u2026</div>"; }

  // ---------- state ---------------------------------------------------------

  const HISTORY_PAGE = 50;      // first page size
  const HISTORY_STEP = 250;     // growth per "load more"

  const state = {
    overview: null,
    overviewError: null,
    history: [],
    historyLimit: HISTORY_PAGE,
    historyDone: false,
    historyError: null,
    tree: null,
    treeError: null,
    view: "dashboard",
    ws: { q: "", status: "all", eco: "all" },
  };

  // ---------- data access ----------------------------------------------------

  async function fetchJSON(url) {
    const res = await fetch(url, { method: "GET" });
    let body = null;
    try { body = await res.json(); } catch (_) { /* no body */ }
    if (!res.ok) {
      throw new Error(body && body.error ? body.error : "HTTP " + res.status);
    }
    return body;
  }

  async function loadOverview() {
    try {
      state.overview = await fetchJSON("/api/overview");
      state.overviewError = null;
    } catch (e) {
      state.overviewError = e.message;
    }
  }

  async function loadHistory(limit) {
    try {
      const body = await fetchJSON("/api/history?limit=" + encodeURIComponent(limit));
      state.history = (body && body.events) || [];
      // Fewer events than requested means the ledger is exhausted.
      state.historyDone = state.history.length < limit;
      state.historyError = null;
    } catch (e) {
      state.historyError = e.message;
    }
    renderHistory();
  }

  async function loadTree(id) {
    if (!/^[0-9a-fA-F]{8,64}$/.test(id)) {
      state.tree = null;
      state.treeError = "Snapshot id must be 8 to 64 hexadecimal characters.";
      renderSnapshot();
      return;
    }
    try {
      state.tree = await fetchJSON("/api/tree?id=" + encodeURIComponent(id));
      state.treeError = null;
    } catch (e) {
      state.tree = null;
      state.treeError = e.message;
    }
    renderSnapshot();
  }

  // ---------- clipboard + toast -----------------------------------------------

  let toastTimer = 0;

  function toast(message) {
    const el = $("#toast");
    el.textContent = message;
    el.classList.remove("hidden");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.add("hidden"), 2600);
  }

  function copyCommand(cmd) {
    const done = () => toast("Copied: " + (cmd.length > 64 ? cmd.slice(0, 61) + "\u2026" : cmd));
    const fail = () => toast("Copy failed \u2014 select the command text manually");
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(cmd).then(done, () => { legacyCopy(cmd) ? done() : fail(); });
    } else {
      legacyCopy(cmd) ? done() : fail();
    }
  }

  // legacyCopy: execCommand fallback for older / non-secure contexts.
  function legacyCopy(text) {
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand("copy");
      document.body.removeChild(ta);
      return ok;
    } catch (_) {
      return false;
    }
  }

  // copyButton builds a clipboard-action button (DOM-built so the
  // command never round-trips through HTML).
  function copyButton(label, cmd) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "btn copy";
    b.title = cmd;
    b.textContent = label;
    b.addEventListener("click", () => copyCommand(cmd));
    return b;
  }

  // ---------- view switching ---------------------------------------------------

  const VIEWS = ["dashboard", "workspaces", "history", "snapshot", "analyse"];

  function switchView(name) {
    if (VIEWS.indexOf(name) < 0) name = "dashboard";
    state.view = name;
    VIEWS.forEach((v) => $("#view-" + v).classList.toggle("hidden", v !== name));
    $$("#tabs .tab").forEach((t) => t.classList.toggle("active", t.dataset.view === name));
    renderCurrent();
  }

  function renderCurrent() {
    switch (state.view) {
      case "dashboard": renderDashboard(); break;
      case "workspaces": renderWorkspaces(); break;
      case "history": renderHistory(); break;
      case "snapshot": renderSnapshot(); break;
      case "analyse": renderAnalyse(); break;
    }
  }

  // ---------- dashboard ---------------------------------------------------------

  function hero(label, value, sub) {
    return "<div class='hero'><div class='hero-value'>" + value + "</div>" +
      "<div class='hero-label'>" + esc(label) + "</div>" +
      "<div class='hero-sub'>" + esc(sub) + "</div></div>";
  }

  function stat(label, value, sub) {
    return "<div class='stat'><div class='stat-body'><div class='stat-value'>" + value + "</div>" +
      "<div class='stat-label'>" + esc(label) + "</div>" +
      (sub ? "<div class='stat-sub'>" + esc(sub) + "</div>" : "") + "</div></div>";
  }

  function scoreBadge(s) {
    if (!s || (!s.grade && !s.label)) return stat("Hoarding score", "\u2014", "no score yet");
    const g = String(s.grade || "?").toUpperCase();
    const cls = ["S", "A", "B", "C", "D", "F"].indexOf(g) >= 0 ? g.toLowerCase() : "c";
    return "<div class='stat score " + cls + "'><div class='score-grade'>" + esc(g) + "</div>" +
      "<div class='stat-body'><div class='stat-label'>Hoarding score</div>" +
      "<div class='stat-sub'>" + esc(s.label || "") + "</div></div></div>";
  }

  function compareCard(c) {
    if (!c || !c.text) return "";
    return "<div class='compare-card'><span class='chip'>" + esc(c.category || "scale") + "</span>" +
      "<div class='compare-subject'>" + esc(c.subject || "") + "</div>" +
      "<p class='compare-text'>" + esc(c.text) + "</p></div>";
  }

  function topCommandsHTML(cmds) {
    if (!cmds || !cmds.length) return "<p class='muted'>No commands recorded yet.</p>";
    const max = Math.max.apply(null, cmds.map((c) => Number(c.count) || 0).concat([1]));
    return "<div class='bars'>" + cmds.map((c) => {
      const w = Math.max(2, Math.round(((Number(c.count) || 0) / max) * 100));
      return "<div class='bar-row'>" +
        "<span class='bar-label mono' title='" + esc(c.command) + "'>" + esc(c.command) + "</span>" +
        "<span class='bar-track'><span class='bar-fill' style='width:" + w + "%'></span></span>" +
        "<span class='bar-value mono'>" + fmtInt(c.count) + "</span>" +
        "</div>";
    }).join("") + "</div>";
  }

  function renderDashboard() {
    if (state.overviewError) {
      $("#dash-heroes").innerHTML = "";
      $("#dash-secondary").innerHTML = "";
      $("#dash-topcmds").innerHTML = "";
      $("#dash-compare").innerHTML = "";
      $("#dash-since").innerHTML = "";
      $("#view-dashboard").insertAdjacentHTML("afterbegin",
        errBox("Failed to load overview: " + esc(state.overviewError)));
      return;
    }
    const o = state.overview;
    if (!o) {
      $("#dash-heroes").innerHTML = loadingBox();
      return;
    }
    const m = o.metrics || {};
    $("#dash-heroes").innerHTML =
      hero("Lifetime reclaimed", humanBytes(m.lifetime_reclaimed_bytes), "bytes given back by reclaim & trim") +
      hero("Lifetime restored", humanBytes(m.lifetime_restored_bytes), "bytes brought back from the vault") +
      hero("Currently parked", humanBytes(m.currently_parked_bytes), fmtInt(m.parked_workspaces) + " workspace(s) parked") +
      hero("Active workspaces", fmtInt(m.active_workspaces), "roots currently live");

    $("#dash-secondary").innerHTML =
      stat("Space efficiency", fmtRatio(m.space_efficiency_ratio), "parked vs live bytes") +
      stat("Clean-desk streak", fmtInt(m.clean_desk_streak_days) + "d", "since the last stray workspace") +
      scoreBadge(m.hoarding_score) +
      stat("Zombies exorcised", humanBytes(m.zombie_gb_exorcised), "dead-weight bytes removed") +
      stat("SSD wear saved", humanBytes(m.estimated_ssd_wear_saved), "writes avoided (estimate)");

    $("#dash-topcmds").innerHTML = topCommandsHTML(m.top_commands);
    $("#dash-compare").innerHTML = compareCard(o.comparison_reclaimed) + compareCard(o.comparison_restored);

    $("#dash-since").innerHTML = m.tracking_since
      ? "Tracking since " + esc(m.tracking_since) + " \u00b7 " + fmtInt(m.total_invocations) + " invocation(s)."
      : "No tracking history yet.";
  }

  // ---------- workspaces ----------------------------------------------------------

  function allWorkspaces() { return (state.overview && state.overview.workspaces) || []; }

  function workspacesFiltered() {
    const q = state.ws.q.trim().toLowerCase();
    return allWorkspaces().filter((w) => {
      if (state.ws.status !== "all" && String(w.status || "").toLowerCase() !== state.ws.status) return false;
      if (state.ws.eco !== "all" && String(w.ecosystem || "") !== state.ws.eco) return false;
      if (q) {
        const hay = (w.name + " " + w.root + " " + w.ecosystem).toLowerCase();
        if (hay.indexOf(q) < 0) return false;
      }
      return true;
      // Sorted by last activity, newest first (ISO timestamps sort
      // lexically).
    }).sort((a, b) => String(b.last_activity || "").localeCompare(String(a.last_activity || "")));
  }

  // wsCommands: the copy-only action model, per spec:
  //   active rows  \u2192 reclaim / restore / park commands
  //   parked rows  \u2192 open command
  function wsCommands(w) {
    if (String(w.status || "").toLowerCase() === "parked") {
      return [{ label: "\u{1F4CB} Copy Open Command", cmd: "ebb open " + shellQuote(w.name) }];
    }
    const root = shellQuote(w.root);
    return [
      { label: "\u{1F4CB} Copy Reclaim Command", cmd: "ebb reclaim " + root + " --yes" },
      { label: "\u{1F4CB} Copy Restore Command", cmd: "ebb restore " + root },
      { label: "\u{1F4CB} Copy Park Command", cmd: "ebb park " + root + " --yes" },
    ];
  }

  function td(content, cls) {
    const td = document.createElement("td");
    if (cls) td.className = cls;
    if (content instanceof Node) td.appendChild(content);
    else td.innerHTML = content;
    return td;
  }

  function statusChip(status) {
    const s = String(status || "").toLowerCase();
    const cls = s === "parked" ? "warn" : "ok";
    return "<span class='chip " + cls + " " + (s === "parked" ? "status-parked" : "status-active") + "'>" + esc(status || "\u2014") + "</span>";
  }

  function wsRow(w) {
    const tr = document.createElement("tr");
    tr.dataset.root = w.root || "";
    tr.appendChild(td("<span class='ws-name'>" + esc(w.name) + "</span>"));
    tr.appendChild(td(statusChip(w.status)));
    tr.appendChild(td("<span class='root-cell' title='" + esc(w.root) + "'>" + esc(w.root) + "</span>", "root-cell"));
    tr.appendChild(td(esc(w.ecosystem || "plain")));
    tr.appendChild(td("<span class='muted nowrap'>" + esc(fmtWhen(w.last_activity)) + "</span>"));
    tr.appendChild(td(humanBytes(w.size_bytes), "num"));
    tr.appendChild(td(humanBytes(w.reclaimed_bytes), "num"));
    const actions = document.createElement("div");
    actions.className = "row-actions";
    wsCommands(w).forEach((c) => actions.appendChild(copyButton(c.label, c.cmd)));
    tr.appendChild(td(actions));
    return tr;
  }

  function renderWorkspaces() {
    if (state.overviewError) {
      $("#ws-tbody").replaceChildren();
      $("#ws-count").textContent = "";
      $("#view-workspaces").insertAdjacentHTML("afterbegin",
        errBox("Failed to load workspaces: " + esc(state.overviewError)));
      return;
    }

    // Ecosystem filter is populated from the data; the selection is
    // kept when it still exists.
    const ecos = Array.from(new Set(allWorkspaces().map((w) => w.ecosystem || "plain").filter(Boolean))).sort();
    const ecoSel = $("#ws-eco");
    ecoSel.innerHTML = "<option value='all'>all ecosystems</option>" +
      ecos.map((e) => "<option value='" + esc(e) + "'>" + esc(e) + "</option>").join("");
    ecoSel.value = ecos.indexOf(state.ws.eco) >= 0 ? state.ws.eco : "all";
    state.ws.eco = ecoSel.value;

    const rows = workspacesFiltered();
    const tbody = $("#ws-tbody");
    tbody.replaceChildren();
    if (!rows.length) {
      const tr = document.createElement("tr");
      const empty = document.createElement("td");
      empty.colSpan = 8;
      empty.innerHTML = "<span class='muted'>No workspaces match the current filters.</span>";
      tr.appendChild(empty);
      tbody.appendChild(tr);
    } else {
      rows.forEach((w) => tbody.appendChild(wsRow(w)));
    }
    $("#ws-count").textContent = rows.length + " of " + allWorkspaces().length + " shown";
  }

  function highlightWorkspace(root) {
    const row = $("tr[data-root='" + CSS.escape(root || "") + "']");
    if (row) {
      row.scrollIntoView({ block: "center" });
      row.classList.remove("flash");
      void row.offsetWidth; // restart the animation
      row.classList.add("flash");
    }
  }

  // ---------- history ----------------------------------------------------------------

  // ICON_PATHS: per-command inline SVG icons (stroke-only, no external
  // namespaces needed in an HTML context).
  const ICON_PATHS = {
    reclaim: "<path d='M3 4h10M6.5 4V2.5h3V4M5 4l.6 9h4.8L11 4'/>",
    park: "<path d='M2.5 3h11v4h-11zM8 7v6M5.5 13h5'/>",
    restore: "<path d='M8 13V4M4.5 7.5L8 4l3.5 3.5M3 14h10'/>",
    open: "<path d='M2 4h4l1.2 1.5H14V13H2z'/>",
    verify: "<path d='M3 8.5l3.2 3L13 4.5'/>",
    gc: "<path d='M9 2.5L4.5 8H8l-1 5.5L11.5 8H8z'/>",
    forget: "<path d='M3 3l10 10M13 3L3 13'/>",
    import: "<path d='M8 2v8M4.5 6.5L8 10l3.5-3.5M3 13h10'/>",
    export: "<path d='M8 10V2M4.5 5.5L8 2l3.5 3.5M3 13h10'/>",
    trim: "<path d='M4 2.5l8 8M12 2.5l-8 8M2.5 11.5l2 2'/>",
    freeze: "<path d='M8 2v12M2.8 5l10.4 6M13.2 5L2.8 11'/>",
  };

  function cmdIcon(command) {
    const words = String(command || "").trim().split(/\s+/).filter(Boolean);
    let key = words[0] || "";
    if (key === "ebb" && words.length > 1) key = words[1];
    const path = ICON_PATHS[key] || "<circle cx='8' cy='8' r='4'/>";
    return "<svg viewBox='0 0 16 16' fill='none' stroke='currentColor' stroke-width='1.4' " +
      "stroke-linecap='round' stroke-linejoin='round'>" + path + "</svg>";
  }

  function outcomeChip(outcome) {
    const o = String(outcome || "").toLowerCase();
    const cls = o === "ok" || o === "executed" || o === "done" ? "ok"
      : o === "failed" || o === "error" || o === "blocked" ? "bad" : "warn";
    return "<span class='chip " + cls + "'>" + esc(outcome || "\u2014") + "</span>";
  }

  function historyItemHTML(ev, i) {
    return "<li class='tl-item' id='hist-" + i + "'>" +
      "<span class='tl-icon'>" + cmdIcon(ev.command) + "</span>" +
      "<div class='tl-body'>" +
        "<div class='tl-head'>" +
          "<span class='mono cmd'>" + esc(ev.command) + "</span>" +
          outcomeChip(ev.outcome) +
          (ev.bytes_out ? "<span class='tl-bytes out'>&minus;" + humanBytes(ev.bytes_out) + "</span>" : "") +
          (ev.bytes_in ? "<span class='tl-bytes in'>+" + humanBytes(ev.bytes_in) + "</span>" : "") +
        "</div>" +
        "<div class='tl-meta'>" + esc(fmtWhen(ev.ts)) +
          (ev.workspace ? " \u00b7 " + esc(ev.workspace) : "") + "</div>" +
      "</div>" +
    "</li>";
  }

  function renderHistory() {
    const list = $("#history-list");
    if (state.historyError) {
      list.innerHTML = errBox("Failed to load history: " + esc(state.historyError));
    } else if (!state.history.length) {
      list.innerHTML = noteBox("No events recorded yet \u2014 they appear as ebb commands run.");
    } else {
      list.innerHTML = state.history.map(historyItemHTML).join("");
    }
    const btn = $("#btn-load-more");
    btn.disabled = state.historyDone;
    btn.textContent = state.historyDone ? "All loaded" : "Load more";
    $("#history-count").textContent = state.history.length + " event(s) shown";
  }

  function flashHistory(i) {
    const el = $("#hist-" + i);
    if (el) {
      el.scrollIntoView({ block: "center" });
      el.classList.add("flash");
    }
  }

  // ---------- snapshot explorer ---------------------------------------------------------

  const KIND_LABELS = { dir: "Directories", file: "Files", link: "Links" };

  function kindTag(kind) {
    const k = KIND_LABELS[kind] ? kind : "file";
    return "<span class='k " + k + "'>" + k + "</span>";
  }

  function bySizeDesc(a, b) { return (b.size || 0) - (a.size || 0); }
  function byName(a, b) { return String(a.name).localeCompare(String(b.name)); }

  // treeHTML: when entry names carry path separators a real collapsible
  // tree is built from the segments; otherwise entries are grouped by
  // kind under collapsible headings (the view type carries names only).
  function treeHTML(entries) {
    if (entries.some((e) => String(e.name || "").indexOf("/") >= 0)) return pathTreeHTML(entries);
    let html = "";
    for (const kind of ["dir", "file", "link"]) {
      const items = entries.filter((e) => (KIND_LABELS[e.kind] ? e.kind : "file") === kind).sort(bySizeDesc);
      if (!items.length) continue;
      html += "<details class='tree-group' open><summary>" + KIND_LABELS[kind] +
        " <span class='muted'>(" + items.length + ")</span></summary><ul class='tree'>" +
        items.map((e) =>
          "<li class='tree-leaf'>" + kindTag(e.kind) +
          "<span class='tree-name mono'>" + esc(e.name) + "</span>" +
          "<span class='tree-size muted mono'>" + humanBytes(e.size) + "</span></li>").join("") +
        "</ul></details>";
    }
    return html;
  }

  function pathTreeHTML(entries) {
    const root = { dirs: {}, files: [] };
    for (const e of entries) {
      const parts = String(e.name || "").split("/").filter(Boolean);
      if (!parts.length) continue;
      let node = root;
      for (let i = 0; i < parts.length - 1; i += 1) {
        node = node.dirs[parts[i]] = node.dirs[parts[i]] || { dirs: {}, files: [] };
      }
      const leaf = { name: parts[parts.length - 1], kind: e.kind, size: e.size };
      if (leaf.kind === "dir") node.dirs[leaf.name] = node.dirs[leaf.name] || { dirs: {}, files: [] };
      else node.files.push(leaf);
    }
    return "<ul class='tree'>" + treeNodeHTML(root) + "</ul>";
  }

  function treeNodeHTML(node) {
    let html = "";
    Object.keys(node.dirs).sort().forEach((name) => {
      html += "<li><details class='tree-group' open><summary>" + kindTag("dir") +
        " <span class='mono'>" + esc(name) + "/</span></summary>" +
        "<ul class='tree'>" + treeNodeHTML(node.dirs[name]) + "</ul></details></li>";
    });
    node.files.sort(byName).forEach((f) => {
      html += "<li class='tree-leaf'>" + kindTag(f.kind) +
        "<span class='tree-name mono'>" + esc(f.name) + "</span>" +
        "<span class='tree-size muted mono'>" + humanBytes(f.size) + "</span></li>";
    });
    return html;
  }

  function renderSnapshot() {
    const res = $("#snap-result");
    if (state.treeError) {
      res.innerHTML = errBox(esc(state.treeError));
      return;
    }
    if (!state.tree) { res.innerHTML = ""; return; }
    const entries = state.tree.entries || [];
    if (!entries.length) {
      res.innerHTML = noteBox("This snapshot reports no entries \u2014 nothing to browse. " +
        "Data availability depends on the catalog; verify the snapshot with <code>ebb verify</code>.");
      return;
    }
    res.innerHTML = "<div class='panel'><h2 class='mono' style='text-transform:none'>" + esc(state.tree.id) +
      " <span class='muted'>(" + entries.length + " entries)</span></h2>" + treeHTML(entries) + "</div>";
  }

  // ---------- analyse ----------------------------------------------------------------------

  function recCardHTML(r, idx) {
    const shielded = !!r.shielded;
    // Shielded findings: chip only, NO copy action — the shield, not
    // the dashboard, is the authority.
    return "<div class='card rec" + (shielded ? " shielded" : "") + "' data-rec-idx='" + idx + "'>" +
      "<div class='card-head'><span class='mono strong'>" + esc(r.root || r.category) + "</span>" +
      (shielded ? "<span class='chip shield'>shielded</span>" : "") + "</div>" +
      (r.reason ? "<p class='reason'>" + esc(r.reason) + "</p>" : "") +
      "<div class='rec-meta'><span class='bytes mono'>" + humanBytes(r.reclaimable_bytes) + " reclaimable</span>" +
      "<span class='muted'>" + esc(r.category) + "</span></div>" +
      (!shielded && r.command
        ? "<div class='cmd-line'><code class='mono'>" + esc(r.command) + "</code></div>" +
          "<button type='button' class='btn copy'>\u{1F4CB} Copy Batch Command</button>"
        : "") +
      "</div>";
  }

  function renderAnalyse() {
    const host = $("#analyse-list");
    if (state.overviewError) {
      host.innerHTML = errBox("Failed to load recommendations: " + esc(state.overviewError));
      return;
    }
    const recs = (state.overview && state.overview.recommendations) || [];
    if (!recs.length) {
      host.innerHTML = noteBox("No recommendations \u2014 nothing stale, abandoned or prunable was detected in the last analysis.");
      return;
    }
    const byCat = {};
    recs.forEach((r) => {
      const cat = r.category || "other";
      (byCat[cat] = byCat[cat] || []).push(r);
    });
    host.innerHTML = Object.keys(byCat).sort().map((cat) =>
      "<h2 class='cat-title'>" + esc(cat) + " <span class='muted'>(" + byCat[cat].length + ")</span></h2>" +
      "<div class='cards'>" + byCat[cat].map((r) => recCardHTML(r, recs.indexOf(r))).join("") + "</div>"
    ).join("");
  }

  function onAnalyseClick(e) {
    const btn = e.target.closest("button.copy");
    if (!btn) return;
    const card = btn.closest("[data-rec-idx]");
    if (!card) return;
    const recs = (state.overview && state.overview.recommendations) || [];
    const r = recs[Number(card.dataset.recIdx)];
    if (r && r.command && !r.shielded) copyCommand(r.command);
  }

  // ---------- command palette ---------------------------------------------------------------

  let paletteItems = [];
  let paletteSel = 0;

  function buildPaletteIndex() {
    const items = [];
    VIEWS.forEach((v) => items.push({
      type: "view", label: "View: " + cap(v), hint: "switch tab",
      run: () => switchView(v),
    }));
    const o = state.overview;
    if (o) {
      (o.workspaces || []).forEach((w) => {
        items.push({
          type: "workspace", label: "Workspace: " + (w.name || w.root || "?"),
          hint: (w.status || "") + (w.ecosystem ? " \u00b7 " + w.ecosystem : ""),
          run: () => {
            switchView("workspaces");
            state.ws.q = w.name || "";
            $("#ws-search").value = state.ws.q;
            renderWorkspaces();
            highlightWorkspace(w.root);
          },
        });
        wsCommands(w).forEach((c) => items.push({
          type: "command", label: c.label.replace("\u{1F4CB} ", "") + " \u2014 " + (w.name || w.root),
          hint: c.cmd, cmd: c.cmd, run: (it) => copyCommand(it.cmd),
        }));
      });
      (o.recommendations || []).forEach((r) => {
        if (!r.shielded && r.command) {
          items.push({
            type: "command", label: "Copy batch command \u2014 " + (r.root || r.category),
            hint: r.command, cmd: r.command, run: (it) => copyCommand(it.cmd),
          });
        }
      });
    }
    state.history.forEach((ev, i) => {
      items.push({
        type: "history", label: "History: " + (ev.command || "?"),
        hint: fmtWhen(ev.ts) + (ev.workspace ? " \u00b7 " + ev.workspace : ""),
        run: () => { switchView("history"); flashHistory(i); },
      });
    });
    return items;
  }

  // fuzzyScore: subsequence match with tightness and word-start bonuses;
  // -1 means "no match".
  function fuzzyScore(query, target) {
    if (!query) return 1;
    const q = query.toLowerCase();
    const t = target.toLowerCase();
    let qi = 0, score = 0, streak = 0, last = -2;
    for (let ti = 0; ti < t.length && qi < q.length; ti += 1) {
      if (t[ti] === q[qi]) {
        streak = ti === last + 1 ? streak + 1 : 1;
        score += 1 + streak * 2;
        if (ti === 0 || /[\s/:_.-]/.test(t[ti - 1])) score += 4;
        last = ti;
        qi += 1;
      }
    }
    return qi === q.length ? score : -1;
  }

  function renderPalette(query) {
    const scored = [];
    buildPaletteIndex().forEach((it) => {
      const s = fuzzyScore(query, it.label + " " + (it.hint || ""));
      if (s >= 0) scored.push({ it, s });
    });
    scored.sort((a, b) => b.s - a.s);
    paletteItems = scored.slice(0, 50).map((x) => x.it);
    paletteSel = 0;
    $("#palette-list").innerHTML = paletteItems.length
      ? paletteItems.map((it, i) =>
          "<li class='palette-item" + (i === 0 ? " sel" : "") + "' data-i='" + i + "'>" +
          "<span class='palette-type'>" + esc(it.type) + "</span>" +
          "<span class='palette-label'>" + esc(it.label) + "</span>" +
          (it.hint ? "<span class='palette-hint muted'>" + esc(it.hint) + "</span>" : "") +
          "</li>").join("")
      : "<li class='palette-empty muted'>No matches.</li>";
  }

  function updatePaletteSel() {
    $$("#palette-list .palette-item").forEach((li, i) => li.classList.toggle("sel", i === paletteSel));
    const sel = $("#palette-list .palette-item.sel");
    if (sel) sel.scrollIntoView({ block: "nearest" });
  }

  function palettePick(i) {
    const it = paletteItems[i];
    if (it) {
      closePalette();
      it.run(it);
    }
  }

  function openPalette() {
    $("#palette").classList.remove("hidden");
    const input = $("#palette-input");
    input.value = "";
    renderPalette("");
    input.focus();
  }

  function closePalette() {
    $("#palette").classList.add("hidden");
    paletteItems = [];
  }

  function togglePalette() {
    if ($("#palette").classList.contains("hidden")) openPalette();
    else closePalette();
  }

  function onPaletteKey(e) {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      if (!paletteItems.length) return;
      const delta = e.key === "ArrowDown" ? 1 : paletteItems.length - 1;
      paletteSel = (paletteSel + delta) % paletteItems.length;
      updatePaletteSel();
    } else if (e.key === "Enter") {
      e.preventDefault();
      palettePick(paletteSel);
    } else if (e.key === "Escape") {
      e.preventDefault();
      closePalette();
    }
  }

  // ---------- status line + refresh ----------------------------------------------------------

  function setStatus(msg) { $("#status-right").textContent = msg; }

  async function refreshAll() {
    setStatus("loading\u2026");
    await loadOverview();
    loadHistory(state.historyLimit); // parallel; renders itself
    renderCurrent();
    setStatus(state.overviewError
      ? "error loading data"
      : "refreshed " + new Date().toLocaleTimeString());
  }

  // ---------- init ------------------------------------------------------------------------------

  function init() {
    $("#tabs").addEventListener("click", (e) => {
      const t = e.target.closest(".tab");
      if (t) switchView(t.dataset.view);
    });
    $("#btn-refresh").addEventListener("click", refreshAll);
    $("#btn-palette").addEventListener("click", togglePalette);

    $("#ws-search").addEventListener("input", (e) => {
      state.ws.q = e.target.value;
      renderWorkspaces();
    });
    $("#ws-status").addEventListener("change", (e) => {
      state.ws.status = e.target.value;
      renderWorkspaces();
    });
    $("#ws-eco").addEventListener("change", (e) => {
      state.ws.eco = e.target.value;
      renderWorkspaces();
    });

    $("#btn-load-more").addEventListener("click", () => {
      state.historyLimit += HISTORY_STEP;
      loadHistory(state.historyLimit);
    });

    $("#btn-snap").addEventListener("click", () => loadTree($("#snap-id").value.trim()));
    $("#snap-id").addEventListener("keydown", (e) => {
      if (e.key === "Enter") loadTree($("#snap-id").value.trim());
    });

    $("#analyse-list").addEventListener("click", onAnalyseClick);

    // Palette wiring.
    $("#palette-input").addEventListener("input", (e) => renderPalette(e.target.value));
    $("#palette-input").addEventListener("keydown", onPaletteKey);
    $("#palette-list").addEventListener("click", (e) => {
      const li = e.target.closest(".palette-item");
      if (li) palettePick(Number(li.dataset.i));
    });
    $("#palette-list").addEventListener("mousemove", (e) => {
      const li = e.target.closest(".palette-item");
      if (li) {
        paletteSel = Number(li.dataset.i);
        updatePaletteSel();
      }
    });
    $("#palette").addEventListener("mousedown", (e) => {
      if (e.target === $("#palette")) closePalette();
    });
    document.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && (e.key === "k" || e.key === "K")) {
        e.preventDefault();
        togglePalette();
      } else if (e.key === "Escape" && !$("#palette").classList.contains("hidden")) {
        closePalette();
      }
    });

    refreshAll();
  }

  init();
})();
