"use strict";

(function () {
  history.replaceState(null, "", location.pathname + location.hash);

  const state = {
    overview: null,
    files: [],
    filesLoaded: {},
    selected: null,
    depth: 1,
    mode: "map",
    showTests: false,
    filter: "",
    card: null,
    group: "folders",
    areas: null,
    areaCache: {},
    graphImpact: false,
    graphAllLinks: false,
    graphLimits: {},
    started: false,
  };

  const NAME_MATCH_NOTE = "Matched by name only: the code calls this name, but the graph could not prove which function the call reaches.";
  const MODES = ["graph", "map", "areas", "changes", "pipeline"];
  const NAME_MATCHED_LANGUAGES = ["go", "java", "rust", "php"];

  const VERDICT_LABEL = {
    same_moved: "Same logic",
    same_docs: "Same logic",
    same_renamed: "Same logic",
    same_callee_moved: "Same logic",
    changed: "Logic changed",
    changed_binding: "Needs a look",
    new: "New",
    removed: "Removed",
  };

  const $ = (id) => document.getElementById(id);

  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    if (attrs) {
      for (const [key, value] of Object.entries(attrs)) {
        if (value === null || value === undefined || value === false) continue;
        if (key === "class") el.className = value;
        else if (key === "text") el.textContent = value;
        else if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
        else if (value === true) el.setAttribute(key, "");
        else el.setAttribute(key, String(value));
      }
    }
    for (const kid of kids.flat()) {
      if (kid === null || kid === undefined || kid === false) continue;
      if (kid instanceof Node) el.append(kid);
      else el.append(document.createTextNode(String(kid)));
    }
    return el;
  }

  function svg(tag, attrs, ...kids) {
    const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const [key, value] of Object.entries(attrs || {})) {
      if (key === "text") el.textContent = value;
      else if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
      else el.setAttribute(key, String(value));
    }
    for (const kid of kids.flat()) if (kid) el.append(kid);
    return el;
  }

  async function api(path, options) {
    const init = Object.assign({ headers: {}, credentials: "same-origin" }, options || {});
    const response = await fetch(path, init);
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || ("Request failed: " + response.status));
    return data;
  }

  function toast(text) {
    const el = $("toast");
    el.textContent = text;
    el.hidden = false;
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => { el.hidden = true; }, 2600);
  }

  function shortName(name) {
    const parts = name.split(".");
    return parts[parts.length - 1];
  }

  function owner(name) {
    const parts = name.split(".");
    if (parts.length > 1) return parts.slice(0, -1).join(".");
    return "";
  }

  function vclass(verdict, flagged) {
    if (flagged || verdict === "changed_binding") return "v-flag";
    if (!verdict) return "";
    if (verdict.startsWith("same")) return "v-same";
    if (verdict === "new") return "v-new";
    if (verdict === "removed") return "v-removed";
    return "v-changed";
  }

  function kindChip(kind, isTest) {
    if (isTest) return h("span", { class: "kind k-test", text: "test" });
    return h("span", { class: "kind k-" + kind, text: kind });
  }

  function clip(text, size) {
    if (!text) return "";
    if (text.length > size) return text.slice(0, size - 1) + "…";
    return text;
  }

  function select(id, push) {
    if (!id) return;
    if (graphMounted()) {
      openGraphCard(id);
      return;
    }
    if (push !== false) location.hash = "n=" + encodeURIComponent(id);
    else showNode(id);
  }

  function route() {
    const graphArea = /^#g=(\d+)(?:&n=(.+))?$/.exec(location.hash);
    if (graphArea) {
      let focus = null;
      if (graphArea[2]) focus = decodeURIComponent(graphArea[2]);
      showGraphArea(graphArea[1], focus);
      return;
    }
    const match = /^#n=(.+)$/.exec(location.hash);
    if (match) {
      showNode(decodeURIComponent(match[1]));
      return;
    }
    const change = /^#c=(.+)$/.exec(location.hash);
    if (change) {
      showChange(decodeURIComponent(change[1]));
      return;
    }
    const area = /^#a=(\d+)$/.exec(location.hash);
    if (area) {
      showArea(area[1]);
      return;
    }
    state.selected = null;
    closeCard();
    renderMain();
  }

  function markMode(mode) {
    state.mode = mode;
    for (const name of MODES) {
      $("mode-" + name).classList.toggle("on", mode === name);
      $("mode-" + name).setAttribute("aria-pressed", String(mode === name));
    }
  }

  function setMode(mode) {
    markMode(mode);
    if (location.hash) location.hash = "";
    else renderMain();
  }

  async function load() {
    const [overview, tree] = await Promise.all([api("/api/overview"), api("/api/tree")]);
    state.overview = overview;
    state.files = tree.files;
    state.filesLoaded = {};
    state.areas = null;
    state.areaCache = {};
    const info = overview.overview;
    let label = info.repo || "";
    if (info.commit) label += " · " + info.commit.slice(0, 8);
    if (info.commit && info.dirty) label += " (edited)";
    $("repo").textContent = label;
    $("mode-changes").hidden = !overview.changes;
    $("mode-graph").hidden = !info.areas;
    if (!state.started) {
      state.started = true;
      let first = "map";
      if (info.areas) first = "graph";
      markMode(first);
    } else if (state.mode === "graph" && !info.areas) {
      markMode("map");
    }
    $("tree-group").hidden = !info.areas;
    renderTree();
  }

  function renderMain() {
    const main = $("main");
    main.replaceChildren();
    main.className = "main";
    if (!state.overview) return;
    if (state.mode === "graph") renderGraph(main, null, null, false);
    else if (state.mode === "changes") renderChanges(main);
    else if (state.mode === "pipeline") renderPipeline(main);
    else if (state.mode === "areas") renderAreasPage(main);
    else renderOverview(main);
  }

  async function allAreas() {
    if (!state.areas) state.areas = (await api("/api/areas")).areas;
    return state.areas;
  }

  async function areaData(id) {
    const key = String(id);
    if (!state.areaCache[key]) state.areaCache[key] = await api("/api/area?id=" + encodeURIComponent(key));
    return state.areaCache[key];
  }

  function plural(count, one, many) {
    if (count === 1) return count + " " + one;
    return count + " " + many;
  }

  function openArea(id) {
    location.hash = "a=" + id;
  }

  function areaChip(area) {
    if (!area) return h("span");
    return h("span", { class: "chip area-chip", title: "Area: " + area.name, text: area.name });
  }

  function areaRow(area) {
    return h("button", { class: "row", type: "button", onclick: () => openArea(area.id) },
      h("span", { class: "name", text: area.name }),
      h("span", { class: "chip", text: plural(area.size, "function or class", "functions and classes") }),
      h("span", { class: "where", text: area.where + " · " + plural(area.files, "file", "files") }),
      h("div", { class: "say", text: plural(area.links_inside, "link", "links") + " inside, " + plural(area.links_out, "link", "links") + " to other areas." }));
  }

  function matchesArea(area, text) {
    if (!text) return true;
    return area.name.toLowerCase().includes(text) || area.where.toLowerCase().includes(text);
  }

  async function renderAreasPage(main) {
    main.append(h("h1", { text: "Areas" }),
      h("p", { class: "lede", text: "Functions and classes that work together, grouped folder by folder. Each area is named after its folder and the member the rest of the code depends on most, and keeps its number when the code changes a little. Test code is not grouped." }));
    const filter = h("input", { class: "area-filter", type: "search", placeholder: "Filter areas by name or folder", autocomplete: "off", "aria-label": "Filter areas" });
    const list = h("div", { class: "list" });
    main.append(filter, list);
    let areas;
    try { areas = await allAreas(); } catch (err) { list.append(h("div", { class: "notice", text: err.message })); return; }
    const draw = () => {
      const text = filter.value.trim().toLowerCase();
      const shown = areas.filter((area) => matchesArea(area, text));
      list.replaceChildren(...shown.slice(0, 300).map(areaRow));
      if (shown.length > 300) list.append(h("div", { class: "notice", text: "Showing 300 of " + shown.length + ". Type to narrow the list." }));
      if (!shown.length) list.append(h("div", { class: "notice", text: "No areas match." }));
    };
    filter.addEventListener("input", draw);
    draw();
  }

  async function showArea(id) {
    let area;
    try { area = await areaData(id); } catch (err) { toast(err.message); return; }
    markMode("areas");
    state.selected = null;
    closeCard();
    const main = $("main");
    main.className = "main";
    const hub = area.members.find((m) => m.id === area.hub);
    let lede = "Mostly in " + area.where + ".";
    if (hub) lede += " Named after the member the rest of the code depends on most, " + hub.name + ".";
    main.replaceChildren(
      h("div", { class: "lens-head" }, h("span", { class: "kind k-area", text: "area" }), h("h1", { text: area.name })),
      h("p", { class: "lede", text: lede }),
      h("div", { class: "stats" },
        stat(area.size, "functions and classes"),
        stat(area.files, "files"),
        stat(area.links_inside, "links inside"),
        stat(area.links_out, "links to other areas"),
        stat((area.cohesion * 100).toFixed(1) + "%", "of possible links inside exist")));
    if (area.linked_areas.length) {
      main.append(h("h2", { text: "Linked areas" }));
      main.append(h("div", { class: "list" }, area.linked_areas.map((other) => h("button", { class: "row", type: "button", onclick: () => openArea(other.id) },
        h("span", { class: "name", text: other.name }),
        h("span", { class: "chip", text: plural(other.links, "link", "links") }),
        h("span", { class: "where", text: other.where })))));
    }
    main.append(h("h2", { text: "Members, most important first" }));
    if (area.members_total > area.members.length) main.append(h("p", { class: "lede", text: "Showing the " + area.members.length + " most important of " + area.members_total + "." }));
    main.append(h("div", { class: "list" }, area.members.map((item) => itemRow(item))));
    main.focus({ preventScroll: true });
  }

  function summaryLine(item) {
    if (item.summary) return h("div", { class: "say", text: item.summary });
    return h("div", { class: "say none", text: "No plain-English description yet." });
  }

  function itemRow(item, extra) {
    return h("button", { class: "row", type: "button", onclick: () => select(item.id) },
      h("span", { class: "name" }, kindChip(item.kind, item.is_test), " ", item.name),
      extra || h("span"),
      h("span", { class: "where", text: item.file + ":" + item.line }),
      summaryLine(item));
  }

  function renderOverview(main) {
    const data = state.overview;
    const info = data.overview;
    const total = info.functions + info.methods + info.classes;
    main.append(
      h("h1", { text: info.repo || "Codebase" }),
      h("p", { class: "lede", text: "Every function and class in this repository, what calls what, and what each one does in plain English. Click anything to see it in context." }),
      h("div", { class: "stats" },
        stat(info.files, "files mapped"),
        stat(info.functions + info.methods, "functions and methods"),
        stat(info.classes, "classes"),
        stat(info.links, "links between them"),
        stat(info.described + " / " + total, "described in plain English")));
    const notices = [];
    if (info.described === 0) {
      notices.push(h("div", { class: "notice" }, "No descriptions yet. Run ", h("code", { text: "skylos graph describe" }),
        " with your own model key, or ask your coding agent to fill them in with ", h("code", { text: "skylos graph pending" }), "."));
    } else if (info.stale_descriptions) {
      notices.push(h("div", { class: "notice", text: info.stale_descriptions + " descriptions are out of date because the code changed. Run skylos graph describe to refresh them." }));
    }
    const missing = Object.entries((info.coverage || {}).not_mapped || {});
    if (missing.length) {
      notices.push(h("div", { class: "notice", text: "Not mapped yet: " + missing.map(([lang, n]) => lang + " (" + n + " files)").join(", ") + ". The graph covers Python, TypeScript, JavaScript, Go, Java, Rust and PHP." }));
    }
    if (info.name_links) {
      notices.push(h("div", { class: "notice", text: "Go, Java, Rust and PHP links (" + info.name_links + ") are matched by name only, so some point at the wrong function. They are drawn as faint dashed lines and listed under \"Possibly used by\" and \"Possibly uses\"." }));
    }
    const failed = ((info.coverage || {}).failed || []).length;
    if (failed) notices.push(h("div", { class: "notice", text: failed + " files could not be read and are left out." }));
    if (notices.length) main.append(h("div", { class: "list gap-top" }, notices));
    main.append(h("h2", { text: "Start here" }),
      h("p", { class: "lede", text: "Top-level entry points: nothing else in the repository calls them, and they reach the most code." }));
    let entries = [h("div", { class: "notice", text: "No entry points found." })];
    if (data.entry_points.length) entries = data.entry_points.map((item) => itemRow(item, h("span", { class: "chip v-new", text: "reaches " + item.reaches })));
    main.append(h("div", { class: "list" }, entries));
    if ((data.important || []).length) {
      main.append(h("h2", { text: "Most important" }),
        h("p", { class: "lede", text: "Code the rest of the repository depends on most: scored from how much code leads into it, how often entry points reach it, how much it reaches, and how many tests check it. Test code is left out." }));
      main.append(h("div", { class: "list" }, data.important.map((item) => itemRow(item, areaChip(item.area)))));
    }
    main.append(h("h2", { text: "Most used" }));
    main.append(h("div", { class: "list" }, data.hubs.map((item) => itemRow(item, h("span", { class: "chip", text: "used by " + item.used_by })))));
    if ((data.areas || []).length) {
      main.append(h("h2", { text: "Largest areas · " + info.areas + " in all" }),
        h("p", { class: "lede", text: "Functions and classes that work together, grouped folder by folder and named after the member the rest of the code depends on most." }));
      main.append(h("div", { class: "list" }, data.areas.map(areaRow)));
      if (info.areas > data.areas.length) main.append(h("p", null, h("button", { class: "linkbtn", type: "button", onclick: () => setMode("areas") }, "See all " + info.areas + " areas")));
    }
  }

  function stat(value, label) {
    return h("div", { class: "stat" }, h("b", { text: String(value) }), h("span", { text: label }));
  }

  function renderChanges(main) {
    const changes = state.overview.changes;
    if (!changes) {
      main.append(h("div", { class: "notice" }, "No comparison yet. Run ", h("code", { text: "skylos graph --since main" }), "."));
      return;
    }
    const bucketCount = (name) => changes.rows.filter((r) => r.review === name).length;
    const bucketLines = (name) => changes.rows.filter((r) => r.review === name).reduce((sum, r) => sum + (r.lines_changed || 0), 0);
    const readLines = bucketLines("read_first") + bucketLines("read");
    const allLines = readLines + bucketLines("skim") + bucketLines("skip");
    let commit = "";
    if (changes.base_commit) commit = " (" + changes.base_commit.slice(0, 8) + ")";
    main.append(
      h("h1", { text: "Changes since " + changes.base + commit }),
      h("p", { class: "lede", text: "What to read in this change. Skip is shown only when Skylos can prove the logic is the same: only local names renamed, or only the docstring edited. Moved code is skim: its import path changed." }),
      h("div", { class: "stats" },
        stat(bucketCount("read_first"), "read first"),
        stat(bucketCount("read"), "read"),
        stat(bucketCount("skim"), "skim"),
        stat(bucketCount("skip"), "skip: same logic"),
        stat(readLines + " / " + allLines, "changed lines to read")));
    const groups = [
      ["Read first", (r) => r.review === "read_first"],
      ["Read", (r) => r.review === "read"],
      ["Skim", (r) => r.review === "skim"],
      ["Skip: same logic, proven", (r) => r.review === "skip"],
    ];
    if (!changes.rows.length) main.append(h("div", { class: "notice", text: "No functions or classes changed." }));
    for (const [title, test] of groups) {
      const rows = changes.rows.filter(test);
      if (!rows.length) continue;
      main.append(h("h2", { text: title + " · " + rows.length }));
      main.append(h("div", { class: "list" }, rows.map(changeRow)));
    }
  }

  const STATE_WORDS = {
    pass: "Pass",
    fail: "Fail",
    warn: "Warn",
    unfinished: "Unfinished",
    skipped: "Skipped",
    not_run: "Not run",
  };

  function boxText(stage) {
    if (stage.label) return stage.label;
    return STATE_WORDS[stage.state] || stage.state;
  }

  function when(iso) {
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return iso;
    return date.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  }

  async function renderPipeline(main) {
    main.append(
      h("h1", { text: "Pipeline" }),
      h("p", { class: "lede", text: "Every skylos done run in this repository, newest first, stage by stage. Click a box to see what that stage found. When something failed, Copy fix brief gives your coding agent the exact problems to fix." }),
      checkPanel());
    const holder = h("div", { class: "pipe-holder" }, h("div", { class: "notice", text: "Loading runs…" }));
    main.append(holder);
    let data;
    try { data = await api("/api/pipeline"); } catch (err) { holder.replaceChildren(h("div", { class: "notice", text: err.message })); return; }
    if (state.mode !== "pipeline") return;
    const refresh = h("button", { class: "pipe-refresh", type: "button", text: "Refresh", onclick: () => renderMain() });
    if (!data.runs.length) {
      holder.replaceChildren(h("div", { class: "notice" }, "No runs yet. In this repository run ", h("code", { text: data.start }), " and the run appears here. ", refresh));
      return;
    }
    const used = data.columns.filter((col) => col.key !== "other" || data.runs.some((run) => stageOf(run, "other").state !== "not_run"));
    const detail = h("div", { class: "pipe-detail", id: "pipe-detail", tabindex: "-1" });
    const head = h("tr", {}, h("th", { scope: "col", text: "Run" }), used.map((col) => h("th", { scope: "col", text: col.title })));
    const body = h("tbody", {}, data.runs.map((run) => h("tr", {},
      h("th", { scope: "row", class: "pipe-run" },
        h("span", { class: "pipe-when", text: when(run.when) }),
        h("span", { class: "pipe-sha", text: runLabel(run) }),
        h("span", { class: "pipe-agent", text: run.agent })),
      used.map((col) => h("td", {}, stageBox(run, stageOf(run, col.key), detail))))));
    let note = null;
    if (data.unreadable) note = h("p", { class: "pipe-note", text: data.unreadable + " receipt file(s) could not be read and are left out." });
    holder.replaceChildren(
      h("div", { class: "pipe-bar" }, h("span", { text: data.runs.length + " run(s)" }), refresh),
      h("div", { class: "pipe-scroll" }, h("table", { class: "pipe" }, h("thead", {}, head), body)),
      note || "",
      detail);
    showStage(data.runs[0], stageOf(data.runs[0], "verdict"), detail);
  }

  function stageOf(run, key) {
    return run.stages.find((stage) => stage.key === key) || { key, title: key, state: "not_run", count: 0 };
  }

  function runLabel(run) {
    if (run.dirty) return run.head + " (edited)";
    return run.head;
  }

  function where(item) {
    let text = item.file || "";
    if (item.line) text += ":" + item.line;
    return text;
  }

  function stageBox(run, stage, detail) {
    const parts = [h("span", { class: "box-state", text: boxText(stage) })];
    let label = stage.title + ": " + boxText(stage);
    if (stage.count) {
      parts.push(h("span", { class: "box-count", text: String(stage.count) }));
      label += ", " + stage.count + " found";
    }
    return h("button", {
      class: "box s-" + stage.state,
      type: "button",
      "aria-label": label + ", run " + run.head,
      onclick: () => showStage(run, stage, detail),
    }, parts);
  }

  function showStage(run, stage, detail) {
    const items = [h("h2", { text: stage.title + " · " + boxText(stage) }),
      h("p", { class: "pipe-meta", text: "Run " + runLabel(run) + " compared with " + run.base + " · " + when(run.when) + " · agent: " + run.agent })];
    const checks = stage.checks || [];
    if (stage.key === "review") items.push(reviewDetail(stage));
    else if (!checks.length) items.push(h("p", { class: "pipe-empty", text: stageEmptyText(stage) }));
    for (const check of checks) items.push(checkDetail(check));
    if (run.brief) {
      const copy = h("button", { class: "pipe-copy", type: "button", text: "Copy fix brief", onclick: () => copyBrief(run.brief) });
      items.push(h("div", { class: "pipe-brief" }, h("div", { class: "pipe-brief-head" }, h("b", { text: "Fix brief for your coding agent" }), copy), h("pre", { text: run.brief })));
    }
    items.push(h("p", { class: "pipe-rerun" }, "Run it again: ", h("code", { text: run.rerun })));
    detail.replaceChildren(...items);
  }

  function stageEmptyText(stage) {
    if (stage.key === "verdict") return "The overall result of this run. Click any box to its left for details.";
    return "Skylos did not run this stage in this run.";
  }

  function reviewDetail(stage) {
    if (!stage.review) return h("p", { class: "pipe-empty", text: stage.hint });
    const first = stage.review.read_first || [];
    let list = h("p", { class: "pipe-empty", text: "Nothing to read first." });
    if (first.length) list = h("ul", { class: "pipe-findings" }, first.map((item) => h("li", {}, h("b", { text: item.name }), " " + where(item) + " — " + (item.why || ""))));
    return h("div", { class: "pipe-check" },
      h("p", { text: stage.hint }),
      list,
      h("p", { class: "pipe-hint" }, "Open the Changes tab for the full read, skim and skip lists."));
  }

  function checkDetail(check) {
    const headParts = [h("span", { class: "chip s-" + check.state, text: check.word }), h("b", { text: check.label })];
    if (check.rule) headParts.push(h("span", { class: "pipe-rule", text: check.rule }));
    const parts = [h("div", { class: "pipe-check-head" }, headParts)];
    if (check.problem) parts.push(h("p", { class: "pipe-empty", text: "Not checked: " + check.problem }));
    if (check.findings.length) {
      parts.push(h("ul", { class: "pipe-findings" }, check.findings.map((item) => h("li", {},
        h("code", { text: where(item) }), " " + (item.message || "")))));
    }
    if (check.more) parts.push(h("p", { class: "pipe-hint", text: "…and " + check.more + " more in the receipt." }));
    if (check.fix) parts.push(h("p", { class: "pipe-fix", text: "Fix: " + check.fix }));
    return h("div", { class: "pipe-check" }, parts);
  }

  async function copyBrief(text) {
    try {
      await navigator.clipboard.writeText(text);
      toast("Fix brief copied. Paste it to your coding agent.");
    } catch (err) {
      toast("Could not copy. Select the brief and copy it by hand.");
    }
  }

  function changeRow(row) {
    let lines = [].concat(row.reasons || [], row.evidence || []).slice(0, 3);
    if (row.review === "skim" || row.review === "skip") lines = [];
    let say = row.verdict_text;
    if (row.review_why && row.review_why !== row.verdict_text) say = row.review_why;
    const known = say.toLowerCase();
    lines = lines.filter((line) => !known.includes(String(line).toLowerCase()));
    const open = () => {
      if (row.node_id) select(row.node_id);
      else location.hash = "c=" + encodeURIComponent(row.id);
    };
    return h("button", { class: "row", type: "button", onclick: open },
      h("span", { class: "name", text: row.name }),
      h("span", { class: "chip " + vclass(row.verdict, row.flagged), text: verdictLabel(row.verdict, row.flagged) }),
      h("span", { class: "where", text: row.file }),
      h("div", { class: "say", text: [say].concat(lines.map(sentence)).join(" ") }));
  }

  function buildTree(files) {
    const root = { dirs: {}, files: [] };
    for (const file of files) {
      const parts = file.file.split("/");
      let node = root;
      for (const part of parts.slice(0, -1)) {
        node.dirs[part] = node.dirs[part] || { dirs: {}, files: [] };
        node = node.dirs[part];
      }
      node.files.push(file);
    }
    return root;
  }

  function collapse(name, node) {
    let label = name;
    while (Object.keys(node.dirs).length === 1 && node.files.length === 0) {
      const [child, next] = Object.entries(node.dirs)[0];
      label += "/" + child;
      node = next;
    }
    return [label, node];
  }

  function countFiles(node) {
    let total = node.files.length;
    for (const child of Object.values(node.dirs)) total += countFiles(child);
    return total;
  }

  function renderDir(node, open) {
    const box = h("div");
    for (const [name, child] of Object.entries(node.dirs).sort()) {
      const [label, inner] = collapse(name, child);
      const details = h("details", { class: "dir", open: open },
        h("summary", null, h("span", { class: "fname", text: label }), h("span", { class: "count", text: String(countFiles(inner)) })));
      details.append(renderDir(inner, open));
      box.append(details);
    }
    for (const file of node.files.sort((a, b) => a.file.localeCompare(b.file))) {
      const base = file.file.split("/").pop();
      const details = h("details", { class: "file", "data-file": file.file },
        h("summary", { title: file.file },
          changedDot(file),
          h("span", { class: "fname", text: base }),
          h("span", { class: "count", text: String(file.symbols) })));
      const body = h("div");
      details.append(body);
      details.addEventListener("toggle", () => { if (details.open) fillFile(file.file, body); });
      box.append(details);
    }
    return box;
  }

  async function fillFile(path, body) {
    if (body.dataset.loaded) return;
    body.dataset.loaded = "1";
    const data = state.filesLoaded[path] || await api("/api/file?path=" + encodeURIComponent(path));
    state.filesLoaded[path] = data;
    body.replaceChildren(...data.symbols.map((sym) => h("div", {
      class: symClass(sym),
      "data-id": sym.id,
      title: sym.name,
      onclick: () => select(sym.id),
    }, h("span", { class: ("dot " + vclass(sym.verdict)).trim() }),
      h("span", { class: "kind k-" + sym.kind, text: sym.kind[0] }), " ", sym.name)));
  }

  function renderTree() {
    if (state.group === "areas") {
      renderAreaTree();
      return;
    }
    const filter = state.filter.toLowerCase();
    const files = state.files.filter((f) => (state.showTests || !f.is_test) && (!filter || f.file.toLowerCase().includes(filter)));
    const tree = $("tree");
    tree.replaceChildren(renderDir(buildTree(files), Boolean(filter) || files.length < 60));
    if (!files.length) tree.append(h("div", { class: "notice", text: "No files match." }));
  }

  async function renderAreaTree() {
    const tree = $("tree");
    let areas;
    try { areas = await allAreas(); } catch (err) { tree.replaceChildren(h("div", { class: "notice", text: err.message })); return; }
    if (state.group !== "areas") return;
    const filter = state.filter.trim().toLowerCase();
    const shown = areas.filter((area) => matchesArea(area, filter));
    const box = h("div");
    for (const area of shown.slice(0, 400)) {
      const details = h("details", { class: "dir", "data-area": area.id },
        h("summary", { title: area.name + " · " + area.where }, h("span", { class: "fname", text: area.name }), h("span", { class: "count", text: String(area.size) })));
      const body = h("div");
      details.append(body);
      details.addEventListener("toggle", () => { if (details.open) fillArea(area.id, body); });
      box.append(details);
    }
    tree.replaceChildren(box);
    if (shown.length > 400) tree.append(h("div", { class: "say-src", text: "Showing 400 of " + shown.length + " areas. Type to narrow." }));
    if (!shown.length) tree.append(h("div", { class: "notice", text: "No areas match." }));
  }

  async function fillArea(id, body) {
    if (body.dataset.loaded) return;
    body.dataset.loaded = "1";
    let area;
    try { area = await areaData(id); } catch (err) { body.append(h("div", { class: "say-src", text: err.message })); return; }
    const byFile = new Map();
    for (const member of area.members) {
      if (!byFile.has(member.file)) byFile.set(member.file, []);
      byFile.get(member.file).push(member);
    }
    const open = byFile.size === 1;
    body.append(h("button", { class: "linkbtn tree-open", type: "button", onclick: () => openArea(id) }, "Open area"));
    for (const [file, members] of [...byFile.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
      const details = h("details", { class: "file", open: open },
        h("summary", { title: file }, h("span", { class: "fname", text: file.split("/").pop() }), h("span", { class: "count", text: String(members.length) })));
      const list = h("div");
      members.sort((a, b) => a.line - b.line);
      list.append(...members.map((sym) => h("div", { class: symClass(sym), "data-id": sym.id, title: sym.name, onclick: () => select(sym.id) },
        h("span", { class: "kind k-" + sym.kind, text: sym.kind[0] }), " ", sym.name)));
      details.append(list);
      body.append(details);
    }
    if (area.members_total > area.members.length) body.append(h("div", { class: "say-src", text: "Showing the " + area.members.length + " most important of " + area.members_total + "." }));
  }

  function setGroup(group) {
    state.group = group;
    $("group-folders").classList.toggle("on", group === "folders");
    $("group-areas").classList.toggle("on", group === "areas");
    $("group-folders").setAttribute("aria-pressed", String(group === "folders"));
    $("group-areas").setAttribute("aria-pressed", String(group === "areas"));
    let placeholder = "Filter files";
    if (group === "areas") placeholder = "Filter areas";
    $("tree-filter").placeholder = placeholder;
    renderTree();
  }

  function byName(count) {
    if (!count) return "";
    return " (" + count + " matched by name)";
  }

  function callersTitle(lens) {
    if (!lens.callers_total) return "Nothing in the repository calls this";
    const tests = lens.callers_tests || 0;
    const code = lens.callers_total - tests;
    let title = "Used by · " + code + " + " + tests + " tests";
    if (!tests) title = "Used by · " + code;
    if (!code) title = "Used only by tests · " + tests;
    return title + byName(lens.callers_name);
  }

  function lensLayout(lens, width) {
    const gap = 12, boxH = 46, bandGap = 58, pad = 18, label = 20;
    let boxW = 172;
    let perRow = Math.max(1, Math.floor((width - pad * 2 + gap) / (boxW + gap)));
    if (perRow < 4) {
      boxW = Math.max(124, Math.floor((width - pad * 2 - gap * 3) / 4));
      perRow = Math.max(1, Math.floor((width - pad * 2 + gap) / (boxW + gap)));
    }
    const bands = [];
    if (lens.callers2.length) bands.push({ key: "callers2", title: "2 steps above", items: lens.callers2, total: lens.callers2.length });
    bands.push({ key: "callers", title: callersTitle(lens), items: lens.callers, total: lens.callers_total });
    bands.push({ key: "center", title: "", items: [lens.center], total: 1 });
    let calleesTitle = "Calls nothing else in the repository";
    if (lens.callees_total) calleesTitle = "Uses · " + lens.callees_total + byName(lens.callees_name);
    bands.push({ key: "callees", title: calleesTitle, items: lens.callees, total: lens.callees_total });
    if (lens.callees2.length) bands.push({ key: "callees2", title: "2 steps below", items: lens.callees2, total: lens.callees2.length });
    const placed = {};
    let y = pad;
    for (const band of bands) {
      band.y = y;
      if (band.title) y += label;
      let shown = band.items.slice(0, perRow);
      let extra = Math.max(0, (band.total || 0) - shown.length);
      if (extra > 0 && shown.length === perRow) {
        shown = shown.slice(0, perRow - 1);
        extra = (band.total || 0) - shown.length;
      }
      let count = shown.length;
      if (extra) count += 1;
      const rowWidth = Math.max(0, count * boxW + (count - 1) * gap);
      const left = (width - rowWidth) / 2;
      band.boxes = [];
      placed[band.key] = {};
      shown.forEach((item, i) => {
        const box = { x: left + i * (boxW + gap), y, item, band: band.key };
        band.boxes.push(box);
        placed[band.key][item.id] = box;
      });
      if (extra) band.boxes.push({ x: left + shown.length * (boxW + gap), y, more: extra, band: band.key });
      if (count) y += boxH + bandGap;
      else y += bandGap - 20;
    }
    return { bands, placed, height: y - bandGap + pad + 6, boxW, boxH };
  }

  function edgePath(x1, y1, x2, y2) {
    const mid = (y1 + y2) / 2;
    return "M" + x1 + "," + y1 + " C" + x1 + "," + mid + " " + x2 + "," + mid + " " + x2 + "," + y2;
  }

  let lensObserver = null;
  let lensWidth = 0;

  function watchLens(box) {
    if (lensObserver) lensObserver.disconnect();
    if (!window.ResizeObserver) return;
    lensObserver = new ResizeObserver(() => {
      const width = Math.round(box.clientWidth);
      if (Math.abs(width - lensWidth) > 8 && state.card) renderLens(box, state.card.lens);
    });
    lensObserver.observe(box);
  }

  function renderLens(container, lens) {
    const width = Math.max(420, container.clientWidth || 800);
    lensWidth = Math.round(width);
    const layout = lensLayout(lens, width);
    const { boxW, boxH, placed } = layout;
    const root = svg("svg", { viewBox: "0 0 " + width + " " + layout.height, width: width, height: layout.height, role: "img", "aria-label": "Callers above, " + lens.center.name + " in the middle, what it uses below" });
    const edges = svg("g");
    const nodes = svg("g");
    root.append(edges, nodes);
    const center = layout.bands.find((b) => b.key === "center").boxes[0];
    const link = (from, to, kind, match) => {
      let cls = "edge " + (kind || "");
      if (match === "name") cls += " name";
      edges.append(svg("path", { class: cls, d: edgePath(from.x + boxW / 2, from.y + boxH, to.x + boxW / 2, to.y) }));
    };
    for (const band of layout.bands) {
      if (band.title) nodes.append(svg("text", { class: "band", x: 18, y: band.y + 12, text: band.title }));
      for (const box of band.boxes) {
        if (box.more) {
          let target = "uses";
          if (band.key === "callers" || band.key === "callers2") target = "used-by";
          const more = svg("g", { class: "more node", transform: "translate(" + box.x + "," + box.y + ")", onclick: () => { const t = document.getElementById(target); if (t) t.scrollIntoView({ behavior: "smooth" }); } },
            svg("rect", { width: boxW, height: boxH, rx: 7 }),
            svg("text", { x: 12, y: 28, text: "+" + box.more + " more in the list" }));
          nodes.append(more);
          continue;
        }
        const item = box.item;
        if (band.key === "callers") link(box, center, item.edge, item.match);
        if (band.key === "callees") link(center, box, item.edge, item.match);
        if (band.key === "callers2" && placed.callers && placed.callers[item.via]) link(box, placed.callers[item.via], item.edge, item.match);
        if (band.key === "callees2" && placed.callees && placed.callees[item.via]) link(placed.callees[item.via], box, item.edge, item.match);
        let classes = "node";
        let tabindex = 0;
        if (band.key === "center") { classes += " center"; tabindex = -1; }
        if (item.is_test) classes += " test";
        if (item.match === "name") classes += " named";
        const g = svg("g", { class: classes, transform: "translate(" + box.x + "," + box.y + ")", tabindex: tabindex, role: "button" });
        let tipText = item.name;
        if (item.match === "name") tipText += "\n" + NAME_MATCH_NOTE;
        if (item.summary) tipText += "\n\n" + item.summary;
        const tip = svg("title", { text: tipText });
        g.append(tip, svg("rect", { width: boxW, height: boxH, rx: 7 }));
        const chars = Math.max(10, Math.floor((boxW - 30) / 7));
        g.append(svg("text", { x: 12, y: 19, text: clip(shortName(item.name), chars) }));
        g.append(svg("text", { class: "sub", x: 12, y: 35, text: clip(owner(item.name) || item.file.split("/").pop(), chars + 4) }));
        if (item.verdict) {
          const tone = vclass(item.verdict);
          const colors = { "v-same": "var(--same)", "v-changed": "var(--changed)", "v-flag": "var(--flag)", "v-new": "var(--new)", "v-removed": "var(--removed)" };
          g.append(svg("circle", { cx: boxW - 12, cy: 12, r: 4.5, fill: colors[tone] || "var(--faint)" }));
        }
        if (band.key !== "center") {
          g.addEventListener("click", () => select(item.id));
          g.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); select(item.id); } });
        }
        nodes.append(g);
      }
    }
    container.replaceChildren(root);
  }

  async function showNode(id) {
    let card;
    try {
      card = await api("/api/node?id=" + encodeURIComponent(id) + "&depth=" + state.depth);
    } catch (err) {
      toast(err.message);
      return;
    }
    state.selected = id;
    state.card = card;
    if (state.mode === "graph") markMode("map");
    const node = card.node;
    const main = $("main");
    main.replaceChildren();
    main.className = "main";
    const seg = h("div", { class: "seg", role: "group", "aria-label": "How far to show" },
      depthButton(id, 1, "1 step"),
      depthButton(id, 2, "2 steps"));
    main.append(h("div", { class: "lens-head" }, kindChip(node.kind, node.is_test), h("h1", { text: node.name }), seg));
    const lensBox = h("div", { class: "lens" });
    main.append(lensBox,
      h("div", { class: "legend" },
        h("span", null, h("i"), "calls"),
        h("span", null, h("i", { class: "creates" }), "creates"),
        h("span", null, h("i", { class: "uses" }), "uses the type"),
        h("span", null, h("i", { class: "inherits" }), "inherits from"),
        h("span", null, h("i", { class: "name" }), "matched by name only"),
        h("span", { text: "Dashed box: test code" })));
    renderCard(card);
    requestAnimationFrame(() => renderLens(lensBox, card.lens));
    watchLens(lensBox);
    markTree(id, node.file);
    main.focus({ preventScroll: true });
  }

  function markTree(id, file) {
    document.querySelectorAll(".sym.active").forEach((el) => el.classList.remove("active"));
    const fileEl = document.querySelector('.file[data-file="' + CSS.escape(file) + '"]');
    if (fileEl) {
      let parent = fileEl.parentElement;
      while (parent && parent.id !== "tree") {
        if (parent.tagName === "DETAILS") parent.open = true;
        parent = parent.parentElement;
      }
      fileEl.open = true;
      setTimeout(() => {
        const sym = document.querySelector('.sym[data-id="' + CSS.escape(id) + '"]');
        if (sym) { sym.classList.add("active"); sym.scrollIntoView({ block: "nearest" }); }
      }, 120);
    }
  }

  function openCard() {
    $("card").hidden = false;
    document.querySelector(".layout").classList.add("with-card");
  }

  function closeCard() {
    $("card").hidden = true;
    document.querySelector(".layout").classList.remove("with-card");
  }

  function sourceLabel(source) {
    if (!source) return "";
    if (source === "human") return "Written by a person";
    if (source === "agent") return "Written by your coding agent";
    if (source.startsWith("key:")) return "Written by " + source.slice(4) + " with your key";
    if (source.startsWith("skylos:")) return "Written by Skylos (" + source.slice(7) + ")";
    return source;
  }

  function linkList(id, items, empty) {
    if (!items.length) return h("div", { class: "say-missing", text: empty });
    return h("ul", { class: "links", id }, items.map((item) => h("li", { onclick: () => select(item.id), title: item.id },
      kindChip(item.kind, item.is_test), " ", item.name,
      item.match === "name" && h("span", { class: "tag-name", title: NAME_MATCH_NOTE, text: "by name" }),
      h("span", { class: "sub", text: clip(item.summary, 140) || item.file + ":" + item.line }))));
  }

  function nameSection(title, id, items) {
    if (!items || !items.length) return null;
    return h("section", null,
      h("h3", null, title, h("span", { class: "n", text: String(items.length) })),
      h("div", { class: "say-src name-note", text: NAME_MATCH_NOTE }),
      linkList(id, items, ""));
  }

  function areaLine(area, nodeId) {
    if (!area) return null;
    const open = () => {
      if (state.mode === "graph") location.hash = "g=" + area.id + "&n=" + encodeURIComponent(nodeId);
      else openArea(area.id);
    };
    return h("div", { class: "area-line" }, "Area: ",
      h("button", { class: "linkbtn", type: "button", onclick: open }, area.name));
  }

  function codeBlock(text, start) {
    const pre = h("pre", { class: "code" });
    text.split("\n").forEach((line, i) => pre.append(h("span", { class: "l" }, h("span", { class: "ln", text: String(start + i) }), line)));
    return pre;
  }

  function diffLines(a, b) {
    const x = a.split("\n").slice(0, 400), y = b.split("\n").slice(0, 400);
    const n = x.length, m = y.length;
    const dp = Array.from({ length: n + 1 }, () => new Uint16Array(m + 1));
    for (let i = n - 1; i >= 0; i--) {
      for (let j = m - 1; j >= 0; j--) {
        if (x[i] === y[j]) dp[i][j] = dp[i + 1][j + 1] + 1;
        else dp[i][j] = Math.max(dp[i + 1][j], dp[i][j + 1]);
      }
    }
    const out = [];
    let i = 0, j = 0;
    while (i < n && j < m) {
      if (x[i] === y[j]) { out.push([" ", x[i]]); i++; j++; }
      else if (dp[i + 1][j] >= dp[i][j + 1]) out.push(["-", x[i++]]);
      else out.push(["+", y[j++]]);
    }
    while (i < n) out.push(["-", x[i++]]);
    while (j < m) out.push(["+", y[j++]]);
    const pre = h("pre", { class: "code" });
    for (const [mark, line] of out) {
      let lineClass = "l";
      if (mark === "+") lineClass += " add";
      if (mark === "-") lineClass += " del";
      pre.append(h("span", { class: lineClass }, h("span", { class: "ln", text: mark.trim() }), line));
    }
    return pre;
  }

  function changeSection(change, note) {
    const flagged = (state.overview.changes && (state.overview.changes.rows || []).some((r) => r.id === change.id && r.flagged));
    const label = verdictLabel(change.verdict, flagged);
    const chips = h("div", { class: "chips" }, h("span", { class: "chip " + vclass(change.verdict, flagged), text: label }));
    if (change.review) chips.append(h("span", { class: "chip rv-chip rv-" + change.review, text: reviewWord(change.review) }));
    const box = h("div", { class: "change" }, chips);
    if (change.verdict_text !== label + ".") box.append(h("p", { class: "verdict-text", text: change.verdict_text }));
    if (change.review_why && change.review_why !== change.verdict_text) box.append(h("p", { class: "verdict-text", text: sentence(change.review_why) }));
    const facts = [].concat(change.reasons || [], change.evidence || []);
    if (facts.length) box.append(h("ul", null, facts.map((f) => h("li", { text: sentence(f) }))));
    if (note) {
      const ai = h("div", { class: "ai" }, h("div", { class: "tag", text: "AI's reading · not proof · " + sourceLabel(note.source) }));
      if (note.before) ai.append(h("div", null, h("b", { text: "Before: " }), note.before));
      if (note.after) ai.append(h("div", null, h("b", { text: "After: " }), note.after));
      const answer = { yes: "Yes, same results for every input.", no: "No, some inputs now behave differently.", unclear: "Can't tell from the code." }[note.same_behaviour];
      if (answer) ai.append(h("div", null, h("b", { text: "Same behaviour? " }), answer));
      if (note.why) ai.append(h("div", null, h("b", { text: "Why: " }), note.why));
      box.append(ai);
    }
    const before = (change.before || {}).code || "";
    const after = (change.after || {}).code || "";
    if (before || after) {
      const holder = h("div", { class: "diff-holder" });
      const toggle = h("button", { class: "linkbtn", type: "button", onclick: () => {
        if (holder.childElementCount) { holder.replaceChildren(); toggle.textContent = "Show before and after"; }
        else { holder.append(diffLines(before, after)); toggle.textContent = "Hide before and after"; }
      } }, "Show before and after");
      box.append(h("div", { class: "diff-toggle" }, toggle), holder);
    }
    return h("section", null, h("h3", { text: "What changed" }), box);
  }

  function currentDescription(card) {
    const description = card.description || null;
    if (description && description.now) return description.now;
    if (card.note) return { text: card.note.text, source: card.note.source, stale: card.note.stale };
    return null;
  }

  function describeSection(card) {
    const node = card.node;
    const now = currentDescription(card);
    const section = h("section", null, h("h3", { text: "What it does" }));
    const body = h("div");
    let editLabel = "Write one";
    if (now) editLabel = "Edit";
    const editBtn = h("button", { class: "linkbtn", type: "button", onclick: () => startEdit(body, node, now) }, editLabel);
    if (now && !now.stale) {
      body.append(h("p", { class: "say-big", text: now.text }), h("div", { class: "say-src" }, sourceLabel(now.source), " · ", editBtn));
    } else if (now && now.stale) {
      body.append(h("p", { class: "say-big say-stale", text: now.text }),
        h("div", { class: "say-src" }, h("span", { class: "stale-tag", text: "Out of date" }), " The code changed after this was written. · ", editBtn));
    } else {
      if (node.doc) body.append(h("p", { class: "say-big", text: node.doc }), h("div", { class: "say-src", text: "From the docstring" }));
      body.append(h("div", { class: "say-missing gap-top-sm" }, "No plain-English description yet. Run ", h("code", { text: "skylos graph describe" }), " or ", editBtn, "."));
    }
    section.append(body);
    return section;
  }

  function beforeSection(card) {
    const before = (card.description || {}).before;
    if (!before || !before.text) return null;
    return h("section", null,
      h("h3", { text: "Before this change it did" }),
      h("p", { class: "say-before", text: before.text }),
      h("div", { class: "say-src", text: sourceLabel(before.source) }));
  }

  function stepsText(steps) {
    if (steps === 1) return "calls it directly";
    return steps + " calls away";
  }

  function affectsSection(card) {
    const note = card.change_note;
    const preview = (card.impact_preview || []).filter((row) => !row.is_test);
    let effects = [];
    if (note && Array.isArray(note.impact)) effects = note.impact.filter((row) => row && row.id && row.effect);
    const section = h("section", null, h("h3", null, "What it affects"));
    if (effects.length) {
      const known = new Map(preview.map((row) => [row.id, row]));
      section.querySelector("h3").append(h("span", { class: "n", text: String(effects.length) }));
      section.append(h("div", { class: "say-src name-note", text: "How this change reaches the code that calls it. AI's reading, not proof." }),
        h("ul", { class: "links affects" }, effects.map((row) => {
          const other = known.get(row.id) || {};
          const name = row.name || other.name || shortName(row.id);
          return h("li", { onclick: () => select(row.id), title: row.id }, h("b", { text: name }), h("span", { class: "sub effect", text: row.effect }));
        })));
      return section;
    }
    if (preview.length) {
      section.querySelector("h3").append(h("span", { class: "n", text: String(preview.length) }));
      section.append(h("div", { class: "say-src name-note", text: "Calls into this, may be affected. Proven calls up to 3 steps away." }),
        h("ul", { class: "links affects" }, preview.map((row) => {
          const where = stepsText(row.steps);
          let say = h("span", { class: "sub", text: row.description });
          if (!row.description) say = h("span", { class: "sub none", text: "No description yet" });
          return h("li", { onclick: () => select(row.id), title: row.id }, h("b", { text: row.name }), h("span", { class: "steps", text: " · " + where }), say);
        })));
      return section;
    }
    if (!card.change) return null;
    section.append(h("div", { class: "say-missing", text: "Nothing in the repository calls this, so the change reaches no other code." }));
    return section;
  }

  function startEdit(body, node, note) {
    const area = h("textarea", { class: "edit", maxlength: "600" });
    area.value = "";
    if (note) area.value = note.text;
    const save = h("button", { class: "btn primary", type: "button", onclick: async () => {
      try {
        await api("/api/note", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id: node.id, text: area.value }) });
        toast("Saved to .skylos/graph/notes.json");
        showNode(node.id);
      } catch (err) { toast(err.message); }
    } }, "Save");
    const cancel = h("button", { class: "btn", type: "button", onclick: () => showNode(node.id) }, "Cancel");
    body.replaceChildren(area, h("div", { class: "actions" }, save, cancel));
    area.focus();
  }

  function signatureLine(node) {
    if (!node.signature || node.kind === "class") return null;
    return h("code", { class: "mono sig", text: shortName(node.name) + displaySignature(node) });
  }

  function displaySignature(node) {
    let sig = node.signature.trim();
    if (NAME_MATCHED_LANGUAGES.includes(node.language)) return sig;
    if (node.language !== "python") {
      return sig.replace(/\s*([(),:<>\[\]{}|=])\s*/g, "$1").replace(/,/g, ", ").replace(/:/g, ": ").replace(/=>/g, " => ");
    }
    let returns = "";
    const arrow = /(^|\s)->\s*(.+)$/.exec(sig);
    if (arrow) {
      returns = " -> " + arrow[2];
      sig = sig.slice(0, arrow.index).trim();
    }
    return "(" + sig + ")" + returns;
  }

  function sentence(text) {
    if (!text) return "";
    let out = text.charAt(0).toUpperCase() + text.slice(1);
    if (!/[.!?]$/.test(out)) out += ".";
    return out;
  }

  function verdictLabel(verdict, flagged) {
    if (flagged) return "Needs a look";
    return VERDICT_LABEL[verdict];
  }

  function changedDot(file) {
    if (!file.changed) return null;
    return h("span", { class: "dot v-changed", title: file.changed + " changed" });
  }

  function symClass(sym) {
    if (sym.id === state.selected) return "sym active";
    return "sym";
  }

  function depthButton(id, depth, text) {
    let cls = "";
    if (state.depth === depth) cls = "on";
    return h("button", { type: "button", class: cls, onclick: () => { state.depth = depth; showNode(id); } }, text);
  }

  function expectTitle(entry) {
    if (entry.how === "matched by name") return entry.test + " (matched by name)";
    return entry.test;
  }

  function testList(tests) {
    if (!tests.length) return h("div", { class: "say-missing", text: "No test reaches this code within 3 calls." });
    return h("ul", { class: "links" }, tests.slice(0, 40).map((t) => {
      let distance = t.steps + " calls away";
      if (t.steps === 1) distance = "calls it directly";
      return h("li", { onclick: () => select(t.id) }, t.name, h("span", { class: "sub", text: t.file + " · " + distance }));
    }));
  }

  function renderCard(card) {
    const node = card.node;
    const panel = $("card");
    panel.replaceChildren();
    panel.append(
      h("button", { class: "close", type: "button", "aria-label": "Close details", onclick: () => { location.hash = ""; } }, "×"),
      h("div", null, kindChip(node.kind, node.is_test)),
      h("h1", { text: node.name }),
      h("div", { class: "path" }, h("button", { class: "linkbtn", type: "button", title: "Copy path", onclick: () => {
        const text = node.file + ":" + node.start;
        if (navigator.clipboard) navigator.clipboard.writeText(text).then(() => toast("Copied " + text));
      } }, node.file + ":" + node.start)),
      areaLine(card.area, node.id),
      signatureLine(node));
    panel.append(describeSection(card));
    const before = beforeSection(card);
    if (before) panel.append(before);
    if (card.change) panel.append(changeSection(card.change, card.change_note));
    const affects = affectsSection(card);
    if (affects) panel.append(affects);
    if (card.expected_outputs.length) {
      const table = h("table", { class: "expect" }, card.expected_outputs.map((e) => h("tr", { title: expectTitle(e) },
        h("td", { text: e.call }), h("td", { class: "arrow", text: "→" }), h("td", { text: e.expected.join(" or ") }))));
      panel.append(h("section", null, h("h3", null, "Expected outputs from tests", h("span", { class: "n", text: String(card.expected_outputs.length) })), table));
    }
    if (card.members.length) panel.append(h("section", null, h("h3", null, "Methods", h("span", { class: "n", text: String(card.members.length) })), linkList("members", card.members, "")));
    const usedByName = card.used_by_name || [];
    const usesName = card.uses_name || [];
    let usedByEmpty = "Nothing in the repository calls this.";
    if (usedByName.length) usedByEmpty = "No call to this is proven. Name matches are listed below.";
    let usesEmpty = "Calls nothing else in the repository.";
    if (usesName.length) usesEmpty = "No call from this is proven. Name matches are listed below.";
    panel.append(h("section", null, h("h3", null, "Used by", h("span", { class: "n", text: String(card.used_by.length) })), linkList("used-by", card.used_by, usedByEmpty)));
    const usedByNameSection = nameSection("Possibly used by", "used-by-name", usedByName);
    if (usedByNameSection) panel.append(usedByNameSection);
    panel.append(h("section", null, h("h3", null, "Uses", h("span", { class: "n", text: String(card.uses.length) })), linkList("uses", card.uses, usesEmpty)));
    const usesNameSection = nameSection("Possibly uses", "uses-name", usesName);
    if (usesNameSection) panel.append(usesNameSection);
    panel.append(h("section", null, h("h3", null, "Tests that reach it", h("span", { class: "n", text: String(card.tests.length) })), testList(card.tests)));
    if (card.code) {
      const codeSection = h("section", null, h("h3", { text: "Code" }), codeBlock(card.code.text, card.code.start));
      if (card.code.clipped) codeSection.append(h("div", { class: "say-src", text: "Showing the first 400 lines." }));
      panel.append(codeSection);
    }
    openCard();
    panel.scrollTop = 0;
  }

  async function showChange(id) {
    const row = ((state.overview.changes || {}).rows || []).find((r) => r.id === id);
    if (!row) { location.hash = ""; return; }
    let data;
    try { data = await api("/api/change?id=" + encodeURIComponent(id)); } catch (err) { toast(err.message); return; }
    const panel = $("card");
    panel.replaceChildren(
      h("button", { class: "close", type: "button", "aria-label": "Close details", onclick: () => { location.hash = ""; } }, "×"),
      h("h1", { text: row.name }),
      h("div", { class: "path", text: row.file }),
      changeSection(data.change, data.change_note));
    openCard();
    renderMain();
  }

  const REVIEW_WORDS = { read_first: "Read first", read: "Read", skim: "Skim", skip: "Skip: same logic" };
  const LIT_REVIEWS = ["read_first", "read", "skim"];
  const GRAPH_STEP = 80;
  const EDGE_KINDS = ["calls", "creates", "uses", "inherits", "name"];
  const EDGE_VERBS = { calls: "calls", creates: "creates", uses: "uses the type", inherits: "inherits from", name: "may call (matched by name only)" };
  const graphView = { token: 0, live: null, transforms: {} };
  let measureContext = null;

  function graphFonts() {
    const family = getComputedStyle(document.body).fontFamily || "sans-serif";
    return {
      name: "600 13px " + family,
      small: "600 10.5px " + family,
      meta: "11px " + family,
      text: "12px " + family,
    };
  }

  function textWidth(text, font) {
    if (!measureContext) measureContext = document.createElement("canvas").getContext("2d");
    measureContext.font = font;
    return measureContext.measureText(text).width;
  }

  function fitText(text, width, font) {
    const value = String(text || "");
    if (textWidth(value, font) <= width) return value;
    let low = 0;
    let high = value.length;
    while (low < high) {
      const mid = Math.ceil((low + high) / 2);
      if (textWidth(value.slice(0, mid) + "…", font) <= width) low = mid;
      else high = mid - 1;
    }
    return value.slice(0, low).trimEnd() + "…";
  }

  function wrapText(text, width, font, maxLines) {
    const words = String(text || "").split(/\s+/).filter(Boolean);
    const lines = [];
    let current = "";
    for (let i = 0; i < words.length; i++) {
      let next = words[i];
      if (current) next = current + " " + words[i];
      if (!current || textWidth(next, font) <= width) {
        current = next;
        continue;
      }
      if (lines.length === maxLines - 1) {
        lines.push(fitText(current + " " + words.slice(i).join(" "), width, font));
        return lines;
      }
      lines.push(fitText(current, width, font));
      current = words[i];
    }
    if (current) lines.push(fitText(current, width, font));
    return lines;
  }

  function graphLimit(areaId) {
    return state.graphLimits[String(areaId)] || GRAPH_STEP;
  }

  function isLit(item) {
    return LIT_REVIEWS.includes(item.review) || Boolean(item.impacted);
  }

  function reviewWord(review) {
    return REVIEW_WORDS[review] || "";
  }

  function boxKind(item) {
    if (item.external) return "ext";
    if (item.kind === "class") return "class";
    if (item.kind === "area" || item.kind === "other") return "area";
    return "fn";
  }

  function strongest(edges, count) {
    const stronger = (a, b) => (b.weight - a.weight) || (b.name_links - a.name_links);
    const outgoing = new Map();
    const incoming = new Map();
    for (const edge of edges) {
      if (!outgoing.has(edge.source)) outgoing.set(edge.source, []);
      if (!incoming.has(edge.target)) incoming.set(edge.target, []);
      outgoing.get(edge.source).push(edge);
      incoming.get(edge.target).push(edge);
    }
    const keep = new Set();
    for (const list of [...outgoing.values(), ...incoming.values()]) {
      list.sort(stronger);
      list.slice(0, count).forEach((edge) => keep.add(edge));
    }
    return keep;
  }

  function codebaseModel(data) {
    const boxes = data.nodes.map((item) => ({ id: item.id, item, kind: "area", w: 236, h: 108 }));
    const drawable = data.edges.filter((edge) => edge.source !== "area:other" && edge.target !== "area:other");
    let kept = drawable;
    if (!state.graphAllLinks && drawable.length > data.nodes.length * 1.5) {
      const keep = strongest(drawable, 2);
      kept = drawable.filter((edge) => keep.has(edge) || (data.impact && edge.impact));
    }
    let maxWeight = 1;
    for (const edge of kept) maxWeight = Math.max(maxWeight, edge.weight);
    const links = kept.map((edge) => {
      let kind = "calls";
      if (!edge.weight) kind = "name";
      return { from: edge.source, to: edge.target, source: edge.source, target: edge.target, kind, edge };
    });
    return { level: "codebase", boxes, links, maxWeight, linksTotal: drawable.length, thinned: kept.length < drawable.length, options: { gapX: 40, gapY: 64 }, sideways: { gapX: 22, gapY: 96 } };
  }

  function areaModel(data) {
    const boxes = [];
    const owner = new Map();
    const rowIndex = new Map();
    const rowTops = new Map();
    for (const item of data.nodes) {
      const box = { id: item.id, item, kind: boxKind(item) };
      if (box.kind === "class") {
        const rows = item.members || [];
        let extra = 0;
        if ((item.members_total || 0) > rows.length) extra = 1;
        box.w = 264;
        box.rowTop = 76;
        if (item.summary) box.rowTop = 92;
        rowTops.set(item.id, box.rowTop);
        box.h = box.rowTop + Math.max(1, rows.length + extra) * 20 + 8;
        rows.forEach((row, i) => {
          owner.set(row.id, item.id);
          rowIndex.set(row.id, i);
        });
      } else if (box.kind === "ext") {
        box.w = 184;
        box.h = 46;
        box.pinned = true;
      } else {
        box.w = 240;
        box.h = 60;
        if (item.summary) box.h = 76;
      }
      boxes.push(box);
    }
    const known = new Set(boxes.map((box) => box.id));
    const links = [];
    for (const edge of data.edges) {
      const from = owner.get(edge.source) || edge.source;
      const to = owner.get(edge.target) || edge.target;
      if (from === to || !known.has(from) || !known.has(to)) continue;
      links.push({ from, to, source: edge.source, target: edge.target, kind: edge.kind, edge });
    }
    return { level: "area", boxes, links, owner, rowIndex, rowTops, options: { gapX: 36, gapY: 64 }, sideways: { gapX: 22, gapY: 100 } };
  }

  function breakCycles(ids, out, order) {
    const incoming = new Map();
    const outDegree = new Map();
    const inDegree = new Map();
    for (const id of ids) {
      incoming.set(id, []);
      outDegree.set(id, 0);
      inDegree.set(id, 0);
    }
    for (const [from, targets] of out) {
      for (const to of targets) {
        incoming.get(to).push(from);
        outDegree.set(from, outDegree.get(from) + 1);
        inDegree.set(to, inDegree.get(to) + 1);
      }
    }
    const remaining = new Set(ids);
    const left = [];
    const right = [];
    const remove = (id) => {
      remaining.delete(id);
      for (const to of out.get(id)) if (remaining.has(to)) inDegree.set(to, inDegree.get(to) - 1);
      for (const from of incoming.get(id)) if (remaining.has(from)) outDegree.set(from, outDegree.get(from) - 1);
    };
    while (remaining.size) {
      let moved = true;
      while (moved) {
        moved = false;
        for (const id of [...remaining]) {
          if (remaining.has(id) && outDegree.get(id) === 0) {
            right.unshift(id);
            remove(id);
            moved = true;
          }
        }
        for (const id of [...remaining]) {
          if (remaining.has(id) && inDegree.get(id) === 0) {
            left.push(id);
            remove(id);
            moved = true;
          }
        }
      }
      if (!remaining.size) break;
      let best = null;
      for (const id of remaining) {
        const score = outDegree.get(id) - inDegree.get(id);
        if (best === null || score > best.score || (score === best.score && order.get(id) < order.get(best.id))) best = { id, score };
      }
      left.push(best.id);
      remove(best.id);
    }
    const rank = new Map();
    left.concat(right).forEach((id, i) => rank.set(id, i));
    const reversed = new Set();
    for (const [from, targets] of out) {
      for (const to of targets) if (rank.get(from) > rank.get(to)) reversed.add(from + "\n" + to);
    }
    return reversed;
  }

  function assignLayers(ids, pairs, order, maxWidth) {
    const out = new Map();
    for (const id of ids) out.set(id, []);
    const inCore = new Set(ids);
    for (const pair of pairs) {
      if (inCore.has(pair.from) && inCore.has(pair.to)) out.get(pair.from).push(pair.to);
    }
    const reversed = breakCycles(ids, out, order);
    const down = new Map();
    const indegree = new Map();
    for (const id of ids) {
      down.set(id, new Set());
      indegree.set(id, 0);
    }
    for (const [from, targets] of out) {
      for (const to of targets) {
        let a = from;
        let b = to;
        if (reversed.has(from + "\n" + to)) {
          a = to;
          b = from;
        }
        if (!down.get(a).has(b)) {
          down.get(a).add(b);
          indegree.set(b, indegree.get(b) + 1);
        }
      }
    }
    const minLayer = new Map();
    const layerOf = new Map();
    const counts = [];
    let ready = ids.filter((id) => indegree.get(id) === 0);
    while (ready.length) {
      ready.sort((a, b) => ((minLayer.get(a) || 0) - (minLayer.get(b) || 0)) || (order.get(a) - order.get(b)));
      const id = ready.shift();
      let layer = minLayer.get(id) || 0;
      while ((counts[layer] || 0) >= maxWidth) layer += 1;
      counts[layer] = (counts[layer] || 0) + 1;
      layerOf.set(id, layer);
      for (const child of down.get(id)) {
        minLayer.set(child, Math.max(minLayer.get(child) || 0, layer + 1));
        indegree.set(child, indegree.get(child) - 1);
        if (indegree.get(child) === 0) ready.push(child);
      }
    }
    return layerOf;
  }

  function countCrossings(layers, pos, down) {
    let total = 0;
    for (let l = 0; l < layers.length - 1; l++) {
      const pairs = [];
      for (const id of layers[l]) for (const next of down.get(id)) pairs.push([pos.get(id), pos.get(next)]);
      pairs.sort((a, b) => (a[0] - b[0]) || (a[1] - b[1]));
      const size = layers[l + 1].length;
      const tree = new Array(size + 2).fill(0);
      let seen = 0;
      for (const pair of pairs) {
        let atOrBelow = 0;
        for (let i = pair[1] + 1; i > 0; i -= i & -i) atOrBelow += tree[i];
        total += seen - atOrBelow;
        for (let i = pair[1] + 1; i <= size + 1; i += i & -i) tree[i] += 1;
        seen += 1;
      }
    }
    return total;
  }

  function orderLayers(layers, up, down) {
    const pos = new Map();
    const index = () => layers.forEach((layer) => layer.forEach((id, i) => pos.set(id, i)));
    index();
    const reorder = (l, near) => {
      const scored = layers[l].map((id, i) => {
        const others = near.get(id);
        let score = i;
        if (others.length) score = others.reduce((sum, other) => sum + pos.get(other), 0) / others.length;
        return [score, i, id];
      });
      scored.sort((a, b) => (a[0] - b[0]) || (a[1] - b[1]));
      layers[l] = scored.map((item) => item[2]);
      layers[l].forEach((id, i) => pos.set(id, i));
    };
    let best = layers.map((layer) => layer.slice());
    let bestCount = countCrossings(layers, pos, down);
    for (let sweep = 0; sweep < 12 && bestCount > 0; sweep++) {
      if (sweep % 2 === 0) for (let l = 1; l < layers.length; l++) reorder(l, up);
      else for (let l = layers.length - 2; l >= 0; l--) reorder(l, down);
      const count = countCrossings(layers, pos, down);
      if (count < bestCount) {
        bestCount = count;
        best = layers.map((layer) => layer.slice());
      }
    }
    best.forEach((layer, l) => { layers[l] = layer; });
    index();
    return { pos, crossings: bestCount };
  }

  function placeRow(ids, nodes, x, desired, gapX) {
    const offsets = [0];
    for (let i = 1; i < ids.length; i++) {
      const a = nodes.get(ids[i - 1]);
      const b = nodes.get(ids[i]);
      let gap = gapX;
      if (a.dummy && b.dummy) gap = 10;
      else if (a.dummy || b.dummy) gap = 22;
      offsets.push(offsets[i - 1] + (a.w + b.w) / 2 + gap);
    }
    const blocks = [];
    ids.forEach((id, i) => {
      let weight = 1;
      if (nodes.get(id).dummy) weight = 2;
      blocks.push({ start: i, end: i, sum: (desired[i] - offsets[i]) * weight, weight });
      while (blocks.length > 1) {
        const last = blocks[blocks.length - 1];
        const prev = blocks[blocks.length - 2];
        if (prev.sum / prev.weight <= last.sum / last.weight) break;
        prev.end = last.end;
        prev.sum += last.sum;
        prev.weight += last.weight;
        blocks.pop();
      }
    });
    for (const block of blocks) {
      const value = block.sum / block.weight;
      for (let i = block.start; i <= block.end; i++) x.set(ids[i], value + offsets[i]);
    }
  }

  function layered(boxes, links, options) {
    const margin = 32;
    const horizontal = Boolean(options.horizontal);
    const gapX = options.gapX;
    const gapY = options.gapY;
    const order = new Map();
    boxes.forEach((box, i) => order.set(box.id, i));
    const size = new Map();
    for (const box of boxes) {
      if (horizontal) size.set(box.id, { w: box.h, h: box.w });
      else size.set(box.id, { w: box.w, h: box.h });
    }
    const pairMap = new Map();
    for (const link of links) {
      const key = link.from + "\n" + link.to;
      if (!pairMap.has(key)) pairMap.set(key, { from: link.from, to: link.to, links: [] });
      pairMap.get(key).links.push(link);
    }
    const pairs = [...pairMap.values()];
    const degree = new Map();
    for (const pair of pairs) {
      degree.set(pair.from, (degree.get(pair.from) || 0) + 1);
      degree.set(pair.to, (degree.get(pair.to) || 0) + 1);
    }
    const core = boxes.filter((box) => degree.get(box.id));
    const loose = boxes.filter((box) => !degree.get(box.id));
    let avgW = 200;
    let avgH = 80;
    if (core.length) {
      avgW = core.reduce((sum, box) => sum + size.get(box.id).w, 0) / core.length;
      avgH = core.reduce((sum, box) => sum + size.get(box.id).h, 0) / core.length;
    }
    const maxWidth = Math.max(2, Math.round(Math.sqrt(options.ratio * core.length * (avgH + gapY) / (avgW + gapX))));
    const layerOf = assignLayers(core.map((box) => box.id), pairs, order, maxWidth);
    const nodes = new Map();
    for (const box of core) nodes.set(box.id, { id: box.id, w: size.get(box.id).w, h: size.get(box.id).h, dummy: false, edge: Boolean(box.pinned), layer: layerOf.get(box.id) });
    let dummies = 0;
    for (const pair of pairs) {
      let top = pair.from;
      let bottom = pair.to;
      pair.up = false;
      if (layerOf.get(top) > layerOf.get(bottom)) {
        top = pair.to;
        bottom = pair.from;
        pair.up = true;
      }
      pair.flat = layerOf.get(top) === layerOf.get(bottom);
      const chain = [top];
      for (let l = layerOf.get(top) + 1; l < layerOf.get(bottom); l++) {
        const id = "\u0000" + dummies;
        dummies += 1;
        nodes.set(id, { id, w: 8, h: 0, dummy: true, layer: l });
        chain.push(id);
      }
      chain.push(bottom);
      pair.chain = chain;
    }
    let layerCount = 0;
    for (const node of nodes.values()) layerCount = Math.max(layerCount, node.layer + 1);
    const layers = Array.from({ length: layerCount }, () => []);
    for (const node of nodes.values()) layers[node.layer].push(node.id);
    const up = new Map();
    const down = new Map();
    for (const id of nodes.keys()) {
      up.set(id, []);
      down.set(id, []);
    }
    for (const pair of pairs) {
      if (pair.flat) continue;
      for (let i = 0; i < pair.chain.length - 1; i++) {
        down.get(pair.chain[i]).push(pair.chain[i + 1]);
        up.get(pair.chain[i + 1]).push(pair.chain[i]);
      }
    }
    const ordering = orderLayers(layers, up, down);
    layers.forEach((layer, l) => {
      const first = [];
      const middle = [];
      const last = [];
      layer.forEach((id, i) => {
        if (!nodes.get(id).edge) middle.push(id);
        else if (i < layer.length / 2) first.push(id);
        else last.push(id);
      });
      layers[l] = first.concat(middle, last);
    });
    const x = new Map();
    for (const layer of layers) {
      let cursor = 0;
      layer.forEach((id, i) => {
        const node = nodes.get(id);
        if (i > 0) cursor += gapX;
        x.set(id, cursor + node.w / 2);
        cursor += node.w;
      });
    }
    const pull = (l, near) => {
      const ids = layers[l];
      const desired = ids.map((id) => {
        const others = near(id);
        if (!others.length) return x.get(id);
        return others.reduce((sum, other) => sum + x.get(other), 0) / others.length;
      });
      placeRow(ids, nodes, x, desired, gapX);
    };
    for (let pass = 0; pass < 8; pass++) {
      if (pass % 2 === 0) for (let l = 1; l < layers.length; l++) pull(l, (id) => up.get(id));
      else for (let l = layers.length - 2; l >= 0; l--) pull(l, (id) => down.get(id));
    }
    for (let l = 0; l < layers.length; l++) pull(l, (id) => up.get(id).concat(down.get(id)));
    let left = Infinity;
    for (const [id, value] of x) left = Math.min(left, value - nodes.get(id).w / 2);
    if (!Number.isFinite(left)) left = 0;
    for (const [id, value] of x) x.set(id, value - left + margin);
    const layerH = layers.map((layer) => layer.reduce((most, id) => Math.max(most, nodes.get(id).h), 0));
    const tops = [];
    let y = margin;
    for (let l = 0; l < layers.length; l++) {
      tops.push(y);
      y += layerH[l] + gapY;
    }
    const ports = new Map();
    const port = (id, side, pair, towards) => {
      const key = id + "\n" + side;
      if (!ports.has(key)) ports.set(key, []);
      ports.get(key).push({ pair, towards });
    };
    for (const pair of pairs) {
      if (pair.flat) continue;
      const chain = pair.chain;
      port(chain[0], "bottom", pair, x.get(chain[1]));
      port(chain[chain.length - 1], "top", pair, x.get(chain[chain.length - 2]));
    }
    for (const [key, list] of ports) {
      const parts = key.split("\n");
      const node = nodes.get(parts[0]);
      list.sort((a, b) => a.towards - b.towards);
      let step = 0;
      if (list.length > 1) step = Math.min(16, (node.w * 0.7) / (list.length - 1));
      list.forEach((entry, i) => {
        const offset = (i - (list.length - 1) / 2) * step;
        if (parts[1] === "bottom") entry.pair.startOffset = offset;
        else entry.pair.endOffset = offset;
      });
    }
    const flip = (point) => {
      if (!horizontal) return point;
      return Object.assign({}, point, { x: point.y, y: point.x });
    };
    const pos = new Map();
    for (const node of nodes.values()) {
      if (node.dummy) continue;
      const place = { x: x.get(node.id) - node.w / 2, y: tops[node.layer], w: node.w, h: node.h };
      if (horizontal) pos.set(node.id, { x: place.y, y: place.x, w: place.h, h: place.w });
      else pos.set(node.id, place);
    }
    for (const pair of pairs) {
      if (pair.flat) continue;
      const chain = pair.chain;
      const first = nodes.get(chain[0]);
      const last = nodes.get(chain[chain.length - 1]);
      const points = [{ x: x.get(first.id) + (pair.startOffset || 0), y: tops[first.layer] + first.h }];
      for (let i = 1; i < chain.length - 1; i++) {
        const dummy = nodes.get(chain[i]);
        points.push({ x: x.get(dummy.id), y: tops[dummy.layer], dummy: dummy.id });
        points.push({ x: x.get(dummy.id), y: tops[dummy.layer] + layerH[dummy.layer], dummy: dummy.id });
      }
      points.push({ x: x.get(last.id) + (pair.endOffset || 0), y: tops[last.layer] });
      if (pair.up) points.reverse();
      pair.points = points.map(flip);
    }
    for (const pair of pairs) {
      if (!pair.flat) continue;
      const a = pos.get(pair.from);
      const b = pos.get(pair.to);
      const ax = a.x + a.w / 2;
      const bx = b.x + b.w / 2;
      const ay = a.y + a.h / 2;
      const by = b.y + b.h / 2;
      if (Math.abs(bx - ax) >= Math.abs(by - ay)) {
        const sign = Math.sign(bx - ax) || 1;
        pair.points = [{ x: ax + sign * a.w / 2, y: ay, side: sign }, { x: bx - sign * b.w / 2, y: by, side: -sign }];
      } else {
        const sign = Math.sign(by - ay) || 1;
        pair.points = [{ x: ax, y: ay + sign * a.h / 2 }, { x: bx, y: by - sign * b.h / 2 }];
      }
    }
    let width = margin * 2;
    let height = margin * 2;
    for (const place of pos.values()) {
      width = Math.max(width, place.x + place.w + margin);
      height = Math.max(height, place.y + place.h + margin);
    }
    let looseTop = null;
    if (loose.length) {
      looseTop = height - margin + 24;
      let cursorX = margin;
      let cursorY = looseTop + 26;
      let rowH = 0;
      const limit = Math.max(width - margin, margin + 4 * (loose[0].w + 40));
      for (const box of loose) {
        if (cursorX > margin && cursorX + box.w > limit) {
          cursorX = margin;
          cursorY += rowH + 24;
          rowH = 0;
        }
        pos.set(box.id, { x: cursorX, y: cursorY, w: box.w, h: box.h });
        cursorX += box.w + 40;
        rowH = Math.max(rowH, box.h);
        width = Math.max(width, cursorX - 40 + margin);
      }
      height = cursorY + rowH + margin;
    }
    return { pos, pairs, width, height, looseTop, horizontal, crossings: ordering.crossings, layers: layers.length };
  }

  function curve(points, shift, horizontal) {
    const at = (p) => {
      if (horizontal) return p.x.toFixed(1) + "," + (p.y + shift).toFixed(1);
      return (p.x + shift).toFixed(1) + "," + p.y.toFixed(1);
    };
    let d = "M" + at(points[0]);
    for (let i = 1; i < points.length; i++) {
      const p = points[i - 1];
      const q = points[i];
      if (p.dummy && p.dummy === q.dummy) {
        d += " L" + at(q);
        continue;
      }
      let c1 = { x: p.x, y: p.y + (q.y - p.y) / 2 };
      let c2 = { x: q.x, y: q.y - (q.y - p.y) / 2 };
      if (horizontal) {
        c1 = { x: p.x + (q.x - p.x) / 2, y: p.y };
        c2 = { x: q.x - (q.x - p.x) / 2, y: q.y };
      }
      const reach = Math.max(36, Math.abs(q.x - p.x) / 2);
      if (p.side) c1 = { x: p.x + p.side * reach, y: p.y };
      if (q.side) c2 = { x: q.x + q.side * reach, y: q.y };
      d += " C" + at(c1) + " " + at(c2) + " " + at(q);
    }
    return d;
  }

  function rowAnchor(box, boxId, rowIndex, towardsX, model) {
    const y = box.y + model.rowTops.get(boxId) + rowIndex * 20 + 10;
    if (towardsX >= box.x + box.w / 2) return { x: box.x + box.w, y, side: 1 };
    return { x: box.x, y, side: -1 };
  }

  function routeFor(pair, link, layout, model) {
    const points = pair.points.map((p) => Object.assign({}, p));
    if (model.level !== "area") return points;
    const sourceRow = model.rowIndex.get(link.source);
    const targetRow = model.rowIndex.get(link.target);
    if (sourceRow !== undefined) {
      const box = layout.pos.get(link.from);
      let towards = box.x + box.w;
      if (points.length > 1) towards = points[1].x;
      points[0] = rowAnchor(box, link.from, sourceRow, towards, model);
    }
    if (targetRow !== undefined) {
      const box = layout.pos.get(link.to);
      let towards = box.x;
      if (points.length > 1) towards = points[points.length - 2].x;
      points[points.length - 1] = rowAnchor(box, link.to, targetRow, towards, model);
    }
    return points;
  }

  function chooseLayout(model, canvas) {
    const width = Math.max(320, canvas.clientWidth || 900);
    const height = Math.max(240, canvas.clientHeight || 520);
    const ratio = width / height;
    const tall = layered(model.boxes, model.links, Object.assign({}, model.options, { ratio, horizontal: false }));
    const wide = layered(model.boxes, model.links, Object.assign({}, model.sideways, { ratio: 1 / ratio, horizontal: true }));
    const scale = (layout) => Math.min(width / layout.width, height / layout.height);
    if (scale(wide) > scale(tall) * 1.1) return wide;
    return tall;
  }

  function arrowMarker(kind, hot) {
    let id = "gvm-" + kind;
    let cls = "gv-tip k-" + kind;
    if (hot) {
      id += "-hot";
      cls += " hot";
    }
    let shape = "M1,1 L10,5.5 L1,10 z";
    let size = 11;
    if (kind === "creates" || kind === "uses" || kind === "name") shape = "M1,1 L10,5.5 L1,10";
    if (kind === "inherits") {
      shape = "M1,1 L14,7.5 L1,14 z";
      size = 15;
    }
    const half = size / 2;
    return svg("marker", { id, viewBox: "0 0 " + size + " " + size, refX: size - 1, refY: half, markerWidth: size, markerHeight: size, markerUnits: "userSpaceOnUse", orient: "auto" },
      svg("path", { d: shape, class: cls }));
  }

  function legendLine(kind) {
    let tip = svg("path", { d: "M26,2 L34,6 L26,10 z", class: "gv-tip k-" + kind });
    if (kind === "creates" || kind === "uses" || kind === "name") tip = svg("path", { d: "M26,2 L34,6 L26,10", class: "gv-tip k-" + kind });
    if (kind === "inherits") tip = svg("path", { d: "M24,1 L34,6 L24,11 z", class: "gv-tip k-inherits" });
    return svg("svg", { class: "gv-key-line", width: 36, height: 12, viewBox: "0 0 36 12", "aria-hidden": "true" },
      svg("line", { x1: 1, y1: 6, x2: 30, y2: 6, class: "gv-edge k-" + kind }), tip);
  }

  function graphLegend(level) {
    const swatch = (cls, label) => h("span", { class: "gv-key" }, h("i", { class: "gv-swatch " + cls }), label);
    const items = [
      h("b", { class: "gv-key-title", text: "Changes" }),
      swatch("rv-read_first", "Read first"),
      swatch("rv-read", "Read"),
      swatch("rv-skim", "Skim"),
      swatch("rv-skip", "Skip: same logic"),
      h("span", { class: "gv-key" }, h("i", { class: "gv-tag-new", text: "NEW" }), "new code"),
      swatch("gv-sw-affected", "calls changed code (Impact)"),
      h("b", { class: "gv-key-title", text: "Lines" }),
    ];
    if (level === "area") {
      for (const kind of EDGE_KINDS) items.push(h("span", { class: "gv-key" }, legendLine(kind), EDGE_VERBS[kind]));
      items.push(h("span", { class: "gv-key" }, h("i", { class: "gv-swatch gv-sw-ext" }), "dashed box: in another area"));
    } else {
      items.push(h("span", { class: "gv-key" }, legendLine("calls"), "calls into; thicker means more calls"));
      items.push(h("span", { class: "gv-key" }, legendLine("name"), "matched by name only"));
    }
    return items;
  }

  function nodeTitle(item, model) {
    let text = item.name;
    if (model.level === "codebase") {
      if (item.where) text += "\n" + item.where + " · " + plural(item.size, "function or class", "functions and classes");
    } else if (item.external) {
      text += "\nIn " + item.area_name + ". Click to open that area.";
    } else {
      text += "\n" + item.file + ":" + item.line;
    }
    if (item.review) text += "\nChanged: " + reviewWord(item.review);
    if (item.verdict === "new") text += " (new code)";
    if (item.impacted) text += "\nCalls changed code within 3 steps.";
    if (item.summary) text += "\n\n" + item.summary;
    return text;
  }

  function nodeLabel(item, model) {
    let text = item.name;
    if (model.level === "codebase") text = "Area " + item.name + ", " + plural(item.size, "function or class", "functions and classes");
    else if (item.external) text = item.name + ", in area " + item.area_name;
    else text = item.kind + " " + item.name;
    if (item.changed) text += ", " + item.changed + " changed";
    if (item.review) text += ", " + reviewWord(item.review);
    if (item.impacted) text += ", calls changed code";
    return text;
  }

  function summaryText(group, item, x, y, width, lines, fonts) {
    if (!item.summary) {
      group.append(svg("text", { class: "gv-sum none", x, y, text: "No description yet" }));
      return;
    }
    wrapText(item.summary, width, fonts.text, lines).forEach((line, i) => {
      group.append(svg("text", { class: "gv-sum", x, y: y + i * 16, text: line }));
    });
  }

  function pill(group, x, y, text, cls, fonts) {
    const width = Math.ceil(textWidth(text, fonts.small)) + 12;
    group.append(svg("rect", { class: "gv-pill " + cls, x: x - width, y, width, height: 17, rx: 8.5 }),
      svg("text", { class: "gv-pill-text " + cls, x: x - width / 2, y: y + 12.5, "text-anchor": "middle", text }));
    return width;
  }

  function drawArea(group, box, item, fonts, impact) {
    group.append(svg("rect", { class: "gv-box", width: box.w, height: box.h, rx: 8 }));
    const family = getComputedStyle(document.body).fontFamily || "sans-serif";
    let farName = item.name;
    if (item.kind === "area" && item.name.includes(": ")) farName = item.name.slice(item.name.indexOf(": ") + 2);
    const farWhere = item.where || plural(item.areas || 0, "area", "areas");
    group.append(svg("text", { class: "gv-far-text gv-far-name", x: box.w / 2, y: 42, "text-anchor": "middle", text: fitText(farName, box.w - 20, "600 24px " + family) }));
    group.append(svg("text", { class: "gv-far-text gv-far-where", x: box.w / 2, y: 68, "text-anchor": "middle", text: fitText(farWhere, box.w - 20, "17px " + family) }));
    group.append(svg("text", { class: "gv-name", x: 14, y: 22, text: fitText(item.name, box.w - 28, fonts.name) }));
    let meta = plural(item.size, "function or class", "functions and classes");
    if (item.kind === "other") meta = plural(item.areas, "area", "areas") + " · " + meta + " · links not drawn";
    else if (item.where) meta = item.where + " · " + meta;
    group.append(svg("text", { class: "gv-meta", x: 14, y: 39, text: fitText(meta, box.w - 28, fonts.meta) }));
    summaryText(group, item, 14, 59, box.w - 28, 2, fonts);
    let right = box.w - 10;
    if (item.changed) right -= pill(group, right, box.h - 24, item.changed + " changed", "rv-" + (item.review || "read"), fonts) + 6;
    if (impact && item.affected) pill(group, right, box.h - 24, item.affected + " may be affected", "gv-pill-affected", fonts);
  }

  function drawFunction(group, box, item, fonts) {
    group.append(svg("rect", { class: "gv-box", width: box.w, height: box.h, rx: 14 }));
    let tag = item.kind;
    let tagClass = "gv-kind";
    if (item.verdict === "new") {
      tag = "NEW";
      tagClass = "gv-tag-new-svg";
    }
    const tagWidth = textWidth(tag, fonts.small);
    group.append(svg("text", { class: tagClass, x: box.w - 14, y: 21, "text-anchor": "end", text: tag }));
    group.append(svg("text", { class: "gv-name", x: 14, y: 22, text: fitText(item.name + "()", box.w - 36 - tagWidth, fonts.name) }));
    let lines = 1;
    if (item.summary) lines = 2;
    summaryText(group, item, 14, 42, box.w - 28, lines, fonts);
  }

  function drawExternal(group, box, item, fonts) {
    group.append(svg("rect", { class: "gv-box", width: box.w, height: box.h, rx: 6 }));
    group.append(svg("text", { class: "gv-name small", x: 10, y: 19, text: fitText(item.name, box.w - 20, fonts.name) }));
    group.append(svg("text", { class: "gv-meta", x: 10, y: 35, text: fitText("in " + item.area_name, box.w - 20, fonts.meta) }));
  }

  function drawClass(group, box, item, fonts, view) {
    const rowTop = box.rowTop;
    group.append(svg("rect", { class: "gv-box", width: box.w, height: box.h, rx: 3 }));
    group.append(svg("path", { class: "gv-head-band", d: "M1,4 a3,3 0 0 1 3,-3 h" + (box.w - 8) + " a3,3 0 0 1 3,3 v38 h-" + (box.w - 2) + " z" }));
    let stereo = "«class»";
    if (item.verdict === "new") stereo = "«class» · NEW";
    group.append(svg("text", { class: "gv-kind", x: box.w / 2, y: 16, "text-anchor": "middle", text: stereo }));
    group.append(svg("text", { class: "gv-name", x: box.w / 2, y: 33, "text-anchor": "middle", text: fitText(item.name, box.w - 24, fonts.name) }));
    group.append(svg("line", { class: "gv-rule", x1: 0, y1: 42, x2: box.w, y2: 42 }));
    let summaryLines = 1;
    if (item.summary) summaryLines = 2;
    summaryText(group, item, 12, 60, box.w - 24, summaryLines, fonts);
    group.append(svg("line", { class: "gv-rule", x1: 0, y1: rowTop - 4, x2: box.w, y2: rowTop - 4 }));
    const rows = item.members || [];
    rows.forEach((row, i) => {
      const y = rowTop + i * 20;
      let cls = "gv-row";
      if (row.review) cls += " rv-" + row.review;
      if (isLit(row)) cls += " lit";
      if (row.impacted) cls += " affected";
      const line = svg("g", { class: cls, transform: "translate(0," + y + ")", tabindex: 0, role: "button", "data-id": row.id, "aria-label": "method " + row.name + reviewSuffix(row) });
      line.append(svg("title", { text: nodeTitle(Object.assign({ kind: "method", file: item.file }, row), view.model) }));
      line.append(svg("rect", { class: "gv-row-bg", x: 1, y: 0, width: box.w - 2, height: 20 }));
      line.append(svg("circle", { class: "gv-row-dot", cx: 12, cy: 10, r: 3.5 }));
      let label = "+ " + shortName(row.name) + "()";
      let newWidth = 0;
      if (row.verdict === "new") newWidth = textWidth("NEW", fonts.small) + 10;
      line.append(svg("text", { class: "gv-row-text", x: 22, y: 14, text: fitText(label, box.w - 34 - newWidth, fonts.text) }));
      if (newWidth) line.append(svg("text", { class: "gv-tag-new-svg", x: box.w - 10, y: 14, "text-anchor": "end", text: "NEW" }));
      wireNode(line, row.id, () => openGraphCard(row.id), view);
      group.append(line);
    });
    const hidden = (item.members_total || 0) - rows.length;
    if (hidden > 0) {
      group.append(svg("text", { class: "gv-sum none", x: 22, y: rowTop + rows.length * 20 + 14, text: "+" + hidden + " more methods (click the class)" }));
    } else if (!rows.length) {
      group.append(svg("text", { class: "gv-sum none", x: 12, y: rowTop + 14, text: "No methods" }));
    }
  }

  function reviewSuffix(item) {
    let text = "";
    if (item.review) text += ", " + reviewWord(item.review);
    if (item.impacted) text += ", calls changed code";
    return text;
  }

  function wireNode(group, id, activate, view) {
    group.addEventListener("click", (event) => {
      event.stopPropagation();
      if (view.dragged) return;
      activate();
    });
    group.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        event.stopPropagation();
        activate();
      }
    });
    group.addEventListener("focus", () => view.reveal(id));
    group.addEventListener("pointerenter", () => view.hover(id, true));
    group.addEventListener("pointerleave", () => view.hover(id, false));
  }

  function drawDiagram(canvas, model, layout, data, key) {
    const fonts = graphFonts();
    const impact = Boolean(data.impact);
    let rootClass = "gv-svg";
    if (impact && anyLit(data)) rootClass += " impact-on";
    const root = svg("svg", { class: rootClass, "aria-hidden": "false" });
    const defs = svg("defs");
    for (const kind of EDGE_KINDS) {
      defs.append(arrowMarker(kind, false));
      defs.append(arrowMarker(kind, true));
    }
    const port = svg("g", { class: "gv-port" });
    const edgeLayer = svg("g", { class: "gv-edges" });
    const nodeLayer = svg("g", { class: "gv-nodes" });
    port.append(edgeLayer, nodeLayer);
    root.append(defs, port);
    const view = { k: 1, x: 0, y: 0, canvas, root, port, layout, model, key, area: null, dragged: false, groups: new Map(), edgesOf: new Map(), selected: null };
    if (data.level === "area") view.area = String(data.area.id);
    const nameOf = new Map();
    for (const box of model.boxes) {
      nameOf.set(box.id, box.item.name);
      for (const row of box.item.members || []) nameOf.set(row.id, row.name);
    }
    const remember = (id, element) => {
      if (!view.edgesOf.has(id)) view.edgesOf.set(id, []);
      view.edgesOf.get(id).push(element);
    };
    for (const pair of layout.pairs) {
      pair.links.forEach((link, i) => {
        const shift = (i - (pair.links.length - 1) / 2) * 5;
        const points = routeFor(pair, link, layout, model);
        let cls = "gv-edge k-" + link.kind;
        const hot = impact && Boolean(link.edge.impact);
        if (hot) cls += " hot";
        let marker = "url(#gvm-" + link.kind + ")";
        if (hot) marker = "url(#gvm-" + link.kind + "-hot)";
        const attrs = { d: curve(points, shift, layout.horizontal), class: cls, "marker-end": marker };
        if (model.level === "codebase") {
          attrs.class += " weighted";
          let width = 1.2 + 3.6 * Math.sqrt((link.edge.weight || 0) / model.maxWeight);
          if (hot) width += 1;
          attrs["stroke-width"] = width.toFixed(2);
        }
        const path = svg("path", attrs);
        let title = (nameOf.get(link.source) || link.source) + " " + EDGE_VERBS[link.kind] + " " + (nameOf.get(link.target) || link.target);
        if (model.level === "codebase") {
          title = nameOf.get(link.source) + " → " + nameOf.get(link.target) + ": " + plural(link.edge.weight, "call", "calls");
          if (link.edge.name_links) title += ", " + link.edge.name_links + " more matched by name only";
        }
        path.append(svg("title", { text: title }));
        edgeLayer.append(path);
        remember(link.from, path);
        remember(link.to, path);
      });
    }
    if (layout.looseTop !== null) {
      let label = "Not linked to anything else in this view";
      if (model.boxes.some((box) => box.item.kind === "other")) label = "Not linked to the boxes above";
      nodeLayer.append(svg("text", { class: "gv-band", x: 40, y: layout.looseTop + 12, text: label }));
    }
    for (const box of model.boxes) {
      const place = layout.pos.get(box.id);
      if (!place) continue;
      const item = box.item;
      let cls = "gv-node gv-" + box.kind;
      const review = classReview(item);
      if (review) cls += " rv-" + review;
      if (isLit(item) || (item.members || []).some(isLit)) cls += " lit";
      if (item.impacted) cls += " affected";
      if (item.kind === "other") cls += " gv-other";
      const group = svg("g", { class: cls, transform: "translate(" + place.x.toFixed(1) + "," + place.y.toFixed(1) + ")", tabindex: 0, role: "button", "data-id": box.id, "aria-label": nodeLabel(item, model) });
      group.append(svg("title", { text: nodeTitle(item, model) }));
      group.append(svg("rect", { class: "gv-ring", x: -5, y: -5, width: box.w + 10, height: box.h + 10, rx: 12 }));
      if (box.kind === "area") drawArea(group, box, item, fonts, impact);
      else if (box.kind === "class") drawClass(group, box, item, fonts, view);
      else if (box.kind === "ext") drawExternal(group, box, item, fonts);
      else drawFunction(group, box, item, fonts);
      wireNode(group, box.id, () => activateBox(item), view);
      view.groups.set(box.id, group);
      nodeLayer.append(group);
    }
    canvas.replaceChildren(root);
    attachPanZoom(view);
    return view;
  }

  function anyLit(data) {
    return data.nodes.some((item) => isLit(item) || (item.members || []).some(isLit));
  }

  function classReview(item) {
    if (item.kind !== "class") return item.review;
    const buckets = [item.review].concat((item.members || []).map((row) => row.review)).filter(Boolean);
    buckets.sort((a, b) => LIT_REVIEWS.concat(["skip"]).indexOf(a) - LIT_REVIEWS.concat(["skip"]).indexOf(b));
    return buckets[0] || null;
  }

  function activateBox(item) {
    if (item.kind === "other") {
      setMode("areas");
      return;
    }
    if (item.kind === "area") {
      location.hash = "g=" + item.area;
      return;
    }
    if (item.external) {
      location.hash = "g=" + item.area + "&n=" + encodeURIComponent(item.id);
      return;
    }
    openGraphCard(item.id);
  }

  function attachPanZoom(view) {
    const canvas = view.canvas;
    const apply = () => {
      view.port.setAttribute("transform", "translate(" + view.x.toFixed(1) + "," + view.y.toFixed(1) + ") scale(" + view.k.toFixed(4) + ")");
      view.root.classList.toggle("gv-far", view.k < 0.55);
      graphView.transforms[view.key] = { k: view.k, x: view.x, y: view.y };
    };
    const zoomAt = (px, py, factor) => {
      const next = Math.min(2.5, Math.max(0.12, view.k * factor));
      view.x = px - (px - view.x) * (next / view.k);
      view.y = py - (py - view.y) * (next / view.k);
      view.k = next;
      apply();
    };
    view.fit = () => {
      const width = canvas.clientWidth || 800;
      const height = canvas.clientHeight || 500;
      const k = Math.min(1, Math.max(0.12, Math.min(width / view.layout.width, height / view.layout.height)));
      view.k = k;
      view.x = (width - view.layout.width * k) / 2;
      view.y = Math.max(0, (height - view.layout.height * k) / 2);
      apply();
    };
    view.zoom = (factor) => zoomAt((canvas.clientWidth || 800) / 2, (canvas.clientHeight || 500) / 2, factor);
    view.centre = (id, minimum) => {
      const place = view.layout.pos.get(id);
      if (!place) return;
      if (minimum && view.k < minimum) view.k = minimum;
      view.x = (canvas.clientWidth || 800) / 2 - (place.x + place.w / 2) * view.k;
      view.y = (canvas.clientHeight || 500) / 2 - (place.y + Math.min(place.h, 200) / 2) * view.k;
      apply();
    };
    view.reveal = (id) => {
      let boxId = id;
      if (view.model.owner && view.model.owner.has(id)) boxId = view.model.owner.get(id);
      const place = view.layout.pos.get(boxId);
      if (!place) return;
      const left = view.x + place.x * view.k;
      const top = view.y + place.y * view.k;
      const right = left + place.w * view.k;
      const bottom = top + Math.min(place.h, 240) * view.k;
      if (left < 0 || top < 0 || right > canvas.clientWidth || bottom > canvas.clientHeight) view.centre(boxId);
    };
    view.hover = (id, on) => {
      let boxId = id;
      if (view.model.owner && view.model.owner.has(id)) boxId = view.model.owner.get(id);
      const edges = view.edgesOf.get(boxId) || [];
      view.root.classList.toggle("gv-hl", on && edges.length > 0);
      for (const edge of edges) edge.classList.toggle("near", on);
    };
    let start = null;
    let dragging = false;
    canvas.addEventListener("pointerdown", (event) => {
      if (event.button !== 0) return;
      start = { x: event.clientX, y: event.clientY, vx: view.x, vy: view.y, id: event.pointerId };
      dragging = false;
    });
    canvas.addEventListener("pointermove", (event) => {
      if (!start) return;
      const dx = event.clientX - start.x;
      const dy = event.clientY - start.y;
      if (!dragging && Math.abs(dx) + Math.abs(dy) > 5) {
        dragging = true;
        canvas.classList.add("dragging");
        try { canvas.setPointerCapture(start.id); } catch (err) { dragging = true; }
      }
      if (!dragging) return;
      view.x = start.vx + dx;
      view.y = start.vy + dy;
      apply();
    });
    const stop = () => {
      if (dragging) {
        view.dragged = true;
        setTimeout(() => { view.dragged = false; }, 0);
      }
      start = null;
      dragging = false;
      canvas.classList.remove("dragging");
    };
    canvas.addEventListener("pointerup", stop);
    canvas.addEventListener("pointercancel", stop);
    canvas.addEventListener("wheel", (event) => {
      event.preventDefault();
      const rect = canvas.getBoundingClientRect();
      zoomAt(event.clientX - rect.left, event.clientY - rect.top, Math.exp(-event.deltaY * 0.0015));
    }, { passive: false });
    canvas.addEventListener("keydown", (event) => {
      if (event.target.tagName === "INPUT") return;
      if (event.key === "+" || event.key === "=") view.zoom(1.2);
      else if (event.key === "-" || event.key === "_") view.zoom(1 / 1.2);
      else if (event.key === "0") view.fit();
      else if (event.key === "ArrowLeft") { view.x += 60; apply(); }
      else if (event.key === "ArrowRight") { view.x -= 60; apply(); }
      else if (event.key === "ArrowUp") { view.y += 60; apply(); }
      else if (event.key === "ArrowDown") { view.y -= 60; apply(); }
      else if (event.key === "Escape" && view.area !== null) { location.hash = ""; }
      else return;
      event.preventDefault();
    });
    const saved = graphView.transforms[view.key];
    if (saved) {
      view.k = saved.k;
      view.x = saved.x;
      view.y = saved.y;
      apply();
    } else {
      view.fit();
    }
  }

  function markGraphSelection(id) {
    const view = graphView.live;
    if (!view || !view.canvas.isConnected) return;
    view.root.querySelectorAll(".sel").forEach((el) => el.classList.remove("sel"));
    view.selected = id;
    const found = view.root.querySelector('[data-id="' + CSS.escape(id) + '"]');
    if (found) found.classList.add("sel");
  }

  async function openGraphCard(id) {
    let card;
    try {
      card = await api("/api/node?id=" + encodeURIComponent(id) + "&depth=1");
    } catch (err) {
      toast(err.message);
      return;
    }
    state.selected = id;
    state.card = card;
    renderCard(card);
    markGraphSelection(id);
    const view = graphView.live;
    if (view && view.canvas.isConnected) requestAnimationFrame(() => view.reveal(id));
  }

  function graphMounted() {
    return Boolean(graphView.live && graphView.live.canvas.isConnected && state.mode === "graph");
  }

  function graphStatus(data, model) {
    const parts = [];
    if (data.level === "codebase") {
      let shown = plural(data.areas_total, "area", "areas");
      if (data.folded) shown = (data.nodes.length - 1) + " of " + data.areas_total + " areas drawn (changed first, then largest)";
      parts.push(shown);
      const changed = data.nodes.filter((item) => item.changed).length;
      if (data.changes) parts.push(changed + " with changes");
      if (model && model.thinned) parts.push("strongest " + model.links.length + " of " + model.linksTotal + " links");
    } else {
      parts.push(data.shown + " of " + plural(data.total, "function, class or method", "functions, classes and methods") + " drawn");
      if (data.area.changed) parts.push(data.area.changed + " changed");
    }
    if (data.impact) {
      const affected = data.nodes.filter((item) => item.impacted).length + data.nodes.reduce((sum, item) => sum + (item.members || []).filter((row) => row.impacted).length, 0);
      if (anyLit(data)) parts.push(affected + " call changed code");
      else parts.push("nothing here changed or calls changed code");
    }
    return parts.join(" · ");
  }

  function rerenderGraph() {
    const view = graphView.live;
    let area = null;
    if (view) area = view.area;
    const main = $("main");
    main.replaceChildren();
    renderGraph(main, area, state.selected, true);
  }

  async function renderGraph(main, areaId, focusId, keepCard) {
    main.className = "main graph-main";
    graphView.token += 1;
    const token = graphView.token;
    const head = h("div", { class: "gv-head" });
    if (areaId === null || areaId === undefined) {
      head.append(h("h1", { text: "Graph" }),
        h("p", { class: "lede gv-lede", text: "Every area of the code as a box; arrows show which areas call into which, thicker means more calls. Click an area to open its classes and functions." }));
    } else {
      head.append(h("div", { class: "gv-crumb" }, h("button", { class: "linkbtn", type: "button", onclick: () => { location.hash = ""; } }, "All areas"), h("span", { text: " / " }), h("span", { class: "gv-crumb-here", text: "Area " + areaId })));
    }
    const status = h("span", { class: "gv-status", "aria-live": "polite" });
    const impactButton = h("button", { class: "gv-btn gv-impact", type: "button", "aria-pressed": String(state.graphImpact), title: "Keep changed code and everything that calls it (up to 3 calls away) bright; fade the rest." }, "Impact");
    const more = h("button", { class: "gv-btn", type: "button", hidden: true }, "Show " + GRAPH_STEP + " more");
    const zoomOut = h("button", { class: "gv-btn", type: "button", "aria-label": "Zoom out", title: "Zoom out ( - )" }, "−");
    const zoomIn = h("button", { class: "gv-btn", type: "button", "aria-label": "Zoom in", title: "Zoom in ( + )" }, "+");
    const fit = h("button", { class: "gv-btn", type: "button", title: "Fit to screen ( 0 )" }, "Fit");
    const allLinks = h("button", { class: "gv-btn gv-toggle", type: "button", hidden: true, "aria-pressed": String(state.graphAllLinks), title: "Draw every link between areas, not only the strongest ones for each area." }, "All links");
    const tools = h("div", { class: "gv-tools" }, status, more, allLinks, impactButton, h("span", { class: "gv-zoom" }, zoomOut, zoomIn, fit));
    const canvas = h("div", { class: "gv-canvas", tabindex: "0", role: "group", "aria-label": "Diagram. Drag to move, scroll or press + and - to zoom, 0 to fit. Tab moves between boxes, Enter opens one." });
    canvas.append(h("div", { class: "gv-loading", text: "Drawing the diagram…" }));
    const legend = h("div", { class: "gv-legend" });
    main.append(head, tools, canvas, legend);
    if (!keepCard) {
      state.selected = null;
      closeCard();
    }
    const params = [];
    if (areaId !== null && areaId !== undefined) {
      params.push("area=" + encodeURIComponent(areaId));
      params.push("limit=" + graphLimit(areaId));
    }
    if (state.graphImpact) params.push("impact=1");
    let url = "/api/diagram";
    if (params.length) url += "?" + params.join("&");
    let data;
    try {
      data = await api(url);
    } catch (err) {
      canvas.replaceChildren(h("div", { class: "notice", text: err.message }));
      return;
    }
    if (token !== graphView.token || state.mode !== "graph") return;
    if (data.level === "area") {
      head.replaceChildren(
        h("div", { class: "gv-crumb" }, h("button", { class: "linkbtn", type: "button", onclick: () => { location.hash = ""; } }, "All areas"), h("span", { text: " / " }), h("span", { class: "gv-crumb-here", text: data.area.where })),
        h("h1", { text: data.area.name }),
        h("p", { class: "lede gv-lede", text: "Classes and functions in this area and what calls what. Click one to see what it does, what changed and what it affects; click a dashed box to jump to its area." }));
    }
    status.textContent = graphStatus(data, null);
    if (!data.changes) {
      impactButton.disabled = true;
      impactButton.title = "No comparison yet. Run skylos graph --since main to see what changed and what it affects.";
    }
    impactButton.addEventListener("click", () => {
      state.graphImpact = !state.graphImpact;
      rerenderGraph();
    });
    if (data.level === "area" && data.more) {
      more.hidden = false;
      more.addEventListener("click", () => {
        state.graphLimits[String(areaId)] = data.limit + GRAPH_STEP;
        rerenderGraph();
      });
    }
    legend.append(...graphLegend(data.level));
    if (!data.nodes.length) {
      canvas.replaceChildren(h("div", { class: "notice", text: "Nothing to draw here yet." }));
      return;
    }
    const started = performance.now();
    let model = null;
    if (data.level === "codebase") model = codebaseModel(data);
    else model = areaModel(data);
    status.textContent = graphStatus(data, model);
    if (data.level === "codebase" && (model.thinned || state.graphAllLinks)) {
      allLinks.hidden = false;
      allLinks.addEventListener("click", () => {
        state.graphAllLinks = !state.graphAllLinks;
        rerenderGraph();
      });
    }
    const layout = chooseLayout(model, canvas);
    const key = data.level + ":" + (areaId || "") + ":" + (data.limit || "") + ":" + String(state.graphAllLinks);
    const view = drawDiagram(canvas, model, layout, data, key);
    graphView.live = view;
    canvas.dataset.renderMs = String(Math.round(performance.now() - started));
    canvas.dataset.crossings = String(layout.crossings);
    zoomOut.addEventListener("click", () => view.zoom(1 / 1.25));
    zoomIn.addEventListener("click", () => view.zoom(1.25));
    fit.addEventListener("click", () => view.fit());
    if (focusId) {
      let boxId = focusId;
      if (model.owner && model.owner.has(focusId)) boxId = model.owner.get(focusId);
      if (layout.pos.has(boxId)) {
        if (!keepCard) view.centre(boxId, 0.8);
        if (keepCard) markGraphSelection(focusId);
        else openGraphCard(focusId);
      }
    }
  }

  function showGraphArea(areaId, focusId) {
    markMode("graph");
    const view = graphView.live;
    if (focusId && graphMounted() && view.area === String(areaId)) {
      let boxId = focusId;
      if (view.model.owner && view.model.owner.has(focusId)) boxId = view.model.owner.get(focusId);
      view.centre(boxId, 0.8);
      openGraphCard(focusId);
      return;
    }
    const main = $("main");
    main.replaceChildren();
    renderGraph(main, String(areaId), focusId, false);
  }

  let searchTimer = null;
  let searchIndex = -1;

  function searchResults(items) {
    const list = $("results");
    searchIndex = -1;
    if (!items.length) { list.hidden = true; return; }
    list.replaceChildren(...items.map((item, i) => h("li", { role: "option", "data-i": i, onmousedown: (e) => { e.preventDefault(); pick(item.id); } },
      kindChip(item.kind, item.is_test), " ", h("b", { text: item.name }), h("div", { class: "where", text: item.file + ":" + item.line }))));
    list.hidden = false;
    list.items = items;
  }

  async function pick(id) {
    $("results").hidden = true;
    $("q").blur();
    if (!graphMounted()) {
      select(id);
      return;
    }
    let card;
    try { card = await api("/api/node?id=" + encodeURIComponent(id) + "&depth=1"); } catch (err) { toast(err.message); return; }
    if (card.area) location.hash = "g=" + card.area.id + "&n=" + encodeURIComponent(id);
    else openGraphCard(id);
  }

  function wire() {
    $("mode-graph").addEventListener("click", () => setMode("graph"));
    $("mode-map").addEventListener("click", () => setMode("map"));
    $("mode-areas").addEventListener("click", () => setMode("areas"));
    $("mode-changes").addEventListener("click", () => setMode("changes"));
    $("mode-pipeline").addEventListener("click", () => setMode("pipeline"));
    $("run-check").addEventListener("click", runCheck);
    $("group-folders").addEventListener("click", () => setGroup("folders"));
    $("group-areas").addEventListener("click", () => setGroup("areas"));
    $("tree-filter").addEventListener("input", (e) => { state.filter = e.target.value; renderTree(); });
    $("show-tests").addEventListener("change", (e) => { state.showTests = e.target.checked; renderTree(); });
    const q = $("q");
    q.addEventListener("input", () => {
      clearTimeout(searchTimer);
      const text = q.value.trim();
      if (!text) { $("results").hidden = true; return; }
      searchTimer = setTimeout(async () => {
        try { searchResults((await api("/api/search?q=" + encodeURIComponent(text))).results); } catch (err) { toast(err.message); }
      }, 120);
    });
    q.addEventListener("keydown", (e) => {
      const list = $("results");
      const items = list.items || [];
      if (e.key === "Escape") { list.hidden = true; q.blur(); return; }
      if (list.hidden || !items.length) return;
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        let step = -1;
        if (e.key === "ArrowDown") step = 1;
        searchIndex = (searchIndex + step + items.length) % items.length;
        list.querySelectorAll("li").forEach((li, i) => li.setAttribute("aria-selected", String(i === searchIndex)));
      } else if (e.key === "Enter") {
        e.preventDefault();
        pick(items[Math.max(0, searchIndex)].id);
      }
    });
    q.addEventListener("blur", () => setTimeout(() => { $("results").hidden = true; }, 100));
    document.addEventListener("keydown", (e) => {
      if (e.key === "/" && document.activeElement.tagName !== "INPUT" && document.activeElement.tagName !== "TEXTAREA") { e.preventDefault(); q.focus(); }
    });
    window.addEventListener("hashchange", route);
    const events = new EventSource("/api/events");
    events.addEventListener("reload", async () => {
      await load();
      toast("Graph updated");
      route();
    });
  }

  const check = { status: null, timer: null };

  function clock(seconds) {
    const minutes = Math.floor(seconds / 60);
    return minutes + ":" + String(seconds % 60).padStart(2, "0");
  }

  function checkLabel(status) {
    if (status.state !== "running") return "Check this change";
    const seconds = Math.max(0, Math.round(Date.now() / 1000 - status.started_at));
    return "Checking… " + clock(seconds);
  }

  function checkPanel() {
    const status = check.status;
    if (!status || !status.available || status.state === "idle") return "";
    let tone = "pipe-live";
    if (status.state === "passed") tone += " pass";
    if (status.state === "blocked" || status.state === "error") tone += " fail";
    const panel = h("section", { class: tone, id: "check-live", "aria-live": "polite" },
      h("div", { class: "pipe-live-head" },
        h("strong", { text: status.message || "" }),
        h("code", { text: status.command })));
    const lines = (status.log || []).slice(-14).join("\n");
    if (lines) panel.append(h("pre", { text: lines }));
    return panel;
  }

  function showCheck(status) {
    check.status = status;
    const button = $("run-check");
    button.hidden = !status.available;
    button.disabled = status.state === "running";
    button.textContent = checkLabel(status);
    const live = $("check-live");
    const fresh = checkPanel();
    if (live && fresh) live.replaceWith(fresh);
  }

  async function pollCheck() {
    clearTimeout(check.timer);
    let status;
    try { status = await api("/api/check"); } catch (err) { return; }
    const wasRunning = Boolean(check.status && check.status.state === "running");
    showCheck(status);
    if (status.state === "running") {
      check.timer = setTimeout(pollCheck, 1000);
      return;
    }
    if (!wasRunning) return;
    toast(status.message);
    await load();
    setMode("pipeline");
  }

  async function runCheck() {
    $("run-check").disabled = true;
    try {
      showCheck(await api("/api/check", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }));
    } catch (err) {
      toast(err.message);
    }
    setMode("pipeline");
    pollCheck();
  }

  async function start() {
    wire();
    try {
      await load();
    } catch (err) {
      $("main").replaceChildren(h("div", { class: "notice", text: err.message }));
      return;
    }
    route();
    pollCheck();
  }

  start();
})();
