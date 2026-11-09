"""Scope filtering, label application, metrics and report tables."""

from __future__ import annotations

import hashlib
import json
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path

from .corpus import Workspace
from .tools import CATEGORIES

VERDICTS = {"tp", "fp"}


def fingerprint(ws_id: str, f: dict) -> str:
    key = f"{ws_id}|{f['tool']}|{f['rule']}|{f['file']}|{f['line']}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def dedupe(findings: list[dict]) -> list[dict]:
    """One finding per (tool, rule, file, line); applied identically to every tool."""
    seen, out = set(), []
    for f in sorted(findings, key=lambda x: (x["file"], x["line"], x["rule"])):
        key = (f["tool"], f["rule"], f["file"], f["line"])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def in_scope(ws: Workspace, findings: list[dict]) -> list[dict]:
    return [f for f in findings if ws.in_scope(f["file"], f["line"])]


def location_candidates(ws: Workspace, f: dict) -> list[str]:
    """Seeded defects whose location window contains the finding (a hint for labelers)."""
    return [
        f"{ws.id}/{d.id}"
        for d in ws.defects
        if any(loc.contains(f["file"], f["line"]) for loc in d.locations)
    ]


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float] | None:
    if n == 0:
        return None
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def _ratio(k: int, n: int) -> dict:
    ci = wilson(k, n)
    return {
        "k": k,
        "n": n,
        "value": (k / n) if n else None,
        "ci95": [round(ci[0], 3), round(ci[1], 3)] if ci else None,
    }


def fmt_ratio(r: dict) -> str:
    if not r["n"]:
        return "n/a"
    lo, hi = r["ci95"]
    return f"{r['k']}/{r['n']} = {r['value']:.2f} [{lo:.2f}-{hi:.2f}]"


def load_labels(path: Path) -> dict:
    if not path.exists():
        return {}
    data = json.loads(path.read_text())
    labels = data.get("labels", data)
    for fp, lab in labels.items():
        if lab.get("verdict") not in VERDICTS:
            raise ValueError(f"label {fp}: verdict must be one of {sorted(VERDICTS)}")
        if not lab.get("reason"):
            raise ValueError(f"label {fp}: every label needs a written reason")
    return labels


def build_report(
    workspaces: list[Workspace],
    runs: dict[tuple[str, str], dict],
    normalized: dict[tuple[str, str], tuple[list[dict], dict]],
    labels: dict,
    tools: list[str],
) -> dict:
    """Compute every metric from normalized findings + labels. Pure function of its inputs."""
    ws_by_id = {w.id: w for w in workspaces}
    scoped: list[dict] = []
    for (tool, ws_id), (findings, _signals) in normalized.items():
        ws = ws_by_id[ws_id]
        for f in in_scope(ws, dedupe(findings)):
            f = dict(f)
            f["workspace"] = ws_id
            f["kind"] = ws.kind
            f["fingerprint"] = fingerprint(ws_id, f)
            lab = labels.get(f["fingerprint"])
            f["verdict"] = lab["verdict"] if lab else None
            f["detects"] = (lab or {}).get("detects")
            if f["detects"] and f["detects"] not in location_candidates(ws, f):
                raise ValueError(
                    f"label {f['fingerprint']} claims to detect {f['detects']} but the finding is outside that defect's location window"
                )
            scoped.append(f)

    report: dict = {"tools": tools, "seeded": {}, "real": {}, "timing": {}, "incomplete": {}, "labels": {}}

    # ---------------------------------------------------------------- seeded recall
    seeded_ws = [w for w in workspaces if w.kind == "seeded"]
    defects = [(w, d) for w in seeded_ws for d in w.defects]
    defect_cats = sorted({d.category for _, d in defects})
    detected: dict[str, set[str]] = defaultdict(set)
    for f in scoped:
        if f["kind"] == "seeded" and f["detects"] and f["verdict"] == "tp":
            detected[f["tool"]].add(f["detects"])

    recall = {}
    for tool in tools:
        ran = {w.id for w in seeded_ws if runs.get((tool, w.id), {}).get("status") in {"ok", "not_applicable"}}
        by_cat = {}
        for cat in defect_cats + ["ALL"]:
            rows = [(w, d) for w, d in defects if cat in ("ALL", d.category)]
            k = sum(1 for w, d in rows if f"{w.id}/{d.id}" in detected[tool])
            by_cat[cat] = _ratio(k, len(rows))
        by_lang = {}
        for lang in sorted({w.language for w in seeded_ws}):
            rows = [(w, d) for w, d in defects if w.language == lang]
            k = sum(1 for w, d in rows if f"{w.id}/{d.id}" in detected[tool])
            by_lang[lang] = _ratio(k, len(rows))
        recall[tool] = {
            "by_category": by_cat,
            "by_language": by_lang,
            "workspaces_run": len(ran),
            "detected": sorted(detected[tool]),
        }
    report["seeded"]["recall"] = recall
    report["seeded"]["defect_counts"] = dict(Counter(d.category for _, d in defects))
    report["seeded"]["case_count"] = len(seeded_ws)
    report["seeded"]["clean_case_count"] = sum(1 for w in seeded_ws if w.clean)

    # ---------------------------------------------------------------- precision
    def precision(kind: str, tool: str, category: str | None = None) -> dict:
        rows = [
            f for f in scoped
            if f["kind"] == kind and f["tool"] == tool and (category is None or f["category"] == category)
        ]
        tp = sum(1 for f in rows if f["verdict"] == "tp")
        fp = sum(1 for f in rows if f["verdict"] == "fp")
        out = _ratio(tp, tp + fp)
        out["unlabeled"] = sum(1 for f in rows if f["verdict"] is None)
        out["total"] = len(rows)
        return out

    for kind in ("seeded", "real"):
        report[kind]["precision"] = {
            tool: {"ALL": precision(kind, tool), **{c: precision(kind, tool, c) for c in CATEGORIES}}
            for tool in tools
        }

    report["seeded"]["clean_case_findings"] = {
        tool: sum(1 for f in scoped if f["tool"] == tool and ws_by_id[f["workspace"]].clean)
        for tool in tools
    }

    # ---------------------------------------------------------------- real: density
    real_ws = [w for w in workspaces if w.kind == "real"]
    kloc = sum(w.added_source_lines for w in real_ws) / 1000.0
    density = {}
    for tool in tools:
        rows = [f for f in scoped if f["kind"] == "real" and f["tool"] == tool]
        density[tool] = {
            "findings": len(rows),
            "per_changed_kloc": round(len(rows) / kloc, 2) if kloc else None,
            "tp_per_changed_kloc": round(sum(1 for f in rows if f["verdict"] == "tp") / kloc, 2) if kloc else None,
            "by_category": {c: sum(1 for f in rows if f["category"] == c) for c in CATEGORIES},
            "commits_with_findings": len({f["workspace"] for f in rows}),
        }
    report["real"]["density"] = density
    report["real"]["commit_count"] = len(real_ws)
    report["real"]["added_source_lines"] = sum(w.added_source_lines for w in real_ws)
    report["real"]["by_language"] = dict(Counter(w.language for w in real_ws))
    report["real"]["by_agent"] = dict(Counter(w.meta.get("agent") for w in real_ws))

    # ---------------------------------------------------------------- timing
    for tool in tools:
        tt = {}
        for kind in ("seeded", "real"):
            walls = [
                r["wall_s"] for (t, wid), r in runs.items()
                if t == tool and ws_by_id[wid].kind == kind and r.get("wall_s") is not None and r["status"] == "ok"
            ]
            tt[kind] = _timing(walls)
        report["timing"][tool] = tt

    # ---------------------------------------------------------------- incompleteness
    for tool in tools:
        status_counts = Counter(r["status"] for (t, _), r in runs.items() if t == tool)
        with_reported_errors = []
        for (t, wid), (_f, signals) in normalized.items():
            if t == tool and signals.get("reported_errors"):
                with_reported_errors.append(wid)
        unparseable = {}
        for w in seeded_ws:
            if not w.unparseable:
                continue
            run = runs.get((tool, w.id), {})
            sig = normalized.get((tool, w.id), ([], {}))[1]
            broken = {loc.file for d in w.defects for loc in d.locations}
            reported = [e for e in sig.get("reported_errors", []) if e.get("file") in broken]
            found = [f"{w.id}/{d.id}" in detected[tool] for d in w.defects]
            if run.get("status") == "not_applicable":
                outcome = "not applicable (language not supported)"
            elif run.get("status") != "ok":
                outcome = f"run {run.get('status')}"
            elif all(found):
                outcome = "defect reported despite syntax error"
            elif reported:
                outcome = "reported the file as not analyzed (parse error surfaced)"
            else:
                outcome = "silent: no finding and no parse error for the broken file"
            unparseable[w.id] = {"outcome": outcome, "reported_errors": reported}
        report["incomplete"][tool] = {
            "run_status": dict(status_counts),
            "workspaces_with_tool_reported_errors": sorted(with_reported_errors),
            "unparseable_cases": unparseable,
        }

    # ---------------------------------------------------------------- label coverage
    report["labels"] = {
        "scoped_findings": len(scoped),
        "labeled": sum(1 for f in scoped if f["verdict"]),
        "unlabeled": sum(1 for f in scoped if not f["verdict"]),
    }
    report["_scoped_findings"] = scoped
    return report


def _timing(walls: list[float]) -> dict:
    if not walls:
        return {"runs": 0}
    walls = sorted(walls)
    p90 = walls[min(len(walls) - 1, math.ceil(0.9 * len(walls)) - 1)]
    return {
        "runs": len(walls),
        "median_s": round(statistics.median(walls), 2),
        "p90_s": round(p90, 2),
        "max_s": round(walls[-1], 2),
        "total_s": round(sum(walls), 1),
    }


# ---------------------------------------------------------------- markdown


def render_tables(report: dict, env: dict) -> str:
    tools = report["tools"]
    lines: list[str] = []
    add = lines.append
    add("# agent-pr-bench results")
    add("")
    add("Generated by `benchmarks/agent-pr-bench/bench.py score`. Do not edit by hand.")
    add("")
    add("## Environment")
    add("")
    for k, v in env.items():
        add(f"- **{k}**: {v if not isinstance(v, (dict, list)) else json.dumps(v)}")
    add("")
    lab = report["labels"]
    add(f"In-scope findings: {lab['scoped_findings']} ({lab['labeled']} labeled, {lab['unlabeled']} unlabeled).")
    add("")

    add("## Seeded corpus: recall by defect category")
    add("")
    add(f"{report['seeded']['case_count']} cases ({report['seeded']['clean_case_count']} clean controls), "
        f"{sum(report['seeded']['defect_counts'].values())} seeded defects. Cells: detected/total = recall [Wilson 95% CI].")
    add("")
    cats = sorted(report["seeded"]["defect_counts"]) + ["ALL"]
    add("| Category | n | " + " | ".join(tools) + " |")
    add("|---|---|" + "---|" * len(tools))
    for cat in cats:
        n = sum(report["seeded"]["defect_counts"].values()) if cat == "ALL" else report["seeded"]["defect_counts"][cat]
        cells = [fmt_ratio(report["seeded"]["recall"][t]["by_category"][cat]) for t in tools]
        add(f"| {cat} | {n} | " + " | ".join(cells) + " |")
    add("")
    add("Recall by language (all categories):")
    add("")
    langs = sorted(next(iter(report["seeded"]["recall"].values()))["by_language"])
    add("| Language | " + " | ".join(tools) + " |")
    add("|---|" + "---|" * len(tools))
    for lang in langs:
        add(f"| {lang} | " + " | ".join(fmt_ratio(report["seeded"]["recall"][t]["by_language"][lang]) for t in tools) + " |")
    add("")

    for kind, title in (("seeded", "Seeded corpus"), ("real", "Real agent commits")):
        add(f"## {title}: precision of in-scope findings")
        add("")
        add("Cells: TP/(TP+FP) = precision [Wilson 95% CI]; `u` = unlabeled findings excluded.")
        add("")
        add("| Category | " + " | ".join(tools) + " |")
        add("|---|" + "---|" * len(tools))
        for cat in ["ALL", *CATEGORIES]:
            cells = []
            for t in tools:
                r = report[kind]["precision"][t][cat]
                if not r["total"]:
                    cells.append("-")
                    continue
                cells.append(fmt_ratio(r) + (f" u={r['unlabeled']}" if r["unlabeled"] else ""))
            add(f"| {cat} | " + " | ".join(cells) + " |")
        add("")

    add("Findings on clean control cases (every one is a false alarm unless labeled otherwise): "
        + ", ".join(f"{t}={report['seeded']['clean_case_findings'][t]}" for t in tools))
    add("")

    add("## Real agent commits: finding volume")
    add("")
    real = report["real"]
    add(f"{real['commit_count']} commits, {real['added_source_lines']} added source lines "
        f"({real['added_source_lines'] / 1000:.2f} kLOC). Languages: {real['by_language']}. Agents: {real['by_agent']}.")
    add("")
    add("| Tool | Findings | Findings / changed kLOC | TP / changed kLOC | Commits with >=1 finding | " + " | ".join(CATEGORIES) + " |")
    add("|---|---|---|---|---|" + "---|" * len(CATEGORIES))
    for t in tools:
        d = real["density"][t]
        add(f"| {t} | {d['findings']} | {d['per_changed_kloc']} | {d['tp_per_changed_kloc']} | {d['commits_with_findings']} | "
            + " | ".join(str(d["by_category"][c]) for c in CATEGORIES) + " |")
    add("")

    add("## Wall time per change")
    add("")
    add("| Tool | Corpus | Runs | Median s | p90 s | Max s | Total s |")
    add("|---|---|---|---|---|---|---|")
    for t in tools:
        for kind in ("seeded", "real"):
            tm = report["timing"][t][kind]
            if not tm.get("runs"):
                add(f"| {t} | {kind} | 0 | - | - | - | - |")
                continue
            add(f"| {t} | {kind} | {tm['runs']} | {tm['median_s']} | {tm['p90_s']} | {tm['max_s']} | {tm['total_s']} |")
    add("")

    add("## Incomplete / unknown handling")
    add("")
    add("| Tool | Run status counts | Workspaces where the tool reported analysis errors |")
    add("|---|---|---|")
    for t in tools:
        inc = report["incomplete"][t]
        errs = inc["workspaces_with_tool_reported_errors"]
        add(f"| {t} | {inc['run_status']} | {len(errs)}: {', '.join(errs) if errs else '-'} |")
    add("")
    add("Unparseable seeded files (syntax error + injection in the same file):")
    add("")
    add("| Case | " + " | ".join(tools) + " |")
    add("|---|" + "---|" * len(tools))
    cases = sorted({c for t in tools for c in report["incomplete"][t]["unparseable_cases"]})
    for c in cases:
        add(f"| {c} | " + " | ".join(report["incomplete"][t]["unparseable_cases"].get(c, {}).get("outcome", "-") for t in tools) + " |")
    add("")
    return "\n".join(lines) + "\n"
