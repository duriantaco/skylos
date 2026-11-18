"""Explain the comparison using Git and Skylos's static change map."""
from __future__ import annotations

import ast
import textwrap
from subprocess import SubprocessError

from .explain import owned


def changed_files(root, base_commit, *, ci):
    from skylos.core.git_context import GitContext
    from skylos.done.base import is_runtime_path

    if base_commit is None:
        return []
    context = GitContext.from_path(root)
    result = context.run("diff", "--name-status", "--find-renames", "-z", base_commit, "--")
    if result.returncode:
        raise ValueError("Could not list the files in the UML comparison")
    fields = iter(result.stdout.rstrip("\0").split("\0")) if result.stdout else iter(())
    files = []
    for status in fields:
        path = next(fields)
        previous = None
        if status.startswith(("R", "C")):
            previous, path = path, next(fields)
        files.append({"path": path, "status": status[0], "previous": previous})
    if not ci:
        result = context.run("ls-files", "--others", "--exclude-standard", "-z")
        if result.returncode == 0:
            files.extend({"path": path, "status": "A", "previous": None} for path in result.stdout.split("\0") if path)
    return sorted(
        (file for file in files if not is_runtime_path(file["path"]) and not file["path"].startswith("UML/")),
        key=lambda file: file["path"],
    )


_OPERATORS = {ast.Add: "plus", ast.Sub: "minus", ast.Mult: "times", ast.Div: "divided by"}


def _simple_result(side):
    if not side or side.get("truncated"):
        return None
    try:
        body = ast.parse(textwrap.dedent(side["code"])).body
    except (SyntaxError, ValueError, RecursionError):
        return None
    if not body or not isinstance(body[0], (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    function = body[0]
    returns = [node for node in owned(function) if isinstance(node, ast.Return)]
    if len(returns) != 1 or returns[0] not in function.body:
        return None
    value = returns[0].value
    if value is None:
        return "no value"
    if isinstance(value, ast.BinOp) and type(value.op) in _OPERATORS:
        return f"{ast.unparse(value.left)} {_OPERATORS[type(value.op)]} {ast.unparse(value.right)}"[:160]
    return ast.unparse(value)[:160]


def _explanation(entry):
    from skylos.changemap.render import why_line

    before, after = entry["before"], entry["after"]
    sentences = []
    if entry.get("moved_from"):
        sentences.append(f"Moved here from {entry['moved_from'].partition('::')[0]}.")
    if entry.get("moved_to"):
        sentences.append(f"Moved to {entry['moved_to'].partition('::')[0]}.")
    if entry.get("signature_changed") and before and after:
        sentences.append(f"Inputs changed from ({before['signature']}) to ({after['signature']}).")
    for field, phrase in (
        ("calls_added", "Now calls"),
        ("calls_removed", "Stops calling"),
        ("rejections_removed", "Stops rejecting"),
        ("still_referenced_by", "Still referenced by"),
    ):
        if entry.get(field):
            sentences.append(f"{phrase} {', '.join(entry[field][:3])}.")
    for value in (entry.get("values_changed") or [])[:3]:
        sentences.append(f"Changes {value['name']} from {value['before']} to {value['after']}.")
    if entry["file"].endswith(".py") and after and not entry.get("same_logic"):
        old, new = _simple_result(before), _simple_result(after)
        if old is not None and new is not None and old != new:
            sentences.append(f"Changes the returned value from {old} to {new}.")
        elif before is None and new is not None:
            sentences.append(f"Returns {new}.")
    if not sentences:
        sentences.append(why_line(entry))
    callers = entry.get("callers") or []
    if callers and entry["status"] == "modified":
        names = [caller["name"].rsplit(".", 1)[-1] for caller in callers[:3]]
        sentences.append(f"Used by {', '.join(names)}.")
    sentences.extend(entry.get("test_evidence", [])[:1])
    return sentences


def workflow_jobs(source):
    import yaml

    try:
        document = yaml.safe_load(source)
    except (yaml.YAMLError, RecursionError):
        return None
    jobs = document.get("jobs") if isinstance(document, dict) else None
    if not isinstance(jobs, dict):
        return None
    return {name: job for name, job in jobs.items() if isinstance(name, str) and isinstance(job, dict)}


def _workflow_steps(job):
    steps = job.get("steps")
    if not isinstance(steps, list):
        return {}
    result = {}
    for step in steps:
        if not isinstance(step, dict):
            continue
        label = step.get("name") or step.get("id") or step.get("uses")
        if isinstance(label, str):
            command = {key: step[key] for key in ("run", "uses", "if", "shell") if isinstance(step.get(key), str)}
            inputs = step.get("with")
            if isinstance(inputs, dict):
                command["with"] = {key: value for key, value in inputs.items() if isinstance(key, str) and isinstance(value, (str, bool, int, float))}
            result[label] = command
    return result


def _workflow_changes(root, base_commit, files):
    from skylos.core.git_context import GitContext

    rows = []
    context = GitContext.from_path(root)
    for file in files:
        path = file["path"]
        if not path.startswith(".github/workflows/") or not path.endswith((".yml", ".yaml")):
            continue
        previous = file["previous"] or path
        before = context.run("show", f"{base_commit}:{previous}") if file["status"] != "A" else None
        old = {} if before is None else workflow_jobs(before.stdout) if before.returncode == 0 else None
        target = root / path
        new = None
        if file["status"] == "D":
            new = {}
        elif target.is_file() and not target.is_symlink() and target.resolve().is_relative_to(root):
            new = workflow_jobs(target.read_text(encoding="utf-8", errors="replace"))
        if old is None or new is None:
            continue
        summary = []
        for name in sorted(set(old) | set(new)):
            if name not in old:
                summary.append(f"Adds the {name} job.")
            elif name not in new:
                summary.append(f"Removes the {name} job.")
            else:
                old_steps, new_steps = _workflow_steps(old[name]), _workflow_steps(new[name])
                summary.extend(f"Adds the {step} step to {name}." for step in new_steps if step not in old_steps)
                summary.extend(f"Removes the {step} step from {name}." for step in old_steps if step not in new_steps)
                summary.extend(f"Changes how {step} runs in {name}." for step in new_steps if step in old_steps and old_steps[step] != new_steps[step])
        if summary:
            rows.append({"file": path, "explanation": summary})
    return rows


def build_comparison(root, base_ref, base_commit, files, *, ci):
    from skylos.changemap import build_change_map

    overview = {"files": files, "symbols": [], "moduleChanges": [], "workflows": [], "analyzed": False}
    if base_commit is None:
        meta = {"available": False, "base": None, "scope": "Initial snapshot. No comparison commit is available."}
        return {}, meta, overview

    scope = "Changes since" if ci else "Working tree compared with"
    meta = {"available": True, "base": base_ref, "baseCommit": base_commit, "scope": f"{scope} {base_ref}."}
    if not files:
        return {}, meta, overview
    overview["workflows"] = _workflow_changes(root, base_commit, files)
    try:
        change_map = build_change_map(root, base_commit)
    except (OSError, ValueError, SubprocessError) as error:
        return {}, {**meta, "message": type(error).__name__}, overview

    paths = {file["path"] for file in files}
    paths.update(file["previous"] for file in files if file["previous"])
    first = set(change_map["read_first"])
    symbols = sorted(change_map["symbols"], key=lambda entry: (entry["is_test"], entry["id"] not in first))
    changes = {}
    for entry in symbols:
        if entry["file"] not in paths:
            continue
        before, after = entry["before"], entry["after"]
        overview["symbols"].append({
            "id": entry["id"], "name": entry["name"], "file": entry["file"],
            "line": (after or before)["start"], "status": entry["status"], "inUml": after is not None,
            "explanation": _explanation(entry),
        })
        if after is not None:
            changes[entry["id"]] = {
                "verdict": entry["verdict_text"], "reasons": entry["reasons"],
                "before": before["code"] if before else "", "after": after["code"],
            }
    overview["moduleChanges"] = [item for item in change_map["module_changes"] if item["file"] in paths]
    overview["analyzed"] = True
    return changes, meta, overview
