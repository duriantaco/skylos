"""Local source facts and reading notes for the personal review map."""
from __future__ import annotations

import ast
import copy
import json
import re
from collections import defaultdict, deque
from pathlib import Path

from .cache import digest, read_json, write_json


def owned(node):
    """Walk this function's code without attributing nested definitions to it."""
    yield node
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        yield from owned(child)


def name_of(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = name_of(node.value)
        return (parent + "." if parent else "") + node.attr
    if isinstance(node, ast.Call):
        return name_of(node.func) + "()"
    return ""


def describe_value(node):
    if node is None or isinstance(node, ast.Constant) and node.value is None:
        return "no value"
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool):
            return "yes" if node.value else "no"
        if isinstance(node.value, str):
            return "text"
        if isinstance(node.value, (int, float)):
            return "a number"
    if isinstance(node, ast.Dict):
        keys = [k.value for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)]
        return "a dictionary" + (" with fields " + ", ".join(keys[:6]) if keys else "")
    if isinstance(node, (ast.List, ast.ListComp)):
        return "a list"
    if isinstance(node, (ast.Set, ast.SetComp)):
        return "a set"
    if isinstance(node, ast.Tuple):
        return "a group of " + str(len(node.elts)) + " values"
    if isinstance(node, (ast.Compare, ast.BoolOp)):
        return "a yes/no answer"
    if isinstance(node, ast.IfExp):
        a, b = describe_value(node.body), describe_value(node.orelse)
        return a if a == b else a + " or " + b
    if isinstance(node, ast.Call):
        name = name_of(node.func)
        builtins = {"str": "text", "bool": "a yes/no answer", "int": "an integer", "list": "a list", "dict": "a dictionary", "tuple": "a group of values", "set": "a set"}
        return builtins.get(name, "the result of " + name + "()")
    if isinstance(node, (ast.Name, ast.Attribute)):
        return "the value of " + name_of(node)
    if isinstance(node, ast.Subscript):
        return "an item from " + (name_of(node.value) or "a collection")
    if isinstance(node, ast.Await):
        return describe_value(node.value)
    return "a computed value"


def condition(node):
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return "the check for " + (name_of(node.operand) or "a condition") + " does not pass"
    if isinstance(node, ast.Name):
        return "the value of " + node.id + " is set or true"
    if isinstance(node, ast.Attribute):
        return "the value of " + name_of(node) + " is set or true"
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        left = name_of(node.left) or "the calculated value"
        right = node.comparators[0]
        if isinstance(right, ast.Constant) and right.value is None:
            return left + (" is missing" if isinstance(node.ops[0], (ast.Is, ast.Eq)) else " is provided")
        verbs = {ast.Eq: "matches", ast.NotEq: "does not match", ast.In: "belongs to", ast.NotIn: "does not belong to", ast.Lt: "is below", ast.LtE: "does not exceed", ast.Gt: "is above", ast.GtE: "is at least", ast.Is: "is", ast.IsNot: "is not"}
        return left + " " + verbs.get(type(node.ops[0]), "is compared with") + " " + (name_of(right) or "the expected value")
    if isinstance(node, ast.BoolOp):
        joiner = " and " if isinstance(node.op, ast.And) else " or "
        return joiner.join(condition(value) for value in node.values[:3])
    if isinstance(node, ast.Call):
        callee = name_of(node.func)
        if callee == "isinstance" and len(node.args) >= 2:
            return (name_of(node.args[0]) or "the value") + " has type " + (name_of(node.args[1]) or "the expected type")
        return "the " + (callee or "helper") + "() check passes"
    return "a condition in the source is met"


def first_paragraph(text):
    if not text:
        return ""
    text = text.strip().split("\n\n", 1)[0]
    text = re.split(r"\b(?:Args|Returns|Calls|Called from|Parameters):", text, maxsplit=1)[0]
    text = " ".join(text.split())
    return text[:500].rstrip()


def actual_test(path):
    return path.startswith(("test/", "tests/")) or "/tests/" in path or path.endswith(("_test.go", ".test.ts", ".spec.ts", ".test.js", ".spec.js"))


def related_tests(graph, ids, limit=5, cache=None):
    all_nodes = {n["id"]: n for n in graph["nodes"]}
    outgoing = defaultdict(list)
    for a, b, kind in graph["edges"]:
        if kind in {"calls", "creates"}:
            outgoing[a].append(b)
    node_keys = {key: digest([n["file"], n["kind"], key in ids, outgoing[key]]) for key, n in all_nodes.items()}
    location = cache.directory / "test-links.json.gz" if cache else None
    prior = read_json(location) if cache and not cache.force else None
    algorithm = digest(["bounded-forward-tests-v1", limit, 3, 600])
    stored = prior.get("roots", {}) if isinstance(prior, dict) and prior.get("algorithm") == algorithm and isinstance(prior.get("roots"), dict) else {}
    current, result, dirty = {}, defaultdict(list), False
    for test in graph["nodes"]:
        if test["kind"] not in {"function", "method"} or not actual_test(test["file"]):
            continue
        old = stored.get(test["id"])
        if isinstance(old, dict) and isinstance(old.get("reached"), list) and isinstance(old.get("dependencies"), list) and old["dependencies"] and all(isinstance(row, list) and len(row) == 2 and node_keys.get(row[0]) == row[1] for row in old["dependencies"]):
            found = old
            if cache:
                cache.stats["test_roots_reused"] += 1
        else:
            queue, seen, reached = deque([(test["id"], 0)]), set(), []
            while queue and len(seen) < 600:
                key, depth = queue.popleft()
                if key in seen:
                    continue
                seen.add(key)
                if depth and key in ids:
                    reached.append([key, depth])
                if depth < 3:
                    queue.extend((target, depth + 1) for target in outgoing[key] if target in all_nodes and target not in seen)
            found = {"dependencies": [[key, node_keys[key]] for key in sorted(seen)], "reached": reached}
            dirty = True
            if cache:
                cache.stats["test_roots_analyzed"] += 1
        current[test["id"]] = found
        for key, depth in found["reached"]:
            if key in ids and len(result[key]) < limit:
                result[key].append([test["file"], test["start"], test["name"], depth])
    if cache and (dirty or set(current) != set(stored)):
        write_json(location, {"algorithm": algorithm, "roots": current})
    return result


def module_aliases(module):
    aliases = {}
    for n in owned(module):
        if isinstance(n, ast.Import):
            for item in n.names:
                aliases[item.asname or item.name.split(".")[0]] = item.name
        elif isinstance(n, ast.ImportFrom):
            for item in n.names:
                aliases[item.asname or item.name] = (n.module or "") + "." + item.name
    return aliases


def syntax_facts(node, module, aliases=None):
    facts = {"params": [], "returns": [], "effects": [], "conditions": [], "raises": [], "steps": [], "review": []}
    if isinstance(node, ast.ClassDef):
        fields = [n.target.id for n in node.body if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name)]
        constructor = next((n for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "__init__"), None)
        facts["params"] = [a.arg for a in [*constructor.args.posonlyargs, *constructor.args.args, *constructor.args.kwonlyargs] if a.arg not in {"self", "cls"}] if constructor else fields[:20]
        return facts
    args = node.args
    facts["params"] = [a.arg for a in [*args.posonlyargs, *args.args, *args.kwonlyargs] if a.arg not in {"self", "cls"}]
    if args.vararg:
        facts["params"].append("*" + args.vararg.arg)
    if args.kwarg:
        facts["params"].append("**" + args.kwarg.arg)
    aliases = dict(aliases if aliases is not None else module_aliases(module))
    for n in owned(node):
        if isinstance(n, ast.Import):
            for item in n.names:
                aliases[item.asname or item.name.split(".")[0]] = item.name
        elif isinstance(n, ast.ImportFrom):
            for item in n.names:
                aliases[item.asname or item.name] = (n.module or "") + "." + item.name
    effects, returns, raises, conditions = set(), [], set(), []
    for n in owned(node):
        if isinstance(n, ast.Return):
            value = describe_value(n.value)
            if value not in returns:
                returns.append(value)
        elif isinstance(n, (ast.Yield, ast.YieldFrom)):
            effects.add("Produces values one at a time")
        elif isinstance(n, ast.Raise) and n.exc:
            raises.add(name_of(n.exc.func if isinstance(n.exc, ast.Call) else n.exc) or "an exception")
        elif isinstance(n, ast.If) and len(conditions) < 4:
            conditions.append([n.lineno, condition(n.test)])
        elif isinstance(n, ast.Call):
            name = name_of(n.func)
            first, dot, rest = name.partition(".")
            qualified = aliases.get(first, first) + (dot + rest if dot else "")
            leaf = name.rsplit(".", 1)[-1]
            if qualified.startswith("subprocess.") and leaf in {"run", "Popen", "call", "check_call", "check_output"}:
                effects.add("Starts another program")
            if qualified.startswith(("requests.", "httpx.", "urllib.request.", "socket.")):
                effects.add("Calls a network API")
            if name == "print" or qualified.startswith(("sys.stdout.", "sys.stderr.")):
                effects.add("Writes terminal output")
            if name == "open" or leaf in {"read_text", "read_bytes", "write_text", "write_bytes"}:
                effects.add("Uses file I/O")
            if qualified in {"os.remove", "os.unlink", "os.rmdir", "shutil.rmtree"}:
                effects.add("Removes filesystem entries")
            if qualified in {"sys.exit", "os._exit"} or name == "exit":
                effects.add("Can end the process")
        elif isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = n.targets if isinstance(n, ast.Assign) else [n.target]
            if any(isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id in {"self", "cls"} for target in targets):
                effects.add("Changes object state")
        elif isinstance(n, ast.Global):
            effects.add("Uses shared module state")
        elif isinstance(n, ast.Await):
            effects.add("Waits for asynchronous work")
    facts.update(returns=returns[:6], effects=sorted(effects), conditions=conditions, raises=sorted(raises)[:8])
    calls = sorted((n for n in owned(node) if isinstance(n, ast.Call)), key=lambda n: n.lineno)
    facts["steps"] = [[n.lineno, name_of(n.func)] for n in calls if name_of(n.func) and name_of(n.func) not in {"isinstance", "len", "getattr", "setattr", "str", "dict", "list", "set", "tuple", "bool", "int", "super"}][:8]
    checks = []
    if "Uses file I/O" in effects:
        checks.append("What happens when the file is missing, unreadable, or cannot be written?")
    if "Calls a network API" in effects:
        checks.append("What happens on timeout, a failed response, or an unexpected response body?")
    if "Starts another program" in effects:
        checks.append("Are the child program's timeout, exit code, and output handled?")
    if "Removes filesystem entries" in effects:
        checks.append("Is the exact deletion target checked before anything is removed?")
    if "Can end the process" in effects:
        checks.append("Does each exit code tell the caller whether the operation succeeded, failed, or was incomplete?")
    if "Changes object state" in effects or "Uses shared module state" in effects:
        checks.append("Does repeated use leave the state consistent, including after an exception?")
    if "Waits for asynchronous work" in effects:
        checks.append("Can cancellation or two overlapping calls leave partially completed work?")
    if raises:
        checks.append("Do callers handle the documented exceptions and preserve useful error information?")
    if conditions:
        checks.append("Do tests exercise the alternatives at the conditions listed above?")
    checks.append("Would a meaningful regression test fail if the returned result were wrong?")
    facts["review"] = checks[:5]
    return facts


def fallback_summary(node, facts, doc):
    paragraph = first_paragraph(doc)
    if paragraph:
        return paragraph, "Source docstring"
    if node is None:
        return "The source and linked functions are shown below. A purpose description has not been written for this symbol.", "Purpose not yet described"
    if isinstance(node, ast.ClassDef):
        methods = sum(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) for n in node.body)
        return f"Groups {methods} methods and their shared state in one object. Its responsibilities can be followed through the methods and linked functions below.", "Generated from code structure"
    statements = [n for n in node.body if not isinstance(n, ast.Expr) or not isinstance(n.value, ast.Constant)]
    if len(statements) == 1 and isinstance(statements[0], ast.Return):
        value = statements[0].value
        if isinstance(value, ast.Call):
            return "Passes work to " + (name_of(value.func) or "another function") + "() and returns its result.", "Generated from source"
        if isinstance(value, (ast.Compare, ast.BoolOp)):
            return "Answers whether " + condition(value) + ".", "Generated from source"
        return "Returns " + describe_value(value) + ".", "Generated from source"
    effects = facts["effects"]
    if effects:
        text = "; ".join(effects[:3]) + "."
    elif facts["conditions"]:
        text = "Chooses between paths based on the conditions below."
    else:
        text = "Performs the operations listed below."
    if facts["returns"]:
        text += " Returns " + ", or ".join(facts["returns"][:2]) + "."
    return text, "Generated from source; purpose needs human context"


def empty_facts():
    return {"params": [], "returns": [], "effects": [], "conditions": [], "raises": [], "steps": [], "review": ["Do the implementation and tests agree about the expected behavior?"]}


def file_facts(path, items, cache, logic_key):
    record = cache.file(path)
    old = record.get("functions", {})
    marker = digest([record["hash"], logic_key, [(n["name"], n.get("code_hash"), n.get("doc")) for n in items]])
    if record.get("facts_key") == marker and all(n["name"] in old for n in items):
        cache.stats["function_facts_reused"] += len(items)
        return old
    tree, syntax, aliases, globals_ = None, {}, {}, {}
    if path.endswith((".py", ".pyi", ".pyw")):
        try:
            tree = cache.tree(path)
        except (SyntaxError, UnicodeError):
            pass
        if tree is not None:
            aliases = module_aliases(tree)
            for top in tree.body:
                if isinstance(top, (ast.Assign, ast.AnnAssign)):
                    targets = top.targets if isinstance(top, ast.Assign) else [top.target]
                    for target in targets:
                        for name in ast.walk(target):
                            if isinstance(name, ast.Name):
                                globals_[name.id] = top
                if isinstance(top, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    syntax[top.name] = top
                    if isinstance(top, ast.ClassDef):
                        syntax.update((top.name + "." + n.name, n) for n in top.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)))
    current = {}
    for item in items:
        node = syntax.get(item["name"])
        shape = ast.dump(node, include_attributes=False) if node is not None else item.get("code_hash")
        reads = {n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)} if node is not None else set()
        used_globals, pending = {}, list(reads & globals_.keys())
        while pending:
            name = pending.pop()
            if name in used_globals:
                continue
            definition = globals_[name]
            used_globals[name] = ast.dump(definition, include_attributes=False)
            pending.extend(n.id for n in ast.walk(definition) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id in globals_ and n.id not in used_globals)
        context_key = digest([{key: value for key, value in aliases.items() if key in reads}, used_globals])
        key = digest([logic_key, shape, context_key, item.get("doc"), item["kind"]])
        prior = old.get(item["name"])
        base_line = node.lineno if node is not None else item["start"]
        if isinstance(prior, dict) and prior.get("key") == key:
            value = copy.deepcopy(prior)
            delta = base_line - prior["base_line"]
            for field in ("steps", "conditions"):
                for row in value["facts"][field]:
                    row[0] += delta
            value["base_line"] = base_line
            cache.stats["function_facts_reused"] += 1
        else:
            facts = syntax_facts(node, tree, aliases) if node is not None else empty_facts()
            facts["syntaxParsed"] = node is not None
            summary, origin = fallback_summary(node, facts, item.get("doc", ""))
            value = {"key": key, "context": context_key, "base_line": base_line, "facts": facts, "summary": summary, "origin": origin}
            cache.stats["function_facts_analyzed"] += 1
        current[item["name"]] = value
    record["facts_key"], record["functions"] = marker, current
    cache.changed(path)
    return current


def semantic_context(nodes, edges, facts_by_file, cache):
    """Stable transitive context keys, including mutually recursive functions."""
    import networkx as nx
    by_id = {n["id"]: n for n in nodes}
    graph = nx.DiGraph()
    graph.add_nodes_from(by_id)
    dependencies = defaultdict(list)
    for a, b, kind in edges:
        if a in by_id and b in by_id:
            graph.add_edge(a, b)
            dependencies[a].append([b, kind])
    # A class description also depends on the behavior of its methods. This
    # relationship is for invalidation only; it is not drawn as a call.
    for key, node in by_id.items():
        owner = key.rsplit(".", 1)[0]
        if node["kind"] == "method" and owner in by_id and by_id[owner]["kind"] == "class":
            graph.add_edge(owner, key)
            dependencies[owner].append([key, "method context"])
    bases = {key: digest([n.get("code_hash"), facts_by_file[n["file"]][n["name"]].get("context"), sorted(dependencies[key])]) for key, n in by_id.items()}
    components = list(nx.strongly_connected_components(graph))
    owner = {key: i for i, component in enumerate(components) for key in component}
    dag = nx.DiGraph()
    dag.add_nodes_from(range(len(components)))
    dag.add_edges_from((owner[a], owner[b]) for a, b in graph.edges if owner[a] != owner[b])
    keys = {}
    for component in reversed(list(nx.topological_sort(dag))):
        keys[component] = digest([sorted((key, bases[key]) for key in components[component]), sorted(keys[child] for child in dag.successors(component))])
    result = {key: digest([bases[key], keys[owner[key]]]) for key in by_id}
    path = cache.directory / "semantic-context.json.gz"
    previous = read_json(path)
    previous = previous if isinstance(previous, dict) else {}
    cache.stats["contexts_updated"] += sum(previous.get(key) != value for key, value in result.items())
    if result != previous:
        write_json(path, result)
    return result


def enrich(notes_path, graph, compact, nodes, edges, cache, *, changes):
    logic_key = digest(Path(__file__).read_bytes())
    grouped = defaultdict(list)
    for item in nodes:
        grouped[item["file"]].append(item)
    facts_by_file = {}
    for path, items in grouped.items():
        facts_by_file[path] = file_facts(path, items, cache, logic_key)
        cache.flush_file(path)
    ids = {n["id"] for n in nodes}
    tests = related_tests(graph, ids, cache=cache)
    curated = json.loads(notes_path.read_text()) if notes_path.is_file() else {}
    note_file = cache.directory / "note-context.json"
    note_context = read_json(note_file)
    note_context = note_context if isinstance(note_context, dict) else {}
    contexts = semantic_context(nodes, edges, facts_by_file, cache)
    curated_count, rows = 0, []
    new_context = {}
    for item in nodes:
        key, path = item["id"], item["file"]
        base_facts = facts_by_file[path][item["name"]]
        facts = copy.deepcopy(base_facts["facts"])
        summary, origin = base_facts["summary"], base_facts["origin"]
        note = curated.get(key)
        source_key = item.get("code_hash") or cache.inputs[path]["hash"][:16]
        if note:
            note_key, context_key = digest(note), contexts[key]
            old = note_context.get(key)
            if not isinstance(old, dict) or old.get("note") != note_key:
                old = {"note": note_key, "body": note.get("codeHash", source_key), "context": context_key}
            new_context[key] = old
            if old["body"] == source_key and old["context"] == context_key:
                summary, origin = note["summary"], "Explained from source"
                facts.update(plainSteps=note.get("steps", []), plainInputs=note.get("inputs", ""), plainReturns=note.get("result", ""))
                facts["review"] = note.get("review", facts["review"])
                curated_count += 1
            else:
                facts["descriptionNeedsRefresh"] = True
                cache.stats["descriptions_invalidated"] += 1
        if item["kind"] == "command":
            summary, origin = "The " + item["name"] + " command. Its routing arrows show which handler receives the command-line arguments.", "Command routing table"
        elif item["kind"] == "workflow":
            summary, origin = "A GitHub Actions workflow. Its outgoing arrows show the repository scripts explicitly launched by its run steps.", "Workflow source"
        elif item["kind"] == "script":
            summary, origin = "A runnable script. Its startup arrows show the local functions it invokes.", "Script source"
        rows.append({"summary": summary, "origin": origin, "end": item.get("end", item["start"]), **facts, "tests": tests.get(key, []), "change": changes.get(f"{path}::{item['name']}")})
    if new_context != note_context:
        write_json(note_file, new_context)
    indices = {n["id"]: i for i, n in enumerate(nodes)}
    entry_of = {a: indices[b] for a, b, kind in edges if kind == "starts" and nodes[indices[b]]["name"] == "main"}
    for i, item in enumerate(nodes):
        if item["kind"] == "script" and item["id"] in entry_of:
            main = rows[entry_of[item["id"]]]
            for field in ("summary", "plainInputs", "plainReturns", "plainSteps", "review", "tests"):
                if field in main:
                    rows[i][field] = main[field]
            rows[i]["origin"] = "Script entry: " + main["origin"]
    compact["details"] = rows
    compact["source"] = [cache.source(path) for path in compact["files"]]
    compact["meta"]["explainedFromSource"] = curated_count
    compact["meta"]["sourceFacts"] = sum(bool(n.get("syntaxParsed")) for n in rows)
    compact["meta"]["testLinks"] = sum(len(n["tests"]) for n in rows)
    return rows
