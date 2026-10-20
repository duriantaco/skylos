"""A terminal cursor over analyzer-recorded static proof steps."""

from skylos.cicd.evidence import sanitize_untrusted_text
from skylos.security.trace_report import source_context


def _text(value):
    if not isinstance(value, (str, int, float)):
        return ""
    return sanitize_untrusted_text(
        str(value or ""), max_length=500, neutralize_mentions=False
    )


def show_trace(console, finding, trace):
    console.print(
        f"{_text(finding.get('rule_id'))} {_text(finding.get('file'))}:{_text(finding.get('line', 0))}",
        markup=False,
    )
    console.print(_text(finding.get("message")), markup=False)
    console.print(
        f"Recorded static trace: {_text(trace.get('status', 'unknown'))}. Runtime behavior was not executed or verified.",
        markup=False,
    )
    receiver = trace.get("receiver")
    if isinstance(receiver, dict):
        identity = receiver.get("qualified_name") or receiver.get("reason") or ""
        console.print(
            f"Receiver: {_text(receiver.get('status', 'unknown'))} {_text(identity)}",
            markup=False,
        )
    steps = _steps(trace)
    for index, step in enumerate(steps):
        show_step(console, step, index, len(steps))
    limitations = trace.get("limitations")
    if isinstance(limitations, list):
        for item in limitations[:12]:
            console.print("Unresolved: " + _text(item), markup=False)


def _steps(trace):
    result = []
    for step in trace.get("steps", []):
        if isinstance(step, dict):
            result.append(step)
    return result


def show_step(console, step, index, count):
    location = ""
    if step.get("file") and step.get("line"):
        location = f" {_text(step['file'])}:{_text(step['line'])}"
    console.print(
        f"[{index + 1}/{count}] {_text(step.get('kind', 'step'))}{location}: {_text(step.get('message') or step.get('name'))}",
        markup=False,
    )


def _linked_steps(trace, steps, cursor, direction):
    edge_key = "from"
    destination_key = "to"
    if direction == "parents":
        edge_key, destination_key = destination_key, edge_key
    indices = {}
    for index, step in enumerate(steps):
        if isinstance(step.get("id"), str):
            indices[step["id"]] = index
    matches = set()
    edges = trace.get("edges")
    if not isinstance(edges, list):
        return None
    for edge in edges[:4096]:
        if not isinstance(edge, dict):
            continue
        if edge.get(edge_key) == steps[cursor].get("id"):
            destination_id = edge.get(destination_key)
            if not isinstance(destination_id, str):
                continue
            destination = indices.get(destination_id)
            if destination is not None:
                matches.add(destination)
    return sorted(matches)


def follow_trace(console, trace, *, root=None, read_command=input):
    steps = _steps(trace)
    if not steps:
        console.print("No recorded steps to follow.", markup=False)
        return
    console.print(
        "Static navigation: next/n, back/b, step NUMBER, parents, callers, source, help, quit/q. These commands inspect the saved trace only.",
        markup=False,
    )
    cursor = 0
    history = []
    show_step(console, steps[cursor], cursor, len(steps))
    while True:
        try:
            command = read_command("trace> ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            return
        if command in {"quit", "q", "exit"}:
            return
        if command in {"next", "n", ""}:
            linked = _linked_steps(trace, steps, cursor, "next")
            if linked is None:
                destination = min(cursor + 1, len(steps) - 1)
            elif len(linked) == 1:
                destination = linked[0]
            elif not linked:
                console.print("No later recorded edge from this step.", markup=False)
                continue
            else:
                console.print(
                    "Multiple recorded branches; choose one with step NUMBER:",
                    markup=False,
                )
                for index in linked:
                    show_step(console, steps[index], index, len(steps))
                continue
            if destination != cursor:
                history.append(cursor)
            cursor = destination
        elif command in {"back", "b", "prev", "p"}:
            if history:
                cursor = history.pop()
            else:
                cursor = max(cursor - 1, 0)
        elif command.startswith("step "):
            try:
                selected = int(command[5:]) - 1
            except ValueError:
                selected = -1
            if selected < 0 or selected >= len(steps):
                console.print("Choose a recorded step number.", markup=False)
                continue
            if selected != cursor:
                history.append(cursor)
            cursor = selected
        elif command == "parents":
            linked = _linked_steps(trace, steps, cursor, "parents")
            if not linked:
                console.print(
                    "No recorded predecessor edges for this step.", markup=False
                )
            else:
                for index in linked:
                    show_step(console, steps[index], index, len(steps))
            continue
        elif command == "callers":
            for index, step in enumerate(steps):
                if step.get("kind") in {"call", "caller", "argument", "parameter"}:
                    show_step(console, step, index, len(steps))
            continue
        elif command == "source":
            try:
                for line in source_context(trace, steps[cursor], root):
                    console.print(line, markup=False)
            except ValueError as error:
                console.print(str(error), markup=False)
            continue
        elif command in {"help", "h", "?"}:
            console.print(
                "next follows recorded edges across calls; back retraces your navigation; step N selects a branch/step; parents lists predecessor steps; callers lists call boundaries; source shows hash-verified local code under --root; quit exits. No target code runs.",
                markup=False,
            )
            continue
        else:
            console.print("Unknown navigation command. Type help.", markup=False)
            continue
        show_step(console, steps[cursor], cursor, len(steps))
