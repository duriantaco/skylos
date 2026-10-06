from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.visitors.languages.dart.core import DartCore


def _dart_project(root: Path, source: str) -> Path:
    root = root.resolve(strict=True)
    path = root / "main.dart"
    path.resolve().relative_to(root)
    assert path.parent.resolve(strict=True) == root
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(source)
    return path


def _unused_functions(root: Path, *, grep_verify: bool) -> set[str]:
    result = json.loads(analyze(str(root), conf=60, grep_verify=grep_verify))
    assert result.get("analysis_errors", []) == []
    return {row["full_name"] for row in result.get("unused_functions", [])}


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize(
    "body",
    [
        "consume(_handle);",
        "consume(onTap: _handle);",
        "final callback = _handle; callback();",
        "final callback = ready ? _handle : null; consume(callback);",
        "consume([_handle]);",
        "return _handle;",
        "var callback; callback = _handle; consume(callback);",
    ],
)
def test_dart_function_tear_off_preserves_live_callback_and_dead_control(
    tmp_path, body, grep_verify
):
    consume = (
        "void consume({dynamic onTap}) {}"
        if "onTap:" in body
        else "void consume(dynamic value) {}"
    )
    _dart_project(
        tmp_path,
        f"dynamic main() {{ {body} }}\n"
        "void _handle() {}\n"
        f"void _unused() {{}}\nbool ready = true;\n{consume}\n",
    )
    unused = _unused_functions(tmp_path, grep_verify=grep_verify)
    assert "_handle" not in unused
    assert "_unused" in unused


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize("active_first", [False, True])
@pytest.mark.parametrize(
    "body",
    [
        "consume(_handle);",
        "consume(this._handle);",
        "consume(onTap: _handle);",
        "final callback = _handle; consume(callback);",
        "final callback = this._handle; consume(callback);",
        "consume(ready ? null : this._handle);",
    ],
)
def test_dart_method_tear_off_uses_containing_owner(
    tmp_path, body, active_first, grep_verify
):
    active = f"class Active {{ void run() {{ {body} }} void _handle() {{}} }}\n"
    dormant = "class Dormant { void _handle() {} }\n"
    classes = active + dormant if active_first else dormant + active
    consume = (
        "void consume({dynamic onTap}) {}"
        if "onTap:" in body
        else "void consume(dynamic value) {}"
    )
    _dart_project(
        tmp_path,
        classes + "void main() { Dormant(); Active().run(); }\n"
        f"bool ready = true;\n{consume}\n",
    )
    unused = _unused_functions(tmp_path, grep_verify=grep_verify)
    assert "Active._handle" not in unused
    assert "Dormant._handle" in unused


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize("receiver", ["Active", "final active = Active(); active"])
def test_dart_qualified_method_tear_off_keeps_dead_sibling(tmp_path, receiver, grep_verify):
    prefix, separator, target = receiver.rpartition("; ")
    statement = f"{prefix}; " if separator else ""
    target = target if separator else receiver
    modifier = "" if separator else "static "
    _dart_project(
        tmp_path,
        f"class Dormant {{ {modifier}void _handle() {{}} }}\n"
        f"class Active {{ {modifier}void _handle() {{}} }}\n"
        f"void main() {{ Dormant(); {statement}consume({target}._handle); }}\n"
        "void consume(dynamic value) {}\n",
    )
    unused = _unused_functions(tmp_path, grep_verify=grep_verify)
    assert "Active._handle" not in unused
    assert "Dormant._handle" in unused


@pytest.mark.parametrize(
    "source",
    [
        "void main() { final _handle = () {}; consume(_handle); }",
        "void main(void Function() _handle) { consume(_handle); }",
        "void main() { consume(onTap: () {}); }",
        "void main() { print('_handle'); /* consume(_handle); */ }",
    ],
)
def test_dart_tear_off_does_not_credit_shadowed_names_or_labels(source):
    core = DartCore("/project/main.dart", (source + "\nvoid _handle() {}").encode())
    core.scan()
    assert "_handle" not in {name for name, _ in core.refs}
    assert "onTap" not in {name for name, _ in core.refs}


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize("active_first", [False, True])
def test_dart_constructor_calls_credit_exact_constructor_and_keep_dead_named_control(
    tmp_path, active_first, grep_verify
):
    active = "class _Active { _Active(); _Active._unused(); }\n"
    dormant = "class _Dormant { _Dormant(); _Dormant.live(); }\n"
    classes = active + dormant if active_first else dormant + active
    path = _dart_project(
        tmp_path,
        classes + "void main() { _Dormant.live(); _Active(); }\n",
    )
    core = DartCore(str(path), path.read_bytes())
    core.scan()
    definitions = {definition.name: definition for definition in core.defs}
    assert {"_Active._Active", "_Dormant.live"} <= definitions["main"].calls
    assert "_Active._unused" not in definitions["main"].calls
    assert "_Dormant._Dormant" not in definitions["main"].calls
    unused = _unused_functions(tmp_path, grep_verify=grep_verify)
    assert "_Active._Active" not in unused
    assert "_Active._unused" in unused
    assert "_Dormant._Dormant" in unused


def test_dart_class_value_does_not_invent_default_constructor_call():
    core = DartCore(
        "/project/main.dart",
        b"class _Used { _Used(); }\nvoid main() { consume(_Used); }",
    )
    core.scan()
    assert "_Used._Used" not in {name for name, _ in core.refs}
