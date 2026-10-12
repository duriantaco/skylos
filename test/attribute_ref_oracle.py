"""Frozen attribute-scoring oracle and fixture helpers, independent of the index."""

from pathlib import Path
import struct


def _original(definition, contexts, weights):
    # Freeze the prior loop as an oracle, independent of the optimized helpers.
    matching = [row for row in contexts if row[0] == definition.simple_name]
    if not matching:
        return
    module = definition.name.rsplit(".")[0] if "." in definition.name else ""
    package = module.split(".")[0] if module else ""
    for _attribute, context_module, _class, _line in matching:
        context_package = context_module.split(".")[0] if context_module else ""
        if context_module == module:
            definition.heuristic_refs["same_file_attr"] = definition.heuristic_refs.get(
                "same_file_attr", 0.0
            ) + weights.get("same_file_attr", 1.0)
        elif context_package and package and context_package == package:
            definition.heuristic_refs["same_pkg_attr"] = definition.heuristic_refs.get(
                "same_pkg_attr", 0.0
            ) + weights.get("same_pkg_attr", 0.3)
        else:
            definition.heuristic_refs["global_attr"] = definition.heuristic_refs.get(
                "global_attr", 0.0
            ) + weights.get("global_attr", 0.1)


def _number(value):
    if type(value) is float:
        return float, struct.pack("!d", value)
    return type(value), value


def _scores(definition):
    return [(name, _number(value)) for name, value in definition.heuristic_refs.items()]


def _definition(definition_type, name, initial=None):
    definition = definition_type(name, "function", Path("module.py"), 3)
    definition.heuristic_refs = dict(initial or {})
    definition.calls = {"source.helper"}
    definition.called_by = {"source.entry"}
    definition.decorators = ["source.decorator"]
    definition.why_unused = ["prior reason"]
    return definition


def _fresh_bytecode(monkeypatch, *functions):
    """Restart CPython's adaptive specialization of ``functions`` for one test.

    Each ``+`` specializes from its own execution history, which every earlier
    caller in the process shares. CPython 3.14 on arm64 returns different
    payloads for NaN + NaN from the generic float path and from
    BINARY_OP_ADD_FLOAT, so two scoring loops give the same NaN bits only when
    they run their additions from the same interpreter state.
    """
    for function in functions:
        monkeypatch.setattr(function, "__code__", function.__code__.replace())
