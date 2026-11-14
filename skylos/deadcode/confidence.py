"""Evidence-calibrated confidence for dead-code candidates.

Every candidate used to say 100%. The penalty pass lowers confidence only for
a few Python patterns, and anything it doubts strongly enough becomes
"uncertain" and is withheld. Between "certain" and "withheld" there was no
middle, so a reader could not sort findings and trust the top.

This pass keeps each candidate reported (subject to the threshold) but caps
its confidence by the weakest piece of evidence behind it. The caps come from
hand-judged samples of real repositories (build note T0-C, 14 Oct 2026):

======================================  ====  ==============================
Factor                                  Cap   Why the evidence is weaker
======================================  ====  ==============================
(none: import, private/local symbol)    100   no reference anywhere
``public_name``                          90   a public module-level name can
                                              be imported from outside the
                                              scanned tree
``exported_symbol``                      85   declared ``export`` but no file
                                              in the repo imports it
``unimported_file``                      80   no file imports it; tools and
                                              frameworks load some files by
                                              convention
``public_method``                        80   methods are reached by dynamic
                                              dispatch, templates, reflection
``signature_parameter``                  50   a callback or override protocol
                                              can require the parameter
                                              (3/25 sampled parameters were
                                              truly unused; like Ruff's
                                              opt-in ARG rules, listed only
                                              with ``--confidence 50``).
                                              Not applied to a private,
                                              undecorated function defined
                                              once and only called directly:
                                              no caller can require the
                                              parameter (7 reported on 20
                                              labelled repos, 7 dead,
                                              14 Nov 2026)
``class_attribute``                      80   frameworks read class attributes
                                              through metaclasses
``imported_only_by_unused_files``        65   alive if any importer is
``default_export``                       60   a module's default export is how
                                              routers, mailers, configs and
                                              story loaders consume it
``dynamic_lookup``                       70   nothing names it, but an opaque
                                              lookup (a runtime attribute
                                              name, exec/eval, import *)
                                              could reach any callable; 18 of
                                              20 such findings were dead on
                                              5 repos, 11 of 12 on 3 unseen
                                              repos (20 Oct 2026)
``deprecated_api``                       40   it (or its module, on import)
                                              warns that it is deprecated,
                                              or its docstring says so:
                                              kept for callers on purpose
                                              (8/8 such functions on the same
                                              repos)
``experimental_language``                40   Rust dead code (trait methods,
                                              ``pub`` re-exports, macros) is
                                              not resolved; 0/15 true on
                                              ripgrep. Below the default
                                              threshold, so off by default
======================================  ====  ==============================

The default threshold is 60, so every factor except ``signature_parameter``,
``deprecated_api`` and ``experimental_language`` keeps the finding visible by
default; a scan
says how many parameters it did not list. Raising
``--confidence`` now removes the weakest symbol findings first, and
``skylos clean``'s non-interactive default (80) no longer deletes default
exports or class attributes. Unused-file and unnecessary-export findings
(SKY-E003/E004) carry a confidence for sorting but are not filtered by the
threshold: ``skylos done`` compares those sets between revisions.
"""

from __future__ import annotations

import ast
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from skylos.deadcode.python_proofs import deprecation_facts

CONFIDENCE_CAPS = {
    "public_name": 90,
    "exported_symbol": 85,
    "unimported_file": 80,
    "public_method": 80,
    "signature_parameter": 50,
    "class_attribute": 80,
    "imported_only_by_unused_files": 65,
    "default_export": 60,
    "dynamic_lookup": 70,
    "deprecated_api": 40,
    "experimental_language": 40,
}

FACTOR_LABELS = {
    "public_name": "public name",
    "exported_symbol": "exported but never imported",
    "unimported_file": "file loaded by no import",
    "public_method": "public method (dynamic dispatch possible)",
    "signature_parameter": "parameter may be required by a caller's signature",
    "class_attribute": "class attribute (frameworks may read it)",
    "imported_only_by_unused_files": "only imported by unused files",
    "default_export": "default export (frameworks load modules by it)",
    "dynamic_lookup": "only an opaque dynamic lookup could reach it",
    "deprecated_api": "deprecated, kept for existing callers",
    "experimental_language": "experimental language support",
}

# Languages whose dead-code analysis is experimental: findings are capped
# below the default threshold. Opt in with ``--confidence 40``.
EXPERIMENTAL_DEAD_CODE_SUFFIXES = {".rs": "rust"}

_PYTHON_SUFFIXES = (".py", ".pyi")


def confidence_cap(factors: Iterable[str]) -> int:
    return min((CONFIDENCE_CAPS.get(f, 100) for f in factors), default=100)


def confidence_reason(factors: Iterable[str]) -> str:
    """Human label for the factor that sets the cap (the weakest evidence)."""
    known = [f for f in factors if f in CONFIDENCE_CAPS]
    if not known:
        return ""
    weakest = min(known, key=lambda f: CONFIDENCE_CAPS[f])
    return FACTOR_LABELS.get(weakest, weakest.replace("_", " "))


def _is_candidate(definition: Any) -> bool:
    confidence = getattr(definition, "confidence", 0)
    return (
        getattr(definition, "references", 0) == 0
        and not getattr(definition, "is_exported", False)
        and isinstance(confidence, (int, float))
        and not isinstance(confidence, bool)
        and confidence > 0
    )


def _recorded_factors(definition: Any) -> list[str]:
    recorded = getattr(definition, "confidence_factors", None)
    if not isinstance(recorded, (list, tuple)):
        return []
    return [factor for factor in recorded if isinstance(factor, str)]


def _definition_factors(definition: Any, definitions: dict, demoted: set[int]):
    factors = _recorded_factors(definition)
    suffix = Path(str(definition.filename)).suffix.lower()
    kind = definition.type if isinstance(definition.type, str) else ""
    simple = definition.simple_name if isinstance(definition.simple_name, str) else ""
    name = definition.name if isinstance(definition.name, str) else ""

    if suffix in EXPERIMENTAL_DEAD_CODE_SUFFIXES:
        factors.append("experimental_language")
    if id(definition) in demoted:
        factors.append("exported_symbol")

    if (
        kind in {"function", "method", "class"} and _is_deprecated_python(definition)
    ) or (
        suffix in _PYTHON_SUFFIXES
        and kind in {"function", "class", "variable", "import"}
        and _module_is_deprecated(str(definition.filename))
    ):
        factors.append("deprecated_api")

    if kind == "parameter":
        if not getattr(definition, "direct_call_owner", False):
            factors.append("signature_parameter")
    elif kind == "method":
        if not simple.startswith(("_", "#")):
            factors.append("public_method")
    elif kind == "variable" and "." in name:
        owner_name = name.rsplit(".", 1)[0]
        owner = definitions.get(owner_name)
        if owner is None and suffix == ".cs":
            owner = definitions.get(f"csharp:type:{owner_name}")
        if owner is not None and getattr(owner, "type", None) == "class":
            factors.append("class_attribute")

    if (
        suffix in _PYTHON_SUFFIXES
        and kind in {"function", "class", "variable"}
        and not simple.startswith("_")
        and not _is_nested_python_name(name, definitions)
    ):
        factors.append("public_name")
    return list(dict.fromkeys(factors))


_UNPROVEN_OWNER_EVIDENCE = {
    "dynamic_pattern",
    "unresolved_receiver",
    "unresolved_callback",
    "grep_verify",
    "framework_root",
    "test_entrypoint",
    "package_entrypoint",
}
_FRAME_READERS = {"locals", "vars", "eval", "exec"}


def _has_fixed_signature(owner: Any, definitions: dict) -> bool:
    """A private, undecorated Python function nothing else can constrain."""
    node = getattr(owner, "node", None)
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    simple = str(owner.simple_name)
    if not simple.startswith("_") or simple.startswith("__"):
        return False
    if node.decorator_list or getattr(owner, "decorators", None):
        return False
    if getattr(owner, "references", 0) <= 0 or getattr(owner, "is_exported", False):
        return False
    if _UNPROVEN_OWNER_EVIDENCE.intersection(getattr(owner, "heuristic_refs", None) or ()):
        return False
    scope = definitions.get(owner.name.rpartition(".")[0])
    scope_kind = getattr(scope, "type", None)
    if scope_kind in {"function", "method"}:
        return False
    if scope_kind == "class":
        bases = [
            base
            for base in getattr(scope, "base_classes", None) or ()
            if base not in ("object", "builtins.object")
        ]
        if bases or getattr(scope, "decorators", None):
            return False
    if _returns_only_a_constant(node):
        return False
    return not any(
        isinstance(child, ast.Name) and child.id in _FRAME_READERS
        for child in ast.walk(node)
    )


def _returns_only_a_constant(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """A default hook: its signature serves callers and overriders, not its body."""
    body = list(node.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    if len(body) != 1 or not isinstance(body[0], ast.Return):
        return False
    return body[0].value is None or isinstance(body[0].value, ast.Constant)


def _is_variadic(owner: Any, parameter: Any) -> bool:
    arguments = owner.node.args
    return any(
        argument is not None and argument.arg == parameter.simple_name
        for argument in (arguments.vararg, arguments.kwarg)
    )


def mark_direct_call_parameters(definitions: dict[str, Any], report: Any) -> None:
    """Flag unread parameters whose function has no signature contract.

    A private, undecorated function that the project defines once and only
    calls directly (``name(...)`` for a function, ``self.name(...)`` for a
    method, with explicit arguments) has every caller in view: nothing passes
    it as a callback, overrides it, looks it up by name or calls it on an
    object that may be something else, so no caller can require a parameter
    its body never reads.
    """
    if report is None or not getattr(report, "complete", False):
        return
    looked_up_by_name = getattr(report, "name_exposed_keys", ())
    by_owner: dict[str, list[Any]] = {}
    for definition in definitions.values():
        if definition.type != "parameter" or not _is_candidate(definition):
            continue
        if not str(definition.filename).endswith(_PYTHON_SUFFIXES):
            continue
        owner = definitions.get(definition.name.rpartition(".")[0])
        if owner is None or owner.name in looked_up_by_name:
            continue
        if not _has_fixed_signature(owner, definitions):
            continue
        if _is_variadic(owner, definition):
            continue
        by_owner.setdefault(owner.simple_name, []).append(definition)
    if not by_owner:
        return
    defined = Counter(
        definition.simple_name
        for definition in definitions.values()
        if definition.type in {"function", "method"}
    )
    as_function, on_self = report.direct_call_sites(set(by_owner))
    for name, parameters in by_owner.items():
        if defined[name] != 1:
            continue
        owner = definitions[parameters[0].name.rpartition(".")[0]]
        if owner.type == "method":
            callers_in_view = name in on_self
        else:
            callers_in_view = name in as_function
        if not callers_in_view:
            continue
        for parameter in parameters:
            parameter.direct_call_owner = True


def _is_deprecated_python(definition: Any) -> bool:
    node = getattr(definition, "node", None)
    if node is None:
        return False
    _module, definitions = deprecation_facts(str(definition.filename))
    return (getattr(node, "lineno", None), getattr(node, "name", None)) in definitions


def _module_is_deprecated(filename: str) -> bool:
    deprecated, _definitions = deprecation_facts(filename)
    return deprecated


def _is_nested_python_name(name: str, definitions: dict) -> bool:
    if "." not in name:
        return False
    owner = definitions.get(name.rsplit(".", 1)[0])
    return owner is not None and getattr(owner, "type", None) in {
        "function",
        "method",
        "class",
    }


def calibrate_dead_code_confidence(
    definitions: dict[str, Any],
    demoted_exports: Iterable[Any] = (),
) -> None:
    """Cap each candidate's confidence by its weakest evidence (idempotent)."""
    demoted = {id(definition) for definition in demoted_exports}
    for definition in definitions.values():
        if not _is_candidate(definition):
            continue
        factors = _definition_factors(definition, definitions, demoted)
        definition.confidence_factors = factors
        cap = confidence_cap(factors)
        definition.confidence = min(definition.confidence, cap)


def experimental_hidden_counts(
    definitions: dict[str, Any], threshold: int
) -> dict[str, int]:
    """Candidates per experimental language that only the cap keeps hidden."""
    cap = CONFIDENCE_CAPS["experimental_language"]
    counts: dict[str, int] = {}
    for definition in definitions.values():
        if not _is_candidate(definition):
            continue
        if "experimental_language" not in _recorded_factors(definition):
            continue
        if definition.confidence != cap or cap >= threshold:
            continue
        language = EXPERIMENTAL_DEAD_CODE_SUFFIXES.get(
            Path(str(definition.filename)).suffix.lower()
        )
        if language:
            counts[language] = counts.get(language, 0) + 1
    return counts


# Factors below the default threshold, and the flag that lists them.
BELOW_THRESHOLD_SHOW_WITH = {
    "signature_parameter": f"--confidence {CONFIDENCE_CAPS['signature_parameter']}",
    "deprecated_api": f"--confidence {CONFIDENCE_CAPS['deprecated_api']}",
    "experimental_language": (
        f"--confidence {CONFIDENCE_CAPS['experimental_language']}"
    ),
}


def file_finding_confidence(*, has_importers: bool) -> tuple[int, list[str]]:
    factor = "imported_only_by_unused_files" if has_importers else "unimported_file"
    return CONFIDENCE_CAPS[factor], [factor]


def export_finding_confidence() -> tuple[int, list[str]]:
    return CONFIDENCE_CAPS["exported_symbol"], ["exported_symbol"]


def confidence_detail(item: dict) -> str | None:
    """``Confidence: 60% (default export (frameworks load modules by it))``."""
    confidence = item.get("confidence") if isinstance(item, dict) else None
    if confidence is None:
        return None
    reason = confidence_reason(item.get("confidence_factors") or ())
    if reason and confidence < 100:
        return f"Confidence: {confidence}% ({reason})"
    return f"Confidence: {confidence}%"
