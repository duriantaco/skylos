"""Clone kinds and candidate hashes must respect their literal/name contract."""

import ast
import json
from pathlib import Path

from skylos.rules.quality.clones import (
    CloneConfig,
    CloneType,
    _normalize_text,
    classify_clone,
    detect_pairs,
    extract_fragments,
)


def source(values=("alpha", "beta", "gamma", "delta")):
    return (
        "def make_record():\n"
        + "".join(f"    field_{i} = {value!r}\n" for i, value in enumerate(values))
        + "    return (field_0, field_1, field_2, field_3)\n"
    )


def fragments(code, filename="app/records.py", **options):
    cfg = CloneConfig(min_lines=4, min_statements=4, **options)
    return extract_fragments(Path(filename), code, cfg), cfg


def test_type1_preserves_strings_and_numbers_while_ignoring_layout():
    assert _normalize_text("x = 'allow'\ny = 1") != _normalize_text("x = 'deny'\ny = 2")
    assert _normalize_text("x='allow' # comment\ny=1\n") == _normalize_text(
        "x = 'allow'\ny = 1"
    )


def test_distinct_literal_records_are_not_identical_clone_candidates():
    first, cfg = fragments(source(), "app/first.py")
    second, _ = fragments(
        source(("other", "values", "different", "record")), "app/second.py"
    )
    assert first[0].text_norm != second[0].text_norm
    assert detect_pairs(first + second, cfg) == []


def test_real_copied_implementation_remains_a_type1_clone():
    first, cfg = fragments(source(), "app/first.py")
    second, _ = fragments(source(), "app/second.py")
    pairs = detect_pairs(first + second, cfg)
    assert len(pairs) == 1
    assert pairs[0].clone_type is CloneType.TYPE1
    assert pairs[0].similarity == 1.0


def test_near_identical_literal_change_is_retained_without_type1_claim():
    first, cfg = fragments(source(), "app/first.py", ignore_literals=True)
    second, _ = fragments(
        source(("alphas", "beta", "gamma", "delta")),
        "app/second.py",
        ignore_literals=True,
    )
    kind, score = classify_clone(first[0], second[0], cfg)
    assert kind in {CloneType.TYPE2, CloneType.TYPE3}
    assert score >= cfg.similarity_threshold
    assert len(detect_pairs(first + second, cfg)) == 1


def test_near_identical_annotation_change_is_not_type1():
    first, cfg = fragments(source().replace("make_record()", "make_record() -> bytes"))
    second, _ = fragments(source().replace("make_record()", "make_record() -> str"))
    assert classify_clone(first[0], second[0], cfg)[0] is not CloneType.TYPE1


def test_type1_only_does_not_accept_material_lookalike():
    first, cfg = fragments(source(), enabled_clone_types=(CloneType.TYPE1,))
    second, _ = fragments(source(("alphas", "beta", "gamma", "delta")))
    assert classify_clone(first[0], second[0], cfg) is None
    assert detect_pairs(first + second, cfg) == []


def test_explicit_literal_normalization_still_finds_requested_type2_clones():
    first, cfg = fragments(source(), "app/first.py", ignore_literals=True)
    second, _ = fragments(
        source(("other", "values", "different", "record")),
        "app/second.py",
        ignore_literals=True,
    )
    pairs = detect_pairs(first + second, cfg)
    assert len(pairs) == 1
    assert pairs[0].clone_type is CloneType.TYPE2
    assert first[0].ast_norm_type3 != second[0].ast_norm_type3


def test_identifier_normalization_keeps_original_method_ast_independent():
    code = "class Catalog:\n" + "\n".join(
        "    " + line for line in source().splitlines()
    )
    rows, _ = fragments(code, ignore_identifiers=True)
    method = next(row for row in rows if row.kind == "method")
    assert "field_0" in method.ast_norm_type3
    assert "field_0" not in method.ast_norm_type2


def test_configured_numeric_literal_normalization_includes_zero_and_one():
    first, cfg = fragments(source((0, 1, 0, 1)), "app/first.py", ignore_literals=True)
    second, _ = fragments(source((2, 3, 4, 5)), "app/second.py", ignore_literals=True)
    assert first[0].ast_norm_type2 == second[0].ast_norm_type2
    assert classify_clone(first[0], second[0], cfg)[0] is CloneType.TYPE2


def computation(
    name="combine", parameters="left, right", expression="left + right", local="result"
):
    return (
        f"def {name}({parameters}):\n"
        f"    {local} = {expression}\n"
        f"    doubled = {local} * 2\n"
        "    adjusted = doubled / 3\n"
        "    return adjusted\n"
    )


def _annotate_unrelated_source(monkeypatch):
    from skylos.rules.danger.calls import DangerousCallsRule

    previous = ast.parse("holder = root" + ".field" * 400 + "\n")
    # These parser nodes are shared by future ast.parse calls. Restore their
    # previous metadata after this regression, rather than poisoning the suite.
    contexts = {
        node for node in ast.walk(previous) if isinstance(node, ast.expr_context)
    }
    for context in contexts:
        monkeypatch.setattr(context, "parent", None, raising=False)
    DangerousCallsRule()._annotate_parents(previous)
    return contexts


def test_clone_normalization_copies_syntax_without_foreign_parent_metadata(monkeypatch):
    code = computation()
    expected, cfg = fragments(code, ignore_identifiers=True, ignore_literals=True)
    contexts = _annotate_unrelated_source(monkeypatch)
    parents = {context: context.parent for context in contexts}

    actual = extract_fragments(Path("app/records.py"), code, cfg)

    assert actual == expected
    assert {context: context.parent for context in contexts} == parents


def test_analyze_keeps_production_clones_after_unrelated_security_parent_metadata(
    tmp_path, monkeypatch
):
    from skylos.analyzer import analyze

    monkeypatch.setenv("SKYLOS_JOBS", "1")
    (tmp_path / "pyproject.toml").write_text("[tool.skylos]\n", encoding="utf-8")
    implementation = (
        "def NAME(value):\n"
        "    total = value + 1\n"
        "    total = total * 2\n"
        "    total = total - 3\n"
        "    total = total / 4\n"
        "    total = total + 5\n"
        "    total = total * 6\n"
        "    total = total - 7\n"
        "    total = total / 8\n"
        "    return total\n"
    )
    for relative, name in (
        ("production/alpha_test.py", "first"),
        ("production/beta_test.py", "second"),
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(implementation.replace("NAME", name), encoding="utf-8")
    for name in ("first", "second"):
        path = tmp_path / "tests" / f"test_{name}.py"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"def test_{name}(text):\n"
            "    parts = text.split(',')\n"
            "    parts = [part.strip() for part in parts]\n"
            "    parts = [part for part in parts if part]\n"
            "    joined = '-'.join(parts)\n"
            "    joined = joined.upper()\n"
            "    joined = joined.replace('A', 'B')\n"
            "    size = len(joined)\n"
            "    flag = size > 10\n"
            "    return joined, flag\n",
            encoding="utf-8",
        )
    _annotate_unrelated_source(monkeypatch)

    result = json.loads(
        analyze(str(tmp_path), conf=0, enable_quality=True, grep_verify=False)
    )

    clones = [row for row in result["quality"] if row["rule_id"] == "SKY-C401"]
    assert [row["name"] for row in clones] == ["first"]
    assert result.get("analysis_errors", []) == []


def test_default_identifier_normalization_preserves_distinct_bindings():
    first, cfg = fragments(
        computation(), "app/first.py", ignore_identifiers=True, ignore_literals=True
    )
    second, _ = fragments(
        computation(expression="left + left"),
        "app/second.py",
        ignore_identifiers=True,
        ignore_literals=True,
    )
    assert first[0].ast_norm_type2 != second[0].ast_norm_type2
    assert detect_pairs(first + second, cfg) == []


def test_alpha_renamed_parameters_and_locals_remain_real_type2_clones():
    first, cfg = fragments(
        computation(), "app/first.py", ignore_identifiers=True, ignore_literals=True
    )
    second, _ = fragments(
        computation(
            name="calculate", parameters="a, b", expression="a + b", local="sum_value"
        ),
        "app/second.py",
        ignore_identifiers=True,
        ignore_literals=True,
    )
    assert first[0].ast_norm_type2 == second[0].ast_norm_type2
    assert len(detect_pairs(first + second, cfg)) == 1


def test_parameter_position_is_part_of_the_binding_contract():
    first, cfg = fragments(
        computation(expression="left - right"),
        "app/first.py",
        ignore_identifiers=True,
        ignore_literals=True,
    )
    second, _ = fragments(
        computation(name="subtract", parameters="a, b", expression="b - a"),
        "app/second.py",
        ignore_identifiers=True,
        ignore_literals=True,
    )
    assert first[0].ast_norm_type2 != second[0].ast_norm_type2
    assert detect_pairs(first + second, cfg) == []


def test_same_body_with_reordered_formals_cannot_bypass_binding_identity():
    first, cfg = fragments(
        computation(expression="left - right"),
        "app/first.py",
        ignore_identifiers=True,
        ignore_literals=True,
    )
    second, _ = fragments(
        computation(parameters="right, left", expression="left - right"),
        "app/second.py",
        ignore_identifiers=True,
        ignore_literals=True,
    )
    assert first[0].ast_norm_type2 != second[0].ast_norm_type2
    assert first[0].ast_norm_type3 != second[0].ast_norm_type3
    assert detect_pairs(first + second, cfg) == []


def test_external_api_operations_do_not_become_alpha_renamed_locals():
    code = "def parse(data):\n    raw = data\n    loaded = json.loads(raw)\n    result = validate(loaded)\n    return result\n"
    first, cfg = fragments(
        code, "app/first.py", ignore_identifiers=True, ignore_literals=True
    )
    second, _ = fragments(
        code.replace("json.loads", "yaml.loads"),
        "app/second.py",
        ignore_identifiers=True,
        ignore_literals=True,
    )
    assert "json" in first[0].ast_norm_type2
    assert "loads" in first[0].ast_norm_type2
    assert detect_pairs(first + second, cfg) == []


def test_different_member_operations_remain_different():
    code = "def operate(client):\n    ready = True\n    first = client.load(ready)\n    result = validate(first)\n    return result\n"
    first, cfg = fragments(
        code, "app/first.py", ignore_identifiers=True, ignore_literals=True
    )
    second, _ = fragments(
        code.replace("client.load", "client.delete"),
        "app/second.py",
        ignore_identifiers=True,
        ignore_literals=True,
    )
    assert detect_pairs(first + second, cfg) == []


def test_literal_normalization_preserves_runtime_type():
    first, cfg = fragments(source((1, 2, 3, 4)), "app/first.py", ignore_literals=True)
    second, _ = fragments(
        source(("a", "b", "c", "d")), "app/second.py", ignore_literals=True
    )
    assert first[0].ast_norm_type2 != second[0].ast_norm_type2
    assert detect_pairs(first + second, cfg) == []


def test_nested_closure_and_inner_parameter_have_distinct_identities():
    code = "def outer(value):\n    def inner(item):\n        return value + item\n    first = inner(value)\n    second = inner(first)\n    return second\n"
    first, cfg = fragments(
        code, "app/first.py", ignore_identifiers=True, ignore_literals=True
    )
    second, _ = fragments(
        code.replace("return value + item", "return item + item"),
        "app/second.py",
        ignore_identifiers=True,
        ignore_literals=True,
    )
    outer_first = next(row for row in first if row.name == "outer")
    outer_second = next(row for row in second if row.name == "outer")
    assert outer_first.ast_norm_type2 != outer_second.ast_norm_type2


def test_comprehension_local_alpha_renaming_preserves_external_iterable():
    code = "def collect(values):\n    first = [item + 1 for item in values]\n    second = tuple(first)\n    count = len(second)\n    return count\n"
    first, cfg = fragments(
        code, "app/first.py", ignore_identifiers=True, ignore_literals=True
    )
    second, _ = fragments(
        code.replace("item", "entry"),
        "app/second.py",
        ignore_identifiers=True,
        ignore_literals=True,
    )
    assert first[0].ast_norm_type2 == second[0].ast_norm_type2
    assert len(detect_pairs(first + second, cfg)) == 1


def test_comprehension_walrus_binds_enclosing_function():
    code = "def collect(items):\n    values = [(last := item) for item in items]\n    first = tuple(values)\n    count = len(first)\n    return last, count\n"
    renamed = (
        code.replace("items", "entries")
        .replace("item", "entry")
        .replace("last", "tail")
    )
    first, cfg = fragments(
        code, "app/first.py", ignore_identifiers=True, ignore_literals=True
    )
    second, _ = fragments(
        renamed, "app/second.py", ignore_identifiers=True, ignore_literals=True
    )
    assert first[0].ast_norm_type2 == second[0].ast_norm_type2
    assert len(detect_pairs(first + second, cfg)) == 1


def test_nonlocal_reads_and_writes_keep_their_enclosing_binding():
    code = "def outer(value):\n    state = value\n    def update():\n        nonlocal state\n        state = state + 1\n        return state\n    first = update()\n    return update(), first\n"
    renamed = code.replace("state", "counter").replace("value", "initial")
    first, _ = fragments(
        code, "app/first.py", ignore_identifiers=True, ignore_literals=True
    )
    second, _ = fragments(
        renamed, "app/second.py", ignore_identifiers=True, ignore_literals=True
    )
    assert first[0].ast_norm_type2 == second[0].ast_norm_type2


def test_global_declaration_cannot_capture_an_outer_parameter():
    code = "def outer(value):\n    def read():\n        global value\n        return value\n    first = read()\n    second = read()\n    return first, second\n"
    rows, _ = fragments(code, ignore_identifiers=True, ignore_literals=True)
    outer = next(row for row in rows if row.name == "outer")
    assert "Global(['value'])" in outer.ast_norm_type2
    assert "Name('value', Load())" in outer.ast_norm_type2


def test_lambda_walrus_binding_is_independent_of_the_outer_local():
    code = "def outer(value):\n    outer = value\n    callback = lambda item: (outer := item)\n    first = callback(value)\n    return outer, first\n"
    renamed = code.replace("(outer := item)", "(inner := item)")
    first, _ = fragments(
        code, "app/first.py", ignore_identifiers=True, ignore_literals=True
    )
    second, _ = fragments(
        renamed, "app/second.py", ignore_identifiers=True, ignore_literals=True
    )
    assert first[0].ast_norm_type2 == second[0].ast_norm_type2


def test_nested_class_does_not_capture_outer_class_local_names():
    code = "def factory(value):\n    class Outer:\n        value = 1\n        class Inner:\n            captured = value\n    first = Outer.Inner\n    second = first.captured\n    return second\n"
    changed = code.replace("def factory(value)", "def factory(other)")
    first, _ = fragments(
        code, "app/first.py", ignore_identifiers=True, ignore_literals=True
    )
    second, _ = fragments(
        changed, "app/second.py", ignore_identifiers=True, ignore_literals=True
    )
    a = next(row for row in first if row.name == "factory")
    b = next(row for row in second if row.name == "factory")
    assert a.ast_norm_type2 != b.ast_norm_type2


def test_exception_capture_alpha_renaming_remains_a_clone():
    code = "def process(value):\n    try:\n        first = convert(value)\n        return first\n    except ValueError as error:\n        log(error)\n        return None\n"
    first, _ = fragments(
        code, "app/first.py", ignore_identifiers=True, ignore_literals=True
    )
    second, _ = fragments(
        code.replace("error", "exc"),
        "app/second.py",
        ignore_identifiers=True,
        ignore_literals=True,
    )
    assert first[0].ast_norm_type2 == second[0].ast_norm_type2


def test_pattern_capture_alpha_renaming_remains_a_clone():
    code = "def process(value):\n    match value:\n        case {'item': found, **rest}:\n            first = convert(found)\n            return first, rest\n        case _:\n            return None\n"
    first, _ = fragments(
        code, "app/first.py", ignore_identifiers=True, ignore_literals=True
    )
    second, _ = fragments(
        code.replace("found", "item_value").replace("rest", "remaining"),
        "app/second.py",
        ignore_identifiers=True,
        ignore_literals=True,
    )
    assert first[0].ast_norm_type2 == second[0].ast_norm_type2


def test_nested_function_default_walrus_is_an_outer_binding():
    code = "def outer(value):\n    def inner(item=(saved := value)):\n        return item\n    first = inner()\n    second = saved\n    return first, second\n"
    renamed = code.replace("saved", "cached")
    first, _ = fragments(
        code, "app/first.py", ignore_identifiers=True, ignore_literals=True
    )
    second, _ = fragments(
        renamed, "app/second.py", ignore_identifiers=True, ignore_literals=True
    )
    assert first[0].ast_norm_type2 == second[0].ast_norm_type2


def test_enclosing_class_global_directive_does_not_change_method_closure():
    code = "def outer(value):\n    class Container:\n        global value\n        def read(self):\n            return value\n    first = Container()\n    second = first.read()\n    return second\n"
    changed = code.replace("def outer(value)", "def outer(other)")
    first, _ = fragments(
        code, "app/first.py", ignore_identifiers=True, ignore_literals=True
    )
    second, _ = fragments(
        changed, "app/second.py", ignore_identifiers=True, ignore_literals=True
    )
    a = next(row for row in first if row.name == "outer")
    b = next(row for row in second if row.name == "outer")
    assert a.ast_norm_type2 != b.ast_norm_type2
