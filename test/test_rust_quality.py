from __future__ import annotations

import json
from textwrap import dedent

import pytest

from skylos.analyzer import analyze
from skylos.reporting.listing import is_listed
from skylos.rules.catalog import get_rule_catalog, get_rule_finding_type
from skylos.visitors.languages.rust import scan_rust_file

_QUALITY_RULES = {"SKY-Q305", "SKY-UC002"}


def _scan(tmp_path, source, **options):
    path = tmp_path / "lib.rs"
    path.write_text(dedent(source).lstrip())
    return scan_rust_file(str(path), {}, **options)


def _quality(tmp_path, source):
    return _scan(tmp_path, source)[6]


@pytest.mark.parametrize("terminator", ["return", "break", "continue"])
def test_unreachable_direct_terminator_reports_first_executable(tmp_path, terminator):
    findings = _quality(
        tmp_path,
        f"""
        fn work() {{ loop {{
            {terminator};
            fn item() {{}}
            const VALUE: u32 = 1;
            let value = VALUE;
            consume(value);
        }} }}
    """,
    )
    assert [(f["rule_id"], f["line"], f["col"]) for f in findings] == [
        ("SKY-UC002", 5, 4)
    ]
    assert findings[0]["message"] == f"Unreachable code after {terminator}."
    assert findings[0]["name"] == "work"


def test_labelled_break_is_local_to_its_block(tmp_path):
    findings = _quality(
        tmp_path,
        """
        fn work() {
            'result: {
                break 'result 1;
                let value = 2;
                value
            };
            consume(3);
        }
    """,
    )
    assert [(f["rule_id"], f["line"]) for f in findings] == [("SKY-UC002", 4)]


@pytest.mark.parametrize(
    "source",
    [
        "fn f(flag: bool) { if flag { return; } consume(); }",
        "fn f() { loop { break; } consume(); }",
        "fn f() { let callback = || { return 1; }; consume(callback()); }",
        "fn f() { return; fn item() {} const VALUE: u32 = 1; }",
        'fn f() { let text = "return; consume();"; consume(text); }',
        "fn f() { /* return; consume(); */ consume(); }",
        'fn f() { panic!("stop"); consume(); }',
        "macro_rules! quoted { () => { return; consume(); }; }",
        'fn f() { #[cfg(feature = "early")] return; consume(); }',
        'fn f() { #[cfg_attr(feature = "early", allow(unused))] return; consume(); }',
        "fn f() { return; opaque!(); }",
    ],
)
def test_unreachable_negative_controls(tmp_path, source):
    assert _quality(tmp_path, source) == []


def test_nested_function_has_separate_termination_scope(tmp_path):
    findings = _quality(
        tmp_path,
        """
        fn outer() {
            fn inner() { return; consume(); }
            consume();
        }
    """,
    )
    assert [(f["rule_id"], f["line"], f["name"]) for f in findings] == [
        ("SKY-UC002", 2, "outer.inner")
    ]


def test_duplicate_bodies_ignore_formatting_but_preserve_tokens(tmp_path):
    findings = _quality(
        tmp_path,
        """
        fn render(flag: bool) -> &'static str {
            if flag {
                let label = "active";
                return label;
            } else {
                // Same statements, different formatting.
                let   label="active";
                return   label;
            }
        }
    """,
    )
    assert [(f["rule_id"], f["line"], f["name"], f["value"]) for f in findings] == [
        ("SKY-Q305", 5, "render", "duplicate_body")
    ]
    assert findings[0]["metadata"]["first_branch_line"] == 2


@pytest.mark.parametrize(
    "condition,parameters",
    [
        ("flag", "flag: bool"),
        ("!flag", "flag: bool"),
        ("(flag)", "flag: bool"),
    ],
)
def test_duplicate_conditions_require_plain_bool_binding(
    tmp_path, condition, parameters
):
    findings = _quality(
        tmp_path,
        f"""
        fn f({parameters}) {{
            if {condition} {{ let value = 1; consume(value); }}
            else {{ let value = 1; consume(value); }}
        }}
    """,
    )
    assert [f["rule_id"] for f in findings] == ["SKY-Q305"]


@pytest.mark.parametrize(
    "binding", ["let flag = true;", "let flag: bool = get_flag();"]
)
def test_duplicate_local_bool_binding(tmp_path, binding):
    findings = _quality(
        tmp_path,
        f"""
        fn f() {{ {binding}
            if flag {{ let value = 1; consume(value); }}
            else {{ let value = 1; consume(value); }}
        }}
    """,
    )
    assert [f["rule_id"] for f in findings] == ["SKY-Q305"]


def test_duplicate_chain_reports_each_later_body_once(tmp_path):
    findings = _quality(
        tmp_path,
        """
        fn f(left: bool, right: bool) {
            if left { let value = 1; consume(value); }
            else if right { let value = 1; consume(value); }
            else { let value = 1; consume(value); }
        }
    """,
    )
    assert [(f["rule_id"], f["line"]) for f in findings] == [
        ("SKY-Q305", 3),
        ("SKY-Q305", 4),
    ]


@pytest.mark.parametrize(
    "source",
    [
        'fn f(flag: bool) { if flag { let x="a b"; consume(x); } else { let x="ab"; consume(x); } }',
        'fn f(flag: bool) { if flag { let x=r#"a b"#; consume(x); } else { let x=r#"ab"#; consume(x); } }',
        "fn f(flag: bool) { if flag { return 1; } else { return 1; } }",
        "fn f(flag: bool) { if flag {} else {} }",
        "fn f() { if condition() { let x=1; consume(x); } else { let x=1; consume(x); } }",
        "fn f(value: Custom) { if !value { let x=1; consume(x); } else { let x=1; consume(x); } }",
        "fn f(flag: bool) { let flag=unknown(); if flag { let x=1; consume(x); } else { let x=1; consume(x); } }",
        "fn f(flag: bool) { for flag in values { if flag { let x=1; consume(x); } else { let x=1; consume(x); } } }",
        "fn f(flag: bool) { let c = |flag| { if flag { let x=1; consume(x); } else { let x=1; consume(x); } }; }",
        "fn f(flag: bool) { if let Some(flag) = value { if flag { let x=1; consume(x); } else { let x=1; consume(x); } } }",
        "fn f(flag: bool) { match value { Some(flag) => { if flag { let x=1; consume(x); } else { let x=1; consume(x); } } } }",
        "fn f(left: Option<i32>, right: Option<i32>) { if let Some(x)=left { let y=x; consume(y); } else if let Some(x)=right { let y=x; consume(y); } }",
        "fn f(flag: bool) { if flag { let x=line!(); consume(x); } else { let x=line!(); consume(x); } }",
        'fn f(flag: bool) { if flag { #[cfg(feature="a")] let x=1; consume(x); } else { #[cfg(feature="a")] let x=1; consume(x); } }',
        "fn f(left: bool, right: bool) { if left { let x=1; consume(x); } if right { let x=1; consume(x); } }",
    ],
)
def test_duplicate_negative_controls(tmp_path, source):
    assert _quality(tmp_path, source) == []


def test_quality_is_silent_on_parse_error(tmp_path):
    assert _quality(tmp_path, "fn f() { return; consume(); } fn broken( {") == []


def test_quality_flags_routing_listing_and_catalog(tmp_path):
    source = """
        pub fn duplicate(flag: bool) {
            if flag { let value=1; consume(value); }
            else { let value=1; consume(value); }
        }
        pub fn unreachable() { return; consume(); }
    """
    enabled = _scan(
        tmp_path, source, enable_quality_rules=True, enable_danger_rules=False
    )
    disabled = _scan(tmp_path, source, enable_quality_rules=False)
    assert [f["rule_id"] for f in enabled[6]] == ["SKY-Q305", "SKY-UC002"]
    assert disabled[6] == []
    assert [(d.name, d.line) for d in enabled[0]] == [
        (d.name, d.line) for d in disabled[0]
    ]
    result = json.loads(analyze(str(tmp_path), conf=0, enable_quality=True))
    findings = [f for f in result["quality"] if f["rule_id"] in _QUALITY_RULES]
    assert [(f["rule_id"], f["line"]) for f in findings] == [
        ("SKY-Q305", 3),
        ("SKY-UC002", 5),
    ]
    assert all(is_listed(f) for f in findings)
    assert get_rule_finding_type("SKY-UC002") == "defect"
    assert get_rule_finding_type("SKY-Q305") == "review"
    categories = {row["id"]: row["category"] for row in get_rule_catalog()}
    assert categories["SKY-UC002"] == "dead_code"
    assert categories["SKY-Q305"] == "quality"
    off = json.loads(analyze(str(tmp_path), conf=0, enable_quality=False))
    assert not any(f["rule_id"] in _QUALITY_RULES for f in off.get("quality", []))
    assert len(enabled) == len(disabled) == 13


def test_quality_rule_specific_inline_ignore(tmp_path):
    _scan(
        tmp_path,
        """
        pub fn f() {
            return;
            consume(); // skylos: ignore[SKY-UC002]
        }
    """,
    )
    result = json.loads(analyze(str(tmp_path), conf=0, enable_quality=True))
    assert not any(f["rule_id"] in _QUALITY_RULES for f in result.get("quality", []))
    suppressed = [
        f for f in result.get("suppressed", []) if f["rule_id"] == "SKY-UC002"
    ]
    assert len(suppressed) == 1
    assert suppressed[0]["reason"] == "inline ignore comment"


@pytest.mark.parametrize(
    "marker",
    [
        "// skylos: ignore[SKY-UC002]",
        "/* skylos: ignore[SKY-UC002] */",
        "// skylos: ignore",
    ],
)
def test_quality_suppression_retains_raw_tuple_and_evidence(tmp_path, marker):
    source = f"fn f() {{ return; consume(); {marker}\n }}"
    raw = _scan(tmp_path, source)
    filtered = _scan(tmp_path, source, _include_analysis_metadata=True)
    assert len(raw) == 13
    assert [f["rule_id"] for f in raw[6]] == ["SKY-UC002"]
    assert filtered[6] == []
    assert filtered[13] == set()
    assert [f["rule_id"] for f in filtered[14]] == ["SKY-UC002"]
    assert filtered[14][0]["category"] == "quality"
    assert [(d.name, d.line, d.type) for d in filtered[0]] == [
        (d.name, d.line, d.type) for d in raw[0]
    ]
    assert filtered[1:4] == raw[1:4]
    assert filtered[12] == raw[12]
    assert filtered[7] == raw[7]


@pytest.mark.parametrize(
    "source",
    [
        'fn f() { return; consume("// skylos: ignore[SKY-UC002]"); }',
        'fn f() { return; consume(r#"// skylos: ignore[SKY-UC002]"#); }',
        "fn f() { return; consume(); // skylos: ignore[SKY-Q305]\n }",
        "fn f() { return; consume(); // skylos: ignore[not-a-rule]\n }",
        "fn f() { return; consume(); /* prose skylos: ignore[SKY-UC002] */ }",
    ],
)
def test_quality_ignore_lookalikes_do_not_suppress(tmp_path, source):
    result = _scan(tmp_path, source, _include_analysis_metadata=True)
    assert [f["rule_id"] for f in result[6]] == ["SKY-UC002"]
    assert result[14] == []


def test_quality_block_ignores_and_config_ignore(tmp_path):
    source = """
        // skylos: ignore-start
        fn hidden() { return; consume(); }
        // skylos: ignore-end
        fn visible() { return; consume(); }
    """
    result = _scan(tmp_path, source, _include_analysis_metadata=True)
    assert [(f["rule_id"], f["line"]) for f in result[6]] == [("SKY-UC002", 4)]
    assert [(f["rule_id"], f["line"]) for f in result[14]] == [("SKY-UC002", 2)]
    configured = scan_rust_file(str(tmp_path / "lib.rs"), {"ignore": ["SKY-UC002"]})
    assert configured[6] == []


def test_quality_ignores_leave_danger_output_unchanged(tmp_path):
    source = """
        use std::process::Command;
        fn f(cmd: String) {
            Command::new(cmd).spawn(); // skylos: ignore
            return;
            consume(); // skylos: ignore[SKY-UC002]
        }
    """
    raw = _scan(tmp_path, source)
    filtered = _scan(tmp_path, source, _include_analysis_metadata=True)
    assert filtered[6] == []
    assert raw[7] == filtered[7]
    assert [f["rule_id"] for f in filtered[7]] == ["SKY-D212"]


_CUSTOM_NOT = """
    struct Custom;
    impl std::ops::Not for Custom {
        type Output = ::core::primitive::bool;
        fn not(self) -> Self::Output { side_effect(); true }
    }
"""
_DUPLICATE_NOT = """
    fn inspect(flag: bool) {
        if !flag { let value = 1; consume(value); }
        else { let value = 1; consume(value); }
    }
"""


@pytest.mark.parametrize(
    "declaration",
    [
        "type bool = Custom;",
        "use crate::Custom as bool;",
        "use crate::{Custom as bool};",
        "use crate::types::bool;",
        "use crate::types::{bool};",
        "use crate::types::*;",
        "make_types!();",
    ],
)
def test_custom_bool_name_does_not_prove_pure_not(tmp_path, declaration):
    findings = _quality(tmp_path, _CUSTOM_NOT + declaration + _DUPLICATE_NOT)
    assert not any(f["rule_id"] == "SKY-Q305" for f in findings)


@pytest.mark.parametrize(
    "source",
    [
        "fn inspect<bool: std::ops::Not<Output = ::core::primitive::bool>>(flag: bool) { if !flag { let value=1; consume(value); } else { let value=1; consume(value); } }",
        "fn outer() { type bool = Custom; fn inspect(flag: bool) { if !flag { let value=1; consume(value); } else { let value=1; consume(value); } } }",
        "fn outer() { type bool = Custom; let flag: bool = Custom; if !flag { let value=1; consume(value); } else { let value=1; consume(value); } }",
        "fn outer() { use crate::Custom as bool; let inspect = |flag: bool| { if !flag { let value=1; consume(value); } else { let value=1; consume(value); } }; }",
        "mod nested { type bool = super::Custom; fn inspect(flag: bool) { if !flag { let value=1; consume(value); } else { let value=1; consume(value); } } }",
    ],
)
def test_bool_shadowing_in_nested_type_scopes(tmp_path, source):
    assert not any(
        f["rule_id"] == "SKY-Q305" for f in _quality(tmp_path, _CUSTOM_NOT + source)
    )


def test_nested_bool_alias_does_not_poison_unrelated_primitive_parameter(tmp_path):
    source = _CUSTOM_NOT + "mod nested { type bool = super::Custom; }" + _DUPLICATE_NOT
    assert [f["rule_id"] for f in _quality(tmp_path, source)] == ["SKY-Q305"]


def test_block_alias_does_not_change_preexisting_parameter_type(tmp_path):
    source = (
        _CUSTOM_NOT
        + """
        fn inspect(flag: bool) {
            type bool = Custom;
            if !flag { let value=1; consume(value); }
            else { let value=1; consume(value); }
        }
    """
    )
    assert [f["rule_id"] for f in _quality(tmp_path, source)] == ["SKY-Q305"]


def test_bool_literal_remains_primitive_under_type_alias(tmp_path):
    source = (
        _CUSTOM_NOT
        + """
        type bool = Custom;
        fn inspect() {
            let flag = true;
            if !flag { let value=1; consume(value); }
            else { let value=1; consume(value); }
        }
    """
    )
    assert [f["rule_id"] for f in _quality(tmp_path, source)] == ["SKY-Q305"]
