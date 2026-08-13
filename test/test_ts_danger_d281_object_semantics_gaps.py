"""Adversarial JavaScript object-semantics regressions for SKY-D281.

These fixtures exercise standard ECMAScript behavior that is easy to lose in
an abstract heap: dynamic own keys, CopyDataProperties ordering, descriptors,
accessors, frozen objects, sparse arrays, and mutator return identities.
"""

from __future__ import annotations

import pytest

from skylos.visitors.languages.typescript.danger import (
    _check_nextjs_server_action_sqli,
)


FILE_PATH = "/project/app/actions.ts"


def _rule_ids(source: str) -> list[str]:
    findings: list[dict] = []
    _check_nextjs_server_action_sqli(source.encode(), FILE_PATH, findings)
    return [finding["rule_id"] for finding in findings]


@pytest.mark.parametrize(
    "source",
    [
        """
"use server";
export async function find(input: string) {
  const source: any = {};
  source.sql = input;
  const state = { sql: "SELECT 1" };
  Object.assign(state, source);
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const source: any = {};
  source.sql = input;
  const state = { ...source };
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string, key: string) {
  const source: any = { sql: "SELECT 1" };
  source[key] = input;
  const state = { sql: "SELECT 1" };
  Object.assign(state, source);
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const source: any = {};
  Object.defineProperty(source, "sql", {
    value: input,
    enumerable: true,
  });
  const state = { sql: "SELECT 1" };
  Object.assign(state, source);
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const source: any = {};
  Object.assign(source, { sql: input });
  const state = { sql: "SELECT 1" };
  Object.assign(state, source);
  return db.query(state.sql);
}
""",
    ],
    ids=[
        "assign-dynamically-added-own-key",
        "spread-dynamically-added-own-key",
        "assign-unknown-computed-own-key",
        "assign-dynamically-defined-enumerable-key",
        "assign-key-added-by-earlier-assign",
    ],
)
def test_dynamic_enumerable_own_keys_reach_sql(source: str) -> None:
    assert _rule_ids(source) == ["SKY-D281"]


@pytest.mark.parametrize(
    "source",
    [
        """
"use server";
export async function find(input: string) {
  const state = Object.assign({}, { sql: input });
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const state = Object.defineProperty({}, "sql", {
    value: input,
    enumerable: true,
  });
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const state = Object.defineProperties({}, {
    sql: { value: input, enumerable: true },
  });
  return db.query(state.sql);
}
""",
    ],
    ids=[
        "assign-inline-target",
        "define-property-inline-target",
        "define-properties-inline-target",
    ],
)
def test_inline_mutator_targets_keep_returned_object_state(source: str) -> None:
    assert _rule_ids(source) == ["SKY-D281"]


def test_sparse_array_source_keeps_its_real_index() -> None:
    source = """
"use server";
export async function find(input: string) {
  const target = ["SELECT 0", "SELECT 1"];
  Object.assign(target, [, input]);
  return db.query(target[1]);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_sparse_array_hole_does_not_shift_taint_to_index_zero() -> None:
    source = """
"use server";
export async function find(input: string) {
  const target = ["SELECT 0", "SELECT 1"];
  Object.assign(target, [, input]);
  return db.query(target[0]);
}
"""
    assert _rule_ids(source) == []


def test_object_spread_getter_runs_before_later_property_value() -> None:
    source = """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  const patch = {
    get audit() {
      state.sql = "SELECT 1";
      return 1;
    },
  };
  const copy = { ...patch, late: (state.sql = input) };
  return db.query(state.sql);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_object_spread_getter_side_effect_can_be_overwritten_later() -> None:
    source = """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  const patch = {
    get audit() {
      state.sql = input;
      return 1;
    },
  };
  const copy = { ...patch, late: (state.sql = "SELECT 1") };
  return db.query(state.sql);
}
"""
    assert _rule_ids(source) == []


def test_object_assign_uses_ecmascript_numeric_key_order() -> None:
    source = """
"use server";
export async function find(input: string) {
  const control = { value: "SELECT 1" };
  const target = { sql: "SELECT 1" };
  const source = {
    get sql() { return control.value; },
    get 0() { control.value = input; return 0; },
  };
  Object.assign(target, source);
  return db.query(target.sql);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_object_assign_numeric_key_can_sanitize_before_string_key() -> None:
    source = """
"use server";
export async function find(input: string) {
  const control = { value: input };
  const target = { sql: "SELECT 1" };
  const source = {
    get sql() { return control.value; },
    get 0() { control.value = "SELECT 1"; return 0; },
  };
  Object.assign(target, source);
  return db.query(target.sql);
}
"""
    assert _rule_ids(source) == []


@pytest.mark.parametrize(
    "call",
    [
        "Object.assign(...[state, { sql: input }]);",
        'Object.defineProperty(...[state, "sql", { value: input }]);',
    ],
    ids=["assign-static-spread-arguments", "define-property-static-spread-arguments"],
)
def test_static_spread_arguments_preserve_mutator_effects(call: str) -> None:
    source = f"""
"use server";
export async function find(input: string) {{
  const state = {{ sql: "SELECT 1" }};
  {call}
  return db.query(state.sql);
}}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_boxed_string_with_declared_own_sql_property_is_not_primitive() -> None:
    source = """
"use server";
export async function find(input: String & { sql: string }) {
  const state = { sql: "SELECT 1" };
  Object.assign(state, input);
  return db.query(state.sql);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_string_annotation_is_not_runtime_validation() -> None:
    source = """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  Object.assign(state, input);
  return db.query(state.sql);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_define_properties_reads_outer_descriptor_getter() -> None:
    source = """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  Object.defineProperties(state, {
    get sql() { return { value: input }; },
  });
  return db.query(state.sql);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_define_properties_outer_getter_can_return_safe_descriptor() -> None:
    source = """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1", audit: input };
  Object.defineProperties(state, {
    get sql() { return { value: "SELECT 1" }; },
  });
  return db.query(state.sql);
}
"""
    assert _rule_ids(source) == []


@pytest.mark.parametrize(
    "call",
    [
        'Object.defineProperty(state, "sql", {});',
        'Object.defineProperty(state, "sql", { enumerable: false });',
        "Object.defineProperties(state, { sql: {} });",
        'Reflect.defineProperty(state, "sql", {});',
    ],
    ids=[
        "define-property-empty-descriptor",
        "define-property-attribute-only-descriptor",
        "define-properties-empty-descriptor",
        "reflect-define-property-empty-descriptor",
    ],
)
def test_descriptor_without_value_preserves_existing_tainted_value(call: str) -> None:
    source = f"""
"use server";
export async function find(input: string) {{
  const state = {{ sql: "SELECT 1" }};
  state.sql = input;
  {call}
  return db.query(state.sql);
}}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_non_writable_data_property_rejects_later_sanitizing_write() -> None:
    source = """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  Object.defineProperty(state, "sql", {
    value: input,
    writable: false,
  });
  try { state.sql = "SELECT 1"; } catch {}
  return db.query(state.sql);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_writable_data_property_accepts_later_sanitizing_write() -> None:
    source = """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  Object.defineProperty(state, "sql", {
    value: input,
    writable: true,
  });
  state.sql = "SELECT 1";
  return db.query(state.sql);
}
"""
    assert _rule_ids(source) == []


def test_getter_only_property_rejects_later_sanitizing_write() -> None:
    source = """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  Object.defineProperty(state, "sql", {
    get() { return input; },
  });
  try { state.sql = "SELECT 1"; } catch {}
  return db.query(state.sql);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


@pytest.mark.parametrize(
    "mutation",
    [
        "state.sql = input;",
        "Object.assign(state, { sql: input });",
    ],
    ids=["direct-setter-call", "assign-setter-call"],
)
def test_frozen_accessor_setter_still_runs(mutation: str) -> None:
    source = f"""
"use server";
export async function find(input: string) {{
  const state = {{
    backing: {{ value: "SELECT 1" }},
    set sql(value: string) {{ this.backing.value = value; }},
    get sql() {{ return this.backing.value; }},
  }};
  Object.freeze(state);
  {mutation}
  return db.query(state.sql);
}}
"""
    assert _rule_ids(source) == ["SKY-D281"]


@pytest.mark.parametrize(
    "mutation",
    [
        "state.sql = input;",
        "Object.assign(state, { sql: input });",
    ],
    ids=["direct-setter-throws", "assign-setter-throws"],
)
def test_frozen_setter_cannot_write_another_frozen_own_property(
    mutation: str,
) -> None:
    source = f"""
"use server";
export async function find(input: string) {{
  const state = {{
    backing: "SELECT 1",
    set sql(value: string) {{ this.backing = value; }},
    get sql() {{ return this.backing; }},
  }};
  Object.freeze(state);
  try {{ {mutation} }} catch {{}}
  return db.query(state.sql);
}}
"""
    assert _rule_ids(source) == []


@pytest.mark.parametrize(
    "mutation",
    [
        'try { Object.defineProperty(state, "sql", { value: input }); } catch {}',
        'Reflect.defineProperty(state, "sql", { value: input });',
        'Reflect.set(state, "sql", input);',
    ],
    ids=[
        "object-define-property-frozen-data",
        "reflect-define-property-frozen-data",
        "reflect-set-frozen-data",
    ],
)
def test_frozen_data_property_rejects_mutation(mutation: str) -> None:
    source = f"""
"use server";
export async function find(input: string) {{
  const state = Object.freeze({{ sql: "SELECT 1" }});
  {mutation}
  return db.query(state.sql);
}}
"""
    assert _rule_ids(source) == []


def test_non_enumerable_source_property_is_not_assigned() -> None:
    source = """
"use server";
export async function find(input: string) {
  const source = { sql: "SELECT 1" };
  Object.defineProperty(source, "sql", {
    value: input,
    enumerable: false,
  });
  const state = { sql: "SELECT 1" };
  Object.assign(state, source);
  return db.query(state.sql);
}
"""
    assert _rule_ids(source) == []


def test_enumerable_source_property_is_assigned() -> None:
    source = """
"use server";
export async function find(input: string) {
  const source = { sql: "SELECT 1" };
  Object.defineProperty(source, "sql", {
    value: input,
    enumerable: true,
  });
  const state = { sql: "SELECT 1" };
  Object.assign(state, source);
  return db.query(state.sql);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_object_assign_invokes_target_setter_instead_of_replacing_it() -> None:
    source = """
"use server";
export async function find(input: string) {
  const state = {
    backing: "SELECT 1",
    set sql(value: string) { this.backing = "SELECT 1"; },
    get sql() { return this.backing; },
  };
  Object.assign(state, { sql: input });
  return db.query(state.sql);
}
"""
    assert _rule_ids(source) == []


def test_object_assign_target_setter_can_store_tainted_value() -> None:
    source = """
"use server";
export async function find(input: string) {
  const state = {
    backing: "SELECT 1",
    set sql(value: string) { this.backing = value; },
    get sql() { return this.backing; },
  };
  Object.assign(state, { sql: input });
  return db.query(state.sql);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_deleted_source_property_is_not_assigned() -> None:
    source = """
"use server";
export async function find(input: string) {
  const source: any = { sql: input };
  delete source.sql;
  const state = { sql: "SELECT 1" };
  Object.assign(state, source);
  return db.query(state.sql);
}
"""
    assert _rule_ids(source) == []


def test_source_property_without_delete_is_assigned() -> None:
    source = """
"use server";
export async function find(input: string) {
  const source = { sql: input };
  const state = { sql: "SELECT 1" };
  Object.assign(state, source);
  return db.query(state.sql);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]
