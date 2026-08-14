"""Red-team regressions for precise TypeScript Server Action SQL flow."""

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
    ("source", "expected"),
    [
        (
            """
"use server";
export async function find(input: string) {
  const state = { sql: input };
  for (;;) { state.sql = "SELECT 1"; break; }
  return db.query(state.sql);
}
""",
            [],
        ),
        (
            """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  while (false) { state.sql = input; }
  return db.query(state.sql);
}
""",
            [],
        ),
        (
            """
"use server";
function fail(): never { throw new Error("stop"); }
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  try {
    switch ("x") {
      case fail(): state.sql = input; break;
      default: state.sql = input;
    }
  } catch {}
  return db.query(state.sql);
}
""",
            [],
        ),
        (
            """
"use server";
function fail(): never { throw new Error("stop"); }
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  try { switch (fail()) { default: state.sql = input; } } catch {}
  return db.query(state.sql);
}
""",
            [],
        ),
        (
            """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  switch ("a") { case "b": state.sql = input; break; }
  return db.query(state.sql);
}
""",
            [],
        ),
    ],
    ids=[
        "infinite-for-break",
        "while-false",
        "throwing-case-test",
        "throwing-discriminant",
        "constant-case-mismatch",
    ],
)
def test_control_flow_feasibility(source: str, expected: list[str]) -> None:
    assert _rule_ids(source) == expected


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            """
"use server";
function setOrThrow(state: any, input: string, ok: boolean) {
  if (ok) { state.sql = input; return; }
  throw new Error("stop");
}
export async function find(input: string, ok: boolean) {
  const state = { sql: "SELECT 1" };
  try { setOrThrow(state, input, ok); }
  catch { state.sql = "SELECT 1"; }
  return db.query(state.sql);
}
""",
            ["SKY-D281"],
        ),
        (
            """
"use server";
function resetOrThrow(state: any, ok: boolean) {
  if (ok) { state.sql = "SELECT 1"; return; }
  throw new Error("stop");
}
export async function find(input: string, ok: boolean) {
  const state = { sql: input };
  try { resetOrThrow(state, ok); }
  catch { state.sql = "SELECT 1"; }
  return db.query(state.sql);
}
""",
            [],
        ),
        (
            """
"use server";
function pure() { return 1; }
export async function find(input: string) {
  const state = { sql: input };
  try { pure(); state.sql = "SELECT 1"; } catch {}
  return db.query(state.sql);
}
""",
            [],
        ),
        (
            """
"use server";
export async function find(input: string) {
  [1].forEach(() => { throw new Error("stop"); });
  return db.query(input);
}
""",
            [],
        ),
    ],
    ids=[
        "return-path-taints",
        "return-path-sanitizes",
        "pure-call-no-exception",
        "nonempty-foreach-throw",
    ],
)
def test_local_callable_completion(source: str, expected: list[str]) -> None:
    assert _rule_ids(source) == expected


@pytest.mark.parametrize(
    "declaration",
    [
        'async function fail() { throw new Error("stop"); }',
        'function* fail() { throw new Error("stop"); }',
    ],
    ids=["unawaited-async", "unstarted-generator"],
)
def test_deferred_callable_failure_does_not_hide_reachable_sink(
    declaration: str,
) -> None:
    source = f"""
"use server";
{declaration}
export async function find(input: string) {{
  fail();
  return db.query(input);
}}
"""

    assert _rule_ids(source) == ["SKY-D281"]


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  Object.defineProperty(state, "sql", { get() { return input; } });
  return db.query(state.sql);
}
""",
            ["SKY-D281"],
        ),
        (
            """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  const merge = Object.assign.bind(Object);
  merge(state, { sql: input });
  return db.query(state.sql);
}
""",
            ["SKY-D281"],
        ),
        (
            """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  const { assign } = Object;
  assign(state, { sql: input });
  return db.query(state.sql);
}
""",
            ["SKY-D281"],
        ),
        (
            """
"use server";
function fail(): never { throw new Error("stop"); }
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  try { Object.defineProperty(state, "sql", fail()); } catch {}
  return db.query(state.sql);
}
""",
            [],
        ),
        (
            """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1", audit: "" };
  const changed = Reflect.set(state, "audit", input);
  return db.query(changed ? "SELECT 1" : "SELECT 2");
}
""",
            [],
        ),
        (
            """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1", audit: "" };
  const merged = Object.assign(state, { audit: input });
  return db.query(merged.sql);
}
""",
            [],
        ),
    ],
    ids=[
        "descriptor-getter",
        "bound-object-assign",
        "destructured-object-assign",
        "throwing-descriptor",
        "reflect-set-boolean-result",
        "object-assign-target-result",
    ],
)
def test_builtin_mutator_semantics(source: str, expected: list[str]) -> None:
    assert _rule_ids(source) == expected


@pytest.mark.parametrize(
    ("descriptor", "expected"),
    [
        ('{ get() { return "SELECT 1"; } }', []),
        ("{ get: () => input }", ["SKY-D281"]),
        ("{ set(value: string) { console.info(value); } }", []),
    ],
    ids=["safe-getter", "arrow-getter", "setter-only"],
)
def test_property_descriptor_accessor_semantics(
    descriptor: str,
    expected: list[str],
) -> None:
    source = f"""
"use server";
export async function find(input: string) {{
  const state = {{ sql: "SELECT 1" }};
  Object.defineProperty(state, "sql", {descriptor});
  return db.query(state.sql);
}}
"""

    assert _rule_ids(source) == expected


def test_property_descriptor_getter_reads_late_capture_state() -> None:
    source = """
"use server";
export async function find(input: string) {
  let sql = "SELECT 1";
  const state = { sql: "SELECT 1" };
  Object.defineProperty(state, "sql", { get() { return sql; } });
  sql = input;
  return db.query(state.sql);
}
"""

    assert _rule_ids(source) == ["SKY-D281"]


@pytest.mark.parametrize(
    ("setup", "call"),
    [
        ("const { assign: merge } = Object;", "merge(state, { sql: input });"),
        (
            "const merge = Object.assign.bind(Object, state);",
            "merge({ sql: input });",
        ),
        (
            "const first = Object.assign; const merge = first;",
            "merge(state, { sql: input });",
        ),
    ],
    ids=["renamed-destructure", "prebound-target", "alias-chain"],
)
def test_builtin_mutator_alias_forms_taint_the_target(setup: str, call: str) -> None:
    source = f"""
"use server";
export async function find(input: string) {{
  const state = {{ sql: "SELECT 1" }};
  {setup}
  {call}
  return db.query(state.sql);
}}
"""

    assert _rule_ids(source) == ["SKY-D281"]


def test_object_assign_returned_target_keeps_sql_property_precision() -> None:
    unsafe = """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1", audit: "" };
  const merged = Object.assign(state, { sql: input });
  return db.query(merged.sql);
}
"""
    safe_after_rebind = """
"use server";
export async function find(input: string) {
  let state = { sql: "SELECT 1", audit: "" };
  const merged = Object.assign(state, { audit: input });
  state = { sql: input, audit: "" };
  return db.query(merged.sql);
}
"""

    assert _rule_ids(unsafe) == ["SKY-D281"]
    assert _rule_ids(safe_after_rebind) == []


def test_reflect_boolean_result_does_not_hide_mutated_sql_property() -> None:
    source = """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  const changed = Reflect.set(state, "sql", input);
  console.info(changed);
  return db.query(state.sql);
}
"""

    assert _rule_ids(source) == ["SKY-D281"]


@pytest.mark.parametrize("method", ["freeze", "isFrozen"])
def test_non_escaping_object_inspection_preserves_sql_tag(method: str) -> None:
    source = f"""
"use server";
import * as drizzle from "drizzle-orm";
export async function find(input: string) {{
  Object.{method}(drizzle);
  return db.execute(drizzle.sql`SELECT * FROM users WHERE name = ${{input}}`);
}}
"""

    assert _rule_ids(source) == []


@pytest.mark.parametrize(
    "override",
    [
        "Object.freeze = escape;",
        'Object["freeze"] = escape;',
        "const key = input; Object[key] = escape;",
    ],
    ids=["dot", "bracket", "computed"],
)
def test_overridden_object_freeze_is_not_trusted(override: str) -> None:
    source = f"""
"use server";
import * as drizzle from "drizzle-orm";
declare function escape(value: object): void;
export async function find(input: string) {{
  {override}
  Object.freeze(drizzle);
  return db.execute(drizzle.sql`SELECT * FROM users WHERE name = ${{input}}`);
}}
"""

    assert _rule_ids(source) == ["SKY-D281"]


@pytest.mark.parametrize(
    "escape_statement",
    [
        "escape({ namespace: drizzle });",
        "escape([drizzle]);",
        "const namespace = flag ? drizzle : {}; escape(namespace);",
    ],
    ids=["object", "array", "conditional-alias"],
)
def test_nested_namespace_escape_invalidates_parameterized_tag(
    escape_statement: str,
) -> None:
    source = f"""
"use server";
import * as drizzle from "drizzle-orm";
declare function escape(value: object): void;
export async function find(input: string, flag: boolean) {{
  {escape_statement}
  return db.execute(drizzle.sql`SELECT * FROM users WHERE name = ${{input}}`);
}}
"""

    assert _rule_ids(source) == ["SKY-D281"]


@pytest.mark.parametrize(
    "argument",
    [
        "drizzle ? {} : {}",
        "{ [String(drizzle)]: 1 }",
    ],
    ids=["condition-only", "computed-key-only"],
)
def test_non_value_namespace_references_do_not_escape(argument: str) -> None:
    source = f"""
"use server";
import * as drizzle from "drizzle-orm";
declare function escape(value: object): void;
export async function find(input: string) {{
  escape({argument});
  return db.execute(drizzle.sql`SELECT * FROM users WHERE name = ${{input}}`);
}}
"""

    assert _rule_ids(source) == []


@pytest.mark.parametrize(
    "write",
    [
        'state["query.sql"] = input;',
        'state["*"] = input;',
    ],
    ids=["literal-dot", "literal-star"],
)
def test_literal_property_names_do_not_collide_with_heap_syntax(write: str) -> None:
    extra = ', "query.sql": ""' if "query.sql" in write else ', "*": ""'
    source = f'''
"use server";
export async function find(input: string) {{
  const state = {{ query: {{ sql: "SELECT 1" }}, sql: "SELECT 1"{extra} }};
  {write}
  return db.query({"state.query.sql" if "query.sql" in write else "state.sql"});
}}
'''

    assert _rule_ids(source) == []


def test_helper_exact_reset_masks_earlier_unknown_property_write() -> None:
    source = """
"use server";
function reset(state: any) { state.sql = "SELECT 1"; }
export async function find(input: string, key: string) {
  const state = { sql: "SELECT 0" };
  state[key] = input;
  reset(state);
  return db.query(state.sql);
}
"""

    assert _rule_ids(source) == []


def test_conditional_helper_reset_does_not_mask_unknown_property_write() -> None:
    source = """
"use server";
function reset(state: any, ok: boolean) {
  if (ok) state.sql = "SELECT 1";
}
export async function find(input: string, key: string, ok: boolean) {
  const state = { sql: "SELECT 0" };
  state[key] = input;
  reset(state, ok);
  return db.query(state.sql);
}
"""

    assert _rule_ids(source) == ["SKY-D281"]


def test_nested_helper_reset_masks_nested_unknown_property_write() -> None:
    source = """
"use server";
function reset(state: any) { state.query.sql = "SELECT 1"; }
export async function find(input: string, key: string) {
  const state = { query: { sql: "SELECT 0" } };
  state.query[key] = input;
  reset(state);
  return db.query(state.query.sql);
}
"""

    assert _rule_ids(source) == []


def test_labelled_continue_through_finally_keeps_loop_target() -> None:
    source = """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  outer: for (let i = 0; i < 1; i++) {
    try { continue outer; }
    finally { state.sql = "SELECT 1"; }
  }
  return db.query(state.sql);
}
"""

    assert _rule_ids(source) == []


def test_equivalent_identifier_exception_states_are_deduplicated() -> None:
    statements = "\n".join("state.audit = SAFE; mayThrow();" for _ in range(300))
    source = f"""
"use server";
declare function mayThrow(): void;
const SAFE = "ok";
export async function find(input: string) {{
  const state = {{ sql: "SELECT 1", audit: "" }};
  try {{ {statements} }} catch {{}}
  return db.query(state.sql);
}}
"""

    assert _rule_ids(source) == []
