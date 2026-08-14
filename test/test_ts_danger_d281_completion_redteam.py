"""Red-team regressions for D281 completion and state-join semantics."""

from __future__ import annotations

from skylos.visitors.languages.typescript.danger import (
    _check_nextjs_server_action_sqli,
)


FILE_PATH = "/project/app/actions.ts"


def _rule_ids(source: bytes) -> list[str]:
    findings: list[dict] = []
    _check_nextjs_server_action_sqli(source, FILE_PATH, findings)
    return [finding["rule_id"] for finding in findings]


def test_throwing_helper_heap_mutation_reaches_caller_catch():
    source = b"""\
"use server";
function taintThenThrow(state: any, input: string): never {
    state.sql = input;
    throw new Error("stop");
}
export async function find(input: string) {
    const state = { sql: "SELECT 1" };
    try {
        taintThenThrow(state, input);
    } catch {}
    return db.query(state.sql);
}
"""

    assert _rule_ids(source) == ["SKY-D281"]


def test_returned_object_alias_preserves_tainted_member():
    source = b"""\
"use server";
function taintAndReturn(state: any, input: string) {
    state.sql = input;
    return state;
}
export async function find(input: string) {
    const state = { sql: "SELECT 1" };
    const chosen = taintAndReturn(state, input);
    return db.query(chosen.sql);
}
"""

    assert _rule_ids(source) == ["SKY-D281"]


def test_returned_object_alias_write_reaches_original_object():
    source = b"""\
"use server";
function identity<T>(value: T) {
    return value;
}
export async function find(input: string) {
    const state = { sql: "SELECT 1" };
    const chosen = identity(state);
    chosen.sql = input;
    return db.query(state.sql);
}
"""

    assert _rule_ids(source) == ["SKY-D281"]


def test_unawaited_async_post_await_sanitizer_does_not_clean_current_state():
    source = b"""\
"use server";
async function resetLater(state: any) {
    await Promise.resolve();
    state.sql = "SELECT 1";
}
export async function find(input: string) {
    const state = { sql: input };
    resetLater(state);
    return db.query(state.sql);
}
"""

    assert _rule_ids(source) == ["SKY-D281"]


def test_unawaited_async_post_await_taint_does_not_reach_current_sink():
    source = b"""\
"use server";
async function taintLater(state: any, input: string) {
    await Promise.resolve();
    state.sql = input;
}
export async function find(input: string) {
    const state = { sql: "SELECT 1" };
    taintLater(state, input);
    return db.query(state.sql);
}
"""

    assert _rule_ids(source) == []


def test_for_of_resumes_generator_heap_effects():
    source = b"""\
"use server";
function* taint(state: any, input: string) {
    state.sql = input;
    yield 1;
}
export async function find(input: string) {
    const state = { sql: "SELECT 1" };
    for (const value of taint(state, input)) {
        audit(value);
    }
    return db.query(state.sql);
}
"""

    assert _rule_ids(source) == ["SKY-D281"]


def test_next_resumes_generator_heap_effects():
    source = b"""\
"use server";
function* taint(state: any, input: string) {
    state.sql = input;
    yield 1;
}
export async function find(input: string) {
    const state = { sql: "SELECT 1" };
    const iterator = taint(state, input);
    iterator.next();
    return db.query(state.sql);
}
"""

    assert _rule_ids(source) == ["SKY-D281"]


def test_numeric_false_while_body_is_unreachable():
    source = b"""\
"use server";
export async function find(input: string) {
    const state = { sql: "SELECT 1" };
    while (0) {
        state.sql = input;
    }
    return db.query(state.sql);
}
"""

    assert _rule_ids(source) == []


def test_numeric_true_while_has_no_zero_iteration_path():
    source = b"""\
"use server";
export async function find(input: string) {
    const state = { sql: input };
    while (1) {
        state.sql = "SELECT 1";
        break;
    }
    return db.query(state.sql);
}
"""

    assert _rule_ids(source) == []


def test_empty_array_for_of_body_is_unreachable():
    source = b"""\
"use server";
export async function find(input: string) {
    const state = { sql: "SELECT 1" };
    for (const value of []) {
        state.sql = input;
        audit(value);
    }
    return db.query(state.sql);
}
"""

    assert _rule_ids(source) == []


def test_dense_nonempty_array_for_of_has_no_zero_iteration_path():
    source = b"""\
"use server";
export async function find(input: string) {
    const state = { sql: input };
    for (const value of [1]) {
        state.sql = "SELECT 1";
        audit(value);
    }
    return db.query(state.sql);
}
"""

    assert _rule_ids(source) == []


def test_sparse_array_for_of_still_executes_the_body():
    source = b"""\
"use server";
export async function find(input: string) {
    const state = { sql: "SELECT 1" };
    for (const value of [,]) {
        state.sql = input;
        audit(value);
    }
    return db.query(state.sql);
}
"""

    assert _rule_ids(source) == ["SKY-D281"]


def test_numeric_switch_mismatch_body_is_unreachable():
    source = b"""\
"use server";
export async function find(input: string) {
    const state = { sql: "SELECT 1" };
    switch (1) {
        case 2:
            state.sql = input;
            break;
    }
    return db.query(state.sql);
}
"""

    assert _rule_ids(source) == []


def test_chained_loop_label_continue_is_resolved():
    source = b"""\
"use server";
export async function find(input: string) {
    const state = { sql: "SELECT 1" };
    outer: inner: for (let index = 0; index < 1; index++) {
        try {
            continue outer;
        } finally {
            state.sql = "SELECT 1";
        }
    }
    return db.query(state.sql);
}
"""

    assert _rule_ids(source) == []


def test_unawaited_async_throw_does_not_make_safe_action_incomplete():
    source = b"""\
"use server";
async function failLater() {
    throw new Error("stop");
}
export async function find(input: string) {
    failLater();
    return db.query("SELECT 1");
}
"""

    assert _rule_ids(source) == []


def test_returned_rebound_alias_does_not_mutate_original_object():
    source = b"""\
"use server";
function replace(value: any) {
  value = { sql: "SELECT 1" };
  return value;
}
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  const chosen = replace(state);
  chosen.sql = input;
  return db.query(state.sql);
}
"""

    assert _rule_ids(source) == []


def test_multiple_returned_aliases_preserve_possible_exact_member_taint():
    source = b"""\
"use server";
function choose(a: any, b: any, flag: boolean) {
  if (flag) return a;
  return b;
}
export async function find(input: string, flag: boolean) {
  const a = { sql: "SELECT 0" };
  const b = { sql: "SELECT 1" };
  a.sql = input;
  const chosen = choose(a, b, flag);
  return db.query(chosen.sql);
}
"""

    assert _rule_ids(source) == ["SKY-D281"]


def test_nested_unawaited_async_preserves_preawait_sanitizer():
    source = b"""\
"use server";
async function inner(state: any) {
  state.sql = "SELECT 1";
  await Promise.resolve();
}
async function outer(state: any) {
  await inner(state);
}
export async function find(input: string) {
  const state = { sql: input };
  outer(state);
  return db.query(state.sql);
}
"""

    assert _rule_ids(source) == []


def test_nested_unawaited_async_does_not_apply_postawait_taint():
    source = b"""\
"use server";
async function inner(state: any, input: string) {
  await Promise.resolve();
  state.sql = input;
}
async function outer(state: any, input: string) {
  await inner(state, input);
}
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  outer(state, input);
  return db.query(state.sql);
}
"""

    assert _rule_ids(source) == []


def test_for_of_break_does_not_resume_generator_after_first_yield():
    source = b"""\
"use server";
function* values(state: any, input: string) {
  yield 1;
  state.sql = input;
  yield 2;
}
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  for (const value of values(state, input)) {
    break;
  }
  return db.query(state.sql);
}
"""

    assert _rule_ids(source) == []


def test_second_next_resumes_generator_after_first_yield():
    source = b"""\
"use server";
function* values(state: any, input: string) {
  yield 1;
  state.sql = input;
  yield 2;
}
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  const iterator = values(state, input);
  iterator.next();
  iterator.next();
  return db.query(state.sql);
}
"""

    assert _rule_ids(source) == ["SKY-D281"]


def test_null_while_condition_body_is_unreachable():
    source = b"""\
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  while (null) {
    state.sql = input;
  }
  return db.query(state.sql);
}
"""

    assert _rule_ids(source) == []


def test_negative_numeric_while_has_no_zero_iteration_path():
    source = b"""\
"use server";
export async function find(input: string) {
  const state = { sql: input };
  while (-1) {
    state.sql = "SELECT 1";
    break;
  }
  return db.query(state.sql);
}
"""

    assert _rule_ids(source) == []
