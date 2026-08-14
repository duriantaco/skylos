"""Regression tests for D281 Promise timing and settlement semantics."""

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
  let sql = "SELECT 1";
  const pending = Promise.resolve().then(() => sql);
  sql = input;
  return db.query(await pending);
}
""",
        """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  const pending = Promise.resolve().then(() => db.query(state.sql));
  state.sql = input;
  await pending;
}
""",
        """
"use server";
async function taint(state: any, input: string) {
  await Promise.resolve();
  state.sql = input;
}
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  await taint(state, input);
  return db.query(state.sql);
}
""",
        """
"use server";
async function taint(state: any, input: string) {
  await Promise.resolve();
  state.sql = input;
}
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  const pending = taint(state, input);
  await pending;
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  let value = "SELECT 1";
  const pending = Promise.resolve()
    .then(() => value)
    .then(sql => db.query(sql));
  value = input;
  await pending;
}
""",
        """
"use server";
export async function find(input: string) {
  let value = "SELECT 1";
  value = input;
  await Promise.resolve().then(() => db.query(value));
}
""",
        """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  Promise.resolve().then(() => { state.sql = input; });
  await Promise.resolve();
  return db.query(state.sql);
}
""",
    ],
    ids=[
        "callback-reads-later-tainted-binding",
        "callback-sink-reads-later-tainted-heap",
        "directly-awaited-helper-resumes-after-await",
        "stored-awaited-helper-resumes-after-await",
        "promise-chain-reads-later-tainted-binding",
        "direct-awaited-callback-reads-current-binding",
        "queued-reaction-runs-before-await-continuation",
    ],
)
def test_promise_temporal_semantics_preserve_unsafe_sql_flow(source: str) -> None:
    assert _rule_ids(source) == ["SKY-D281"]


@pytest.mark.parametrize(
    "source",
    [
        """
"use server";
export async function find(input: string) {
  let sql = input;
  const pending = Promise.resolve().then(() => sql);
  sql = "SELECT 1";
  return db.query(await pending);
}
""",
        """
"use server";
export async function find(input: string) {
  const state = { sql: input };
  const pending = Promise.resolve().then(() => db.query(state.sql));
  state.sql = "SELECT 1";
  await pending;
}
""",
        """
"use server";
async function clean(state: any) {
  await Promise.resolve();
  state.sql = "SELECT 1";
}
export async function find(input: string) {
  const state = { sql: input };
  await clean(state);
  return db.query(state.sql);
}
""",
        """
"use server";
async function clean(state: any) {
  await Promise.resolve();
  state.sql = "SELECT 1";
}
export async function find(input: string) {
  const state = { sql: input };
  const pending = clean(state);
  await pending;
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  let value = input;
  const pending = Promise.resolve()
    .then(() => value)
    .then(sql => db.query(sql));
  value = "SELECT 1";
  await pending;
}
""",
        """
"use server";
export async function find(input: string) {
  const state = { sql: input };
  Promise.resolve().then(() => { state.sql = "SELECT 1"; });
  await Promise.resolve();
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  await Promise.resolve().then(() => { throw new Error("stop"); });
  return db.query(input);
}
""",
        """
"use server";
export async function find(input: string) {
  await Promise.resolve().then(async () => {
    await audit();
    throw new Error("stop");
  });
  return db.query(input);
}
""",
        """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  await Promise.resolve().then(undefined, () => { state.sql = input; });
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  await Promise.resolve().catch(() => { state.sql = input; });
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const pending = Promise.reject(input).catch(() => "SELECT 1");
  return db.query(await pending);
}
""",
        """
"use server";
export async function find(input: string) {
  const pending = Promise.resolve(input).then(value => value);
  return db.query(pending);
}
""",
    ],
    ids=[
        "callback-reads-later-safe-binding",
        "callback-sink-reads-later-safe-heap",
        "directly-awaited-helper-sanitizes-after-await",
        "stored-awaited-helper-sanitizes-after-await",
        "promise-chain-reads-later-safe-binding",
        "queued-sanitizer-runs-before-await-continuation",
        "awaited-then-throw-stops-continuation",
        "awaited-async-then-throw-stops-continuation",
        "resolved-promise-skips-rejection-handler",
        "resolved-promise-skips-catch-handler",
        "rejected-promise-catch-replaces-reason",
        "promise-object-is-not-resolved-sql-value",
    ],
)
def test_promise_temporal_semantics_preserve_safe_sql_flow(source: str) -> None:
    assert _rule_ids(source) == []


@pytest.mark.parametrize(
    ("first_write", "second_write", "await_count", "expected"),
    [
        ("input", '"SELECT 1"', 1, ["SKY-D281"]),
        ('"SELECT 1"', "input", 1, []),
        ("input", '"SELECT 1"', 2, []),
        ('"SELECT 1"', "input", 2, ["SKY-D281"]),
    ],
    ids=[
        "one-checkpoint-sees-first-taint",
        "one-checkpoint-sees-first-sanitizer",
        "two-checkpoints-see-second-sanitizer",
        "two-checkpoints-see-second-taint",
    ],
)
def test_promise_microtask_checkpoint_stops_at_await_continuation(
    first_write: str,
    second_write: str,
    await_count: int,
    expected: list[str],
) -> None:
    awaits = "\n".join("  await Promise.resolve();" for _ in range(await_count))
    source = f"""
"use server";
export async function find(input: string) {{
  const state = {{ sql: "SELECT 0" }};
  Promise.resolve()
    .then(() => {{ state.sql = {first_write}; }})
    .then(() => {{ state.sql = {second_write}; }});
{awaits}
  return db.query(state.sql);
}}
"""
    assert _rule_ids(source) == expected


@pytest.mark.parametrize(
    "mutation",
    [
        "Promise.prototype.then = function () { return Promise.resolve(input); };",
        'Promise.prototype["then"] = function () { return Promise.resolve(input); };',
        'Object.defineProperty(Promise.prototype, "then", { value() { return Promise.resolve(input); } });',
        "Object.assign(Promise.prototype, { then() { return Promise.resolve(input); } });",
        "delete Promise.prototype.then;",
    ],
    ids=[
        "prototype-direct-write",
        "prototype-computed-write",
        "prototype-descriptor-write",
        "prototype-assign-write",
        "prototype-delete",
    ],
)
def test_mutated_promise_reaction_never_receives_native_safe_proof(
    mutation: str,
) -> None:
    source = f"""
"use server";
export async function find(input: string) {{
  {mutation}
  const pending = Promise.resolve("SELECT 1").then(() => "SELECT 1");
  return db.query(await pending);
}}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_per_instance_then_override_never_receives_native_safe_proof() -> None:
    source = """
"use server";
export async function find(input: string) {
  const pending: any = Promise.resolve("SELECT 1");
  pending.then = function () { return Promise.resolve(input); };
  const result = pending.then(() => "SELECT 1");
  return db.query(await result);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]
