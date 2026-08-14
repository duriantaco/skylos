"""Regression tests for D281 JavaScript state and completion semantics."""

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
const holder: any = { value: "SELECT 1" };
function take() {
  const result = holder.value;
  holder.value = "SELECT 1";
  return result;
}
export async function find(input: string) {
  holder.value = input;
  const state = { sql: take() };
  return db.query(state.sql);
}
""",
        """
"use server";
const holder: any = { value: "SELECT 1" };
function take() {
  const result = holder.value;
  holder.value = "SELECT 1";
  return result;
}
export async function find(input: string) {
  holder.value = input;
  const state = { sql: "SELECT 0" };
  Object.assign(state, { sql: take() });
  return db.query(state.sql);
}
""",
        """
"use server";
const holder: any = { value: "SELECT 1" };
function take() {
  const result = holder.value;
  holder.value = "SELECT 1";
  return result;
}
export async function find(input: string) {
  holder.value = input;
  const state = { sql: "SELECT 0" };
  const merge = Object.assign.bind(Object, state, { sql: take() });
  merge();
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const O = Object;
  const state = { sql: "SELECT 0" };
  O.assign(state, { sql: input });
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const pending = Promise.resolve(input).then(value => value);
  return db.query(await pending);
}
""",
        """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  await Promise.resolve()
    .then(() => { state.sql = input; })
    .then(() => audit());
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  Promise.resolve().then(async () => {
    await audit();
    return db.query(input);
  });
}
""",
        """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  Promise.resolve()
    .then(() => { state.sql = input; })
    .then(() => db.query(state.sql));
}
""",
        """
"use server";
Object.assign = (target: any, source: any) => {
  target.sql = source.audit;
};
export async function find(input: string) {
  const state = { sql: "SELECT 0" };
  Object.assign(state, { audit: input });
  return db.query(state.sql);
}
""",
        """
"use server";
const O = Object;
O.assign = (target: any, source: any) => {
  target.sql = source.audit;
};
export async function find(input: string) {
  const state = { sql: "SELECT 0" };
  Object.assign(state, { audit: input });
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 0" };
  let value = input;
  const descriptor = { value };
  value = "SELECT 1";
  Object.defineProperty(state, "sql", descriptor);
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 0" };
  Object.defineProperty(state, "sql", {
    value: "SELECT 1",
    value: input,
  });
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const patch = {
    get sql() { return input; },
  };
  const state = { ...patch };
  return db.query(state.sql);
}
""",
    ],
    ids=[
        "object-literal-value-evaluated-once",
        "assign-source-value-evaluated-once",
        "bound-assign-source-value-evaluated-once",
        "native-object-root-alias",
        "promise-then-result-flows-through-await",
        "awaited-promise-chain-projects-heap",
        "async-promise-callback-scans-after-await",
        "promise-chain-projects-heap-between-callbacks",
        "module-scope-direct-builtin-override",
        "module-scope-aliased-builtin-override",
        "descriptor-captures-earlier-tainted-value",
        "descriptor-last-value-wins-unsafe",
        "object-spread-invokes-getter",
    ],
)
def test_state_semantics_preserve_unsafe_sql_flow(source: str) -> None:
    assert _rule_ids(source) == ["SKY-D281"]


@pytest.mark.parametrize(
    "source",
    [
        """
"use server";
function choose(input: string) {
  try {
    return input;
  } finally {
    return "SELECT 1";
  }
}
export async function find(input: string) {
  return db.query(choose(input));
}
""",
        """
"use server";
function choose(input: string) {
  try {
    return input;
  } finally {
    { return "SELECT 1"; }
  }
}
export async function find(input: string) {
  return db.query(choose(input));
}
""",
        """
"use server";
function choose(input: string) {
  try {
    return input;
  } finally {
    if (true) return "SELECT 1";
  }
}
export async function find(input: string) {
  return db.query(choose(input));
}
""",
        """
"use server";
function choose(input: string, ok: boolean) {
  try {
    return input;
  } finally {
    if (ok) return "SELECT 1";
    else throw new Error("stopped");
  }
}
export async function find(input: string) {
  return db.query(choose(input, true));
}
""",
        """
"use server";
function choose(input: string) {
  try {
    return input;
  } finally {
    throw new Error("stopped");
  }
}
export async function find(input: string) {
  return db.query(choose(input));
}
""",
        """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 0" };
  let value = "SELECT 1";
  const descriptor = { value };
  value = input;
  Object.defineProperty(state, "sql", descriptor);
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const pending = Promise.resolve(input).then(() => "SELECT 1");
  return db.query(await pending);
}
""",
        """
"use server";
export async function find(input: string) {
  const pending = Promise.resolve("SELECT 1").finally(() => input);
  return db.query(await pending);
}
""",
        """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 0" };
  Object.defineProperty(state, "sql", {
    value: input,
    value: "SELECT 1",
  });
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const patch = { audit: input };
  const state = { sql: "SELECT 1", ...patch };
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  Promise.resolve().then(() => {
    state.sql = input;
  });
  return db.query(state.sql);
}
""",
    ],
    ids=[
        "finally-return-overrides-try-return",
        "nested-finally-return-overrides-try-return",
        "static-finally-return-overrides-try-return",
        "both-finally-branches-are-abrupt",
        "finally-throw-prevents-caller-sink",
        "descriptor-keeps-earlier-safe-value",
        "promise-then-result-replaces-input",
        "promise-finally-preserves-original-result",
        "descriptor-last-value-wins-safe",
        "object-spread-unrelated-property",
        "promise-then-runs-after-current-sink",
    ],
)
def test_state_semantics_preserve_safe_sql_flow(source: str) -> None:
    assert _rule_ids(source) == []
