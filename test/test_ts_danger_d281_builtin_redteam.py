"""Adversarial built-in and heap regressions for TypeScript SKY-D281."""

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
  const state = { sql: "SELECT 1", audit: input };
  Object.defineProperty(state, "sql", { get() { return this.audit; } });
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1", audit: input };
  Object.defineProperty(state, "sql", { get() { return this["audit"]; } });
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1", audit: input };
  Object.defineProperties(state, {
    sql: { get() { return this.audit; } },
  });
  return db.query(state.sql);
}
""",
        """
"use server";
import * as drizzle from "drizzle-orm";
declare function escape(value: unknown): void;
export async function find(input: string) {
  const box = { namespace: drizzle };
  escape(box.namespace);
  return db.execute(drizzle.sql`SELECT ${input}`);
}
""",
        """
"use server";
import * as drizzle from "drizzle-orm";
declare function escape(value: unknown): void;
export async function find(input: string) {
  const box = [drizzle];
  escape(box[0]);
  return db.execute(drizzle.sql`SELECT ${input}`);
}
""",
        """
"use server";
import * as drizzle from "drizzle-orm";
declare function escape(value: unknown): void;
export async function find(input: string) {
  escape(({ namespace: drizzle }).namespace);
  return db.execute(drizzle.sql`SELECT ${input}`);
}
""",
        """
"use server";
import * as drizzle from "drizzle-orm";
declare function escape(value: unknown): void;
export async function find(input: string) {
  const ObjectAlias = Object;
  ObjectAlias.freeze = escape;
  Object.freeze(drizzle);
  return db.execute(drizzle.sql`SELECT ${input}`);
}
""",
        """
"use server";
import * as drizzle from "drizzle-orm";
declare function escape(value: unknown): void;
function hijack() { Object.freeze = escape; }
export async function find(input: string) {
  hijack();
  Object.freeze(drizzle);
  return db.execute(drizzle.sql`SELECT ${input}`);
}
""",
        """
"use server";
import * as drizzle from "drizzle-orm";
declare function escape(value: unknown): boolean;
export async function find(input: string) {
  const ObjectAlias = Object;
  ObjectAlias.isFrozen = escape;
  Object.isFrozen(drizzle);
  return db.execute(drizzle.sql`SELECT ${input}`);
}
""",
        """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  Object.assign = (target: any, source: any) => { target.sql = source.audit; };
  Object.assign(state, { audit: input });
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  const ObjectAlias = Object;
  ObjectAlias.assign = (target: any, source: any) => {
    target.sql = source.audit;
  };
  Object.assign(state, { audit: input });
  return db.query(state.sql);
}
""",
        """
"use server";
function hijack() {
  Object.assign = (target: any, source: any) => { target.sql = source.audit; };
}
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  hijack();
  Object.assign(state, { audit: input });
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  const invoke = Object.assign.call.bind(Object.assign);
  invoke(Object, state, { sql: input });
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  let value = input;
  const merge = Object.assign.bind(Object, state, { sql: value });
  value = "SELECT 2";
  merge();
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const first = { sql: "SELECT 1" };
  let target = first;
  const merge = Object.assign.bind(Object, target);
  target = { sql: "SELECT 2" };
  merge({ sql: input });
  return db.query(first.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  Object.assign(state, { get sql() { return input; } });
  return db.query(state.sql);
}
""",
    ],
    ids=[
        "descriptor-getter-this-dot",
        "descriptor-getter-this-bracket",
        "define-properties-getter-this",
        "namespace-object-member",
        "namespace-array-member",
        "namespace-inline-object-member",
        "freeze-overridden-through-alias",
        "freeze-overridden-in-helper",
        "is-frozen-overridden-through-alias",
        "assign-direct-override",
        "assign-overridden-through-alias",
        "assign-overridden-in-helper",
        "assign-call-alias",
        "bound-source-captures-taint",
        "bound-target-captures-object",
        "assign-source-getter",
    ],
)
def test_unsafe_builtin_indirection_reaches_sql(source: str) -> None:
    assert _rule_ids(source) == ["SKY-D281"]


@pytest.mark.parametrize(
    "source",
    [
        """
"use server";
export async function find(input: string) {
  const state = { sql: input };
  Object.defineProperty(state, "sql", { get: undefined });
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  Object.defineProperty(state, "sql", {
    value: input,
    get() { return "SELECT 1"; },
  });
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  try {
    Object.defineProperty(state, "sql", {
      value: input,
      get() { return "SELECT 1"; },
    });
  } catch {}
  return db.query(state.sql);
}
""",
        """
"use server";
import * as drizzle from "drizzle-orm";
declare function escape(value: unknown): void;
export async function find(input: string) {
  escape(String(drizzle));
  return db.execute(drizzle.sql`SELECT ${input}`);
}
""",
        """
"use server";
import * as drizzle from "drizzle-orm";
declare function escape(value: unknown): void;
export async function find(input: string) {
  escape(typeof drizzle);
  return db.execute(drizzle.sql`SELECT ${input}`);
}
""",
        """
"use server";
import * as drizzle from "drizzle-orm";
declare function escape(value: unknown): void;
export async function find(input: string) {
  escape(`${drizzle}`);
  return db.execute(drizzle.sql`SELECT ${input}`);
}
""",
        """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  let value = "SELECT 2";
  const merge = Object.assign.bind(Object, state, { sql: value });
  value = input;
  merge();
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const first = { sql: "SELECT 1" };
  let target = first;
  const merge = Object.assign.bind(Object, target);
  target = { sql: "SELECT 2" };
  merge({ sql: input });
  return db.query(target.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const frozen = Object.freeze({ sql: "SELECT 1", audit: input });
  return db.query(frozen.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  const patch = { audit: input };
  Object.assign(state, patch);
  return db.query(state.sql);
}
""",
    ],
    ids=[
        "undefined-getter",
        "invalid-mixed-descriptor-unreachable",
        "invalid-mixed-descriptor-caught",
        "namespace-string-call",
        "namespace-typeof",
        "namespace-template-string",
        "bound-source-captures-safe-value",
        "bound-target-does-not-follow-reassignment",
        "freeze-literal-target-property-precision",
        "assign-aliased-source-property-precision",
    ],
)
def test_safe_builtin_indirection_does_not_reach_sql(source: str) -> None:
    assert _rule_ids(source) == []


@pytest.mark.parametrize(
    "source",
    [
        """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  Object.assign(state, {
    audit: input,
    get sql() { return this.audit; },
  });
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  const patch = { sql: "SELECT 2" };
  const merge = Object.assign.bind(Object, state, patch);
  patch.sql = input;
  merge();
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  const first = Object.assign.bind(Object, state);
  const second = first.bind(null, { sql: input });
  second();
  return db.query(state.sql);
}
""",
        """
"use server";
import * as drizzle from "drizzle-orm";
declare function escape(value: unknown): void;
export async function find(input: string) {
  const box = { get namespace() { return drizzle; } };
  escape(box.namespace);
  return db.execute(drizzle.sql`SELECT ${input}`);
}
""",
        """
"use server";
import * as drizzle from "drizzle-orm";
declare function escape(value: unknown): void;
export async function find(input: string) {
  globalThis.Object.freeze = escape;
  Object.freeze(drizzle);
  return db.execute(drizzle.sql`SELECT ${input}`);
}
""",
    ],
    ids=[
        "assign-inline-source-getter-this",
        "bound-source-observes-later-taint",
        "rebind-bound-assign",
        "namespace-getter-projection",
        "freeze-overridden-through-global-this",
    ],
)
def test_additional_unsafe_builtin_semantics_reach_sql(source: str) -> None:
    assert _rule_ids(source) == ["SKY-D281"]


@pytest.mark.parametrize(
    "source",
    [
        """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  const patch = { audit: input };
  Object.assign(state, { ...patch });
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  Object.assign(state, [input]);
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  Object.assign(state, `${input}`);
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  const patch = { sql: input };
  const merge = Object.assign.bind(Object, state, patch);
  patch.sql = "SELECT 2";
  merge();
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  Object.defineProperty(state, "sql", {
    get: async function () { return input; },
  });
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  Object.defineProperty(state, "sql", {
    get: function* () { return input; },
  });
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const state = { sql: input };
  Object.defineProperty(state, "sql", { get: void 0 });
  return db.query(state.sql);
}
""",
        """
"use server";
import * as drizzle from "drizzle-orm";
declare function escape(value: unknown): void;
export async function find(input: string) {
  escape("" + drizzle);
  return db.execute(drizzle.sql`SELECT ${input}`);
}
""",
        """
"use server";
import * as drizzle from "drizzle-orm";
declare function escape(value: unknown): void;
export async function find(input: string) {
  escape(!!drizzle);
  return db.execute(drizzle.sql`SELECT ${input}`);
}
""",
        """
"use server";
import * as drizzle from "drizzle-orm";
declare function escape(value: unknown): void;
export async function find(input: string) {
  escape(JSON.stringify(drizzle));
  return db.execute(drizzle.sql`SELECT ${input}`);
}
""",
        """
"use server";
export async function find(input: string) {
  const state = Object.freeze({ sql: "SELECT 1" });
  state.sql = input;
  return db.query(state.sql);
}
""",
        """
"use server";
export async function find(input: string) {
  const state = Object.freeze({ sql: "SELECT 1" });
  Object.assign(state, { sql: input });
  return db.query(state.sql);
}
""",
    ],
    ids=[
        "assign-known-spread-source",
        "assign-array-source",
        "assign-runtime-string-source",
        "bound-source-observes-later-sanitization",
        "async-descriptor-getter-returns-promise",
        "generator-descriptor-getter-returns-iterator",
        "void-undefined-descriptor-getter",
        "namespace-string-concatenation",
        "namespace-boolean-coercion",
        "namespace-json-stringify",
        "write-to-frozen-target-is-unreachable",
        "assign-to-frozen-target-is-unreachable",
    ],
)
def test_additional_safe_builtin_semantics_do_not_reach_sql(source: str) -> None:
    assert _rule_ids(source) == []
