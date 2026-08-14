"""Adversarial descriptor/property lifecycle regressions for SKY-D281."""

from __future__ import annotations

from skylos.visitors.languages.typescript.danger import (
    _check_nextjs_server_action_sqli,
)


FILE_PATH = "/project/app/actions.ts"


def _rule_ids(source: str) -> list[str]:
    findings: list[dict] = []
    _check_nextjs_server_action_sqli(source.encode(), FILE_PATH, findings)
    return [finding["rule_id"] for finding in findings]


def test_frozen_same_value_redefinition_keeps_later_sink_reachable() -> None:
    source = """
"use server";
export async function find(input: string) {
  const state = Object.freeze({ sql: "SELECT 1" });
  Object.defineProperty(state, "sql", { value: "SELECT 1" });
  return db.query(input);
}
"""
    # Redefining an identical value on a frozen data property succeeds.
    assert _rule_ids(source) == ["SKY-D281"]


def test_frozen_same_value_redefinition_preserves_safe_value() -> None:
    source = """
"use server";
export async function find(input: string) {
  const state = Object.freeze({ sql: "SELECT 1" });
  Object.defineProperty(state, "sql", { value: "SELECT 1" });
  return db.query(state.sql);
}
"""
    assert _rule_ids(source) == []


def test_unknown_configurable_delete_keeps_failure_path_during_copy() -> None:
    source = """
"use server";
export async function find(input: string, flag: boolean) {
  const source: any = { sql: input };
  Object.defineProperty(source, "sql", { configurable: flag });
  try { delete source.sql; } catch {}
  const target = { sql: "SELECT 1" };
  Object.assign(target, source);
  return db.query(target.sql);
}
"""
    # flag=false rejects deletion, leaving an enumerable tainted property.
    assert _rule_ids(source) == ["SKY-D281"]


def test_unknown_configurable_delete_without_catch_cannot_reach_sink_tainted() -> None:
    source = """
"use server";
export async function find(input: string, flag: boolean) {
  const source: any = { sql: input };
  Object.defineProperty(source, "sql", { configurable: flag });
  delete source.sql;
  const target = { sql: "SELECT 1" };
  Object.assign(target, source);
  return db.query(target.sql);
}
"""
    # flag=false throws before the sink; flag=true removes the tainted property.
    assert _rule_ids(source) == []


def test_configurable_delete_removes_property_before_copy() -> None:
    source = """
"use server";
export async function find(input: string) {
  const source: any = { sql: input };
  Object.defineProperty(source, "sql", { configurable: true });
  delete source.sql;
  const target = { sql: "SELECT 1" };
  Object.assign(target, source);
  return db.query(target.sql);
}
"""
    assert _rule_ids(source) == []


def test_nonconfigurable_delete_preserves_property_during_copy() -> None:
    source = """
"use server";
export async function find(input: string) {
  const source: any = { sql: input };
  Object.defineProperty(source, "sql", { configurable: false });
  try { delete source.sql; } catch {}
  const target = { sql: "SELECT 1" };
  Object.assign(target, source);
  return db.query(target.sql);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_nonconfigurable_tainted_getter_rejects_safe_redefinition() -> None:
    source = """
"use server";
export async function find(input: string) {
  const state: any = {};
  Object.defineProperty(state, "sql", {
    get() { return input; },
    configurable: false,
  });
  try {
    Object.defineProperty(state, "sql", {
      get() { return "SELECT 1"; },
    });
  } catch {}
  return db.query(state.sql);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_nonconfigurable_safe_getter_rejects_tainted_redefinition() -> None:
    source = """
"use server";
export async function find(input: string) {
  const state: any = {};
  Object.defineProperty(state, "sql", {
    get() { return "SELECT 1"; },
    configurable: false,
  });
  try {
    Object.defineProperty(state, "sql", {
      get() { return input; },
    });
  } catch {}
  return db.query(state.sql);
}
"""
    assert _rule_ids(source) == []


def test_deleted_configurable_property_is_absent_on_direct_read() -> None:
    source = """
"use server";
export async function find(input: string) {
  const state: any = { sql: input };
  delete state.sql;
  return db.query(state.sql);
}
"""
    assert _rule_ids(source) == []


def test_deleted_own_property_reads_tainted_prototype_value() -> None:
    source = """
"use server";
export async function find(input: string) {
  const state: any = { sql: "SELECT 1" };
  Object.setPrototypeOf(state, { sql: input });
  delete state.sql;
  return db.query(state.sql);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_failed_nonconfigurable_delete_preserves_direct_read() -> None:
    source = """
"use server";
export async function find(input: string) {
  const state: any = {};
  Object.defineProperty(state, "sql", {
    value: input,
    configurable: false,
  });
  try { delete state.sql; } catch {}
  return db.query(state.sql);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_object_assign_keeps_successful_write_before_later_failure() -> None:
    source = """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1", locked: 0 };
  Object.defineProperty(state, "locked", { writable: false });
  try {
    Object.assign(state, { sql: input, locked: 1 });
  } catch {}
  return db.query(state.sql);
}
"""
    # Object.assign is not atomic: sql is written before locked throws.
    assert _rule_ids(source) == ["SKY-D281"]


def test_object_assign_keeps_sanitizer_before_later_failure() -> None:
    source = """
"use server";
export async function find(input: string) {
  const state = { sql: input, locked: 0 };
  Object.defineProperty(state, "locked", { writable: false });
  try {
    Object.assign(state, { sql: "SELECT 1", locked: 1 });
  } catch {}
  return db.query(state.sql);
}
"""
    assert _rule_ids(source) == []


def test_frozen_uncertain_property_keeps_same_value_success_path() -> None:
    source = """
"use server";
export async function find(input: string, flag: boolean) {
  const state: any = { sql: "SELECT 1" };
  if (flag) delete state.sql;
  Object.freeze(state);
  Object.defineProperty(state, "sql", { value: "SELECT 1" });
  return db.query(input);
}
"""
    # flag=false permits a SameValue redefinition and reaches the sink.
    assert _rule_ids(source) == ["SKY-D281"]
