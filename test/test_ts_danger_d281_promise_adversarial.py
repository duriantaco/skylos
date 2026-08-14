"""Adversarial JavaScript Promise semantics for SKY-D281."""

from skylos.visitors.languages.typescript.danger import (
    _check_nextjs_server_action_sqli,
)


FILE_PATH = "/project/app/actions.ts"


def _rule_ids(source: str) -> list[str]:
    findings: list[dict] = []
    _check_nextjs_server_action_sqli(source.encode(), FILE_PATH, findings)
    return [finding["rule_id"] for finding in findings]


def test_mutually_exclusive_promise_jobs_do_not_sanitize_tainted_branch() -> None:
    source = """
"use server";
export async function find(input: string, flag: boolean) {
  const state = { sql: "SELECT 0" };
  if (flag) Promise.resolve().then(() => { state.sql = input; });
  else Promise.resolve().then(() => { state.sql = "SELECT 1"; });
  await Promise.resolve();
  return db.query(state.sql);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_mutually_exclusive_jobs_are_not_source_order_dependent() -> None:
    source = """
"use server";
export async function find(input: string, flag: boolean) {
  const state = { sql: "SELECT 0" };
  if (flag) Promise.resolve().then(() => { state.sql = "SELECT 1"; });
  else Promise.resolve().then(() => { state.sql = input; });
  await Promise.resolve();
  return db.query(state.sql);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_job_from_terminated_branch_does_not_reach_other_branch() -> None:
    source = """
"use server";
export async function find(input: string, flag: boolean) {
  const state = { sql: "SELECT 1" };
  if (flag) {
    Promise.resolve().then(() => { state.sql = input; });
    return;
  }
  await Promise.resolve();
  return db.query(state.sql);
}
"""
    assert _rule_ids(source) == []


def test_queued_sink_on_returned_branch_still_runs() -> None:
    source = """
"use server";
export async function find(input: string, flag: boolean) {
  if (flag) {
    Promise.resolve().then(() => db.query(input));
    return;
  }
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_branch_callback_observes_post_join_taint_write() -> None:
    source = """
"use server";
export async function find(input: string, flag: boolean) {
  const state = { sql: "SELECT 1" };
  if (flag) Promise.resolve().then(() => db.query(state.sql));
  else Promise.resolve().then(() => db.query(state.sql));
  state.sql = input;
  await Promise.resolve();
}
"""
    assert _rule_ids(source) == ["SKY-D281", "SKY-D281"]


def test_branch_callback_observes_post_join_sanitizer_write() -> None:
    source = """
"use server";
export async function find(input: string, flag: boolean) {
  const state = { sql: input };
  if (flag) Promise.resolve().then(() => db.query(state.sql));
  else Promise.resolve().then(() => db.query(state.sql));
  state.sql = "SELECT 1";
  await Promise.resolve();
}
"""
    assert _rule_ids(source) == []


def test_conditional_expression_jobs_preserve_unsafe_branch() -> None:
    source = """
"use server";
export async function find(input: string, flag: boolean) {
  const state = { sql: "SELECT 0" };
  flag
    ? Promise.resolve().then(() => { state.sql = input; })
    : Promise.resolve().then(() => { state.sql = "SELECT 1"; });
  await Promise.resolve();
  return db.query(state.sql);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_nested_branch_jobs_preserve_unsafe_path() -> None:
    source = """
"use server";
export async function find(input: string, first: boolean, second: boolean) {
  const state = { sql: "SELECT 0" };
  if (first) {
    if (second) Promise.resolve().then(() => { state.sql = input; });
    else Promise.resolve().then(() => { state.sql = "SELECT 1"; });
  } else {
    Promise.resolve().then(() => { state.sql = "SELECT 2"; });
  }
  await Promise.resolve();
  return db.query(state.sql);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_switch_jobs_preserve_unsafe_case() -> None:
    source = """
"use server";
export async function find(input: string, choice: number) {
  const state = { sql: "SELECT 0" };
  switch (choice) {
    case 0:
      Promise.resolve().then(() => { state.sql = input; });
      break;
    default:
      Promise.resolve().then(() => { state.sql = "SELECT 1"; });
  }
  await Promise.resolve();
  return db.query(state.sql);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_unawaited_reaction_keeps_action_lexical_binding_alive() -> None:
    source = """
"use server";
export async function find(input: string) {
  let sql = input;
  Promise.resolve().then(() => db.query(sql));
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_unawaited_reaction_keeps_shadowed_block_binding() -> None:
    source = """
"use server";
export async function find(sql: string) {
  {
    let sql = "SELECT 1";
    Promise.resolve().then(() => db.query(sql));
  }
}
"""
    assert _rule_ids(source) == []


def test_reaction_projects_scalar_taint_write() -> None:
    source = """
"use server";
export async function find(input: string) {
  let sql = "SELECT 1";
  Promise.resolve().then(() => { sql = input; });
  await Promise.resolve();
  return db.query(sql);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_reaction_projects_scalar_sanitizer_write() -> None:
    source = """
"use server";
export async function find(input: string) {
  let sql = input;
  Promise.resolve().then(() => { sql = "SELECT 1"; });
  await Promise.resolve();
  return db.query(sql);
}
"""
    assert _rule_ids(source) == []


def test_named_handler_uses_definition_scope_not_registration_scope() -> None:
    source = """
"use server";
export async function find(sql: string) {
  function handler() { return db.query(sql); }
  {
    let sql = "SELECT 1";
    Promise.resolve().then(handler);
  }
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_named_handler_does_not_capture_registration_shadow() -> None:
    source = """
"use server";
export async function find(input: string) {
  let sql = "SELECT 1";
  function handler() { return db.query(sql); }
  {
    let sql = input;
    Promise.resolve().then(handler);
  }
}
"""
    assert _rule_ids(source) == []


def test_reaction_adopts_fulfilled_promise_return_value() -> None:
    source = """
"use server";
export async function find(input: string) {
  const pending = Promise.resolve().then(() => Promise.resolve(input));
  return db.query(await pending);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_reaction_adopts_rejected_promise_and_stops_await_continuation() -> None:
    source = """
"use server";
export async function find(input: string) {
  await Promise.resolve().then(() => Promise.reject("stop"));
  return db.query(input);
}
"""
    assert _rule_ids(source) == []


def test_async_return_adopts_fulfilled_promise_value() -> None:
    source = """
"use server";
async function pass(value: string) { return Promise.resolve(value); }
export async function find(input: string) {
  return db.query(await pass(input));
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_async_return_adopts_rejected_promise_and_stops_continuation() -> None:
    source = """
"use server";
async function fail() { return Promise.reject("stop"); }
export async function find(input: string) {
  await fail();
  return db.query(input);
}
"""
    assert _rule_ids(source) == []


def test_reaction_adopts_pending_fulfilled_promise() -> None:
    source = """
"use server";
export async function find(input: string) {
  const inner = Promise.resolve(input).then(value => value);
  const outer = Promise.resolve().then(() => inner);
  return db.query(await outer);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_reaction_adopts_pending_rejection() -> None:
    source = """
"use server";
export async function find(input: string) {
  const inner = Promise.resolve().then(() => Promise.reject("stop"));
  await Promise.resolve().then(() => inner);
  return db.query(input);
}
"""
    assert _rule_ids(source) == []


def test_reaction_self_adoption_rejects() -> None:
    source = """
"use server";
export async function find(input: string) {
  let pending: Promise<unknown>;
  pending = Promise.resolve().then(() => pending);
  await pending;
  return db.query(input);
}
"""
    assert _rule_ids(source) == []


def test_finally_adopts_fulfillment_but_preserves_original_value() -> None:
    source = """
"use server";
export async function find(input: string) {
  const pending = Promise.resolve(input).finally(() => Promise.resolve("safe"));
  return db.query(await pending);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_finally_adopts_rejection_and_stops_continuation() -> None:
    source = """
"use server";
export async function find(input: string) {
  await Promise.resolve("safe").finally(() => Promise.reject("stop"));
  return db.query(input);
}
"""
    assert _rule_ids(source) == []


def test_async_continuation_preserves_heap_write_before_rejection() -> None:
    source = """
"use server";
async function fail(state: { sql: string }, input: string) {
  await Promise.resolve();
  state.sql = input;
  throw "stop";
}
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  await fail(state, input).catch(() => {});
  return db.query(state.sql);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_thrown_taint_becomes_rejection_reason() -> None:
    source = """
"use server";
export async function find(input: string) {
  const pending = Promise.resolve().then(() => { throw input; }).catch(reason => reason);
  return db.query(await pending);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_catch_callback_receives_tainted_rejection_reason() -> None:
    source = """
"use server";
export async function find(input: string) {
  await Promise.resolve().then(() => { throw input; }).catch(reason => db.query(reason));
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_heap_write_before_throw_survives_caught_rejection() -> None:
    source = """
"use server";
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  const pending = Promise.resolve().then(() => {
    state.sql = input;
    throw "stop";
  }).catch(() => {});
  await pending;
  return db.query(state.sql);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_safe_rejection_reason_does_not_inherit_visible_taint() -> None:
    source = """
"use server";
export async function find(input: string) {
  await Promise.reject("SELECT 1").catch(reason => db.query(reason));
}
"""
    assert _rule_ids(source) == []


def test_rejected_await_resumption_keeps_fifo_checkpoint_order() -> None:
    source = """
"use server";
async function fail() { await Promise.reject("stop"); }
export async function find(input: string) {
  const state = { sql: "SELECT 1" };
  const pending = fail();
  Promise.resolve().then(() => { state.sql = input; });
  pending.catch(() => { state.sql = "SELECT 1"; });
  await Promise.resolve();
  return db.query(state.sql);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_rejected_await_resumption_does_not_run_catch_before_checkpoint() -> None:
    source = """
"use server";
async function fail() { await Promise.reject("stop"); }
export async function find(input: string) {
  const state = { sql: input };
  const pending = fail();
  Promise.resolve().then(() => { state.sql = "SELECT 1"; });
  pending.catch(() => { state.sql = input; });
  await Promise.resolve();
  return db.query(state.sql);
}
"""
    assert _rule_ids(source) == []


def test_bound_callback_cannot_fail_open() -> None:
    source = """
"use server";
export async function find(input: string) {
  const callback = (() => input).bind(null);
  const pending = Promise.resolve("safe").then(callback);
  return db.query(await pending);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_callback_factory_cannot_fail_open() -> None:
    source = """
"use server";
function make(value: string) { return () => value; }
export async function find(input: string) {
  const pending = Promise.resolve("safe").then(make(input));
  return db.query(await pending);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_conditional_callback_cannot_fail_open() -> None:
    source = """
"use server";
export async function find(input: string, flag: boolean) {
  const callback = flag ? () => input : () => "safe";
  const pending = Promise.resolve("safe").then(callback);
  return db.query(await pending);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_cast_global_promise_replacement_invalidates_native_proof() -> None:
    source = """
"use server";
export async function find(input: string) {
  (globalThis as any).Promise = {
    resolve() { return { then() { return input; } }; },
  };
  const pending = Promise.resolve("safe").then(() => "safe");
  return db.query(await pending);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_prototype_alias_mutation_invalidates_native_proof() -> None:
    source = """
"use server";
export async function find(input: string) {
  const proto = Object.getPrototypeOf(Promise.resolve());
  proto.then = () => input;
  const pending = Promise.resolve("safe").then(() => "safe");
  return db.query(await pending);
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_instance_alias_mutation_invalidates_native_proof() -> None:
    source = """
"use server";
export async function find(input: string) {
  const pending = Promise.resolve("safe");
  const alias = ({ pending }).pending;
  alias.then = () => input;
  return db.query(await pending.then(() => "safe"));
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_array_alias_mutation_invalidates_native_proof() -> None:
    source = """
"use server";
export async function find(input: string) {
  const pending = Promise.resolve("safe");
  const alias = [pending][0];
  alias.then = () => input;
  return db.query(await pending.then(() => "safe"));
}
"""
    assert _rule_ids(source) == ["SKY-D281"]


def test_reflect_get_alias_mutation_invalidates_native_proof() -> None:
    source = """
"use server";
export async function find(input: string) {
  const pending = Promise.resolve("safe");
  const alias = Reflect.get({ pending }, "pending");
  alias.then = () => input;
  return db.query(await pending.then(() => "safe"));
}
"""
    assert _rule_ids(source) == ["SKY-D281"]
