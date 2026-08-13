"""Adversarial callable-indirection coverage for Server Action SQL taint."""

from __future__ import annotations

import pytest

from skylos.visitors.languages.typescript.danger import (
    _check_nextjs_server_action_sqli,
)


def _rule_ids(source: bytes) -> list[str]:
    findings: list[dict] = []
    _check_nextjs_server_action_sqli(
        source,
        "/project/app/actions.ts",
        findings,
    )
    return [finding["rule_id"] for finding in findings]


@pytest.mark.parametrize(
    "source",
    [
        b"""\
"use server";
const repository = {
    lookup(value: string) {
        return db.query("SELECT * FROM users WHERE name = '" + value + "'");
    },
};
export async function find(input: string) {
    return repository.lookup(input);
}
""",
        b"""\
"use server";
class UserRepository {
    lookup(value: string) {
        return db.query("SELECT * FROM users WHERE name = '" + value + "'");
    }
}
const repository = new UserRepository();
export async function find(input: string) {
    return repository.lookup(input);
}
""",
        b"""\
"use server";
function lookup(value: string) {
    return db.query("SELECT * FROM users WHERE name = '" + value + "'");
}
export async function find(inputs: string[]) {
    return inputs.map(lookup);
}
""",
        b"""\
"use server";
function lookup(value: string) {
    return db.query("SELECT * FROM users WHERE name = '" + value + "'");
}
const run = lookup;
export async function find(input: string) {
    return run(input);
}
""",
        b"""\
"use server";
function buildQuery(value: string) {
    return "SELECT * FROM users WHERE name = '" + value + "'";
}
export async function find(input: string) {
    return db.query(buildQuery(input));
}
""",
        b"""\
"use server";
export async function find(input: string) {
    return ((value: string) =>
        db.query("SELECT * FROM users WHERE name = '" + value + "'"))(input);
}
""",
        b"""\
"use server";
function lookup(value: string) {
    return db.query("SELECT * FROM users WHERE name = '" + value + "'");
}
export async function find(input: string) {
    return lookup.call(null, input);
}
""",
        b"""\
"use server";
function lookup(value: string) {
    return db.query("SELECT * FROM users WHERE name = '" + value + "'");
}
export async function find(input: string) {
    return lookup.apply(null, [input]);
}
""",
    ],
    ids=[
        "object-method",
        "class-method",
        "named-callback",
        "callable-alias",
        "sql-returning-helper",
        "iife",
        "function-call",
        "function-apply",
    ],
)
def test_action_input_reaches_sql_through_callable_indirection(source: bytes):
    assert _rule_ids(source) == ["SKY-D281"]


@pytest.mark.parametrize(
    "source",
    [
        b"""\
"use server";
const repository = {
    lookup(value: string) {
        return db.query("SELECT * FROM users WHERE name = '" + value + "'");
    },
};
export async function find() {
    return repository.lookup("maintainer");
}
""",
        b"""\
"use server";
function lookup(value: string) {
    return db.query("SELECT * FROM users WHERE name = '" + value + "'");
}
export async function find() {
    return ["maintainer"].map(lookup);
}
""",
        b"""\
"use server";
function buildQuery(value: string) {
    return "SELECT * FROM users WHERE name = '" + value + "'";
}
export async function find() {
    return db.query(buildQuery("maintainer"));
}
""",
    ],
    ids=["constant-object-call", "constant-callback", "constant-query-helper"],
)
def test_trusted_values_through_callable_indirection_are_clean(source: bytes):
    assert _rule_ids(source) == []


def test_named_then_callback_receives_tainted_resolution():
    source = b"""\
"use server";
function lookup(value: string) {
    return db.query("SELECT * FROM users WHERE name = '" + value + "'");
}
export async function find(input: string) {
    return Promise.resolve(input).then(lookup);
}
"""

    assert _rule_ids(source) == ["SKY-D281"]


def test_locally_reassigned_callable_is_resolved():
    source = b"""\
"use server";
function lookup(value: string) {
    return db.query("SELECT * FROM users WHERE name = '" + value + "'");
}
function trusted(_value: string) {
    return "maintainer";
}
export async function find(input: string) {
    let run = trusted;
    run = lookup;
    return run(input);
}
"""

    assert _rule_ids(source) == ["SKY-D281"]


def test_collection_callback_index_is_not_tainted():
    source = b"""\
"use server";
export async function find(inputs: string[]) {
    return inputs.map((_value, index) =>
        db.query(`SELECT * FROM users LIMIT ${index}`)
    );
}
"""

    assert _rule_ids(source) == []


def test_collection_this_arg_is_not_invoked_as_callback():
    source = b"""\
"use server";
function trusted(value: string) {
    return value.length;
}
function callbackContext(value: string) {
    return db.query("SELECT * FROM users WHERE name = '" + value + "'");
}
export async function find(inputs: string[]) {
    return inputs.map(trusted, callbackContext);
}
"""

    assert _rule_ids(source) == []


def test_promise_rejection_callback_does_not_receive_resolved_value():
    source = b"""\
"use server";
function onRejected(error: Error) {
    return db.query("SELECT * FROM errors WHERE message = '" + error.message + "'");
}
export async function find(input: string) {
    return Promise.resolve(input).then(undefined, onRejected);
}
"""

    assert _rule_ids(source) == []


@pytest.mark.parametrize(
    "source",
    [
        b"""\
"use server";
export async function find(input: string) {
    return db.query({
        text: "SELECT * FROM users WHERE name = $1",
        values: [input],
    });
}
""",
        b"""\
"use server";
function build(text: string, value: string) {
    return { text, values: [value] };
}
export async function find(input: string) {
    return db.query(build("SELECT * FROM users WHERE name = $1", input));
}
""",
    ],
    ids=["direct-config", "helper-config"],
)
def test_parameterized_query_config_is_clean(source: bytes):
    assert _rule_ids(source) == []


@pytest.mark.parametrize(
    "source",
    [
        b"""\
"use server";
export async function find(input: string) {
    return db.query({ text: input, values: [] });
}
""",
        b"""\
"use server";
function build(text: string, value: string) {
    return { text, values: [value] };
}
export async function find(input: string) {
    return db.query(build(input, input));
}
""",
    ],
    ids=["direct-tainted-text", "helper-tainted-text"],
)
def test_query_config_with_tainted_text_is_flagged(source: bytes):
    assert _rule_ids(source) == ["SKY-D281"]


def test_database_import_overrides_misleading_receiver_name():
    source = b"""\
"use server";
import { Client } from "pg";
const auditLogger = new Client();
export async function find(input: string) {
    return auditLogger.query(`SELECT * FROM users WHERE id = ${input}`);
}
"""

    assert _rule_ids(source) == ["SKY-D281"]
