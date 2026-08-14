"""Final adversarial regressions for the TypeScript D281 proof engine."""

from __future__ import annotations

import pytest

from skylos.visitors.languages.typescript.danger import (
    _check_nextjs_server_action_sqli,
)


FILE_PATH = "/project/app/actions.ts"


def _rule_ids(source: bytes) -> list[str]:
    findings: list[dict] = []
    _check_nextjs_server_action_sqli(source, FILE_PATH, findings)
    return [finding["rule_id"] for finding in findings]


@pytest.mark.parametrize(
    "loop",
    [
        """
        for (const item of items) {
            state.sql = input;
            if (stop) break;
            state.sql = "SELECT 1";
        }
        """,
        """
        for (const item of items) {
            state.sql = input;
            if (stop) continue;
            state.sql = "SELECT 1";
            break;
        }
        """,
        """
        do {
            state.sql = input;
            if (stop) break;
            state.sql = "SELECT 1";
        } while (false);
        """,
    ],
    ids=["conditional-break", "conditional-continue", "do-while-break"],
)
def test_abrupt_loop_exit_preserves_tainted_path(loop: str):
    source = (
        '"use server";\n'
        "export async function find(\n"
        "    input: string, items: string[], stop: boolean,\n"
        ") {\n"
        '    const state = { sql: "SELECT 0" };\n'
        f"    {loop}\n"
        "    return db.query(state.sql);\n"
        "}\n"
    ).encode()

    assert _rule_ids(source) == ["SKY-D281"]


def test_do_while_definite_first_iteration_can_sanitize_taint():
    source = b"""\
"use server";
export async function find(input: string) {
    const state = { sql: input };
    do {
        state.sql = "SELECT 1";
    } while (false);
    return db.query(state.sql);
}
"""

    assert _rule_ids(source) == []


def test_zero_iteration_for_loop_does_not_run_sanitizing_increment():
    source = b"""\
"use server";
export async function find(input: string, enabled: boolean) {
    const state = { sql: input };
    for (; enabled; state.sql = "SELECT 1") {
        audit();
    }
    return db.query(state.sql);
}
"""

    assert _rule_ids(source) == ["SKY-D281"]


def test_switch_case_test_side_effect_can_taint_sql():
    source = b"""\
"use server";
export async function find(input: string, mode: string) {
    const state = { sql: "SELECT 0" };
    switch (mode) {
        case (state.sql = input, "match"):
            break;
        default:
            break;
    }
    return db.query(state.sql);
}
"""

    assert _rule_ids(source) == ["SKY-D281"]


def test_switch_case_test_side_effect_can_sanitize_sql():
    source = b"""\
"use server";
export async function find(input: string, mode: string) {
    const state = { sql: input };
    switch (mode) {
        case (state.sql = "SELECT 1", "match"):
            break;
        default:
            break;
    }
    return db.query(state.sql);
}
"""

    assert _rule_ids(source) == []


def test_labeled_break_runs_finally_with_tainted_state():
    source = b"""\
"use server";
export async function find(input: string) {
    const state = { sql: "SELECT 0" };
    outer: {
        try {
            state.sql = input;
            break outer;
        } finally {
            db.query(state.sql);
        }
    }
}
"""

    assert _rule_ids(source) == ["SKY-D281"]


def test_finally_sanitizer_applies_before_labeled_break_completes():
    source = b"""\
"use server";
export async function find(input: string) {
    const state = { sql: input };
    outer: {
        try {
            break outer;
        } finally {
            state.sql = "SELECT 1";
        }
    }
    return db.query(state.sql);
}
"""

    assert _rule_ids(source) == []


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (
            """
            state.sql = input;
            break outer;
            state.sql = "SELECT 1";
            """,
            ["SKY-D281"],
        ),
        (
            """
            state.sql = "SELECT 1";
            break outer;
            state.sql = input;
            """,
            [],
        ),
    ],
    ids=["tainted-exit", "sanitized-exit"],
)
def test_labeled_break_preserves_only_reachable_state(
    body: str,
    expected: list[str],
):
    source = (
        '"use server";\n'
        "export async function find(input: string) {\n"
        '    const state = { sql: "SELECT 0" };\n'
        "    outer: {\n"
        f"        {body}\n"
        "    }\n"
        "    return db.query(state.sql);\n"
        "}\n"
    ).encode()

    assert _rule_ids(source) == expected


@pytest.mark.parametrize(
    "expression",
    [
        "(state.sql = input, registry).service.run()",
        "new ((state.sql = input, registry).Service)()",
        "(state.sql = input, registry).service.value = 1",
    ],
    ids=["call-callee", "constructor-callee", "assignment-lhs"],
)
def test_intermediate_getter_exception_keeps_prior_side_effect(expression: str):
    source = (
        '"use server";\n'
        "declare const registry: any;\n"
        "export async function find(input: string) {\n"
        '    const state = { sql: "SELECT 0" };\n'
        "    try {\n"
        f"        {expression};\n"
        '        state.sql = "SELECT 1";\n'
        "    } catch {}\n"
        "    return db.query(state.sql);\n"
        "}\n"
    ).encode()

    assert _rule_ids(source) == ["SKY-D281"]


def test_sink_after_local_always_throwing_call_is_unreachable():
    source = b"""\
"use server";
function fail(): never {
    throw new Error("stop");
}
export async function find(input: string) {
    fail();
    return db.query(input);
}
"""

    assert _rule_ids(source) == []


def test_impossible_normal_completion_from_throwing_helper_is_not_merged():
    source = b"""\
"use server";
function fail(): never {
    throw new Error("stop");
}
export async function find(input: string) {
    const state = { sql: "SELECT 0" };
    try {
        fail();
        state.sql = input;
    } catch {
        state.sql = "SELECT 1";
    }
    return db.query(state.sql);
}
"""

    assert _rule_ids(source) == []


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        ("`sql`", ["SKY-D281"]),
        ('"s" + "ql"', ["SKY-D281"]),
        ("`audit`", []),
        ('"au" + "dit"', []),
    ],
    ids=["template-sql", "binary-sql", "template-audit", "binary-audit"],
)
def test_static_computed_property_keys_are_resolved(
    key: str,
    expected: list[str],
):
    source = (
        '"use server";\n'
        "export async function find(input: string) {\n"
        '    const state = { sql: "SELECT 0", audit: "" };\n'
        f"    state[{key}] = input;\n"
        "    return db.query(state.sql);\n"
        "}\n"
    ).encode()

    assert _rule_ids(source) == expected


@pytest.mark.parametrize(
    "write",
    [
        "drizzle[`audit`] = input;",
        'drizzle["au" + "dit"] = input;',
    ],
    ids=["template-key", "binary-key"],
)
def test_trusted_sql_tag_survives_static_non_sql_namespace_write(write: str):
    source = (
        '"use server";\n'
        'import * as drizzle from "drizzle-orm";\n'
        "export async function find(input: string) {\n"
        f"    {write}\n"
        "    return db.execute(\n"
        "        drizzle.sql`SELECT * FROM users WHERE name = ${input}`,\n"
        "    );\n"
        "}\n"
    ).encode()

    assert _rule_ids(source) == []


def test_static_computed_sql_namespace_write_invalidates_trusted_tag():
    source = b"""\
"use server";
import * as drizzle from "drizzle-orm";
export async function find(input: string) {
    drizzle["s" + "ql"] = String.raw;
    return db.execute(
        drizzle.sql`SELECT * FROM users WHERE name = ${input}`,
    );
}
"""

    assert _rule_ids(source) == ["SKY-D281"]


@pytest.mark.parametrize(
    "mutation",
    [
        'Reflect.set(target, "sql", value);',
        'Object.defineProperty(target, "sql", { value });',
        "Object.defineProperties(target, { sql: { value } });",
    ],
    ids=["reflect-set", "define-property", "define-properties"],
)
def test_local_helper_reflective_mutation_taints_sql(mutation: str):
    source = (
        '"use server";\n'
        "function taint(target: object, value: string) {\n"
        f"    {mutation}\n"
        "}\n"
        "export async function find(input: string) {\n"
        '    const state = { sql: "SELECT 0" };\n'
        "    taint(state, input);\n"
        "    return db.query(state.sql);\n"
        "}\n"
    ).encode()

    assert _rule_ids(source) == ["SKY-D281"]


def test_local_reflective_helper_can_definitely_sanitize_sql():
    source = b"""\
"use server";
function reset(target: object) {
    Object.defineProperty(target, "sql", { value: "SELECT 1" });
}
export async function find(input: string) {
    const state = { sql: input };
    reset(state);
    return db.query(state.sql);
}
"""

    assert _rule_ids(source) == []


@pytest.mark.parametrize(
    "mutation",
    [
        "const merge = Object.assign; merge(state, { sql: input });",
        "Object.assign.call(Object, state, { sql: input });",
    ],
    ids=["alias", "function-call"],
)
def test_object_assign_indirection_taints_sql(mutation: str):
    source = (
        '"use server";\n'
        "export async function find(input: string) {\n"
        '    const state = { sql: "SELECT 0" };\n'
        f"    {mutation}\n"
        "    return db.query(state.sql);\n"
        "}\n"
    ).encode()

    assert _rule_ids(source) == ["SKY-D281"]


def test_unresolved_namespace_escape_before_tag_construction_is_unsafe():
    source = b"""\
"use server";
import * as drizzle from "drizzle-orm";
declare function escapeNamespace(value: object): void;
export async function find(input: string) {
    escapeNamespace(drizzle);
    return db.execute(
        drizzle.sql`SELECT * FROM users WHERE name = ${input}`,
    );
}
"""

    assert _rule_ids(source) == ["SKY-D281"]


def test_unresolved_namespace_escape_after_tag_construction_keeps_proof():
    source = b"""\
"use server";
import * as drizzle from "drizzle-orm";
declare function escapeNamespace(value: object): void;
export async function find(input: string) {
    const query = drizzle.sql`SELECT * FROM users WHERE name = ${input}`;
    escapeNamespace(drizzle);
    return db.execute(query);
}
"""

    assert _rule_ids(source) == []


@pytest.mark.parametrize(
    "body",
    [
        """
        const state = { query: { sql: "SELECT 0" } };
        state.query.sql = input;
        return db.query(state.query.sql);
        """,
        """
        const state = { query: { sql: "SELECT 0" } };
        const query = state.query;
        query.sql = input;
        return db.query(state.query.sql);
        """,
        """
        const state = { query: { sql: "SELECT 0" } };
        const alias = state;
        alias.query.sql = input;
        return db.query(state.query.sql);
        """,
        """
        const state = { queries: [{ sql: "SELECT 0" }] };
        state.queries[0].sql = input;
        return db.query(state.queries[0].sql);
        """,
        """
        const state = { queries: [{ sql: "SELECT 0" }] };
        const query = state.queries[0];
        query.sql = input;
        return db.query(state.queries[0].sql);
        """,
    ],
    ids=[
        "nested-write",
        "nested-member-alias",
        "parent-alias",
        "array-slot-write",
        "array-slot-alias",
    ],
)
def test_nested_and_array_member_writes_reach_sql(body: str):
    source = (
        f'"use server";\nexport async function find(input: string) {{\n    {body}\n}}\n'
    ).encode()

    assert _rule_ids(source) == ["SKY-D281"]


@pytest.mark.parametrize(
    "body",
    [
        """
        const state = { query: { sql: "SELECT 0", audit: "" } };
        state.query.audit = input;
        return db.query(state.query.sql);
        """,
        """
        const state = {
            queries: [{ sql: "SELECT 0" }, { sql: "SELECT 1" }],
        };
        state.queries[1].sql = input;
        return db.query(state.queries[0].sql);
        """,
    ],
    ids=["unrelated-nested-property", "different-array-slot"],
)
def test_unrelated_nested_and_array_writes_remain_clean(body: str):
    source = (
        f'"use server";\nexport async function find(input: string) {{\n    {body}\n}}\n'
    ).encode()

    assert _rule_ids(source) == []
