"""Release-blocker regressions for proof-based TypeScript SQL analysis."""

from __future__ import annotations

import pytest

from skylos.visitors.languages.typescript.core import TypeScriptCore
from skylos.visitors.languages.typescript.danger import (
    _ServerActionSQLTaint,
    _check_nextjs_server_action_sqli,
    scan_danger,
)


FILE_PATH = "/project/app/actions.ts"
SQL_RULE_IDS = {"SKY-D211", "SKY-D281", "SKY-ANALYSIS-INCOMPLETE"}


def _focused_findings(source: bytes) -> list[dict]:
    findings: list[dict] = []
    _check_nextjs_server_action_sqli(source, FILE_PATH, findings)
    return findings


def _focused_rule_ids(source: bytes) -> list[str]:
    return [finding["rule_id"] for finding in _focused_findings(source)]


def _full_sql_rule_ids(source: bytes) -> list[str]:
    core = TypeScriptCore(FILE_PATH, source)
    findings = scan_danger(
        core.root_node,
        core.file_path,
        lang=core.lang,
        source=source,
    )
    return [
        finding["rule_id"] for finding in findings if finding["rule_id"] in SQL_RULE_IDS
    ]


def test_full_scan_suppresses_d211_after_trusted_server_action_proof():
    safe_source = b"""\
"use server";
export async function recordAudit() {
    const now = new Date().toISOString();
    return db.query(`INSERT INTO audit(ts) VALUES (${now})`);
}
"""
    unsafe_source = b"""\
"use server";
export async function recordAudit(now: string) {
    return db.query(`INSERT INTO audit(ts) VALUES (${now})`);
}
"""

    assert _full_sql_rule_ids(safe_source) == []
    assert _full_sql_rule_ids(unsafe_source) == ["SKY-D281"]


def test_full_scan_keeps_d211_when_dynamic_value_has_no_positive_trust_proof():
    source = b"""\
"use server";
let queuedSql: string;
export async function runQueuedQuery() {
    return db.query(`SELECT * FROM users WHERE ${queuedSql}`);
}
"""

    assert _full_sql_rule_ids(source) == ["SKY-D211"]


def test_d281_deduplication_does_not_hide_a_different_sink_on_same_line():
    source = b"""\
"use server";
let queuedSql: string;
export async function run(input: string) {
    db.query(`SELECT ${input}`); return db.query(`SELECT ${queuedSql}`);
}
"""

    assert _full_sql_rule_ids(source) == ["SKY-D211", "SKY-D281"]


def test_unrelated_member_assignment_does_not_erase_tainted_sql_property():
    source = b"""\
"use server";
export async function find(input: string) {
    const state = { sql: input, audit: "" };
    state.audit = "maintainer";
    return db.query(state.sql);
}
"""

    assert _focused_rule_ids(source) == ["SKY-D281"]


def test_unrelated_member_assignment_does_not_taint_trusted_sql_property():
    source = b"""\
"use server";
export async function find(input: string) {
    const state = { sql: "SELECT 1", audit: input };
    state.audit = input;
    return db.query(state.sql);
}
"""

    assert _focused_rule_ids(source) == []


def test_same_member_assignment_updates_sql_taint_without_poisoning_object():
    unsafe_source = b"""\
"use server";
export async function find(input: string) {
    const state = { sql: "SELECT 1", audit: "" };
    state.sql = input;
    return db.query(state.sql);
}
"""
    safe_source = b"""\
"use server";
export async function find(input: string) {
    const state = { sql: input, audit: "" };
    state.sql = "SELECT 1";
    return db.query(state.sql);
}
"""

    assert _focused_rule_ids(unsafe_source) == ["SKY-D281"]
    assert _focused_rule_ids(safe_source) == []


def test_zero_iteration_loop_cannot_erase_taint():
    source = b"""\
"use server";
export async function find(input: string) {
    let query = input;
    for (const ignored of []) {
        query = "SELECT 1";
    }
    return db.query(query);
}
"""

    assert _focused_rule_ids(source) == ["SKY-D281"]


def test_zero_iteration_while_loop_cannot_erase_taint():
    source = b"""\
"use server";
export async function find(input: string, enabled: boolean) {
    let query = input;
    while (enabled) {
        query = "SELECT 1";
        enabled = false;
    }
    return db.query(query);
}
"""

    assert _focused_rule_ids(source) == ["SKY-D281"]


def test_unproven_local_prisma_import_is_not_a_safe_tag_proof():
    source = b"""\
"use server";
import { prisma } from "@/lib/not-prisma";
export async function find(input: string) {
    return prisma.$queryRaw`SELECT * FROM users WHERE name = ${input}`;
}
"""

    assert _focused_rule_ids(source) == ["SKY-D281"]


def test_official_prisma_client_parameterizing_tag_remains_safe():
    source = b"""\
"use server";
import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();
export async function find(input: string) {
    return prisma.$queryRaw`SELECT * FROM users WHERE name = ${input}`;
}
"""

    assert _focused_rule_ids(source) == []


def test_database_receiver_provenance_survives_value_aliases():
    source = b"""\
"use server";
import { Pool } from "pg";
const pool = new Pool();
const client = pool;
export async function find(input: string) {
    return client.query("SELECT * FROM users WHERE name = '" + input + "'");
}
"""

    assert _focused_rule_ids(source) == ["SKY-D281"]


def test_libsql_client_factory_is_sql_receiver_provenance():
    source = b"""\
"use server";
import { createClient } from "@libsql/client";
const client = createClient({ url: process.env.DATABASE_URL! });
export async function find(input: string) {
    return client.execute("SELECT * FROM users WHERE name = '" + input + "'");
}
"""

    assert _focused_rule_ids(source) == ["SKY-D281"]


@pytest.mark.parametrize(
    "source",
    [
        b"""\
"use server";
import * as drizzle from "drizzle-orm";
export async function find(input: string) {
    return db.execute(
        drizzle.sql`SELECT * FROM users WHERE name = ${input}`,
    );
}
""",
        b"""\
"use server";
import sql from "@databases/sql";
export async function find(input: string) {
    return db.query(sql`SELECT * FROM users WHERE name = ${input}`);
}
""",
    ],
    ids=["drizzle-namespace", "databases-default-import"],
)
def test_documented_parameterizing_sql_tags_are_safe(source: bytes):
    assert _focused_rule_ids(source) == []


def test_aliased_raw_escape_invalidates_parameterizing_tag_proof():
    source = b"""\
"use server";
import { Prisma, PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();
const raw = Prisma.raw;
export async function find(input: string) {
    return prisma.$queryRaw`SELECT * FROM users WHERE name = ${raw(input)}`;
}
"""

    assert _focused_rule_ids(source) == ["SKY-D281"]


def test_parser_recovery_with_hidden_candidate_fails_closed():
    source = b"""\
"use server";
const broken = "
export async function find(input: string) {
    return db.query(`SELECT * FROM users WHERE name = ${input}`);
}
"""
    core = TypeScriptCore(FILE_PATH, source)

    assert core.root_node.has_error
    assert _focused_rule_ids(source) == ["SKY-ANALYSIS-INCOMPLETE"]


@pytest.mark.parametrize(
    "expression",
    [
        'sqlText + ""',
        "`${sqlText}`",
        'sqlText ?? ""',
        'sqlText.replace("", "")',
        "input.sql",
        "input[0]",
    ],
    ids=[
        "empty-concatenation",
        "template-forward",
        "nullish-forward",
        "no-op-replace",
        "object-property",
        "array-element",
    ],
)
def test_whole_sql_taint_survives_expression_shapes(expression: str):
    parameter = (
        "input: { sql: string }"
        if expression == "input.sql"
        else ("input: string[]" if expression == "input[0]" else "sqlText: string")
    )
    source = (
        '"use server";\n'
        f"export async function run({parameter}) {{\n"
        f"    return db.query({expression});\n"
        "}\n"
    ).encode()

    assert _focused_rule_ids(source) == ["SKY-D281"]


@pytest.mark.parametrize(
    "expression",
    ["identity(input)", "input.slice(0)", "decodeURIComponent(input)"],
    ids=["local-identity", "slice", "decode-uri-component"],
)
def test_whole_sql_taint_survives_common_forwarders(expression: str):
    source = (
        '"use server";\n'
        "function identity(value: string) { return value; }\n"
        "export async function run(input: string) {\n"
        f"    return db.query({expression});\n"
        "}\n"
    ).encode()

    assert _focused_rule_ids(source) == ["SKY-D281"]


def test_parameterized_query_config_remains_safe():
    source = b"""\
"use server";
export async function find(input: string) {
    return db.query({
        text: "SELECT * FROM users WHERE name = $1",
        values: [input],
    });
}
"""

    assert _focused_rule_ids(source) == []


def test_sqlite_run_is_a_raw_sql_sink():
    unsafe_source = b"""\
"use server";
export async function remove(input: string) {
    return db.run("DELETE FROM users WHERE id = " + input);
}
"""
    safe_source = b"""\
"use server";
export async function remove(input: string) {
    return db.run("DELETE FROM users WHERE id = ?", input);
}
"""

    assert _focused_rule_ids(unsafe_source) == ["SKY-D281"]
    assert _focused_rule_ids(safe_source) == []


def test_static_bracket_query_is_a_sql_sink():
    source = b"""\
"use server";
export async function find(input: string) {
    return db["query"](`SELECT * FROM users WHERE name = ${input}`);
}
"""

    assert _full_sql_rule_ids(source) == ["SKY-D281"]


def test_static_bracket_logger_method_remains_safe():
    source = b"""\
"use server";
const auditLogger = {
    query(message: string) {
        console.info(message);
    },
};
export async function log(input: string) {
    return auditLogger["query"](`SELECT is logged: ${input}`);
}
"""

    assert _full_sql_rule_ids(source) == []


def test_mutated_local_logger_method_is_no_longer_a_non_sql_proof():
    source = b"""\
"use server";
const repository = {
    query(message: string) {
        console.info(message);
    },
};
repository.query = db.query;
export async function find(input: string) {
    return repository.query(`SELECT * FROM users WHERE name = ${input}`);
}
"""

    assert "SKY-D281" in _full_sql_rule_ids(source)


def test_unmutated_local_logger_method_remains_safe():
    source = b"""\
"use server";
const repository = {
    query(message: string) {
        console.info(message);
    },
};
export async function log(input: string) {
    return repository.query(`SELECT is logged: ${input}`);
}
"""

    assert _full_sql_rule_ids(source) == []


def test_unresolved_local_query_wrapper_keeps_generic_sql_warning():
    source = b"""\
"use server";
const repository = {
    query(message: string) {
        return forwardToUnknownAdapter(message);
    },
};
export async function find(input: string) {
    return repository.query(`SELECT * FROM users WHERE name = ${input}`);
}
"""

    assert _full_sql_rule_ids(source) == ["SKY-D211"]


@pytest.mark.parametrize(
    "source",
    [
        b"""\
"use server";
function lookup(query: string, input: string) {
    return db.query(query + " WHERE name = '" + input + "'");
}
export async function find(inputs: string[]) {
    return inputs.reduce(lookup, "SELECT * FROM users");
}
""",
        b"""\
"use server";
export async function find(inputs: string[]) {
    return inputs.sort((left, right) => {
        db.query("SELECT * FROM users WHERE name = '" + left + "'");
        return left.localeCompare(right);
    });
}
""",
        b"""\
"use server";
function lookup(input: string) {
    return db.query("SELECT * FROM users WHERE name = '" + input + "'");
}
export async function find(inputs: string[]) {
    return Array.from(inputs, lookup);
}
""",
    ],
    ids=["reduce", "sort", "array-from"],
)
def test_modeled_callbacks_preserve_action_input_taint(source: bytes):
    assert _focused_rule_ids(source) == ["SKY-D281"]


def test_reduce_callback_with_trusted_values_remains_safe():
    source = b"""\
"use server";
function lookup(query: string, input: string) {
    return db.query(query + " WHERE name = '" + input + "'");
}
export async function find() {
    return ["maintainer"].reduce(lookup, "SELECT * FROM users");
}
"""

    assert _focused_rule_ids(source) == []


@pytest.mark.parametrize(
    "mutation",
    [
        'enabled && (sql = "SELECT * FROM users WHERE name = \'" + input + "\'")',
        'sql = enabled ? "SELECT 1" : "SELECT * FROM users WHERE name = \'" + input + "\'"',
    ],
    ids=["short-circuit", "ternary"],
)
def test_conditional_expression_mutation_cannot_erase_sql_taint(mutation: str):
    source = (
        '"use server";\n'
        "export async function find(input: string, enabled: boolean) {\n"
        '    let sql = "SELECT 1";\n'
        f"    {mutation};\n"
        "    return db.query(sql);\n"
        "}\n"
    ).encode()

    assert _focused_rule_ids(source) == ["SKY-D281"]


def test_switch_branch_cannot_erase_sql_taint():
    source = b"""\
"use server";
export async function find(input: string, mode: string) {
    let sql = input;
    switch (mode) {
        case "safe":
            sql = "SELECT 1";
            break;
        default:
            break;
    }
    return db.query(sql);
}
"""

    assert _focused_rule_ids(source) == ["SKY-D281"]


@pytest.mark.parametrize(
    "write",
    [
        "state[key] = input",
        'state["sql"] = input',
        "alias.sql = input",
        "Object.assign(state, { sql: input })",
        "setSql(state, input)",
    ],
    ids=[
        "unknown-computed-key",
        "static-computed-key",
        "object-alias",
        "object-assign",
        "helper-side-effect",
    ],
)
def test_object_property_write_preserves_sql_taint(write: str):
    helper = (
        "function setSql(target: { sql: string }, value: string) {\n"
        "    target.sql = value;\n"
        "}\n"
        if write == "setSql(state, input)"
        else ""
    )
    source = (
        '"use server";\n'
        f"{helper}"
        "export async function find(input: string, key: string) {\n"
        '    const state = { sql: "SELECT 1" };\n'
        "    const alias = state;\n"
        f"    {write};\n"
        "    return db.query(state.sql);\n"
        "}\n"
    ).encode()

    assert _focused_rule_ids(source) == ["SKY-D281"]


def test_helper_side_effect_with_trusted_value_remains_safe():
    source = b"""\
"use server";
function setSql(target: { sql: string }, value: string) {
    target.sql = value;
}
export async function find() {
    const state = { sql: "SELECT * FROM users" };
    setSql(state, "SELECT 1");
    return db.query(state.sql);
}
"""

    assert _focused_rule_ids(source) == []


@pytest.mark.parametrize(
    "source",
    [
        b"""\
"use server";
import { sql } from "drizzle-orm";
export async function find(input: string) {
    const sql = (parts: TemplateStringsArray, value: string) =>
        parts[0] + value;
    return db.query(sql`SELECT * FROM users WHERE name = ${input}`);
}
""",
        b"""\
"use server";
import * as drizzle from "drizzle-orm";
export async function find(input: string) {
    const drizzle = {
        sql(parts: TemplateStringsArray, value: string) {
            return parts[0] + value;
        },
    };
    return db.query(drizzle.sql`SELECT * FROM users WHERE name = ${input}`);
}
""",
        b"""\
"use server";
import * as drizzle from "drizzle-orm";
drizzle.sql = (parts: TemplateStringsArray, value: string) => parts[0] + value;
export async function find(input: string) {
    return db.query(drizzle.sql`SELECT * FROM users WHERE name = ${input}`);
}
""",
    ],
    ids=["named-tag-shadow", "namespace-shadow", "namespace-reassignment"],
)
def test_shadowed_or_reassigned_sql_tag_is_not_a_safety_proof(source: bytes):
    assert _focused_rule_ids(source) == ["SKY-D281"]


def test_static_bracket_sql_sink_outside_server_action_gets_d211():
    source = b"""\
export function find(input: string) {
    return db["query"](`SELECT * FROM users WHERE name = ${input}`);
}
"""

    assert _full_sql_rule_ids(source) == ["SKY-D211"]


def test_static_bracket_local_logger_outside_server_action_remains_safe():
    source = b"""\
const auditLogger = {
    query(message: string) {
        console.info(message);
    },
};
export function log(input: string) {
    return auditLogger["query"](`SELECT is logged: ${input}`);
}
"""

    assert _full_sql_rule_ids(source) == []


def test_short_circuit_safe_overwrite_cannot_erase_existing_taint():
    source = b"""\
"use server";
export async function find(input: string, enabled: boolean) {
    let sql = input;
    enabled && (sql = "SELECT 1");
    return db.query(sql);
}
"""

    assert _focused_rule_ids(source) == ["SKY-D281"]


def test_switch_lexical_shadow_does_not_overwrite_outer_binding():
    source = b"""\
"use server";
export async function find(input: string, mode: string) {
    let sql = input;
    switch (mode) {
        default:
            const sql = "SELECT 1";
            console.info(sql);
    }
    return db.query(sql);
}
"""

    assert _focused_rule_ids(source) == ["SKY-D281"]


def test_switch_ignores_unreachable_assignment_after_break():
    source = b"""\
"use server";
export async function find(input: string, mode: string) {
    let sql = input;
    switch (mode) {
        case "one":
            break;
            sql = "SELECT 1";
        default:
            break;
            sql = "SELECT 2";
    }
    return db.query(sql);
}
"""

    assert _focused_rule_ids(source) == ["SKY-D281"]


def test_switch_fallthrough_unconditional_reset_is_safe():
    source = b"""\
"use server";
export async function find(input: string, mode: string) {
    let sql = "SELECT 0";
    switch (mode) {
        case "unsafe":
            sql = input;
        case "safe":
            sql = "SELECT 1";
            break;
        default:
            sql = "SELECT 2";
    }
    return db.query(sql);
}
"""

    assert _focused_rule_ids(source) == []


def test_switch_returning_path_is_not_merged_at_later_sink():
    source = b"""\
"use server";
export async function find(input: string, mode: string) {
    let sql = input;
    switch (mode) {
        case "skip":
            return null;
        default:
            sql = "SELECT 1";
    }
    return db.query(sql);
}
"""

    assert _focused_rule_ids(source) == []


def test_mutated_static_bracket_logger_keeps_generic_warning():
    source = b"""\
const repository = {
    query(message: string) {
        console.info(message);
    },
};
repository["query"] = db.query;
export function find(input: string) {
    return repository["query"](`SELECT * FROM users WHERE name = ${input}`);
}
"""

    assert _full_sql_rule_ids(source) == ["SKY-D211"]


def test_conditional_helper_overwrite_cannot_erase_existing_property_taint():
    source = b"""\
"use server";
function setSafe(target: { sql: string }, enabled: boolean) {
    if (enabled) {
        target.sql = "SELECT 1";
    }
}
export async function find(input: string, enabled: boolean) {
    const state = { sql: input };
    setSafe(state, enabled);
    return db.query(state.sql);
}
"""

    assert _focused_rule_ids(source) == ["SKY-D281"]


def test_helper_dynamic_property_write_taints_possible_sql_member():
    source = b"""\
"use server";
function setValue(target: { sql: string }, key: string, value: string) {
    target[key] = value;
}
export async function find(input: string, key: string) {
    const state = { sql: "SELECT 1" };
    setValue(state, key, input);
    return db.query(state.sql);
}
"""

    assert _focused_rule_ids(source) == ["SKY-D281"]


def test_helper_write_to_module_captured_object_is_preserved():
    source = b"""\
"use server";
const state = { sql: "SELECT 1" };
function setSql(value: string) {
    state.sql = value;
}
export async function find(input: string) {
    setSql(input);
    return db.query(state.sql);
}
"""

    assert _focused_rule_ids(source) == ["SKY-D281"]


def test_definite_helper_literal_overwrite_clears_existing_property_taint():
    source = b"""\
"use server";
function setSafe(target: { sql: string }) {
    target.sql = "SELECT 1";
}
export async function find(input: string) {
    const state = { sql: input };
    setSafe(state);
    return db.query(state.sql);
}
"""

    assert _full_sql_rule_ids(source) == []


@pytest.mark.parametrize(
    "helper",
    [
        "target = { sql: 'SELECT 1' };",
        "const state = { sql: 'SELECT 1' }; state.sql = 'SELECT 2';",
    ],
    ids=["parameter-rebinding", "callee-local-same-name"],
)
def test_non_mutating_helper_does_not_clear_caller_property_taint(helper: str):
    source = (
        '"use server";\n'
        "function touch(target: { sql: string }) {\n"
        f"    {helper}\n"
        "}\n"
        "export async function find(input: string) {\n"
        "    const state = { sql: input };\n"
        "    touch(state);\n"
        "    return db.query(state.sql);\n"
        "}\n"
    ).encode()

    assert _focused_rule_ids(source) == ["SKY-D281"]


@pytest.mark.parametrize(
    "mutation",
    [
        "if (enabled) { drizzle.sql = String.raw; }",
        "if (enabled) { Object.assign(drizzle, { sql: String.raw }); }",
    ],
    ids=["conditional-member-write", "conditional-object-assign"],
)
def test_conditional_namespace_tag_poisoning_is_unsafe(mutation: str):
    source = (
        '"use server";\n'
        'import * as drizzle from "drizzle-orm";\n'
        "export async function find(input: string, enabled: boolean) {\n"
        f"    {mutation}\n"
        "    return db.execute(\n"
        "        drizzle.sql`SELECT * FROM users WHERE name = ${input}`,\n"
        "    );\n"
        "}\n"
    ).encode()

    assert _focused_rule_ids(source) == ["SKY-D281"]


def test_conditional_named_tag_poisoning_is_unsafe():
    source = b"""\
"use server";
import { sql } from "drizzle-orm";
export async function find(input: string, enabled: boolean) {
    if (enabled) {
        sql = String.raw;
    }
    return db.execute(sql`SELECT * FROM users WHERE name = ${input}`);
}
"""

    assert _focused_rule_ids(source) == ["SKY-D281"]


def test_module_alias_tag_poisoning_is_unsafe():
    source = b"""\
"use server";
import * as drizzle from "drizzle-orm";
const tagAlias = drizzle;
tagAlias.sql = String.raw;
export async function find(input: string) {
    return db.execute(
        drizzle.sql`SELECT * FROM users WHERE name = ${input}`,
    );
}
"""

    assert _focused_rule_ids(source) == ["SKY-D281"]


def test_invoked_tag_poisoning_helper_is_unsafe():
    source = b"""\
"use server";
import * as drizzle from "drizzle-orm";
function poison() {
    drizzle.sql = String.raw;
}
export async function find(input: string) {
    poison();
    return db.execute(
        drizzle.sql`SELECT * FROM users WHERE name = ${input}`,
    );
}
"""

    assert _focused_rule_ids(source) == ["SKY-D281"]


def test_unused_tag_poisoning_helper_does_not_invalidate_import():
    source = b"""\
"use server";
import * as drizzle from "drizzle-orm";
function poison() {
    drizzle.sql = String.raw;
}
export async function find(input: string) {
    return db.execute(
        drizzle.sql`SELECT * FROM users WHERE name = ${input}`,
    );
}
"""

    assert _focused_rule_ids(source) == []


def test_parameterized_query_keeps_construction_time_proof():
    source = b"""\
"use server";
import * as drizzle from "drizzle-orm";
export async function find(input: string) {
    const query = drizzle.sql`SELECT * FROM users WHERE name = ${input}`;
    drizzle.sql = String.raw;
    return db.execute(query);
}
"""

    assert _focused_rule_ids(source) == []


def test_parameterizing_tag_proof_is_not_reused_across_helper_invocations():
    source = b"""\
"use server";
import * as drizzle from "drizzle-orm";
function lookup(input: string) {
    return db.execute(drizzle.sql`SELECT * FROM users WHERE name = ${input}`);
}
export async function first(input: string) {
    return lookup(input);
}
export async function second(input: string) {
    drizzle.sql = String.raw;
    return lookup(input);
}
"""

    assert _focused_rule_ids(source) == ["SKY-D281"]


def test_computed_object_literal_key_taints_possible_sql_member():
    source = b"""\
"use server";
export async function find(input: string, key: string) {
    const state = { sql: "SELECT 1", [key]: input };
    return db.query(state.sql);
}
"""

    assert _focused_rule_ids(source) == ["SKY-D281"]


def test_conditional_switch_break_preserves_break_exit_state():
    source = b"""\
"use server";
export async function find(input: string, mode: string, stop: boolean) {
    let sql = "SELECT 1";
    switch (mode) {
        case "unsafe":
            sql = input;
            if (stop) break;
            sql = "SELECT 1";
        default:
            return null;
    }
    return db.query(sql);
}
"""

    assert _focused_rule_ids(source) == ["SKY-D281"]


def test_pending_return_does_not_skip_reachable_finally_sink():
    source = b"""\
"use server";
export async function find(input: string) {
    try {
        return null;
    } catch {
        return null;
    } finally {
        audit();
        db.query(`SELECT * FROM users WHERE name = ${input}`);
    }
}
"""

    assert _focused_rule_ids(source) == ["SKY-D281"]


def test_finally_sink_sees_heap_state_from_returning_path():
    source = b"""\
"use server";
export async function find(input: string) {
    const state = { sql: "SELECT 1" };
    try {
        state.sql = input;
        return null;
    } finally {
        audit();
        db.query(state.sql);
    }
}
"""

    assert _focused_rule_ids(source) == ["SKY-D281"]


def test_try_catch_preserves_partial_state_at_possible_throw_point():
    source = b"""\
"use server";
export async function find(input: string) {
    const state = { sql: "SELECT 1" };
    try {
        state.sql = input;
        mayThrow();
        state.sql = "SELECT 1";
    } catch {}
    return db.query(state.sql);
}
"""

    assert _focused_rule_ids(source) == ["SKY-D281"]


def test_caught_helper_throw_preserves_heap_effect_before_throw():
    source = b"""\
"use server";
function setSql(
    target: { sql: string },
    input: string,
    stop: boolean,
) {
    if (stop) {
        target.sql = input;
        throw new Error("stop");
    }
    target.sql = "SELECT 1";
}
export async function find(input: string, stop: boolean) {
    const state = { sql: "SELECT 1" };
    try {
        setSql(state, input, stop);
    } catch {}
    return db.query(state.sql);
}
"""

    assert _focused_rule_ids(source) == ["SKY-D281"]


@pytest.mark.parametrize(
    "writes",
    [
        "const state = { ...{ sql: input }, sql: 'SELECT 1' };",
        (
            "const state = { sql: 'SELECT 0' }; "
            "state[key] = input; state.sql = 'SELECT 1';"
        ),
    ],
    ids=["object-spread-before-exact", "wildcard-before-exact"],
)
def test_later_exact_property_write_masks_earlier_wildcard(writes: str):
    source = (
        '"use server";\n'
        "export async function find(input: string, key: string) {\n"
        f"    {writes}\n"
        "    return db.query(state.sql);\n"
        "}\n"
    ).encode()

    assert _focused_rule_ids(source) == []


def test_nested_finally_sanitizes_exception_state_before_outer_catch():
    source = b"""\
"use server";
export async function find(input: string) {
    const state = { sql: input };
    try {
        try {
            mayThrow();
        } finally {
            state.sql = "SELECT 1";
        }
    } catch {}
    return db.query(state.sql);
}
"""

    assert _focused_rule_ids(source) == []


@pytest.mark.parametrize(
    "throwing_expression",
    [
        "mayThrow(state.sql = input)",
        "Object.assign(state, { sql: input })",
        "getFn(state.sql = input)()",
    ],
    ids=["assignment-argument", "object-assign", "callee-side-effect"],
)
def test_call_exception_state_includes_argument_and_callee_effects(
    throwing_expression: str,
):
    source = (
        '"use server";\n'
        "export async function find(input: string) {\n"
        "    const state = { sql: 'SELECT 1' };\n"
        "    try {\n"
        f"        {throwing_expression};\n"
        "        state.sql = 'SELECT 1';\n"
        "    } catch {}\n"
        "    return db.query(state.sql);\n"
        "}\n"
    ).encode()

    assert _focused_rule_ids(source) == ["SKY-D281"]


def test_constructor_exception_preserves_heap_state():
    source = b"""\
"use server";
export async function find(input: string) {
    const state = { sql: "SELECT 1" };
    try {
        state.sql = input;
        new MayThrow();
        state.sql = "SELECT 1";
    } catch {}
    return db.query(state.sql);
}
"""

    assert _focused_rule_ids(source) == ["SKY-D281"]


@pytest.mark.parametrize(
    "poison",
    [
        "drizzle[key] = String.raw;",
        "function poison(target: typeof drizzle, key: string) { "
        "target[key] = String.raw; } poison(drizzle, key);",
    ],
    ids=["direct", "helper"],
)
def test_computed_namespace_tag_poisoning_is_unsafe(poison: str):
    source = (
        '"use server";\n'
        'import * as drizzle from "drizzle-orm";\n'
        "export async function find(input: string, key: string) {\n"
        f"    {poison}\n"
        "    return db.execute(\n"
        "        drizzle.sql`SELECT * FROM users WHERE name = ${input}`,\n"
        "    );\n"
        "}\n"
    ).encode()

    assert _focused_rule_ids(source) == ["SKY-D281"]


@pytest.mark.parametrize(
    "computed_key",
    ["0", "true", "Symbol.iterator"],
    ids=["number", "boolean", "symbol"],
)
def test_static_non_string_computed_key_cannot_taint_sql(computed_key: str):
    source = (
        '"use server";\n'
        "export async function find(input: string) {\n"
        f"    const state = {{ sql: 'SELECT 1', [{computed_key}]: input }};\n"
        "    return db.query(state.sql);\n"
        "}\n"
    ).encode()

    assert _focused_rule_ids(source) == []


def test_all_branch_exact_writes_mask_earlier_wildcard():
    source = b"""\
"use server";
export async function find(input: string, key: string, flag: boolean) {
    const state = { sql: "SELECT 0" };
    state[key] = input;
    if (flag) {
        state.sql = "SELECT 1";
    } else {
        state.sql = "SELECT 2";
    }
    return db.query(state.sql);
}
"""

    assert _focused_rule_ids(source) == []


def test_exact_write_masks_wildcard_from_helper_object_assign():
    source = b"""\
"use server";
function merge(target: object, patch: object) {
    Object.assign(target, patch);
}
export async function find(input: string) {
    const state = { sql: "SELECT 0" };
    merge(state, { other: input });
    state.sql = "SELECT 1";
    return db.query(state.sql);
}
"""

    assert _focused_rule_ids(source) == []


def test_switch_break_inside_outer_loop_preserves_switch_exit_state():
    source = b"""\
"use server";
export async function find(
    input: string,
    xs: string[],
    mode: string,
    stop: boolean,
) {
    for (const x of xs) {
        let sql = "SELECT 1";
        switch (mode) {
            case "unsafe":
                sql = input;
                if (stop) break;
                sql = "SELECT 1";
            default:
                return null;
        }
        db.query(sql);
    }
}
"""

    assert _focused_rule_ids(source) == ["SKY-D281"]


def test_labelled_break_is_not_treated_as_switch_exit():
    source = b"""\
"use server";
export async function find(input: string, mode: string) {
    let sql = "SELECT 1";
    outer: {
        switch (mode) {
            case "unsafe":
                sql = input;
                break outer;
            default:
                sql = "SELECT 1";
        }
        db.query(sql);
    }
}
"""

    assert _focused_rule_ids(source) == []


@pytest.mark.parametrize(
    "callee",
    [
        "db.run",
        "db.all",
        "db.each",
        "db.get",
        'db["query"]',
        "prisma.queryRawUnsafe",
    ],
)
def test_parser_recovery_fails_closed_for_every_sql_candidate_shape(callee: str):
    source = (
        '"use server";\n'
        'const broken = "\n'
        "export async function find(input: string) {\n"
        f"    return {callee}(`SELECT ${{input}}`);\n"
        "}\n"
    ).encode()

    assert _focused_rule_ids(source) == ["SKY-ANALYSIS-INCOMPLETE"]


@pytest.mark.parametrize(
    "shadow",
    [
        'import { Date } from "./untrusted";',
        'import { String } from "./untrusted";',
        "function Date() { return queuedSql; }",
        "function String() { return queuedSql; }",
    ],
)
def test_shadowed_safe_value_builtins_do_not_suppress_generic_sql_warning(
    shadow: str,
):
    expression = "new Date().toISOString()" if "Date" in shadow else "String()"
    source = (
        '"use server";\n'
        f"{shadow}\n"
        "export async function find(input: string) {\n"
        f"    return db.query(`SELECT * FROM users WHERE name = ${{{expression}}}`);\n"
        "}\n"
    ).encode()

    assert _full_sql_rule_ids(source)


def test_called_member_mutator_declared_after_action_is_executed():
    source = b"""\
"use server";
const db = {
    query(message: string) { console.info(message); },
};
export async function find(input: string) {
    install();
    return db.query(`SELECT * FROM users WHERE name = ${input}`);
}
function install() {
    db.query = realDb.query;
}
"""

    assert _full_sql_rule_ids(source) == ["SKY-D281"]


def test_uncalled_member_mutator_does_not_invalidate_local_non_sql_proof():
    source = b"""\
"use server";
const db = {
    query(message: string) { console.info(message); },
};
function neverCalled() {
    db.query = realDb.query;
}
export async function find(input: string) {
    return db.query(`SELECT is logged: ${input}`);
}
"""

    assert _full_sql_rule_ids(source) == []


def test_local_sql_wrapper_reports_the_inner_sink_once():
    source = b"""\
"use server";
const repository = {
    query(sql: string) {
        return db.query(sql);
    },
};
export async function find(input: string) {
    return repository.query(`SELECT * FROM users WHERE name = ${input}`);
}
"""

    assert _full_sql_rule_ids(source) == ["SKY-D281"]


def test_repeated_identical_exception_states_do_not_exhaust_replay_budget():
    calls = "\n".join("        mayThrow();" for _ in range(300))
    catch_body = "\n".join('        state.audit = "ok";' for _ in range(1_000))
    source = f"""\
"use server";
export async function find(input: string) {{
    const state = {{ sql: input, audit: "" }};
    try {{
{calls}
    }} catch {{
{catch_body}
    }}
    return db.query(state.sql);
}}
""".encode()

    findings = _focused_findings(source)

    assert [finding["rule_id"] for finding in findings] == ["SKY-D281"]
    evidence = findings[0]["metadata"]["security_evidence"]
    assert evidence["analysis_complete"] is True
    assert "exception-state budget exhausted" not in " ".join(
        evidence["analysis_diagnostics"]
    )


def test_module_declarators_consume_the_bounded_analysis_budget(monkeypatch):
    declarations = ", ".join(f"value_{index} = {index}" for index in range(200))
    source = f'"use server";\nconst {declarations};\n'.encode()
    core = TypeScriptCore(FILE_PATH, source)
    monkeypatch.setattr(_ServerActionSQLTaint, "_MAX_WORK", 5)

    analysis = _ServerActionSQLTaint(core.root_node, source, FILE_PATH)

    assert analysis.analysis_complete is False
    assert len(analysis.module_values) < 200
    assert "D281 work budget exhausted" in analysis.diagnostics
