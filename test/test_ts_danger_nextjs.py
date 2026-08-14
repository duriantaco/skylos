"""Tests for Next.js-specific security pattern detection in TypeScript."""

from __future__ import annotations

from skylos.visitors.languages.typescript.danger import (
    _check_nextjs_missing_auth,
    _check_nextjs_client_secrets,
    _check_nextjs_server_action_sqli,
    scan_danger,
)
from skylos.visitors.languages.typescript.core import TypeScriptCore


# ---------- Missing auth in API routes (SKY-D280) ----------


class TestMissingAuth:
    def test_route_with_post_no_auth(self):
        source = b"""
export async function POST(request: Request) {
    const data = await request.json();
    return Response.json({ ok: true });
}
"""
        findings = []
        _check_nextjs_missing_auth(source, "/project/app/api/users/route.ts", findings)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-D280"

    def test_route_with_author_identifier_still_requires_auth(self):
        source = b"""
export async function POST(request: Request) {
    const body = await request.json();
    const authorId = body.authorId;
    await db.billing.update({ where: { id: body.id }, data: { authorId } });
    return Response.json({ ok: true });
}
"""
        findings = []
        _check_nextjs_missing_auth(
            source, "/project/app/api/billing/route.ts", findings
        )
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-D280"

    def test_route_with_post_has_auth(self):
        source = b"""
import { getServerSession } from "next-auth";

export async function POST(request: Request) {
    const session = await getServerSession();
    if (!session) return Response.json({ error: "Unauthorized" }, { status: 401 });
    return Response.json({ ok: true });
}
"""
        findings = []
        _check_nextjs_missing_auth(source, "/project/app/api/users/route.ts", findings)
        assert len(findings) == 0

    def test_route_with_get_only_no_auth_ok(self):
        """GET-only routes don't need auth (read-only)."""
        source = b"""
export async function GET(request: Request) {
    return Response.json({ items: [] });
}
"""
        findings = []
        _check_nextjs_missing_auth(source, "/project/app/api/items/route.ts", findings)
        assert len(findings) == 0

    def test_route_with_delete_no_auth(self):
        source = b"""
export async function DELETE(request: Request) {
    await db.delete(items);
    return Response.json({ ok: true });
}
"""
        findings = []
        _check_nextjs_missing_auth(source, "/project/app/api/items/route.ts", findings)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-D280"

    def test_non_route_file_ignored(self):
        source = b"""
export async function POST(data: any) {
    return data;
}
"""
        findings = []
        _check_nextjs_missing_auth(source, "/project/src/utils/helpers.ts", findings)
        assert len(findings) == 0

    def test_pages_api_route(self):
        source = b"""
export default function handler(req, res) {
    if (req.method === 'POST') {
        res.json({ ok: true });
    }
}
"""
        findings = []
        _check_nextjs_missing_auth(source, "/project/pages/api/users.ts", findings)
        assert len(findings) == 1

    def test_pages_api_route_js(self):
        source = b"""
export default function handler(req, res) {
    if (req.method === 'POST') {
        res.json({ ok: true });
    }
}
"""
        findings = []
        _check_nextjs_missing_auth(source, "/project/pages/api/users.js", findings)
        assert len(findings) == 1

    def test_pages_api_route_with_auth_is_safe(self):
        source = b"""
import { getServerSession } from "next-auth";

export default async function handler(req, res) {
    if (req.method === 'POST') {
        const session = await getServerSession(req, res);
        if (!session) {
            return res.status(401).json({ error: "Unauthorized" });
        }
        return res.status(200).json({ ok: true });
    }
    return res.status(405).end();
}
"""
        findings = []
        _check_nextjs_missing_auth(source, "/project/pages/api/users.ts", findings)
        assert findings == []

    def test_pages_api_switch_handler_delete(self):
        source = b"""
export default function handler(req, res) {
    switch (req.method) {
        case "DELETE":
            return res.status(200).json({ ok: true });
        default:
            return res.status(405).end();
    }
}
"""
        findings = []
        _check_nextjs_missing_auth(source, "/project/pages/api/users.ts", findings)
        assert len(findings) == 1

    def test_route_with_cookie_access_still_requires_auth(self):
        source = b"""
import { cookies } from "next/headers";

export async function POST(request: Request) {
    const cookieStore = cookies();
    return Response.json({ ok: true });
}
"""
        findings = []
        _check_nextjs_missing_auth(source, "/project/app/api/data/route.ts", findings)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-D280"


# ---------- Client component secrets (SKY-S102) ----------


class TestClientSecrets:
    def test_server_env_in_client_component(self):
        source = b"""
"use client"

export default function Dashboard() {
    const apiKey = process.env.DATABASE_URL;
    return <div>Dashboard</div>;
}
"""
        findings = []
        _check_nextjs_client_secrets(
            source, "/project/app/dashboard/page.tsx", findings
        )
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-S102"
        assert "DATABASE_URL" in findings[0]["message"]

    def test_next_public_env_in_client_ok(self):
        source = b"""
"use client"

export default function Dashboard() {
    const url = process.env.NEXT_PUBLIC_API_URL;
    return <div>Dashboard</div>;
}
"""
        findings = []
        _check_nextjs_client_secrets(
            source, "/project/app/dashboard/page.tsx", findings
        )
        assert len(findings) == 0

    def test_sensitive_public_env_names_are_reported_without_flagging_api_keys(self):
        source = b""""use client"\n
const react = process.env.REACT_APP_API_KEY;
const vite = process.env.VITE_AUTH_TOKEN;
const nuxt = process.env.NUXT_PUBLIC_KEY;
const expo = process.env.EXPO_PUBLIC_TOKEN;
const generic = process.env.PUBLIC_API_KEY;
"""
        findings = []
        _check_nextjs_client_secrets(
            source, "/project/app/dashboard/page.tsx", findings
        )
        assert {finding["env_name"] for finding in findings} == {
            "VITE_AUTH_TOKEN",
            "EXPO_PUBLIC_TOKEN",
        }
        assert {finding["severity"] for finding in findings} == {"HIGH"}
        assert all("public env var" in finding["message"] for finding in findings)

    def test_danger_pipeline_defers_s102_to_the_secrets_scanner(self):
        source = b"""\
"use client";
const exposed = process.env.ACCOUNT_SECRET;
"""
        core = TypeScriptCore("/project/app/account.client.ts", source)
        findings = scan_danger(
            core.root_node,
            "/project/app/account.client.ts",
            lang=core.lang,
            source=source,
        )
        assert "SKY-S102" not in [finding["rule_id"] for finding in findings]

    def test_import_meta_and_bracket_env_access_in_client_are_checked(self):
        source = b""""use client";
const first = import.meta.env.PAYMENT_SECRET;
const second = process.env["ACCOUNT_TOKEN"];
"""
        findings = []
        _check_nextjs_client_secrets(
            source, "/project/app/dashboard/page.tsx", findings
        )
        assert {finding["env_name"] for finding in findings} == {
            "PAYMENT_SECRET",
            "ACCOUNT_TOKEN",
        }

    def test_client_source_path_without_directive_is_checked(self):
        source = b"const key = process.env.DATABASE_URL;\n"
        findings = []
        _check_nextjs_client_secrets(source, "/project/src/client/config.ts", findings)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-S102"

    def test_next_route_under_client_named_package_remains_server_only(self):
        source = b"const key = process.env.STRIPE_WEBHOOK_SECRET;\n"
        findings = []
        _check_nextjs_client_secrets(
            source,
            "/project/packages/client/src/app/api/stripe/route.ts",
            findings,
        )
        assert findings == []

    def test_server_component_env_ok(self):
        """Server components can access any env var."""
        source = b"""
export default function Dashboard() {
    const dbUrl = process.env.DATABASE_URL;
    return <div>Dashboard</div>;
}
"""
        findings = []
        _check_nextjs_client_secrets(
            source, "/project/app/dashboard/page.tsx", findings
        )
        assert len(findings) == 0

    def test_multiple_secret_envs(self):
        source = b"""
"use client"

const db = process.env.DATABASE_URL;
const secret = process.env.JWT_SECRET;
const pub = process.env.NEXT_PUBLIC_NAME;
"""
        findings = []
        _check_nextjs_client_secrets(source, "/project/app/component.tsx", findings)
        assert len(findings) == 2
        messages = [f["message"] for f in findings]
        assert any("DATABASE_URL" in m for m in messages)
        assert any("JWT_SECRET" in m for m in messages)

    def test_use_client_with_semicolon(self):
        source = b"""'use client';

const key = process.env.SECRET_KEY;
"""
        findings = []
        _check_nextjs_client_secrets(source, "/project/app/comp.tsx", findings)
        assert len(findings) == 1


# ---------- Generic TypeScript SQL injection (SKY-D211) ----------


def _full_scan_d211(source: bytes) -> list[dict]:
    core = TypeScriptCore("/project/src/database.ts", source)
    findings = scan_danger(
        core.root_node,
        core.file_path,
        lang=core.lang,
        source=source,
    )
    return [finding for finding in findings if finding["rule_id"] == "SKY-D211"]


class TestGenericSQLTemplateInjection:
    def test_dynamic_database_templates_remain_flagged(self):
        source = b"""\
const input = request.body.value;
db.query(`SELECT * FROM users WHERE id = ${input}`);
conn.execute(`UPDATE users SET name = ${input}`);
repository.query(`DELETE FROM users WHERE id = ${input}`);
"""
        findings = _full_scan_d211(source)

        assert sorted(finding["line"] for finding in findings) == [
            2,
            3,
            4,
        ]

    def test_static_template_and_keyword_substring_are_safe(self):
        source = b"""\
const input = request.body.value;
db.query(`SELECT * FROM users`);
db.query(`selected record: ${input}`);
"""

        assert _full_scan_d211(source) == []

    def test_regexp_receivers_are_safe(self):
        source = b"""\
const input = request.body.value;
const literalPattern = /DELETE/;
const constructedPattern = new RegExp("SELECT");
literalPattern.exec(`DELETE is regex text: ${input}`);
constructedPattern.exec(`SELECT is regex text: ${input}`);
"""

        assert _full_scan_d211(source) == []

    def test_structurally_known_logger_receiver_is_safe(self):
        source = b"""\
const input = request.body.value;
const auditLogger = {
    query(message: string) {
        console.info(message);
    },
};
auditLogger.query(`SELECT is logged: ${input}`);
"""

        assert _full_scan_d211(source) == []

    def test_database_client_with_logger_name_remains_flagged(self):
        source = b"""\
import { Client } from "pg";
const input = request.body.value;
const auditLogger = new Client();
auditLogger.query(`SELECT * FROM users WHERE id = ${input}`);
"""
        findings = _full_scan_d211(source)

        assert [finding["line"] for finding in findings] == [4]


# ---------- SQL injection in server actions (SKY-D281) ----------


class TestServerActionSQLi:
    def test_sql_template_in_server_action(self):
        source = b"""
"use server"

export async function deleteUser(userId: string) {
    await db.query(`DELETE FROM users WHERE id = ${userId}`);
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-D281"

    def test_parameterized_query_ok(self):
        source = b"""
"use server"

export async function deleteUser(userId: string) {
    await db.query("DELETE FROM users WHERE id = $1", [userId]);
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert len(findings) == 0

    def test_execute_with_template(self):
        source = b"""
"use server"

export async function updateUser(id: string, name: string) {
    await conn.execute(`UPDATE users SET name = ${name} WHERE id = ${id}`);
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert len(findings) == 1

    def test_non_server_action_ignored(self):
        """Regular files with SQL templates are caught by general SQL injection check."""
        source = b"""
export async function deleteUser(userId: string) {
    await db.query(`DELETE FROM users WHERE id = ${userId}`);
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert len(findings) == 0

    def test_raw_method(self):
        source = b"""
"use server"

export async function search(term: string) {
    return await prisma.raw(`SELECT * FROM items WHERE name = ${term}`);
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert len(findings) == 1

    def test_prisma_query_raw_unsafe_method(self):
        source = b"""
"use server"

export async function findUser(formData: FormData) {
    const email = String(formData.get("email") ?? "");
    return prisma.$queryRawUnsafe(`SELECT * FROM users WHERE email = '${email}'`);
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-D281"

    def test_prisma_safe_query_raw_tag_not_flagged(self):
        source = b"""
"use server"
import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();

export async function findUser(email: string) {
    return prisma.$queryRaw`SELECT * FROM users WHERE email = ${email}`;
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert len(findings) == 0

    def test_unproven_sql_tag_is_flagged(self):
        source = b"""
"use server";

export async function findUser(email: string) {
    return db.query`SELECT * FROM users WHERE email = ${email}`;
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert [finding["rule_id"] for finding in findings] == ["SKY-D281"]

    def test_runtime_alias_is_still_dynamic(self):
        source = b"""
"use server";

export async function findUser(email: string) {
    const lookup = email;
    return db.query(`SELECT * FROM users WHERE email = '${lookup}'`);
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert len(findings) == 1

    def test_template_without_sql_keywords_ok(self):
        source = b"""
"use server"

export async function doThing(name: string) {
    await db.query(`hello ${name}`);
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert len(findings) == 0

    def test_constant_interpolation_is_not_critical_sqli(self):
        source = b"""
"use server";

const table = "users";
const limit = 25;

export async function listUsers() {
    return db.query(`SELECT * FROM ${table} LIMIT ${limit}`);
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert findings == []

    def test_inline_server_action_directive_is_detected(self):
        source = b"""
export async function findUser(email: string) {
    "use server";
    return db.query(`SELECT * FROM users WHERE email = '${email}'`);
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/page.tsx", findings)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-D281"

    def test_file_directive_with_trailing_comment_is_detected(self):
        source = b"""
"use server"; // Next.js file-level directive

export async function deleteUser(userId: string) {
    return db.query(`DELETE FROM users WHERE id = ${userId}`);
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert len(findings) == 1

    def test_non_server_sibling_is_not_claimed_by_inline_action(self):
        source = b"""
export async function safeAction(id: string) {
    "use server";
    return db.query("SELECT * FROM users WHERE id = $1", [id]);
}

export async function ordinaryUtility(value: string) {
    return db.query(`SELECT * FROM audit WHERE value = ${value}`);
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/page.tsx", findings)
        assert findings == []

    def test_trusted_runtime_value_is_not_taint(self):
        source = b"""\
"use server";

export async function writeAuditLog() {
    const timestamp = new Date().toISOString();
    return db.query(`INSERT INTO audit(created_at) VALUES (${timestamp})`);
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert findings == []

    def test_private_helper_in_use_server_file_is_not_an_action(self):
        source = b"""\
"use server";

async function privateLookup(value: string) {
    return db.query(`SELECT * FROM users WHERE name = ${value}`);
}

export async function publicAction() {
    return privateLookup("maintainer");
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert findings == []

    def test_taint_flows_through_alias_and_string_concatenation(self):
        source = b"""\
"use server";

export async function search(term: string) {
    const alias = term;
    const sql = "SELECT * FROM items WHERE name = '" + alias + "'";
    return db.query(sql);
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert [finding["rule_id"] for finding in findings] == ["SKY-D281"]

    def test_taint_flows_into_nested_collection_callback(self):
        source = b"""\
"use server";

export async function removeUsers(userIds: string[]) {
    return userIds.map((userId) =>
        db.query(`DELETE FROM users WHERE id = ${userId}`)
    );
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert [finding["rule_id"] for finding in findings] == ["SKY-D281"]

    def test_catch_parameter_shadows_tainted_action_parameter(self):
        source = b"""\
"use server";

export async function record(value: string) {
    try {
        await trustedOperation();
    } catch (value) {
        await db.query(`INSERT INTO errors(message) VALUES (${value.message})`);
    }
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert findings == []

    def test_loop_binding_shadows_tainted_action_parameter(self):
        source = b"""\
"use server";

export async function record(value: string) {
    const trustedValues = ["created", "updated"];
    for (const value of trustedValues) {
        await db.query(`INSERT INTO audit(kind) VALUES (${value})`);
    }
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert findings == []

    def test_sql_keyword_resolves_through_constant_alias(self):
        source = b"""\
"use server";
const prefix = "SELECT * FROM users WHERE email = ";

export async function findUser(email: string) {
    const sql = prefix + email;
    return db.query(sql);
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert [finding["rule_id"] for finding in findings] == ["SKY-D281"]

    def test_module_constant_declared_after_action_is_not_taint(self):
        source = b"""\
"use server";

export async function listUsers() {
    return db.query(`SELECT * FROM users LIMIT ${limit}`);
}

const limit = 25;
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert findings == []

    def test_proven_prisma_parameterizing_tag_is_safe(self):
        source = b"""\
"use server";
import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();

export async function findUser(email: string) {
    return prisma.$queryRaw`SELECT * FROM users WHERE email = ${email}`;
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert findings == []

    def test_spoofed_prisma_parameterizing_tag_is_not_trusted(self):
        source = b"""\
"use server";
class PrismaClient {}
const prisma = new PrismaClient();

export async function findUser(email: string) {
    return prisma.$queryRaw`SELECT * FROM users WHERE email = ${email}`;
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert [finding["rule_id"] for finding in findings] == ["SKY-D281"]

    def test_private_helper_called_with_action_input_is_traced(self):
        source = b"""\
"use server";

async function lookup(value: string) {
    return db.query(`SELECT * FROM users WHERE name = ${value}`);
}

export async function findUser(name: string) {
    return lookup(name);
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert [finding["rule_id"] for finding in findings] == ["SKY-D281"]

    def test_callback_closure_over_action_input_is_traced(self):
        source = b"""\
"use server";

export async function findUser(email: string) {
    return Promise.resolve().then(() =>
        db.query(`SELECT * FROM users WHERE email = ${email}`)
    );
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert [finding["rule_id"] for finding in findings] == ["SKY-D281"]

    def test_full_scan_coalesces_generic_and_server_action_sql_findings(self):
        source = b"""\
"use server";

export async function findUser(email: string) {
    return db.query(`SELECT * FROM users WHERE email = ${email}`);
}
"""
        core = TypeScriptCore("/project/app/actions.ts", source)
        findings = scan_danger(
            core.root_node,
            "/project/app/actions.ts",
            lang=core.lang,
            source=source,
        )
        assert [finding["rule_id"] for finding in findings].count("SKY-D281") == 1
        assert "SKY-D211" not in [finding["rule_id"] for finding in findings]

    def test_local_arrow_helper_called_with_action_input_is_traced(self):
        source = b"""\
"use server";

export async function findUser(email: string) {
    const run = (value: string) =>
        db.query(`SELECT * FROM users WHERE email = ${value}`);
    return run(email);
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert [finding["rule_id"] for finding in findings] == ["SKY-D281"]

    def test_export_list_marks_function_as_server_action(self):
        source = b"""\
"use server";

async function findUser(email: string) {
    return db.query(`SELECT * FROM users WHERE email = ${email}`);
}

export { findUser };
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert [finding["rule_id"] for finding in findings] == ["SKY-D281"]

    def test_exported_arrow_is_server_action(self):
        source = b"""\
"use server";

export const findUser = async (email: string) =>
    db.query(`SELECT * FROM users WHERE email = ${email}`);
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert [finding["rule_id"] for finding in findings] == ["SKY-D281"]

    def test_default_identifier_export_is_server_action(self):
        source = b"""\
"use server";

const findUser = async (email: string) =>
    db.query(`SELECT * FROM users WHERE email = ${email}`);

export default findUser;
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert [finding["rule_id"] for finding in findings] == ["SKY-D281"]

    def test_parenthesized_default_async_arrow_is_server_action(self):
        source = b"""\
"use server";

export default (async (email: string) => {
    return db.query(`SELECT * FROM users WHERE email = ${email}`);
});
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert [finding["rule_id"] for finding in findings] == ["SKY-D281"]

    def test_exported_const_alias_is_server_action(self):
        source = b"""\
"use server";

const actual = async (email: string) =>
    db.query(`SELECT * FROM users WHERE email = ${email}`);

export const findUser = actual;
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert [finding["rule_id"] for finding in findings] == ["SKY-D281"]

    def test_exported_alias_chain_is_server_action(self):
        source = b"""\
"use server";

const actual = async (email: string) =>
    db.query(`SELECT * FROM users WHERE email = ${email}`);
const firstAlias = actual;
const secondAlias = firstAlias;

export { secondAlias as findUser };
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert [finding["rule_id"] for finding in findings] == ["SKY-D281"]

    def test_aliased_prisma_constructor_keeps_parameterizing_tag_safe(self):
        source = b"""\
"use server";
import { PrismaClient as DatabaseClient } from "@prisma/client";
const prisma = new DatabaseClient();

export async function findUser(email: string) {
    return prisma.$queryRaw`SELECT * FROM users WHERE email = ${email}`;
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert findings == []

    def test_mutated_prisma_tag_is_not_trusted(self):
        source = b"""\
"use server";
import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();
prisma.$queryRaw = unsafeTag;

export async function findUser(email: string) {
    return prisma.$queryRaw`SELECT * FROM users WHERE email = ${email}`;
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert [finding["rule_id"] for finding in findings] == ["SKY-D281"]

    def test_reassigned_action_parameter_to_trusted_value_is_not_taint(self):
        source = b"""\
"use server";

export async function record(value: string) {
    value = "maintainer";
    return db.query(`INSERT INTO audit(actor) VALUES (${value})`);
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert findings == []

    def test_recovered_parse_does_not_crash_and_marks_proof_incomplete(self):
        source = b"""\
"use server";
export async function find(input: string) {
    const broken = ;
    return db.query(`SELECT * FROM users WHERE x = ${input}`);
}
"""
        core = TypeScriptCore("/project/app/actions.ts", source)
        assert core.root_node.has_error

        findings = scan_danger(
            core.root_node,
            "/project/app/actions.ts",
            lang=core.lang,
            source=source,
        )

        d281 = [finding for finding in findings if finding["rule_id"] == "SKY-D281"]
        assert len(d281) == 1
        evidence = d281[0]["metadata"]["security_evidence"]
        assert evidence["analysis_complete"] is False

    def test_helper_sql_argument_keeps_caller_value_for_sink_proof(self):
        source = b"""\
"use server";

function run(sql: string) {
    return db.query(sql);
}

export async function find(input: string) {
    return run(`SELECT * FROM users WHERE x = ${input}`);
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert [finding["rule_id"] for finding in findings] == ["SKY-D281"]

    def test_destructured_helper_tracks_tainted_property_only(self):
        unsafe_source = b"""\
"use server";
function run({ safe, dangerous }: { safe: string; dangerous: string }) {
    return db.query(`SELECT * FROM users WHERE x = ${dangerous}`);
}
export async function find(input: string) {
    return run({ safe: "maintainer", dangerous: input });
}
"""
        safe_source = unsafe_source.replace(
            b"x = ${dangerous}",
            b"x = ${safe}",
        )

        unsafe_findings = []
        _check_nextjs_server_action_sqli(
            unsafe_source, "/project/app/actions.ts", unsafe_findings
        )
        safe_findings = []
        _check_nextjs_server_action_sqli(
            safe_source, "/project/app/actions.ts", safe_findings
        )

        assert [finding["rule_id"] for finding in unsafe_findings] == ["SKY-D281"]
        assert safe_findings == []

    def test_array_destructured_helper_tracks_tainted_element_only(self):
        source = b"""\
"use server";
function run([safe, dangerous]: [string, string]) {
    return db.query(`SELECT * FROM users WHERE x = ${dangerous}`);
}
export async function find(input: string) {
    return run(["maintainer", input]);
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert [finding["rule_id"] for finding in findings] == ["SKY-D281"]

    def test_deep_expression_is_bounded_without_losing_sink(self):
        wrapped = (
            b"String(" * 600 + b"`SELECT * FROM users WHERE x = ${input}`" + b")" * 600
        )
        source = (
            b'"use server"; export async function find(input: string) {'
            b"return db.query(" + wrapped + b");}"
        )

        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)

        assert [finding["rule_id"] for finding in findings] == ["SKY-D281"]
        evidence = findings[0]["metadata"]["security_evidence"]
        assert evidence["analysis_complete"] is False
        assert "traversal-depth" in " ".join(evidence["analysis_diagnostics"])

    def test_deep_statement_nesting_is_bounded_without_losing_sink(self):
        source = (
            b'"use server"; export async function find(input: string) {'
            + b"{" * 300
            + b"return db.query(`SELECT * FROM users WHERE x = ${input}`);"
            + b"}" * 300
            + b"}"
        )

        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)

        assert [finding["rule_id"] for finding in findings] == ["SKY-D281"]
        assert (
            findings[0]["metadata"]["security_evidence"]["analysis_complete"] is False
        )

    def test_whole_action_parameter_reaching_database_query_is_flagged(self):
        source = b"""\
"use server";
export async function run(sqlText: string) {
    return db.query(sqlText);
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert [finding["rule_id"] for finding in findings] == ["SKY-D281"]

    def test_prisma_unsafe_whole_query_is_flagged_without_keyword(self):
        source = b"""\
"use server";
export async function run(sqlText: string) {
    return prisma.$queryRawUnsafe(sqlText);
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert [finding["rule_id"] for finding in findings] == ["SKY-D281"]

    def test_raw_escape_inside_prisma_safe_tag_is_flagged(self):
        source = b"""\
"use server";
import { Prisma, PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();
export async function run(fragment: string) {
    return prisma.$queryRaw`SELECT * FROM users WHERE ${Prisma.raw(fragment)}`;
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert [finding["rule_id"] for finding in findings] == ["SKY-D281"]

    def test_drizzle_parameterized_sql_tag_is_safe(self):
        source = b"""\
"use server";
import { sql } from "drizzle-orm";
export async function run(email: string) {
    return db.execute(sql`SELECT * FROM users WHERE email = ${email}`);
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert findings == []

    def test_drizzle_raw_escape_is_flagged(self):
        source = b"""\
"use server";
import { sql } from "drizzle-orm";
export async function run(sqlText: string) {
    return db.execute(sql.raw(sqlText));
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert [finding["rule_id"] for finding in findings] == ["SKY-D281"]

    def test_prisma_sql_parameterized_value_is_safe_and_not_duplicated(self):
        source = b"""\
"use server";
import { Prisma, PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();
export async function run(email: string) {
    return prisma.$queryRaw(Prisma.sql`SELECT * FROM users WHERE email = ${email}`);
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert findings == []

    def test_sql_shaped_non_database_methods_are_not_sinks(self):
        source = b"""\
"use server";
export async function render(input: string) {
    String.raw`SELECT is merely text: ${input}`;
    auditLogger.query(`SELECT is logged: ${input}`);
    regex.exec(`DELETE is regex text: ${input}`);
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert findings == []

    def test_prisma_generated_client_import_is_trusted(self):
        source = b"""\
"use server";
import { PrismaClient } from "./generated/client";
const prisma = new PrismaClient();
export async function run(email: string) {
    return prisma.$queryRaw`SELECT * FROM users WHERE email = ${email}`;
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert findings == []

    def test_imported_prisma_singleton_tag_is_trusted(self):
        source = b"""\
"use server";
import { prisma } from "@/lib/prisma";
export async function run(email: string) {
    return prisma.$queryRaw`SELECT * FROM users WHERE email = ${email}`;
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert findings == []

    def test_prisma_constructor_alias_tag_is_trusted(self):
        source = b"""\
"use server";
import { PrismaClient } from "@prisma/client";
const PC = PrismaClient;
const prisma = new PC();
export async function run(email: string) {
    return prisma.$queryRaw`SELECT * FROM users WHERE email = ${email}`;
}
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert findings == []

    def test_module_mutation_after_action_invalidates_prisma_tag_proof(self):
        source = b"""\
"use server";
import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();
export async function run(email: string) {
    return prisma.$queryRaw`SELECT * FROM users WHERE email = ${email}`;
}
prisma.$queryRaw = unsafeTag;
"""
        findings = []
        _check_nextjs_server_action_sqli(source, "/project/app/actions.ts", findings)
        assert [finding["rule_id"] for finding in findings] == ["SKY-D281"]
