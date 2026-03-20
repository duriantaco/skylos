"""Tests for Next.js-specific security pattern detection in TypeScript."""

from __future__ import annotations

import pytest

from skylos.visitors.languages.typescript.danger import (
    _check_nextjs_missing_auth,
    _check_nextjs_client_secrets,
    _check_nextjs_server_action_sqli,
)


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
        _check_nextjs_missing_auth(
            source, "/project/app/api/users/route.ts", findings
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
        _check_nextjs_missing_auth(
            source, "/project/app/api/users/route.ts", findings
        )
        assert len(findings) == 0

    def test_route_with_get_only_no_auth_ok(self):
        """GET-only routes don't need auth (read-only)."""
        source = b"""
export async function GET(request: Request) {
    return Response.json({ items: [] });
}
"""
        findings = []
        _check_nextjs_missing_auth(
            source, "/project/app/api/items/route.ts", findings
        )
        assert len(findings) == 0

    def test_route_with_delete_no_auth(self):
        source = b"""
export async function DELETE(request: Request) {
    await db.delete(items);
    return Response.json({ ok: true });
}
"""
        findings = []
        _check_nextjs_missing_auth(
            source, "/project/app/api/items/route.ts", findings
        )
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-D280"

    def test_non_route_file_ignored(self):
        source = b"""
export async function POST(data: any) {
    return data;
}
"""
        findings = []
        _check_nextjs_missing_auth(
            source, "/project/src/utils/helpers.ts", findings
        )
        assert len(findings) == 0

    def test_pages_api_route(self):
        source = b"""
export default function handler(req, res) {
    if (req.method === 'POST') {
        res.json({ ok: true });
    }
}

export async function POST(request: Request) {
    return Response.json({});
}
"""
        findings = []
        _check_nextjs_missing_auth(
            source, "/project/pages/api/users.ts", findings
        )
        assert len(findings) == 1

    def test_route_with_cookies_auth(self):
        source = b"""
import { cookies } from "next/headers";

export async function POST(request: Request) {
    const cookieStore = cookies();
    return Response.json({ ok: true });
}
"""
        findings = []
        _check_nextjs_missing_auth(
            source, "/project/app/api/data/route.ts", findings
        )
        assert len(findings) == 0


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
        _check_nextjs_client_secrets(source, "/project/app/dashboard/page.tsx", findings)
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
        _check_nextjs_client_secrets(source, "/project/app/dashboard/page.tsx", findings)
        assert len(findings) == 0

    def test_server_component_env_ok(self):
        """Server components can access any env var."""
        source = b"""
export default function Dashboard() {
    const dbUrl = process.env.DATABASE_URL;
    return <div>Dashboard</div>;
}
"""
        findings = []
        _check_nextjs_client_secrets(source, "/project/app/dashboard/page.tsx", findings)
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
