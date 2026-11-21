"""SKY-D280: Next.js routes that authenticate through a project helper or an
explicit authorization check.

The helper's source is followed through project imports (bounded) and must
reach a recognised identity verification; the route must reject on the
helper's failure before it mutates."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skylos.visitors.languages.typescript import scan_typescript_file

JWT = """import jwt from 'jsonwebtoken';
export function parseToken(token: string, secret: string) {
  try {
    return jwt.verify(token, secret);
  } catch {
    return null;
  }
}
"""

AUTH = """import { parseToken } from './jwt';
export async function checkAuth(request: Request) {
  const token = request.headers.get('authorization')?.split(' ')[1];
  return parseToken(token as string, process.env.APP_SECRET as string);
}
"""

REQUEST = """import { checkAuth } from '@/lib/auth';
import { unauthorized } from '@/lib/response';

export async function parseRequest(request: Request, schema?: any, options?: any) {
  let error: undefined | (() => Response);
  let auth = null;
  const body = await request.clone().json();
  if (!options?.skipAuth) {
    auth = await checkAuth(request);
    if (!auth) {
      error = () => unauthorized();
    }
  }
  return { auth, body, error };
}

export async function parseBody(request: Request) {
  return { body: await request.json(), error: undefined };
}
"""

RESPONSE = """export function unauthorized() { return new Response(null, { status: 401 }); }
export function json(data: unknown) { return Response.json(data); }
"""


def _project(tmp_path: Path, route: str, extra: dict[str, str] | None = None) -> Path:
    files = {
        "package.json": json.dumps({"name": "app", "dependencies": {"next": "15"}}),
        "tsconfig.json": json.dumps(
            {"compilerOptions": {"baseUrl": ".", "paths": {"@/*": ["./src/*"]}}}
        ),
        "src/lib/jwt.ts": JWT,
        "src/lib/auth.ts": AUTH,
        "src/lib/request.ts": REQUEST,
        "src/lib/response.ts": RESPONSE,
        "src/app/api/items/route.ts": route,
    }
    files.update(extra or {})
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return tmp_path / "src/app/api/items/route.ts"


def _d280(path: Path) -> list[int]:
    return [
        finding["line"]
        for finding in scan_typescript_file(str(path))[7]
        if finding["rule_id"] == "SKY-D280"
    ]


GUARDED = """import { z } from 'zod';
import { parseRequest } from '@/lib/request';
import { json } from '@/lib/response';
import { createItem } from '@/queries';

export async function POST(request: Request) {
  const schema = z.object({ name: z.string() });
  const { auth, body, error } = await parseRequest(request, schema);
  if (error) {
    return error();
  }
  const item = await createItem({ ...body, userId: auth.user.id });
  return json(item);
}
"""


def test_project_helper_that_verifies_a_jwt_and_rejects_is_authentication(tmp_path):
    assert _d280(_project(tmp_path, GUARDED)) == []


def test_identity_guard_on_helper_result_is_authentication(tmp_path):
    route = GUARDED.replace(
        "if (error) {\n    return error();\n  }",
        "if (!auth) return new Response(null, { status: 401 });",
    )
    assert _d280(_project(tmp_path, route)) == []


def test_helper_result_object_with_error_member_is_authentication(tmp_path):
    route = """import { parseRequest } from '@/lib/request';
import { createItem } from '@/queries';
export async function POST(request: Request) {
  const access = await parseRequest(request);
  if (access.error) return access.error();
  await createItem(access.body);
  return Response.json({ ok: true });
}
"""
    assert _d280(_project(tmp_path, route)) == []


def test_helper_without_identity_verification_is_not_authentication(tmp_path):
    route = GUARDED.replace("parseRequest } from", "parseBody } from").replace(
        "await parseRequest(request, schema)", "await parseBody(request)"
    )
    assert _d280(_project(tmp_path, route)) == [6]


def test_proven_helper_without_a_rejecting_guard_still_reports(tmp_path):
    route = GUARDED.replace(
        "if (error) {\n    return error();\n  }",
        "if (error) {\n    console.log(error);\n  }",
    )
    assert _d280(_project(tmp_path, route)) == [6]


def test_helper_called_with_skip_auth_still_reports(tmp_path):
    route = GUARDED.replace(
        "parseRequest(request, schema)",
        "parseRequest(request, schema, { skipAuth: true })",
    )
    assert _d280(_project(tmp_path, route)) == [6]


def test_guard_after_the_mutation_still_reports(tmp_path):
    route = """import { parseRequest } from '@/lib/request';
import { createItem } from '@/queries';
export async function POST(request: Request) {
  const { auth, body, error } = await parseRequest(request);
  await createItem(body);
  if (error) return error();
  return Response.json({ ok: true });
}
"""
    assert _d280(_project(tmp_path, route)) == [3]


def test_helper_chain_beyond_the_depth_bound_is_not_followed(tmp_path):
    hops = {
        f"src/lib/hop{index}.ts": (
            f"import {{ hop{index + 1} }} from './hop{index + 1}';\n"
            f"export async function hop{index}(r: Request) {{ return hop{index + 1}(r); }}\n"
        )
        for index in range(6)
    }
    hops["src/lib/hop6.ts"] = (
        "import { checkAuth } from './auth';\n"
        "export async function hop6(r: Request) { return checkAuth(r); }\n"
    )
    route = """import { hop0 } from '@/lib/hop0';
import { createItem } from '@/queries';
export async function POST(request: Request) {
  const auth = await hop0(request);
  if (!auth) return new Response(null, { status: 401 });
  await createItem({});
  return Response.json({ ok: true });
}
"""
    assert _d280(_project(tmp_path, route, hops)) == [3]


AUTHORIZED = """import { getContext } from '@/lib/context';
import { unauthorized } from '@/lib/response';
import { canUpdateItem } from '@/permissions';
import { updateItem } from '@/queries';

export async function POST(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { auth, body } = await getContext(request);
  const { id } = await params;
  if (!(await canUpdateItem(auth, id))) {
    return unauthorized();
  }
  await updateItem(id, body);
  return Response.json({ ok: true });
}
"""


def test_explicit_authorization_check_that_rejects_protects_the_mutation(tmp_path):
    assert _d280(_project(tmp_path, AUTHORIZED)) == []


def test_authorization_result_stored_then_checked(tmp_path):
    route = AUTHORIZED.replace(
        "if (!(await canUpdateItem(auth, id))) {",
        "const allowed = await canUpdateItem(auth, id);\n  if (!allowed) {",
    )
    assert _d280(_project(tmp_path, route)) == []


def test_authorization_check_that_does_not_reject_still_reports(tmp_path):
    route = AUTHORIZED.replace(
        "return unauthorized();", "console.warn('denied');\n    return;"
    )
    assert _d280(_project(tmp_path, route)) == [6]


def test_authorization_check_after_mutation_still_reports(tmp_path):
    route = """import { canUpdateItem } from '@/permissions';
import { updateItem } from '@/queries';
export async function POST(request: Request) {
  const body = await request.json();
  await updateItem(body.id, body);
  if (!(await canUpdateItem(null, body.id))) {
    return new Response(null, { status: 403 });
  }
  return Response.json({ ok: true });
}
"""
    assert _d280(_project(tmp_path, route)) == [3]


@pytest.mark.parametrize(
    "helper",
    [
        (
            "import { getServerSession } from 'next-auth';\n"
            "export async function requireUser() { return getServerSession(); }\n"
        ),
        (
            "import { jwtVerify } from 'jose';\n"
            "export const requireUser = async (token: string) => jwtVerify(token, key);\n"
        ),
        (
            "import * as jwt from 'jsonwebtoken';\n"
            "export async function requireUser(token: string) { return jwt.verify(token, 's'); }\n"
        ),
        (
            "import { createClient } from '@supabase/supabase-js';\n"
            "const supabase = createClient('u', 'k');\n"
            "export async function requireUser() { return supabase.auth.getUser(); }\n"
        ),
        "export { requireUser } from './inner';\n",
    ],
)
def test_recognised_verifiers_inside_project_helpers(tmp_path, helper):
    route = """import { requireUser } from '@/lib/session';
import { createItem } from '@/queries';
export async function POST(request: Request) {
  const user = await requireUser(request.headers.get('authorization'));
  if (!user) return new Response(null, { status: 401 });
  await createItem({});
  return Response.json({ ok: true });
}
"""
    extra = {
        "src/lib/session.ts": helper,
        "src/lib/inner.ts": (
            "import { getServerSession } from 'next-auth';\n"
            "export async function requireUser() { return getServerSession(); }\n"
        ),
    }
    assert _d280(_project(tmp_path, route, extra)) == []
