import pytest

from skylos.changemap import build_change_map, render_markdown, render_text
from test.test_changemap import repo, symbol, write

pytest.importorskip("tree_sitter")

AUTH = "export function requireAuth(user: unknown) {\n  if (!user) throw new UnauthorizedError('login');\n}\n"


def names(entries):
    return [e["name"] for e in entries]


def test_removed_require_auth_call_is_flagged_and_read_first(tmp_path):
    repo(tmp_path, {
        "lib/auth.ts": AUTH,
        "app/route.ts": (
            "import { requireAuth } from '../lib/auth';\n\n"
            "export async function POST(req: any) {\n  requireAuth(req.user);\n  return save(req);\n}\n\n"
            "function save(req: any) {\n  return req;\n}\n"
        ),
    })
    write(tmp_path, {"app/route.ts": (
        "import { requireAuth } from '../lib/auth';\n\n"
        "export async function POST(req: any) {\n  return save(req);\n}\n\n"
        "function save(req: any) {\n  return req;\n}\n"
    )})
    result = build_change_map(tmp_path, "HEAD")
    post = symbol(result, "app.route.POST")
    assert post["security_removed"] == ["lib.auth.requireAuth"]
    assert result["read_first"][0] == post["id"]
    assert post["id"] in result["flagged"]
    assert result["coverage"]["languages"] == ["TypeScript/JavaScript"]


def test_auth_call_moved_into_a_helper_is_not_flagged(tmp_path):
    repo(tmp_path, {
        "lib/auth.ts": AUTH,
        "app/route.ts": "import { requireAuth } from '../lib/auth';\n\nexport function POST(req: any) {\n  requireAuth(req.user);\n  return 1;\n}\n",
    })
    write(tmp_path, {"app/route.ts": (
        "import { requireAuth } from '../lib/auth';\n\n"
        "export function POST(req: any) {\n  guard(req);\n  return 1;\n}\n\n"
        "function guard(req: any) {\n  requireAuth(req.user);\n}\n"
    )})
    post = symbol(build_change_map(tmp_path, "HEAD"), "app.route.POST")
    assert post["calls_moved"] == ["lib.auth.requireAuth"]
    assert post["security_removed"] == []


def test_auth_import_swapped_for_a_same_named_local_stub_is_flagged(tmp_path):
    repo(tmp_path, {
        "lib/auth.ts": AUTH,
        "app/route.ts": "import { requireAuth } from '../lib/auth';\n\nexport function POST(req: any) {\n  requireAuth(req.user);\n  return 1;\n}\n",
    })
    write(tmp_path, {"app/route.ts": (
        "function requireAuth(user: unknown) {\n  return user;\n}\n\n"
        "export function POST(req: any) {\n  requireAuth(req.user);\n  return 1;\n}\n"
    )})
    result = build_change_map(tmp_path, "HEAD")
    post = symbol(result, "app.route.POST")
    assert post["security_removed"] == ["lib.auth.requireAuth"]
    assert post["id"] in result["flagged"]


FORBID = (
    "export async function DELETE(req: any) {\n"
    "  if (!req.user?.admin) {\n    return new Response('no', { status: 403 });\n  }\n"
    "  return remove(req);\n}\n\nfunction remove(req: any) {\n  return req;\n}\n"
)


def test_deleted_inline_403_response_is_a_removed_security_check(tmp_path):
    repo(tmp_path, {"app/admin.ts": FORBID})
    write(tmp_path, {"app/admin.ts": FORBID.replace(
        "  if (!req.user?.admin) {\n    return new Response('no', { status: 403 });\n  }\n", ""
    )})
    delete = symbol(build_change_map(tmp_path, "HEAD"), "app.admin.DELETE")
    assert delete["security_removed"] == ["inline 403 check"]


def test_inline_403_replaced_by_an_auth_wrapper_is_reported_as_replaced(tmp_path):
    repo(tmp_path, {"app/admin.ts": FORBID, "lib/with-auth.ts": "export const withAuth = (fn: any) => fn;\n"})
    write(tmp_path, {"app/admin.ts": (
        "import { withAuth } from '../lib/with-auth';\n\n"
        "export const DELETE = withAuth(async (req: any) => {\n  return remove(req);\n});\n\n"
        "function remove(req: any) {\n  return req;\n}\n"
    )})
    delete = symbol(build_change_map(tmp_path, "HEAD"), "app.admin.DELETE")
    assert delete["security_removed"] == []
    assert delete["guards_replaced_by"] == ["withAuth"]


def test_alias_js_extension_default_and_namespace_imports_find_callers(tmp_path):
    repo(tmp_path, {
        "tsconfig.json": '{"compilerOptions": {"baseUrl": ".", "paths": {"@/*": ["src/*"]}}}\n',
        "src/lib/price.ts": "export function total(items: number[]) {\n  return items.length;\n}\nexport default function fee() {\n  return 1;\n}\n",
        "src/a.ts": "import { total } from '@/lib/price';\n\nexport function a() {\n  return total([1]);\n}\n",
        "src/b.ts": "import { total } from './lib/price.js';\n\nexport function b() {\n  return total([2]);\n}\n",
        "src/c.ts": "import * as price from './lib/price';\n\nexport function c() {\n  return price.total([3]);\n}\n",
        "src/d.ts": "import fee from './lib/price';\n\nexport function d() {\n  return fee();\n}\n",
    })
    write(tmp_path, {"src/lib/price.ts": (
        "export function total(items: number[]) {\n  return items.length * 2;\n}\n"
        "export default function fee() {\n  return 2;\n}\n"
    )})
    result = build_change_map(tmp_path, "HEAD")
    assert names(symbol(result, "src.lib.price.total")["callers"]) == ["src.a.a", "src.b.b", "src.c.c"]
    assert names(symbol(result, "src.lib.price.fee")["callers"]) == ["src.d.d"]


def test_barrel_reexport_and_commonjs_require_find_callers(tmp_path):
    repo(tmp_path, {
        "lib/util.js": "function helper(x) {\n  return x;\n}\nmodule.exports = { helper };\n",
        "lib/fmt.ts": "export function fmt(x: string) {\n  return x;\n}\n",
        "lib/index.ts": "export * from './fmt';\n",
        "use.js": "const { helper } = require('./lib/util');\n\nfunction run() {\n  return helper(1);\n}\n",
        "page.ts": "import { fmt } from './lib';\n\nexport function page() {\n  return fmt('a');\n}\n",
    })
    write(tmp_path, {
        "lib/util.js": "function helper(x) {\n  return [x];\n}\nmodule.exports = { helper };\n",
        "lib/fmt.ts": "export function fmt(x: string) {\n  return x.trim();\n}\n",
    })
    result = build_change_map(tmp_path, "HEAD")
    assert names(symbol(result, "lib.fmt.fmt")["callers"]) == ["page.page"]
    assert names(symbol(result, "lib.util.helper")["callers"]) == ["use.run"]


SVC = "export class Svc {\n  constructor(private url: string) {}\n\n  attach(t: string) {\n    return t;\n  }\n}\n"


def test_constructor_and_typed_receiver_callers(tmp_path):
    repo(tmp_path, {
        "svc.ts": SVC,
        "use.ts": (
            "import { Svc } from './svc';\n\n"
            "export function make() {\n  return new Svc('u');\n}\n\n"
            "export function wire(svc: Svc) {\n  return svc.attach('t');\n}\n\n"
            "export function local() {\n  const s = new Svc('u');\n  return s.attach('x');\n}\n\n"
            "export function untyped(thing: any) {\n  return thing.attach('y');\n}\n"
        ),
    })
    write(tmp_path, {"svc.ts": SVC.replace("constructor(private url: string)", "constructor(private url: string, private retries = 0)").replace("return t;", "return [t];")})
    result = build_change_map(tmp_path, "HEAD")
    assert names(symbol(result, "svc.Svc.constructor")["callers"]) == ["use.local", "use.make"]
    attach = symbol(result, "svc.Svc.attach")
    assert names(attach["callers"]) == ["use.local", "use.wire"]
    assert names(attach["possible_callers"]) == ["use.untyped"]


def test_new_required_parameter_breaks_only_callers_that_pass_too_few(tmp_path):
    repo(tmp_path, {
        "api.ts": "export function fetchIt(url: string) {\n  return url;\n}\n",
        "use.ts": "import { fetchIt } from './api';\n\nexport function a() {\n  return fetchIt('x');\n}\n",
    })
    write(tmp_path, {"api.ts": "export function fetchIt(url: string, timeout: number) {\n  return url + timeout;\n}\n"})
    result = build_change_map(tmp_path, "HEAD")
    fetch = symbol(result, "api.fetchIt")
    assert fetch["signature_change"] == "breaking"
    assert fetch["breaking_callers"] == ["use.a"]
    assert fetch["id"] in result["flagged"]


def test_new_optional_parameter_lists_callers_using_the_default(tmp_path):
    repo(tmp_path, {
        "api.ts": "export function fetchIt(url: string) {\n  return url;\n}\n",
        "use.ts": "import { fetchIt } from './api';\n\nexport function a() {\n  return fetchIt('x');\n}\n",
    })
    write(tmp_path, {"api.ts": "export function fetchIt(url: string, timeout = 5) {\n  return url + timeout;\n}\n"})
    fetch = symbol(build_change_map(tmp_path, "HEAD"), "api.fetchIt")
    assert fetch["signature_change"] == "compatible"
    assert fetch["new_optional_params"] == ["timeout"]
    assert fetch["callers_not_updated"] == 1


def test_jsx_component_render_counts_as_a_caller(tmp_path):
    repo(tmp_path, {
        "components/Card.tsx": "export function Card({ title }: { title: string }) {\n  return <div>{title}</div>;\n}\n",
        "pages/home.tsx": "import { Card } from '../components/Card';\n\nexport default function Home() {\n  return <Card title='hi' />;\n}\n",
    })
    write(tmp_path, {"components/Card.tsx": "export function Card({ title }: { title: string }) {\n  return <h2>{title}</h2>;\n}\n"})
    card = symbol(build_change_map(tmp_path, "HEAD"), "components.Card.Card")
    assert names(card["callers"]) == ["pages.home.Home"]


def test_new_child_process_call_and_raw_html_are_risky(tmp_path):
    repo(tmp_path, {"tool.ts": "export function run(cmd: string) {\n  return cmd;\n}\n"})
    write(tmp_path, {"tool.ts": "import { exec } from 'child_process';\n\nexport function run(cmd: string) {\n  return exec(cmd);\n}\n"})
    result = build_change_map(tmp_path, "HEAD")
    run = symbol(result, "tool.run")
    assert run["risky_calls_added"] == ["child_process.exec"]
    assert run["id"] in result["flagged"]


def test_class_security_setting_read_by_a_method_is_flagged(tmp_path):
    base = "export class Agent {\n  permissionMode = 'plan';\n\n  args() {\n    return ['--mode', this.permissionMode];\n  }\n}\n"
    repo(tmp_path, {"agent.ts": base})
    write(tmp_path, {"agent.ts": base.replace("'plan'", "'bypass'")})
    result = build_change_map(tmp_path, "HEAD")
    agent = symbol(result, "agent.Agent")
    assert agent["values_changed"][0]["used_by"] == ["Agent.args"]
    assert agent["id"] in result["flagged"]


def test_deleted_export_still_imported_elsewhere_is_reported(tmp_path):
    repo(tmp_path, {
        "util.ts": "export function old() {\n  return 1;\n}\nexport function keep() {\n  return 2;\n}\n",
        "use.ts": "import { old } from './util';\n\nexport function use() {\n  return old();\n}\n",
    })
    write(tmp_path, {"util.ts": "export function keep() {\n  return 2;\n}\n"})
    old = symbol(build_change_map(tmp_path, "HEAD"), "util.old")
    assert old["status"] == "deleted"
    assert old["still_referenced_by"] == ["use.use"]


def test_mixed_python_and_typescript_change_lists_both_languages(tmp_path):
    repo(tmp_path, {"a.py": "def f():\n    return 1\n", "b.ts": "export function g() {\n  return 1;\n}\n"})
    write(tmp_path, {"a.py": "def f():\n    return 2\n", "b.ts": "export function g() {\n  return 2;\n}\n"})
    result = build_change_map(tmp_path, "HEAD")
    assert result["coverage"]["languages"] == ["Python", "TypeScript/JavaScript"]
    assert "Coverage: Python, TypeScript/JavaScript only" in render_text(result)


def test_removed_validation_throw_is_flagged(tmp_path):
    base = "export function parse(q: string) {\n  if (!q.trim()) {\n    throw new ValidationError('query must not be empty');\n  }\n  return q.split(' ');\n}\n"
    repo(tmp_path, {"q.ts": base})
    write(tmp_path, {"q.ts": "export function parse(q: string) {\n  return q.split(' ');\n}\n"})
    result = build_change_map(tmp_path, "HEAD")
    parse = symbol(result, "q.parse")
    assert parse["rejections_removed"] == ["throw ValidationError('query must not be empty')"]
    assert parse["id"] in result["flagged"]


def test_markdown_fences_typescript_and_jsx_code_in_their_own_language(tmp_path):
    repo(tmp_path, {
        "lib/auth.ts": AUTH,
        "app/route.ts": "import { requireAuth } from '../lib/auth';\n\nexport function POST(req: any) {\n  requireAuth(req.user);\n  return 1;\n}\n",
        "ui/Card.jsx": "export function Card() {\n  return <div>a</div>;\n}\n",
        "README.md": "a\n",
    })
    write(tmp_path, {
        "app/route.ts": "import { requireAuth } from '../lib/auth';\n\nexport function POST(req: any) {\n  return 1;\n}\n",
        "ui/Card.jsx": "export function Card() {\n  return <div>b</div>;\n}\n",
        "README.md": "b\n",
    })
    text = render_markdown(build_change_map(tmp_path, "HEAD"))
    assert "```ts\nexport function POST(req: any) {" in text
    assert "```jsx\nexport function Card() {" in text
    assert "```python" not in text
    assert "Not mapped: 1 file(s) that are not Python or TypeScript/JavaScript." in text
