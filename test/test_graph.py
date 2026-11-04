import http.client
import json
import subprocess
import threading

import pytest

from skylos.graph import build_graph
from skylos.graph.changes import build_changes
from skylos.graph.describe import apply_summaries, parse_summaries, pending
from skylos.graph.query import GraphIndex
from skylos.changemap.sameness import SAME_DOCS, SAME_RENAMED, same_logic
from skylos.graph.server import GraphServer
from skylos.graph.store import load_notes


def git(root, *args):
    return subprocess.run(
        ["git", "-c", "user.name=Skylos Test", "-c", "user.email=test@example.invalid", *args],
        cwd=root, capture_output=True, text=True, check=True,
    ).stdout.strip()


def write(root, files):
    for name, source in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source)  # skylos: ignore[SKY-D324] fixed paths under a fresh pytest tmp_path


def repo(root, files):
    write(root, files)
    git(root, "init", "-q")
    git(root, "add", ".")
    git(root, "commit", "-q", "-m", "base")
    return root


def edges(graph):
    return {tuple(edge) for edge in graph["edges"]}


STORE = (
    "class Base:\n"
    "    def save(self):\n"
    "        return 1\n\n"
    "    def kind(self):\n"
    "        return 'base'\n\n"
    "class Plain(Base):\n"
    "    kind = 'plain'\n\n"
    "    def describe(self):\n"
    "        return self.kind\n\n"
    "class Store(Base):\n"
    "    def __init__(self, path):\n"
    "        self.path = path\n\n"
    "    def load(self):\n"
    "        return self.read() + helper(2) + self.save()\n\n"
    "    def read(self):\n"
    "        return open(self.path).read()\n\n"
    "def helper(x):\n"
    "    return x * 2\n"
)
APP = (
    "from pkg.store import Store, helper\n"
    "from pkg import store as st\n\n"
    "def main(repo: Store):\n"
    "    s = Store('a')\n"
    "    s.load()\n"
    "    repo.read()\n"
    "    st.helper(3)\n"
    "    obj = make()\n"
    "    obj.unknown_method()\n"
    "    return helper(1)\n\n"
    "def make():\n"
    "    def inner():\n"
    "        return helper(5)\n"
    "    return inner()\n\n"
    "def peek(repo: Store) -> bool:\n"
    "    return isinstance(repo, Store) and repo.read() == ''\n"
)


def test_python_links_follow_imports_constructors_inheritance_and_annotations(tmp_path):
    write(tmp_path, {"pkg/__init__.py": "", "pkg/store.py": STORE, "pkg/app.py": APP})
    graph = build_graph(tmp_path)
    assert edges(graph) == {
        ("pkg.app.main", "pkg.app.make", "calls"),
        ("pkg.app.main", "pkg.store.Store", "creates"),
        ("pkg.app.main", "pkg.store.Store.load", "calls"),
        ("pkg.app.main", "pkg.store.Store.read", "calls"),
        ("pkg.app.main", "pkg.store.helper", "calls"),
        ("pkg.app.make", "pkg.store.helper", "calls"),
        ("pkg.app.peek", "pkg.store.Store", "uses"),
        ("pkg.app.peek", "pkg.store.Store.read", "calls"),
        ("pkg.store.Store", "pkg.store.Base", "inherits"),
        ("pkg.store.Plain", "pkg.store.Base", "inherits"),
        ("pkg.store.Store.load", "pkg.store.Base.save", "calls"),
        ("pkg.store.Store.load", "pkg.store.Store.read", "calls"),
        ("pkg.store.Store.load", "pkg.store.helper", "calls"),
    }


def test_typescript_links_follow_reexports_and_barrels(tmp_path):
    write(tmp_path, {
        "web/lib/math.ts": (
            "export function add(a: number, b: number): number {\n  return a + b;\n}\n"
            "export class Calc {\n  total = 0;\n  plus(n: number) {\n    this.total = add(this.total, n);\n    return this;\n  }\n}\n"
        ),
        "web/lib/index.ts": 'export * from "./math";\nexport { add as sum } from "./math";\n',
        "web/app.ts": (
            'import { Calc, sum } from "./lib";\n'
            "export function run(): number {\n  const c = new Calc();\n  c.plus(2);\n  return sum(1, 2);\n}\n"
        ),
    })
    graph = build_graph(tmp_path)
    assert edges(graph) == {
        ("web.app.run", "web.lib.math.Calc", "creates"),
        ("web.app.run", "web.lib.math.Calc.plus", "calls"),
        ("web.app.run", "web.lib.math.add", "calls"),
        ("web.lib.math.Calc.plus", "web.lib.math.add", "calls"),
    }


def test_rebuild_reparses_only_edited_files_and_updates_links(tmp_path):
    write(tmp_path, {"pkg/__init__.py": "", "pkg/store.py": STORE, "pkg/app.py": APP})
    first = build_graph(tmp_path)
    assert ("pkg.app.make", "pkg.store.helper", "calls") in edges(first)
    write(tmp_path, {"pkg/app.py": APP.replace("        return helper(5)\n", "        return 5\n")})
    second = build_graph(tmp_path)
    assert second["coverage"]["reused"] == second["coverage"]["files"] - 1
    assert ("pkg.app.make", "pkg.store.helper", "calls") not in edges(second)
    assert ("pkg.app.main", "pkg.store.helper", "calls") in edges(second)


def snippet(code):
    return {"code": code, "truncated": False}


@pytest.mark.parametrize(
    ("before", "after", "expected"),
    [
        ("def f(a):\n    total = a + 1\n    return total\n", "def f(a):\n    result = a + 1\n    return result\n", SAME_RENAMED),
        ('def f(a):\n    """Old."""\n    return a\n', 'def f(a):\n    """New words."""\n    return a\n', SAME_DOCS),
        ("def f(a):\n    return a\n", "def f(b):\n    return b\n", None),
        ("def f(a):\n    x = a\n    return x + n\n", "def f(a):\n    n = a\n    return n + n\n", None),
        ("def f(a):\n    x = 1\n    return a + x\n", "def f(a):\n    x = 2\n    return a + x\n", None),
        ("def f(items):\n    size = 0\n    return size + len(items)\n", "def f(items):\n    len = 0\n    return len + len(items)\n", None),
        ("def f(a):\n    return a.total\n", "def f(a):\n    return a.amount\n", None),
        ("def f(a):\n    return a + LIMIT\n", "def f(a):\n    return a + MAXIMUM\n", None),
        ("def f(a):\n    return helper(a)\n", "def f(a):\n    return other(a)\n", None),
    ],
    ids=[
        "renamed-local", "docstring-only", "renamed-parameter", "captures-global", "changed-constant",
        "shadows-builtin", "changed-attribute", "swapped-global", "swapped-callee",
    ],
)
def test_same_logic_is_claimed_only_when_proven(before, after, expected):
    assert same_logic(snippet(before), snippet(after)) == expected


def test_same_logic_refuses_truncated_code():
    before = {"code": "def f(a):\n    x = a\n    return x\n", "truncated": True}
    after = {"code": "def f(a):\n    y = a\n    return y\n", "truncated": False}
    assert same_logic(before, after) is None


BASE_FILES = {
    "calc/__init__.py": "",
    "calc/core.py": (
        "from calc.strict import validate\n\n"
        "def add(a, b):\n    total = a + b\n    return total\n\n"
        "def scale(value, factor):\n    return value * factor\n\n"
        "def label(value):\n    \"\"\"Old text.\"\"\"\n    return str(value)\n\n"
        "def check(value):\n    return validate(value)\n"
    ),
    "calc/strict.py": "def validate(value):\n    if value < 0:\n        raise ValueError(value)\n    return value\n",
    "calc/loose.py": "",
    "tests/test_core.py": (
        "from calc.core import add, scale\n\n"
        "def test_add():\n    assert add(2, 3) == 5\n\n"
        "def test_scale():\n    assert scale(2, 3) == 6\n"
    ),
}


def test_change_verdicts_end_to_end(tmp_path):
    repo(tmp_path, BASE_FILES)
    write(tmp_path, {
        "calc/core.py": (
            "def add(a, b):\n    result = a + b\n    return result\n\n"
            "def scale(value, factor):\n    return value * factor + 1\n\n"
            "def label(value):\n    \"\"\"Clearer text.\"\"\"\n    return str(value)\n"
        ),
        "calc/loose.py": "def validate(value):\n    return value\n\n\ndef check(value):\n    return validate(value)\n",
        "tests/test_core.py": BASE_FILES["tests/test_core.py"].replace("== 6", "== 7"),
    })
    graph = build_graph(tmp_path)
    changes = build_changes(tmp_path, "HEAD", GraphIndex(tmp_path, graph, load_notes(tmp_path)))
    verdicts = {(s["file"], s["name"]): s for s in changes["symbols"] if not s["is_test"]}
    assert verdicts[("calc/core.py", "add")]["verdict"] == "same_renamed"
    assert verdicts[("calc/core.py", "label")]["verdict"] == "same_docs"
    scale = verdicts[("calc/core.py", "scale")]
    assert scale["verdict"] == "changed"
    assert any("Tests now expect scale(2, 3) to give 7 (was 6)" in line for line in scale["evidence"])
    moved = verdicts[("calc/loose.py", "check")]
    assert moved["same_logic"] is False
    assert moved["verdict"] == "changed"


def test_descriptions_go_stale_when_code_changes(tmp_path):
    write(tmp_path, {"pkg/__init__.py": "", "pkg/store.py": STORE, "pkg/app.py": APP})
    graph = build_graph(tmp_path)
    index = GraphIndex(tmp_path, graph, load_notes(tmp_path))
    assert parse_summaries('{"items": [{"id": "pkg.nope", "summary": "Made up."}, {"id": "pkg.store.helper", "summary": ""}]}', set(index.nodes)) == {}
    assert apply_summaries(tmp_path, index, {"pkg.store.helper": "Doubles a number."}, "human") == 1
    assert "pkg.store.helper" not in pending(GraphIndex.load(tmp_path))
    write(tmp_path, {"pkg/store.py": STORE.replace("return x * 2", "return x * 3")})
    build_graph(tmp_path)
    fresh = GraphIndex.load(tmp_path)
    assert fresh.note("pkg.store.helper")["stale"] is True
    assert "pkg.store.helper" in pending(fresh)


def test_expected_outputs_attach_to_the_function_the_test_calls(tmp_path):
    write(tmp_path, BASE_FILES)
    graph = build_graph(tmp_path)
    cases = graph["expectations"]["calc.core.add"]
    assert cases[0]["call"] == "add(2, 3)"
    assert cases[0]["expected"] == ["5"]


def _request(port, method, path, headers=None, body=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    data = response.read()
    connection.close()
    return response.status, data


def test_viewer_requires_its_token_and_a_local_host(tmp_path):
    write(tmp_path, {"pkg/__init__.py": "", "pkg/store.py": STORE, "pkg/app.py": APP})
    build_graph(tmp_path)
    server = GraphServer(tmp_path, 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        token = {"X-Skylos-Token": server.token}
        assert _request(port, "GET", "/api/node?id=pkg.store.helper")[0] == 403
        assert _request(port, "GET", "/api/node?id=pkg.store.helper", {**token, "Host": f"attacker.example:{port}"})[0] == 403
        status, data = _request(port, "GET", "/api/node?id=pkg.store.helper", token)
        assert status == 200
        assert json.loads(data)["node"]["name"] == "helper"
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        connection.request("GET", f"/?token={server.token}")
        response = connection.getresponse()
        response.read()
        cookie = response.getheader("Set-Cookie").split(";")[0]
        connection.close()
        assert "HttpOnly" in response.getheader("Set-Cookie")
        assert _request(port, "GET", "/api/node?id=pkg.store.helper", {"Cookie": cookie})[0] == 200
        assert _request(port, "GET", "/api/node?id=pkg.store.helper", {"Cookie": cookie.split("=")[0] + "=wrong"})[0] == 403
        assert _request(port, "POST", "/api/note", {**token, "Content-Type": "text/plain"}, "x")[0] == 415
        body = json.dumps({"id": "pkg.store.helper", "text": "Doubles a number."})
        assert _request(port, "POST", "/api/note", {**token, "Content-Type": "application/json"}, body)[0] == 200
        assert load_notes(tmp_path)["nodes"]["pkg.store.helper"]["source"] == "human"
    finally:
        server.shutdown()
        server.server_close()


def test_graph_refuses_to_write_through_a_symlinked_output_folder(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    project = tmp_path / "project"
    write(project, {"app.py": "def run():\n    return 1\n"})
    (project / ".skylos").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        build_graph(project)
    assert list(outside.iterdir()) == []


def test_graph_skips_source_files_that_point_outside_the_repository(tmp_path):
    secret = tmp_path / "elsewhere" / "secret.py"
    write(tmp_path, {"elsewhere/secret.py": "def leaked():\n    return 'token'\n"})
    project = repo(tmp_path / "project", {"app.py": "def run():\n    return 1\n"})
    (project / "linked.py").symlink_to(secret)
    graph = build_graph(project)
    assert [n["id"] for n in graph["nodes"]] == ["app.run"]


CHANGED_FILES = {
    "calc/core.py": (
        "def add(a, b):\n    result = a + b\n    return result\n\n"
        "def scale(value, factor):\n    return value * factor + 1\n\n"
        "def label(value):\n    \"\"\"Clearer text.\"\"\"\n    return str(value)\n"
    ),
    "tests/test_core.py": BASE_FILES["tests/test_core.py"].replace("== 6", "== 7"),
}


def committed_change(root):
    repo(root, BASE_FILES)
    base = git(root, "rev-parse", "HEAD")
    write(root, CHANGED_FILES)
    git(root, "commit", "-qam", "change")
    return base, git(root, "rev-parse", "HEAD")


def run_cli(argv, capsys):
    from skylos.commands.graph_cmd import run_graph_command

    code = run_graph_command(argv)
    return code, capsys.readouterr()


def test_cloud_report_carries_verdicts_but_no_source_code(tmp_path, capsys):
    base, head = committed_change(tmp_path)
    code, captured = run_cli(["report", str(tmp_path), "--base", base, "--pr-number", "4"], capsys)
    assert code == 0
    report = json.loads(captured.out)
    assert report["commit"] == head
    assert report["pr_number"] == 4
    assert report["tests_changed"] == 1
    verdicts = {s["name"]: s["verdict"] for s in report["symbols"]}
    assert verdicts["add"] == "same_renamed"
    assert verdicts["label"] == "same_docs"
    assert verdicts["scale"] == "changed"
    assert all(not s["file"].startswith("tests/") for s in report["symbols"])
    assert "value * factor + 1" not in captured.out
    assert not any(key in s for s in report["symbols"] for key in ("before", "after", "code"))
    wrong, captured = run_cli(["report", str(tmp_path), "--base", base, "--commit", base], capsys)
    assert wrong == 2


class FakeCloud:
    def __init__(self, replies):
        import http.server

        self.replies = list(replies)
        self.requests = []
        cloud = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                cloud.requests.append({
                    "path": self.path,
                    "auth": self.headers.get("Authorization"),
                    "body": json.loads(self.rfile.read(length)),
                })
                status, body = cloud.replies.pop(0)
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                return None

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def cloud(monkeypatch):
    import skylos.api

    servers = []

    def start(*replies):
        fake = FakeCloud(replies)
        servers.append(fake)
        monkeypatch.setattr(skylos.api, "BASE_URL", fake.url)
        monkeypatch.setattr(skylos.api, "get_project_token", lambda: "sk-test")
        monkeypatch.setattr(skylos.api, "get_credit_balance", lambda token=None: {"balance": 5})
        return fake

    yield start
    for fake in servers:
        fake.close()


def test_describe_via_skylos_saves_only_ids_it_sent_and_stops_without_credits(tmp_path, capsys, cloud):
    write(tmp_path, {"pkg/__init__.py": "", "pkg/store.py": STORE, "pkg/app.py": APP})
    build_graph(tmp_path)
    fake = cloud(
        (200, {"summaries": {"pkg.store.helper": "Doubles a number.", "pkg.invented": "Made up."},
               "notes": {}, "credits_used": 1, "balance_after": 4, "model": "gpt-4o-mini"}),
        (402, {"error": "Insufficient credits"}),
    )
    code, captured = run_cli(["describe", "--path", str(tmp_path), "--via", "skylos", "--yes"], capsys)
    assert code == 0
    sent = fake.requests[0]
    assert sent["path"] == "/api/graph/describe"
    assert sent["auth"] == "Bearer sk-test"
    assert sent["body"]["kind"] == "symbols"
    assert "pkg.store.helper" in {item["id"] for item in sent["body"]["items"]}
    notes = load_notes(tmp_path)["nodes"]
    assert notes["pkg.store.helper"]["text"] == "Doubles a number."
    assert notes["pkg.store.helper"]["source"] == "skylos:gpt-4o-mini"
    assert "pkg.invented" not in notes
    code, captured = run_cli(["describe", "--path", str(tmp_path), "--via", "skylos", "--yes"], capsys)
    assert code == 2
    assert "Not enough credits" in captured.err


def test_upload_needs_a_commit_and_sends_the_report_with_the_login_token(tmp_path, capsys, cloud):
    base, head = committed_change(tmp_path)
    write(tmp_path, {"calc/strict.py": "def validate(value):\n    return value\n"})
    fake = cloud((200, {"report_id": "r1", "charged": 1, "comment": "skipped", "url": "https://skylos.dev/x"}))
    code, captured = run_cli([str(tmp_path), "--since", base, "--upload"], capsys)
    assert code == 2
    assert "Commit your changes first" in captured.err
    assert fake.requests == []
    git(tmp_path, "checkout", "--", "calc/strict.py")
    code, captured = run_cli([str(tmp_path), "--since", base, "--upload", "--pr-number", "3"], capsys)
    assert code == 0
    sent = fake.requests[0]
    assert sent["path"] == "/api/graph/reports"
    assert sent["auth"] == "Bearer sk-test"
    assert sent["body"]["kind"] == "skylos-graph-report"
    assert sent["body"]["commit"] == head
    assert sent["body"]["pr_number"] == 3
    assert "1 credit used" in captured.out


def test_describe_changes_via_skylos_sends_callers_and_keeps_only_their_impact(tmp_path, capsys, cloud):
    repo(tmp_path, BASE_FILES)
    write(tmp_path, {"calc/strict.py": BASE_FILES["calc/strict.py"].replace("value < 0", "value <= 0")})
    assert run_cli([str(tmp_path), "--since", "HEAD"], capsys)[0] == 0
    code, captured = run_cli(["pending", "--changes", "--format", "json", "--path", str(tmp_path)], capsys)
    key = json.loads(captured.out)["items"][0]["id"]
    impact = [
        {"id": "calc.core.check", "effect": "check now refuses 0 as well as negative numbers."},
        {"id": "calc.core.add", "effect": "Never offered."},
    ]
    fake = cloud((200, {"notes": {key: {"before": "Refused negatives.", "after": "Refuses zero too.", "same_behaviour": "no",
                                        "why": "validate(0) now raises.", "impact": impact}},
                        "summaries": {}, "credits_used": 1, "balance_after": 4, "model": "m"}))
    code, captured = run_cli(["describe", "--changes", "--path", str(tmp_path), "--via", "skylos", "--yes"], capsys)
    assert code == 0
    sent = fake.requests[0]["body"]["items"][0]
    assert [(row["id"], row["steps"]) for row in sent["callers"]] == [("calc.core.check", 1)]
    saved = load_notes(tmp_path)["changes"][key]
    assert [row["id"] for row in saved["impact"]] == ["calc.core.check"]


def test_lookups_see_code_edited_after_the_last_build(tmp_path):
    from skylos.graph import fresh_index
    from skylos.graph.describe import apply_summaries

    write(tmp_path, {"pkg/__init__.py": "", "pkg/calc.py": "def double(x):\n    return x * 2\n"})
    build_graph(tmp_path)
    index = fresh_index(tmp_path)
    apply_summaries(tmp_path, index, {"pkg.calc.double": "Doubles a number."}, "agent")
    assert pending(fresh_index(tmp_path)) == []

    write(tmp_path, {"pkg/calc.py": "def double(x):\n    return x * 2 + 1\n\n\ndef half(x):\n    return x / 2\n"})
    index = fresh_index(tmp_path)

    assert sorted(pending(index)) == ["pkg.calc.double", "pkg.calc.half"]
    assert index.note("pkg.calc.double")["stale"] is True


def test_cloud_without_graph_support_says_so_plainly(monkeypatch):
    import requests

    from skylos.graph import cloud

    class Reply:
        def __init__(self, status, body):
            self.status_code = status
            self._body = body

        def json(self):
            return self._body

    replies = [Reply(404, "<html>not found</html>"), Reply(404, {"error": "Project not found."})]
    monkeypatch.setattr(requests, "post", lambda *args, **kwargs: replies.pop(0))

    missing = cloud.upload_report("token", {"symbols": []})
    explained = cloud.upload_report("token", {"symbols": []})

    assert (missing.ok, missing.status) == (False, 404)
    assert missing.message == "Skylos Cloud does not accept this yet: its codebase graph support has not shipped."
    assert explained.message == "Project not found."
