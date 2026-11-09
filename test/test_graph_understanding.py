import http.client
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import skylos.graph.build as build_module
from skylos.graph import build_graph
from skylos.graph.other_languages import grammar_ready
from skylos.graph.query import GraphIndex
from skylos.graph.rank import order_by_importance
from skylos.graph.server import GraphServer
from skylos.graph.store import load_notes

ROOT = Path(__file__).resolve().parents[1]


def write(root, files):
    for name, source in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source)  # skylos: ignore[SKY-D324] fixed paths under a fresh pytest tmp_path


def index_for(root):
    graph = build_graph(root)
    return graph, GraphIndex(root, graph, load_notes(root))


def area_ids(index, prefix):
    return {index.node_area[n] for n in index.nodes if n.startswith(prefix) and n in index.node_area}


def needs(*languages):
    missing = [language for language in languages if not grammar_ready(language)]
    return pytest.mark.skipif(bool(missing), reason=f"tree-sitter grammar missing: {missing}")


PY_TWO_PACKAGES = {
    "billing/__init__.py": "",
    "billing/util.py": "def helper(items):\n    return len(items)\n\ndef round_cents(x):\n    return helper([x])\n",
    "billing/invoice.py": (
        "from billing.util import helper\n\n"
        "def total(items):\n    return helper(items) + tax(items)\n\n"
        "def tax(items):\n    return helper(items) * 2\n\n"
        "def render(items):\n    return total(items) + tax(items)\n\n"
        "class Invoice:\n    def amount(self):\n        return total([]) + render([])\n"
    ),
    "search/__init__.py": "",
    "search/util.py": "def helper(text):\n    return len(text)\n\ndef tokenize(text):\n    return helper(text)\n",
    "search/index.py": (
        "from search.util import helper\n\n"
        "def query(text):\n    return helper(text) + rank(text)\n\n"
        "def rank(text):\n    return helper(text) * 3\n\n"
        "def highlight(text):\n    return query(text) + rank(text)\n\n"
        "class Index:\n    def lookup(self):\n        return query('') + highlight('')\n"
    ),
}

GO_TWO_PACKAGES = {
    "go.mod": "module example.com/shop\n",
    "billing/invoice.go": "package billing\n\nfunc Total() int { return helper() + Tax() }\n\nfunc Tax() int { return helper() * 2 }\n",
    "billing/util.go": "package billing\n\nfunc helper() int { return 1 }\n",
    "search/index.go": "package search\n\nfunc Query() int { return helper() + Rank() }\n\nfunc Rank() int { return helper() }\n",
    "search/util.go": "package search\n\nfunc helper() int { return 2 }\n",
}


def test_areas_never_merge_unrelated_modules_that_share_a_helper_name(tmp_path):
    write(tmp_path, PY_TWO_PACKAGES)
    _graph, index = index_for(tmp_path)
    billing = area_ids(index, "billing.")
    search = area_ids(index, "search.")
    assert billing and search
    assert billing.isdisjoint(search)
    names = [area["name"] for area in index.areas()]
    assert len(names) == len(set(names))
    assert index.area_of("billing.util.helper")["id"] != index.area_of("search.util.helper")["id"]


@needs("go")
def test_go_name_links_stay_inside_their_package_and_areas_stay_apart(tmp_path):
    write(tmp_path, GO_TWO_PACKAGES)
    graph, index = index_for(tmp_path)
    assert graph["edges"] == []
    assert graph["name_edges"] == [
        ["billing.invoice_go.Tax", "billing.util_go.helper", "calls"],
        ["billing.invoice_go.Total", "billing.invoice_go.Tax", "calls"],
        ["billing.invoice_go.Total", "billing.util_go.helper", "calls"],
        ["search.index_go.Query", "search.index_go.Rank", "calls"],
        ["search.index_go.Query", "search.util_go.helper", "calls"],
        ["search.index_go.Rank", "search.util_go.helper", "calls"],
    ]
    assert area_ids(index, "billing.").isdisjoint(area_ids(index, "search."))


def test_areas_are_deterministic_keep_ids_after_a_small_edit_and_are_reused(tmp_path, monkeypatch):
    write(tmp_path, PY_TWO_PACKAGES)
    graph, index = index_for(tmp_path)
    dumped = tmp_path / "graph-input.json"
    dumped.write_text(json.dumps({"nodes": graph["nodes"], "edges": graph["edges"]}))  # skylos: ignore[SKY-D324] fixed path under a fresh pytest tmp_path
    script = (
        "import json, sys\n"
        "from skylos.graph.areas import compute_areas\n"
        "data = json.load(open(sys.argv[1]))\n"
        "nodes = {n['id']: n for n in data['nodes']}\n"
        "print(json.dumps(compute_areas(nodes, data['edges'], []), sort_keys=True))\n"
    )
    outputs = []
    for seed in ("1", "2"):
        env = dict(os.environ, PYTHONHASHSEED=seed, PYTHONPATH=str(ROOT))
        result = subprocess.run([sys.executable, "-c", script, str(dumped)], capture_output=True, text=True, env=env, check=True)
        outputs.append(result.stdout)
    assert outputs[0] == outputs[1]
    before = dict(index.node_area)
    write(tmp_path, {"search/index.py": PY_TWO_PACKAGES["search/index.py"] + "\ndef suggest(text):\n    return helper(text)\n"})
    _graph, edited = index_for(tmp_path)
    for node_id, area_id in before.items():
        assert edited.node_area[node_id] == area_id
    assert edited.node_area["search.index.suggest"] == edited.node_area["search.util.helper"]
    assert sorted(area["id"] for area in edited.areas()) == sorted(area["id"] for area in index.areas())

    def refuse(*args, **kwargs):
        raise AssertionError("areas were recomputed although the graph did not change")

    monkeypatch.setattr(build_module, "compute_areas", refuse)
    _graph, again = index_for(tmp_path)
    assert again.node_area == edited.node_area


RANKED = {
    "app/__init__.py": "",
    "app/cli.py": "from app.core import run\n\ndef main():\n    return run()\n",
    "app/core.py": "def run():\n    return step_one() + step_two()\n\ndef step_one():\n    return 1\n\ndef step_two():\n    return step_one() + 1\n",
    "app/testing.py": "def build_fake():\n    return {'fake': True}\n",
    "tests/helpers.py": "def make_fixture():\n    return {'x': 1}\n",
    "tests/test_app.py": "from app.core import run\nfrom app.testing import build_fake\nfrom tests.helpers import make_fixture\n\n" + "".join(
        f"def test_{n}():\n    assert make_fixture() and build_fake() and run()\n\n" for n in range(40)
    ),
}


def test_ranking_keeps_production_entry_points_above_test_only_helpers(tmp_path):
    write(tmp_path, RANKED)
    _graph, index = index_for(tmp_path)
    scores = index.importance()
    assert "tests.helpers.make_fixture" not in scores
    assert scores["app.cli.main"] > scores["app.testing.build_fake"]
    assert order_by_importance(index, ["tests.helpers.make_fixture", "app.cli.main"]) == ["app.cli.main", "tests.helpers.make_fixture"]
    ranked_ids = [item["id"] for item in index.ranked(20)]
    assert ranked_ids.index("app.cli.main") < ranked_ids.index("app.testing.build_fake")


def test_relevant_code_for_a_file_fits_the_budget_and_skips_the_file_itself(tmp_path):
    write(tmp_path, RANKED)
    _graph, index = index_for(tmp_path)
    found = index.relevant(["./app/cli.py"], budget=400)
    assert found["files"] == ["app/cli.py"]
    assert found["items"][0]["id"] == "app.core.run"
    assert "used by the given files" in found["items"][0]["relation"]
    assert all(item["file"] != "app/cli.py" for item in found["items"])
    assert found["used_tokens"] <= 400
    assert len(index.relevant(["app/cli.py"], budget=12)["items"]) == 1
    missing = index.relevant(["nope.py"])
    assert missing["unknown_files"] == ["nope.py"]
    assert missing["files"] == []


GO_COLLISION = {
    "go.mod": "module example.com/demo\n",
    "a/a.go": (
        "package a\n\nimport (\n\t\"fmt\"\n\n\t\"example.com/demo/b\"\n)\n\n"
        "func Run() {\n\thelper()\n\tb.Do()\n\tfmt.Println(\"x\")\n}\n\nfunc helper() {}\n"
    ),
    "b/b.go": "package b\n\nfunc Do() {}\n",
    "c/c.go": "package c\n\nfunc Println(args ...any) {}\n",
}


@needs("go")
def test_name_matched_links_are_never_reported_as_resolved(tmp_path):
    write(tmp_path, GO_COLLISION)
    graph, index = index_for(tmp_path)
    assert graph["edges"] == []
    assert graph["name_edges"] == [
        ["a.a_go.Run", "a.a_go.helper", "calls"],
        ["a.a_go.Run", "b.b_go.Do", "calls"],
    ]
    run = index.card("a.a_go.Run", with_code=False)
    assert run["uses"] == []
    assert {item["id"] for item in run["uses_name"]} == {"a.a_go.helper", "b.b_go.Do"}
    assert all(item["match"] == "name" for item in run["uses_name"])
    done = index.card("b.b_go.Do", with_code=False)
    assert done["used_by"] == []
    assert [item["id"] for item in done["used_by_name"]] == ["a.a_go.Run"]
    impact = index.impact("b.b_go.Do")
    assert impact["callers_by_distance"] == []
    assert impact["total"] == 0
    assert [(item["id"], item["steps"], item["match"]) for item in impact["possible_callers"]] == [("a.a_go.Run", 1, "name")]
    overview = index.overview()
    assert overview["links"] == 0
    assert overview["name_links"] == 2


GO_EVIDENCE = {
    "go.mod": "module example.com/shop\n",
    "store/store.go": (
        "package store\n\n"
        "type Disk struct{}\n\nfunc (d *Disk) Close() error { return nil }\n\n"
        "type Net struct{}\n\nfunc (n *Net) Close() error { return nil }\n\n"
        "type Mux struct{}\n\nfunc (m *Mux) Get(pattern string, h func()) {}\n\n"
        "type Cache struct{}\n\nfunc (c *Cache) Fetch(key string, ttl int) {}\n\n"
        "func NewMux() *Mux { return &Mux{} }\n"
    ),
    "store/use.go": (
        "package store\n\nimport \"sync\"\n\n"
        "func Shutdown(pool *sync.Pool) {\n"
        "\tfor _, c := range lookup() {\n\t\tc.Close()\n\t\tc.Flush()\n\t}\n"
        "\tfor _, r := range lookup() {\n\t\tr.Fetch()\n\t}\n"
        "\tpool.Get()\n\td := &Disk{}\n\td.Close()\n\tm := NewMux()\n\tm.Get(\"/\", nil)\n}\n"
    ),
    "store/fake_test.go": "package store\n\ntype fake struct{}\n\nfunc (f *fake) Flush() {}\n",
}


@needs("go")
def test_name_links_need_one_candidate_with_matching_arguments_and_no_outside_type(tmp_path):
    write(tmp_path, GO_EVIDENCE)
    graph, _index = index_for(tmp_path)
    assert graph["name_edges"] == [
        ["store.store_go.NewMux", "store.store_go.Mux", "creates"],
        ["store.use_go.Shutdown", "store.store_go.Disk", "creates"],
        ["store.use_go.Shutdown", "store.store_go.Disk.Close", "calls"],
        ["store.use_go.Shutdown", "store.store_go.Mux.Get", "calls"],
        ["store.use_go.Shutdown", "store.store_go.NewMux", "calls"],
    ]
    assert graph["coverage"]["name_links"]["ambiguous"] == 1


OTHER_LANGUAGES = {
    "src/a/b/Foo.java": (
        "package a.b;\nimport a.c.Helper;\n/** Docs here. */\n"
        "public class Foo extends Base implements Runnable {\n"
        "  public Foo(int x) { this(x, 2); }\n  public Foo(int x, int y) {}\n"
        "  @Override public void run() { helper(); this.go(); Helper.make(); new Bar(); list.get(0); }\n"
        "  static int helper() { return 1; }\n  void go() {}\n}\n"
    ),
    "src/a/c/Helper.java": "package a.c;\npublic class Helper { static void make() {} }\n",
    "src/a/b/Bar.java": "package a.b;\nclass Bar {}\nclass Base { void go() {} }\n",
    "src/lib.rs": (
        "mod util { pub fn helper() {} }\nstruct Foo;\n"
        "impl Foo { pub fn new() -> Self { util::helper(); Self::other(); Foo } fn other() {} }\n"
        "impl Display for Foo { fn fmt(&self) { self.other(); helper(); println!(\"x\"); } }\n"
        "trait Display { fn fmt(&self); }\n"
        "#[cfg(test)]\nmod tests { #[test] fn it_works() { super::helper(); } }\nfn helper() {}\n"
    ),
    "src/Models/User.php": (
        "<?php\nnamespace App\\Models;\nuse App\\Util\\Helper;\n"
        "class User extends Model implements Arrayable {\n"
        "  public function save(): int { $this->validate(); Helper::run(); self::boot(); helper(); new Post(); $x?->go(); return 1; }\n"
        "  public function validate() {}\n  public static function boot() {}\n}\nfunction helper() {}\n"
    ),
    "src/Util/Helper.php": "<?php\nnamespace App\\Util;\nclass Helper { public static function run() {} }\nclass Post {}\n",
}


@needs("java", "rust", "php")
def test_java_rust_and_php_definitions_and_name_links(tmp_path):
    write(tmp_path, OTHER_LANGUAGES)
    graph, index = index_for(tmp_path)
    java = "src.a.b.Foo_java.Foo"
    rust = "src.lib_rs"
    php = "src.Models.User_php"
    assert {tuple(edge) for edge in graph["name_edges"]} == {
        (java, "src.a.b.Bar_java.Base", "inherits"),
        (f"{java}.run", "src.a.b.Bar_java.Bar", "creates"),
        (f"{java}.run", f"{java}.go", "calls"),
        (f"{java}.run", f"{java}.helper", "calls"),
        (f"{java}.run", "src.a.c.Helper_java.Helper.make", "calls"),
        (f"{rust}.Foo", f"{rust}.Display", "inherits"),
        (f"{rust}.Foo.fmt", f"{rust}.Foo.other", "calls"),
        (f"{rust}.Foo.new", f"{rust}.Foo.other", "calls"),
        (f"{rust}.Foo.new", f"{rust}.util.helper", "calls"),
        (f"{rust}.Foo.fmt", f"{rust}.helper", "calls"),
        (f"{rust}.tests.it_works", f"{rust}.helper", "calls"),
        (f"{php}.User.save", f"{php}.User.validate", "calls"),
        (f"{php}.User.save", f"{php}.User.boot", "calls"),
        (f"{php}.User.save", f"{php}.helper", "calls"),
        (f"{php}.User.save", "src.Util.Helper_php.Helper.run", "calls"),
    }
    assert f"{java}.Foo" in index.nodes and f"{java}.Foo~2" in index.nodes
    assert index.nodes[f"{rust}.tests.it_works"]["is_test"] is True
    assert index.nodes[java]["doc"] == "Docs here."
    assert graph["edges"] == []


def test_other_language_files_do_not_change_python_links(tmp_path):
    python = {
        "core/__init__.py": "",
        "core/models.py": "class Base:\n    def save(self):\n        return 1\n",
        "pkg/__init__.py": "",
        "pkg/other.py": "class Child(Base):\n    def go(self):\n        return self.save()\n",
    }
    alone = tmp_path / "alone"
    mixed = tmp_path / "mixed"
    write(alone, python)
    write(mixed, dict(python, **{"src/Base.java": "class Base { void save() {} }\n", "main.go": "package main\n\ntype Base struct{}\n"}))
    alone_graph = build_graph(alone)
    mixed_graph = build_graph(mixed)
    assert ["pkg.other.Child", "core.models.Base", "inherits"] in alone_graph["edges"]
    assert mixed_graph["edges"] == alone_graph["edges"]
    assert mixed_graph["expectations"] == alone_graph["expectations"]
    python_nodes = [n for n in mixed_graph["nodes"] if n["language"] == "python"]
    assert python_nodes == alone_graph["nodes"]


def _get(port, path, headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    connection.request("GET", path, headers=dict({"Host": f"127.0.0.1:{port}"}, **(headers or {})))
    response = connection.getresponse()
    body = response.read()
    connection.close()
    return response.status, body


@needs("go")
def test_viewer_area_routes_need_the_token_and_mark_name_links(tmp_path):
    write(tmp_path, GO_COLLISION)
    _graph, index = index_for(tmp_path)
    area_id = index.node_area["a.a_go.Run"]
    server = GraphServer(tmp_path, 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        token = {"X-Skylos-Token": server.token}
        assert _get(port, "/api/areas")[0] == 403
        assert _get(port, f"/api/area?id={area_id}")[0] == 403
        status, body = _get(port, f"/api/area?id={area_id}", token)
        assert status == 200
        assert "a.a_go.Run" in [member["id"] for member in json.loads(body)["members"]]
        assert _get(port, "/api/area?id=abc", token)[0] == 404
        status, body = _get(port, "/api/node?id=a.a_go.Run", token)
        lens = json.loads(body)["lens"]
        assert lens["callees_name"] == 2
        assert {item["match"] for item in lens["callees"]} == {"name"}
    finally:
        server.shutdown()
        server.server_close()


def test_an_area_is_named_after_a_function_not_an_exception_everyone_raises(tmp_path):
    shop = tmp_path / "shop"
    shop.mkdir()
    (shop / "__init__.py").write_text("")
    (shop / "errors.py").write_text("class OutOfStock(Exception):\n    pass\n")
    (shop / "stock.py").write_text(
        "from shop.errors import OutOfStock\n\n\n"
        "def reserve(qty):\n    if qty > 5:\n        raise OutOfStock(qty)\n    return qty\n\n\n"
        "def release(qty):\n    if qty < 0:\n        raise OutOfStock(qty)\n    return reserve(qty)\n\n\n"
        "def audit(qty):\n    if qty is None:\n        raise OutOfStock(qty)\n    return reserve(qty)\n"
    )
    graph = build_graph(tmp_path)
    names = [area["name"] for area in GraphIndex(tmp_path, graph, {}).areas()]
    assert names
    assert all("OutOfStock" not in name for name in names)
    assert "shop: stock, errors" in names
