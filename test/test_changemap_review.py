import subprocess

import pytest

from skylos.changemap import build_change_map, render_markdown, render_text
from skylos.changemap.review import (
    WHY_CLASS_METHODS,
    WHY_DOC_CLASS,
    WHY_DOC_DECORATED,
    WHY_DOC_RUNTIME,
    WHY_MOVED,
    WHY_REMOVED_UNUSED,
    WHY_SPECIAL_REMOVED,
    WHY_TESTS_EDITED,
)
from skylos.changemap.sameness import SAME_RENAMED, same_logic


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


def by_id(change_map):
    return {s["id"]: s for s in change_map["symbols"]}


AUTH = "def require_auth(user):\n    if not user:\n        raise PermissionError\n    return user\n"
SAME_EDIT = "".join(f"\ndef a{i}(x):\n    return x\n" for i in range(1, 4))
SAME_EDIT_HEAD = "".join(f"\ndef a{i}(x):\n    log_call()\n    return x\n" for i in range(1, 4))

BASE = {
    "auth.py": AUTH,
    "app/__init__.py": "",
    "app/core.py": (
        "from auth import require_auth\n\n"
        "def handler(user):\n    require_auth(user)\n    return 1\n\n"
        "def total(items):\n    count = 0\n    for item in items:\n        count += item\n    return count\n\n"
        "def label(value):\n    \"\"\"Old text.\"\"\"\n    return str(value)\n\n"
        "def price(amount):\n    return amount * 2\n\n"
        "def unused_old():\n    return 0\n"
        + SAME_EDIT
    ),
    "app/util.py": "def other():\n    return 1\n\ndef fmt(value):\n    return f'<{value}>'\n",
    "tests/test_core.py": "from app.core import price\n\ndef test_price():\n    assert price(2) == 4\n",
}

HEAD = {
    "app/core.py": (
        "from auth import require_auth\nfrom app.extra import log_call\n\n"
        "def handler(user):\n    return 1\n\n"
        "def total(items):\n    running = 0\n    for entry in items:\n        running += entry\n    return running\n\n"
        "def label(value):\n    \"\"\"New, clearer text.\"\"\"\n    return str(value)\n\n"
        "def price(amount):\n    return amount * 3\n\n"
        "def brand_new(x):\n    return x + 1\n"
        + SAME_EDIT_HEAD
    ),
    "app/util.py": "def other():\n    return 1\n",
    "app/formatting.py": "def fmt(value):\n    return f'<{value}>'\n",
    "app/extra.py": "def log_call():\n    return None\n",
    "tests/test_core.py": "from app.core import price\n\ndef test_price():\n    assert price(2) == 6\n",
}


def test_each_changed_symbol_lands_in_one_review_bucket_with_a_reason(tmp_path):
    repo(tmp_path, BASE)
    write(tmp_path, HEAD)
    result = build_change_map(tmp_path, "HEAD")
    review = result["review"]
    buckets = {name: set(ids) for name, ids in review["buckets"].items()}
    assert result["read_first"][0] == "app/core.py::handler"
    assert buckets["read_first"] | buckets["read"] == {
        "app/core.py::handler", "app/core.py::price", "app/core.py::brand_new", "app/core.py::a1", "app/extra.py::log_call",
    }
    assert buckets["skim"] == {"app/core.py::a2", "app/core.py::a3", "app/core.py::unused_old", "app/formatting.py::fmt"}
    assert buckets["skip"] == {"app/core.py::total", "app/core.py::label"}
    symbols = by_id(result)
    assert symbols["app/formatting.py::fmt"]["review_why"] == WHY_MOVED.format(file="app/formatting.py")
    assert symbols["app/util.py::fmt"]["review"] == "skim"
    assert symbols["app/util.py::fmt"]["review_why"] == "Moved to app/formatting.py; reviewed there."
    assert symbols["app/core.py::price"]["review_why"] == WHY_TESTS_EDITED
    assert symbols["app/core.py::a2"]["review_why"] == "Same edit as a1."
    assert symbols["app/core.py::unused_old"]["review_why"] == WHY_REMOVED_UNUSED
    assert symbols["app/core.py::total"]["verdict"] == "same_renamed"
    assert symbols["app/core.py::label"]["verdict"] == "same_docs"
    assert review["counts"] == {"read_first": 3, "read": 2, "skim": 4, "skip": 2}
    assert review["total"] == 11
    assert review["total_lines"] == sum(review["lines"].values())
    assert review["lines"]["skip"] > 0
    text = render_text(result)
    assert (
        f"Review: {review['counts']['read_first']} to read first, {review['counts']['read']} to read, 4 to skim, "
        f"2 to skip (same logic, proven). {review['lines']['read_first'] + review['lines']['read']} of "
        f"{review['total_lines']} changed lines need reading."
    ) in text
    assert text.index("READ FIRST") < text.index("\nREAD\n") < text.index("SKIM") < text.index("SKIP: SAME LOGIC, PROVEN")
    markdown = render_markdown(result)
    skip = markdown.split("#### Skip: same logic, proven")[1]
    assert "`total` modified" in skip
    assert "Same logic. Only local variable names changed." in skip
    assert "`handler`" not in skip
    assert "`fmt`" not in skip


ADVERSARIAL_BASE = {
    "grammar.py": "import ply.yacc as yacc\n\ndef p_expr(p):\n    \"\"\"expr : NUMBER\"\"\"\n    p[0] = p[1]\n",
    "cli.py": "import click\n\n@click.command()\ndef run():\n    \"\"\"Run it.\"\"\"\n    return 1\n",
    "shell.py": "import cmd\n\nclass Shell(cmd.Cmd):\n    def do_go(self, arg):\n        \"\"\"Go somewhere.\"\"\"\n        return arg\n",
    "plain.py": (
        "def show(a):\n    x = a\n    return locals()\n\n"
        "def outer(a):\n    def inner(v):\n        return v + a\n    return inner\n\n"
        "def note(a):\n    \"\"\"Old.\"\"\"\n    return a\n"
    ),
    "helpers.py": "def check(value):\n    return value\n",
    "strict.py": "def check(value):\n    if value is None:\n        raise ValueError\n    return value\n",
    "guards.py": "from helpers import check\n\ndef guard(v):\n    return check(v)\n",
    "rebind.py": "from helpers import check\n\ndef guard2(v):\n    return check(v)\n",
}

ADVERSARIAL_HEAD = {
    "grammar.py": "import ply.yacc as yacc\n\ndef p_expr(p):\n    \"\"\"expr : NUMBER PLUS NUMBER\"\"\"\n    p[0] = p[1]\n",
    "cli.py": "import click\n\n@click.command()\ndef run():\n    \"\"\"Run everything now.\"\"\"\n    return 1\n",
    "shell.py": "import cmd\n\nclass Shell(cmd.Cmd):\n    def do_go(self, arg):\n        \"\"\"Go anywhere.\"\"\"\n        return arg\n",
    "plain.py": (
        "def show(a):\n    y = a\n    return locals()\n\n"
        "def outer(a):\n    def helper(v):\n        return v + a\n    return helper\n\n"
        "def note(a):\n    \"\"\"New.\"\"\"\n    return a\n"
    ),
    "guards.py": "",
    "moved_guards.py": "from strict import check\n\ndef guard(v):\n    return check(v)\n",
    "rebind.py": "from strict import check\n\ndef guard2(v):\n    return check(v)\n",
}


def test_lookalike_same_logic_changes_are_never_skipped(tmp_path):
    repo(tmp_path, ADVERSARIAL_BASE)
    write(tmp_path, ADVERSARIAL_HEAD)
    result = build_change_map(tmp_path, "HEAD")
    symbols = by_id(result)
    p_expr = symbols["grammar.py::p_expr"]
    assert p_expr["review"] in ("read", "read_first")
    assert p_expr["review_why"] == WHY_DOC_RUNTIME
    assert (symbols["cli.py::run"]["review"], symbols["cli.py::run"]["review_why"]) == ("skim", WHY_DOC_DECORATED)
    assert (symbols["shell.py::Shell.do_go"]["review"], symbols["shell.py::Shell.do_go"]["review_why"]) == ("skim", WHY_DOC_CLASS)
    assert symbols["plain.py::show"]["verdict"] == "changed"
    assert symbols["plain.py::outer"]["verdict"] == "changed"
    moved = symbols["moved_guards.py::guard"]
    assert moved["verdict"] != "same_moved"
    origin = symbols["guards.py::guard"]
    assert origin["review"] == moved["review"]
    assert moved["review"] in ("read", "read_first")
    assert origin["verdict_text"].startswith("Moved to moved_guards.py, where it changed:")
    assert origin["review_why"] == "Moved to moved_guards.py; reviewed there."
    assert all("guards.py::guard" not in ids for ids in result["review"]["buckets"].values())
    assert symbols["rebind.py::guard2"]["verdict"] == "changed_binding"
    never_skipped = {
        "grammar.py::p_expr", "cli.py::run", "shell.py::Shell.do_go", "plain.py::show", "plain.py::outer",
        "moved_guards.py::guard", "guards.py::guard", "rebind.py::guard2",
    }
    assert never_skipped.isdisjoint(result["review"]["buckets"]["skip"])
    assert symbols["plain.py::note"]["review"] == "skip"


def code(text):
    return {"code": text, "truncated": False}


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("def f(a):\n    x = a\n    return eval('x')\n", "def f(a):\n    y = a\n    return eval('y')\n"),
        ("def f(a):\n    x = a\n    return vars()\n", "def f(a):\n    y = a\n    return vars()\n"),
        ("def f(a):\n    g = lambda value: value + a\n    return g\n", "def f(a):\n    g = lambda v: v + a\n    return g\n"),
        ("def f(a):\n    import sys\n    x = a\n    return sys._getframe().f_locals\n", "def f(a):\n    import sys\n    y = a\n    return sys._getframe().f_locals\n"),
    ],
    ids=["eval-reads-a-local-by-name", "vars-returns-local-names", "lambda-keyword-names", "frame-locals"],
)
def test_renames_visible_at_runtime_are_not_same_logic(before, after):
    assert same_logic(code(before), code(after)) is None


def test_plain_local_rename_is_still_same_logic():
    before = "def f(items):\n    total = 0\n    for item in items:\n        total += item\n    return total\n"
    after = "def f(items):\n    acc = 0\n    for each in items:\n        acc += each\n    return acc\n"
    assert same_logic(code(before), code(after)) == SAME_RENAMED


def test_code_from_the_change_cannot_close_the_markdown_code_block(tmp_path):
    repo(tmp_path, {"app.py": "def doc():\n    return 'plain'\n"})
    write(tmp_path, {"app.py": "def doc():\n    return '```\\n<img src=x onerror=alert(1)>\\n```'\n"})
    markdown = render_markdown(build_change_map(tmp_path, "HEAD"))
    block = markdown.split("After (lines 1-2):\n")[1]
    fence = block.split("python\n")[0]
    assert fence == "````"
    body = block.split(fence + "python\n")[1].split("\n" + fence + "\n")[0]
    assert "<img src=x onerror=alert(1)>" in body


def test_values_from_test_files_cannot_inject_mentions_or_links(tmp_path):
    test_base = "from app import greet\n\ndef test_greet():\n    assert greet('a') == 'hi a'\n"
    repo(tmp_path, {"app.py": "def greet(name):\n    return 'hi ' + name\n", "tests/test_app.py": test_base})
    write(tmp_path, {
        "app.py": "def greet(name):\n    return 'hello ' + name\n",
        "tests/test_app.py": test_base.replace("'hi a'", "'@octocat [x](https://evil.example) <b>a</b>'"),
    })
    result = build_change_map(tmp_path, "HEAD")
    greet = by_id(result)["app.py::greet"]
    assert greet["review_why"] == WHY_TESTS_EDITED
    assert any("@octocat" in line for line in greet["test_evidence"])
    markdown = render_markdown(result)
    assert "Tests now expect" in markdown
    assert "@octocat" not in markdown
    assert "[x](https://evil.example)" not in markdown
    assert "<b>" not in markdown


def test_moved_code_is_skimmed_never_skipped_because_its_import_path_changed(tmp_path):
    model = "from pydantic import BaseModel\n\nclass ServiceResponse(BaseModel):\n    name: str\n"
    repo(tmp_path, {"app/__init__.py": "", "app/models.py": model + "\nOTHER = 1\n"})
    write(tmp_path, {"app/models.py": "OTHER = 1\n", "app/responses.py": model})
    result = build_change_map(tmp_path, "HEAD")
    moved = by_id(result)["app/responses.py::ServiceResponse"]
    assert moved["verdict"] == "same_moved"
    assert (moved["review"], moved["review_why"]) == ("skim", WHY_MOVED.format(file="app/responses.py"))
    assert result["review"]["buckets"]["skip"] == []
    assert result["review"]["total"] == 1


def test_removing_a_special_method_needs_reading(tmp_path):
    base = "class Worker:\n    async def __aenter__(self):\n        return self\n\n    async def __aexit__(self, *exc):\n        return None\n\n    def run(self):\n        return 1\n"
    repo(tmp_path, {"worker.py": base})
    write(tmp_path, {"worker.py": "class Worker:\n    def run(self):\n        return 1\n"})
    symbols = by_id(build_change_map(tmp_path, "HEAD"))
    for name in ("__aenter__", "__aexit__"):
        entry = symbols[f"worker.py::Worker.{name}"]
        assert entry["review"] in ("read", "read_first")
        assert entry["review_why"] == WHY_SPECIAL_REMOVED.format(name=name)


def test_class_docstrings_are_same_logic_unless_a_method_really_changed(tmp_path):
    base = (
        "class Plain:\n    \"\"\"Old.\"\"\"\n    size = 1\n\n    @property\n    def area(self):\n        \"\"\"Old area.\"\"\"\n        return self.size\n\n"
        "class Busy:\n    \"\"\"Old.\"\"\"\n    def go(self):\n        return 1\n"
    )
    head = (
        "class Plain:\n    \"\"\"New.\"\"\"\n    size = 1\n\n    @property\n    def area(self):\n        \"\"\"New area.\"\"\"\n        return self.size\n\n"
        "class Busy:\n    \"\"\"New.\"\"\"\n    def go(self):\n        return 2\n"
    )
    repo(tmp_path, {"shapes.py": base})
    write(tmp_path, {"shapes.py": head})
    symbols = by_id(build_change_map(tmp_path, "HEAD"))
    assert symbols["shapes.py::Plain"]["review"] == "skip"
    assert symbols["shapes.py::Plain.area"]["review"] == "skip"
    assert symbols["shapes.py::Busy"]["verdict"] == "same_docs"
    assert (symbols["shapes.py::Busy"]["review"], symbols["shapes.py::Busy"]["review_why"]) == ("skim", WHY_CLASS_METHODS)
    assert symbols["shapes.py::Busy.go"]["review"] in ("read", "read_first")


def test_files_skylos_writes_for_itself_are_not_part_of_the_change(tmp_path):
    repo(tmp_path, {"app.py": "def run():\n    return 1\n"})
    write(tmp_path, {
        "app.py": "def run():\n    return 2\n",
        ".skylos/graph/.gitignore": "*\n!.gitignore\n!notes.json\n",
        ".skylos/graph/reviews/a-b.json": "{}",
        ".skylos/graph/notes.json": "{}",
        "docs/notes.txt": "hello\n",
    })
    coverage = build_change_map(tmp_path, "HEAD")["coverage"]
    assert sorted(coverage["not_mapped"]) == [".skylos/graph/notes.json", "docs/notes.txt"]


MONEY_BASE = {
    "shop/__init__.py": "",
    "shop/pricing.py": (
        "RATE = 0.09\n\n\n"
        "def round_cents(value):\n    return int(value + 0.5)\n\n\n"
        "def taxed(value):\n    return round_cents(value * RATE)\n\n\n"
        "def scaled(value):\n    return round_cents(value * RATE * 2)\n"
    ),
    "shop/cart.py": "from shop.pricing import round_cents\n\n\ndef total(items):\n    return round_cents(sum(items))\n",
}


def test_callers_of_a_cleanly_moved_function_are_proven_unchanged(tmp_path):
    repo(tmp_path, MONEY_BASE)
    write(tmp_path, {
        "shop/money.py": "def round_cents(value):\n    return int(value + 0.5)\n",
        "shop/pricing.py": MONEY_BASE["shop/pricing.py"].replace("def round_cents(value):\n    return int(value + 0.5)\n\n\n", "").replace("RATE = 0.09\n", "from shop.money import round_cents\n\nRATE = 0.09\n"),
        "shop/cart.py": MONEY_BASE["shop/cart.py"].replace("shop.pricing", "shop.money"),
    })
    result = build_change_map(tmp_path, "HEAD")
    symbols = by_id(result)
    for entry_id in ("shop/cart.py::total", "shop/pricing.py::taxed", "shop/pricing.py::scaled"):
        assert symbols[entry_id]["verdict"] == "same_callee_moved", entry_id
        assert symbols[entry_id]["review"] == "skip"
        assert "shop.pricing.round_cents → shop.money.round_cents" in symbols[entry_id]["review_why"]
    assert symbols["shop/money.py::round_cents"]["review"] == "skim"
    assert result["review"]["counts"]["read_first"] + result["review"]["counts"]["read"] == 0


def test_a_move_that_leaves_a_name_behind_must_be_read_and_proves_nothing(tmp_path):
    base = dict(MONEY_BASE)
    base["shop/pricing.py"] = base["shop/pricing.py"].replace("    return int(value + 0.5)\n", "    return int(value + HALF)\n", 1).replace("RATE = 0.09\n", "RATE = 0.09\nHALF = 0.5\n")
    repo(tmp_path, base)
    write(tmp_path, {
        "shop/money.py": "def round_cents(value):\n    return int(value + HALF)\n",
        "shop/pricing.py": base["shop/pricing.py"].replace("def round_cents(value):\n    return int(value + HALF)\n\n\n", "").replace("RATE = 0.09\n", "from shop.money import round_cents\n\nRATE = 0.09\n"),
        "shop/cart.py": base["shop/cart.py"].replace("shop.pricing", "shop.money"),
    })
    symbols = by_id(build_change_map(tmp_path, "HEAD"))
    moved = symbols["shop/money.py::round_cents"]
    assert moved["verdict"] == "changed"
    assert moved["review"] in ("read", "read_first")
    assert moved["review_why"] == "Moved to shop/money.py, but it reads HALF, which shop/money.py does not define or import."
    assert symbols["shop/cart.py::total"]["verdict"] == "changed_binding"
    assert symbols["shop/cart.py::total"]["review"] != "skip"


def test_a_move_that_reads_a_value_from_another_module_is_read_not_proven(tmp_path):
    base = dict(MONEY_BASE)
    base["shop/pricing.py"] = base["shop/pricing.py"].replace("    return int(value + 0.5)\n", "    return int(value + HALF)\n", 1).replace("RATE = 0.09\n", "RATE = 0.09\nHALF = 0.5\n")
    repo(tmp_path, base)
    write(tmp_path, {
        "shop/money.py": "from shop.constants import HALF\n\n\ndef round_cents(value):\n    return int(value + HALF)\n",
        "shop/constants.py": "HALF = 0.5\n",
        "shop/pricing.py": base["shop/pricing.py"].replace("def round_cents(value):\n    return int(value + HALF)\n\n\n", "").replace("RATE = 0.09\n", "from shop.money import round_cents\n\nRATE = 0.09\n"),
        "shop/cart.py": base["shop/cart.py"].replace("shop.pricing", "shop.money"),
    })
    symbols = by_id(build_change_map(tmp_path, "HEAD"))
    assert symbols["shop/money.py::round_cents"]["verdict"] == "changed"
    assert symbols["shop/money.py::round_cents"]["review"] != "skip"
    assert symbols["shop/cart.py::total"]["verdict"] == "changed_binding"
    assert symbols["shop/cart.py::total"]["review"] != "skip"


def test_calls_inside_the_same_file_are_shown_relative_to_it():
    from skylos.changemap.render import _local_calls

    function = {"full_name": "acme.orders.place_order", "name": "place_order",
                "calls_added": ["acme.cart.Cart", "acme.orders.cart.region", "acme.ordersx.helper"]}
    method = {"full_name": "acme.cart.Cart.add", "name": "Cart.add", "calls_removed": ["acme.cart.get_product", "acme.catalog.Product"]}

    assert _local_calls(function, "calls_added") == ["acme.cart.Cart", "cart.region", "acme.ordersx.helper"]
    assert _local_calls(method, "calls_removed") == ["get_product", "acme.catalog.Product"]
    assert _local_calls({"full_name": "", "name": "x", "calls_added": ["a.b"]}, "calls_added") == ["a.b"]
