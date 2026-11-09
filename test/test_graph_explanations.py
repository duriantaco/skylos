import contextlib
import io
import json
import subprocess

from rich.console import Console

from skylos.commands.graph_cmd import run_graph_command
from skylos.graph import build_graph
from skylos.graph.describe import apply_summaries, change_material, pending_changes
from skylos.graph.query import GraphIndex
from skylos.graph.store import load_notes, save_notes

STOCK = "def available(count, wanted):\n    return wanted <= count\n"
CART = (
    "from shop.stock import available\n\n\n"
    "def add_item(cart, count, wanted):\n"
    "    if not available(count, wanted):\n"
    "        return 409\n"
    "    cart.append(wanted)\n"
    "    return 201\n\n\n"
    "def checkout(cart, count, wanted):\n"
    "    return add_item(cart, count, wanted)\n\n\n"
    "def audit(cart):\n"
    "    return len(cart)\n"
)
TESTS = (
    "from shop.cart import add_item, checkout\n"
    "from shop.stock import available\n\n\n"
    "def test_available():\n"
    "    assert available(3, 3)\n\n\n"
    "def test_add_item():\n"
    "    assert add_item([], 3, 3) == 201\n\n\n"
    "def test_checkout():\n"
    "    assert checkout([], 3, 3) == 201\n"
)
FILES = {"shop/__init__.py": "", "shop/stock.py": STOCK, "shop/cart.py": CART, "tests/test_cart.py": TESTS}
AVAILABLE = "shop.stock.available"
ADD_ITEM = "shop.cart.add_item"
CHECKOUT = "shop.cart.checkout"
AUDIT = "shop.cart.audit"


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


def cli(*argv):
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = run_graph_command(list(argv), console=Console(file=buffer, width=1000, highlight=False))
    return code, buffer.getvalue()


def import_items(root, items):
    path = root / "agent.json"
    path.write_text(json.dumps({"items": items}))
    code, out = cli("import", str(path), "--path", str(root))
    assert code == 0, out
    return out


def test_a_replaced_description_keeps_one_previous_version(tmp_path):
    write(tmp_path, FILES)
    build_graph(tmp_path)
    apply_summaries(tmp_path, GraphIndex.load(tmp_path), {AUDIT: "Counts the items in a cart."}, "agent")
    apply_summaries(tmp_path, GraphIndex.load(tmp_path), {AUDIT: "Returns how many items a cart holds."}, "human")
    apply_summaries(tmp_path, GraphIndex.load(tmp_path), {AUDIT: "Returns how many items a cart holds."}, "human")
    entry = load_notes(tmp_path)["nodes"][AUDIT]
    assert entry["text"] == "Returns how many items a cart holds."
    assert entry["previous"]["text"] == "Counts the items in a cart."
    assert entry["previous"]["source"] == "agent"
    assert GraphIndex.load(tmp_path).card(AUDIT, with_code=False)["description"]["before"] is None
    apply_summaries(tmp_path, GraphIndex.load(tmp_path), {AUDIT: "Gives the cart size."}, "human")
    entry = load_notes(tmp_path)["nodes"][AUDIT]
    assert entry["previous"]["text"] == "Returns how many items a cart holds."
    assert "previous" not in entry["previous"]


def test_impact_preview_and_change_callers_use_proven_links_only(tmp_path):
    write(tmp_path, FILES)
    graph = build_graph(tmp_path)
    graph["name_edges"] = list(graph.get("name_edges") or []) + [[AUDIT, AVAILABLE, "calls"]]
    index = GraphIndex(tmp_path, graph, load_notes(tmp_path))
    assert AUDIT in {row["id"] for row in index.impact(AVAILABLE)["possible_callers"]}
    preview = index.card(AVAILABLE, with_code=False)["impact_preview"]
    assert [(row["id"], row["steps"], row["is_test"]) for row in preview] == [
        (ADD_ITEM, 1, False),
        (CHECKOUT, 2, False),
        ("tests.test_cart.test_available", 1, True),
        ("tests.test_cart.test_add_item", 2, True),
        ("tests.test_cart.test_checkout", 3, True),
    ]
    entry = {"change_key": "k", "name": "available", "file": "shop/stock.py", "verdict_text": "Logic changed.", "node_id": AVAILABLE}
    callers = change_material([entry], index)[0]["callers"]
    assert [row["id"] for row in callers] == [ADD_ITEM, CHECKOUT, "tests.test_cart.test_available", "tests.test_cart.test_add_item"]


def test_change_explanation_with_impact_end_to_end(tmp_path):
    write(tmp_path, FILES)
    git(tmp_path, "init", "-q")
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-q", "-m", "base")
    assert cli(str(tmp_path), "--since", "none")[0] == 0
    import_items(tmp_path, [
        {"id": AVAILABLE, "summary": "Says yes when the stock covers the amount asked for, including all of it."},
        {"id": ADD_ITEM, "summary": "Adds an amount to the cart and answers 201, or 409 when stock is short."},
    ])
    write(tmp_path, {"shop/stock.py": STOCK.replace("wanted <= count", "wanted < count")})
    assert cli(str(tmp_path), "--since", "HEAD")[0] == 0
    import_items(tmp_path, [{"id": AVAILABLE, "summary": "Says yes only when more stock is left than the amount asked for."}])
    code, out = cli("pending", "--changes", "--base", "HEAD", "--format", "json", "--path", str(tmp_path))
    assert code == 0
    item = json.loads(out)["items"][0]
    assert "impact" in json.loads(out)["instructions"]
    assert [(row["id"], row["steps"]) for row in item["callers"]][:2] == [(ADD_ITEM, 1), (CHECKOUT, 2)]
    assert item["callers"][0]["description"].startswith("Adds an amount")
    assert item["tests"] == ["test_available", "test_add_item", "test_checkout"]
    import_items(tmp_path, [{
        "id": item["id"], "before": "Allowed taking the whole stock.", "after": "Refuses to take the last unit.",
        "same_behaviour": "no", "why": "available(3, 3) was True and is now False.",
        "impact": [
            {"id": ADD_ITEM, "effect": "add_item now answers 409 instead of 201 when a cart asks for exactly the stock left."},
            {"id": AUDIT, "effect": "Not offered, so it must be dropped."},
            {"id": CHECKOUT, "effect": "z" * 500},
        ],
    }])
    note = load_notes(tmp_path)["changes"][item["id"]]
    assert [row["id"] for row in note["impact"]] == [ADD_ITEM, CHECKOUT]
    assert len(note["impact"][1]["effect"]) == 300
    code, out = cli("show", "available", "--path", str(tmp_path))
    assert code == 0
    order = [
        "What it does: Says yes only when more stock",
        "Before this change it did: Says yes when the stock covers",
        "What changed:",
        "Same behaviour: no, some inputs now behave differently",
        "What it affects (2)",
        "add_item shop/cart.py:4: add_item now answers 409",
    ]
    positions = [out.index(text) for text in order]
    assert positions == sorted(positions)
    assert "Not offered" not in out
    card = json.loads(cli("show", "available", "--path", str(tmp_path), "--format", "json")[1])
    assert card["description"]["before"]["text"].startswith("Says yes when the stock covers")
    assert card["change_note"]["impact"][0]["name"] == "add_item"
    notes = load_notes(tmp_path)
    notes["changes"][item["id"]] = {"before": "Old.", "after": "New.", "same_behaviour": "no", "why": "x", "source": "agent", "at": "2026-01-01"}
    save_notes(tmp_path, notes)
    code, out = cli("show", "available", "--path", str(tmp_path))
    assert code == 0
    assert "Calls into this, may be affected: (5)" in out
    assert pending_changes(GraphIndex.load(tmp_path)) == []
