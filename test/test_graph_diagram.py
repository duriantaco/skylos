import http.client
import json
import threading

from skylos.graph.diagram import area_diagram, codebase_diagram
from skylos.graph.query import GraphIndex
from skylos.graph.server import GraphServer
from skylos.graph.store import GRAPH_FILE, ensure_dir, write_json


def node(node_id, kind="function", start=1, is_test=False, code_hash="h"):
    module, _, name = node_id.partition(".")
    return {
        "id": node_id,
        "kind": kind,
        "name": name,
        "module": module,
        "file": module + ".py",
        "start": start,
        "end": start + 2,
        "lines": 3,
        "language": "python",
        "is_test": is_test,
        "signature": "",
        "doc": "",
        "decorators": [],
        "code_hash": code_hash,
    }


def area(area_id, members, size=None):
    return {
        "id": area_id,
        "name": f"area {area_id}",
        "hub": members[0],
        "size": size or len(members),
        "files": 1,
        "where": f"pkg{area_id}",
        "cohesion": 0.0,
        "links_inside": 0,
        "links_out": 0,
        "members": members,
    }


def graph(nodes, edges, areas, name_edges=()):
    return {
        "nodes": nodes,
        "edges": [list(edge) for edge in edges],
        "name_edges": [list(edge) for edge in name_edges],
        "areas": areas,
        "files": [],
        "expectations": {},
    }


def changes(*entries):
    symbols = []
    for node_id, review, verdict, is_test in entries:
        symbols.append({"id": node_id, "node_id": node_id, "review": review, "verdict": verdict, "is_test": is_test})
    return {"symbols": symbols}


def edge_set(data):
    found = set()
    for edge in data["edges"]:
        if data["level"] == "codebase":
            found.add((edge["source"], edge["target"], edge["weight"], edge["name_links"]))
        else:
            found.add((edge["source"], edge["target"], edge["kind"]))
    return found


def by_id(data):
    return {item["id"]: item for item in data["nodes"]}


def test_area_links_count_proven_links_and_keep_name_matches_apart():
    nodes = [node("a.one"), node("a.two"), node("b.one"), node("c.one"), node("tests.check", is_test=True)]
    edges = [
        ("a.one", "b.one", "calls"),
        ("a.two", "b.one", "calls"),
        ("b.one", "c.one", "uses"),
        ("a.one", "a.two", "calls"),
        ("tests.check", "a.one", "calls"),
    ]
    name_edges = [("a.one", "c.one", "calls"), ("b.one", "c.one", "calls")]
    notes = {
        "nodes": {
            "a.one": {"text": "Adds two prices.", "code_hash": "h", "source": "human"},
            "b.one": {"text": "Old text.", "code_hash": "old", "source": "human"},
        },
        "changes": {},
    }
    index = GraphIndex("/nowhere", graph(nodes, edges, [area(0, ["a.one", "a.two"]), area(1, ["b.one"]), area(2, ["c.one"])], name_edges), notes)
    data = codebase_diagram(index)
    assert edge_set(data) == {
        ("area:0", "area:1", 2, 0),
        ("area:1", "area:2", 1, 1),
        ("area:0", "area:2", 0, 1),
    }
    areas = by_id(data)
    assert areas["area:0"]["summary"] == "Adds two prices."
    assert areas["area:1"]["summary"] == ""
    assert [areas[key]["review"] for key in ("area:0", "area:1", "area:2")] == [None, None, None]


def test_codebase_level_caps_areas_and_folds_the_rest_into_other():
    nodes = [node(f"m{i}.f") for i in range(70)]
    areas = [area(i, [f"m{i}.f"], size=100 - i) for i in range(70)]
    edges = [("m0.f", "m1.f", "calls"), ("m60.f", "m0.f", "calls"), ("m61.f", "m62.f", "calls")]
    index = GraphIndex("/nowhere", graph(nodes, edges, areas), changes=changes(("m69.f", "read", "changed", False)))
    data = codebase_diagram(index)
    ids = [item["id"] for item in data["nodes"]]
    assert len(ids) == 60
    assert ids[0] == "area:69"
    assert ids[-1] == "area:other"
    assert "area:58" not in ids and "area:57" in ids
    other = by_id(data)["area:other"]
    assert other["areas"] == 11
    assert other["size"] == sum(100 - i for i in range(58, 69))
    assert edge_set(data) == {("area:0", "area:1", 1, 0), ("area:other", "area:0", 1, 0)}
    assert by_id(data)["area:69"]["review"] == "read"
    assert by_id(data)["area:69"]["changed"] == 1


def test_review_buckets_colour_areas_and_class_boxes_list_their_methods():
    nodes = [
        node("p.load"),
        node("p.Store", kind="class", start=10),
        node("p.Store.get", kind="method", start=11),
        node("p.Store.put", kind="method", start=14),
        node("q.use"),
        node("tests.check", is_test=True),
    ]
    edges = [
        ("p.load", "p.Store", "creates"),
        ("p.Store.put", "p.load", "calls"),
        ("p.Store.get", "p.Store.put", "calls"),
        ("q.use", "p.Store.put", "calls"),
        ("tests.check", "p.load", "calls"),
    ]
    found = changes(
        ("p.load", "read_first", "changed", False),
        ("p.Store.put", "read", "new", False),
        ("p.Store.get", "skip", "same_docs", False),
        ("tests.check", None, "new", True),
    )
    index = GraphIndex("/nowhere", graph(nodes, edges, [area(0, ["p.load", "p.Store", "p.Store.get", "p.Store.put"]), area(1, ["q.use"])]), changes=found)
    codebase = by_id(codebase_diagram(index))
    assert (codebase["area:0"]["review"], codebase["area:0"]["changed"]) == ("read_first", 3)
    assert (codebase["area:1"]["review"], codebase["area:1"]["changed"]) == (None, 0)
    data = area_diagram(index, 0)
    shown = by_id(data)
    assert set(shown) == {"p.load", "p.Store", "q.use"}
    assert shown["p.load"]["review"] == "read_first"
    assert shown["p.Store"]["review"] is None
    assert [(m["id"], m["review"], m["verdict"]) for m in shown["p.Store"]["members"]] == [
        ("p.Store.get", "skip", "same_docs"),
        ("p.Store.put", "read", "new"),
    ]
    assert shown["q.use"]["external"] is True
    assert shown["q.use"]["area"] == 1
    assert edge_set(data) == {
        ("p.load", "p.Store", "creates"),
        ("p.Store.put", "p.load", "calls"),
        ("q.use", "p.Store.put", "calls"),
    }
    assert (data["area"]["review"], data["area"]["changed"]) == ("read_first", 3)


def impact_index():
    nodes = [
        node("x.f0"),
        node("x.Thing", kind="class"),
        node("x.Thing.__init__", kind="method", start=2),
        node("y.f1"),
        node("y.f2"),
        node("y.f3"),
        node("y.f4"),
        node("y.f3b"),
        node("y.g"),
        node("y.maker"),
        node("y.named"),
        node("y.same"),
        node("y.same_caller"),
        node("tests.check", is_test=True),
    ]
    edges = [
        ("y.f1", "x.f0", "calls"),
        ("y.f2", "y.f1", "calls"),
        ("y.f3", "y.f2", "calls"),
        ("y.f4", "y.f3", "calls"),
        ("y.f3b", "y.f2", "calls"),
        ("y.f3", "y.f3b", "calls"),
        ("y.g", "x.f0", "calls"),
        ("y.maker", "x.Thing", "creates"),
        ("y.same_caller", "y.same", "calls"),
        ("tests.check", "y.f1", "calls"),
    ]
    name_edges = [("y.named", "x.f0", "calls")]
    members = ["y.f1", "y.f2", "y.f3", "y.f4", "y.f3b", "y.g", "y.maker", "y.named", "y.same", "y.same_caller"]
    found = changes(
        ("x.f0", "read", "changed", False),
        ("x.Thing.__init__", "read_first", "changed", False),
        ("y.same", "skip", "same_renamed", False),
        ("y.g", "read", "changed", False),
    )
    return GraphIndex("/nowhere", graph(nodes, edges, [area(0, ["x.f0", "x.Thing", "x.Thing.__init__"]), area(1, members)], name_edges), changes=found)


def test_impact_marks_callers_up_to_three_steps_and_never_follows_name_matches():
    index = impact_index()
    data = area_diagram(index, 1, impact=True)
    shown = by_id(data)
    impacted = {key for key, item in shown.items() if item.get("impacted")}
    assert impacted == {"y.f1", "y.f2", "y.f3", "y.f3b", "y.maker"}
    assert "tests.check" not in shown
    assert shown["x.f0"]["external"] is True and shown["x.f0"]["review"] == "read"
    hot = {(edge["source"], edge["target"], edge["kind"]): edge["impact"] for edge in data["edges"]}
    assert hot == {
        ("y.f1", "x.f0", "calls"): True,
        ("y.f2", "y.f1", "calls"): True,
        ("y.f3", "y.f2", "calls"): True,
        ("y.f4", "y.f3", "calls"): False,
        ("y.f3b", "y.f2", "calls"): True,
        ("y.f3", "y.f3b", "calls"): False,
        ("y.g", "x.f0", "calls"): True,
        ("y.maker", "x.Thing", "creates"): True,
        ("y.named", "x.f0", "name"): False,
        ("y.same_caller", "y.same", "calls"): False,
    }
    codebase = codebase_diagram(index, impact=True)
    assert (by_id(codebase)["area:1"]["impacted"], by_id(codebase)["area:1"]["affected"]) == (True, 5)
    assert by_id(codebase)["area:0"]["impacted"] is False
    assert codebase["edges"] == [{"source": "area:1", "target": "area:0", "weight": 3, "name_links": 1, "impact": True}]
    assert all("impacted" not in item for item in codebase_diagram(index)["nodes"])


def test_external_neighbours_are_capped_and_ranked_by_proven_links():
    nodes = [node("hub.h"), node("z.f")] + [node(f"e{i}.f") for i in range(1, 16)]
    edges = [(f"e{i}.f", "hub.h", "calls") for i in range(1, 16)]
    edges += [(f"e{i}.f", "hub.h", "uses") for i in (13, 14, 15)]
    areas = [area(0, ["hub.h"]), area(16, ["z.f"])] + [area(i, [f"e{i}.f"]) for i in range(1, 16)]
    index = GraphIndex("/nowhere", graph(nodes, edges, areas, [("z.f", "hub.h", "calls")]))
    data = area_diagram(index, 0)
    externals = [item["id"] for item in data["nodes"] if item.get("external")]
    assert externals == ["e13.f", "e14.f", "e15.f", "e1.f", "e10.f", "e11.f", "e12.f", "e2.f", "e3.f", "e4.f", "e5.f", "e6.f"]
    assert len(data["edges"]) == 15
    assert not any(edge["source"] in ("e7.f", "z.f") for edge in data["edges"])


def test_area_level_caps_members_and_offers_more():
    nodes = [node(f"big.f{i:03d}") for i in range(100)]
    methods = [node(f"wide.K.m{i:02d}", kind="method", start=10 + i) for i in range(30)]
    areas = [area(0, [n["id"] for n in nodes]), area(1, ["wide.K"] + [m["id"] for m in methods])]
    index = GraphIndex("/nowhere", graph(nodes + [node("wide.K", kind="class")] + methods, [], areas))
    first = area_diagram(index, 0)
    assert (len(first["nodes"]), first["shown"], first["total"], first["more"]) == (80, 80, 100, True)
    every = area_diagram(index, 0, limit=1000)
    assert (len(every["nodes"]), every["limit"], every["more"]) == (100, 400, False)
    assert area_diagram(index, 7) is None
    wide = area_diagram(index, 1)
    assert [len(wide["nodes"]), len(wide["nodes"][0]["members"]), wide["nodes"][0]["members_total"], wide["more"]] == [1, 26, 30, True]
    wide_all = area_diagram(index, 1, limit=400)
    assert [len(wide_all["nodes"][0]["members"]), wide_all["more"]] == [30, False]


def _get(port, path, headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    connection.request("GET", path, headers=headers or {})
    response = connection.getresponse()
    body = response.read()
    connection.close()
    return response.status, body


def test_diagram_route_needs_the_token_and_rejects_unknown_areas(tmp_path):
    ensure_dir(tmp_path)
    write_json(tmp_path / ".skylos" / "graph" / GRAPH_FILE, graph([node("a.one"), node("b.one")], [("a.one", "b.one", "calls")], [area(0, ["a.one"]), area(1, ["b.one"])]))
    server = GraphServer(tmp_path, 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        token = {"X-Skylos-Token": server.token}
        assert _get(port, "/api/diagram")[0] == 403
        status, body = _get(port, "/api/diagram", token)
        assert status == 200
        assert edge_set(json.loads(body)) == {("area:0", "area:1", 1, 0)}
        assert _get(port, "/api/diagram?area=9", token)[0] == 404
        assert _get(port, "/api/diagram?area=x", token)[0] == 404
        status, body = _get(port, "/api/diagram?area=0&impact=1&limit=5", token)
        assert status == 200
        assert json.loads(body)["level"] == "area"
    finally:
        server.shutdown()
        server.server_close()
