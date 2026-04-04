import json
from skylos.city import (
    generate_topology,
    format_rich_summary,
    _squarify,
    _complexity_color,
    _grade_from_avg_complexity,
)


def _make_analysis(definitions=None, unused_functions=None, circular_dependencies=None):
    return {
        "definitions": definitions or {},
        "unused_functions": unused_functions or [],
        "unused_imports": [],
        "unused_classes": [],
        "unused_variables": [],
        "unused_parameters": [],
        "circular_dependencies": circular_dependencies or [],
    }


class TestSquarify:
    def test_empty_items(self):
        result = _squarify([], 0, 0, 100, 100)
        assert result == []

    def test_single_item(self):
        items = [{"area": 100, "id": "a"}]
        _squarify(items, 0, 0, 100, 100)
        assert items[0]["x"] == 0
        assert items[0]["y"] == 0
        assert items[0]["w"] == 100
        assert items[0]["h"] == 100

    def test_two_items(self):
        items = [{"area": 50, "id": "a"}, {"area": 50, "id": "b"}]
        _squarify(items, 0, 0, 100, 100)
        for it in items:
            assert it["w"] > 0
            assert it["h"] > 0
        total = sum(it["w"] * it["h"] for it in items)
        assert abs(total - 10000) < 1

    def test_zero_area_items(self):
        items = [{"area": 0}, {"area": 0}]
        _squarify(items, 0, 0, 100, 100)
        for it in items:
            assert "x" in it
            assert "y" in it

    def test_coordinates_within_bounds(self):
        items = [{"area": a} for a in [30, 20, 15, 10, 5]]
        _squarify(items, 10, 10, 80, 80)
        for it in items:
            assert it["x"] >= 10 - 0.01
            assert it["y"] >= 10 - 0.01
            assert it["x"] + it["w"] <= 90.01
            assert it["y"] + it["h"] <= 90.01


class TestComplexityColor:
    def test_low(self):
        assert _complexity_color(1) == "#4caf50"
        assert _complexity_color(3) == "#4caf50"

    def test_medium(self):
        assert _complexity_color(5) == "#ffeb3b"

    def test_high(self):
        assert _complexity_color(10) == "#ff9800"

    def test_critical(self):
        assert _complexity_color(20) == "#f44336"


class TestGrade:
    def test_grades(self):
        assert _grade_from_avg_complexity(1) == "A"
        assert _grade_from_avg_complexity(4) == "B"
        assert _grade_from_avg_complexity(6) == "C"
        assert _grade_from_avg_complexity(10) == "D"
        assert _grade_from_avg_complexity(15) == "F"


class TestGenerateTopology:
    def test_empty_analysis(self):
        result = _make_analysis()
        topology = generate_topology(result)

        assert topology["districts"] == []
        assert topology["edges"] == []
        assert topology["grade"] == "A"
        assert topology["summary"]["total_buildings"] == 0

    def test_single_definition(self):
        defs = {
            "mymod.foo": {
                "name": "foo",
                "file": "mymod/bar.py",
                "line": 10,
                "type": "function",
                "loc": 5,
                "complexity": 2,
                "calls": [],
                "called_by": [],
                "dead": False,
            }
        }
        topology = generate_topology(_make_analysis(definitions=defs))

        assert len(topology["districts"]) == 1
        assert topology["districts"][0]["name"] == "mymod"
        blocks = topology["districts"][0]["blocks"]
        assert len(blocks) == 1
        assert blocks[0]["name"] == "bar.py"
        buildings = blocks[0]["buildings"]
        assert len(buildings) == 1
        assert buildings[0]["name"] == "foo"
        assert buildings[0]["loc"] == 5
        assert buildings[0]["height"] == 5
        assert buildings[0]["complexity"] == 2
        assert buildings[0]["dead"] is False
        assert buildings[0]["color"] == "#4caf50"

    def test_dead_building_detection(self):
        defs = {
            "mod.dead_func": {
                "name": "dead_func",
                "file": "mod/a.py",
                "line": 1,
                "type": "function",
                "loc": 3,
                "complexity": 1,
                "calls": [],
                "called_by": [],
                "dead": False,
            }
        }
        unused = [{"name": "mod.dead_func", "type": "function"}]
        topology = generate_topology(
            _make_analysis(definitions=defs, unused_functions=unused)
        )

        building = topology["districts"][0]["blocks"][0]["buildings"][0]
        assert building["dead"] is True

    def test_edges_from_calls(self):
        defs = {
            "mod.caller": {
                "name": "caller",
                "file": "mod/a.py",
                "line": 1,
                "type": "function",
                "loc": 10,
                "complexity": 3,
                "calls": ["mod.callee"],
                "called_by": [],
                "dead": False,
            },
            "mod.callee": {
                "name": "callee",
                "file": "mod/a.py",
                "line": 15,
                "type": "function",
                "loc": 5,
                "complexity": 1,
                "calls": [],
                "called_by": ["mod.caller"],
                "dead": False,
            },
        }
        topology = generate_topology(_make_analysis(definitions=defs))

        assert len(topology["edges"]) == 1
        assert topology["edges"][0]["from"] == "mod.caller"
        assert topology["edges"][0]["to"] == "mod.callee"

    def test_circular_deps_passed_through(self):
        circulars = [{"cycle": ["a", "b", "a"], "severity": "warning"}]
        topology = generate_topology(_make_analysis(circular_dependencies=circulars))
        assert topology["circular_deps"] == circulars

    def test_multiple_districts(self):
        defs = {
            "pkg.a.foo": {
                "name": "foo",
                "file": "pkg/a/mod.py",
                "line": 1,
                "type": "function",
                "loc": 5,
                "complexity": 1,
                "calls": [],
                "called_by": [],
                "dead": False,
            },
            "pkg.b.bar": {
                "name": "bar",
                "file": "pkg/b/mod.py",
                "line": 1,
                "type": "function",
                "loc": 10,
                "complexity": 5,
                "calls": [],
                "called_by": [],
                "dead": False,
            },
        }
        topology = generate_topology(_make_analysis(definitions=defs))
        assert len(topology["districts"]) == 2
        assert topology["summary"]["total_districts"] == 2
        assert topology["summary"]["total_buildings"] == 2

    def test_layout_coordinates_present(self):
        defs = {
            "mod.func": {
                "name": "func",
                "file": "mod/a.py",
                "line": 1,
                "type": "function",
                "loc": 10,
                "complexity": 1,
                "calls": [],
                "called_by": [],
                "dead": False,
            }
        }
        topology = generate_topology(
            _make_analysis(definitions=defs), canvas_size=200.0
        )

        district = topology["districts"][0]
        assert "x" in district
        assert "y" in district
        assert "w" in district
        assert "h" in district

        block = district["blocks"][0]
        assert "x" in block
        assert "y" in block

        building = block["buildings"][0]
        assert "x" in building
        assert "y" in building
        assert "w" in building
        assert "h" in building

    def test_grade_calculation(self):
        defs = {}
        for i in range(5):
            defs[f"mod.func{i}"] = {
                "name": f"func{i}",
                "file": "mod/a.py",
                "line": i * 20,
                "type": "function",
                "loc": 15,
                "complexity": 15,
                "calls": [],
                "called_by": [],
                "dead": False,
            }
        topology = generate_topology(_make_analysis(definitions=defs))
        assert topology["grade"] == "F"

    def test_summary_fields(self):
        defs = {
            "mod.a": {
                "name": "a",
                "file": "mod/x.py",
                "line": 1,
                "type": "function",
                "loc": 5,
                "complexity": 2,
                "calls": ["mod.b"],
                "called_by": [],
                "dead": False,
            },
            "mod.b": {
                "name": "b",
                "file": "mod/x.py",
                "line": 10,
                "type": "function",
                "loc": 3,
                "complexity": 1,
                "calls": [],
                "called_by": ["mod.a"],
                "dead": False,
            },
        }
        topology = generate_topology(_make_analysis(definitions=defs))
        s = topology["summary"]
        assert s["total_districts"] == 1
        assert s["total_blocks"] == 1
        assert s["total_buildings"] == 2
        assert s["dead_buildings"] == 0
        assert s["total_edges"] == 1
        assert s["canvas_size"] == 100.0


class TestFormatRichSummary:
    def test_basic_output(self):
        defs = {
            "mod.func": {
                "name": "func",
                "file": "mod/a.py",
                "line": 1,
                "type": "function",
                "loc": 10,
                "complexity": 5,
                "calls": [],
                "called_by": [],
                "dead": False,
            }
        }
        topology = generate_topology(_make_analysis(definitions=defs))
        output = format_rich_summary(topology)

        assert "Code City Grade:" in output
        assert "Districts:" in output
        assert "Hotspots" in output

    def test_dead_buildings_shown(self):
        defs = {
            "mod.dead": {
                "name": "dead",
                "file": "mod/a.py",
                "line": 1,
                "type": "function",
                "loc": 5,
                "complexity": 1,
                "calls": [],
                "called_by": [],
                "dead": False,
            }
        }
        unused = [{"name": "mod.dead", "type": "function"}]
        topology = generate_topology(
            _make_analysis(definitions=defs, unused_functions=unused)
        )
        output = format_rich_summary(topology)
        assert "Abandoned Buildings" in output

    def test_empty_topology(self):
        topology = generate_topology(_make_analysis())
        output = format_rich_summary(topology)
        assert "Code City Grade: A" in output


class TestTopologyJSON:
    """Test that topology is JSON-serializable."""

    def test_serializable(self):
        defs = {
            "mod.func": {
                "name": "func",
                "file": "mod/a.py",
                "line": 1,
                "type": "function",
                "loc": 10,
                "complexity": 3,
                "calls": ["mod.other"],
                "called_by": [],
                "dead": False,
            }
        }
        topology = generate_topology(_make_analysis(definitions=defs))
        output = json.dumps(topology, indent=2)
        parsed = json.loads(output)
        assert parsed["grade"] in ("A", "B", "C", "D", "F")
