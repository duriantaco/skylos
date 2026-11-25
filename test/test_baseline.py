import json

from skylos.core.baseline import filter_new_findings, load_baseline, save_baseline


def _sample_result():
    return {
        "unused_functions": [
            {"name": "old_func", "file": "app.py", "line": 10},
            {"name": "another_func", "file": "app.py", "line": 20},
        ],
        "unused_imports": [
            {"name": "os", "file": "app.py", "line": 1},
        ],
        "unused_classes": [],
        "unused_variables": [],
        "danger": [
            {
                "rule_id": "SKY-D211",
                "file": "app.py",
                "line": 50,
                "message": "SQL injection",
            },
        ],
        "quality": [
            {
                "rule_id": "SKY-Q301",
                "file": "app.py",
                "line": 80,
                "message": "Complex function",
            },
        ],
        "secrets": [],
    }


class TestSaveBaseline:
    def test_creates_file(self, tmp_path):
        result = _sample_result()
        path = save_baseline(tmp_path, result)
        assert path.exists()
        assert path.name == "baseline.json"
        assert path.parent.name == ".skylos"

    def test_counts_correct(self, tmp_path):
        result = _sample_result()
        save_baseline(tmp_path, result)
        baseline = json.loads((tmp_path / ".skylos" / "baseline.json").read_text())
        assert baseline["counts"]["unused_functions"] == 2
        assert baseline["counts"]["unused_imports"] == 1
        assert baseline["counts"]["danger"] == 1
        assert baseline["counts"]["quality"] == 1
        assert baseline["counts"]["secrets"] == 0

    def test_fingerprints_created(self, tmp_path):
        result = _sample_result()
        save_baseline(tmp_path, result)
        baseline = json.loads((tmp_path / ".skylos" / "baseline.json").read_text())
        fps = set(baseline["fingerprints"])
        assert "dead:unused_functions:old_func" in fps
        assert "dead:unused_functions:another_func" in fps
        assert "dead:unused_imports:os" in fps
        assert "SKY-D211:app.py:50" in fps
        assert "SKY-Q301:app.py:80" in fps

    def test_unused_file_round_trip_uses_rule_path_and_line(self, tmp_path):
        result = _sample_result()
        result["unused_files"] = [
            {
                "rule_id": "SKY-E003",
                "file": "src/unused.js",
                "line": 1,
            }
        ]
        result["analysis_summary"] = {"unused_files_count": 1}

        save_baseline(tmp_path, result)
        baseline = load_baseline(tmp_path)
        filtered = filter_new_findings(result, baseline)

        assert baseline["counts"]["unused_files"] == 1
        assert "SKY-E003:src/unused.js:1" in baseline["fingerprints"]
        assert filtered["unused_files"] == []
        assert filtered["analysis_summary"]["unused_files_count"] == 0

    def test_module_cycle_baseline_matches_directed_edges_across_checkouts(
        self, tmp_path
    ):
        original = {
            "rule_id": "SKY-CIRC",
            "cycle": ["pkg.a", "pkg.b", "pkg.c"],
            "file": str(tmp_path / "pkg/a.py"),
            "line": 4,
        }
        self_cycle = {**original, "cycle": ["pkg.a"]}
        result = {"circular_dependencies": [original, self_cycle]}
        save_baseline(tmp_path, result)
        baseline = load_baseline(tmp_path)
        moved = {
            **original,
            "cycle": ["pkg.b", "pkg.c", "pkg.a"],
            "file": str(tmp_path / "other-checkout/pkg/b.py"),
            "line": 24,
        }
        reversed_cycle = {**original, "cycle": ["pkg.a", "pkg.c", "pkg.b"]}
        filtered = filter_new_findings(
            {
                "circular_dependencies": [moved, reversed_cycle, self_cycle],
                "analysis_summary": {"circular_dependencies_count": 3},
            },
            baseline,
        )

        assert baseline["counts"]["circular_dependencies"] == 2
        assert filtered["circular_dependencies"] == [reversed_cycle]
        assert filtered["analysis_summary"]["circular_dependencies_count"] == 1

    def test_typescript_cycle_baseline_matches_all_edges_in_the_group(self, tmp_path):
        original = {
            "rule_id": "SKY-CIRC",
            "cycle": ["a.ts", "b.ts"],
            "file": str(tmp_path / "a.ts"),
            "line": 4,
            "cycle_edges": [
                ["a.ts", "b.ts"],
                ["b.ts", "a.ts"],
                ["b.ts", "c.ts"],
                ["c.ts", "a.ts"],
            ],
        }
        save_baseline(tmp_path, {"circular_dependencies": [original]})
        baseline = load_baseline(tmp_path)
        moved = {
            **original,
            "file": str(tmp_path / "other-checkout/a.ts"),
            "line": 8,
            "cycle_edges": list(reversed(original["cycle_edges"])),
        }
        grown = {
            **moved,
            "cycle_edges": [*moved["cycle_edges"], ["c.ts", "b.ts"]],
        }

        filtered = filter_new_findings(
            {"circular_dependencies": [moved, grown]}, baseline
        )

        assert filtered["circular_dependencies"] == [grown]

    def test_package_cycle_baseline_keeps_new_edges_between_existing_members(
        self, tmp_path
    ):
        outward = {
            "from_package": "pkg.web",
            "to_package": "pkg.db",
            "from_module": "pkg.web.page",
            "to_module": "pkg.db.connect",
            "file": "pkg/web/page.py",
            "line": 1,
        }
        return_edge = {
            "from_package": "pkg.db",
            "to_package": "pkg.web",
            "from_module": "pkg.db.audit",
            "to_module": "pkg.web.metrics",
            "file": "pkg/db/audit.py",
            "line": 5,
        }
        original = {
            "rule_id": "SKY-Q807",
            "file": "pkg/db/audit.py",
            "line": 5,
            "cycle_members": ["pkg.db", "pkg.web"],
            "dependency_edges": [outward, return_edge],
        }
        save_baseline(tmp_path, {"quality": [original]})
        baseline = load_baseline(tmp_path)
        moved = {
            **original,
            "line": 25,
            "dependency_edges": [
                {**return_edge, "line": 25},
                outward,
                {**outward, "line": 30},
            ],
        }
        grown = {
            **original,
            "dependency_edges": [
                outward,
                return_edge,
                {**outward, "to_module": "pkg.db.query"},
            ],
        }

        filtered = filter_new_findings({"quality": [moved, grown]}, baseline)

        assert filtered["quality"] == [grown]

    def test_cycle_does_not_match_legacy_file_and_line(self):
        finding = {
            "rule_id": "SKY-CIRC",
            "file": "app.py",
            "line": 5,
            "cycle": ["app", "store"],
        }
        result = {"circular_dependencies": [finding]}
        filtered = filter_new_findings(result, {"fingerprints": ["SKY-CIRC:app.py:5"]})

        assert filtered["circular_dependencies"] == [finding]

    def test_layer_baseline_does_not_hide_a_new_forbidden_import(self, tmp_path):
        original = {
            "rule_id": "SKY-Q805",
            "file": str(tmp_path / "app/domain/cart.py"),
            "line": 1,
            "from_module": "app.domain.cart",
            "from_layer": "domain",
            "to_module": "app.web.session",
            "to_layer": "web",
        }
        new_import = {**original, "to_module": "app.web.views"}
        moved = {**original, "line": 10}
        result = {"quality": [original]}
        legacy = {"fingerprints": [f"SKY-Q805:{original['file']}:1"]}
        assert filter_new_findings(result, legacy)["quality"] == [original]

        save_baseline(tmp_path, result)
        baseline = load_baseline(tmp_path)
        filtered = filter_new_findings({"quality": [moved, new_import]}, baseline)

        assert filtered["quality"] == [new_import]

    def test_overwrites_existing(self, tmp_path):
        save_baseline(tmp_path, _sample_result())
        save_baseline(
            tmp_path,
            {
                "unused_functions": [],
                "unused_imports": [],
                "unused_classes": [],
                "unused_variables": [],
                "danger": [],
                "quality": [],
                "secrets": [],
            },
        )
        baseline = json.loads((tmp_path / ".skylos" / "baseline.json").read_text())
        assert len(baseline["fingerprints"]) == 0


class TestLoadBaseline:
    def test_returns_none_if_missing(self, tmp_path):
        assert load_baseline(tmp_path) is None

    def test_loads_saved_baseline(self, tmp_path):
        save_baseline(tmp_path, _sample_result())
        baseline = load_baseline(tmp_path)
        assert baseline is not None
        assert "counts" in baseline
        assert "fingerprints" in baseline


class TestFilterNewFindings:
    def test_filters_known_findings(self):
        result = _sample_result()
        baseline = {
            "fingerprints": [
                "dead:unused_functions:old_func",
                "dead:unused_functions:another_func",
                "dead:unused_imports:os",
                "SKY-D211:app.py:50",
                "SKY-Q301:app.py:80",
            ]
        }
        filtered = filter_new_findings(result, baseline)
        assert len(filtered["unused_functions"]) == 0
        assert len(filtered["unused_imports"]) == 0
        assert len(filtered["danger"]) == 0
        assert len(filtered["quality"]) == 0

    def test_keeps_new_findings(self):
        result = _sample_result()
        result["danger"].append(
            {
                "rule_id": "SKY-D212",
                "file": "new.py",
                "line": 5,
                "message": "CMD injection",
            }
        )
        result["unused_functions"].append(
            {"name": "brand_new_func", "file": "new.py", "line": 15}
        )
        baseline = {
            "fingerprints": [
                "dead:unused_functions:old_func",
                "dead:unused_functions:another_func",
                "dead:unused_imports:os",
                "SKY-D211:app.py:50",
                "SKY-Q301:app.py:80",
            ]
        }
        filtered = filter_new_findings(result, baseline)
        assert len(filtered["danger"]) == 1
        assert filtered["danger"][0]["rule_id"] == "SKY-D212"
        assert len(filtered["unused_functions"]) == 1
        assert filtered["unused_functions"][0]["name"] == "brand_new_func"

    def test_empty_baseline_keeps_all(self):
        result = _sample_result()
        baseline = {"fingerprints": []}
        filtered = filter_new_findings(result, baseline)
        assert len(filtered["unused_functions"]) == 2
        assert len(filtered["danger"]) == 1
        assert len(filtered["quality"]) == 1

    def test_round_trip(self, tmp_path):
        """Save baseline, load it, filter — same result should yield 0 new."""
        result = _sample_result()
        save_baseline(tmp_path, result)
        baseline = load_baseline(tmp_path)
        filtered = filter_new_findings(result, baseline)
        total = sum(
            len(filtered.get(k, []))
            for k in [
                "unused_functions",
                "unused_imports",
                "unused_classes",
                "unused_variables",
                "danger",
                "quality",
                "secrets",
            ]
        )
        assert total == 0

    def test_recomputes_counts_and_removes_unfiltered_aggregates(self):
        result = _sample_result()
        result["reliability"] = [
            {
                "rule_id": "SKY-GPU001",
                "file": "Dockerfile",
                "line": 1,
                "message": "CUDA image needs a newer driver",
            }
        ]
        result["ai_defects"] = []
        result["analysis_summary"] = {
            "total_files": 1,
            "danger_count": 1,
            "reliability_count": 1,
            "quality_count": 1,
            "by_directory": [{"path": ".", "total": 3}],
            "dead_code_evidence": {"candidate_decisions": {"reported": 3}},
            "grep_verify": {"verified": 3},
        }
        result["grade"] = {"overall": {"score": 100}}
        result["ai_security_stats"] = {"total_findings": 3}
        result["provenance_summary"] = {"ai_authored_findings": 1}
        baseline = {
            "fingerprints": [
                "SKY-D211:app.py:50",
                "SKY-GPU001:Dockerfile:1",
                "SKY-Q301:app.py:80",
            ]
        }

        filtered = filter_new_findings(result, baseline)

        assert filtered["danger"] == []
        assert filtered["reliability"] == []
        assert filtered["quality"] == []
        assert filtered["analysis_summary"]["danger_count"] == 0
        assert filtered["analysis_summary"]["reliability_count"] == 0
        assert filtered["analysis_summary"]["quality_count"] == 0
        assert "by_directory" not in filtered["analysis_summary"]
        assert "dead_code_evidence" not in filtered["analysis_summary"]
        assert "grep_verify" not in filtered["analysis_summary"]
        assert "grade" not in filtered
        assert "ai_security_stats" not in filtered
        assert "provenance_summary" not in filtered

    def test_preserves_incomplete_grep_status(self):
        result = _sample_result()
        grep_verify = {
            "enabled": True,
            "complete": False,
            "status": "incomplete",
            "incomplete_reason": "budget_exhausted",
        }
        result["analysis_summary"] = {"grep_verify": grep_verify}

        filtered = filter_new_findings(result, {"fingerprints": []})

        assert filtered["analysis_summary"]["grep_verify"] == grep_verify
