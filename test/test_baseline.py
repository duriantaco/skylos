import json
from skylos.baseline import save_baseline, load_baseline, filter_new_findings


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
