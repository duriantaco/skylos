from pathlib import Path
import tempfile
import sqlite3

from skylos.implicit_refs import ImplicitRefTracker


class MockDefinition:
    def __init__(self, simple_name, filename="app.py", line=10):
        self.simple_name = simple_name
        self.filename = filename
        self.line = line


class TestImplicitRefTracker:
    def test_init(self):
        tracker = ImplicitRefTracker()
        assert tracker.known_refs == set()
        assert tracker.pattern_refs == []
        assert tracker.f_string_patterns == {}
        assert tracker.coverage_hits == set()

    def test_exact_match_found(self):
        tracker = ImplicitRefTracker()
        tracker.known_refs.add("handle_login")

        defn = MockDefinition("handle_login")
        found, confidence, reason = tracker.should_mark_as_used(defn)

        assert found is True
        assert confidence == 95
        assert reason == "dynamic reference"

    def test_exact_match_not_found(self):
        tracker = ImplicitRefTracker()
        tracker.known_refs.add("handle_login")

        defn = MockDefinition("handle_logout")
        found, confidence, reason = tracker.should_mark_as_used(defn)

        assert found is False
        assert confidence == 0
        assert reason is None

    def test_multiple_known_refs(self):
        tracker = ImplicitRefTracker()
        tracker.known_refs.add("func_a")
        tracker.known_refs.add("func_b")
        tracker.known_refs.add("func_c")

        assert tracker.should_mark_as_used(MockDefinition("func_b"))[0] is True
        assert tracker.should_mark_as_used(MockDefinition("func_d"))[0] is False

    def test_pattern_match_prefix(self):
        tracker = ImplicitRefTracker()
        tracker.pattern_refs.append(("handle_*", 70))

        defn = MockDefinition("handle_login")
        found, confidence, reason = tracker.should_mark_as_used(defn)

        assert found is True
        assert confidence == 70
        assert "handle_*" in reason

    def test_pattern_match_suffix(self):
        tracker = ImplicitRefTracker()
        tracker.pattern_refs.append(("*_handler", 65))

        defn = MockDefinition("login_handler")
        found, confidence, reason = tracker.should_mark_as_used(defn)

        assert found is True
        assert confidence == 65

    def test_pattern_match_middle(self):
        tracker = ImplicitRefTracker()
        tracker.pattern_refs.append(("do_*_action", 60))

        defn = MockDefinition("do_login_action")
        found, confidence, reason = tracker.should_mark_as_used(defn)

        assert found is True
        assert confidence == 60

    def test_pattern_no_match(self):
        tracker = ImplicitRefTracker()
        tracker.pattern_refs.append(("handle_*", 70))

        defn = MockDefinition("process_login")
        found, _, _ = tracker.should_mark_as_used(defn)

        assert found is False

    def test_multiple_patterns_first_wins(self):
        tracker = ImplicitRefTracker()
        tracker.pattern_refs.append(("handle_*", 70))
        tracker.pattern_refs.append(("*_login", 80))

        defn = MockDefinition("handle_login")
        found, confidence, reason = tracker.should_mark_as_used(defn)

        assert found is True
        assert confidence == 70

    def test_coverage_hit_exact(self):
        tracker = ImplicitRefTracker()
        tracker.coverage_hits.add(("app.py", 10))

        defn = MockDefinition("my_func", filename="app.py", line=10)
        found, confidence, reason = tracker.should_mark_as_used(defn)

        assert found is True
        assert confidence == 100
        assert reason == "executed (coverage)"

    def test_coverage_hit_full_path(self):
        tracker = ImplicitRefTracker()
        tracker.coverage_hits.add(("/home/user/project/app.py", 25))

        defn = MockDefinition("my_func", filename="app.py", line=25)
        found, confidence, _ = tracker.should_mark_as_used(defn)

        assert found is True
        assert confidence == 100

    def test_coverage_hit_wrong_line(self):
        tracker = ImplicitRefTracker()
        tracker.coverage_hits.add(("app.py", 10))

        defn = MockDefinition("my_func", filename="app.py", line=20)
        found, _, _ = tracker.should_mark_as_used(defn)

        assert found is False

    def test_coverage_hit_wrong_file(self):
        tracker = ImplicitRefTracker()
        tracker.coverage_hits.add(("utils.py", 10))

        defn = MockDefinition("my_func", filename="app.py", line=10)
        found, _, _ = tracker.should_mark_as_used(defn)

        assert found is False

    def test_known_refs_checked_before_patterns(self):
        tracker = ImplicitRefTracker()
        tracker.known_refs.add("handle_login")
        tracker.pattern_refs.append(("handle_*", 70))

        defn = MockDefinition("handle_login")
        _, confidence, reason = tracker.should_mark_as_used(defn)

        assert confidence == 95
        assert reason == "dynamic reference"

    def test_patterns_checked_before_coverage(self):
        tracker = ImplicitRefTracker()
        tracker.pattern_refs.append(("my_*", 70))
        tracker.coverage_hits.add(("app.py", 10))

        defn = MockDefinition("my_func", filename="app.py", line=10)
        found, confidence, reason = tracker.should_mark_as_used(defn)

        assert confidence == 70
        assert "my_*" in reason

    def test_load_coverage_file_not_exists(self):
        tracker = ImplicitRefTracker()
        result = tracker.load_coverage("/nonexistent/.coverage")

        assert result is None
        assert len(tracker.coverage_hits) == 0

    def test_load_coverage_real_db(self):
        tracker = ImplicitRefTracker()

        with tempfile.NamedTemporaryFile(suffix=".coverage", delete=False) as f:
            db_path = f.name

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute("CREATE TABLE file (id INTEGER PRIMARY KEY, path TEXT)")
            cursor.execute("CREATE TABLE line_bits (file_id INTEGER, numbits BLOB)")

            cursor.execute("INSERT INTO file VALUES (1, '/project/app.py')")
            cursor.execute("INSERT INTO file VALUES (2, '/project/utils.py')")

            cursor.execute("INSERT INTO line_bits VALUES (1, ?)", (bytes([14]),))

            cursor.execute("INSERT INTO line_bits VALUES (2, ?)", (bytes([0, 4]),))

            conn.commit()
            conn.close()

            tracker.load_coverage(db_path)

            assert len(tracker.coverage_hits) > 0
            assert ("/project/app.py", 1) in tracker.coverage_hits
            assert ("/project/app.py", 2) in tracker.coverage_hits
            assert ("/project/app.py", 3) in tracker.coverage_hits
            assert ("/project/utils.py", 10) in tracker.coverage_hits

        finally:
            Path(db_path).unlink(missing_ok=True)

    def test_load_coverage_corrupted_db(self):
        tracker = ImplicitRefTracker()

        with tempfile.NamedTemporaryFile(suffix=".coverage", delete=False) as f:
            f.write(b"not a sqlite database")
            db_path = f.name

        try:
            tracker.load_coverage(db_path)
            assert len(tracker.coverage_hits) == 0
        finally:
            Path(db_path).unlink(missing_ok=True)


class TestPatternTracker:
    def test_singleton_exists(self):
        from skylos.implicit_refs import pattern_tracker

        assert isinstance(pattern_tracker, ImplicitRefTracker)
