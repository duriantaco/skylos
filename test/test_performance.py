import unittest
import ast
from pathlib import Path
from tempfile import TemporaryDirectory
from skylos.rules.quality.performance import PerformanceRule


class TestPerformanceRule(unittest.TestCase):
    def _analyze(self, source_code, ignore_list=None, project_root=None):
        tree = ast.parse(source_code)
        rule = PerformanceRule(ignore_list=ignore_list)
        context = {"filename": "test_perf.py"}
        if project_root is not None:
            context.update(
                filename=str(Path(project_root) / "app.py"),
                project_root=project_root,
            )
        all_findings = []

        for node in ast.walk(tree):
            res = rule.visit_node(node, context)
            if res:
                all_findings.extend(res)

        return all_findings

    def test_detect_file_read_memory_risk(self):
        code = """
from io import BytesIO

def process(f, data, path):
    content = f.read()
    lines = f.readlines()
    other = f.readline()
    handle = BytesIO(b"fixed")
    handle.read()
    alias = handle
    alias.write(data)
    handle.read()
    handle.readlines()
    handle = open(path, "rb")
    handle.read()

class Holder:
    def __init__(self):
        self.buffer = BytesIO()

    def load(self, path):
        alias = self
        alias.buffer = open(path, "rb")
        return self.buffer.read()

def buffered():
    with BytesIO(b"fixed") as buffer:
        return buffer.read()
"""
        with TemporaryDirectory() as project_root:
            findings = self._analyze(code, project_root=project_root)
        # Memory reads remain quiet while the receiver and method are known.
        # readlines() allocates a new list, and alias writes can install files.
        self.assertEqual([finding["line"] for finding in findings], [5, 6, 13, 15, 24])
        self.assertTrue(all(finding["rule_id"] == "SKY-P401" for finding in findings))
        self.assertTrue(
            all("may materialize" in finding["message"] for finding in findings[:2])
        )
        self.assertIn("allocates a new list", findings[2]["message"])
        self.assertIn("entire remaining file", findings[3]["message"])
        self.assertIn("may materialize", findings[4]["message"])
        self.assertTrue(
            all("entire file" not in finding["message"] for finding in findings)
        )

        # Only a test module inside the scanned project can exempt a read.
        scoped_code = "def test_read(handle):\n    return handle.read()\n"
        with TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            project = base / "project"
            external = base / "external"
            project.mkdir()
            external.mkdir()
            local_test = project / "test_local.py"
            external_test = external / "test_external.py"
            local_test.write_text(scoped_code, encoding="utf-8")
            external_test.write_text(scoped_code, encoding="utf-8")
            linked = project / "linked"
            linked.symlink_to(external, target_is_directory=True)
            cases = (
                (local_test, 0),
                (external_test, 1),
                (linked / external_test.name, 1),
                (project / ".." / "external" / external_test.name, 1),
            )
            for filename, expected in cases:
                with self.subTest(filename=str(filename)):
                    rule = PerformanceRule()
                    context = {"filename": str(filename), "project_root": project}
                    findings = []
                    for node in ast.walk(ast.parse(scoped_code)):
                        findings.extend(rule.visit_node(node, context) or [])
                    self.assertEqual(
                        len([f for f in findings if f["rule_id"] == "SKY-P401"]),
                        expected,
                    )

    def test_chunked_read_is_not_memory_risk(self):
        # agent-pr-bench real-02/real-13: hashing a file in 1 MiB chunks.
        code = """
def digest(path, h):
    size = 1024 * 1024
    with open(path, "rb") as f:
        while chunk := f.read(size):
            h.update(chunk)
        f.read(4096)
        f.read(-1)
        f.read(None)
        f.readlines(0)
        f.read(0)
        size = -1
        f.read(size)
"""
        findings = [f for f in self._analyze(code) if f["rule_id"] == "SKY-P401"]
        self.assertEqual([f["line"] for f in findings], [8, 9, 10, 13])
        self.assertTrue(all("entire remaining file" in f["message"] for f in findings))

    def test_detect_pandas_no_chunk(self):
        code = """
import pandas as pd
df = pd.read_csv("large_file.csv") # Bad
"""
        findings = self._analyze(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "SKY-P402")

    def test_allow_pandas_with_chunk(self):
        code = """
import pandas as pd
df = pd.read_csv("large_file.csv", chunksize=1000) # Good
"""
        findings = self._analyze(code)
        self.assertEqual(len(findings), 0)

    def test_detect_nested_loops(self):
        code = """
def heavy(items, others):
    for item in items:
        print(item)
        for other in others:
            selected = other.key == item.key
            if selected:
                print(other)
        others = others
    buckets = {item: [] for item in items}
    alias = buckets
    for item in items:
        alias[item] = others
        for other in buckets[item]:
            if other.key == item.key:
                print(other)
"""
        findings = self._analyze(code)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["rule_id"], "SKY-P403")
        self.assertEqual(findings[0]["value"], "repeated_scan")
        self.assertEqual(findings[0]["evidence"]["outer_iterable"], "items")
        self.assertEqual(findings[0]["evidence"]["inner_iterable"], "others")
        self.assertEqual(findings[1]["evidence"]["inner_iterable"], "buckets[item]")

        # Copying the catalog changes identity, but retains the repeated work.
        code = """
def copy_catalog(items, catalog):
    for item in items:
        for other in catalog:
            if other.key == item.key:
                print(other)
        catalog = list(catalog)
"""
        findings = self._analyze(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "SKY-P403")

    def test_nested_loops_without_a_search_are_not_repeated_scans(self):
        code = """
def visit(items, others, size, index):
    rows = [items if index else items for index in items]
    for row in rows:
        for item in row:
            print(item)
    grid = [[0 for _ in range(size)] for _ in range(size)]
    for i in range(size):
        for j in range(size):
            grid[i][j] = 1 if i == j else 0
    for item in items:
        for other in others:
            compare(item, other)
    index = {item: [item] for item in items}
    for item in items:
        for entry in index[item]:
            if entry == item:
                print(entry)
    result = []
    for item in items:
        row = []
        for other in others:
            if item == other:
                row.append(1)
                continue
            row.append(0)
        result.append(row)

def reset_catalog(items, catalog):
    for item in items:
        for other in catalog:
            if other.key == item.key:
                print(other)
        catalog = [item]
"""
        self.assertEqual(self._analyze(code), [])

    def test_os_walk_partition_loops_are_not_quadratic(self):
        code = """
def inspect_tree(path):
    for root, dirs, files in os.walk(path, followlinks=False):
        for dirname in list(dirs):
            inspect_directory(root, dirname)
        for filename in files:
            inspect_file(root, filename)
"""
        findings = [
            finding
            for finding in self._analyze(code)
            if finding["rule_id"] == "SKY-P403"
        ]
        self.assertEqual(findings, [])

    def test_os_walk_does_not_hide_independent_nested_loops(self):
        code = """
def compare_tree(path, candidates):
    for root, dirs, files in os.walk(path):
        for candidate in candidates:
            if matches(root, candidate):
                print(root)
"""
        findings = [
            finding
            for finding in self._analyze(code)
            if finding["rule_id"] == "SKY-P403"
        ]
        self.assertEqual(len(findings), 1)

    def test_detect_unbounded_orm_all(self):
        code = """
def list_users():
    return User.query.all()
"""
        findings = self._analyze(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "SKY-P404")

    def test_detect_unbounded_sqlalchemy_session_query_all(self):
        code = """
def list_users(db):
    return db.session.query(User).all()
"""
        findings = self._analyze(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "SKY-P404")

    def test_allow_limited_orm_all(self):
        code = """
def list_users():
    return User.query.limit(100).all()
"""
        findings = self._analyze(code)
        self.assertEqual(len(findings), 0)

    def test_allow_django_queryset_all_because_it_is_lazy(self):
        code = """
def get_queryset():
    return User.objects.all()

def filtered_queryset():
    return User.objects.filter(active=True).all()
"""
        findings = self._analyze(code)
        self.assertEqual(len(findings), 0)

    def test_ignore_list_logic(self):
        code = """
def ignore_me(f, items, others):
    f.read()
    for i in items:
        for j in others:
            if i == j:
                pass
"""
        findings = self._analyze(code, ignore_list=[])
        self.assertEqual(len(findings), 2)

        findings = self._analyze(code, ignore_list=["SKY-P401"])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "SKY-P403")


if __name__ == "__main__":
    unittest.main()
