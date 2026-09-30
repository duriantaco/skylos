import unittest
import ast
from skylos.rules.quality.performance import PerformanceRule


class TestPerformanceRule(unittest.TestCase):
    def _analyze(self, source_code, ignore_list=None):
        tree = ast.parse(source_code)
        rule = PerformanceRule(ignore_list=ignore_list)
        context = {"filename": "test_perf.py"}
        all_findings = []

        for node in ast.walk(tree):
            res = rule.visit_node(node, context)
            if res:
                all_findings.extend(res)

        return all_findings

    def test_detect_file_read_memory_risk(self):
        code = """
def process(f):
    content = f.read()
    lines = f.readlines()
    other = f.readline()
"""
        findings = self._analyze(code)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["rule_id"], "SKY-P401")
        self.assertEqual(findings[1]["rule_id"], "SKY-P401")

    def test_chunked_read_is_not_memory_risk(self):
        # agent-pr-bench real-02/real-13: hashing a file in 1 MiB chunks.
        code = """
def digest(path, h):
    with open(path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
        f.read(size=4096)
        f.read(-1)
        f.read(None)
"""
        findings = [f for f in self._analyze(code) if f["rule_id"] == "SKY-P401"]
        self.assertEqual([f["line"] for f in findings], [7, 8])

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
def heavy():
    for i in range(10):
        print(i)
        for j in range(10):
            print(j)
"""
        findings = self._analyze(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "SKY-P403")

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
            compare(root, candidate)
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
def ignore_me(f):
    f.read()
    for i in range(10):
        for j in range(10):
            pass
"""
        findings = self._analyze(code, ignore_list=[])
        self.assertEqual(len(findings), 2)

        findings = self._analyze(code, ignore_list=["SKY-P401"])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "SKY-P403")


if __name__ == "__main__":
    unittest.main()
