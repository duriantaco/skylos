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
