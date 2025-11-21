import ast
from skylos.constants import TEST_IMPORT_RE, TEST_DECOR_RE, TEST_FILE_RE


class TestAwareVisitor:
    def __init__(self, filename=None):
        self.is_test_file = False
        self.test_decorated_lines = set()

        if filename and TEST_FILE_RE.search(str(filename)):
            self.is_test_file = True

    def visit(self, node):
        method = "visit_" + node.__class__.__name__
        visitor = getattr(self, method, self.generic_visit)
        return visitor(node)

    def generic_visit(self, node):
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        self.visit(item)
            elif isinstance(value, ast.AST):
                self.visit(value)

    def visit_Import(self, node):
        if self.is_test_file:
            for alias in node.names:
                if TEST_IMPORT_RE.match(alias.name):
                    pass
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if self.is_test_file:
            if node.module and TEST_IMPORT_RE.match(node.module):
                pass
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        if (
            node.name.startswith("test_")
            or node.name.endswith("_test")
            or any(node.name.startswith(prefix) for prefix in ["setup", "teardown"])
            or node.name
            in [
                "setUp",
                "tearDown",
                "setUpClass",
                "tearDownClass",
                "setUpModule",
                "tearDownModule",
            ]
        ):
            self.test_decorated_lines.add(node.lineno)

        for deco in node.decorator_list:
            name = self._decorator_name(deco)
            if name and (
                TEST_DECOR_RE.match(name) or "pytest" in name or "fixture" in name
            ):
                self.test_decorated_lines.add(node.lineno)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def _decorator_name(self, deco):
        if isinstance(deco, ast.Name):
            return deco.id
        if isinstance(deco, ast.Attribute):
            parent = self._decorator_name(deco.value)
            return f"{parent}.{deco.attr}" if parent else deco.attr
        return ""
