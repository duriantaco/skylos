import ast


class LinterVisitor(ast.NodeVisitor):
    def __init__(self, rules, filename):
        self.rules = rules
        self.filename = filename
        self.findings = []
        self.context = {"filename": filename}

    def visit(self, node):
        for rule in self.rules:
            results = rule.visit_node(node, self.context)
            if results:
                self.findings.extend(results)

        for child in ast.iter_child_nodes(node):
            self.visit(child)
