import ast
from collections import defaultdict


class LinterVisitor(ast.NodeVisitor):
    def __init__(self, rules, filename):
        self.rules = rules
        self.filename = filename
        self.findings = []
        self.context = {"filename": filename}
        self.generic_rules = []
        self.rules_by_node_type = defaultdict(list)
        for rule in rules:
            node_types = getattr(rule, "node_types", None)
            if node_types:
                for node_type in node_types:
                    self.rules_by_node_type[node_type].append(rule)
            else:
                self.generic_rules.append(rule)

    def visit(self, node):
        for rule in self.generic_rules:
            results = rule.visit_node(node, self.context)
            if results:
                self.findings.extend(results)

        for rule in self.rules_by_node_type.get(type(node), ()):
            results = rule.visit_node(node, self.context)
            if results:
                self.findings.extend(results)

        for child in ast.iter_child_nodes(node):
            self.visit(child)
