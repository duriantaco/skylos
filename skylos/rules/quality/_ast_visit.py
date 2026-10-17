import ast


class IterativeNodeVisitor(ast.NodeVisitor):
    """``ast.NodeVisitor`` whose default traversal uses an explicit stack.

    Nodes reach ``visit_*`` methods in the same pre-order as the standard
    visitor. Nodes without a custom method are expanded without recursion, so
    long operator chains or nested expressions do not exhaust the stack.
    """

    def generic_visit(self, node):
        pending = list(ast.iter_child_nodes(node))
        pending.reverse()
        while pending:
            child = pending.pop()
            visitor = getattr(self, "visit_" + child.__class__.__name__, None)
            if visitor is None:
                children = list(ast.iter_child_nodes(child))
                children.reverse()
                pending.extend(children)
            else:
                visitor(child)
