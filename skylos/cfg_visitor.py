# import ast

# class BasicBlock:
#     def __init__(self, id):
#         self.id = id
#         self.statements = []
#         self.exits = []
#         self.incoming = []

#     def add_edge(self, target_block):
#         self.exits.append(target_block)
#         target_block.incoming.append(self)

# class CFGBuilder(ast.NodeVisitor):
#     def __init__(self):
#         self.blocks = []
#         self.current_block = None
#         self.cfgs = {}

#     def _new_block(self):
#         block = BasicBlock(len(self.blocks))
#         self.blocks.append(block)
#         return block

#     def visit_FunctionDef(self, node):
#         entry_block = self._new_block()
#         self.cfgs[node.name] = entry_block
#         self.current_block = entry_block

#         for stmt in node.body:
#             self.visit(stmt)

#     def visit_If(self, node):
#         self.current_block.statements.append(node.test)

#         cond_block = self.current_block
#         then_block = self._new_block()
#         else_block = self._new_block()
#         join_block = self._new_block()

#         cond_block.add_edge(then_block)
#         cond_block.add_edge(else_block)

#         self.current_block = then_block
#         for stmt in node.body:
#             self.visit(stmt)
#         self.current_block.add_edge(join_block)

#         self.current_block = else_block
#         for stmt in node.orelse:
#             self.visit(stmt)
#         self.current_block.add_edge(join_block)

#         self.current_block = join_block

#     def generic_visit(self, node):
#         if isinstance(node, ast.stmt):
#             if self.current_block:
#                 self.current_block.statements.append(node)
#         super().generic_visit(node)
