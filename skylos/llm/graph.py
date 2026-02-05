import ast
import networkx as nx


class CodeGraph:
    def __init__(self):
        self.call_graph = nx.DiGraph()
        self.data_flow = nx.DiGraph()
        self.definitions = {}
        self.class_hierarchy = {}
        self.source_lines = []

        self.taint_sources = {
            "request.args",
            "request.form",
            "request.json",
            "request.data",
            "input",
            "raw_input",
            "sys.argv",
            "os.environ",
            "request.GET",
            "request.POST",
        }
        self.taint_sinks = {
            "execute",
            "raw",
            "system",
            "popen",
            "eval",
            "exec",
            "subprocess.call",
            "subprocess.run",
            "subprocess.Popen",
            "os.system",
            "render_template_string",
            "open",
        }

    def build(self, source_code):
        self.source_lines = source_code.splitlines()
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                self._add_def(node, "class")
                bases = [b.id for b in node.bases if isinstance(b, ast.Name)]
                self.class_hierarchy[node.name] = bases
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self._add_def(item, "method", parent=node.name)

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name not in self.definitions:
                    self._add_def(node, "function")

        for name, def_data in self.definitions.items():
            visitor = ContextCallVisitor(name, self.definitions)
            visitor.visit(def_data["node"])
            for called in visitor.calls:
                self.call_graph.add_edge(name, called)

        for name, def_data in self.definitions.items():
            df_visitor = DataFlowVisitor(name)
            df_visitor.visit(def_data["node"])
            for src, dst, line in df_visitor.flows:
                if not isinstance(src, str) or not isinstance(dst, str):
                    continue
                if not src or not dst:
                    continue
                self.data_flow.add_edge(f"{name}:{src}", f"{name}:{dst}", line=line)
            def_data["params"] = df_visitor.params
            def_data["returns"] = df_visitor.returns

        self.propagate_sinks()

    def _add_def(self, node, dtype, parent=None):
        name = node.name if not parent else f"{parent}.{node.name}"
        if name in self.definitions:
            return
        self.definitions[name] = {
            "node": node,
            "type": dtype,
            "start": node.lineno - 1,
            "end": getattr(node, "end_lineno", node.lineno),
            "params": [],
            "returns": [],
        }
        self.call_graph.add_node(name)

    def get_slice(self, target_name, depth=1):
        if target_name not in self.definitions:
            return None

        relevant = {target_name}
        if depth > 0 and self.call_graph.has_node(target_name):
            try:
                for d in range(1, depth + 1):
                    descendants = nx.descendants_at_distance(
                        self.call_graph, target_name, d
                    )
                    relevant.update(descendants)
            except Exception:
                pass

        output = []
        for name in relevant:
            if name == target_name:
                continue
            if name in self.definitions:
                d = self.definitions[name]
                code = "\n".join(self.source_lines[d["start"] : d["end"]])
                output.append(f"# [Dependency] {name}\n{code}")

        d = self.definitions[target_name]
        code = "\n".join(self.source_lines[d["start"] : d["end"]])
        output.append(f"# [Target] {target_name}\n{code}")

        return "\n\n".join(output)

    def get_cross_file_slice(self, target_name, defs_map, depth=2):
        base_slice = self.get_slice(target_name, depth=depth)
        if not base_slice or not defs_map:
            return base_slice

        if target_name not in self.definitions:
            return base_slice

        def_data = self.definitions[target_name]
        node = def_data["node"]

        call_visitor = ContextCallVisitor(target_name, self.definitions)
        call_visitor.visit(node)

        cross_file_deps = []
        for called in call_visitor.calls:
            if called not in self.definitions and called in defs_map:
                ext_def = defs_map[called]
                cross_file_deps.append(
                    f"# [External: {ext_def.get('file', 'unknown')}] {called}"
                )
                if "code" in ext_def:
                    cross_file_deps.append(ext_def["code"])
                elif "source" in ext_def:
                    cross_file_deps.append(ext_def["source"])

        if cross_file_deps:
            return "\n".join(cross_file_deps) + "\n\n" + base_slice

        return base_slice

    def find_taint_paths(self, func_name):
        if func_name not in self.definitions:
            return []

        paths = []
        prefix = f"{func_name}:"

        tainted_nodes = set()
        for node in self.data_flow.nodes():
            if not isinstance(node, str):
                continue
            if not node.startswith(prefix):
                continue
            var_name = node[len(prefix) :]
            if any(src in var_name for src in self.taint_sources):
                tainted_nodes.add(node)

        def_data = self.definitions[func_name]
        for param in def_data.get("params", []):
            param_node = f"{prefix}{param}"
            if self.data_flow.has_node(param_node):
                tainted_nodes.add(param_node)

        all_tainted = set(tainted_nodes)
        for source in tainted_nodes:
            if self.data_flow.has_node(source):
                try:
                    reachable = nx.descendants(self.data_flow, source)
                    all_tainted.update(reachable)
                except Exception:
                    pass

        for node in all_tainted:
            if not isinstance(node, str):
                continue
            var_name = node[len(prefix) :] if node.startswith(prefix) else node
            for sink in self.taint_sinks:
                if sink in var_name:
                    for source in tainted_nodes:
                        if self.data_flow.has_node(source) and self.data_flow.has_node(
                            node
                        ):
                            try:
                                if nx.has_path(self.data_flow, source, node):
                                    path = nx.shortest_path(
                                        self.data_flow, source, node
                                    )
                                    paths.append(
                                        {
                                            "source": source,
                                            "sink": node,
                                            "path": path,
                                            "sink_type": sink,
                                        }
                                    )
                            except Exception:
                                pass

        return paths

    def get_security_context(self, func_name, defs_map=None):
        if defs_map:
            base_slice = self.get_cross_file_slice(func_name, defs_map, depth=2)
        else:
            base_slice = self.get_slice(func_name, depth=2)

        if not base_slice:
            return None

        taint_paths = self.find_taint_paths(func_name)

        if taint_paths:
            hints = ["\n# [SECURITY HINTS - Potential taint flows detected]"]
            for tp in taint_paths[:5]:
                src = tp["source"].split(":")[-1]
                sink = tp["sink"].split(":")[-1]
                hints.append(f"# ⚠️  {src} → {sink} (potential {tp['sink_type']})")
            base_slice = "\n".join(hints) + "\n\n" + base_slice

        return base_slice

    def get_function_summary(self, func_name):
        if func_name not in self.definitions:
            return None

        def_data = self.definitions[func_name]
        summary = {
            "name": func_name,
            "type": def_data["type"],
            "params": def_data.get("params", []),
            "calls": list(self.call_graph.successors(func_name))
            if self.call_graph.has_node(func_name)
            else [],
            "called_by": list(self.call_graph.predecessors(func_name))
            if self.call_graph.has_node(func_name)
            else [],
            "taint_paths": self.find_taint_paths(func_name),
        }
        return summary

    def propagate_sinks(self):
        changed = True
        while changed:
            changed = False
            for name, def_data in self.definitions.items():
                if name in self.taint_sinks:
                    continue

                params = def_data.get("params", [])
                if not params:
                    continue

                prefix = f"{name}:"
                is_wrapper = False

                for param in params:
                    param_node = f"{prefix}{param}"

                    if not self.data_flow.has_node(param_node):
                        continue

                    try:
                        descendants = nx.descendants(self.data_flow, param_node)
                    except nx.NetworkXError:
                        continue

                    for node in descendants:
                        # Safety: ensure node is a string before using 'in'
                        if not isinstance(node, str):
                            continue
                        if any(sink in node for sink in self.taint_sinks):
                            is_wrapper = True
                            break

                    if is_wrapper:
                        break

                if is_wrapper:
                    self.taint_sinks.add(name)
                    changed = True


class DataFlowVisitor(ast.NodeVisitor):
    def __init__(self, scope_name):
        super().__init__()
        self.scope = scope_name
        self.flows = []
        self.params = []
        self.returns = []
        self._in_nested_scope = False

    def visit_FunctionDef(self, node):
        if self._in_nested_scope:
            return

        self._in_nested_scope = True
        for arg in node.args.args:
            self.params.append(arg.arg)

        for stmt in node.body:
            self.visit(stmt)

        self._in_nested_scope = False

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        pass

    def generic_visit(self, node):
        pass

    def visit_Assign(self, node):
        targets = []
        for target in node.targets:
            if isinstance(target, ast.Name):
                targets.append(target.id)
            elif isinstance(target, ast.Tuple):
                for elt in target.elts:
                    if isinstance(elt, ast.Name):
                        targets.append(elt.id)

        sources = self._extract_names(node.value)

        for src in sources:
            for tgt in targets:
                self.flows.append((src, tgt, node.lineno))

    def visit_AugAssign(self, node):
        if isinstance(node.target, ast.Name):
            target = node.target.id
            sources = self._extract_names(node.value)
            sources.add(target)
            for src in sources:
                self.flows.append((src, target, node.lineno))

    def visit_Return(self, node):
        if node.value:
            self.returns.extend(self._extract_names(node.value))

    def visit_Call(self, node):
        call_name = self._get_call_name(node)
        if call_name:
            for arg in node.args:
                for name in self._extract_names(arg):
                    self.flows.append((name, f"call:{call_name}", node.lineno))

    def visit_Expr(self, node):
        self.visit(node.value)

    def visit_If(self, node):
        for stmt in node.body:
            self.visit(stmt)
        for stmt in node.orelse:
            self.visit(stmt)

    def visit_For(self, node):
        # Track loop variable assignment
        if isinstance(node.target, ast.Name):
            sources = self._extract_names(node.iter)
            for src in sources:
                self.flows.append((src, node.target.id, node.lineno))

        for stmt in node.body:
            self.visit(stmt)
        for stmt in node.orelse:
            self.visit(stmt)

    def visit_While(self, node):
        for stmt in node.body:
            self.visit(stmt)
        for stmt in node.orelse:
            self.visit(stmt)

    def visit_With(self, node):
        for item in node.items:
            if item.optional_vars and isinstance(item.optional_vars, ast.Name):
                sources = self._extract_names(item.context_expr)
                for src in sources:
                    self.flows.append((src, item.optional_vars.id, node.lineno))

        for stmt in node.body:
            self.visit(stmt)

    def visit_Try(self, node):
        for stmt in node.body:
            self.visit(stmt)
        for handler in node.handlers:
            for stmt in handler.body:
                self.visit(stmt)
        for stmt in node.orelse:
            self.visit(stmt)
        for stmt in node.finalbody:
            self.visit(stmt)

    def _extract_names(self, node):
        names = set()
        if node is None:
            return names

        self._visit_for_names(node, names)
        return names

    def _visit_for_names(self, node, names):
        if node is None:
            return

        if isinstance(node, ast.Name):
            names.add(node.id)

        elif isinstance(node, ast.Attribute):
            chain = self._get_attr_chain(node)
            if chain:
                names.add(chain)

        elif isinstance(node, ast.Call):
            for arg in node.args:
                self._visit_for_names(arg, names)
            for keyword in node.keywords:
                if keyword.value:
                    self._visit_for_names(keyword.value, names)

        elif isinstance(node, ast.Subscript):
            self._visit_for_names(node.value, names)
            if isinstance(node.slice, ast.Index):
                self._visit_for_names(node.slice.value, names)
            else:
                self._visit_for_names(node.slice, names)

        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for elt in node.elts:
                self._visit_for_names(elt, names)

        elif isinstance(node, ast.Dict):
            for key in node.keys:
                if key:
                    self._visit_for_names(key, names)
            for val in node.values:
                self._visit_for_names(val, names)

        elif isinstance(node, ast.BinOp):
            self._visit_for_names(node.left, names)
            self._visit_for_names(node.right, names)

        elif isinstance(node, ast.UnaryOp):
            self._visit_for_names(node.operand, names)

        elif isinstance(node, ast.Compare):
            self._visit_for_names(node.left, names)
            for comp in node.comparators:
                self._visit_for_names(comp, names)

        elif isinstance(node, ast.BoolOp):
            for val in node.values:
                self._visit_for_names(val, names)

        elif isinstance(node, ast.IfExp):
            self._visit_for_names(node.test, names)
            self._visit_for_names(node.body, names)
            self._visit_for_names(node.orelse, names)

        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            self._visit_for_names(node.elt, names)
            for gen in node.generators:
                self._visit_for_names(gen.iter, names)

        elif isinstance(node, ast.DictComp):
            self._visit_for_names(node.key, names)
            self._visit_for_names(node.value, names)
            for gen in node.generators:
                self._visit_for_names(gen.iter, names)

        elif isinstance(node, ast.Starred):
            self._visit_for_names(node.value, names)

        elif isinstance(node, ast.JoinedStr):
            for val in node.values:
                if isinstance(val, ast.FormattedValue):
                    self._visit_for_names(val.value, names)

        elif isinstance(node, ast.Lambda):
            self._visit_for_names(node.body, names)

        else:
            for child in ast.iter_child_nodes(node):
                self._visit_for_names(child, names)

    def _get_attr_chain(self, node):
        if not isinstance(node, ast.Attribute):
            return ""

        parts = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value

        if isinstance(current, ast.Name):
            parts.append(current.id)
            return ".".join(reversed(parts))

        if parts:
            return ".".join(reversed(parts))

        return ""

    def _get_call_name(self, node):
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return self._get_attr_chain(node.func)
        return None


class ContextCallVisitor(ast.NodeVisitor):
    def __init__(self, current_scope, definitions):
        super().__init__()
        self.calls = set()
        self.current_scope = current_scope
        self.definitions = definitions
        if "." in current_scope:
            self.current_class = current_scope.split(".")[0]
        else:
            self.current_class = None

    def visit(self, node):
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                self._process_call(child)

    def _process_call(self, node):
        if isinstance(node.func, ast.Attribute) and isinstance(
            node.func.value, ast.Name
        ):
            if node.func.value.id == "self" and self.current_class:
                target = f"{self.current_class}.{node.func.attr}"
                if target in self.definitions:
                    self.calls.add(target)
        elif isinstance(node.func, ast.Name):
            if node.func.id in self.definitions:
                self.calls.add(node.func.id)
