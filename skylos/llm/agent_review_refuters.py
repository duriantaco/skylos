from __future__ import annotations

from .schemas import IssueType


class AgentReviewRefuterMixin:
    def _remap_handler_symbols(self, findings, source):
        import ast

        if not findings:
            return findings

        try:
            tree = ast.parse(source)
        except SyntaxError:
            return findings

        function_nodes = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        weak_symbols = {
            "archive",
            "bundle",
            "file",
            "filename",
            "handle",
            "member",
            "name",
            "path",
            "request",
            "target",
            "upload",
        }

        for finding in findings:
            if finding.issue_type != IssueType.SECURITY:
                continue
            symbol = str(getattr(finding, "symbol", "") or "")
            if symbol and symbol not in weak_symbols:
                continue
            owner = self._function_for_line(function_nodes, finding.location.line)
            if owner is None:
                continue
            if not self._function_has_handler_security_pattern(owner):
                continue
            if symbol and symbol != owner.name:
                finding.metadata["symbol_remapped_from"] = symbol
            finding.symbol = owner.name

        return findings

    def _function_for_line(self, functions, line):
        owner = None
        owner_start = -1
        for node in functions:
            start = getattr(node, "lineno", 0)
            end = getattr(node, "end_lineno", start)
            if start <= line <= end and start > owner_start:
                owner = node
                owner_start = start
        return owner

    def _function_has_handler_security_pattern(self, node):
        import ast

        if getattr(node, "decorator_list", None):
            return True
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                name = self._call_name(child.func)
                if name.split(".")[-1] in {"extractall", "extract"}:
                    return True
                if name == "open":
                    return True
            if self._is_request_files_expr(child):
                return True
        return False

    def _filter_refuted_agent_findings(self, findings, source, issue_types=None):
        import ast

        if not findings:
            return findings

        try:
            tree = ast.parse(source)
        except SyntaxError:
            return findings

        function_nodes = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]

        filtered = []
        for finding in findings:
            if self._is_static_agent_finding(finding):
                filtered.append(finding)
                continue
            if not self._finding_matches_active_modes(finding, issue_types):
                continue
            owner = self._owner_function_for_finding(finding, function_nodes)
            if owner is None:
                filtered.append(finding)
                continue
            if self._refutes_clean_async_owner(finding, owner):
                continue
            if self._refutes_safe_subprocess_owner(finding, owner, tree):
                continue
            if self._refutes_clean_quality_owner(finding, owner):
                continue
            filtered.append(finding)
        return filtered

    def _is_static_agent_finding(self, finding):
        return (finding.metadata or {}).get("source") == "static_agent_hint"

    def _finding_matches_active_modes(self, finding, issue_types=None):
        modes = self._active_review_modes(issue_types)
        if not modes:
            return True
        mode = self._static_route_mode_for_finding(finding)
        return not mode or mode in modes

    def _owner_function_for_finding(self, finding, functions):
        symbol = str(getattr(finding, "symbol", "") or "")
        if symbol:
            short = symbol.split(".")[-1]
            for node in functions:
                if node.name == short:
                    return node
        return self._function_for_line(functions, finding.location.line)

    def _refutes_safe_subprocess_owner(self, finding, owner, tree):
        evidence = self._finding_text(finding)
        if not any(
            term in evidence
            for term in ("command", "shell", "subprocess", "injection", "popen")
        ):
            return False
        return self._function_uses_literal_subprocess_allowlist(owner, tree)

    def _refutes_clean_async_owner(self, finding, owner):
        import ast

        if finding.issue_type not in {
            IssueType.QUALITY,
            IssueType.BUG,
            IssueType.PERFORMANCE,
            IssueType.STYLE,
            IssueType.HALLUCINATION,
        }:
            return False

        return isinstance(owner, ast.AsyncFunctionDef) and self._is_clean_async_helper(
            owner
        )

    def _function_uses_literal_subprocess_allowlist(self, node, tree):
        import ast

        saw_safe_subprocess = False
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            if self._call_name(child.func).split(".")[:1] != ["subprocess"]:
                continue
            if self._call_has_shell_true(child):
                return False
            if not child.args:
                return False
            argv = child.args[0]
            if isinstance(argv, (ast.List, ast.Tuple)):
                if not self._literal_sequence(argv):
                    return False
                saw_safe_subprocess = True
                continue
            allowlist = self._subscript_name(argv)
            if (
                allowlist
                and allowlist.isupper()
                and self._literal_allowlist_is_safe(tree, allowlist)
            ):
                saw_safe_subprocess = True
                continue
            return False
        return saw_safe_subprocess

    def _call_has_shell_true(self, node):
        import ast

        for keyword in node.keywords:
            if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
                return keyword.value.value is True
        return False

    def _literal_sequence(self, node):
        import ast

        return all(isinstance(item, ast.Constant) for item in node.elts)

    def _subscript_name(self, node):
        import ast

        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
            return node.value.id
        return ""

    def _literal_allowlist_is_safe(self, tree, name):
        bindings = self._literal_allowlist_bindings(tree, name)
        return (
            bindings is not None
            and len(bindings) == 1
            and self._literal_allowlist_value(bindings[0])
        )

    def _literal_allowlist_bindings(self, tree, name):
        import ast

        bindings = []
        for node in ast.walk(tree):
            if self._node_mutates_name(node, name):
                return None
            if isinstance(node, ast.Assign):
                target = node.targets[0] if len(node.targets) == 1 else None
                if isinstance(target, ast.Name) and target.id == name:
                    bindings.append(node.value)
        return bindings

    def _node_mutates_name(self, node, name):
        import ast

        if isinstance(node, ast.Assign):
            return any(self._target_mutates_name(target, name) for target in node.targets)
        if isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            return self._assignment_mutates_name(node.target, name)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            return self._call_mutates_name(node.func, name)
        return False

    def _assignment_mutates_name(self, target, name):
        import ast

        return (
            isinstance(target, ast.Name)
            and target.id == name
            or self._target_mutates_name(target, name)
        )

    def _call_mutates_name(self, func, name):
        mutating_methods = {
            "append",
            "clear",
            "extend",
            "insert",
            "pop",
            "remove",
            "setdefault",
            "update",
        }
        return (
            self._call_name(func.value) == name
            and func.attr in mutating_methods
        )

    def _target_mutates_name(self, target, name):
        import ast

        if isinstance(target, ast.Subscript):
            return self._call_name(target.value) == name
        if isinstance(target, ast.Attribute):
            return self._call_name(target.value) == name
        return False

    def _literal_allowlist_value(self, node):
        import ast

        if isinstance(node, ast.Dict):
            return all(
                isinstance(value, (ast.List, ast.Tuple))
                and self._literal_sequence(value)
                for value in node.values
            )
        if isinstance(node, (ast.List, ast.Tuple)):
            return all(
                isinstance(value, (ast.List, ast.Tuple))
                and self._literal_sequence(value)
                for value in node.elts
            )
        return False

    def _refutes_clean_quality_owner(self, finding, owner):
        import ast

        if finding.issue_type not in {
            IssueType.QUALITY,
            IssueType.BUG,
            IssueType.PERFORMANCE,
        }:
            return False
        if isinstance(owner, ast.AsyncFunctionDef):
            return self._is_clean_async_helper(owner)
        if self._finding_text_mentions_explicit_issue(finding):
            return False
        return self._is_small_safe_helper(owner)

    def _finding_text_mentions_explicit_issue(self, finding):
        evidence = self._finding_text(finding)
        explicit_terms = (
            "shell=true",
            "subprocess",
            "inconsistent",
            "return path",
            "swallow",
            "exception",
            "duplicate condition",
            "resource leak",
            "complexity",
            "branch",
            "sql injection",
            "path traversal",
            "ssrf",
            "pickle",
            "eval(",
            "exec(",
            "mutable default",
            "missing await",
            "unawaited",
            "blocking",
            "time.sleep",
            "requests.",
        )
        return any(term in evidence for term in explicit_terms)

    def _is_clean_async_helper(self, node):
        if self._has_async_blocking_call(node):
            return False
        if self._has_exception_handling(node):
            return False
        if self._control_flow_count(node) > 1:
            return False
        if self._function_parameter_count(node) > 3:
            return False
        return self._all_async_calls_are_awaited(node)

    def _all_async_calls_are_awaited(self, node):
        import ast

        awaited = {
            id(call)
            for await_node in ast.walk(node)
            if isinstance(await_node, ast.Await)
            for call in ast.walk(await_node.value)
            if isinstance(call, ast.Call)
        }
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            name = self._call_name(child.func)
            if name.startswith(("client.", "session.", "response.")):
                method = name.split(".")[-1]
                if method not in {
                    "delete",
                    "get",
                    "json",
                    "patch",
                    "post",
                    "put",
                    "read",
                    "request",
                    "text",
                }:
                    continue
                if id(child) not in awaited:
                    return False
        return True

    def _is_small_safe_helper(self, node):
        if self._has_exception_handling(node):
            return False
        if self._control_flow_count(node) > 1:
            return False
        if self._function_length(node) > 6:
            return False
        if self._has_dangerous_call(node):
            return False
        return True

    def _has_dangerous_call(self, node):
        import ast

        dangerous_roots = {
            "eval",
            "exec",
            "open",
            "pickle",
            "requests",
            "subprocess",
            "os",
            "shutil",
        }
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            name = self._call_name(child.func)
            if name.split(".", 1)[0] in dangerous_roots:
                return True
        return False

    def _finding_text(self, finding):
        parts = [
            finding.rule_id,
            finding.message,
            finding.explanation,
            finding.suggestion,
            finding.code_snippet,
        ]
        return " ".join(str(part or "") for part in parts).lower()

