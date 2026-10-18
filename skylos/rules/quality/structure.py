import ast
from pathlib import Path
from typing import NamedTuple

from skylos.rules.base import SkylosRule
from skylos.rules.quality._code_lines import code_lines
from skylos.rules.quality._overload_groups import overload_groups
from skylos.rules.quality._receivers import (
    context_method_kinds,
    method_receiver,
    possible_method_receiver,
    resolve_method_kinds,
)
from skylos.rules.quality._scope import is_non_production_python


class _Arity(NamedTuple):
    required: int
    max_required: int
    total: int
    max_total: int
    optional_positional: int
    keyword_only: int
    uncertain: bool


class ArgCountRule(SkylosRule):
    """Positional arity (like pylint R0917) and total parameter count.

    Required positional arguments must be passed in order, which is what
    makes a wide signature error-prone. Keyword-only parameters are named at
    every call site, so they count toward the total only.
    """

    rule_id = "SKY-C303"
    name = "Too Many Arguments"

    def __init__(self, max_args=5, max_required=5, max_total=10):
        self.max_required = max_required if max_required != 5 else max_args
        self.max_total = max_total
        self._methods = {}
        self._skip_file = False
        self._overloads = {}

    def visit_node(self, node, context):
        if isinstance(node, ast.Module):
            self._skip_file = is_non_production_python(
                context.get("filename"), context.get("project_root")
            )
            self._methods = (
                {} if self._skip_file else context_method_kinds(node, context)
            )
            self._overloads = (
                {
                    member: group
                    for group in overload_groups(
                        node, filename=context.get("filename", "")
                    )
                    for member in group.members
                }
                if not self._skip_file
                else {}
            )
            return None
        if self._skip_file:
            return None
        if isinstance(node, ast.ClassDef):
            if not any(
                method in self._methods
                for method in ast.walk(node)
                if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
            ):
                self._methods.update(resolve_method_kinds(node))
            return None
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None

        group = self._overloads.get(node)
        if group is not None:
            return self._overload_finding(group, node, context)

        arity = self._arity(node)
        if arity.required > self.max_required:
            return [self._required_finding(node, context, arity)]
        if arity.total > self.max_total:
            return [self._total_finding(node, context, arity)]
        return None

    def _overload_finding(self, group, node, context):
        if node is not group.anchor:
            return None
        arities = [(member, self._arity(member)) for member in group.members]
        required = [item for item in arities if item[1].required > self.max_required]
        total = [item for item in arities if item[1].total > self.max_total]
        if required:
            member, arity = max(
                required, key=lambda item: (item[1].required, item[1].total)
            )
            finding = self._required_finding(node, context, arity)
        elif total:
            member, arity = max(
                total, key=lambda item: (item[1].total, item[1].required)
            )
            finding = self._total_finding(node, context, arity)
        else:
            return None
        if member is not group.implementation:
            finding["message"] = finding["message"].replace(
                "Function has", "Callable has an overload signature with", 1
            )
        finding["overload_metric_source_line"] = member.lineno
        finding["overload_signatures"] = [
            {
                "line": signature.lineno,
                "kind": "implementation"
                if signature is group.implementation
                else "overload",
                "required_positional": signature_arity.required,
                "total_parameters": signature_arity.total,
                "optional_positional": signature_arity.optional_positional,
                "positional_only": len(signature.args.posonlyargs),
                "positional_parameters": [
                    arg.arg
                    for arg in (*signature.args.posonlyargs, *signature.args.args)
                ],
                "keyword_only_parameters": [
                    arg.arg for arg in signature.args.kwonlyargs
                ],
                "required_keyword_only": [
                    arg.arg
                    for arg, default in zip(
                        signature.args.kwonlyargs, signature.args.kw_defaults
                    )
                    if default is None
                ],
                "variadic_positional": signature.args.vararg.arg
                if signature.args.vararg
                else None,
                "variadic_keyword": signature.args.kwarg.arg
                if signature.args.kwarg
                else None,
                **(
                    {
                        "required_argument_range": [
                            signature_arity.required,
                            signature_arity.max_required,
                        ],
                        "total_parameter_range": [
                            signature_arity.total,
                            signature_arity.max_total,
                        ],
                        "receiver_binding": "unknown",
                    }
                    if signature_arity.uncertain
                    else {}
                ),
            }
            for signature, signature_arity in arities
        ]
        return [finding]

    def _arity(self, node) -> _Arity:
        args = node.args
        positional = [*args.posonlyargs, *args.args]
        required_positional = len(positional) - len(args.defaults)
        known = node in self._methods
        implicit_receiver = (
            known and method_receiver(node, kinds=self._methods) is not None
        )
        possible_receiver = (
            known and possible_method_receiver(node, kinds=self._methods) is not None
        )
        has_required = required_positional > 0
        return _Arity(
            required=required_positional - int(possible_receiver and has_required),
            max_required=required_positional - int(implicit_receiver and has_required),
            total=len(positional) - int(possible_receiver) + len(args.kwonlyargs),
            max_total=len(positional) - int(implicit_receiver) + len(args.kwonlyargs),
            optional_positional=len(args.defaults),
            keyword_only=len(args.kwonlyargs),
            uncertain=possible_receiver and not implicit_receiver,
        )

    def _finding(self, node, context, arity, **fields):
        mod = context.get("mod", "")
        filename = context.get("filename")
        finding = {
            "rule_id": self.rule_id,
            "kind": "structure",
            "type": "function",
            "name": f"{mod}.{node.name}" if mod else node.name,
            "simple_name": node.name,
            **fields,
            "file": filename,
            "basename": Path(filename or "").name,
            "line": node.lineno,
            "col": node.col_offset,
        }
        if arity.uncertain:
            finding["required_argument_range"] = [arity.required, arity.max_required]
            finding["total_parameter_range"] = [arity.total, arity.max_total]
            finding["receiver_binding"] = "unknown"
        return finding

    def _required_finding(self, node, context, arity):
        at_least = "at least " if arity.uncertain else ""
        return self._finding(
            node,
            context,
            arity,
            value=arity.required,
            threshold=self.max_required,
            severity="MEDIUM",
            message=(
                f"Function has {at_least}{arity.required} required positional "
                f"arguments (limit: {self.max_required}). Callers must pass "
                "them in order; consider making some keyword-only or "
                "grouping related ones into a parameter object."
            ),
        )

    def _total_finding(self, node, context, arity):
        if arity.uncertain:
            breakdown = (
                f"Required positional arguments range from {arity.required} to "
                f"{arity.max_required} depending on decorator binding; "
                f"{arity.keyword_only} keyword-only."
            )
        else:
            breakdown = (
                f"({arity.required} required positional, "
                f"{arity.optional_positional} optional positional, "
                f"{arity.keyword_only} keyword-only)."
            )
        at_least = "at least " if arity.uncertain else ""
        return self._finding(
            node,
            context,
            arity,
            value=arity.total,
            threshold=self.max_total,
            severity="LOW",
            message=(
                f"Function has {at_least}{arity.total} total parameters "
                f"(limit: {self.max_total}). {breakdown}"
            ),
        )


class FunctionLengthRule(SkylosRule):
    """Counts code lines from the ``def`` line to the end of the function.

    Blank lines, comment-only lines and docstrings (of the function and of
    the functions and classes nested in it) are not code.
    """

    rule_id = "SKY-C304"
    name = "Function Too Long"

    def __init__(self, max_lines=50):
        self.max_lines = max_lines

    def visit_node(self, node, context):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None

        start = getattr(node, "lineno", 0)
        end = getattr(node, "end_lineno", start)
        if max(end - start + 1, 0) <= self.max_lines:
            return None

        length = len(code_lines(node, context.get("source"), start=start, end=end))
        if length <= self.max_lines:
            return None

        if length < 100:
            severity = "MEDIUM"
        else:
            severity = "HIGH"

        mod = context.get("mod", "")

        if mod:
            func_name = f"{mod}.{node.name}"
        else:
            func_name = node.name

        return [
            {
                "rule_id": self.rule_id,
                "kind": "structure",
                "type": "function",
                "name": func_name,
                "simple_name": node.name,
                "value": length,
                "threshold": self.max_lines,
                "severity": severity,
                "message": (
                    f"Function has {length} code lines (limit: {self.max_lines}); "
                    "blank, comment and docstring lines are not counted."
                ),
                "file": context.get("filename"),
                "basename": Path(context.get("filename", "")).name,
                "line": node.lineno,
                "col": node.col_offset,
            }
        ]
