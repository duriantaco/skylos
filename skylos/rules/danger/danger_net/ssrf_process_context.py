"""Static process provenance for URLs read from native argv/environment.

An operator-source label alone cannot exclude HTTP-to-child transports. Reuse
the source-attested project/process model; no scanned module is imported or run.
"""

from __future__ import annotations

import ast
from pathlib import Path

from skylos.rules.danger.import_proof import provider_binding_is_stable
from skylos.security.parser_contracts import native_environment_reader_is_intact


class URLProcessContext:
    def __init__(self, tree, filename, project_root):
        self.tree = tree
        self.filename = filename
        self.root = project_root
        self.state = None

    @staticmethod
    def _failure(reason):
        return {
            "version": 1,
            "status": "incomplete",
            "complete_project": False,
            "incomplete": [[reason]],
        }

    def _load(self):
        from skylos.rules.danger.danger_fs.path_provenance import (
            _FORMAT_ONLY_METHODS,
            _HASH_DIGEST,
            _MODULE_DUNDERS,
            _SAFE_CALLS,
            _TEMP_CALLS,
            SAFE,
            UNKNOWN,
            _Facts,
            _Project,
            _Tracer,
        )

        class URLSourceTracer(_Tracer):
            # Reuse caller/process edges, not the path rule's value-domain
            # shortcuts. A hash or temporary filename shape is no URL-origin
            # proof, including when another component has an operator origin.
            def _call_source(self, unit, scope, node, names, env=None):
                result = super()._call_source(unit, scope, node, names, env)
                shortcut = any(
                    name in _TEMP_CALLS
                    or name in _SAFE_CALLS
                    and not name.startswith("builtins.")
                    or _HASH_DIGEST.match(name.replace("()", ""))
                    for name in names
                )
                if result is not None and shortcut:
                    return result.add(
                        _Facts.leaf(
                            UNKNOWN,
                            "a path-safe value producer does not establish URL input origin",
                        )
                    )
                return result

            def _call(self, unit, scope, node, env):
                result = super()._call(unit, scope, node, env)
                if (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr in _FORMAT_ONLY_METHODS
                ):
                    values = self.project.values(unit, scope, node.func)
                    if not values or not all(
                        value.kind in {"fn", "partial", "cls"} for value in values
                    ):
                        result.add(
                            _Facts.leaf(
                                UNKNOWN,
                                "date/time formatting is not a URL source-domain proof",
                            )
                        )
                return result

            def _trace(self, unit, scope, expr, env):
                result = super()._trace(unit, scope, expr, env)
                if (
                    isinstance(expr, ast.Compare)
                    or isinstance(expr, ast.UnaryOp)
                    and isinstance(expr.op, ast.Not)
                ):
                    result = result.moved(
                        SAFE,
                        UNKNOWN,
                        "comparison/boolean shape does not establish URL input origin",
                    )
                return result

            def _attribute_source(self, unit, scope, node):
                result = super()._attribute_source(unit, scope, node)
                if result is not None and result[0] == SAFE:
                    return UNKNOWN, "process metadata is not a proven URL input origin"
                return result

            def _name(self, unit, scope, node, env):
                result = super()._name(unit, scope, node, env)
                if (
                    node.id in _MODULE_DUNDERS | {"__file__"}
                    and unit.lookup(scope, node.id) is None
                ):
                    result = result.moved(
                        SAFE,
                        UNKNOWN,
                        "module metadata is not a proven URL input origin",
                    )
                return result

        if self.root is None:
            return None
        root = Path(self.root).resolve()
        source = Path(self.filename).resolve()
        if not source.is_relative_to(root):
            return None
        if not (root / ".git").exists() and any(
            any(
                (ancestor / marker).exists()
                for marker in (".git", "pyproject.toml", "setup.cfg", "setup.py")
            )
            for ancestor in root.parents
        ):
            # A subtree cannot certify launchers/importers outside its scope.
            return None
        project = _Project.load(root)
        unit = project.by_path.get(source)
        if unit is None or ast.dump(unit.tree) != ast.dump(self.tree):
            return None
        return project, unit, URLSourceTracer(project, "SKY-D216")

    def inspect(self, operand):
        from skylos.rules.danger.danger_fs.path_process_flow import operator_launch_gap
        from skylos.rules.danger.danger_fs.path_provenance import (
            INCOMPLETE,
            OPERATOR,
            UNKNOWN,
            UNTRUSTED,
            _Facts,
            _locate_operand,
        )

        try:
            if self.state is None:
                self.state = False
                self.state = self._load() or False
            if self.state is False:
                return self._failure(
                    "the URL's complete project source context is unavailable"
                )
            project, unit, tracer = self.state
            located = _locate_operand(
                unit,
                {
                    "line": operand.lineno,
                    "col": operand.col_offset,
                    "end_line": operand.end_lineno,
                    "end_col": operand.end_col_offset,
                },
            )
            if located is None or ast.dump(located) != ast.dump(operand):
                return self._failure(
                    "the URL source expression no longer matches the indexed snapshot"
                )
            tracer.work = 0
            facts = tracer.trace(unit, unit.scope_of(located), located)
            # Provider changes cannot establish native process input. Checking
            # the mapping is necessary even when a label says 'os.environ'.
            for source_unit, kind in facts.operator_origins:
                native = (
                    provider_binding_is_stable(
                        "sys.argv", source_unit.tree, source_unit.path, project.root
                    )
                    if kind == "cli"
                    else native_environment_reader_is_intact(
                        source_unit.tree, source_unit.path, project.root
                    )
                    if kind in {"env", "environment"}
                    else False
                )
                if not native:
                    facts = (
                        _Facts()
                        .add(facts)
                        .add(
                            _Facts.leaf(
                                UNKNOWN,
                                "the native process-input provider may have changed",
                            )
                        )
                    )
            facts = _Facts().add(facts).add(operator_launch_gap(tracer, facts))
            if not facts.operator_origins or not facts.chains[OPERATOR]:
                facts.add(
                    _Facts.leaf(
                        UNKNOWN,
                        "no complete structured operator origin establishes this URL input",
                    )
                )
            if (
                not project.complete
                or project.truncated
                or not facts.parameter_names_complete
                or not facts.operator_origins_complete
            ):
                facts.add(
                    _Facts.leaf(
                        INCOMPLETE,
                        "the process-source analysis did not resolve every source",
                    )
                )
            status = "operator"
            if facts.chains[UNTRUSTED]:
                status = UNTRUSTED
            elif facts.chains[INCOMPLETE]:
                status = INCOMPLETE
            elif facts.chains[UNKNOWN] or facts.chains["parameter"] or facts.empty():
                status = UNKNOWN
            return {
                "version": 1,
                "status": status,
                "complete_project": project.complete and not project.truncated,
                "source_kinds": sorted(
                    {kind for _unit, kind in facts.operator_origins}
                ),
                **{
                    kind: [list(chain) for chain in facts.chains[kind]]
                    for kind in (UNTRUSTED, UNKNOWN, INCOMPLETE, OPERATOR)
                    if facts.chains[kind]
                },
            }
        except (
            OSError,
            RuntimeError,
            MemoryError,
            ValueError,
            TypeError,
            AttributeError,
            KeyError,
            IndexError,
        ):
            # A failed source/context computation cannot restore the old
            # blanket operator exemption.
            return self._failure(
                "the bounded process-source analysis could not complete"
            )
