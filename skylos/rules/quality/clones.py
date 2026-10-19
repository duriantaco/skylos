from __future__ import annotations

import ast
import copy
import hashlib
import io
import tokenize
from collections import Counter
from dataclasses import dataclass
from difflib import SequenceMatcher
from enum import Enum

try:
    from skylos_fast import compute_similarity as _fast_similarity
except ImportError:
    _fast_similarity = None
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from skylos.rules.quality._test_code import (
    is_python_golden_fixture,
    is_python_test_file,
    is_test_package_name,
    python_test_directory,
)
from skylos.rules.quality._code_lines import code_lines, count_statements
from skylos.rules.quality._scope import is_sample_or_build_python


class CloneType(str, Enum):
    TYPE1 = "type1"
    TYPE2 = "type2"
    TYPE3 = "type3"
    TYPE4 = "type4"


class GroupingMode(str, Enum):
    CONNECTED = "connected"
    K_CORE = "k_core"


@dataclass(frozen=True)
class CloneConfig:
    # Code lines of the fragment: blank, comment and docstring lines excluded.
    min_lines: int = 8
    min_nodes: int = 10
    # Statements in the compared body (docstrings excluded, nested counted).
    min_statements: int = 4
    type1_threshold: float = 0.98
    type2_threshold: float = 0.95
    type3_threshold: float = 0.88
    type4_threshold: float = 0.75

    similarity_threshold: float = 0.90
    ignore_identifiers: bool = False
    ignore_literals: bool = False
    skip_docstrings: bool = True
    enabled_clone_types: Tuple[CloneType, ...] = (
        CloneType.TYPE1,
        CloneType.TYPE2,
        CloneType.TYPE3,
    )

    grouping_mode: GroupingMode = GroupingMode.CONNECTED
    grouping_threshold: float = 0.80
    k_core_k: int = 2

    bucket_prefix: int = 6
    max_bucket: int = 250


@dataclass(frozen=True)
class Fragment:
    file_path: str
    start_line: int
    end_line: int
    name: str
    kind: str
    node_count: int
    text_norm: str
    ast_norm_type2: str
    ast_norm_type3: str


@dataclass(frozen=True)
class ClonePair:
    a: Fragment
    b: Fragment
    similarity: float
    clone_type: CloneType


@dataclass
class CloneGroup:
    fragments: List[Fragment]
    similarity: float
    clone_type: CloneType


def _strip_docstring(body: List[ast.stmt]) -> List[ast.stmt]:
    if not body:
        return body
    first = body[0]
    if (
        isinstance(first, ast.Expr)
        and isinstance(first.value, ast.Constant)
        and isinstance(first.value.value, str)
    ):
        return body[1:]
    return body


def _copy_syntax(tree: ast.AST) -> ast.AST:
    """Copy syntax without following metadata on shared parser nodes.

    Contexts and operators are singleton objects in parsed ASTs. Another
    analyzer can annotate one with a parent in an unrelated source tree;
    deepcopy would traverse that graph rather than just this fragment.
    """
    copies = {}
    for original in ast.walk(tree):
        if original in copies:
            continue
        duplicate = copy.copy(original)
        duplicate.__dict__.clear()
        for attribute in original._attributes:
            if hasattr(original, attribute):
                setattr(duplicate, attribute, getattr(original, attribute))
        copies[original] = duplicate
    for original, duplicate in copies.items():
        for field, value in ast.iter_fields(original):
            if isinstance(value, ast.AST):
                value = copies[value]
            elif isinstance(value, list):
                value = [
                    copies[item] if isinstance(item, ast.AST) else item
                    for item in value
                ]
            setattr(duplicate, field, value)
    return copies[tree]


def clone_member_label(
    fragment: "Fragment", project_root: str | Path | None = None
) -> str:
    """``path:start-end (kind name)`` with the path relative to the project.

    Copies in ``a/x.py`` and ``b/x.py`` share a basename; the relative path
    keeps them apart.
    """
    path = Path(fragment.file_path)
    shown = str(path)
    if project_root is not None:
        try:
            shown = path.resolve().relative_to(Path(project_root).resolve()).as_posix()
        except (OSError, ValueError):
            shown = str(path)
    return (
        f"{shown}:{fragment.start_line}-{fragment.end_line} "
        f"({fragment.kind} {fragment.name})"
    )


def _normalize_text(source: str) -> str:
    out = []
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        for tok_type, tok_str, *_ in tokens:
            if tok_type in (
                tokenize.COMMENT,
                tokenize.NL,
                tokenize.NEWLINE,
                tokenize.INDENT,
                tokenize.DEDENT,
            ):
                continue
            # Type 1 ignores layout/comments, not literal values. Replacing
            # every string and number here bypassed ignore_literals=False and
            # made distinct declaration/data tables look like exact clones.
            out.append(tok_str)
    except tokenize.TokenError:
        return " ".join(source.split())
    return " ".join(out)


def _local_clone_bindings(body, parameters=()):
    """Lexical bindings, excluding independent nested bodies and imports."""
    names = set(parameters)
    external = set()
    pending = list(body)
    while pending:
        current = pending.pop()
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(current.name)
            pending.extend(current.decorator_list)
            if isinstance(current, ast.ClassDef):
                pending.extend(current.bases)
                pending.extend(keyword.value for keyword in current.keywords)
            else:
                pending.extend(current.args.defaults)
                pending.extend(
                    item for item in current.args.kw_defaults if item is not None
                )
            continue
        if isinstance(current, (ast.Global, ast.Nonlocal)):
            external.update(current.names)
            continue
        if isinstance(current, ast.ExceptHandler) and current.name:
            names.add(current.name)
        if isinstance(current, (ast.MatchAs, ast.MatchStar)) and current.name:
            names.add(current.name)
        if isinstance(current, ast.MatchMapping) and current.rest:
            names.add(current.rest)
        if isinstance(
            current,
            (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp),
        ):
            # A comprehension's iteration variables are local to it, but a
            # walrus expression binds the enclosing function's namespace.
            if isinstance(current, ast.Lambda):
                pending.extend(current.args.defaults)
                pending.extend(
                    item for item in current.args.kw_defaults if item is not None
                )
            else:
                expressions = list(ast.iter_child_nodes(current))
                while expressions:
                    expression = expressions.pop()
                    if isinstance(expression, ast.Lambda):
                        expressions.extend(expression.args.defaults)
                        expressions.extend(
                            item
                            for item in expression.args.kw_defaults
                            if item is not None
                        )
                        continue
                    if isinstance(
                        expression,
                        (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
                    ):
                        continue
                    if isinstance(expression, ast.NamedExpr) and isinstance(
                        expression.target, ast.Name
                    ):
                        names.add(expression.target.id)
                    expressions.extend(ast.iter_child_nodes(expression))
            continue
        if isinstance(current, (ast.Import, ast.ImportFrom)):
            external.update(
                alias.asname or alias.name.split(".", 1)[0] for alias in current.names
            )
            continue
        if isinstance(current, ast.Name) and isinstance(
            current.ctx, (ast.Store, ast.Del)
        ):
            names.add(current.id)
        pending.extend(ast.iter_child_nodes(current))
    return names - external


def _clone_binding_declarations(body):
    global_names, nonlocal_names = set(), set()
    pending = list(body)
    while pending:
        current = pending.pop()
        if isinstance(
            current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        if isinstance(current, ast.Global):
            global_names.update(current.names)
        elif isinstance(current, ast.Nonlocal):
            nonlocal_names.update(current.names)
        pending.extend(ast.iter_child_nodes(current))
    return global_names, nonlocal_names


def _clone_parameters(arguments):
    return [
        argument.arg
        for argument in (
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
            arguments.vararg,
            arguments.kwarg,
        )
        if argument is not None
    ]


class _Type2Normalizer(ast.NodeTransformer):
    def __init__(
        self,
        ignore_identifiers: bool,
        ignore_literals: bool,
        *,
        local_names=(),
        parameters=(),
        global_names=(),
        nonlocal_names=(),
    ):
        self.ignore_identifiers = ignore_identifiers
        self.ignore_literals = ignore_literals
        self._scope_number = 0
        self._scopes = []
        self._push_scope(
            set(local_names),
            parameters,
            global_names=global_names,
            nonlocal_names=nonlocal_names,
        )

    def _push_scope(
        self,
        names,
        parameters=(),
        *,
        namespace=False,
        global_names=(),
        nonlocal_names=(),
    ):
        scope = [
            self._scope_number,
            set(names),
            {},
            namespace,
            set(global_names),
            set(nonlocal_names),
        ]
        self._scope_number += 1
        self._scopes.append(scope)
        for parameter in parameters:
            self._identifier(parameter)

    def _identifier(self, name, *, store=False):
        if not self.ignore_identifiers:
            return name
        for (
            number,
            names,
            replacements,
            namespace,
            global_names,
            nonlocal_names,
        ) in reversed(self._scopes):
            if namespace and number != self._scopes[-1][0] and not store:
                # Neither bindings nor directives from an outer class enter
                # a nested method/class/comprehension's lexical environment.
                continue
            if name in global_names:
                return name
            if name in nonlocal_names:
                store = False
                continue
            if name in names:
                if namespace:
                    return name
                if name not in replacements:
                    # This cannot collide with a parsed Python identifier.
                    replacements[name] = f"<local:{number}:{len(replacements)}>"
                return replacements[name]
            if store:
                break
        return name

    def visit_Name(self, node: ast.Name):
        if self.ignore_identifiers:
            return ast.copy_location(
                ast.Name(
                    id=self._identifier(
                        node.id, store=isinstance(node.ctx, (ast.Store, ast.Del))
                    ),
                    ctx=node.ctx,
                ),
                node,
            )
        return node

    def visit_arg(self, node: ast.arg):
        if self.ignore_identifiers:
            node.arg = self._identifier(node.arg)
        return node

    def visit_Attribute(self, node: ast.Attribute):
        # Member/API selectors are operations, not alpha-renamable variables.
        return self.generic_visit(node)

    def visit_NamedExpr(self, node):
        if isinstance(node.target, ast.Name):
            node.target.id = self._identifier(node.target.id)
        else:
            node.target = self.visit(node.target)
        node.value = self.visit(node.value)
        return node

    def visit_Nonlocal(self, node):
        node.names = [self._identifier(name) for name in node.names]
        return node

    def visit_ExceptHandler(self, node):
        if node.type is not None:
            node.type = self.visit(node.type)
        if node.name:
            node.name = self._identifier(node.name, store=True)
        node.body = [self.visit(item) for item in node.body]
        return node

    def visit_MatchAs(self, node):
        if node.pattern is not None:
            node.pattern = self.visit(node.pattern)
        if node.name:
            node.name = self._identifier(node.name, store=True)
        return node

    def visit_MatchStar(self, node):
        if node.name:
            node.name = self._identifier(node.name, store=True)
        return node

    def visit_MatchMapping(self, node):
        node.keys = [self.visit(item) for item in node.keys]
        node.patterns = [self.visit(item) for item in node.patterns]
        if node.rest:
            node.rest = self._identifier(node.rest, store=True)
        return node

    def _function(self, node):
        original_name = node.name
        node.name = self._identifier(original_name, store=True)
        node.decorator_list = [self.visit(item) for item in node.decorator_list]
        node.args.defaults = [self.visit(item) for item in node.args.defaults]
        node.args.kw_defaults = [
            self.visit(item) if item is not None else None
            for item in node.args.kw_defaults
        ]
        parameters = _clone_parameters(node.args)
        for argument in (
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
            node.args.vararg,
            node.args.kwarg,
        ):
            if argument is not None and argument.annotation is not None:
                argument.annotation = self.visit(argument.annotation)
        if node.returns is not None:
            node.returns = self.visit(node.returns)
        global_names, nonlocal_names = _clone_binding_declarations(node.body)
        self._push_scope(
            _local_clone_bindings(node.body, parameters),
            parameters,
            global_names=global_names,
            nonlocal_names=nonlocal_names,
        )
        for argument in (
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
            node.args.vararg,
            node.args.kwarg,
        ):
            if argument is not None:
                argument.arg = self._identifier(argument.arg)
        node.body = [self.visit(item) for item in node.body]
        self._scopes.pop()
        return node

    visit_FunctionDef = _function
    visit_AsyncFunctionDef = _function

    def visit_ClassDef(self, node):
        node.name = self._identifier(node.name, store=True)
        node.bases = [self.visit(item) for item in node.bases]
        node.keywords = [self.visit(item) for item in node.keywords]
        node.decorator_list = [self.visit(item) for item in node.decorator_list]
        names = _local_clone_bindings(node.body)
        global_names, nonlocal_names = _clone_binding_declarations(node.body)
        self._push_scope(
            names,
            namespace=True,
            global_names=global_names,
            nonlocal_names=nonlocal_names,
        )
        node.body = [self.visit(item) for item in node.body]
        self._scopes.pop()
        return node

    def visit_Lambda(self, node):
        node.args.defaults = [self.visit(item) for item in node.args.defaults]
        node.args.kw_defaults = [
            self.visit(item) if item is not None else None
            for item in node.args.kw_defaults
        ]
        parameters = _clone_parameters(node.args)
        self._push_scope(_local_clone_bindings([node.body], parameters), parameters)
        for argument in (
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
            node.args.vararg,
            node.args.kwarg,
        ):
            if argument is not None:
                argument.arg = self._identifier(argument.arg)
        node.body = self.visit(node.body)
        self._scopes.pop()
        return node

    def _comprehension(self, node):
        # The first iterable runs in the enclosing scope.
        first = node.generators[0]
        first.iter = self.visit(first.iter)
        names = {
            child.id
            for generator in node.generators
            for child in ast.walk(generator.target)
            if isinstance(child, ast.Name)
        }
        self._push_scope(names)
        for index, generator in enumerate(node.generators):
            generator.target = self.visit(generator.target)
            if index:
                generator.iter = self.visit(generator.iter)
            generator.ifs = [self.visit(item) for item in generator.ifs]
        if isinstance(node, ast.DictComp):
            node.key, node.value = self.visit(node.key), self.visit(node.value)
        else:
            node.elt = self.visit(node.elt)
        self._scopes.pop()
        return node

    visit_ListComp = _comprehension
    visit_SetComp = _comprehension
    visit_DictComp = _comprehension
    visit_GeneratorExp = _comprehension

    def visit_Constant(self, node: ast.Constant):
        if self.ignore_literals:
            if node.value is None or isinstance(node.value, bool):
                return node
            replacement = {
                str: "<string>",
                bytes: b"<bytes>",
                int: 0,
                float: 0.0,
                complex: 0j,
            }.get(type(node.value), node.value)
            return ast.copy_location(ast.Constant(value=replacement), node)
        return node


def _dump_ast(node: ast.AST) -> str:
    return ast.dump(node, annotate_fields=False, include_attributes=False)


def _count_nodes(node: ast.AST) -> int:
    return sum(1 for _ in ast.walk(node))


def _similarity(a: str, b: str, threshold: float | None = None) -> float:
    if a == b:
        return 1.0

    if _fast_similarity is not None:
        return _fast_similarity(a, b)

    if threshold is not None:
        total_len = len(a) + len(b)
        if total_len == 0:
            return 1.0
        if (2 * min(len(a), len(b)) / total_len) < threshold:
            return 0.0

    matcher = SequenceMatcher(a=a, b=b)
    if threshold is not None and matcher.quick_ratio() < threshold:
        return 0.0
    return matcher.ratio()


_BOILERPLATE_METHODS = {
    "__init__",
    "__repr__",
    "__str__",
    "__eq__",
    "__hash__",
    "__lt__",
    "__le__",
    "__gt__",
    "__ge__",
    "__ne__",
    "__len__",
    "__iter__",
    "__next__",
    "__contains__",
    "__enter__",
    "__exit__",
    "__call__",
    "setUp",
    "tearDown",
    "setUpClass",
    "tearDownClass",
}


def extract_fragments(
    py_path: Path,
    source: str,
    cfg: CloneConfig,
    *,
    project_root: str | Path | None = None,
) -> List[Fragment]:
    # Keep test fragments until group analysis can retain shared production
    # implementations. Sample and build code has no such metric contract.
    if is_sample_or_build_python(py_path, project_root):
        return []

    # Always a private tree: _Type2Normalizer rewrites identifiers in place,
    # and a tree shared with the analyzer keeps nodes later passes read (the
    # class bases behind framework-override evidence).
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    fragments: List[Fragment] = []
    class_stack: List[str] = []
    src_lines = source.splitlines()

    def mk_fragment(n: ast.AST, kind: str, name: str, body: Optional[List[ast.stmt]]):
        start = getattr(n, "lineno", None)
        end = getattr(n, "end_lineno", None)
        if start is None or end is None:
            return
        if (end - start + 1) < cfg.min_lines:
            return
        # Size is measured in code: docstring, comment and blank lines do not
        # count, and a long signature over a one- or two-statement body is
        # not duplicated logic.
        if len(code_lines(n, source, start=start, end=end)) < cfg.min_lines:
            return
        if body is not None and count_statements(body) < cfg.min_statements:
            return

        if body is not None:
            body2 = _strip_docstring(body) if cfg.skip_docstrings else body
            node_for_dump = ast.Module(body=body2, type_ignores=[])
        else:
            node_for_dump = n

        node_count = _count_nodes(node_for_dump)
        if node_count < cfg.min_nodes:
            return

        frag_src = "\n".join(src_lines[start - 1 : end])
        text_norm = _normalize_text(frag_src)

        ast_norm_type3 = _dump_ast(node_for_dump)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # An identical body can bind its names to different positional
            # inputs. Keep the original signature in the unnormalized
            # candidate identity; otherwise that bucket bypasses the scoped
            # type-2 binding comparison (e.g. f(left, right) versus
            # f(right, left), both returning left - right).
            ast_norm_type3 = _dump_ast(n.args) + ":" + ast_norm_type3
        if cfg.ignore_identifiers or cfg.ignore_literals:
            # Normalizing a class must not rewrite the original AST of the
            # methods which are extracted as independent fragments afterward.
            parameters = (
                _clone_parameters(n.args)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                else []
            )
            local_names = (
                _local_clone_bindings(node_for_dump.body, parameters)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                else set()
            )
            global_names, nonlocal_names = _clone_binding_declarations(
                node_for_dump.body
            )
            t2 = _Type2Normalizer(
                cfg.ignore_identifiers,
                cfg.ignore_literals,
                local_names=local_names,
                parameters=parameters,
                global_names=global_names,
                nonlocal_names=nonlocal_names,
            ).visit(_copy_syntax(node_for_dump))
            ast_norm_type2 = _dump_ast(t2)
        else:
            ast_norm_type2 = ast_norm_type3

        fragments.append(
            Fragment(
                file_path=str(py_path),
                start_line=int(start),
                end_line=int(end),
                name=name,
                kind=kind,
                node_count=node_count,
                text_norm=text_norm,
                ast_norm_type2=ast_norm_type2,
                ast_norm_type3=ast_norm_type3,
            )
        )

    class Visitor(ast.NodeVisitor):
        def generic_visit(self, node):
            for child in ast.iter_child_nodes(node):
                self.visit(child)

        def visit_ClassDef(self, node: ast.ClassDef):
            mk_fragment(node, "class", node.name, node.body)
            class_stack.append(node.name)
            self.generic_visit(node)
            class_stack.pop()

        def visit_FunctionDef(self, node: ast.FunctionDef):
            if node.name in _BOILERPLATE_METHODS:
                self.generic_visit(node)
                return
            if class_stack:
                mk_fragment(node, "method", f"{class_stack[-1]}.{node.name}", node.body)
            else:
                mk_fragment(node, "function", node.name, node.body)
            self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
            if node.name in _BOILERPLATE_METHODS:
                self.generic_visit(node)
                return
            if class_stack:
                mk_fragment(node, "method", f"{class_stack[-1]}.{node.name}", node.body)
            else:
                mk_fragment(node, "function", node.name, node.body)
            self.generic_visit(node)

    Visitor().visit(tree)
    return fragments


def classify_clone(
    f1: Fragment, f2: Fragment, cfg: CloneConfig
) -> Optional[Tuple[CloneType, float]]:
    enabled = set(cfg.enabled_clone_types)

    if CloneType.TYPE1 in enabled:
        # Type 1 permits layout/comments only. A high similarity score cannot
        # establish that literal, annotation or operator differences are absent.
        if f1.text_norm == f2.text_norm and cfg.type1_threshold <= 1.0:
            return (CloneType.TYPE1, 1.0)

    if CloneType.TYPE2 in enabled:
        sim2 = _similarity(f1.ast_norm_type2, f2.ast_norm_type2, cfg.type2_threshold)
        if sim2 >= cfg.type2_threshold:
            return (CloneType.TYPE2, sim2)

    if CloneType.TYPE3 in enabled:
        sim3 = _similarity(f1.ast_norm_type3, f2.ast_norm_type3, cfg.type3_threshold)
        if sim3 >= cfg.type3_threshold:
            return (CloneType.TYPE3, sim3)
        if CloneType.TYPE1 in enabled:
            # Preserve already accepted near-copies if text similarity is
            # stronger than AST similarity, but label their edits honestly.
            sim1 = _similarity(f1.text_norm, f2.text_norm, cfg.type1_threshold)
            if sim1 >= cfg.type1_threshold:
                return (CloneType.TYPE3, sim1)

    if CloneType.TYPE4 in enabled:
        pass

    return None


def _bucket_key(f: Fragment, cfg: CloneConfig) -> str:
    h = hashlib.sha1(f.ast_norm_type3.encode("utf-8", errors="ignore")).hexdigest()
    return h[: cfg.bucket_prefix]


def _bucket_key_text(f: Fragment, cfg: CloneConfig) -> str:
    h = hashlib.sha1(f.text_norm.encode("utf-8", errors="ignore")).hexdigest()
    return h[: cfg.bucket_prefix]


def _bucket_key_ast(f: Fragment, cfg: CloneConfig) -> str:
    h = hashlib.sha1(f.ast_norm_type3.encode("utf-8", errors="ignore")).hexdigest()
    return h[: cfg.bucket_prefix]


def detect_clone_pairs(fragments: List[Fragment], cfg: CloneConfig) -> List[ClonePair]:
    buckets_list: List[Dict[str, List[Fragment]]] = []

    buckets_text: Dict[str, List[Fragment]] = {}
    for f in fragments:
        buckets_text.setdefault(_bucket_key_text(f, cfg), []).append(f)
    buckets_list.append(buckets_text)

    buckets_ast: Dict[str, List[Fragment]] = {}
    for f in fragments:
        buckets_ast.setdefault(_bucket_key_ast(f, cfg), []).append(f)
    buckets_list.append(buckets_ast)

    buckets_type2: Dict[str, List[Fragment]] = {}
    for f in fragments:
        h = hashlib.sha1(f.ast_norm_type2.encode("utf-8", errors="ignore")).hexdigest()
        buckets_type2.setdefault(h[: cfg.bucket_prefix], []).append(f)
    buckets_list.append(buckets_type2)

    seen_pairs: Set[
        Tuple[Tuple[str, int, int, str, str], Tuple[str, int, int, str, str]]
    ] = set()
    out: List[ClonePair] = []

    def frag_id(x: Fragment) -> Tuple[str, int, int, str, str]:
        return (x.file_path, x.start_line, x.end_line, x.kind, x.name)

    for buckets in buckets_list:
        for items in buckets.values():
            if len(items) < 2:
                continue
            items = items[: cfg.max_bucket]

            for i in range(len(items)):
                for j in range(i + 1, len(items)):
                    a, b = items[i], items[j]
                    ida, idb = frag_id(a), frag_id(b)
                    key = (ida, idb) if ida <= idb else (idb, ida)
                    if key in seen_pairs:
                        continue
                    seen_pairs.add(key)

                    res = classify_clone(a, b, cfg)
                    if not res:
                        continue
                    ctype, sim = res

                    if sim < cfg.similarity_threshold:
                        continue

                    out.append(ClonePair(a=a, b=b, similarity=sim, clone_type=ctype))

    out.sort(
        key=lambda p: (
            -p.similarity,
            p.a.file_path,
            p.a.start_line,
            p.b.file_path,
            p.b.start_line,
        )
    )
    return out


detect_pairs = detect_clone_pairs


class _UnionFind:
    def __init__(self):
        self.parent: Dict[int, int] = {}
        self.rank: Dict[int, int] = {}

    def find(self, x: int) -> int:
        p = self.parent.get(x, x)
        if p != x:
            p = self.find(p)
            self.parent[x] = p
        return p

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        pa, pb = self.rank.get(ra, 0), self.rank.get(rb, 0)
        if pa < pb:
            ra, rb = rb, ra
        self.parent[rb] = ra
        if pa == pb:
            self.rank[ra] = pa + 1


def _pair_key(a: Fragment, b: Fragment) -> Tuple[str, int, str, int]:
    return (
        (a.file_path, a.start_line, b.file_path, b.start_line)
        if (a.file_path, a.start_line) <= (b.file_path, b.start_line)
        else (b.file_path, b.start_line, a.file_path, a.start_line)
    )


def _select_group_clone_type(types: List[CloneType]) -> CloneType:
    if not types:
        return CloneType.TYPE3

    counts = Counter(types)
    return min(counts, key=lambda clone_type: (-counts[clone_type], clone_type.value))


def group_pairs(pairs: List[ClonePair], cfg: CloneConfig) -> List[CloneGroup]:
    if not pairs:
        return []

    frag_list: List[Fragment] = []
    idx: Dict[Tuple[str, int, int, str, str], int] = {}

    def key(f: Fragment) -> Tuple[str, int, int, str, str]:
        return (f.file_path, f.start_line, f.end_line, f.kind, f.name)

    def get_idx(f: Fragment) -> int:
        k = key(f)
        if k in idx:
            return idx[k]
        idx[k] = len(frag_list)
        frag_list.append(f)
        return idx[k]

    adj: Dict[int, Dict[int, ClonePair]] = {}
    for p in pairs:
        if p.similarity < cfg.grouping_threshold:
            continue
        i, j = get_idx(p.a), get_idx(p.b)
        adj.setdefault(i, {})[j] = p
        adj.setdefault(j, {})[i] = p

    if cfg.grouping_mode == GroupingMode.CONNECTED:
        return _group_connected(frag_list, adj, cfg)

    if cfg.grouping_mode == GroupingMode.K_CORE:
        return _group_kcore(frag_list, adj, cfg, cfg.k_core_k)

    return _group_connected(frag_list, adj, cfg)


def _group_connected(
    frag_list: List[Fragment], adj: Dict[int, Dict[int, ClonePair]], cfg: CloneConfig
) -> List[CloneGroup]:
    uf = _UnionFind()
    for i, nbrs in adj.items():
        for j in nbrs.keys():
            uf.union(i, j)

    comps: Dict[int, List[int]] = {}
    for i in range(len(frag_list)):
        r = uf.find(i)
        comps.setdefault(r, []).append(i)

    groups: List[CloneGroup] = []
    for members in comps.values():
        if len(members) < 2:
            continue

        sims: List[float] = []
        types: List[CloneType] = []
        for a in range(len(members)):
            for b in range(a + 1, len(members)):
                i, j = members[a], members[b]
                p = adj.get(i, {}).get(j)
                if p:
                    sims.append(p.similarity)
                    types.append(p.clone_type)

        avg_sim = sum(sims) / len(sims) if sims else cfg.grouping_threshold
        clone_type = _select_group_clone_type(types)

        groups.append(
            CloneGroup(
                fragments=[frag_list[i] for i in members],
                similarity=avg_sim,
                clone_type=clone_type,
            )
        )

    groups.sort(key=lambda g: (-len(g.fragments), -g.similarity))
    return groups


def _group_kcore(frag_list, adj, cfg: CloneConfig, k: int):
    k = max(2, int(k))
    degree = {i: len(nbrs) for i, nbrs in adj.items()}
    alive: Set[int] = set(degree.keys())

    changed = True
    while changed:
        changed = False
        kill = [i for i in list(alive) if degree.get(i, 0) < k]
        if not kill:
            break
        changed = True
        for i in kill:
            alive.remove(i)
            for j in list(adj.get(i, {}).keys()):
                if j in alive:
                    degree[j] = max(0, degree.get(j, 0) - 1)

    sub_adj: Dict[int, Dict[int, ClonePair]] = {}
    for i in alive:
        for j, p in adj.get(i, {}).items():
            if j in alive:
                sub_adj.setdefault(i, {})[j] = p

    return _group_connected(frag_list, sub_adj, cfg)


def without_test_only_groups(
    groups: List[CloneGroup],
    project_root: Path | str | None = None,
    *,
    imported_modules: Set[str] = frozenset(),
    module_names: Optional[Dict[str, str]] = None,
) -> List[CloneGroup]:
    """Drop clone groups whose members are all test code.

    Near-identical test bodies are normal (one case per input), so such a
    group is not a duplication defect. A group that reaches production code
    is kept, and so is one whose test module non-test code imports
    (``imported_modules``, with ``module_names`` mapping files to modules):
    production then depends on the duplicated code. Golden source/output
    fixture pairs also count when a matching text reader proves the fixture
    protocol. Path names alone do not establish either exemption.
    """
    module_names = module_names or {}
    test_context = {}

    def test_only(fragment) -> bool:
        filename = fragment.file_path
        if filename not in test_context:
            test_context[filename] = is_python_test_file(
                filename, project_root
            ) or is_python_golden_fixture(filename, project_root)
        return test_context[filename]

    def imported(fragment) -> bool:
        # The module itself, or a test package above it (its ``__init__`` can
        # re-export it); importing ``pkg`` does not reach ``pkg.tests.x``.
        module = module_names.get(_resolved(fragment.file_path))
        return bool(module) and any(
            module == name
            or (module.startswith(name + ".") and is_test_package_name(name))
            for name in imported_modules
        )

    return [
        group
        for group in groups
        if not all(
            test_only(fragment) and not imported(fragment)
            for fragment in group.fragments
        )
    ]


def python_imports_outside_tests(
    raw_imports: Dict[Path, list], project_root: Path | str | None = None
) -> Set[str]:
    """Modules that non-test files import, as dotted names (``module`` and
    ``module.name`` for ``from`` imports).

    ``raw_imports`` maps a file to its module-level imports as
    ``(module, line, kind, names)``. Helpers in a directory containing actual
    tests do not count as outside importers unless production reaches them.
    """
    test_files = {
        file for file in raw_imports if is_python_test_file(file, project_root)
    }
    # An uncollected support module in a proven test suite is not itself a
    # production importer. Otherwise ``tests/mockserver.py: from tests ...``
    # keeps every clone under tests/, even when no shipped code uses it.
    # Do retain support modules reached by production imports, transitively.
    suite_directories = {
        directory
        for file in test_files
        if (directory := python_test_directory(file, project_root)) is not None
    }
    test_context_files = test_files | {
        file
        for file in raw_imports
        if python_test_directory(file, project_root) in suite_directories
    }

    def import_names(imports):
        names = set()
        for module, _line, kind, imported_names in imports:
            if not module:
                continue
            names.add(module)
            if kind == "from_import":
                names.update(f"{module}.{name}" for name in imported_names)
        return names

    candidate_modules = {}
    if project_root is not None:
        root = Path(project_root).resolve()
        for file in test_context_files:
            try:
                path = Path(file)
                if not path.is_absolute():
                    path = root / path
                parts = list(path.resolve().relative_to(root).with_suffix("").parts)
                if parts[-1] == "__init__":
                    parts.pop()
                modules = {".".join(parts)}
                if parts and parts[0] == "src":
                    modules.add(".".join(parts[1:]))
                candidate_modules[file] = modules - {""}
            except (OSError, RuntimeError, ValueError):
                continue

    names: Set[str] = set()
    for file, imports in raw_imports.items():
        if file in test_context_files:
            continue
        names.update(import_names(imports))
    pending = set(candidate_modules)
    package_initializers = {
        file for file in candidate_modules if Path(file).name == "__init__.py"
    }
    while pending:
        reached = {
            file
            for file in pending
            if any(
                module == name
                or module.startswith(name + ".")
                or (file in package_initializers and name.startswith(module + "."))
                for module in candidate_modules[file]
                for name in names
            )
        }
        if not reached:
            break
        for file in reached:
            names.update(import_names(raw_imports[file]))
        pending.difference_update(reached)
    return names


def _resolved(path) -> str:
    try:
        return str(Path(path).resolve())
    except (OSError, RuntimeError):
        return str(path)
