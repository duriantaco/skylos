from __future__ import annotations

import ast
import hashlib
import io
import tokenize
from dataclasses import dataclass
from difflib import SequenceMatcher
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


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
    min_lines: int = 5
    min_nodes: int = 10
    type1_threshold: float = 0.98
    type2_threshold: float = 0.95
    type3_threshold: float = 0.80
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
            if tok_type == tokenize.STRING:
                out.append('"STR"')
            elif tok_type == tokenize.NUMBER:
                out.append("0")
            else:
                out.append(tok_str)
    except tokenize.TokenError:
        return " ".join(source.split())
    return " ".join(out)


class _Type2Normalizer(ast.NodeTransformer):
    def __init__(self, ignore_identifiers: bool, ignore_literals: bool):
        self.ignore_identifiers = ignore_identifiers
        self.ignore_literals = ignore_literals

    def visit_Name(self, node: ast.Name):
        if self.ignore_identifiers:
            return ast.copy_location(ast.Name(id="_ID", ctx=node.ctx), node)
        return node

    def visit_arg(self, node: ast.arg):
        if self.ignore_identifiers:
            node.arg = "_ARG"
        return node

    def visit_Attribute(self, node: ast.Attribute):
        node = self.generic_visit(node)
        if self.ignore_identifiers:
            node.attr = "_ATTR"
        return node

    def visit_Constant(self, node: ast.Constant):
        if self.ignore_literals:
            if node.value in (None, True, False):
                return node
            return ast.copy_location(ast.Constant(value="_LIT"), node)
        return node


def _dump_ast(node: ast.AST) -> str:
    return ast.dump(node, annotate_fields=False, include_attributes=False)


def _count_nodes(node: ast.AST) -> int:
    return sum(1 for _ in ast.walk(node))


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(a=a, b=b).ratio()


def extract_fragments(py_path: Path, source: str, cfg: CloneConfig) -> List[Fragment]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    fragments: List[Fragment] = []
    class_stack: List[str] = []

    def mk_fragment(n: ast.AST, kind: str, name: str, body: Optional[List[ast.stmt]]):
        start = getattr(n, "lineno", None)
        end = getattr(n, "end_lineno", None)
        if start is None or end is None:
            return
        if (end - start + 1) < cfg.min_lines:
            return

        if body is not None:
            body2 = _strip_docstring(body) if cfg.skip_docstrings else body
            node_for_dump = ast.Module(body=body2, type_ignores=[])
        else:
            node_for_dump = n

        node_count = _count_nodes(node_for_dump)
        if node_count < cfg.min_nodes:
            return

        src_lines = source.splitlines()
        frag_src = "\n".join(src_lines[start - 1 : end])
        text_norm = _normalize_text(frag_src)

        t2 = _Type2Normalizer(cfg.ignore_identifiers, cfg.ignore_literals).visit(
            ast.fix_missing_locations(node_for_dump)
        )
        ast_norm_type2 = _dump_ast(t2)

        ast_norm_type3 = _dump_ast(node_for_dump)

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
            if class_stack:
                mk_fragment(node, "method", f"{class_stack[-1]}.{node.name}", node.body)
            else:
                mk_fragment(node, "function", node.name, node.body)
            self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
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
        sim1 = _similarity(f1.text_norm, f2.text_norm)
        if sim1 >= cfg.type1_threshold:
            return (CloneType.TYPE1, sim1)

    if CloneType.TYPE2 in enabled:
        sim2 = _similarity(f1.ast_norm_type2, f2.ast_norm_type2)
        if sim2 >= cfg.type2_threshold:
            return (CloneType.TYPE2, sim2)

    if CloneType.TYPE3 in enabled:
        sim3 = _similarity(f1.ast_norm_type3, f2.ast_norm_type3)
        if sim3 >= cfg.type3_threshold:
            return (CloneType.TYPE3, sim3)

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
        clone_type = max(set(types), key=types.count) if types else CloneType.TYPE3

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
