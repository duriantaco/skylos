"""P403 distinguishes repeated selection from required nested work.

Equality joins, predicate filters and shared-file searches
remain positive. Cartesian outputs, sorting, traversal and opaque helper results
do not prove an avoidable lookup merely by containing a nested loop.
"""

import ast

import pytest

from skylos.rules.quality.performance import PerformanceRule


def _p403_lines(source):
    tree = ast.parse(source)
    rule = PerformanceRule()
    lines = []
    for node in ast.walk(tree):
        for finding in rule.visit_node(node, {"filename": "sample.py"}) or []:
            if finding["rule_id"] == "SKY-P403":
                lines.append(finding["line"])
    return sorted(lines)


# --- per-item work: not a repeated scan -------------------------------------
# (The first four sources are call results: reported, see the shared list.)

BATCH_RESULT_RECOMPUTED_PER_ITEM = """
class Searcher:
    def batch_search(self, queries, topk):
        responses = []
        for start in range(0, len(queries), self.batch_size):
            batch = queries[start : start + self.batch_size]
            embeddings = self.encoder.encode(batch)
            scores, indexes = self.index.search(embeddings, topk)
            for row_ids, row_scores in zip(indexes, scores, strict=True):
                items = []
                for doc_id, score in zip(row_ids, row_scores, strict=True):
                    if int(doc_id) < 0:
                        continue
                    items.append((self.corpus[int(doc_id)], float(score)))
                responses.append(items)
        return responses
"""

ZIP_OF_OUTER_BINDINGS = """
def pair_rows(left_rows, right_rows):
    out = []
    for left, right in zip(left_rows, right_rows):
        for a, b in zip(left, right, strict=True):
            out.append(a + b)
    return out
"""

CALL_RESULT_FROM_OUTER_ITEM = """
def totals(users, db):
    total = 0
    for user in users:
        for order in db.orders_for(user_id=user.id):
            total += order.amount
    return total
"""

NAMED_CALL_RESULT_FROM_OUTER_ITEM = """
def totals(users, fetch_orders):
    total = 0
    for user in users:
        orders = fetch_orders(user)
        for order in orders:
            total += order.amount
    return total
"""

PARSED_LOOKUP_RESULT = """
def collect(cache, paths, parse):
    found = {}
    for path in paths:
        content = cache.get(path)
        if not content:
            continue
        for name, version in parse(content):
            found[name] = version
    return found
"""

ITEM_AND_ITS_STORED_CHILDREN = """
def valid(result):
    for segment in result["segments"]:
        if not isinstance(segment, dict):
            return False
        words = segment.get("words") or []
        if not isinstance(words, list):
            return False
        if not words and not isinstance(segment.get("text"), str):
            return False
        if any(not isinstance(w, dict) or not isinstance(w.get("w"), str) for w in words):
            return False
        for item in [segment, *words]:
            if not isinstance(item, dict):
                return False
    return True
"""

CONSTANT_KEY_READ_OF_OUTER_ITEM = """
def count_words(segments):
    n = 0
    for segment in segments:
        for word in segment["words"]:
            n += len(word)
    return n
"""

SPLIT_OF_OUTER_ITEM = """
def tokens(lines):
    out = []
    for line in lines:
        for token in line.split():
            out.append(token)
    return out
"""

OS_WALK_PRUNED_IN_PLACE = """
import os

def scan(root, skip):
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(name for name in dirnames if name not in skip)
        for dirname in list(dirnames):
            found.append(dirname)
    return found
"""

OS_WALK_SORTED_AND_PRUNED = """
import os

def scan(root):
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        if ".git" in dirnames:
            dirnames.remove(".git")
        filenames.sort(key=str.lower)
        for dirname in dirnames:
            found.append(dirname)
        for filename in filenames:
            found.append(filename)
    return found
"""


FILE_OPENED_PER_ITEM = """
def lines(paths):
    for path in paths:
        with open(path) as handle:
            for line in handle:
                yield line
"""

FILE_OPENED_FROM_DERIVED_PATH = """
import os

def lines(root, names):
    for name in names:
        with open(os.path.join(root, name)) as handle:
            for line in handle:
                yield line
"""


@pytest.mark.parametrize(
    "source",
    [
        pytest.param(ZIP_OF_OUTER_BINDINGS, id="zip-of-outer-bindings"),
        pytest.param(ITEM_AND_ITS_STORED_CHILDREN, id="item-and-stored-children"),
        pytest.param(CONSTANT_KEY_READ_OF_OUTER_ITEM, id="constant-key-read"),
        pytest.param(OS_WALK_PRUNED_IN_PLACE, id="os-walk-slice-prune"),
        pytest.param(OS_WALK_SORTED_AND_PRUNED, id="os-walk-sort-remove"),
    ],
)
def test_per_item_inner_iteration_is_not_reported(source):
    assert _p403_lines(source) == []


# --- shared sources: selection versus required output -------------------------------

ALL_PAIRS = """
def match(users, orders):
    for user in users:
        for order in orders:
            if order.user_id == user.id:
                yield user, order
"""

MODULE_GLOBAL = """
CATALOG = load_catalog()

def match(users):
    for user in users:
        for entry in CATALOG:
            if entry.owner == user.id:
                yield entry
"""

SHARED_SELF_ATTRIBUTE = """
class Matcher:
    def match(self, users):
        for user in users:
            for order in self.orders:
                if order.user_id == user.id:
                    yield order
"""

SORTED_SHARED_BY_ITEM = """
def rank(users, candidates, score):
    for user in users:
        for candidate in sorted(candidates, key=lambda c: score(user, c)):
            yield user, candidate
"""

BOUND_SORTED_SHARED_BY_ITEM = """
def rank(users, candidates, score):
    for user in users:
        ranked = sorted(candidates, key=lambda c: score(user, c))
        for candidate in ranked:
            yield user, candidate
"""

FILTERED_SHARED_BY_ITEM = """
def rank(users, candidates, ok):
    for user in users:
        for candidate in filter(lambda c: ok(user, c), candidates):
            yield user, candidate
"""

TRIANGLE_SLICE = """
def pairs(items):
    for i in range(len(items)):
        for other in items[i + 1:]:
            yield items[i], other
"""

LOOP_INVARIANT_CALL = """
def match(users, load_all):
    for user in users:
        rows = load_all()
        for row in rows:
            if row.user_id == user.id:
                yield row
"""

SHARED_MAPPING_LOOKUP_BY_ITEM = """
def members(users, groups):
    for user in users:
        group = groups.get(user.group_id)
        for member in group:
            yield user, member
"""

SHARED_MAPPING_SUBSCRIPT_BY_ITEM = """
def members(users, groups):
    for user in users:
        for member in groups[user.group_id]:
            yield user, member
"""

ATTRIBUTE_CHAIN_TO_SHARED = """
def neighbours(nodes):
    for node in nodes:
        for other in node.graph.nodes:
            yield node, other
"""

STARRED_SHARED_IN_LITERAL = """
def expand(segments, all_words):
    for segment in segments:
        for item in [segment, *all_words]:
            yield item
"""

FALLBACK_TO_SHARED = """
def expand(segments, all_words):
    for segment in segments:
        words = segment.get("words") or all_words
        for word in words:
            yield word
"""

FRESH_RESULT_GROWN_FROM_SHARED = """
def expand(users, fetch, everything):
    for user in users:
        rows = fetch(user)
        rows.extend(everything)
        for row in rows:
            yield row
"""

CONDITIONAL_FRESH_RESULT = """
def expand(users, fetch, everything):
    rows = everything
    for user in users:
        if user.active:
            rows = fetch(user)
        for row in rows:
            yield row
"""

ZIP_WITH_SHARED_ROWS = """
def expand(keys, shared):
    for key, row in zip(keys, [shared] * len(keys)):
        for a, b in zip(row, row):
            yield key, a, b
"""

OS_WALK_REPLACED_FROM_SHARED = """
import os

def scan(root, extra):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = extra
        for dirname in dirnames:
            yield dirname
"""

OS_WALK_EXTENDED = """
import os

def scan(root, extra):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.extend(extra)
        for dirname in dirnames:
            yield dirname
"""


SCALAR_SIZED_RANGE = """
def triangle(n):
    for i in range(n):
        for j in range(i):
            yield i, j
"""

ITERTOOLS_PREFIX_OF_SHARED = """
import itertools

def prefixes(items):
    for i in range(len(items)):
        for item in itertools.islice(items, i):
            yield i, item
"""

COPY_OF_SHARED = """
def match(users, orders):
    for user in users:
        for order in list(orders):
            yield user, order
"""

SHARED_ITERABLE_WITH_ITEM_LABEL = """
def train(epochs, loader, tqdm, step):
    for epoch in range(epochs):
        for batch in tqdm(loader, desc=f"epoch {epoch}"):
            step(batch)
"""

SHARED_TOP_K_KEYED_BY_ITEM = """
import heapq

def nearest(users, candidates, k, dist):
    for user in users:
        for c in heapq.nsmallest(k, candidates, key=lambda c: dist(user, c)):
            yield user, c
"""

# Calls given the outer item: nothing local proves the result is per-item.

CLOSE_MATCHES_OF_SHARED = """
import difflib

def suggest(names):
    for name in names:
        for match in difflib.get_close_matches(name, names):
            yield name, match
"""

HELPER_GIVEN_ITEM_AND_SHARED = """
def link(items, related):
    for item in items:
        for other in related(item, items):
            yield item, other
"""

SELF_METHOD_GIVEN_ITEM = """
class Dedup:
    def run(self):
        for user in self.users:
            for dup in self.find_duplicates(user):
                yield user, dup
"""

HELPER_RETURNING_GLOBAL = """
CATALOG = []

def same(item):
    return CATALOG

def scan(items):
    for item in items:
        for entry in same(item):
            yield entry
"""

CALLEE_IS_THE_ITEM = """
def run(factories):
    for factory in factories:
        for value in factory():
            yield value
"""

METHOD_ON_ITEM_ATTRIBUTE = """
def neighbours(nodes):
    for node in nodes:
        for other in node.graph.all_nodes():
            yield node, other
"""

SPLIT_OF_CALL_RESULT = """
def words(paths, load):
    for path in paths:
        text = load(path)
        for word in text.split():
            yield word
"""

SHARED_FILE_REREAD = """
def scan(users, path):
    for user in users:
        with open(path) as fh:
            for line in fh:
                if user.name in line:
                    yield user
"""


@pytest.mark.parametrize(
    ("source", "lines"),
    [
        pytest.param(ALL_PAIRS, [4], id="all-pairs"),
        pytest.param(MODULE_GLOBAL, [6], id="module-global"),
        pytest.param(SHARED_SELF_ATTRIBUTE, [5], id="shared-self-attribute"),
        pytest.param(SORTED_SHARED_BY_ITEM, [], id="sorted-shared-keyed-by-item"),
        pytest.param(BOUND_SORTED_SHARED_BY_ITEM, [], id="bound-sorted-shared"),
        pytest.param(FILTERED_SHARED_BY_ITEM, [4], id="filtered-shared"),
        pytest.param(TRIANGLE_SLICE, [], id="triangle-slice"),
        pytest.param(LOOP_INVARIANT_CALL, [], id="loop-invariant-call"),
        pytest.param(SHARED_MAPPING_LOOKUP_BY_ITEM, [], id="shared-mapping-get"),
        pytest.param(
            SHARED_MAPPING_SUBSCRIPT_BY_ITEM, [], id="shared-mapping-subscript"
        ),
        pytest.param(ATTRIBUTE_CHAIN_TO_SHARED, [], id="attribute-chain"),
        pytest.param(STARRED_SHARED_IN_LITERAL, [], id="starred-shared"),
        pytest.param(FALLBACK_TO_SHARED, [], id="fallback-to-shared"),
        pytest.param(FRESH_RESULT_GROWN_FROM_SHARED, [], id="fresh-result-grown"),
        pytest.param(CONDITIONAL_FRESH_RESULT, [], id="conditional-fresh-result"),
        pytest.param(ZIP_WITH_SHARED_ROWS, [], id="zip-with-shared-rows"),
        pytest.param(OS_WALK_REPLACED_FROM_SHARED, [], id="os-walk-replaced"),
        pytest.param(OS_WALK_EXTENDED, [], id="os-walk-extended"),
        pytest.param(SCALAR_SIZED_RANGE, [], id="range-of-outer-index"),
        pytest.param(ITERTOOLS_PREFIX_OF_SHARED, [], id="itertools-prefix"),
        pytest.param(COPY_OF_SHARED, [], id="copy-of-shared"),
        pytest.param(SHARED_ITERABLE_WITH_ITEM_LABEL, [], id="wrapper-label-only"),
        pytest.param(SHARED_TOP_K_KEYED_BY_ITEM, [], id="top-k-of-shared"),
        pytest.param(BATCH_RESULT_RECOMPUTED_PER_ITEM, [], id="batch-search-result"),
        pytest.param(CALL_RESULT_FROM_OUTER_ITEM, [], id="call-result-from-item"),
        pytest.param(NAMED_CALL_RESULT_FROM_OUTER_ITEM, [], id="named-call-result"),
        pytest.param(PARSED_LOOKUP_RESULT, [], id="parsed-lookup-result"),
        pytest.param(CLOSE_MATCHES_OF_SHARED, [], id="close-matches-of-shared"),
        pytest.param(HELPER_GIVEN_ITEM_AND_SHARED, [], id="helper-item-and-shared"),
        pytest.param(SELF_METHOD_GIVEN_ITEM, [], id="self-method-given-item"),
        pytest.param(HELPER_RETURNING_GLOBAL, [], id="helper-returning-global"),
        pytest.param(CALLEE_IS_THE_ITEM, [], id="callee-is-the-item"),
        pytest.param(METHOD_ON_ITEM_ATTRIBUTE, [], id="method-on-item-attribute"),
        pytest.param(SPLIT_OF_CALL_RESULT, [], id="split-of-call-result"),
        pytest.param(SHARED_FILE_REREAD, [5], id="shared-file-reread"),
        # Calls are not proof of per-item data, even on the item.
        pytest.param(FILE_OPENED_PER_ITEM, [], id="file-opened-per-item"),
        pytest.param(FILE_OPENED_FROM_DERIVED_PATH, [], id="file-opened-derived-path"),
        pytest.param(SPLIT_OF_OUTER_ITEM, [], id="split-of-outer-item"),
    ],
)
def test_shared_inner_iteration_is_still_reported(source, lines):
    assert _p403_lines(source) == lines
