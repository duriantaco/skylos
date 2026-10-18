"""Round-5 cases reconciled with repeated-selection and stream-size evidence.

Required nested output stays quiet. Genuine selection and shared-file searches
remain positive. Unbounded HTTP and opaque stream reads remain P401 findings;
proven in-memory buffer reads stay quiet. Fixture source is unchanged.
"""

import ast
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from skylos.rules.quality.performance import PerformanceRule


def _lines(source, rule_id):
    tree = ast.parse(source)
    rule = PerformanceRule()
    lines = []
    with TemporaryDirectory() as directory:
        context = {
            "filename": str(Path(directory) / "sample.py"),
            "project_root": directory,
        }
        for node in ast.walk(tree):
            for finding in rule.visit_node(node, context) or []:
                if finding["rule_id"] == rule_id:
                    lines.append(finding["line"])
    return sorted(lines)


CASES = [
    pytest.param(
        'def expand(segments, all_words):\n    out = []\n    for segment in segments:\n        for word in segment.get("words", all_words):\n            out.append(word)\n    return out\n\n\ndef consume(segments, all_words):\n    out = []\n    for segment in segments:\n        for word in segment.pop("words", all_words):\n            out.append(word)\n    return out\n',
        "SKY-P403",
        [],
        id="q01_get_default_shared: .get/.pop with a shared default",
    ),
    pytest.param(
        'def effective_permissions(users, default_perms):\n    granted = []\n    for user in users:\n        for perm in user.setdefault("perms", default_perms):\n            granted.append((user["id"], perm))\n    return granted\n',
        "SKY-P403",
        [],
        id="q02_setdefault_shared: setdefault with a shared default",
    ),
    pytest.param(
        "def nearest(queries, candidates, dist):\n    result = []\n    for q in queries:\n        best, pool = None, candidates\n        for c in pool:\n            if best is None or dist(q, c) < dist(q, best):\n                best = c\n        result.append(best)\n    return result\n",
        "SKY-P403",
        [5],
        id="q03_tuple_unpack_pool: tuple-unpacked shared pool",
    ),
    pytest.param(
        'def score(users, catalog):\n    total = 0\n    for user in users:\n        sources = [user["history"], catalog]\n        for entry in sources[1]:\n            total += entry["weight"]\n    return total\n',
        "SKY-P403",
        [],
        id="q04_literal_subscript_shared: subscript of a literal holding shared data",
    ),
    pytest.param(
        'def expand(segments, all_words):\n    out = []\n    for segment in segments:\n        words = segment["words"]\n        segment["words"].extend(all_words)\n        for word in words:\n            out.append(word)\n    return out\n',
        "SKY-P403",
        [],
        id="q05_view_alias_mutated_via_item: view alias grown through the item",
    ),
    pytest.param(
        'DEBUG_LOG = "/var/log/app/debug.log"\nMAIN_LOG = "/var/log/app/main.log"\nREGION_LOGS = {"eu": "/var/log/app/eu.log", "us": "/var/log/app/us.log"}\n\n\ndef activity(users):\n    counts = {}\n    for user in users:\n        with open(DEBUG_LOG if user.debug else MAIN_LOG) as fh:\n            for line in fh:\n                if user.name in line:\n                    counts[user.name] = counts.get(user.name, 0) + 1\n    return counts\n\n\ndef activity_by_region(users):\n    counts = {}\n    for user in users:\n        with open(REGION_LOGS[user.region]) as fh:\n            for line in fh:\n                if user.name in line:\n                    counts[user.name] = counts.get(user.name, 0) + 1\n    return counts\n\n\ndef activity_shared(users):\n    counts = {}\n    for user in users:\n        with open(MAIN_LOG) as fh:\n            for line in fh:\n                if user.name in line:\n                    counts[user.name] = counts.get(user.name, 0) + 1\n    return counts\n',
        "SKY-P403",
        [10, 20, 30],
        id="q06_shared_logfile_by_item: item only picks a shared file",
    ),
    pytest.param(
        "def label_chunks(data, labels, size):\n    chunks = [data[i:i + size] for i in range(0, len(data), size)]\n    out = []\n    for label, chunk in zip(labels, chunks):\n        for item in chunk:\n            out.append((label, item))\n    return out\n\n\ndef tag_tokens(labels, lines):\n    words = [line.split() for line in lines]\n    out = []\n    for label, toks in zip(labels, words):\n        for tok in toks:\n            out.append((label, tok))\n    return out\n\n\ndef tag_tokens_enumerated(lines):\n    words = [line.split() for line in lines]\n    out = []\n    for index, toks in enumerate(words):\n        for tok in toks:\n            out.append((index, tok))\n    return out\n",
        "SKY-P403",
        [],
        id="q07_zip_disjoint_rows: zip rows from comprehensions (base: not reported)",
    ),
    pytest.param(
        "def compare_to_first(rows):\n    diffs = 0\n    for r in rows:\n        row = rows[0]\n        for value in row:\n            if value not in r:\n                diffs += 1\n    return diffs\n",
        "SKY-P403",
        [5],
        id="q08_first_row_alias: first row of the outer collection",
    ),
    pytest.param(
        "def walk(nodes, root_children):\n    count = 0\n    for node in nodes:\n        if node is None:\n            node = root_children\n        for child in node:\n            count += len(child)\n    return count\n\n\ndef drain(items, fallback):\n    n = 0\n    for item in items:\n        item, spare = fallback, item\n        for x in item:\n            n += len(x) + len(spare)\n    return n\n",
        "SKY-P403",
        [],
        id="q09_rebind_item: item rebound to shared data",
    ),
    pytest.param(
        'def peers(users):\n    out = []\n    for user in users:\n        for member in user["org"]["members"]:\n            if member is not user:\n                out.append((user["id"], member["id"]))\n    return out\n',
        "SKY-P403",
        [],
        id="q12_nested_subscript_org: two-level subscript is not a strict view",
    ),
    pytest.param(
        'def link(users, members):\n    for user in users:\n        user["peers"] = members\n    pairs = []\n    for user in users:\n        for peer in user["peers"]:\n            pairs.append((user["id"], peer["id"]))\n    return pairs\n',
        "SKY-P403",
        [],
        id="q13_stored_shared_then_read: item key assigned a shared list in an earlier loop",
    ),
    pytest.param(
        "REGISTRY = {}\n\n\ndef resolve(names):\n    found = []\n    for name in names:\n        for key, handler in REGISTRY.items():\n            if key == name:\n                found.append(handler)\n    return found\n\n\ndef by_key(keys, shared):\n    out = []\n    for k in keys:\n        for v in shared[k].values():\n            out.append(v)\n    return out\n\n\ndef generator_filter(users, orders):\n    out = []\n    for user in users:\n        for o in (o for o in orders if o.user_id == user.id):\n            out.append(o)\n    return out\n",
        "SKY-P403",
        [24],
        id="q14_shared_views: views of shared mappings (line 7: empty global, base misses it)",
    ),
    pytest.param(
        'def flatten(rows):\n    out = []\n    for row in rows:\n        for key, value in row.items():\n            out.append((key, value))\n    return out\n\n\ndef read_all(paths):\n    out = []\n    for path in paths:\n        with open(path) as fh:\n            for line in fh:\n                out.append(line)\n    return out\n\n\ndef tokens(records):\n    out = []\n    for rec in records:\n        for tok in rec["text"].split():\n            out.append(tok)\n    return out\n',
        "SKY-P403",
        [],
        id="q15_per_item_controls: row.items() is per-item; open(path) and split() are not proven",
    ),
    pytest.param(
        "def normalise(rows, headers):\n    out = []\n    for row in rows:\n        pairs = zip(headers, row)\n        record = dict(pairs)\n        for cell in row:\n            out.append((record, cell))\n    return out\n",
        "SKY-P403",
        [],
        id="q16_zip_named_dict: base behaviour",
    ),
    pytest.param(
        "def scan(groups):\n    for group in groups:\n        for value in group:\n            yield value\n",
        "SKY-P403",
        [],
        id="b_control_per_item/sample: the item itself",
    ),
    pytest.param(
        "def scan(items, fetch):\n    for item in items:\n        for value in fetch(item):\n            yield value\n",
        "SKY-P403",
        [],
        id="b_control_unknown_call/sample: call result",
    ),
    pytest.param(
        "class Item:\n    def split(self):\n        return SHARED\n\nSHARED = list(range(100))\n\ndef scan(items):\n    for item in items:\n        for value in item.split():\n            yield value\n",
        "SKY-P403",
        [],
        id="b_custom_split_shared/sample: custom split returning shared data",
    ),
    pytest.param(
        "SHARED = list(range(100))\n\nclass Group(list):\n    def get(self):\n        self.extend(SHARED)\n\ndef scan(groups):\n    for group in groups:\n        group.get()\n        for value in group:\n            yield value\n",
        "SKY-P403",
        [],
        id="b_mutating_get/sample: custom get() growing the item",
    ),
    pytest.param(
        "class Source:\n    def __init__(self, shared):\n        self.shared = shared\n\n    def open(self, key):\n        return self.shared\n\ndef scan(keys, source):\n    for key in keys:\n        for value in source.open(key):\n            yield value\n",
        "SKY-P403",
        [],
        id="b_open_returns_shared/sample: custom open() returning shared data",
    ),
    pytest.param(
        "import os as filesystem\n\ndef scan(root):\n    for base, dirs, files in filesystem.walk(root):\n        for name in files:\n            yield base, name\n",
        "SKY-P403",
        [],
        id="b_os_walk_alias/sample: os.walk through an aliased import",
    ),
    pytest.param(
        "def scan(groups):\n    for group, flag in zip(groups, [True] * len(groups)):\n        for value in group:\n            yield value\n",
        "SKY-P403",
        [],
        id="b_zip_repeated_secondary/sample: repeated value in another zip position",
    ),
    pytest.param(
        'import io\n\n\nclass Source:\n    def __init__(self):\n        self.handle = io.BytesIO()\n\n    def payload(self):\n        return self.handle.read()\n\n\nclass FileSource(Source):\n    def __init__(self, path):\n        super().__init__()\n        self.handle = open(path, "rb")\n',
        "SKY-P401",
        [9],
        id="r01_subclass_file_attr: instance attribute rebound to a file in a subclass",
    ),
    pytest.param(
        'import io\n\n\nclass Blob:\n    def __init__(self):\n        self.src = io.BytesIO()\n\n    @classmethod\n    def from_path(cls, path):\n        blob = cls()\n        blob.src = open(path, "rb")\n        return blob\n\n    def data(self):\n        return self.src.read()\n\n    @staticmethod\n    def drain(entry):\n        return entry.src.read()\n',
        "SKY-P401",
        [15, 19],
        id="r02_classmethod_file_attr: attribute set to a file by a classmethod",
    ),
    pytest.param(
        'import io\n\npayload = io.BytesIO()\n\n\ndef use_file(path):\n    global payload\n    payload = open(path, "rb")\n\n\ndef drain():\n    return payload.read()\n',
        "SKY-P401",
        [12],
        id="r03_global_rebound_buffer: module buffer rebound to a file via global",
    ),
    pytest.param(
        'import io\n\n\ndef load(path, lazy):\n    data = io.BytesIO()\n\n    def swap():\n        nonlocal data\n        data = open(path, "rb")\n\n    if lazy:\n        swap()\n    return data.read()\n',
        "SKY-P401",
        [13],
        id="r04_nonlocal_rebound_buffer: local buffer rebound to a file via nonlocal",
    ),
    pytest.param(
        "import urllib.request\n\n\ndef fetch(url, jar):\n    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))\n    with opener.open(url, timeout=10) as response:\n        return response.read()\n\n\ndef fetch_plain(url):\n    with urllib.request.urlopen(url, timeout=10) as response:\n        return response.read()\n",
        "SKY-P401",
        [7, 12],
        id="r05_opener_open_response: opener.open() is an HTTP response",
    ),
    pytest.param(
        "import sys\n\n\ndef main():\n    return sys.stdin.read()\n\n\ndef handler(request):\n    body = request.stream.read()\n    return body\n\n\ndef handler_alias(request):\n    stream = request.stream\n    return stream.read()\n",
        "SKY-P401",
        [5, 9, 15],
        id="r06_stdin_and_request_stream: stdin and request streams (line 15: name hint, base)",
    ),
    pytest.param(
        "import zipfile\n\n\ndef extract(path, name):\n    with zipfile.ZipFile(path) as zf:\n        return zf.read(name)\n\n\ndef extract_open(path, name):\n    with zipfile.ZipFile(path) as zf:\n        return zf.open(name).read()\n",
        "SKY-P401",
        [6, 11],
        id="r07_zipfile_member_read: zip member opened (line 6: name arg read as a size, base)",
    ),
    pytest.param(
        'import io\n\nfrom flask import request\n\n\ndef ingest(parse):\n    upload = request.files["doc"]\n    content = io.BytesIO(upload.read())\n    return parse(content.read())\n',
        "SKY-P401",
        [8],
        id="r09_bytesio_from_upload: upload read; the BytesIO built from it is memory",
    ),
    pytest.param(
        'import urllib.error\n\n\nclass PayloadTooLarge(Exception):\n    def __init__(self, stream):\n        super().__init__("too large")\n        self.stream = stream\n\n\ndef handle(upload, check):\n    try:\n        check(upload)\n    except PayloadTooLarge as exc:\n        return exc.stream.read()\n    return b""\n\n\ndef fetch(opener, url):\n    try:\n        return opener(url)\n    except urllib.error.HTTPError as err:\n        return err.read()\n',
        "SKY-P401",
        [14, 22],
        id="r10_exception_wraps_stream: stream held by an exception; HTTPError body is not",
    ),
    pytest.param(
        "def load_pair(path):\n    with open(path) as fh:\n        header, body = fh.readlines()\n    return header, body\n",
        "SKY-P401",
        [3],
        id="r11_readlines_unpacked: readlines of an opened file",
    ),
    pytest.param(
        "def load(path, fallback):\n    try:\n        return fallback()\n    except OSError as e:\n        print(e)\n    with open(path) as e:\n        return e.read()\n",
        "SKY-P401",
        [7],
        id="r14_except_name_reused_as_file: except name reused for a file",
    ),
    pytest.param(
        'def load(path):\n    response = open(path, "rb")\n    return response.read()\n',
        "SKY-P401",
        [3],
        id="b_exact_file_response/sample: a file named response",
    ),
    pytest.param(
        "import io\n\nclass Reader:\n    def __init__(self):\n        self.buffer = io.StringIO()\n\n    def load(self, path):\n        alias = self\n        alias.buffer = open(path)\n        return self.buffer.read()\n",
        "SKY-P401",
        [10],
        id="b_instance_alias_file/sample: attribute set through an alias of self",
    ),
    pytest.param(
        'class Client:\n    def open(self, key):\n        return "text response"\n\ndef fetch(client):\n    response = client.open("x")\n    return response.read()\n',
        "SKY-P401",
        [7],
        id="b_nonfile_open_response/sample: client.open() is not a file opener",
    ),
    pytest.param(
        'def load(path):\n    f = open(path, "rb")\n    first, second = f.read()\n    return first, second\n',
        "SKY-P401",
        [3],
        id="b_tuple_unpack_file/sample: file read unpacked into a tuple",
    ),
    pytest.param(
        'class Response:\n    def read(self):\n        return "text"\n\nclass Client:\n    def open(self, key):\n        return Response()\n\ndef fetch(client):\n    response = client.open("x")\n    return response.read()\n',
        "SKY-P401",
        [11],
        id="b_valid_nonfile_open_response/sample: client.open() is not a file opener",
    ),
]


@pytest.mark.parametrize(("source", "rule_id", "lines"), CASES)
def test_round5_review_case(source, rule_id, lines):
    assert _lines(source, rule_id) == lines


# Shared children still require every emitted pair. These fixtures exercise
# required nested output, without a selection an index could replace.
TRADE_OFFS = [
    pytest.param(
        'def scan(items, shared):\n    for item in items:\n        for value in item["child"]:\n            yield value\n\nshared = list(range(100))\nitems = [{"child": shared} for _ in range(100)]\n',
        [],
        id='b_shared_child: item["child"] shared by every item',
    ),
    pytest.param(
        'def scan(items, shared):\n    for item in items:\n        for value in item.get("child"):\n            yield value\n\nshared = list(range(100))\nitems = [{"child": shared} for _ in range(100)]\n',
        [],
        id='b_alias_shared_child: item.get("child") shared by every item',
    ),
]


@pytest.mark.parametrize(("source", "lines"), TRADE_OFFS)
def test_shared_children_behind_a_view_are_not_detected(source, lines):
    assert _lines(source, "SKY-P403") == lines


FIXED_PATTERNS_REBOUND_PER_ITEM = """
def check(triggers):
    found = []
    for trigger in triggers:
        patterns = [r"^a$", r"^b$", r"^c$"]
        for pattern in patterns:
            if trigger == pattern:
                found.append(trigger)
    return found
"""

PATTERNS_GROWN_FROM_SHARED = """
def check(triggers, extra):
    found = []
    for trigger in triggers:
        patterns = ["a", "b"]
        patterns.extend(extra)
        for pattern in patterns:
            found.append((trigger, pattern))
    return found
"""

PATTERNS_GROWN_THROUGH_AN_ALIAS = """
def check(triggers, extra):
    found = []
    for trigger in triggers:
        patterns = ["a", "b"]
        alias = patterns
        alias += extra
        for pattern in patterns:
            found.append((trigger, pattern))
    return found
"""

PATTERNS_PASSED_TO_A_CALLEE = """
def check(triggers, grow):
    found = []
    for trigger in triggers:
        patterns = ["a", "b"]
        grow(patterns)
        for pattern in patterns:
            found.append((trigger, pattern))
    return found
"""


@pytest.mark.parametrize(
    ("source", "lines"),
    [
        pytest.param(FIXED_PATTERNS_REBOUND_PER_ITEM, [], id="fixed-display-rebound"),
        pytest.param(PATTERNS_GROWN_FROM_SHARED, [], id="display-grown"),
        pytest.param(PATTERNS_GROWN_THROUGH_AN_ALIAS, [], id="display-aliased"),
        pytest.param(PATTERNS_PASSED_TO_A_CALLEE, [], id="display-passed-on"),
    ],
)
def test_fixed_size_display_is_bounded_only_while_untouched(source, lines):
    assert _lines(source, "SKY-P403") == lines


ITEM_GROWN_THROUGH_A_TUPLE_ALIAS = """
def expand(segments, shared):
    out = []
    for segment in segments:
        alias, other = segment, shared
        alias["words"].extend(shared)
        for word in segment["words"]:
            out.append(word)
    return out
"""

CHILD_GROWN_THROUGH_A_COMPUTED_KEY = """
def expand(segments, key, shared):
    out = []
    for segment in segments:
        child = segment[key]
        child.extend(shared)
        for word in segment["words"]:
            out.append(word)
    return out
"""

CHILD_GROWN_THROUGH_A_METHOD_RESULT = """
def expand(segments, key, shared):
    out = []
    for segment in segments:
        child = segment.get(key)
        child.append(shared)
        for word in segment["words"]:
            out.append(word)
    return out
"""

UNUSED_ALIAS_OF_THE_ITEM = """
def expand(segments, shared):
    out = []
    for segment in segments:
        alias, other = segment, shared
        for word in segment["words"]:
            out.append((alias is other, word))
    return out
"""


@pytest.mark.parametrize(
    ("source", "lines"),
    [
        pytest.param(ITEM_GROWN_THROUGH_A_TUPLE_ALIAS, [], id="tuple-alias-grown"),
        pytest.param(CHILD_GROWN_THROUGH_A_COMPUTED_KEY, [], id="computed-key-alias"),
        pytest.param(CHILD_GROWN_THROUGH_A_METHOD_RESULT, [], id="method-result-alias"),
        pytest.param(UNUSED_ALIAS_OF_THE_ITEM, [], id="alias-never-changed"),
    ],
)
def test_item_changed_through_an_alias_is_reported(source, lines):
    assert _lines(source, "SKY-P403") == lines
