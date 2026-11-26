import ast
import json

import pytest

from skylos.analyzer import analyze
from skylos.rules.danger.danger_fs import path_provenance
from skylos.rules.danger.project_security_sources import SecurityProject
from skylos.scale.parallel_static import run_proc_file_parallel


def _scan_import_branches(tmp_path, monkeypatch, producers, cache_units):
    names = []
    for name, producer in producers:
        names.append(name)
        (tmp_path / f"{name}.py").write_text(producer)
    consumer = tmp_path / "consumer.py"
    source = ["import importlib"]
    source.extend(
        f"from {name} import read as read_{i}" for i, name in enumerate(names)
    )
    source.append("def check(which):")
    for index in range(len(names) - 1):
        branch = "if" if index == 0 else "elif"
        source.extend(
            [f"    {branch} which == {index}:", f"        choose = read_{index}"]
        )
    source += [
        "    else:",
        f"        choose = read_{len(names) - 1}",
        "    importlib.import_module(choose())",
    ]
    consumer.write_text("\n".join(source) + "\n")

    # Force the order of genuine branch targets while leaving tracing, its
    # evidence limits, and the rest of the worker exactly as used in a scan.
    order = {name + ".py": i for i, name in enumerate(names)}
    observed = []

    class OrderedValues(frozenset):
        def __iter__(self):
            return iter(
                sorted(super().__iter__(), key=lambda value: order[value.unit.rel])
            )

    resolve = SecurityProject.values

    def ordered(project, unit, scope, node, *args, **kwargs):
        result = resolve(project, unit, scope, node, *args, **kwargs)
        if (
            isinstance(node, ast.Name)
            and node.id == "choose"
            and result
            and len(result) == len(names)
        ):
            result = OrderedValues(result)
            observed.append([value.unit.rel for value in result])
        return result

    monkeypatch.setattr(SecurityProject, "values", ordered)
    if not cache_units:
        monkeypatch.setattr(
            SecurityProject, "_add_python", path_provenance._Project._add_python
        )
    results = run_proc_file_parallel(
        [consumer, consumer], {consumer: "consumer"}, jobs=1, project_root=tmp_path
    )
    assert observed and all(seen == list(order) for seen in observed)
    assert all(row[25] is None for row in results)
    assert path_provenance._SELECT_UNTRUSTED_CHAINS.get() is None
    return [row[7] for row in results]


@pytest.mark.parametrize("cache_units", [False, True])
@pytest.mark.parametrize("production_slots", [*((i,) for i in range(6)), (), (0, 5)])
def test_import_witness_survives_each_branch_order(
    tmp_path, monkeypatch, cache_units, production_slots
):
    producers = []
    for index in range(6):
        name = f"production_{index}" if index in production_slots else f"test_{index}"
        imports = "import pytest\n" if index not in production_slots else ""
        producers.append(
            (
                name,
                imports + "from urllib.request import urlopen\n"
                "def read():\n    return urlopen('https://example.invalid').read().decode()\n",
            )
        )
    results = _scan_import_branches(tmp_path, monkeypatch, producers, cache_units)
    for findings in results:
        hits = [row for row in findings if row["rule_id"] == "SKY-D357"]
        assert len(hits) == int(bool(production_slots))
        if production_slots:
            expected = f"production_{production_slots[0]}.py:"
            assert hits[0]["security_evidence"]["source"].startswith(expected)


def test_project_source_warnings_are_recomputed_with_a_legacy_disk_cache(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    (tmp_path / "consumer.py").write_text(
        "import importlib, shlex, subprocess\n"
        "from source import read\n"
        "def dispatch(argv):\n    subprocess.run(argv)\n"
        "def check():\n"
        "    value = read()\n"
        "    importlib.import_module(value)\n"
        "    words = ['example']\n"
        "    words.extend(shlex.split(value))\n"
        "    dispatch(words)\n"
    )
    source = tmp_path / "source.py"
    remote = (
        "from urllib.request import urlopen\n"
        "def read():\n    return urlopen('https://example.invalid').read().decode()\n"
    )
    source.write_text(remote)
    rules = {"SKY-D212", "SKY-D357"}

    def findings():
        report = json.loads(analyze(str(tmp_path), enable_danger=True))
        return [row for row in report.get("danger", []) if row["rule_id"] in rules]

    fresh = findings()
    assert {row["rule_id"] for row in fresh} == rules
    legacy = tmp_path / ".skylos" / "cache" / "grep_results.json"
    legacy.parent.mkdir(parents=True, exist_ok=True)
    content = '{"version": 1, "entries": {"old": {"results": ["source.py:2:read()"]}}}'
    legacy.write_text(content)
    assert findings() == fresh
    source.write_text("def read():\n    return 'fixed'\n")
    assert findings() == []
    source.write_text(remote)
    assert findings() == fresh
    assert legacy.read_text() == content


@pytest.mark.parametrize("eligible", [None, 0, 1, 2, 3, 4])
def test_returned_formals_bind_each_actual_before_witness_limit(tmp_path, eligible):
    consumer = tmp_path / "consumer.py"
    names = [f"p{i}" for i in range(5)]
    args = ", ".join(
        "urlopen('https://example.invalid').read().decode()"
        if i == eligible
        else "'fixed'"
        for i in range(5)
    )
    source = [
        "import importlib",
        "from urllib.request import urlopen",
        "def choose(which, " + ", ".join(names) + "):",
        *(f"    if which == {i}: return {name}" for i, name in enumerate(names[:-1])),
        "    return p4",
        "def handle(which):",
        f"    value = choose(which, {args})",
        "    importlib.import_module(value)",
    ]
    consumer.write_text("\n".join(source) + "\n")
    rows = run_proc_file_parallel(
        [consumer, consumer], {consumer: "consumer"}, jobs=1, project_root=tmp_path
    )
    for row in rows:
        assert row[25] is None
        assert any(m["rule_id"] == "SKY-D357" for m in row[7]) == (eligible is not None)


@pytest.mark.parametrize(
    "method",
    [
        "single_guarded_expansion",
        "mutate",
        "alias",
        "forward_mutation",
        "no_boundary",
        "namespace",
        "computed_callee",
    ],
)
def test_final_vector_boundary_is_tied_to_its_actual_use(tmp_path, method):
    consumer = tmp_path / "consumer.py"
    source = [
        "import shlex, subprocess",
        "from urllib.request import urlopen",
        "def temporary():",
        "    pieces = []",
        "    pieces.extend(shlex.split(urlopen('https://example.invalid').read().decode()))",
        "    return pieces",
        "def from_context(namespace):",
        "    namespace['words'].pop(1)",
        "    return temporary()",
        "def dispatch(argv):",
        *(["    argv.pop(1)"] if method == "forward_mutation" else []),
        "    subprocess.run(argv)",
        "def destination(namespace):",
        "    namespace['words'].pop(1)",
        "    return dispatch",
        "def handle():",
        "    prepared = []",
        "    prepared.extend(temporary())",
        "    words = ['example']"
        if method == "no_boundary"
        else "    words = ['example', '--']",
        *(["    alias = words"] if method == "alias" else []),
        {
            "single_guarded_expansion": "    words.extend(shlex.split(urlopen('https://example.invalid').read().decode()))",
            "namespace": "    words.extend(from_context(locals()))",
        }.get(method, "    words.extend(prepared)"),
        *(["    words.pop(1)"] if method == "mutate" else []),
        *(["    alias.pop(1)"] if method == "alias" else []),
        "    destination(locals())(words)"
        if method == "computed_callee"
        else "    dispatch(words)",
    ]
    consumer.write_text("\n".join(source) + "\n")
    rows = run_proc_file_parallel(
        [consumer, consumer], {consumer: "consumer"}, jobs=1, project_root=tmp_path
    )
    for row in rows:
        assert row[25] is None
        assert any(m["rule_id"] == "SKY-D212" for m in row[7]) == (
            method != "single_guarded_expansion"
        )


@pytest.mark.parametrize("production_branch", [False, True])
@pytest.mark.parametrize("test_first", [False, True])
def test_import_keeps_production_return_for_same_formal(
    tmp_path, production_branch, test_first
):
    (tmp_path / "test_shim.py").write_text(
        "import pytest\ndef identity(value): return value\n"
    )
    consumer = tmp_path / "consumer.py"
    branches = ["identity(value)", "value" if production_branch else "identity(value)"]
    if not test_first:
        branches.reverse()
    consumer.write_text(
        "from urllib.request import urlopen\nimport importlib\n"
        "from test_shim import identity\n"
        "def choose(flag, value):\n"
        f"    if flag: return {branches[0]}\n    return {branches[1]}\n"
        "def start(flag):\n"
        "    value = urlopen('https://example.invalid').read().decode()\n"
        "    importlib.import_module(choose(flag, value))\n"
    )
    (row,) = run_proc_file_parallel(
        [consumer], {consumer: "consumer"}, jobs=1, project_root=tmp_path
    )
    assert row[25] is None
    assert any(m["rule_id"] == "SKY-D357" for m in row[7]) == production_branch


def test_command_with_final_option_boundary_and_seven_producer_paths(tmp_path):
    path = tmp_path / "backend.py"
    alternatives = "".join(
        f"    if i == {i}:\n"
        f"        return [urlopen('https://example.invalid/{i}').read().decode()]\n"
        for i in range(1, 7)
    )
    path.write_text(
        "from urllib.request import urlopen\nimport shlex, subprocess\n"
        "def dispatch(words):\n    subprocess.run(words)\n"
        "def choose(i):\n"
        "    if i == 0:\n"
        "        parts = []\n"
        "        parts.extend(shlex.split(urlopen('https://example.invalid/').read().decode()))\n"
        "        return parts\n"
        + alternatives
        + "    return ['example']\n"
        "def show(i):\n"
        "    output = ['example', '--']\n"
        "    output.extend(choose(i))\n"
        "    dispatch(output)\n"
    )
    (row,) = run_proc_file_parallel(
        [path], {path: "backend"}, jobs=1, project_root=tmp_path
    )
    assert row[25] is None
    assert all(finding["rule_id"] != "SKY-D212" for finding in row[7])


@pytest.mark.parametrize("bound_receiver", [False, True])
@pytest.mark.parametrize(
    "arguments",
    [
        "1, 2, 3, 4, 5, 6, 7",
        "1, *extras, 2, 3, 4",
        "1, b=2, **extras, qq=6, other=7",
        "",
    ],
)
def test_wide_summary_binds_like_single_parameter_resolution(
    tmp_path, bound_receiver, arguments
):
    (tmp_path / "module.py").write_text(
        "def choose(self, a, /, b=2, c=3, d=4, *items, qq=None, flag=5, **attrs):\n    pass\n"
    )
    project = SecurityProject.load(tmp_path)
    unit = project.units[0]
    fn = unit.tree.body[0]
    call = ast.parse(f"choose({arguments})", mode="eval").body
    site = path_provenance._Site(
        unit, unit.module, call, call.args, call.keywords, bound_receiver, "call"
    )
    names = ["self", "a", "b", "c", "d", "items", "qq", "flag", "attrs"]
    expected = {
        name: path_provenance._Project.bind_argument(project, fn, site, name)
        for name in names
    }
    token = path_provenance._SELECT_UNTRUSTED_CHAINS.set(
        lambda paths, limit: list(paths)[:limit]
    )
    try:
        assert {
            name: project.bind_argument(fn, site, name) for name in names
        } == expected
    finally:
        path_provenance._SELECT_UNTRUSTED_CHAINS.reset(token)
