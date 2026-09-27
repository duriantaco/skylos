from pathlib import Path

import pytest

from skylos.rules.danger.danger import scan_ctx


def _write(tmp_path: Path, name, code):
    p = tmp_path / name
    p.write_text(code, encoding="utf-8")
    return p


def _rule_ids(findings):
    return {f["rule_id"] for f in findings}


def _scan_one(tmp_path: Path, name, code):
    file_path = _write(tmp_path, name, code)
    return scan_ctx(tmp_path, [file_path])


def test_open_tainted_flags(tmp_path):
    code = (
        "@app.get('/files')\n"
        "def f(p):\n"
        "    with open(p, 'r', encoding='utf-8', errors='ignore') as fh:\n"
        "        fh.read()\n"
    )
    out = _scan_one(tmp_path, "pt_open.py", code)
    assert "SKY-D215" in _rule_ids(out)


def test_os_remove_tainted_flags(tmp_path):
    code = "import os\n@app.post('/rm')\ndef f(p):\n    os.remove(p)\n"
    out = _scan_one(tmp_path, "pt_os.py", code)
    assert "SKY-D215" in _rule_ids(out)


def test_shutil_rmtree_keyword_path_matches_positional_sink(tmp_path):
    code = """
import shutil
from pathlib import Path

@app.post("/a")
def positional_argument(destination: str) -> None:
    destination_path = Path(destination)
    shutil.rmtree(destination_path)

@app.post("/b")
def keyword_argument(destination: str) -> None:
    destination_path = Path(destination)
    shutil.rmtree(path=destination_path)
"""

    out = _scan_one(tmp_path, "pt_rmtree_keyword.py", code)
    symbols = {
        finding["symbol"]
        for finding in out
        if finding.get("rule_id") == "SKY-D215"
    }

    assert {"positional_argument", "keyword_argument"} <= symbols


@pytest.mark.parametrize(
    "call",
    [
        "open(file=path, mode='r')",
        "os.open(path=path, flags=os.O_RDONLY)",
        "os.unlink(path=path)",
        "os.remove(path=path)",
        "os.mkdir(path=path)",
        "os.rmdir(path=path)",
        "os.makedirs(name=path)",
        "shutil.copy(src=path, dst='fixed')",
        "shutil.copy2(src=path, dst='fixed')",
        "shutil.copytree(src=path, dst='fixed')",
        "shutil.move(src=path, dst='fixed')",
        "shutil.rmtree(path=path)",
    ],
)
def test_keyword_bound_first_path_argument_flags(tmp_path, call):
    code = f"""
import os
import shutil

@app.post("/x")
def vulnerable(path):
    {call}
"""

    out = _scan_one(tmp_path, "pt_keyword_path.py", code)

    assert "SKY-D215" in _rule_ids(out)


def test_os_open_keyword_flags_preserve_symlink_write_classification(tmp_path):
    code = """
import os

@app.post("/x")
def vulnerable(path):
    os.open(path=path, flags=os.O_WRONLY)
"""

    out = _scan_one(tmp_path, "pt_os_open_keyword_flags.py", code)
    rule_ids = _rule_ids(out)

    assert "SKY-D215" in rule_ids
    assert "SKY-D324" in rule_ids
    assert "SKY-D325" not in rule_ids


def test_tainted_non_path_keyword_does_not_flag_literal_rmtree_path(tmp_path):
    code = """
import shutil

@app.post("/x")
def cleanup(onerror):
    shutil.rmtree(path="/srv/cache", onerror=onerror)
"""

    out = _scan_one(tmp_path, "pt_rmtree_non_path_keyword.py", code)

    assert "SKY-D215" not in _rule_ids(out)


def test_open_constant_ok(tmp_path):
    code = "def f():\n    open('README.md', 'r')\n"
    out = _scan_one(tmp_path, "pt_ok.py", code)
    assert "SKY-D215" not in _rule_ids(out)


def test_pathlib_read_text_tainted_join_flags(tmp_path):
    code = (
        "from pathlib import Path\n"
        "BASE = Path('/srv/uploads')\n"
        "@app.get('/f')\n"
        "def f(name):\n"
        "    return (BASE / name).read_text(encoding='utf-8')\n"
    )
    out = _scan_one(tmp_path, "pt_pathlib_read.py", code)
    assert "SKY-D215" in _rule_ids(out)


def test_pathlib_name_projection_sanitizes_path_join(tmp_path):
    code = (
        "from pathlib import Path\n"
        "BASE = Path('/srv/uploads')\n"
        "@app.get('/f')\n"
        "def f(raw):\n"
        "    name = Path(raw).name\n"
        "    return (BASE / name).read_text(encoding='utf-8')\n"
    )
    out = _scan_one(tmp_path, "pt_pathlib_name_safe.py", code)
    assert "SKY-D215" not in _rule_ids(out)


def test_string_replace_on_tainted_value_is_not_path_sink(tmp_path):
    code = "def f(raw):\n    return raw.replace('x', 'y')\n"
    out = _scan_one(tmp_path, "pt_string_replace_safe.py", code)
    assert "SKY-D215" not in _rule_ids(out)


def test_path_like_global_shadowed_by_string_assignment(tmp_path):
    code = (
        "from pathlib import Path\n"
        "p = Path('/srv/uploads')\n"
        "def f(raw):\n"
        "    p = raw\n"
        "    return p.replace('x', 'y')\n"
    )
    out = _scan_one(tmp_path, "pt_path_like_shadow_assign.py", code)
    assert "SKY-D215" not in _rule_ids(out)


def test_path_like_global_shadowed_by_parameter(tmp_path):
    code = (
        "from pathlib import Path\n"
        "p = Path('/srv/uploads')\n"
        "def f(p):\n"
        "    return p.replace('x', 'y')\n"
    )
    out = _scan_one(tmp_path, "pt_path_like_shadow_param.py", code)
    assert "SKY-D215" not in _rule_ids(out)


# --- precision: paths that no remote party controls (agent-pr-bench FPs) ----


def _path_rules(findings):
    return {
        f["rule_id"]
        for f in findings
        if f["rule_id"] in {"SKY-D215", "SKY-D324", "SKY-D325"}
    }


def test_helper_parameter_path_without_known_caller_remains_reported(tmp_path):
    # A helper can also be called by a route in another module. Its bare
    # parameter does not prove that the caller is the program operator.
    code = """
import json
from pathlib import Path

class BatchParser:
    @staticmethod
    def _manifest_path(output_dir: str) -> Path:
        return Path(output_dir) / ".manifest.json"

    def load(self, output_dir: str):
        manifest_path = self._manifest_path(output_dir)
        return json.loads(manifest_path.read_text(encoding="utf-8"))

    def process(self, output_dir: str):
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _compute_digest(file_path: str) -> str:
        with Path(file_path).open("rb") as fh:
            return fh.read()
"""
    out = _scan_one(tmp_path, "batch_parser.py", code)
    assert {"SKY-D215", "SKY-D325"} <= _path_rules(out)


def test_unproven_cache_path_parameters_remain_reported(tmp_path):
    code = """
import json
from pathlib import Path

CACHE_DIR = Path(".cache/asr")

def cache_key(media_file):
    with open(media_file, "rb") as source:
        return source.read()

def read_result(key, part):
    return json.loads((CACHE_DIR / key / f"{part}.json").read_text(encoding="utf-8"))

def write_result(key, part, data):
    directory = CACHE_DIR / key
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{part}.json").write_text(data)
"""
    out = _scan_one(tmp_path, "transcription_cache.py", code)
    assert {"SKY-D215", "SKY-D324", "SKY-D325"} <= _path_rules(out)


def test_direct_cli_and_repo_root_paths_are_not_reported(tmp_path):
    code = """
import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def render_notes(root: Path, tag: str) -> str:
    return (root / "plugin.json").read_text(encoding="utf-8")

def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))

def published_dirs():
    return [p for p in (ROOT / "skills").iterdir() if (p / "SKILL.md").exists()]

def audit(path: Path) -> int:
    return len(path.read_text(encoding="utf-8"))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    args = parser.parse_args()
    audit(Path(args.path))
    open(args.path).read()
    open(sys.argv[1]).read()
    open(os.environ["CONFIG_PATH"]).read()
    for name in os.listdir(ROOT):
        (ROOT / name).read_text()
"""
    out = _scan_one(tmp_path, "prepare_release.py", code)
    # Direct argv/environment and directory-listing paths are operator owned.
    assert not {
        f["symbol"] for f in out if f["rule_id"] in {"SKY-D215", "SKY-D324", "SKY-D325"}
    } & {"main", "published_dirs"}
    # These generic helpers have no proof about other modules' callers.
    assert {"render_notes", "load_json", "audit"} <= {
        f["symbol"] for f in out if f["rule_id"] == "SKY-D325"
    }


def test_click_cli_parameter_path_is_not_reported(tmp_path):
    code = """
import click

@click.command()
@click.argument("src")
def cli(src):
    with open(src, "w") as fh:
        fh.write("x")
"""
    out = _scan_one(tmp_path, "cli_tool.py", code)
    assert _path_rules(out) == set()


def test_remote_bot_command_path_is_reported(tmp_path):
    code = """
from pathlib import Path

BASE = Path("/srv/uploads")

@bot.command()
async def save(name):
    (BASE / name).write_text("x")
"""
    out = _scan_one(tmp_path, "bot.py", code)
    assert {"SKY-D215", "SKY-D324"} <= _path_rules(out)
    traversal = next(f for f in out if f["rule_id"] == "SKY-D215")
    assert traversal["metadata"]["security_evidence"]["source"].startswith(
        "route parameter"
    )


@pytest.mark.parametrize(
    "name", ["tests/test_batch.py", "tests/helpers.py", "conftest.py", "x_test.py"]
)
def test_remote_route_in_test_named_file_remains_reported(tmp_path, name):
    code = """
from pathlib import Path

@app.get("/f")
def handler(p):
    Path(p).read_text()
    Path(p).write_text("x")
    open(p, "w").write("y")
"""
    target = tmp_path / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(code, encoding="utf-8")
    out = scan_ctx(tmp_path, [target])
    assert {"SKY-D215", "SKY-D324", "SKY-D325"} <= _path_rules(out)


def test_proven_pytest_fixture_path_in_tests_dir_is_not_reported(tmp_path):
    code = """
from pathlib import Path
import pytest

class FakeParser:
    def parse_document(self, file_path, output_dir):
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        return Path(file_path).read_text()

@pytest.fixture
def seeded(tmp_path):
    doc = tmp_path / "a.txt"
    doc.write_text("alpha")
"""
    target = tmp_path / "tests" / "testbatch_incremental.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(code, encoding="utf-8")
    out = scan_ctx(tmp_path, [target])
    assert not [
        f
        for f in out
        if f["symbol"] == "seeded"
        and f["rule_id"] in {"SKY-D215", "SKY-D324", "SKY-D325"}
    ]
    assert {"SKY-D215", "SKY-D325"} <= {
        f["rule_id"] for f in out if f["symbol"] == "parse_document"
    }


# --- recall: untrusted sources still reach the path rules -------------------


def test_flask_request_arg_to_open_flags_traversal_and_symlink_read(tmp_path):
    code = """
from flask import request

def download():
    name = request.args.get("name")
    with open(f"/srv/files/{name}") as fh:
        return fh.read()
"""
    out = _scan_one(tmp_path, "views.py", code)
    assert {"SKY-D215", "SKY-D325"} <= _rule_ids(out)
    finding = next(f for f in out if f["rule_id"] == "SKY-D215")
    assert finding["metadata"]["security_evidence"]["source"].startswith(
        "request data"
    )


def test_route_parameter_write_flags_symlink_write(tmp_path):
    code = """
from pathlib import Path

UPLOADS = Path("/srv/uploads")

@app.post("/upload/{name}")
def upload(name: str, body: bytes):
    (UPLOADS / name).write_bytes(body)
"""
    out = _scan_one(tmp_path, "upload.py", code)
    assert {"SKY-D215", "SKY-D324"} <= _rule_ids(out)


def test_uploaded_filename_flags_traversal(tmp_path):
    code = """
import os
from fastapi import UploadFile

@router.post("/upload")
async def upload(file: UploadFile):
    dest = os.path.join("/srv/uploads", file.filename)
    with open(dest, "wb") as out:
        out.write(await file.read())
"""
    out = _scan_one(tmp_path, "upload_api.py", code)
    assert {"SKY-D215", "SKY-D324"} <= _rule_ids(out)


def test_mcp_tool_argument_read_flags_traversal(tmp_path):
    code = """
@mcp.tool()
def read_file(path: str) -> str:
    with open(path) as fh:
        return fh.read()
"""
    out = _scan_one(tmp_path, "server.py", code)
    assert {"SKY-D215", "SKY-D325"} <= _rule_ids(out)


def test_contained_route_path_is_not_traversal(tmp_path):
    code = """
from pathlib import Path

BASE = Path("/srv/files").resolve()

@app.get("/f")
def read(name: str):
    target = (BASE / name).resolve()
    if not target.is_relative_to(BASE):
        raise ValueError("outside")
    return open(target).read()
"""
    out = _scan_one(tmp_path, "contained.py", code)
    assert "SKY-D215" not in _rule_ids(out)


def test_route_path_forwarded_to_helpers_keeps_remote_source(tmp_path):
    code = """
from pathlib import Path

BASE = Path("/srv/files")

def load(name):
    return (BASE / name).read_text()

def forward(name):
    return load(name)

def save(name, data):
    (BASE / name).write_text(data)

@app.get("/{name}")
def download(name):
    return forward(name)

@app.post("/{name}")
def upload(name, data):
    save(name, data)
"""
    out = _scan_one(tmp_path, "service.py", code)
    by_symbol = {
        symbol: {f["rule_id"] for f in out if f.get("symbol") == symbol}
        for symbol in ("load", "save")
    }
    assert {"SKY-D215", "SKY-D325"} <= by_symbol["load"]
    assert {"SKY-D215", "SKY-D324"} <= by_symbol["save"]
    for finding in out:
        if finding.get("symbol") in by_symbol and finding["rule_id"] == "SKY-D215":
            assert "route parameter" in finding["metadata"]["security_evidence"]["source"]


@pytest.mark.parametrize("local_cli_caller", [False, True])
def test_cross_module_route_to_path_helper_remains_reported(tmp_path, local_cli_caller):
    # The path checker sees storage.py independently. A same-file CLI call to
    # the helper must not hide its separate use by a remote web route.
    cli_caller = (
        """
def cli():
    read_file(sys.argv[1])
    write_file(sys.argv[1], b"data")
"""
        if local_cli_caller
        else ""
    )
    storage = _write(
        tmp_path,
        "storage.py",
        """import sys
from pathlib import Path

BASE = Path("/srv/uploads")

def read_file(name):
    return (BASE / name).read_text()

def write_file(name, body):
    (BASE / name).write_bytes(body)
"""
        + cli_caller,
    )
    service = _write(
        tmp_path,
        "service.py",
        """from flask import Flask
from storage import read_file, write_file

app = Flask(__name__)

@app.get("/download/<name>")
def download(name):
    return read_file(name)

@app.post("/upload/<name>")
def upload(name):
    write_file(name, b"data")
""",
    )
    out = scan_ctx(tmp_path, [service, storage])
    by_symbol = {
        symbol: {f["rule_id"] for f in out if f.get("symbol") == symbol}
        for symbol in ("read_file", "write_file")
    }
    assert {"SKY-D215", "SKY-D325"} <= by_symbol["read_file"]
    assert {"SKY-D215", "SKY-D324"} <= by_symbol["write_file"]


def test_nested_route_helpers_keep_parameter_and_closure_sources(tmp_path):
    code = """
from pathlib import Path

BASE = Path("/srv/files")

@app.get("/{name}")
def download(name):
    def load(path):
        return (BASE / path).read_text()
    return load(name)

@app.post("/{name}")
def upload(name, data):
    def save():
        (BASE / name).write_text(data)
    save()
"""
    out = _scan_one(tmp_path, "service.py", code)
    by_symbol = {
        symbol: {f["rule_id"] for f in out if f.get("symbol") == symbol}
        for symbol in ("load", "save")
    }
    assert {"SKY-D215", "SKY-D325"} <= by_symbol["load"]
    assert {"SKY-D215", "SKY-D324"} <= by_symbol["save"]


def test_safe_literal_allowlist_forwarded_to_open_world_helper_is_reported(tmp_path):
    code = """
from pathlib import Path

BASE = Path("/srv/files")
ALLOWED = {"a": "a.txt", "b": "b.txt"}

def load(path):
    return (BASE / path).read_text()

@app.get("/{name}")
def download(name):
    return load(ALLOWED[name])
"""
    out = _scan_one(tmp_path, "service.py", code)
    helper_rules = {f["rule_id"] for f in out if f.get("symbol") == "load"}
    # A caller in another module may bypass the local allowlist.
    assert "SKY-D215" in helper_rules
    assert "SKY-D325" in helper_rules


def test_unsafe_helper_caller_still_flags_when_another_caller_uses_allowlist(tmp_path):
    code = """
from pathlib import Path

BASE = Path("/srv/files")
ALLOWED = {"a": "a.txt"}

def load(path):
    return (BASE / path).read_text()

@app.get("/safe/{name}")
def safe(name):
    return load(ALLOWED[name])

@app.get("/unsafe/{name}")
def unsafe(name):
    return load(name)
"""
    out = _scan_one(tmp_path, "service.py", code)
    finding = next(
        f for f in out if f["rule_id"] == "SKY-D215" and f.get("symbol") == "load"
    )
    assert any(
        "`unsafe`" in source
        for source in finding["metadata"]["security_evidence"]["sources"]
    )


@pytest.mark.parametrize(
    "mutation",
    ['ALLOWED["a"] = "../secret"', 'alias = ALLOWED\nalias["a"] = "../secret"'],
)
def test_mutated_literal_allowlist_does_not_suppress_traversal(tmp_path, mutation):
    code = """
from pathlib import Path

BASE = Path("/srv/files")
ALLOWED = {"a": "a.txt"}
__MUTATION__

def load(path):
    return (BASE / path).read_text()

@app.get("/{name}")
def download(name):
    return load(ALLOWED[name])
""".replace("__MUTATION__", mutation)
    out = _scan_one(tmp_path, "service.py", code)
    assert "SKY-D215" in {
        f["rule_id"] for f in out if f.get("symbol") == "load"
    }


def test_indirect_mutation_of_literal_map_does_not_hide_traversal(tmp_path):
    code = """
from pathlib import Path

BASE = Path("/srv/files")
ALLOWED = {"a": "a.txt"}
dict.__setitem__(ALLOWED, "a", "../secret")

@app.get("/{name}")
def download(name):
    return (BASE / ALLOWED[name]).read_text()
"""
    out = _scan_one(tmp_path, "service.py", code)
    assert {"SKY-D215", "SKY-D325"} <= _path_rules(out)


def test_imported_mutable_path_map_does_not_hide_traversal(tmp_path):
    mapping = _write(
        tmp_path,
        "mapping.py",
        "ALLOWED = {'a': 'a.txt'}\n",
    )
    service = _write(
        tmp_path,
        "service.py",
        """from pathlib import Path
from mapping import ALLOWED

BASE = Path("/srv/files")

@app.get("/{name}")
def download(name):
    return (BASE / ALLOWED[name]).read_text()
""",
    )
    out = scan_ctx(tmp_path, [mapping, service])
    assert {"SKY-D215", "SKY-D325"} <= {
        f["rule_id"] for f in out if Path(f["file"]).name == "service.py"
    }


def test_contained_path_joined_with_new_request_value_is_traversal(tmp_path):
    code = """
from pathlib import Path
from flask import request

BASE = Path("/srv/files")

@app.get("/{name}")
def download(name):
    safe = (BASE / name).resolve()
    if not safe.is_relative_to(BASE):
        raise ValueError("outside")
    return (safe / request.args["other"]).read_text()
"""
    out = _scan_one(tmp_path, "service.py", code)
    assert "SKY-D215" in _rule_ids(out)


def test_request_override_of_operator_default_remains_remote_path(tmp_path):
    code = """
import os
from pathlib import Path
from flask import request

@app.get("/download")
def download():
    path = os.getenv("DEFAULT_PATH")
    if request.args.get("path"):
        path = request.args["path"]
    return Path(path).read_text()

@app.post("/upload")
def upload(data):
    path = os.getenv("DEFAULT_PATH")
    if request.args.get("path"):
        path = request.args["path"]
    Path(path).write_text(data)
"""
    out = _scan_one(tmp_path, "service.py", code)
    by_symbol = {
        symbol: {f["rule_id"] for f in out if f.get("symbol") == symbol}
        for symbol in ("download", "upload")
    }
    assert {"SKY-D215", "SKY-D325"} <= by_symbol["download"]
    assert {"SKY-D215", "SKY-D324"} <= by_symbol["upload"]
    for finding in out:
        if finding["rule_id"] == "SKY-D215":
            assert "request data" in finding["metadata"]["security_evidence"]["source"]
