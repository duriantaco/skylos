"""A sink finding needs a source: controls for claims that had none."""

from __future__ import annotations

import ast
import json

import pytest

from skylos.rules.danger.danger import scan_ctx
from skylos.rules.danger.danger_fs.path_flow import scan as scan_paths
from skylos.visitors.languages.rust import scan_rust_file
from skylos.visitors.languages.typescript import scan_typescript_file


def _rust_lines(tmp_path, code, name="lib.rs", rule="SKY-D215"):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(code, encoding="utf-8")
    return sorted(
        f["line"] for f in scan_rust_file(str(path), {})[7] if f["rule_id"] == rule
    )


def _ts_lines(tmp_path, rule, code, name="module.ts"):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(code, encoding="utf-8")
    return sorted(
        f["line"] for f in scan_typescript_file(str(path))[7] if f["rule_id"] == rule
    )


def _py_lines(tmp_path, rule, code, name="app.py"):
    path = tmp_path / name
    path.write_text(code, encoding="utf-8")
    return sorted(f["line"] for f in scan_ctx(tmp_path, [path]) if f["rule_id"] == rule)


RUST_HELPER = """use std::fs;
use std::path::{Path, PathBuf};

fn read_optional(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_default()
}

pub fn load_state() -> Vec<u8> {
    read_optional(&PathBuf::from("/var/lib/app").join("state.json"))
}
"""


def test_rust_private_helper_with_only_fixed_callers_has_no_source(tmp_path):
    assert _rust_lines(tmp_path, RUST_HELPER) == []


FORWARDED = """pub fn load_named(file_name: &str) -> Vec<u8> {
    read_optional(Path::new(file_name))
}
"""
COMMAND_LINE = """pub fn load_first() -> Vec<u8> {
    let first = std::env::args().nth(1).unwrap();
    read_optional(Path::new(&first))
}
"""
AS_VALUE = """pub fn load_all(names: &[PathBuf]) -> Vec<Vec<u8>> {
    names.iter().map(|p| p.as_path()).map(read_optional).collect()
}
"""
IN_MACRO = """pub fn load_listed() -> Vec<Vec<u8>> {
    vec![read_optional(Path::new("/var/lib/app/a.json"))]
}
pub fn load_other(file_name: &str) -> Vec<Vec<u8>> {
    vec![read_optional(Path::new(file_name))]
}
"""


@pytest.mark.parametrize(
    "extra",
    [FORWARDED, COMMAND_LINE, AS_VALUE, IN_MACRO],
    ids=["forwarded-parameter", "command-line", "passed-as-value", "macro-call"],
)
def test_rust_private_helper_with_an_unproven_caller_still_reports(tmp_path, extra):
    assert _rust_lines(tmp_path, RUST_HELPER + extra) == [5]


def test_rust_private_helper_called_from_a_child_module_file_still_reports(tmp_path):
    parent = RUST_HELPER.replace("use std::fs;", "mod remote;\nmod keys;\nuse std::fs;")
    caller = """use std::path::Path;

pub fn load_named(file_name: &str) -> Vec<u8> {
    super::read_optional(Path::new(file_name))
}
"""
    (tmp_path / "store").mkdir()
    (tmp_path / "cache").mkdir()
    (tmp_path / "store" / "remote.rs").write_text(caller)
    (tmp_path / "store" / "keys.rs").write_text("pub fn key() -> u8 { 1 }\n")
    (tmp_path / "cache" / "remote.rs").write_text("pub fn other() -> u8 { 2 }\n")
    (tmp_path / "cache" / "keys.rs").write_text("pub fn key() -> u8 { 1 }\n")
    assert _rust_lines(tmp_path, parent, "store/mod.rs") == [7]
    assert _rust_lines(tmp_path, parent, "cache/mod.rs") == []


def test_rust_trait_method_and_registered_command_keep_unknown_callers(tmp_path):
    code = """use std::fs;
use std::path::Path;

pub trait Loader {
    fn load(&self, path: &Path) -> Vec<u8>;
}

pub struct Disk;

impl Loader for Disk {
    fn load(&self, path: &Path) -> Vec<u8> {
        fs::read(path).unwrap_or_default()
    }
}

#[tauri::command]
fn read_note(path: String) -> String {
    fs::read_to_string(path).unwrap()
}

pub fn defaults(disk: &Disk) -> (Vec<u8>, String) {
    (
        disk.load(Path::new("/var/lib/app/defaults.json")),
        read_note(String::from("/var/lib/app/welcome.txt")),
    )
}
"""
    assert _rust_lines(tmp_path, code) == [12, 18]


def test_rust_test_only_code_drops_the_name_hypothesis_not_real_sources(tmp_path):
    code = """use std::fs;

pub fn export(path: &str, data: &[u8]) {
    fs::write(path, data).unwrap();
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    fn cleanup(dir: &Path) {
        fs::remove_dir_all(dir).ok();
    }

    fn fixture_from_environment() -> Vec<u8> {
        let chosen = std::env::var("FIXTURE_FILE").unwrap();
        fs::read(chosen).unwrap()
    }
}
"""
    assert _rust_lines(tmp_path, code) == [4, 18]


def test_rust_file_declared_as_a_test_module_is_test_only(tmp_path):
    code = """use std::fs;
use std::path::Path;

pub fn walk(dir: &Path) -> Vec<u8> {
    fs::read(dir.join("ids.json")).unwrap()
}
"""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "lib.rs").write_text(
        "#[cfg(test)]\nmod storage_tests;\nmod storage_checks;\n"
        "#[cfg(not(test))]\nmod storage_live;\n"
    )
    assert _rust_lines(tmp_path, code, "src/storage_tests.rs") == []
    assert _rust_lines(tmp_path, code, "src/storage_checks.rs") == [5]
    assert _rust_lines(tmp_path, code, "src/storage_live.rs") == [5]


def test_rust_build_script_trusts_only_variables_cargo_sets(tmp_path):
    script = """use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("table.rs");
    fs::write(out, "x").unwrap();
    let chosen = PathBuf::from(env::var("GENERATED_TARGET").unwrap());
    fs::write(chosen, "x").unwrap();
}
"""
    (tmp_path / "Cargo.toml").write_text('[package]\nname = "fixture"\n')
    assert _rust_lines(tmp_path, script, "build.rs") == [9]
    assert _rust_lines(tmp_path, script, "src/build.rs") == [7, 9]


def test_rust_request_extractor_is_a_source_and_a_local_lookalike_is_not(tmp_path):
    handler = """use axum::extract::Path;
use std::fs;

async fn download(Path(name): Path<String>) -> Vec<u8> {
    fs::read(format!("/srv/files/{}", name)).unwrap()
}
"""
    lookalike = handler.replace("use axum::extract::Path;", "use crate::model::Path;")
    assert _rust_lines(tmp_path, handler) == [5]
    assert _rust_lines(tmp_path, lookalike, "other.rs") == []


def test_rust_target_is_not_an_input_like_name_but_arg_is(tmp_path):
    code = """use std::fs;
use std::path::Path;

pub fn sync(target: &Path, data: &[u8]) {
    fs::write(target, data).unwrap();
}

pub fn open(cli_args: Vec<String>) -> Vec<u8> {
    fs::read(&cli_args[1]).unwrap()
}
"""
    assert _rust_lines(tmp_path, code) == [9]


def test_axios_error_guards_are_not_requests(tmp_path):
    code = """import axios from "axios";
export async function load(req: any) {
  try {
    return await axios.get(req.query.target);
  } catch (error) {
    if (axios.isAxiosError(error) || axios.isCancel(error)) {
      return null;
    }
    return axios.create(req.body.config);
  }
}
"""
    assert _ts_lines(tmp_path, "SKY-D216", code) == [4, 9]


def test_bundled_asset_url_import_is_constant_and_other_imports_are_not(tmp_path):
    code = """import wasmUrl from "./codec.wasm?url";
import otherUrl from "./runtime-config";
import { remoteUrl } from "./settings";
export const a = () => fetch(wasmUrl);
export const b = () => fetch(otherUrl);
export const c = () => fetch(remoteUrl);
"""
    assert _ts_lines(tmp_path, "SKY-D216", code) == [5, 6]


FETCH = "export async function load(target: string) {\n  return fetch(target);\n}\n"


@pytest.mark.parametrize(
    "dependencies, code, expected",
    [
        ({"react-native": "0.74.0"}, FETCH, []),
        ({"vue": "^3.4.0"}, FETCH, []),
        ({"react-native": "0.74.0", "fastify": "^4.0.0"}, FETCH, [2]),
        ({"vue": "^3.4.0", "express": "^4.19.0"}, FETCH, [2]),
        ({"vue": "^3.4.0"}, 'import { readFileSync } from "node:fs";\n' + FETCH, [3]),
        ({"lodash": "^4.0.0"}, FETCH, [2]),
    ],
    ids=[
        "device-package",
        "browser-package",
        "device-with-server",
        "browser-with-server",
        "node-module-in-browser-package",
        "no-runtime-declared",
    ],
)
def test_fetch_needs_a_server_network_position(tmp_path, dependencies, code, expected):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": dependencies}))
    assert _ts_lines(tmp_path, "SKY-D216", code, "src/api.ts") == expected


def test_client_directive_must_be_the_module_directive(tmp_path):
    directive = '"use client";\n' + FETCH
    value = 'const mode = "use client";\n' + FETCH
    assert _ts_lines(tmp_path, "SKY-D216", directive, "app/page.tsx") == []
    assert _ts_lines(tmp_path, "SKY-D216", value, "app/notes.tsx") == [3]


def test_presence_check_against_global_undefined_is_not_a_secret_compare(tmp_path):
    presence = """export function options(auth: { apiKey?: string }, req: any) {
  const extra = auth.apiKey === undefined ? {} : { apiKey: auth.apiKey };
  return req.query.token === process.env.WEBHOOK_TOKEN ? extra : null;
}
"""
    shadowed = """export function compare(token: string, undefined: string) {
  return token === undefined;
}
"""
    assert _ts_lines(tmp_path, "SKY-D253", presence) == [3]
    assert _ts_lines(tmp_path, "SKY-D253", shadowed, "shadowed.ts") == [2]


def test_mapping_get_is_a_lookup_unless_the_receiver_can_be_a_client(tmp_path):
    code = """import httpx
from flask import Flask, request

app = Flask(__name__)
_session_cache = {}


class Relay:
    def __init__(self, live):
        self._session_replacements = {}
        self._client_pool = {}
        if live:
            self._client_pool = httpx.Client()

    def send(self):
        target = request.args["target"]
        self._session_replacements.get(target)
        _session_cache.get(target)
        return self._client_pool.get(target)
"""
    assert _py_lines(tmp_path, "SKY-D216", code) == [19]


def test_logged_value_must_still_carry_the_credential(tmp_path):
    code = """import getpass
import os


def mask(key):
    return key[:6] + "..." + key[-4:]


def redact(key):
    return key.replace("-", "")


def store():
    value = getpass.getpass("API key (hidden): ").strip()
    print(f"stored as {mask(value)}")
    print(f"masked {mask(value)} raw {value}")
    print(redact(value))
    print(value[1:])
    tokens = os.environ["API_TOKEN"].split(",")
    print(tokens[:2])
"""
    assert _py_lines(tmp_path, "SKY-D251", code) == [16, 17, 18, 20]


def test_key_typed_on_one_branch_is_still_a_string_and_a_token_list_is_not(tmp_path):
    code = """import getpass
import os
from pathlib import Path


def mask(key):
    return key[:6] + "..." + key[-4:]


def store(from_file, many):
    if from_file:
        value = Path(from_file).read_text().strip()
    else:
        value = getpass.getpass("API key (hidden): ").strip()
    print(f"stored as {mask(value)}")
    if many:
        tokens = os.environ["API_TOKEN"].split(",")
    else:
        tokens = getpass.getpass("API key (hidden): ")
    print(tokens[:2])
"""
    assert _py_lines(tmp_path, "SKY-D251", code) == [20]


def test_helper_summary_does_not_add_a_key_the_helper_reads_itself(tmp_path):
    code = """import json
import os


class PanelClient:
    def __init__(self, panel, key):
        self.panel = panel
        self.key = key

    def sites(self):
        return {"panel": self.panel, "sites": []}


def build_client():
    return PanelClient("https://panel.example", os.environ.get("PANEL_API_KEY"))


def pretty(value):
    return json.dumps(value, indent=2)


def main():
    result = build_client().sites()
    print(pretty(result))
    key = os.environ.get("PANEL_API_KEY")
    print(pretty(key))
"""
    assert _py_lines(tmp_path, "SKY-D251", code) == [26]


def test_dynamic_import_from_a_fixed_table_is_an_allowlist(tmp_path):
    code = """import importlib
import sys

COMMANDS = {"build": "tool.commands.build"}
PLUGINS = {"build": "tool.commands.build"}


def register(name, module):
    PLUGINS[name] = module


def main():
    importlib.import_module(COMMANDS[sys.argv[1]])
    importlib.import_module(PLUGINS[sys.argv[1]])
    importlib.import_module(COMMANDS.get(sys.argv[1], sys.argv[1]))
"""
    assert _py_lines(tmp_path, "SKY-D357", code) == [14, 15]


def test_filesystem_path_reference_downloads_nothing(tmp_path):
    code = """from pathlib import Path

from transformers import AutoModel


def local(checkpoint_dir: Path):
    return AutoModel.from_pretrained(str(checkpoint_dir))


def named(model_dir: str):
    return AutoModel.from_pretrained(model_dir)


def either(model: str | Path):
    return AutoModel.from_pretrained(model)
"""
    assert _py_lines(tmp_path, "SKY-D345", code) == [11, 15]


PATH_ROUTES = """import os
import re

from fastapi import APIRouter, HTTPException

router = APIRouter()
NAME_RE = re.compile(r"^[a-zA-Z0-9_-]{1,50}$")
PREFIX_RE = re.compile(r"[a-zA-Z0-9_-]+")
LINES_RE = re.compile(r"^[a-z]+$", re.M)


def _validate_name(name: str) -> str:
    trimmed = name.strip()
    if not trimmed or not NAME_RE.match(trimmed):
        raise HTTPException(status_code=400)
    return trimmed


@router.delete("/a/{name}")
async def validated(name: str):
    os.remove(os.path.join("state", _validate_name(name) + ".json"))


@router.delete("/b/{name}")
async def prefix_only(name: str):
    if not PREFIX_RE.match(name):
        raise HTTPException(status_code=400)
    os.remove(os.path.join("state", name))


@router.delete("/c/{name}")
async def multiline(name: str):
    if not LINES_RE.match(name):
        raise HTTPException(status_code=400)
    os.remove(os.path.join("state", name))


@router.delete("/d/{name}")
async def one_branch(name: str, strict: bool = False):
    if strict:
        if not NAME_RE.fullmatch(name):
            raise HTTPException(status_code=400)
    os.remove(os.path.join("state", name))


@router.delete("/e/{name}/{extra}")
async def second_segment(name: str, extra: str):
    if not NAME_RE.fullmatch(name):
        raise HTTPException(status_code=400)
    os.remove(os.path.join("state", name, extra))
"""


def test_full_match_on_filename_characters_clears_the_path_and_weak_checks_do_not(
    tmp_path,
):
    path = tmp_path / "app.py"
    path.write_text(PATH_ROUTES, encoding="utf-8")
    findings = []
    scan_paths(ast.parse(PATH_ROUTES), path, findings)
    lines = sorted(f["line"] for f in findings if f["rule_id"] == "SKY-D215")
    assert lines == [28, 35, 43, 50]


def test_mcp_constructor_host_counts_only_for_a_network_transport(tmp_path):
    code = """from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Tools", host="0.0.0.0", port=3005)
mcp.run(transport="{transport}")
"""
    exposed = code.replace("{transport}", "streamable-http")
    local = code.replace("{transport}", "stdio")
    assert _py_lines(tmp_path, "SKY-D243", exposed, "exposed.py") == [4]
    assert _py_lines(tmp_path, "SKY-D243", local, "local.py") == []
