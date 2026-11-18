"""Content-addressed JSON caches for the incremental UML report."""
from __future__ import annotations

import gzip
import hashlib
import importlib
import json
import os
import platform
import tempfile
import time
from collections import Counter
from contextlib import contextmanager
from dataclasses import replace
from importlib import metadata
from pathlib import Path
from unittest.mock import patch

SCHEMA = 1
MAX_JSON_BYTES = 220_000_000


def digest(value):
    raw = value if isinstance(value, bytes) else json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


def stamp(path):
    value = path.stat()
    return [value.st_size, value.st_mtime_ns, value.st_ctime_ns, value.st_ino]


def read_json(path):
    try:
        if path.is_symlink():
            return None
        if path.suffix == ".gz":
            with gzip.open(path, "rb") as stream:
                raw = stream.read(MAX_JSON_BYTES + 1)
        else:
            with path.open("rb") as stream:
                raw = stream.read(MAX_JSON_BYTES + 1)
        if len(raw) > MAX_JSON_BYTES:
            return None
        return json.loads(raw)
    except (OSError, ValueError, EOFError, UnicodeError):
        return None


def atomic_write(path, raw):
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError(f"Refusing a symlinked report/cache path: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".uml-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_json(path, value, *, pretty=False):
    raw = json.dumps(value, ensure_ascii=False, indent=2 if pretty else None, separators=None if pretty else (",", ":")).encode()
    atomic_write(path, gzip.compress(raw, compresslevel=3, mtime=0) if path.suffix == ".gz" else raw)


def write_changed(path, value):
    raw = value.encode() if isinstance(value, str) else value
    if path.exists() and not path.is_symlink() and path.read_bytes() == raw:
        return False
    atomic_write(path, raw)
    return True


@contextmanager
def build_lock(directory):
    import fcntl
    if directory.is_symlink():
        raise ValueError(f"Refusing a symlinked cache directory: {directory}")
    directory.mkdir(parents=True, exist_ok=True)
    lock = directory / "build.lock"
    if lock.is_symlink():
        raise ValueError(f"Refusing a symlinked lock: {lock}")
    with lock.open("a+") as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("A UML build is already running; waiting to reuse its cache.", flush=True)
            fcntl.flock(stream, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


def runtime_key():
    packages = {}
    for name in ("networkx", "tree-sitter", "tree-sitter-typescript", "tree-sitter-go", "tree-sitter-java", "tree-sitter-rust", "tree-sitter-php", "pyyaml"):
        try:
            packages[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            packages[name] = None
    return digest([platform.python_version(), packages])


class ReportCache:
    """Reuse source facts and stage outputs after checking their content keys."""
    def __init__(self, root, directory, *, force=False):
        self.root, self.directory, self.force = Path(root), Path(directory), force
        self.state_path = self.directory / "state.json"
        prior = read_json(self.state_path)
        self.prior = prior if isinstance(prior, dict) and prior.get("schema") == SCHEMA else {}
        self.previous_files = self.prior.get("inputs", {})
        self.inputs, self.records, self.trees = {}, {}, {}
        self.dirty_records = set()
        self.stats = Counter()
        self.started = time.monotonic()

    def fingerprint(self, path, *, key=None):
        path = Path(path)
        key = key or path.relative_to(self.root).as_posix()
        if not path.is_file():
            return None
        current = stamp(path)
        old = self.previous_files.get(key)
        if not self.force and isinstance(old, dict) and old.get("stat") == current:
            record = old
            self.stats["file_hashes_reused"] += 1
        else:
            raw = path.read_bytes()
            record = {"stat": current, "hash": digest(raw), "native_hash": digest(raw.decode("utf-8", "replace").encode())[:16]}
            self.stats["files_hashed"] += 1
        self.inputs[key] = record
        return record["hash"]

    def file(self, path):
        if path in self.records:
            return self.records[path]
        if path not in self.inputs:
            self.fingerprint(self.root / path)
        content_hash = self.inputs[path]["hash"]
        location = self.directory / "files" / (digest(path)[:24] + ".json.gz")
        record = read_json(location) if not self.force else None
        if not isinstance(record, dict) or record.get("schema") != SCHEMA or record.get("path") != path or record.get("hash") != content_hash or not isinstance(record.get("source"), str) or not isinstance(record.get("functions"), dict):
            raw = (self.root / path).read_bytes()
            if digest(raw) != content_hash:
                raise RuntimeError(f"Source changed during the build: {path}. Rerun the report.")
            # Preserve per-function records across edits to this file. Their own
            # body/import keys decide whether they can be reused.
            functions = record.get("functions", {}) if isinstance(record, dict) and record.get("schema") == SCHEMA and isinstance(record.get("functions"), dict) else {}
            record = {"schema": SCHEMA, "path": path, "hash": content_hash, "source": raw.decode("utf-8", "replace"), "functions": functions}
            self.dirty_records.add(path)
        self.records[path] = record
        return record

    def source(self, path):
        return self.file(path)["source"]

    def tree(self, path):
        import ast
        if path not in self.trees:
            self.trees[path] = ast.parse(self.source(path))
            self.stats["python_files_parsed"] += 1
        return self.trees[path]

    def changed(self, path):
        self.dirty_records.add(path)

    def blob(self, name, key, compute):
        path = self.directory / (name + ".json.gz")
        old = read_json(path) if not self.force else None
        if name == "native_graph":
            self.previous_graph = old.get("value") if isinstance(old, dict) else None
        if isinstance(old, dict) and old.get("schema") == SCHEMA and old.get("key") == key:
            self.stats[name + "_reused"] += 1
            return old["value"]
        self.stats[name + "_rebuilt"] += 1
        value = compute()
        write_json(path, {"schema": SCHEMA, "key": key, "value": value})
        return value

    def save_files(self):
        for path in list(self.dirty_records):
            self.flush_file(path)

    def flush_file(self, path):
        if path in self.dirty_records:
            location = self.directory / "files" / (digest(path)[:24] + ".json.gz")
            write_json(location, self.records[path])
            self.dirty_records.discard(path)

    def outputs_match(self, output):
        outputs = self.prior.get("outputs", {})
        if not outputs:
            return False
        for path, expected in outputs.items():
            full = output / path
            if not full.is_file() or full.is_symlink():
                return False
            if digest(full.read_bytes()) != expected:
                return False
        return True

    def save_state(self, signature, output, output_paths, native_key, engine_key, native_sources):
        self.save_files()
        outputs = {p: digest((output / p).read_bytes()) for p in output_paths}
        report_sources = {p: record["hash"] for p, record in self.inputs.items() if not p.startswith(("asset:", "tool:")) and p != "notes"}
        write_json(self.state_path, {"schema": SCHEMA, "signature": signature, "native_key": native_key, "engine_key": engine_key, "native_sources": native_sources, "report_sources": report_sources, "inputs": self.inputs, "outputs": outputs})

    def summary(self):
        return {**self.stats, "elapsed_seconds": round(time.monotonic() - self.started, 3)}


def capture_inputs(root, cache, *, scope=None):
    from skylos.graph.files import list_repo_files
    repo = list_repo_files(root)
    if scope is not None:
        paths = [path for path in repo.paths if path in scope and not (root / path).is_symlink()]
        repo = replace(repo, paths=paths)
    hashes = {p: cache.fingerprint(root / p) for p in repo.paths}
    controls = {}
    for path in [root / "pyproject.toml", *sorted((root / ".github/workflows").glob("*.y*ml"))]:
        rel = path.relative_to(root).as_posix()
        if (scope is None or rel in scope) and path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(root):
            controls[rel] = cache.fingerprint(path)
    return repo, hashes, controls


def native_graph(root, cache, repo, hashes, *, engine_key, reuse_project_cache=True):
    """Use the native parser with a report-owned cache and content validation."""
    builder = importlib.import_module("skylos.graph.build")
    key = digest([hashes, repo.not_mapped, engine_key, reuse_project_cache])
    prior_key = cache.prior.get("native_key")

    def compute():
        directory = cache.directory / "native"
        if directory.is_symlink():
            raise ValueError(f"Refusing a symlinked native cache: {directory}")
        directory.mkdir(parents=True, exist_ok=True)
        # Reuse the CLI's existing parse cache on the first report-cache build.
        if reuse_project_cache:
            import shutil
            for name in ("cache.json", "areas.json"):
                source, dest = root / ".skylos/graph" / name, directory / name
                if not dest.exists() and source.is_file() and not source.is_symlink():
                    shutil.copyfile(source, dest)
        load_cache = builder._load_cache

        def checked(directory):
            if cache.force or prior_key and cache.prior.get("engine_key") != engine_key:
                return {}
            found = load_cache(directory)
            # An edit can preserve size and mtime. Validate native records by
            # source content as well, rather than relying on those two fields.
            valid = {}
            for p, item in found.items():
                if p in hashes and item.get("record", {}).get("hash") == cache.inputs[p]["native_hash"]:
                    # A fresh CI checkout changes mtimes/inodes even when the
                    # content is identical. Advance the verified stat stamp so
                    # the native parser can reuse that file across runners.
                    valid[p] = {**item, "stat": cache.inputs[p]["stat"][:2]}
            return valid

        with (
            patch.object(builder, "list_repo_files", return_value=repo),
            patch.object(builder, "ensure_dir", lambda _root: directory),
            patch.object(builder, "_load_cache", checked),
        ):
            graph = builder.build_graph(root)
        cache.stats["native_files_parsed"] += graph["coverage"]["parsed"] - graph["coverage"]["reused"]
        cache.stats["native_files_reused"] += graph["coverage"]["reused"]
        return graph

    graph = cache.blob("native_graph", key, compute)
    graph["commit"], graph["dirty"] = repo.head, repo.dirty
    graph["root"] = str(root)
    graph["repo"] = root.name
    return graph, key


def affected_callers(previous, current, changed_ids):
    reverse = {}
    for graph in (previous or {}, current):
        for a, b, kind in graph.get("edges", []):
            if kind in {"calls", "creates"}:
                reverse.setdefault(b, set()).add(a)
    seen, pending = set(changed_ids), list(changed_ids)
    while pending:
        for caller in reverse.get(pending.pop(), ()):
            if caller not in seen:
                seen.add(caller)
                pending.append(caller)
    return seen - set(changed_ids)
