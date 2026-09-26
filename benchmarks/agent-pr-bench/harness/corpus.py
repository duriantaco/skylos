"""Corpus loading and workspace preparation.

Two kinds of workspaces are produced, both as Git checkouts so every tool sees
an ordinary repository:

* seeded cases: a pinned base commit with the case's edits applied to the
  working tree (uncommitted). The changed-line map is computed from the edit
  application itself, independent of any tool.
* real commits: a checkout of the agent commit; changed lines come from
  ``git diff -U0 <parent> <sha>``.
"""

from __future__ import annotations

import difflib
import json
import re
import shutil
import subprocess
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

BENCH_ROOT = Path(__file__).resolve().parents[1]
SEEDED_DIR = BENCH_ROOT / "corpus" / "seeded"
REAL_COMMITS = BENCH_ROOT / "corpus" / "real_commits.json"

# Files counted as source for "changed kLOC" and handed to per-file tools.
SOURCE_EXTENSIONS = {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
LOCATION_TOLERANCE = 3  # lines either side of a seeded defect location


class CorpusError(RuntimeError):
    pass


@dataclass
class DefectLocation:
    file: str
    start: int
    end: int

    def contains(self, file: str, line: int, tolerance: int = LOCATION_TOLERANCE) -> bool:
        return file == self.file and self.start - tolerance <= line <= self.end + tolerance


@dataclass
class Defect:
    id: str
    category: str
    subcategory: str | None
    description: str
    locations: list[DefectLocation]


@dataclass
class Workspace:
    """One unit of analysis: a checkout plus the lines the change touched."""

    id: str
    kind: str  # "seeded" | "real"
    language: str
    path: Path
    diff_base: str  # git ref the change is measured against
    changed_lines: dict[str, set[int]]  # repo-relative posix path -> new-side line numbers
    changed_files: list[str]  # files that exist after the change
    added_source_lines: int
    defects: list[Defect] = field(default_factory=list)
    clean: bool = False
    unparseable: bool = False
    meta: dict = field(default_factory=dict)

    @property
    def source_files(self) -> list[str]:
        return [f for f in self.changed_files if Path(f).suffix.lower() in SOURCE_EXTENSIONS]

    def in_scope(self, file: str, line: int) -> bool:
        if line in self.changed_lines.get(file, ()):
            return True
        return any(loc.contains(file, line) for d in self.defects for loc in d.locations)

    def to_json(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "language": self.language,
            "path": str(self.path),
            "diff_base": self.diff_base,
            "changed_lines": {k: sorted(v) for k, v in sorted(self.changed_lines.items())},
            "changed_files": self.changed_files,
            "added_source_lines": self.added_source_lines,
            "defects": [
                {
                    "id": d.id,
                    "category": d.category,
                    "subcategory": d.subcategory,
                    "description": d.description,
                    "locations": [vars(loc) for loc in d.locations],
                }
                for d in self.defects
            ],
            "clean": self.clean,
            "unparseable": self.unparseable,
            "meta": self.meta,
        }

    @classmethod
    def from_json(cls, data: dict) -> "Workspace":
        return cls(
            id=data["id"],
            kind=data["kind"],
            language=data["language"],
            path=Path(data["path"]),
            diff_base=data["diff_base"],
            changed_lines={k: set(v) for k, v in data["changed_lines"].items()},
            changed_files=data["changed_files"],
            added_source_lines=data["added_source_lines"],
            defects=[
                Defect(
                    id=d["id"],
                    category=d["category"],
                    subcategory=d.get("subcategory"),
                    description=d["description"],
                    locations=[DefectLocation(**loc) for loc in d["locations"]],
                )
                for d in data["defects"]
            ],
            clean=data["clean"],
            unparseable=data["unparseable"],
            meta=data.get("meta", {}),
        )


def git(*args: str, cwd: Path | None = None, check: bool = True) -> str:
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise CorpusError(f"git {' '.join(args)} failed in {cwd}: {proc.stderr.strip()[:500]}")
    return proc.stdout


def ensure_clone(url: str, dest: Path, sha: str) -> Path:
    """Blobless clone of ``url`` into ``dest`` (cached) that contains ``sha``."""
    if not (dest / ".git").exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        git("clone", "--quiet", "--filter=blob:none", "--no-checkout", url, str(dest))
    if subprocess.run(["git", "cat-file", "-e", f"{sha}^{{commit}}"], cwd=dest, capture_output=True).returncode:
        git("fetch", "--quiet", "--filter=blob:none", "origin", sha, cwd=dest)
    return dest


def fresh_checkout(cache: Path, dest: Path, sha: str) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    # --shared reuses the cache's object store; the promisor remote lets Git
    # lazily fetch any blob the blobless cache has not downloaded yet.
    git("clone", "--quiet", "--shared", "--no-checkout", str(cache), str(dest))
    remote = git("remote", "get-url", "origin", cwd=cache).strip()
    git("remote", "set-url", "origin", remote, cwd=dest)
    git("config", "remote.origin.promisor", "true", cwd=dest)
    git("config", "remote.origin.partialclonefilter", "blob:none", cwd=dest)
    git("checkout", "--quiet", "--detach", sha, cwd=dest)


# ---------------------------------------------------------------- seeded cases


def load_bases() -> dict:
    return tomllib.loads((SEEDED_DIR / "bases.toml").read_text())


def load_cases() -> list[dict]:
    cases = []
    for path in sorted((SEEDED_DIR / "cases").glob("*.toml")):
        case = tomllib.loads(path.read_text())
        if case.get("id") != path.stem:
            raise CorpusError(f"{path.name}: id {case.get('id')!r} does not match file name")
        cases.append(case)
    return cases


def _materialize(text: str, case: dict) -> str:
    for placeholder, parts in (case.get("materialize") or {}).items():
        text = text.replace(placeholder, "".join(parts))
    return text


def _apply_edit(root: Path, edit: dict, case: dict) -> None:
    target = root / edit["file"]
    mode = edit.get("mode", "replace")
    new = _materialize(edit.get("new", ""), case)
    if mode in {"create", "overwrite"}:
        if mode == "create" and target.exists():
            raise CorpusError(f"{case['id']}: create target already exists: {edit['file']}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(new)
        return
    if not target.exists():
        raise CorpusError(f"{case['id']}: edit target missing: {edit['file']}")
    text = target.read_text()
    if mode == "append":
        target.write_text(text + new)
        return
    if mode != "replace":
        raise CorpusError(f"{case['id']}: unknown edit mode {mode!r}")
    old = _materialize(edit["old"], case)
    count = text.count(old)
    if count != 1:
        raise CorpusError(f"{case['id']}: 'old' text occurs {count} times in {edit['file']} (must be exactly 1)")
    target.write_text(text.replace(old, new, 1))


def changed_new_lines(before: list[str], after: list[str]) -> tuple[set[int], int]:
    """Return (1-based new-side lines that were inserted/replaced plus both
    neighbours of a pure deletion, number of added lines)."""
    lines: set[int] = set()
    added = 0
    matcher = difflib.SequenceMatcher(a=before, b=after, autojunk=False)
    for tag, _i1, _i2, j1, j2 in matcher.get_opcodes():
        if tag in {"replace", "insert"}:
            lines.update(range(j1 + 1, j2 + 1))
            added += j2 - j1
        elif tag == "delete":
            lines.update(n for n in (j1, j1 + 1) if 1 <= n <= len(after))
    return lines, added


def _resolve_location(root: Path, loc: dict, case_id: str) -> DefectLocation:
    path = root / loc["file"]
    lines = path.read_text().splitlines()
    hits = [i for i, text in enumerate(lines, 1) if loc["anchor"] in text]
    if len(hits) != 1:
        raise CorpusError(f"{case_id}: anchor {loc['anchor']!r} matched {len(hits)} lines in {loc['file']}")
    start = end = hits[0]
    if loc.get("end_anchor"):
        after = [i for i, text in enumerate(lines, 1) if i >= start and loc["end_anchor"] in text]
        if not after:
            raise CorpusError(f"{case_id}: end_anchor {loc['end_anchor']!r} not found after line {start}")
        end = after[0]
    return DefectLocation(file=loc["file"], start=start, end=end)


def prepare_seeded(work: Path, case_filter: set[str] | None = None) -> list[Workspace]:
    bases = load_bases()
    workspaces = []
    for case in load_cases():
        if case_filter and case["id"] not in case_filter:
            continue
        base = bases[case["base"]]
        cache = ensure_clone(base["repo"], work / "cache" / case["base"], base["sha"])
        dest = work / "workspaces" / "seeded" / case["id"]
        fresh_checkout(cache, dest, base["sha"])

        touched = sorted({e["file"] for e in case["edits"]})
        before = {f: ((dest / f).read_text().splitlines() if (dest / f).exists() else []) for f in touched}
        for edit in case["edits"]:
            _apply_edit(dest, edit, case)
        changed: dict[str, set[int]] = {}
        added_source = 0
        for f in touched:
            after = (dest / f).read_text().splitlines()
            lines, added = changed_new_lines(before[f], after)
            changed[f] = lines
            if Path(f).suffix.lower() in SOURCE_EXTENSIONS:
                added_source += added
        defects = [
            Defect(
                id=d["id"],
                category=d["category"],
                subcategory=d.get("subcategory"),
                description=d["description"],
                locations=[_resolve_location(dest, loc, case["id"]) for loc in d["locations"]],
            )
            for d in case.get("defects", [])
        ]
        if case.get("clean") and defects:
            raise CorpusError(f"{case['id']}: clean cases must not declare defects")
        if not case.get("clean") and not defects:
            raise CorpusError(f"{case['id']}: non-clean case declares no defects")
        workspaces.append(
            Workspace(
                id=case["id"],
                kind="seeded",
                language=case["language"],
                path=dest,
                diff_base="HEAD",
                changed_lines=changed,
                changed_files=touched,
                added_source_lines=added_source,
                defects=defects,
                clean=bool(case.get("clean")),
                unparseable=bool(case.get("unparseable")),
                meta={"base": case["base"], "base_sha": base["sha"], "story": case["story"]},
            )
        )
    return workspaces


# ---------------------------------------------------------------- real commits

_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def parse_unified_zero(diff: str) -> dict[str, set[int]]:
    """Map new-side path -> changed line numbers from ``git diff -U0`` output."""
    changed: dict[str, set[int]] = {}
    current: str | None = None
    for line in diff.splitlines():
        if line.startswith("+++ "):
            target = line[4:]
            current = None if target == "/dev/null" else target[2:] if target.startswith("b/") else target
            if current is not None:
                changed.setdefault(current, set())
            continue
        m = _HUNK.match(line)
        if m and current is not None:
            start = int(m.group(1))
            count = int(m.group(2)) if m.group(2) is not None else 1
            if count == 0:
                # Pure deletion: git reports the line *before* the gap.
                changed[current].update(n for n in (start, start + 1) if n >= 1)
            else:
                changed[current].update(range(start, start + count))
    return changed


def load_real_commits() -> list[dict]:
    if not REAL_COMMITS.exists():
        return []
    return json.loads(REAL_COMMITS.read_text())["commits"]


def prepare_real(work: Path, commit_filter: set[str] | None = None) -> list[Workspace]:
    """Compute each commit's change map from the blobless cache. The checkout
    itself is created lazily by :func:`materialize` right before tools run, so
    at most one real repository is checked out at a time."""
    workspaces = []
    for c in load_real_commits():
        if commit_filter and c["id"] not in commit_filter:
            continue
        owner_repo = c["repo"]
        cache = ensure_clone(
            f"https://github.com/{owner_repo}", work / "cache" / owner_repo.replace("/", "__"), c["sha"]
        )
        diff = git("diff", "--no-color", "--no-ext-diff", "-U0", "--no-renames", c["parent"], c["sha"], cwd=cache)
        changed = parse_unified_zero(diff)
        existing = []
        if changed:
            tree = git("ls-tree", "-r", c["sha"], "--", *sorted(changed), cwd=cache)
            for row in tree.splitlines():
                meta, path = row.split("\t", 1)
                mode, kind, _obj = meta.split()
                if kind == "blob" and mode != "120000":  # regular files only (no symlinks/submodules)
                    existing.append(path)
        existing.sort()
        added_source = 0
        numstat = git("diff", "--numstat", "--no-renames", c["parent"], c["sha"], cwd=cache)
        for row in numstat.splitlines():
            adds, _dels, path = row.split("\t", 2)
            if adds != "-" and path in existing and Path(path).suffix.lower() in SOURCE_EXTENSIONS:
                added_source += int(adds)
        workspaces.append(
            Workspace(
                id=c["id"],
                kind="real",
                language=c["language"],
                path=work / "workspaces" / "real" / c["id"],
                diff_base=c["parent"],
                changed_lines={f: changed[f] for f in existing},
                changed_files=existing,
                added_source_lines=added_source,
                meta={**{k: c[k] for k in ("repo", "sha", "parent", "agent", "url", "subject")}, "cache": str(cache)},
            )
        )
    return workspaces


def materialize(ws: Workspace) -> None:
    """Check out a real-commit workspace if it is not present."""
    if ws.kind == "real" and not ws.path.exists():
        fresh_checkout(Path(ws.meta["cache"]), ws.path, ws.meta["sha"])


def snapshot_and_prune(ws: Workspace, snapshot_root: Path) -> None:
    """Keep copies of the changed files (for labeling context) and delete the checkout."""
    if ws.kind != "real" or not ws.path.exists():
        return
    dest = snapshot_root / ws.id
    for rel in ws.changed_files:
        src = ws.path / rel
        if src.is_file():
            (dest / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dest / rel)
    shutil.rmtree(ws.path)
