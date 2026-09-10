"""Resolve selected repositories and immutable identities before comparison."""

from __future__ import annotations

from dataclasses import dataclass, replace
import os
from pathlib import Path
from typing import Sequence

from skylos.core.verify_change_schema import parse_line_range
from skylos.verification.comparison import ComparisonScope, SourceSnapshot
from skylos.verification.refactor import _base_sources, _current_sources, _git


@dataclass(frozen=True)
class ComparisonTarget:
    """A caller-selected path, optional relative file and function line scope."""

    path: str | Path
    file: str | Path | None = None
    line_range: str | tuple[int, int] | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", Path(self.path).expanduser())
        if self.file is not None:
            selected = Path(self.file)
            if (
                selected.is_absolute()
                or ".." in selected.parts
                or "\0" in str(selected)
            ):
                raise ValueError(
                    "--file must be a relative path within the selected directory"
                )
            object.__setattr__(self, "file", selected)
        bounds = self.line_range
        if isinstance(bounds, str):
            bounds = parse_line_range(bounds)
        scope = ComparisonScope(line_range=bounds)
        object.__setattr__(self, "line_range", scope.line_range)


@dataclass(frozen=True)
class ComparisonContext:
    """A prepared source pair and the exact revisions/scopes that identify it."""

    repository_root: Path | None
    base_ref: str
    current_kind: str
    base_ref_commit: str | None = None
    base_commit: str | None = None
    head_commit: str | None = None
    scopes: tuple[ComparisonScope, ...] = ()
    before: SourceSnapshot | None = None
    after: SourceSnapshot | None = None
    status: str = "ready"
    reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.repository_root is not None:
            object.__setattr__(self, "repository_root", Path(self.repository_root))
        object.__setattr__(self, "scopes", tuple(self.scopes))
        object.__setattr__(self, "reasons", tuple(self.reasons))

    @property
    def current_commit(self) -> str | None:
        return self.head_commit if self.current_kind == "commit" else None

    def metadata(self) -> dict:
        return {
            "repository_root": str(self.repository_root)
            if self.repository_root is not None
            else None,
            "mode": "branch" if self.current_kind == "commit" else "local",
            "base_ref": self.base_ref,
            "base_ref_commit": self.base_ref_commit,
            "base_commit": self.base_commit,
            "head_commit": self.head_commit,
            "current_kind": self.current_kind,
            "current_commit": self.current_commit,
            "scopes": [
                {
                    "selected": scope.selected,
                    "directory": scope.directory,
                    "line_range": list(scope.line_range)
                    if scope.line_range is not None
                    else None,
                    "exclude_folders": sorted(scope.exclude_folders),
                }
                for scope in self.scopes
            ],
        }


@dataclass(frozen=True)
class _LocatedTarget:
    target: ComparisonTarget
    selected: str
    path: str
    directory_hint: bool


def _validate_base_ref(base_ref: str | None) -> None:
    if base_ref is not None and (
        not isinstance(base_ref, str)
        or not base_ref.strip()
        or len(base_ref) > 1024
        or base_ref.startswith("-")
        or "\0" in base_ref
    ):
        raise ValueError("Comparison base must be a valid Git commit reference")


def _existing_anchor(path: Path) -> Path:
    anchor = path if path.is_dir() else path.parent
    while not anchor.is_dir() and anchor != anchor.parent:
        anchor = anchor.parent
    return anchor


def _reject_local_symlinks(path: Path, root: Path) -> None:
    ancestor = path
    while True:
        if ancestor.is_symlink():
            if ancestor == path or ancestor.resolve().is_relative_to(root):
                raise ValueError("Verification file or directory must not be a symlink")
        if ancestor.resolve() == root or ancestor == ancestor.parent:
            return
        ancestor = ancestor.parent


def _locate_target(target: ComparisonTarget, *, branch: bool):
    path = target.path.absolute()
    if "\0" in str(path):
        raise ValueError("Verification scope contains an invalid path")
    if path.is_symlink():
        raise ValueError("Verification path must not be a symlink")
    selected = path / target.file if target.file is not None else path
    anchor = _existing_anchor(path)
    try:
        root = Path(
            os.fsdecode(_git(anchor, "rev-parse", "--show-toplevel")).removesuffix("\n")
        ).resolve()
    except ValueError:
        return None, anchor.resolve(), None
    _reject_local_symlinks(selected, root)
    if not branch:
        if target.file is not None and path.exists() and not path.is_dir():
            raise ValueError("--file cannot be combined with a file path target")
        resolved = selected.resolve()
        resolved_path = path.resolve()
    else:
        # Preserve the selected spelling below the discovery anchor: dirty files
        # and directories do not decide which committed path is compared.
        resolved = anchor.resolve() / selected.relative_to(anchor)
        resolved_path = anchor.resolve() / path.relative_to(anchor)
    if not resolved.is_relative_to(root) or ".." in resolved.relative_to(root).parts:
        raise ValueError("Verification scope must stay within the Git repository")
    located = _LocatedTarget(
        target,
        resolved.relative_to(root).as_posix(),
        resolved_path.relative_to(root).as_posix(),
        target.file is None and path.is_dir(),
    )
    return root, root, located


def _resolve_commit(root: Path, ref: str) -> str:
    return (
        _git(root, "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}")
        .decode("ascii")
        .strip()
    )


def _pin_revisions(context: ComparisonContext) -> ComparisonContext:
    root = context.repository_root
    try:
        head = _resolve_commit(root, "HEAD")
    except ValueError:
        return replace(
            context,
            status="unavailable",
            reasons=("No local Git HEAD is available for behavior comparison",),
        )
    context = replace(context, head_commit=head)
    if context.current_kind == "working_tree":
        return replace(context, base_ref_commit=head, base_commit=head)
    try:
        reference = (
            head
            if context.base_ref == "HEAD"
            else _resolve_commit(root, context.base_ref)
        )
    except ValueError:
        return replace(
            context,
            status="unavailable",
            reasons=(
                f"Cannot resolve comparison base {context.base_ref!r} in the target repository",
            ),
        )
    context = replace(context, base_ref_commit=reference)
    try:
        bases = (
            _git(root, "merge-base", "--all", reference, head)
            .decode("ascii")
            .splitlines()
        )
    except ValueError:
        bases = []
    if len(bases) != 1:
        reason = (
            "Comparison history has multiple merge bases; a unique baseline is required"
            if bases
            else "Comparison merge-base history is unavailable; history may be shallow or unrelated"
        )
        return replace(context, status="unavailable", reasons=(reason,))
    return replace(context, base_commit=bases[0])


def _snapshot_kind(name: str, names: set[str]) -> str | None:
    if name == "." or any(path.startswith(name + "/") for path in names):
        return "directory"
    return "file" if name in names else None


class _UnavailableScope(ValueError):
    pass


def _committed_kind(root: Path, commit: str, name: str) -> str | None:
    if name == ".":
        return "directory"
    try:
        # The object-path suffix is exact, not a glob or working-tree path.
        kind = _git(root, "cat-file", "-t", f"{commit}:{name}").strip()
    except ValueError:
        return None
    return {b"blob": "file", b"tree": "directory", b"commit": "submodule"}.get(kind)


def _target_kinds(context: ComparisonContext, name: str) -> set[str]:
    if context.current_kind == "commit":
        return {
            kind
            for commit in {context.base_commit, context.head_commit}
            if (kind := _committed_kind(context.repository_root, commit, name))
            is not None
        }
    return {
        kind
        for snapshot in (context.before, context.after)
        if (kind := _snapshot_kind(name, set(snapshot.hashes))) is not None
    }


def _scopes_for_targets(
    targets: Sequence[_LocatedTarget],
    context: ComparisonContext,
    *,
    excluded: frozenset[str],
) -> tuple[ComparisonScope, ...]:
    scopes = []
    for item in targets:
        kinds = _target_kinds(context, item.selected)
        branch = context.current_kind == "commit"
        if branch and not kinds:
            raise _UnavailableScope(
                f"Selected scope {item.selected!r} does not exist in either compared commit"
            )
        if "submodule" in kinds:
            raise _UnavailableScope(
                "Selected scope is a Git submodule, outside source comparison"
            )
        if item.target.file is not None:
            if "file" in _target_kinds(context, item.path):
                raise _UnavailableScope(
                    "--file cannot be combined with a file path target"
                )
            if "directory" in kinds:
                raise _UnavailableScope(
                    "--file must select a file in the compared sources"
                )
            kinds = {"file"}
        elif not branch:
            if item.directory_hint:
                kinds.add("directory")
            if not kinds:
                kinds.add("file")
        # A committed file-to-directory change includes both the deleted file
        # and new descendants; neither side may disappear during selection.
        for kind in sorted(kinds):
            scope = ComparisonScope(
                item.selected, kind == "directory", item.target.line_range, excluded
            )
            if scope not in scopes:
                scopes.append(scope)
    return tuple(scopes)


def _check_submodules(context: ComparisonContext) -> None:
    revisions = [context.base_commit]
    if context.current_kind == "commit":
        revisions.append(context.head_commit)
    changes = _git(
        context.repository_root,
        "diff",
        "--raw",
        "--no-ext-diff",
        "--no-textconv",
        "--ignore-submodules=none",
        *revisions,
        "--",
    )
    if any(
        b"160000" in row.split(b"\t", 1)[0].split() or row.startswith(b":160000 ")
        for row in changes.splitlines()
    ):
        raise ValueError(
            "Git submodule dependencies changed; behavior comparison is incomplete"
        )


def _load_context(
    context: ComparisonContext,
    targets: Sequence[_LocatedTarget],
    excluded: frozenset[str],
) -> ComparisonContext:
    context = _pin_revisions(context)
    if context.status != "ready":
        return context
    root = context.repository_root
    branch = context.current_kind == "commit"
    if not branch and all(
        not item.directory_hint
        and (
            Path(item.selected).suffix
            or (item.target.path / (item.target.file or "")).is_file()
        )
        and not item.selected.endswith(".py")
        for item in targets
    ):
        return replace(
            context,
            status="unavailable",
            reasons=(
                "Automatic behavior comparison currently applies to Python files",
            ),
            scopes=tuple(
                ComparisonScope(item.selected, False, item.target.line_range, excluded)
                for item in targets
            ),
        )
    try:
        before = SourceSnapshot(
            *_base_sources(root, context.base_commit, allow_submodules=True)
        )
        if branch:
            after = (
                before
                if context.base_commit == context.head_commit
                else SourceSnapshot(
                    *_base_sources(root, context.head_commit, allow_submodules=True)
                )
            )
        else:
            selected = tuple(
                sorted(
                    {
                        item.selected
                        for item in targets
                        if not item.directory_hint and item.selected.endswith(".py")
                    }
                )
            )
            after = SourceSnapshot(
                *_current_sources(root, selected or None, allow_submodules=True)
            )
        context = replace(context, before=before, after=after)
        _check_submodules(context)
    except ValueError as exc:
        return replace(context, status="unknown", reasons=(str(exc),))
    try:
        scopes = _scopes_for_targets(targets, context, excluded=excluded)
    except _UnavailableScope as exc:
        return replace(context, status="unavailable", reasons=(str(exc),))
    if not any(scope.directory or scope.selected.endswith(".py") for scope in scopes):
        return replace(
            context,
            scopes=scopes,
            status="unavailable",
            reasons=(
                "Automatic behavior comparison currently applies to Python files",
            ),
        )
    return replace(context, scopes=scopes)


def resolve_comparison_contexts(
    paths: Sequence[str | Path | ComparisonTarget],
    *,
    base_ref: str | None = None,
    exclude_folders: Sequence[str] | None = None,
) -> list[ComparisonContext]:
    """Read each selected repository's source pair once with pinned revisions."""
    _validate_base_ref(base_ref)
    if isinstance(paths, (str, Path, ComparisonTarget)):
        paths = [paths]
    excluded = frozenset(exclude_folders or ())
    groups = {}
    for value in paths:
        target = (
            value if isinstance(value, ComparisonTarget) else ComparisonTarget(value)
        )
        root, group, located = _locate_target(target, branch=base_ref is not None)
        if group not in groups:
            groups[group] = (root, [])
        if located is not None:
            groups[group][1].append(located)
    contexts = []
    for root, targets in groups.values():
        context = ComparisonContext(
            root,
            base_ref or "HEAD",
            "commit" if base_ref is not None else "working_tree",
        )
        if root is None:
            contexts.append(
                replace(
                    context,
                    status="unavailable",
                    reasons=(
                        "No local Git repository is available for behavior comparison",
                    ),
                )
            )
        else:
            contexts.append(_load_context(context, targets, excluded))
    return contexts
