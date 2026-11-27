"""Bind ASP.NET Minimal API method groups within the admitted C# project."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from xml.etree import ElementTree

from skylos.core.safe_cache_io import read_project_text_no_symlink

from . import core
from ._lex import _METHOD_RE, _argument_spans, mask_comments_and_strings
from .bindings import _USING, ReferenceContext
from .routes import MAP_CALL_RE, declared_framework_homonyms, endpoint_receiver_offsets

_MAX_BYTES = 4_000_000
_NAME = r"@?[A-Za-z_]\w*"
_GROUP = re.compile(
    rf"\s*(?P<target>(?:global\s*::\s*)?{_NAME}(?:\s*\.\s*{_NAME})*)\s*"
)
_FRAMEWORK_TYPES = re.compile(
    r"\b(?:class|record(?:\s+(?:class|struct))?|struct|interface)\s+(WebApplication(?:Builder)?|IEndpointRouteBuilder|RouteGroupBuilder)\b"
)
_CONDITIONAL = re.compile(r"(?m)^\s*#\s*(if|endif)\b")
_HANDLER_ARG = re.compile(r"\s*(?:handler|requestDelegate)\s*:\s*")


@dataclass(frozen=True)
class RouteFileFacts:
    digest: bytes = b""
    lambdas: tuple[tuple[int, int], ...] = ()
    method_offsets: frozenset[int] = frozenset()

    def matches(self, source: str) -> bool:
        return self.digest == _digest(source)


def _digest(source: str) -> bytes:
    return hashlib.blake2s(source.encode("utf-8"), digest_size=16).digest()


def _conditional_ranges(masked):
    depth = 0
    start = 0
    for directive in _CONDITIONAL.finditer(masked):
        if directive[1] == "if":
            if not depth:
                start = directive.start()
            depth += 1
        elif depth:
            depth -= 1
            if not depth:
                yield start, directive.end()
    if depth:
        yield start, len(masked)


def _registrations(masked, shadowed_types, global_usings=()):
    lambdas = []
    groups = []
    contexts = None
    enabled = endpoint_receiver_offsets(
        masked, shadowed_types=shadowed_types, global_usings=global_usings
    )
    conditional = tuple(_conditional_ranges(masked))
    for match in MAP_CALL_RE.finditer(masked):
        if match.start() not in enabled or any(
            a <= match.start() < b for a, b in conditional
        ):
            continue
        opening = match.end() - 1
        closing = core._matching_paren(masked, opening)
        if closing is None:
            continue
        args = _argument_spans(masked, opening + 1, closing)
        if len(args) < 2 and "MapFallback" not in match.group():
            continue
        start, end = args[-1]
        for arg_start, arg_end in args:
            named = _HANDLER_ARG.match(masked, arg_start, arg_end)
            if named:
                start, end = named.end(), arg_end
                break
        target = _GROUP.fullmatch(masked, start, end)
        if not target:
            lambdas.append((start, end))
            continue
        spelling = re.sub(r"[\s@]", "", target["target"])
        if contexts is None:
            namespaces = core._namespace_ranges(masked)
            contexts = ReferenceContext(
                masked, core._type_ranges(masked, namespaces), namespaces
            )
            if conditional:
                contexts.usings = [
                    directive
                    for directive in contexts.usings
                    if not any(a <= directive.start("name") < b for a, b in conditional)
                ]
        contexts.record(spelling, target.start("target"))
        context = contexts.destination[spelling].pop()
        # Top-level statements have no method body in ReferenceContext.
        first = spelling.split(".", 1)[0]
        if context["receiver_shadowed"] or (
            context["owner"] is None
            and not spelling.startswith("global::")
            and re.search(
                rf"\b(?!using\b)[\w.<>]+\s+{re.escape(first)}\s*=", masked[:start]
            )
        ):
            continue
        groups.append((spelling, context))
    return tuple(lambdas), groups


class _Declarations:
    def __init__(self):
        self.types = defaultdict(list)
        self.methods = defaultdict(list)
        self.locals = defaultdict(list)
        self.nested_locals = set()
        self.file_types = set()

    def add(self, path, masked, wanted):
        ranges = core._type_ranges(masked, core._namespace_ranges(masked))
        for _, _, owner, partial in ranges:
            self.types[owner].append((path, partial))
        for decl in core._TYPE_RE.finditer(masked):
            if "file" in decl["mods"].split():
                self.file_types.add((path, decl["name"]))
        conditional = tuple(_conditional_ranges(masked))
        for match in _METHOD_RE.finditer(masked):
            name = match["name"]
            if name not in wanted:
                continue
            owner = core._containing_type_range(ranges, match.start("name"))
            # Conditional and inaccessible overloads still make a name ambiguous.
            active = not any(a <= match.start("name") < b for a, b in conditional)
            mods = set((match["mods"] + match["rtype"]).split())
            if owner is None:
                if masked.count("{", 0, match.start()) == masked.count(
                    "}", 0, match.start()
                ):
                    self.locals[path, name].append((match.end(), active))
            elif core._is_direct_member(masked, owner, match.start()):
                self.methods[owner[2], name].append((path, match.end(), mods, active))
            else:
                self.nested_locals.add((path, owner[2], name))

    def resolve(self, path, spelling, context, global_usings):
        absolute = spelling.startswith("global::")
        owner, _, method = spelling.removeprefix("global::").rpartition(".")
        enclosing = context["owner"]
        if not owner:
            if (path, enclosing, method) in self.nested_locals:
                return None
            if not enclosing:
                local = self.locals.get((path, method), ())
                if local:
                    return (
                        (path, local[0][0]) if len(local) == 1 and local[0][1] else None
                    )
            static_usings = context["static_usings"] + [
                name for alias, static, name in global_usings if static
            ]
            owners = (
                [enclosing]
                if enclosing and (enclosing, method) in self.methods
                else static_usings
            )
        else:
            owners = self._resolve_types(owner, absolute, context, global_usings)
        owners = set(owners)
        if len(owners) != 1:
            return None
        owner = owners.pop()
        declarations = self.types.get(owner, ())
        if len(declarations) > 1 and not all(partial for _, partial in declarations):
            return None
        methods = self.methods.get((owner, method), ())
        if len(methods) != 1:
            return None
        file, offset, mods, active = methods[0]
        if path != file and any(
            (file, part) in self.file_types for part in owner.split(".")
        ):
            return None
        if (
            not active
            or ("." in spelling and "static" not in mods)
            or (
                enclosing != owner
                and ("static" not in mods or mods.isdisjoint({"public", "internal"}))
            )
        ):
            return None
        return file, offset

    def _resolve_types(self, owner, absolute, context, global_usings):
        if absolute:
            return [owner] if owner in self.types else []
        first, dot, suffix = owner.partition(".")
        namespaces = [""]
        prefix = context["namespace"]
        while prefix:
            namespaces.append(prefix + ".")
            prefix = prefix.rpartition(".")[0]
        aliases = {
            name + dot + suffix for alias, _, name in global_usings if alias == first
        }
        if first in context["aliases"]:
            aliases.update(
                prefix + context["aliases"][first] + dot + suffix
                for prefix in namespaces
            )
        if aliases:
            return self.types.keys() & aliases
        scope = context["owner"] or context["namespace"]
        # An enclosing type or the current namespace wins over imported names.
        namespace = context["namespace"]
        while scope and (
            not namespace or scope.startswith(namespace + ".") or scope == namespace
        ):
            name = scope + "." + owner
            if name in self.types:
                return [name]
            scope = scope.rpartition(".")[0]
        # Imports can be relative to their declaring namespace. If flattening
        # nested directives leaves two possible types, do not infer an edge.
        candidates = {prefix + owner for prefix in namespaces}
        candidates.update(
            prefix + name + "." + owner
            for name in context["usings"]
            for prefix in namespaces
        )
        candidates.update(
            name + "." + owner
            for alias, static, name in global_usings
            if not alias and not static
        )
        return self.types.keys() & candidates


def local_route_facts(masked: str) -> RouteFileFacts:
    if not MAP_CALL_RE.search(masked):
        return RouteFileFacts()
    lambdas, groups = _registrations(masked, frozenset())
    offsets = set()
    if groups:
        declarations = _Declarations()
        declarations.add(
            "", masked, {target.rsplit(".", 1)[-1] for target, _ in groups}
        )
        for spelling, context in groups:
            hit = declarations.resolve("", spelling, context, ())
            if hit:
                offsets.add(hit[1])
    return RouteFileFacts(lambdas=lambdas, method_offsets=frozenset(offsets))


def _compile_usings(root, project, *, sdk_required=True):
    """Read namespace imports only for projects with ordinary SDK compile items."""
    text = read_project_text_no_symlink(root, project, max_bytes=512_000)
    if not text or re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", text, re.IGNORECASE):
        return None
    try:
        xml = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return None
    if xml.tag.rsplit("}", 1)[-1] != "Project":
        return None
    sdk = xml.get("Sdk", "").split("/", 1)[0]
    if sdk_required and sdk not in {
        "Microsoft.NET.Sdk",
        "Microsoft.NET.Sdk.Web",
        "Microsoft.NET.Sdk.Worker",
        "Microsoft.NET.Sdk.Razor",
    }:
        return None

    usings = set()
    stack = [(xml, False)]
    while stack:
        node, conditional = stack.pop()
        name = node.tag.rsplit("}", 1)[-1]
        conditional = conditional or "Condition" in node.attrib or name == "Choose"
        if name == "Compile" and (
            "Update" not in node.attrib
            or {"Include", "Remove", "Exclude"} & node.attrib.keys()
        ):
            return None
        if (
            name in {"EnableDefaultCompileItems", "EnableDefaultItems"}
            and (node.text or "").strip().lower() != "true"
        ):
            return None
        if name in {
            "DefaultItemExcludes",
            "DefaultItemExcludesInProjectFolder",
            "DefaultExcludesInProjectFolder",
            "BaseOutputPath",
            "BaseIntermediateOutputPath",
            "Import",
        }:
            return None
        if name == "Using":
            target = node.get("Include", "")
            if (
                conditional
                or set(node.attrib) != {"Include"}
                or len(node)
                or not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", target)
            ):
                return None
            usings.add((None, False, target))
        stack.extend((child, conditional) for child in node)
    return frozenset(usings)


def build_route_handler_index(files, root) -> dict[str, RouteFileFacts]:
    """Cross-file edges require one owning project with default compile inputs."""
    root = Path(root).absolute()

    @cache
    def directory_usings(directory, name):
        build_file = directory / name
        if build_file.is_file() or build_file.is_symlink():
            return _compile_usings(root, build_file, sdk_required=False)
        if directory == root:
            return frozenset()
        return directory_usings(directory.parent, name)

    @cache
    def owner(directory):
        if not directory.is_relative_to(root) or directory.is_symlink():
            return None
        try:
            projects = list(directory.glob("*.csproj"))
        except OSError:
            return None
        if not projects:
            return owner(directory.parent) if directory != root else None
        if len(projects) != 1:
            return None
        usings = _compile_usings(root, projects[0])
        for name in ("Directory.Build.props", "Directory.Build.targets"):
            inherited = directory_usings(directory, name)
            if inherited is None or usings is None:
                return None
            usings = usings | inherited
        return projects[0], usings

    projects = defaultdict(list)
    for file in files:
        path = Path(file)
        if path.suffix.lower() != ".cs":
            continue
        project = owner(path.absolute().parent)
        if project is not None:
            parts = path.absolute().relative_to(project[0].parent).parts[:-1]
            if not any(part.lower() in {"obj", "bin"} for part in parts):
                projects[project].append(path)
    result = {}
    for (_, usings), paths in projects.items():
        result.update(_project_facts(root, paths, usings))
    return result


def _project_facts(root, paths, project_usings):
    registrations = {}
    global_usings = set(project_usings)
    shadowed_types = set()
    for path in paths:
        source = read_project_text_no_symlink(
            root, path, max_bytes=_MAX_BYTES, errors="ignore"
        )
        if source is None:
            return {}
        has_map = MAP_CALL_RE.search(source)
        if (
            not has_map
            and not _FRAMEWORK_TYPES.search(source)
            and not re.search(r"\bglobal\s+using\b", source)
        ):
            continue
        masked = mask_comments_and_strings(source)
        if _FRAMEWORK_TYPES.search(masked):
            shadowed_types.update(declared_framework_homonyms(masked))
        conditional = tuple(_conditional_ranges(masked))
        for match in _USING.finditer(masked):
            if match.group().lstrip().startswith("global") and not any(
                a <= match.start("name") < b for a, b in conditional
            ):
                global_usings.add(
                    (
                        match["alias"],
                        bool(match["static"]),
                        match["name"].removeprefix("global::"),
                    )
                )
        if has_map:
            registrations[str(path)] = (_digest(source), masked)

    lambdas = {}
    groups = []
    wanted = set()
    digests = {}
    for path, (digest, masked) in registrations.items():
        digests[path] = digest
        lambdas[path], references = _registrations(
            masked, frozenset(shadowed_types), global_usings
        )
        for spelling, context in references:
            groups.append((path, spelling, context))
            wanted.add(spelling.rsplit(".", 1)[-1])
    offsets = defaultdict(set)
    if wanted:
        declarations = _Declarations()
        for path in paths:
            file = str(path)
            if file in registrations:
                masked = registrations[file][1]
            else:
                source = read_project_text_no_symlink(
                    root, path, max_bytes=_MAX_BYTES, errors="ignore"
                )
                if source is None:
                    return {}
                masked = mask_comments_and_strings(source)
                digests[file] = _digest(source)
            declarations.add(file, masked, wanted)
        for file, spelling, context in groups:
            hit = declarations.resolve(file, spelling, context, global_usings)
            if hit:
                offsets[hit[0]].add(hit[1])
    return {
        file: RouteFileFacts(
            digests[file], lambdas.get(file, ()), frozenset(offsets[file])
        )
        for file in registrations.keys() | offsets.keys()
    }
