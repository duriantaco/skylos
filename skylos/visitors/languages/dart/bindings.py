"""Bounded project-owned Dart library, import and export binding resolution.

No dependency code is executed. Missing provider namespaces remain unknown;
they are never proof that every import or public declaration is used.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

from skylos.core.safe_cache_io import read_project_text_no_symlink


# The SDK's public declaration names needed for binding, not an import allowlist.
# Unlisted SDK namespaces are handled just like other unresolved providers.
_SDK = {
    "dart:async": set(
        "Completer FutureOr StreamController StreamSubscription StreamTransformer EventSink StreamSink Timer Zone ZoneDelegate ZoneSpecification runZoned runZonedGuarded scheduleMicrotask unawaited FutureExtensions ParallelWaitError FutureIterable FutureRecord2 FutureRecord3".split()
    ),
    "dart:math": set(
        "Random Point Rectangle MutableRectangle min max pow sqrt sin cos tan asin acos atan atan2 exp log pi e ln2 ln10 log2e log10e sqrt1_2 sqrt2".split()
    ),
    "dart:convert": set(
        "AsciiCodec AsciiDecoder AsciiEncoder Base64Codec Base64Decoder Base64Encoder Codec Converter Encoding HtmlEscape HtmlEscapeMode JsonCodec JsonDecoder JsonEncoder Latin1Codec Latin1Decoder Latin1Encoder LineSplitter Utf8Codec Utf8Decoder Utf8Encoder ascii base64 base64Decode base64Encode base64Url htmlEscape json jsonDecode jsonEncode latin1 utf8".split()
    ),
    "dart:typed_data": set(
        "ByteBuffer ByteData Endian Float32List Float32x4 Float32x4List Float64List Float64x2 Float64x2List Int8List Int16List Int32List Int32x4 Int32x4List Int64List TypedData Uint8List Uint8ClampedList Uint16List Uint32List Uint64List".split()
    ),
    "dart:isolate": set(
        "Capability Isolate IsolateSpawnException RawReceivePort ReceivePort RemoteError SendPort TransferableTypedData".split()
    ),
    "dart:io": set(
        "Platform File Directory Link FileStat FileMode FileLock FileSystemEntity FileSystemEntityType FileSystemException InternetAddress InternetAddressType Process ProcessException ProcessResult ProcessSignal HttpClient HttpClientRequest HttpClientResponse HttpHeaders HttpStatus HttpOverrides HttpClientResponseCompressionState HttpServer HttpRequest HttpResponse HttpException Socket ServerSocket SecureSocket SecurityContext SocketException RawSocket RawDatagramSocket Datagram IOSink Stdin Stdout ZLibCodec GZipCodec exit exitCode pid stdin stdout stderr sleep gzip zlib systemEncoding".split()
    ),
    "dart:js_interop": set(
        "JS JSAny JSObject JSFunction JSArray JSArrayBuffer JSBoolean JSBoxedDartObject JSDataView JSExport JSInt8Array JSInt16Array JSInt32Array JSNumber JSPromise JSString JSSymbol JSTypedArray JSUint8Array JSUint16Array JSUint32Array JSUint8ClampedArray JSFloat32Array JSFloat64Array".split()
    ),
}
_CORE = set(
    "Object Null Never dynamic void bool num int double String Symbol Type Function Record Enum Iterable Iterator List Set Map MapEntry Future Stream FutureExtensions FutureIterable FutureRecord2 FutureRecord3 FutureRecord4 FutureRecord5 FutureRecord6 FutureRecord7 FutureRecord8 FutureRecord9 ParallelWaitError NullableIterableExtensions IterableExtensions Duration DateTime Stopwatch RegExp Match Pattern StringBuffer BigInt Uri Error Exception ArgumentError AssertionError ConcurrentModificationError FormatException IndexError RangeError StateError TypeError UnimplementedError UnsupportedError StackTrace Comparable Comparator Expando Invocation NoSuchMethodError WeakReference Finalizer pragma Deprecated deprecated override identical identityHashCode print assert true false null".split()
)


def apply_dart_project_bindings(definitions, metadata_by_file, project_root):
    """Credit concrete binding reads and explicit exports, and record uncertainty."""
    root = Path(project_root).resolve()
    metadata = {
        str(Path(path).resolve()): facts
        for path, facts in metadata_by_file.items()
        if isinstance(facts, dict)
    }
    by_file = defaultdict(list)
    id_to_key = {id(definition): key for key, definition in definitions.items()}
    for definition in definitions.values():
        if str(definition.filename).endswith(".dart"):
            by_file[str(Path(definition.filename).resolve())].append(definition)
    packages = {}
    for path in metadata:
        directory = Path(path).parent
        while directory == root or root in directory.parents:
            manifest = directory / "pubspec.yaml"
            if manifest.is_file() and not manifest.is_symlink():
                text = (
                    read_project_text_no_symlink(
                        root, manifest, max_bytes=65536, errors="ignore"
                    )
                    or ""
                )
                match = re.search(r"^name:\s*['\"]?([A-Za-z_]\w*)", text, re.MULTILINE)
                if match:
                    packages[match.group(1)] = directory / "lib"
                break
            if directory == root:
                break
            directory = directory.parent

    def resolve(owner, source):
        if source.startswith("dart:"):
            return source if source in _SDK else None
        if source.startswith("package:"):
            package, separator, suffix = source[8:].partition("/")
            if not separator or package not in packages:
                return None
            candidate = packages[package] / suffix
        elif ":" in source or source.startswith(("/", "\\")):
            return None
        else:
            candidate = Path(owner).parent / source
        candidate = candidate.resolve()
        if root not in candidate.parents or str(candidate) not in metadata:
            return None
        return str(candidate)

    # A part is inside its owner's private namespace, not an independent import.
    parents = {path: path for path in metadata}

    def unit(path):
        while parents[path] != path:
            path = parents[path]
        return path

    for path, facts in metadata.items():
        for source in facts.get("parts", []):
            part = resolve(path, source)
            if part in metadata and metadata[part].get("part_of"):
                if resolve(part, metadata[part]["part_of"]) == path:
                    parents[unit(part)] = unit(path)
    units = defaultdict(list)
    for path in metadata:
        units[unit(path)].append(path)
    local = defaultdict(lambda: defaultdict(list))
    members = defaultdict(lambda: defaultdict(list))
    for owner, paths in units.items():
        for path in paths:
            for definition in by_file[path]:
                if definition.type != "import" and "." not in definition.name:
                    local[owner][definition.name].append(definition)
                elif definition.type != "import":
                    members[owner][definition.name].append(definition)

    def selected(names, directive):
        shown, hidden = set(directive.get("show", [])), set(directive.get("hide", []))
        return {
            name: values
            for name, values in names.items()
            if (not shown or name in shown) and name not in hidden
        }

    def exported(path, seen=frozenset()):
        if path in _SDK:
            # This is a finite known subset, not a version-pinned exhaustive SDK
            # namespace. An unlisted identifier must remain unresolved.
            return {name: [] for name in _SDK[path]}, True
        if path not in metadata or path in seen:
            return {}, path not in metadata
        owner = unit(path)
        found = {
            name: list(values)
            for name, values in local[owner].items()
            if not name.startswith("_")
        }
        unresolved = False
        for member in units[owner]:
            for directive in metadata[member].get("exports", []):
                for source in directive.get("sources", []):
                    provider = resolve(member, source)
                    if provider is None:
                        unresolved = True
                        continue
                    names, unknown = exported(provider, seen | {path})
                    unresolved |= unknown
                    for name, values in selected(names, directive).items():
                        found.setdefault(name, []).extend(values)
        return found, unresolved

    def credit(values, reason):
        for definition in values:
            definition.references += 1
            definition.heuristic_refs[reason] = 1.0

    visible_extensions = defaultdict(dict)
    for owner, paths in units.items():
        for values in local[owner].values():
            for definition in values:
                if getattr(definition, "dart_extension_target", None):
                    visible_extensions[owner][id(definition)] = definition
        for path in paths:
            for directive in metadata[path].get("imports", []):
                for source in directive.get("sources", []):
                    provider = resolve(path, source)
                    if provider is None:
                        continue
                    names, _ = exported(provider)
                    for values in selected(names, directive).values():
                        for definition in values:
                            if getattr(definition, "dart_extension_target", None):
                                visible_extensions[owner][id(definition)] = definition

    def subtype(owner, receiver, target):
        if receiver == target:
            return True
        if target == "Object" and receiver not in {"dynamic", "void", "Null"}:
            return True
        if target == "num" and receiver in {"int", "double"}:
            return True
        if target == "Iterable" and receiver in {"List", "Set"}:
            return True
        pending, seen = [receiver], set()
        while pending:
            name = pending.pop()
            if name in seen:
                continue
            seen.add(name)
            for definition in local[owner].get(name, []):
                for base in definition.base_classes:
                    if base == target:
                        return True
                    pending.append(base)
        return False

    def extension_dispatch(owner, use):
        receiver, member = use.get("receiver_type"), use.get("member")
        if (
            not receiver
            or not member
            or use.get("known_receiver_member")
            or members[owner].get(use.get("target"))
        ):
            return None
        candidates = []
        for extension in visible_extensions[owner].values():
            target = extension.dart_extension_target
            if not subtype(owner, receiver, target):
                continue
            provider = unit(str(Path(extension.filename).resolve()))
            if member.startswith("_") and provider != owner:
                continue
            methods = members[provider].get(f"{extension.name}.{member}", [])
            if methods:
                candidates.append((extension, methods))
        # A less specific on-type cannot win over a visible more specific one.
        candidates = [
            candidate
            for candidate in candidates
            if not any(
                other[0].dart_extension_target != candidate[0].dart_extension_target
                and subtype(
                    owner,
                    other[0].dart_extension_target,
                    candidate[0].dart_extension_target,
                )
                for other in candidates
            )
        ]
        return candidates[0] if len(candidates) == 1 else None

    call_graph = {
        id_to_key[id(definition)]: set()
        for values in by_file.values()
        for definition in values
    }

    def connect(owner, use, values):
        caller = use.get("caller") or use.get("owner")
        callers = local[owner].get(caller, []) or members[owner].get(caller, [])
        for definition in values:
            if definition.type not in {"method", "function", "class", "extension"}:
                continue
            for calling in callers:
                if calling is not definition:
                    calling.calls.add(definition.name)
                    definition.called_by.add(calling.name)
                    call_graph[id_to_key[id(calling)]].add(id_to_key[id(definition)])

    rescued, uncertain = 0, 0
    for path, facts in metadata.items():
        owner = unit(path)
        unit_uses = [
            use for member in units[owner] for use in metadata[member].get("uses", [])
        ]
        possible_extensions = [
            call
            for member in units[owner]
            for call in metadata[member].get("possible_extension_calls", [])
        ]
        uses = [use["name"] for use in unit_uses if use.get("import_eligible", True)]
        prefixes = {
            directive.get("prefix")
            for member in units[owner]
            for directive in metadata[member].get("imports", [])
            if directive.get("prefix")
        }
        bound_names = set(local[owner]) | _CORE | prefixes
        for member in units[owner]:
            for imported in metadata[member].get("imports", []):
                if imported.get("prefix"):
                    continue
                for source in imported.get("sources", []):
                    provider = resolve(member, source)
                    if provider is not None:
                        names, _ = exported(provider)
                        bound_names.update(selected(names, imported))
        for use in facts.get("uses", []):
            if (
                use.get("import_eligible", True)
                and use["name"].partition(".")[0] in prefixes
            ):
                continue
            target = use.get("target")
            if use.get("unknown_receiver"):
                values = [
                    definition
                    for group in members[owner].values()
                    for definition in group
                    if definition.type == "method"
                    and definition.simple_name == use.get("member")
                ]
            else:
                values = local[owner].get(target, []) or members[owner].get(target, [])
                dispatch = extension_dispatch(owner, use) if not values else None
                if dispatch:
                    extension, values = dispatch
                    credit([extension], "dart_extension_dispatch")
                    connect(owner, use, [extension])
            credit(values, "dart_library_reference")
            connect(owner, use, values)
        for directive in facts.get("exports", []):
            relative = Path(path).relative_to(root)
            test_only = "test" in relative.parts or relative.name.endswith("_test.dart")
            if not test_only:
                for source in directive.get("sources", []):
                    provider = resolve(path, source)
                    if provider is None:
                        continue
                    names, _ = exported(provider)
                    for values in selected(names, directive).values():
                        for definition in values:
                            definition.is_exported = True
                            definition.heuristic_refs["dart_explicit_export"] = 1.0
                            if definition.type == "extension":
                                provider_owner = unit(
                                    str(Path(definition.filename).resolve())
                                )
                                for name, group in members[provider_owner].items():
                                    if not name.startswith(definition.name + "."):
                                        continue
                                    for method in group:
                                        if not method.simple_name.startswith("_"):
                                            method.is_exported = True
                                            method.heuristic_refs[
                                                "dart_explicit_export"
                                            ] = 1.0
            for definition in by_file[path]:
                details = getattr(definition, "dart_import", None)
                if (
                    details
                    and details["kind"] == "export"
                    and details["line"] == directive["line"]
                ):
                    definition.is_exported = True

        for directive in facts.get("imports", []):
            matching = [
                definition
                for definition in by_file[path]
                if definition.type == "import"
                and getattr(definition, "dart_import", None) == directive
            ]
            prefix = directive.get("prefix")
            namespaces, unknown = {}, False
            for source in directive.get("sources", []):
                provider = resolve(path, source)
                if provider is None:
                    unknown = True
                    continue
                names, unresolved = exported(provider)
                unknown |= unresolved
                for name, values in selected(names, directive).items():
                    namespaces.setdefault(name, []).extend(values)
            read_names = set()
            provided_extensions = {
                id(definition): name
                for name, group in namespaces.items()
                for definition in group
                if getattr(definition, "dart_extension_target", None)
            }
            for record in unit_uses:
                dispatch = extension_dispatch(owner, record)
                if dispatch and id(dispatch[0]) in provided_extensions:
                    read_names.add(provided_extensions[id(dispatch[0])])
                if not record.get("import_eligible", True):
                    continue
                use = record["name"]
                first, separator, rest = use.partition(".")
                if prefix:
                    if first != prefix:
                        continue
                    if not separator:
                        continue
                    name = rest.split(".", 1)[0]
                    read_names.add(name)
                else:
                    if first in local[owner] or first in _CORE:
                        continue
                    if first in namespaces:
                        read_names.add(first)
                if (prefix and first == prefix) or (not prefix and first in namespaces):
                    selected_name = rest.split(".", 1)[0] if prefix else first
                    targets = namespaces.get(selected_name, [])
                    credit(targets, "dart_import_binding")
                    connect(owner, record, targets)
            for definition in matching:
                if prefix:
                    used = (
                        definition.name in read_names
                        if directive.get("show")
                        else bool(read_names)
                    )
                elif directive.get("show"):
                    used = definition.name in read_names
                else:
                    used = bool(read_names)
                if used:
                    definition.references += 1
                    definition.heuristic_refs["dart_import_binding"] = 1.0
                    rescued += 1
                elif unknown and not prefix:
                    potential = {
                        use.split(".", 1)[0]
                        for use in uses
                        if re.fullmatch(r"[^\W\d]\w*", use.split(".", 1)[0])
                    } - bound_names
                    if directive.get("show"):
                        potential &= set(directive["show"])
                    potential -= set(directive.get("hide", []))
                    if potential or possible_extensions:
                        reason = (
                            "Dart import provider namespace unresolved: "
                            + ", ".join(directive.get("sources", []))
                        )
                        if possible_extensions:
                            calls = sorted(
                                {
                                    f"{call['receiver']}.{call['member']} at line {call['line']}"
                                    for call in possible_extensions
                                }
                            )
                            reason += "; possible extension call " + ", ".join(calls)
                        if reason not in definition.why_confidence_reduced:
                            definition.why_confidence_reduced.append(reason)
                        uncertain += 1
    return {
        "binding_reads": rescued,
        "unresolved_imports": uncertain,
        "processed_files": sorted(metadata),
        "call_graph": {key: sorted(targets) for key, targets in call_graph.items()},
    }
