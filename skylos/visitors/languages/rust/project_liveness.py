"""Project-wide Rust dead-code evidence, applied after the global reference pass.

Every step here can only keep a candidate alive or make Skylos abstain:

- `use` trees, `pub(crate) use` re-exports, `as` aliases and `Type::item`
  paths credit the item they resolve to (`project_model.py`);
- a method called on a receiver whose type the file visitor qualified by its
  module path credits that method on every same-named type of the crate;
- `#[allow(dead_code)]` / `#[allow(unused_imports)]` (item, impl, module or
  crate scope, `expect` and `cfg_attr` forms included) keep their items out of
  the report and alive as seeds, like rustc;
- `#[cfg(...)]` alternatives of one function share liveness;
- an unread import is reported only when it is provably not a trait. A trait
  import is used by method calls and `Type::method` paths that never name it,
  so unresolved, external and project trait imports become abstentions.
"""

from __future__ import annotations

from pathlib import Path

from .project_model import (
    EXTERNAL,
    UNKNOWN,
    allows_dead_code,
    allows_unused_imports,
)

POSSIBLE_TRAIT_IMPORT = (
    "possible trait import: a trait brings its methods into scope without "
    "its name being read"
)
ALLOWED_DEAD_CODE = "#[allow(dead_code)] in scope"
ALLOWED_UNUSED_IMPORT = "#[allow(unused_imports)] in scope"

# Prelude traits of each edition: importing them again changes nothing.
_PRELUDE_TRAITS = {
    "std::marker::Send": "2015",
    "std::marker::Sized": "2015",
    "std::marker::Sync": "2015",
    "std::marker::Unpin": "2015",
    "std::marker::Copy": "2015",
    "std::ops::Drop": "2015",
    "std::ops::Fn": "2015",
    "std::ops::FnMut": "2015",
    "std::ops::FnOnce": "2015",
    "std::borrow::ToOwned": "2015",
    "std::clone::Clone": "2015",
    "std::cmp::PartialEq": "2015",
    "std::cmp::PartialOrd": "2015",
    "std::cmp::Eq": "2015",
    "std::cmp::Ord": "2015",
    "std::convert::AsRef": "2015",
    "std::convert::AsMut": "2015",
    "std::convert::Into": "2015",
    "std::convert::From": "2015",
    "std::default::Default": "2015",
    "std::iter::Iterator": "2015",
    "std::iter::Extend": "2015",
    "std::iter::IntoIterator": "2015",
    "std::iter::DoubleEndedIterator": "2015",
    "std::iter::ExactSizeIterator": "2015",
    "std::string::ToString": "2015",
    "std::convert::TryFrom": "2021",
    "std::convert::TryInto": "2021",
    "std::iter::FromIterator": "2021",
    "std::future::Future": "2024",
    "std::future::IntoFuture": "2024",
}

# Standard-library items that are known not to be traits.
_STD_NON_TRAITS = {
    "std::borrow": {"Cow"},
    "std::cell": {"Cell", "RefCell", "OnceCell", "Ref", "RefMut", "UnsafeCell"},
    "std::cmp": {"Ordering", "Reverse"},
    "std::collections": {
        "BTreeMap",
        "BTreeSet",
        "BinaryHeap",
        "HashMap",
        "HashSet",
        "LinkedList",
        "VecDeque",
    },
    "std::collections::hash_map": {"Entry", "DefaultHasher", "RandomState"},
    "std::collections::btree_map": {"Entry"},
    "std::env": {"Args", "ArgsOs", "Vars", "VarError"},
    "std::ffi": {"CStr", "CString", "OsStr", "OsString", "NulError"},
    "std::fmt": {"Arguments", "Error", "Formatter", "Result", "Alignment"},
    "std::fs": {
        "DirEntry",
        "File",
        "FileType",
        "Metadata",
        "OpenOptions",
        "Permissions",
        "ReadDir",
    },
    "std::hash": {"BuildHasherDefault", "DefaultHasher"},
    "std::io": {
        "BufReader",
        "BufWriter",
        "Cursor",
        "Empty",
        "Error",
        "ErrorKind",
        "IoSlice",
        "IoSliceMut",
        "LineWriter",
        "Result",
        "SeekFrom",
        "Sink",
        "Stderr",
        "StderrLock",
        "Stdin",
        "StdinLock",
        "Stdout",
        "StdoutLock",
    },
    "std::marker": {"PhantomData", "PhantomPinned"},
    "std::mem": {"ManuallyDrop", "MaybeUninit", "Discriminant"},
    "std::net": {
        "IpAddr",
        "Ipv4Addr",
        "Ipv6Addr",
        "Shutdown",
        "SocketAddr",
        "SocketAddrV4",
        "SocketAddrV6",
        "TcpListener",
        "TcpStream",
        "UdpSocket",
    },
    "std::num": {
        "NonZeroI32",
        "NonZeroI64",
        "NonZeroU8",
        "NonZeroU16",
        "NonZeroU32",
        "NonZeroU64",
        "NonZeroUsize",
        "ParseFloatError",
        "ParseIntError",
        "TryFromIntError",
        "Wrapping",
    },
    "std::ops": {
        "ControlFlow",
        "Range",
        "RangeFrom",
        "RangeFull",
        "RangeInclusive",
        "RangeTo",
        "RangeToInclusive",
        "Bound",
    },
    "std::path": {"Component", "Components", "Path", "PathBuf", "Prefix"},
    "std::pin": {"Pin"},
    "std::process": {
        "Child",
        "ChildStderr",
        "ChildStdin",
        "ChildStdout",
        "Command",
        "ExitCode",
        "ExitStatus",
        "Output",
        "Stdio",
    },
    "std::ptr": {"NonNull"},
    "std::rc": {"Rc", "Weak"},
    "std::str": {"Chars", "CharIndices", "Utf8Error", "Lines", "Split"},
    "std::string": {"FromUtf8Error", "String"},
    "std::sync": {
        "Arc",
        "Barrier",
        "Condvar",
        "LazyLock",
        "Mutex",
        "MutexGuard",
        "Once",
        "OnceLock",
        "RwLock",
        "RwLockReadGuard",
        "RwLockWriteGuard",
        "Weak",
    },
    "std::sync::atomic": {
        "AtomicBool",
        "AtomicI32",
        "AtomicI64",
        "AtomicU8",
        "AtomicU16",
        "AtomicU32",
        "AtomicU64",
        "AtomicUsize",
        "Ordering",
    },
    "std::sync::mpsc": {"Receiver", "Sender", "SyncSender", "RecvError", "SendError"},
    "std::task": {"Context", "Poll", "Waker", "RawWaker"},
    "std::thread": {"JoinHandle", "Builder", "Thread", "ThreadId", "Scope"},
    "std::time": {"Duration", "Instant", "SystemTime", "SystemTimeError"},
    "std::vec": {"Vec", "IntoIter"},
    "std::boxed": {"Box"},
    "std::option": {"Option"},
    "std::result": {"Result"},
}


# Standard macros expand to standard-library code only (`write!`/`writeln!`
# are recorded as a `write_fmt` call by the visitor).
_STD_MACROS = frozenset(
    {
        "assert",
        "assert_eq",
        "assert_ne",
        "debug_assert",
        "debug_assert_eq",
        "debug_assert_ne",
        "cfg",
        "matches",
        "vec",
        "format",
        "format_args",
        "write",
        "writeln",
        "print",
        "println",
        "eprint",
        "eprintln",
        "panic",
        "todo",
        "unimplemented",
        "unreachable",
        "dbg",
        "stringify",
        "concat",
        "env",
        "option_env",
        "line",
        "column",
        "file",
        "module_path",
        "include_str",
        "include_bytes",
    }
)

# Complete member lists of common standard traits. An import of one of them
# is reportable only when none of these names is reached in its scope.
_STD_TRAIT_MEMBERS = {
    "std::string::ToString": {"to_string"},
    "std::borrow::ToOwned": {"Owned", "to_owned", "clone_into"},
    "std::io::Write": {
        "write",
        "write_vectored",
        "is_write_vectored",
        "flush",
        "write_all",
        "write_all_vectored",
        "write_fmt",
        "by_ref",
    },
    "std::io::Read": {
        "read",
        "read_vectored",
        "is_read_vectored",
        "read_to_end",
        "read_to_string",
        "read_exact",
        "read_buf",
        "read_buf_exact",
        "by_ref",
        "bytes",
        "chain",
        "take",
    },
    "std::io::BufRead": {
        "fill_buf",
        "consume",
        "has_data_left",
        "read_until",
        "skip_until",
        "read_line",
        "split",
        "lines",
    },
    "std::io::Seek": {
        "seek",
        "rewind",
        "stream_len",
        "stream_position",
        "seek_relative",
    },
    "std::io::IsTerminal": {"is_terminal"},
    "std::fmt::Write": {"write_str", "write_char", "write_fmt"},
    "std::fmt::Display": {"fmt"},
    "std::fmt::Debug": {"fmt"},
    "std::error::Error": {"source", "description", "cause", "provide", "type_id"},
    "std::str::FromStr": {"from_str", "Err"},
    "std::hash::Hash": {"hash", "hash_slice"},
    "std::borrow::Borrow": {"borrow"},
    "std::borrow::BorrowMut": {"borrow_mut"},
    "std::any::Any": {"type_id"},
    "std::ops::Deref": {"deref", "Target"},
    "std::ops::DerefMut": {"deref_mut"},
    "std::os::unix::fs::PermissionsExt": {"mode", "set_mode", "from_mode"},
    "std::os::unix::fs::OpenOptionsExt": {"mode", "custom_flags"},
    "std::os::unix::fs::FileTypeExt": {
        "is_block_device",
        "is_char_device",
        "is_fifo",
        "is_socket",
    },
    "std::os::unix::ffi::OsStrExt": {"from_bytes", "as_bytes"},
    "std::os::unix::ffi::OsStringExt": {"from_vec", "into_vec"},
    "std::os::fd::AsRawFd": {"as_raw_fd"},
    "std::os::unix::io::AsRawFd": {"as_raw_fd"},
    "std::os::fd::FromRawFd": {"from_raw_fd"},
    "std::os::unix::io::FromRawFd": {"from_raw_fd"},
    "std::os::fd::IntoRawFd": {"into_raw_fd"},
    "std::os::unix::io::IntoRawFd": {"into_raw_fd"},
}


def _std_path(path):
    if path and path[0] in {"core", "alloc"}:
        return ("std", *path[1:])
    return tuple(path)


def _edition_at_least(edition, minimum):
    try:
        return int(edition) >= int(minimum)
    except (TypeError, ValueError):
        return False


class _Liveness:
    def __init__(self, definitions, project):
        self.definitions = definitions
        self.project = project
        self.by_location = {}
        for definition in definitions.values():
            filename = str(definition.filename)
            if not filename.endswith(".rs"):
                continue
            try:
                path = Path(filename).resolve()
            except (OSError, RuntimeError, ValueError):
                continue
            self.by_location.setdefault(
                (path, definition.line, definition.simple_name), []
            ).append(definition)

    def definitions_of(self, item):
        return self.by_location.get((item.file, item.line, item.name), ())

    def credit_item(self, item, caller=None):
        for definition in self.definitions_of(item):
            if definition.type == "import":
                continue
            if caller is not None and caller is definition:
                continue
            if definition.references == 0:
                definition.references = 1
            if caller is not None:
                definition.called_by.add(caller.name)
                caller.calls.add(definition.name)

    def credit_target(self, target, caller=None):
        if target[0] == "item":
            self.credit_item(target[1], caller)
        elif target[0] == "member":
            for method in self.project.methods_of(target[1], target[2]):
                self.credit_item(method, caller)

    def caller_of(self, owner):
        if owner is None:
            return None
        found = [
            definition
            for definition in self.definitions_of(owner)
            if definition.type in {"function", "method"}
        ]
        return found[0] if len(found) == 1 else None

    def apply_paths(self):
        project = self.project
        used = set()
        for reference in project.path_refs:
            caller = self.caller_of(reference.owner)
            for target in project.resolve(
                reference.module, reference.segments, used, local=reference.local
            ):
                self.credit_target(target, caller)
        for item in project.uses:
            if item.kind == "glob":
                # `use self::State::*;` brings the enum's variants into scope
                # for its patterns and constructors.
                for target in project.resolve(item.module, item.path, used):
                    if target[0] == "item" and target[1].kind in {"enum", "type"}:
                        self.credit_item(target[1])
            else:
                project.resolve_use(item, used)
        for item in project.uses:
            if item.kind != "use":
                continue
            imports = [
                definition
                for definition in self.definitions_of(item)
                if definition.type == "import"
            ]
            if item in used:
                # Another module reads this binding, e.g. `flags::Mode` after
                # `pub(crate) use lowargs::Mode;` in flags/mod.rs.
                for definition in imports:
                    definition.references = max(definition.references, 1)
            if (
                item in used
                or item.public
                or any(definition.references > 0 for definition in imports)
            ):
                for target in project.resolve_use(item):
                    self.credit_target(target)

    def apply_receiver_methods(self, references):
        """`args.quit_after_match()` with `args: &HiArgs` imported from a
        re-exporting module: the visitor qualifies the receiver by module path
        (`flags.HiArgs`), which names no definition. Credit the method on the
        crate's types of that name."""
        seen = set()
        for reference, ref_file in references:
            ref_file = str(ref_file)
            if not ref_file.endswith(".rs") or "." not in reference:
                continue
            if reference.startswith(("~", "@")):
                continue
            owner, _, method = reference.rpartition(".")
            type_name = owner.rpartition(".")[2]
            if not type_name[:1].isupper() or not method:
                continue
            crates = self.project.crate_keys(ref_file)
            key = (owner, method, crates)
            if key in seen:
                continue
            seen.add(key)
            for type_item in self.project.types_named(crates, type_name):
                for item in self.project.methods_of(type_item, method):
                    self.credit_item(item)

    def apply_cfg_alternatives(self):
        """`#[cfg(unix)] fn imp` and `#[cfg(not(unix))] fn imp` are one
        function in every build; a call reaches whichever is compiled."""
        groups = {}
        for (path, _line, name), items in self.project.items_by_location.items():
            for item in items:
                if item.kind not in {"fn", "method"} or not item.cfg:
                    continue
                scope = id(item.owner) if item.owner is not None else id(item.module)
                groups.setdefault((path, scope, name), []).append(item)
        for items in groups.values():
            if len(items) < 2:
                continue
            definitions = [
                definition for item in items for definition in self.definitions_of(item)
            ]
            if any(definition.references > 0 for definition in definitions):
                for definition in definitions:
                    definition.references = max(definition.references, 1)

    def apply_lint_levels(self):
        for key, definitions in self.by_location.items():
            items = self.project.items_by_location.get(key, ())
            if not items:
                continue
            for definition in definitions:
                if definition.type == "import":
                    allowed = any(
                        allows_unused_imports(item.lints)
                        for item in items
                        if item.kind == "use"
                    )
                    reason = ALLOWED_UNUSED_IMPORT
                else:
                    allowed = any(
                        allows_dead_code(item.lints)
                        for item in items
                        if item.kind != "use"
                    )
                    reason = ALLOWED_DEAD_CODE
                if not allowed:
                    continue
                if definition.references == 0 and not definition.is_exported:
                    definition.confidence = 0
                    definition.skip_reason = reason
                    definition.suppression_code = "rust_allow_lint"
                # rustc treats allowed items as seeds: their callees stay live.
                definition.references += 1


def _members_unreached(definition, members, project, writer=None):
    """No member of the trait is called or named in the import's scope, and
    no macro that could expand to such a call is invoked there.

    `members=None` stands for an item of unknown kind: then the scope must
    call no method and name no associated item at all."""
    facts = getattr(definition, "rust_reference_facts", None)
    scope = facts.get("scope_members") if isinstance(facts, dict) else None
    if scope is None:
        return False
    names = set()
    for name in scope:
        if name.endswith("!"):
            continue
        member, _, kind = name.partition("@")
        # `write!` on a String reaches fmt::Write, on a byte buffer io::Write.
        if not kind or writer is None or kind == writer:
            names.add(member)
    macros = {name[:-1] for name in scope if name.endswith("!")} - _STD_MACROS
    if members is None:
        return not names and not macros
    if set(members) & names:
        return False
    project_macros = project.macro_names if project is not None else set()
    return not (macros & project_macros)


def _import_reportable(definition, items, project):
    """An unread import is reported only when it cannot be a trait used
    through its methods: a module, function, macro or constant; a project
    item that is not a trait; an enum variant; a known non-trait std type;
    a prelude trait the edition already imports; or a trait with a known
    member list none of whose members the scope reaches."""
    name = definition.simple_name
    if name[:1].islower() or name[:1] == "_":
        return True  # Modules, functions, macros and crates are never traits.
    if name.isupper() and len(name) > 1:
        return True  # A constant or static.
    uses = [item for item in items if item.kind == "use" and item.path]
    if not uses:
        return False
    for item in uses:
        path = item.path
        original = path[-1]
        if original[:1].islower() or (original.isupper() and len(original) > 1):
            return True
        if len(path) >= 2 and path[-2][:1].isupper():
            # `use syn::Fields::Unit`: an enum variant or associated item.
            return True
        targets = project.resolve_use(item) if project is not None else [UNKNOWN]
        resolved = [target for target in targets if target not in (UNKNOWN, EXTERNAL)]
        if resolved and len(resolved) == len(targets):
            traits = [
                target[1]
                for target in resolved
                if target[0] == "item" and target[1].kind == "trait"
            ]
            members = set().union(*(trait.members for trait in traits))
            return not members or _members_unreached(definition, members, project)
        normalized = _std_path(path)
        if normalized[:1] != ("std",):
            # An external or unresolved item of unknown kind.
            return _members_unreached(definition, None, project)
        joined = "::".join(normalized)
        if normalized[-1] in _STD_NON_TRAITS.get("::".join(normalized[:-1]), ()):
            return True
        minimum = _PRELUDE_TRAITS.get(joined)
        edition = (
            project.edition_by_file.get(item.file) if project is not None else None
        )
        # These allocation traits are absent from the core prelude. One source
        # file may belong to both std and no_std Cargo targets.
        if joined in {"std::string::ToString", "std::borrow::ToOwned"} and any(
            use.module.crate.may_use_core_prelude for use in uses
        ):
            minimum = None
        if minimum is not None and _edition_at_least(edition, minimum):
            return True
        return _members_unreached(
            definition,
            _STD_TRAIT_MEMBERS.get(joined),
            project,
            writer={"std::io::Write": "io", "std::fmt::Write": "fmt"}.get(joined),
        )
    return False


def apply_import_abstentions(definitions, project):
    for definition in definitions.values():
        if definition.type != "import" or definition.references != 0:
            continue
        if definition.is_exported or not str(definition.filename).endswith(".rs"):
            continue
        if getattr(definition, "skip_reason", None):
            continue
        items = ()
        if project is not None:
            items = project.items_at(
                definition.filename, definition.line, definition.simple_name
            )
        if _import_reportable(definition, items, project):
            continue
        if POSSIBLE_TRAIT_IMPORT not in definition.why_confidence_reduced:
            definition.why_confidence_reduced.append(POSSIBLE_TRAIT_IMPORT)


def apply_project_liveness(definitions, references, project, *, exclude_folders=()):
    """Credit resolved Rust references, honour lint levels, then decide which
    unread imports are reportable."""
    if project is not None and project.complete:
        liveness = _Liveness(definitions, project)
        from .include_liveness import apply_include_liveness

        apply_include_liveness(liveness, exclude_folders)
        liveness.apply_paths()
        liveness.apply_receiver_methods(references)
        liveness.apply_cfg_alternatives()
        liveness.apply_lint_levels()
    else:
        project = None
    apply_import_abstentions(definitions, project)
