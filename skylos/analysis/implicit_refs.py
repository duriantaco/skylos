import re
from pathlib import Path

from skylos.core.result_cache import read_trace_payload


def _compile_pattern_ref(pattern):
    escaped = re.escape(pattern).replace(r"\*", ".*")
    return re.compile(f"^{escaped}$")


def is_specific_name_pattern(pattern) -> bool:
    """Whether a wildcard name pattern keeps a literal identifier part.

    ``handle_*`` or ``*_queries`` name a family of attributes. ``*``, ``_*`` or
    ``*.*`` come from a fully computed name and would match every definition.
    """
    if not isinstance(pattern, str) or not pattern:
        return False
    if "*" not in pattern:
        return True
    literal = pattern.replace("*", "").strip("_")
    return len(literal) >= 2 and any(ch.isalnum() for ch in literal)


def _owner_of(qualified_name: str) -> str:
    return qualified_name.rsplit(".", 1)[0] if "." in qualified_name else ""


class ImplicitRefTracker:
    def __init__(self):
        self.known_refs = set()
        self.known_qualified_refs = set()
        self.pattern_refs = []
        self._compiled_patterns = []
        self.f_string_patterns = {}
        self.coverage_hits = set()
        self.covered_files_lines = {}
        self.traced_calls = set()
        self.traced_by_file = {}
        self._traced_by_basename = {}
        self._coverage_by_basename = {}
        # Name patterns reached through ``self``/``cls`` or a class object:
        # (regex, confidence, pattern, owner class). They apply to members of
        # that class and of its subclasses in any module.
        self._class_patterns = []
        self._subclasses_of = {}
        # Reflection over a module object (``dir(module)``, ``vars(module)``,
        # ``inspect.getmembers(module)``), resolved once all modules are known.
        # A name filter is (issubclass bases, name patterns); empty means none.
        # reflective_params: (function, positional index) -> {name filter}
        self.reflective_params = {}
        # module_call_args: (callee, positional index, imported name)
        self.module_call_args = set()
        # reflected_modules: {(imported name, name filter)}
        self.reflected_modules = set()
        # Source-owned discovery sites: (base, caller, module, line, kind,
        # reflected receiver). A base name alone does not establish liveness.
        self.discovered_subclass_bases = set()

    def __getattr__(self, name):
        if name == "known_qualified_refs":
            self.known_qualified_refs = set()
            return self.known_qualified_refs
        defaults = {
            "_class_patterns": list,
            "_subclasses_of": dict,
            "reflective_params": dict,
            "module_call_args": set,
            "reflected_modules": set,
            "discovered_subclass_bases": set,
        }
        if name in defaults:
            value = defaults[name]()
            setattr(self, name, value)
            return value
        raise AttributeError(
            f"'{type(self).__name__}' object has no attribute '{name}'"
        )

    def add_pattern_ref(self, pattern, confidence, source_module=None):
        if not is_specific_name_pattern(pattern):
            return
        self.pattern_refs.append((pattern, confidence))
        regex = _compile_pattern_ref(pattern)
        self._compiled_patterns.append((regex, confidence, pattern, source_module))

    def add_class_pattern_ref(self, pattern, confidence, owner_class):
        if not owner_class or not is_specific_name_pattern(pattern):
            return
        entry = (_compile_pattern_ref(pattern), confidence, pattern, owner_class)
        if any(existing[1:] == entry[1:] for existing in self._class_patterns):
            return
        self._class_patterns.append(entry)

    def set_class_hierarchy(self, children_of):
        """Record direct subclasses so class-scoped patterns reach overrides."""
        closure = {}
        for owner in {entry[3] for entry in self._class_patterns}:
            seen = set()
            stack = list(children_of.get(owner, ()))
            while stack:
                child = stack.pop()
                if child in seen:
                    continue
                seen.add(child)
                stack.extend(children_of.get(child, ()))
            closure[owner] = seen
        self._subclasses_of = closure

    def merge(self, other) -> None:
        """Fold the tracker a worker process returned into this one.

        Workers fill their own module-level tracker, so patterns found while
        visiting files in a process pool reach the parent only through here.
        """
        if other is None or other is self:
            return
        self.known_refs.update(getattr(other, "known_refs", ()) or ())
        self.known_qualified_refs.update(
            getattr(other, "known_qualified_refs", ()) or ()
        )
        seen = {
            (entry[2], entry[1], entry[3] if len(entry) > 3 else None)
            for entry in self._compiled_patterns
        }
        for entry in getattr(other, "_compiled_patterns", ()) or ():
            source_module = entry[3] if len(entry) > 3 else None
            key = (entry[2], entry[1], source_module)
            if key in seen:
                continue
            seen.add(key)
            self.pattern_refs.append((entry[2], entry[1]))
            self._compiled_patterns.append(
                (entry[0], entry[1], entry[2], source_module)
            )
        for entry in getattr(other, "_class_patterns", ()) or ():
            self.add_class_pattern_ref(entry[2], entry[1], entry[3])
        for key, filters in (getattr(other, "reflective_params", None) or {}).items():
            self.reflective_params.setdefault(key, set()).update(filters)
        self.module_call_args.update(getattr(other, "module_call_args", ()) or ())
        self.reflected_modules.update(getattr(other, "reflected_modules", ()) or ())
        self.discovered_subclass_bases.update(
            getattr(other, "discovered_subclass_bases", ()) or ()
        )

    def reset_for_worker_file(self) -> None:
        """Start a pool worker's file with an empty tracker.

        The parent merges each returned tracker, so a worker only needs what
        the current file adds; carrying earlier files would re-send them.
        """
        self.known_refs = set()
        self.known_qualified_refs = set()
        self.pattern_refs = []
        self._compiled_patterns = []
        self.f_string_patterns = {}
        self.coverage_hits = set()
        self.covered_files_lines = {}
        self.traced_calls = set()
        self.traced_by_file = {}
        self._traced_by_basename = {}
        self._coverage_by_basename = {}
        self._class_patterns = []
        self._subclasses_of = {}
        self.reflective_params = {}
        self.module_call_args = set()
        self.reflected_modules = set()
        self.discovered_subclass_bases = set()

    def reset_dynamic_refs(self) -> None:
        self._class_patterns.clear()
        self._subclasses_of.clear()
        self.reflective_params.clear()
        self.module_call_args.clear()
        self.reflected_modules.clear()
        self.discovered_subclass_bases.clear()

    def _class_pattern_match(self, definition):
        if not self._class_patterns:
            return None
        owner = _owner_of(str(getattr(definition, "name", "") or ""))
        if not owner:
            return None
        simple_name = definition.simple_name
        for regex, confidence, pattern, owner_class in self._class_patterns:
            if owner != owner_class and owner not in self._subclasses_of.get(
                owner_class, ()
            ):
                continue
            if regex.match(simple_name):
                return confidence, pattern
        return None

    def should_mark_as_used(self, definition):
        if getattr(definition, "name", None) in self.known_qualified_refs:
            return True, 100, "entrypoint (pyproject)"

        simple_name = definition.simple_name

        if simple_name in self.known_refs:
            return True, 95, "dynamic reference"

        def_qname = getattr(definition, "name", "")
        for entry in self._compiled_patterns:
            regex, confidence, pattern = entry[0], entry[1], entry[2]
            source_module = entry[3] if len(entry) > 3 else None
            if source_module and not def_qname.startswith(source_module + "."):
                continue
            if regex.match(simple_name):
                return True, confidence, f"pattern '{pattern}'"

        class_match = self._class_pattern_match(definition)
        if class_match is not None:
            confidence, pattern = class_match
            return True, confidence, f"pattern '{pattern}'"

        def_file = str(definition.filename)
        def_line = definition.line
        def_basename = Path(def_file).name

        if self._traced_by_basename:
            func_name = simple_name
            for traced_file in self._traced_by_basename.get(def_basename, []):
                funcs = self.traced_by_file[traced_file]
                if func_name in funcs:
                    for traced_line in funcs[func_name]:
                        if abs(traced_line - def_line) <= 5:
                            return True, 100, "executed (call trace)"

        if (def_file, def_line) in self.coverage_hits:
            return True, 100, "executed (coverage)"

        if self._coverage_by_basename:
            for cov_file in self._coverage_by_basename.get(def_basename, []):
                lines = self.covered_files_lines.get(cov_file, set())

                if def_line in lines:
                    return True, 100, "executed (coverage)"

                def_type = getattr(definition, "type", None)
                if def_type in ("function", "method"):
                    check_range = set(range(def_line, def_line + 51))
                    if lines & check_range:
                        return True, 100, "executed (coverage)"

        return False, 0, None

    def load_trace(self, trace_file=".skylos_trace"):
        path = Path(trace_file)
        if not path.exists():
            return False

        data = read_trace_payload(path)
        if data is None:
            return False

        try:
            for item in data.get("calls", []):
                filename = item["file"]
                func_name = item["function"]
                line = item["line"]

                self.traced_calls.add((filename, func_name, line))

                if filename not in self.traced_by_file:
                    self.traced_by_file[filename] = {}
                if func_name not in self.traced_by_file[filename]:
                    self.traced_by_file[filename][func_name] = []
                self.traced_by_file[filename][func_name].append(line)

            for traced_file in self.traced_by_file:
                basename = Path(traced_file).name
                if basename not in self._traced_by_basename:
                    self._traced_by_basename[basename] = []
                self._traced_by_basename[basename].append(traced_file)

            return len(self.traced_calls) > 0

        except Exception as e:
            import logging

            logging.getLogger("Skylos").warning(f"Failed to load trace data: {e}")
            return False

    def load_coverage(self, coverage_file=".coverage"):
        path = Path(coverage_file)
        if not path.exists():
            return None

        try:
            import sqlite3

            conn = sqlite3.connect(str(path))
            cursor = conn.cursor()

            cursor.execute("SELECT id, path FROM file")
            files = {}
            for row in cursor.fetchall():
                files[row[0]] = row[1]

            cursor.execute("SELECT file_id, numbits FROM line_bits")
            for file_id, numbits in cursor.fetchall():
                if file_id in files:
                    filename = files[file_id]
                    if filename not in self.covered_files_lines:
                        self.covered_files_lines[filename] = set()

                    for byte_idx, byte in enumerate(numbits):
                        for bit_idx in range(8):
                            if byte & (1 << bit_idx):
                                line = byte_idx * 8 + bit_idx
                                self.coverage_hits.add((filename, line))
                                self.covered_files_lines[filename].add(line)

            conn.close()

            for cov_file in self.covered_files_lines:
                basename = Path(cov_file).name
                if basename not in self._coverage_by_basename:
                    self._coverage_by_basename[basename] = []
                self._coverage_by_basename[basename].append(cov_file)

            return len(self.coverage_hits) > 0

        except Exception as e:
            import logging

            logging.getLogger("Skylos").warning(f"Failed to load coverage: {e}")
            return False


pattern_tracker = ImplicitRefTracker()
