import re
import json
from pathlib import Path


class ImplicitRefTracker:
    def __init__(self):
        self.known_refs = set()
        self.pattern_refs = []
        self._compiled_patterns = []
        self.f_string_patterns = {}
        self.coverage_hits = set()
        self.covered_files_lines = {}
        self.traced_calls = set()
        self.traced_by_file = {}
        self._traced_by_basename = {}
        self._coverage_by_basename = {}

    def add_pattern_ref(self, pattern, confidence):
        self.pattern_refs.append((pattern, confidence))
        regex = re.compile("^" + pattern.replace("*", ".*") + "$")
        self._compiled_patterns.append((regex, confidence, pattern))

    def should_mark_as_used(self, definition):
        simple_name = definition.simple_name

        if simple_name in self.known_refs:
            return True, 95, "dynamic reference"

        for regex, confidence, pattern in self._compiled_patterns:
            if regex.match(simple_name):
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

        # Direct coverage hit check - O(1)
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

        try:
            data = json.loads(path.read_text())

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