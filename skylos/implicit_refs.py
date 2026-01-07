import re
import json
from pathlib import Path


class ImplicitRefTracker:
    def __init__(self):
        self.known_refs = set()
        self.pattern_refs = []
        self.f_string_patterns = {}
        self.coverage_hits = set()
        self.covered_files_lines = {}
        self.traced_calls = set()
        self.traced_by_file = {}  # {filename: {func_name: [line1, line2, ...]}}

    def should_mark_as_used(self, definition):
        simple_name = definition.simple_name

        if simple_name in self.known_refs:
            return True, 95, "dynamic reference"

        for pattern, confidence in self.pattern_refs:
            regex = "^" + pattern.replace("*", ".*") + "$"
            if re.match(regex, simple_name):
                return True, confidence, f"pattern '{pattern}'"

        if self.traced_by_file:
            def_file = str(definition.filename)
            def_line = definition.line
            func_name = simple_name

            for traced_file, funcs in self.traced_by_file.items():
                if Path(traced_file).name == Path(def_file).name:
                    if func_name in funcs:
                        traced_lines = funcs[func_name]
                        for traced_line in traced_lines:
                            if abs(traced_line - def_line) <= 5:
                                return True, 100, "executed (call trace)"

        def_file = str(definition.filename)
        def_line = definition.line

        if (def_file, def_line) in self.coverage_hits:
            return True, 100, "executed (coverage)"

        def_base = Path(def_file).name
        for cov_file, cov_line in self.coverage_hits:
            if cov_line == def_line and Path(str(cov_file)).name == def_base:
                return True, 100, "executed (coverage)"

        if self.covered_files_lines:
            for cov_file, lines in self.covered_files_lines.items():
                if Path(cov_file).name == def_base:
                    def_type = getattr(definition, "type", None)
                    if def_type in ("function", "method"):
                        for offset in range(50):
                            if (def_line + offset) in lines:
                                return True, 100, "executed (coverage)"
                    else:
                        if def_line in lines:
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
            return len(self.coverage_hits) > 0

        except Exception as e:
            import logging

            logging.getLogger("Skylos").warning(f"Failed to load coverage: {e}")
            return False


pattern_tracker = ImplicitRefTracker()
