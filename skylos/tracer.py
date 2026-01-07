import sys
import json
import threading
from pathlib import Path
from collections import defaultdict


class CallTracer:
    def __init__(self, include_patterns=None, exclude_patterns=None):
        self.called_functions = set()
        self.call_counts = defaultdict(int)
        self._lock = threading.Lock()
        self._previous_profile = None
        self._previous_thread_profile = None
        self._tracing = False

        self.include_patterns = include_patterns or []
        self.exclude_patterns = exclude_patterns or [
            "site-packages",
            "venv",
            ".venv",
            "/lib/python",
            "/site-packages/pytest",
            "/site-packages/_pytest",
            "/site-packages/pluggy",
            "<frozen",
            "<string>",
        ]

    def _should_trace_file(self, filename):
        if not filename:
            return False

        if self.include_patterns:
            for pat in self.include_patterns:
                if pat in filename:
                    return True
            return False

        for pattern in self.exclude_patterns:
            if pattern in filename:
                return False

        return True

    def _trace_calls(self, frame, event, arg):
        if event == "call":
            code = frame.f_code
            filename = code.co_filename

            if self._should_trace_file(filename):
                func_name = code.co_name
                lineno = code.co_firstlineno

                key = (filename, func_name, lineno)

                with self._lock:
                    self.called_functions.add(key)
                    self.call_counts[key] += 1

        return self._trace_calls

    def start(self):
        if not self._tracing:
            self._previous_profile = sys.getprofile()
            self._previous_thread_profile = threading.getprofile()
            sys.setprofile(self._trace_calls)
            threading.setprofile(self._trace_calls)
            self._tracing = True

    def stop(self):
        if self._tracing:
            sys.setprofile(self._previous_profile)
            threading.setprofile(self._previous_thread_profile)
            self._tracing = False

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()

    def save(self, filepath=".skylos_trace"):
        data = {
            "version": 1,
            "calls": [
                {
                    "file": filename,
                    "function": func_name,
                    "line": lineno,
                    "count": self.call_counts[(filename, func_name, lineno)],
                }
                for filename, func_name, lineno in sorted(self.called_functions)
            ],
        }

        Path(filepath).write_text(json.dumps(data, indent=2))
        print(f"Saved {len(self.called_functions)} traced function calls to {filepath}")

    @classmethod
    def load(cls, filepath=".skylos_trace"):
        path = Path(filepath)
        if not path.exists():
            return None

        try:
            data = json.loads(path.read_text())
            calls = set()
            for item in data.get("calls", []):
                calls.add((item["file"], item["function"], item["line"]))
            return calls
        except Exception as e:
            print(f"Warning: Failed to load trace data: {e}")
            return None

    def get_stats(self):
        files = set()
        for f, _, _ in self.called_functions:
            files.add(f)

        return {
            "total_calls": len(self.called_functions),
            "unique_functions": len(self.called_functions),
            "files_traced": len(files),
            "files": sorted(files),
        }


_global_tracer = None


def start_tracing(include_patterns=None, exclude_patterns=None):
    global _global_tracer
    _global_tracer = CallTracer(include_patterns, exclude_patterns)
    _global_tracer.start()
    return _global_tracer


def stop_tracing(save_path=".skylos_trace"):
    global _global_tracer
    if _global_tracer:
        _global_tracer.stop()
        _global_tracer.save(save_path)
        stats = _global_tracer.get_stats()
        print(
            f"Traced {stats['unique_functions']} functions across {stats['files_traced']} files"
        )
        return _global_tracer
    return None


def pytest_configure(config):
    if config.getoption("--skylos-trace", default=False):
        include = config.getoption("--skylos-trace-include", default=None)
        if include:
            include_patterns = include.split(",")
        else:
            include_patterns = None
        start_tracing(include_patterns=include_patterns)
        print("Skylos call tracing enabled")


def pytest_unconfigure(config):
    if config.getoption("--skylos-trace", default=False):
        stop_tracing()


def pytest_addoption(parser):
    parser.addoption(
        "--skylos-trace",
        action="store_true",
        default=False,
        help="Enable Skylos call tracing",
    )
    parser.addoption(
        "--skylos-trace-include",
        action="store",
        default=None,
        help="Comma separated list of path patterns to include in tracing",
    )


if __name__ == "__main__":
    import runpy

    if len(sys.argv) < 2:
        print("Usage: python -m skylos_trace <script.py> [args...]")
        print("       python -m skylos_trace -m <module> [args...]")
        sys.exit(1)

    sys.argv = sys.argv[1:]

    if sys.argv[0] == "-m":
        if len(sys.argv) < 2:
            print("Error: -m requires module name")
            sys.exit(1)
        module_name = sys.argv[1]
        sys.argv = sys.argv[1:]

        tracer = CallTracer()
        with tracer:
            runpy.run_module(module_name, run_name="__main__", alter_sys=True)
        tracer.save()
    else:
        script_path = sys.argv[0]

        tracer = CallTracer()
        with tracer:
            runpy.run_path(script_path, run_name="__main__")
        tracer.save()
