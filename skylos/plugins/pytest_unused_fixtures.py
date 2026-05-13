from __future__ import annotations

import json
import os
from pathlib import Path
import pytest


class FixtureInfo:
    def __init__(self, name, file, line, scope):
        self.name = name
        self.file = file
        self.line = line
        self.scope = scope


class UnusedFixturesPlugin:
    def __init__(self, config):
        self.config = config
        self.root = Path(str(getattr(config, "rootpath", Path.cwd()))).resolve()

        self.available = {}
        self.used_local = set()
        self.used_from_workers = set()

    def _is_worker(self):
        return hasattr(self.config, "workerinput")

    def _out_path(self):
        p = os.getenv("SKYLOS_UNUSED_FIXTURES_OUT", ".skylos_unused_fixtures.json")
        return (self.root / p) if not os.path.isabs(p) else Path(p)

    def pytest_collection_finish(self, session):
        if self._is_worker():
            return

        fm = getattr(session, "_fixturemanager", None)
        if fm is None:
            return

        arg2defs = getattr(fm, "_arg2fixturedefs", {}) or {}
        for name, defs in arg2defs.items():
            for fdef in defs or []:
                func = getattr(fdef, "func", None)
                if func is None or not hasattr(func, "__code__"):
                    continue

                file = str(Path(func.__code__.co_filename).resolve())
                line = int(func.__code__.co_firstlineno or 1)
                scope = str(getattr(fdef, "scope", "function"))

                if (
                    "site-packages" in file
                    or "/_pytest/" in file
                    or "\\_pytest\\" in file
                ):
                    continue

                try:
                    if not Path(file).resolve().is_relative_to(self.root):
                        continue
                except Exception:
                    if str(self.root) not in file:
                        continue

                if name not in self.available:
                    self.available[name] = FixtureInfo(
                        name=name, file=file, line=line, scope=scope
                    )

    def pytest_fixture_setup(self, fixturedef, request):
        name = getattr(fixturedef, "argname", None)
        if name:
            self.used_local.add(str(name))

    def pytest_sessionfinish(self, session, exitstatus):
        if self._is_worker():
            out = getattr(self.config, "workeroutput", None)
            if isinstance(out, dict):
                out["skylos_used_fixtures"] = sorted(self.used_local)
            return

        if not hasattr(session.config, "workerinput"):
            self._write_report()

    @pytest.hookimpl(optionalhook=True)
    def pytest_testnodedown(self, node, error):
        out = getattr(node, "workeroutput", None) or {}
        used = out.get("skylos_used_fixtures") or []
        for name in used:
            self.used_from_workers.add(str(name))

    def _write_report(self):
        used = set(self.used_local) | set(self.used_from_workers)
        unused = []

        for name, info in sorted(self.available.items(), key=lambda kv: kv[0]):
            if name not in used:
                unused.append(
                    {
                        "name": info.name,
                        "file": info.file,
                        "line": info.line,
                        "scope": info.scope,
                    }
                )

        out = self._out_path()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(
                {
                    "unused_fixtures": unused,
                    "counts": {
                        "available": len(self.available),
                        "used": len(used),
                        "unused": len(unused),
                    },
                },
                indent=2,
            )
        )


def pytest_configure(config):
    config.pluginmanager.register(
        UnusedFixturesPlugin(config), "skylos-unused-fixtures"
    )
