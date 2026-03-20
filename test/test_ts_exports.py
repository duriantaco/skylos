"""Tests for TypeScript export graph, re-export handling, and Next.js conventions."""

from __future__ import annotations

import os
from collections import defaultdict

import pytest

from skylos.visitor import Definition
from skylos.visitors.languages.typescript.analysis import (
    build_ts_import_graph,
    demote_unconsumed_ts_exports,
    find_unused_ts_exports,
    _is_nextjs_convention_file,
    _NEXTJS_CONVENTION_EXPORTS,
)


def _make_def(name, typ, filename, line=1, exported=False):
    d = Definition(name, typ, filename, line)
    d.is_exported = exported
    return d


# ---------- Aliased import consumption ----------


class TestAliasedImports:
    def test_aliased_import_consumes_original_name(self, tmp_path):
        """import { foo as bar } from './mod' should mark 'foo' as consumed."""
        mod_file = tmp_path / "mod.ts"
        mod_file.write_text("export function foo() {}")
        app_file = tmp_path / "app.ts"
        app_file.write_text("import { foo as bar } from './mod';")

        defs = {
            f"{mod_file}:foo": _make_def("foo", "function", str(mod_file), exported=True),
        }

        ts_raw_imports = {
            str(app_file): [
                {"source": "./mod", "names": ["foo as bar"], "line": 1}
            ]
        }

        consumed, _, _ = build_ts_import_graph(ts_raw_imports, defs)
        assert "foo" in consumed[str(mod_file)]

    def test_plain_import_still_works(self, tmp_path):
        """import { foo } from './mod' should still mark 'foo' as consumed."""
        mod_file = tmp_path / "mod.ts"
        mod_file.write_text("export function foo() {}")
        app_file = tmp_path / "app.ts"
        app_file.write_text("import { foo } from './mod';")

        defs = {
            f"{mod_file}:foo": _make_def("foo", "function", str(mod_file), exported=True),
        }

        ts_raw_imports = {
            str(app_file): [
                {"source": "./mod", "names": ["foo"], "line": 1}
            ]
        }

        consumed, _, _ = build_ts_import_graph(ts_raw_imports, defs)
        assert "foo" in consumed[str(mod_file)]

    def test_multiple_aliased_imports(self, tmp_path):
        """Multiple aliased imports from same module."""
        mod_file = tmp_path / "mod.ts"
        mod_file.write_text("export function foo() {} export function bar() {}")
        app_file = tmp_path / "app.ts"
        app_file.write_text("import { foo as f, bar as b } from './mod';")

        defs = {
            f"{mod_file}:foo": _make_def("foo", "function", str(mod_file), exported=True),
            f"{mod_file}:bar": _make_def("bar", "function", str(mod_file), exported=True),
        }

        ts_raw_imports = {
            str(app_file): [
                {"source": "./mod", "names": ["foo as f", "bar as b"], "line": 1}
            ]
        }

        consumed, _, _ = build_ts_import_graph(ts_raw_imports, defs)
        assert "foo" in consumed[str(mod_file)]
        assert "bar" in consumed[str(mod_file)]


# ---------- Default re-export tracking ----------


class TestDefaultReexport:
    def test_export_default_as_name(self, tmp_path):
        """export { default as MyComponent } from './comp' should mark 'default' consumed."""
        comp_file = tmp_path / "comp.ts"
        comp_file.write_text("export default function MyComponent() {}")
        index_file = tmp_path / "index.ts"
        index_file.write_text("export { default as MyComponent } from './comp';")
        consumer_file = tmp_path / "consumer.ts"
        consumer_file.write_text("import { MyComponent } from './index';")

        defs = {
            f"{comp_file}:default": _make_def("default", "function", str(comp_file), exported=True),
        }

        ts_raw_imports = {
            str(index_file): [
                {"source": "./comp", "names": ["default as MyComponent"], "line": 1}
            ],
            str(consumer_file): [
                {"source": "./index", "names": ["MyComponent"], "line": 1}
            ],
        }

        consumed, _, _ = build_ts_import_graph(ts_raw_imports, defs)
        # MyComponent is consumed from index, and the alias resolver should
        # propagate to mark 'default' consumed in comp
        assert "default" in consumed[str(comp_file)]

    def test_export_named_as_alias(self, tmp_path):
        """export { foo as publicFoo } from './mod' should propagate."""
        mod_file = tmp_path / "mod.ts"
        mod_file.write_text("export function foo() {}")
        barrel_file = tmp_path / "barrel.ts"
        barrel_file.write_text("export { foo as publicFoo } from './mod';")
        consumer_file = tmp_path / "consumer.ts"
        consumer_file.write_text("import { publicFoo } from './barrel';")

        defs = {
            f"{mod_file}:foo": _make_def("foo", "function", str(mod_file), exported=True),
        }

        ts_raw_imports = {
            str(barrel_file): [
                {"source": "./mod", "names": ["foo as publicFoo"], "line": 1}
            ],
            str(consumer_file): [
                {"source": "./barrel", "names": ["publicFoo"], "line": 1}
            ],
        }

        consumed, _, _ = build_ts_import_graph(ts_raw_imports, defs)
        assert "foo" in consumed[str(mod_file)]


# ---------- Next.js convention export exclusion ----------


class TestNextjsConventionExports:
    def test_is_nextjs_convention_file_app_dir(self):
        assert _is_nextjs_convention_file("/project/app/dashboard/page.tsx")
        assert _is_nextjs_convention_file("/project/app/api/route.ts")

    def test_is_nextjs_convention_file_pages_dir(self):
        assert _is_nextjs_convention_file("/project/pages/index.tsx")
        assert _is_nextjs_convention_file("/project/pages/api/users.ts")

    def test_is_not_nextjs_convention_file(self):
        assert not _is_nextjs_convention_file("/project/src/utils/helpers.ts")
        assert not _is_nextjs_convention_file("/project/lib/db.ts")

    def test_convention_exports_not_flagged(self):
        """Exports like 'default', 'GET', 'POST' in app/ dirs should not be flagged."""
        fname = "/project/app/api/users/route.ts"

        demoted = []
        for export_name in ("default", "GET", "POST", "generateMetadata"):
            d = _make_def(export_name, "function", fname, exported=True)
            d.references = 1  # has internal refs
            d.is_exported = False  # demoted
            demoted.append(d)

        findings = find_unused_ts_exports(demoted, {})
        # None should be flagged because they're all convention exports in app/
        flagged_names = {f["name"] for f in findings}
        for export_name in ("default", "GET", "POST", "generateMetadata"):
            assert export_name not in flagged_names

    def test_non_convention_export_still_flagged(self):
        """A non-convention export in app/ should still be flagged."""
        fname = "/project/app/utils/helpers.ts"

        d = _make_def("myHelper", "function", fname, exported=True)
        d.references = 1
        d.is_exported = False

        findings = find_unused_ts_exports([d], {})
        assert len(findings) == 1
        assert findings[0]["name"] == "myHelper"

    def test_convention_export_outside_app_dir_flagged(self):
        """Convention export names outside app/pages dirs should still be flagged."""
        fname = "/project/src/lib/utils.ts"

        d = _make_def("GET", "function", fname, exported=True)
        d.references = 1
        d.is_exported = False

        findings = find_unused_ts_exports([d], {})
        assert len(findings) == 1
        assert findings[0]["name"] == "GET"

    def test_all_convention_exports_covered(self):
        """Verify key Next.js convention exports are in the set."""
        expected = {
            "default", "generateMetadata", "generateStaticParams",
            "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
            "middleware", "loading", "error", "layout", "page",
        }
        assert expected.issubset(_NEXTJS_CONVENTION_EXPORTS)


# ---------- Wildcard re-export passthrough ----------


class TestWildcardPassthrough:
    def test_wildcard_reexport_propagates(self, tmp_path):
        """export * from './mod' should propagate consumed names."""
        mod_file = tmp_path / "mod.ts"
        mod_file.write_text("export function helper() {}")
        index_file = tmp_path / "index.ts"
        index_file.write_text("export * from './mod';")
        consumer_file = tmp_path / "consumer.ts"
        consumer_file.write_text("import { helper } from './index';")

        defs = {
            f"{mod_file}:helper": _make_def("helper", "function", str(mod_file), exported=True),
        }

        ts_raw_imports = {
            str(index_file): [
                {"source": "./mod", "names": ["*"], "line": 1}
            ],
            str(consumer_file): [
                {"source": "./index", "names": ["helper"], "line": 1}
            ],
        }

        consumed, _, _ = build_ts_import_graph(ts_raw_imports, defs)
        assert "helper" in consumed[str(mod_file)]
