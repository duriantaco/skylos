"""File exclusions require real provenance or executable bundle structure."""

import pytest

from test.fixture_paths import make_fixture_directory
from skylos.core.safe_cache_io import write_text_no_symlink

from skylos.core.generated_files import (
    classify_generated_file,
    partition_generated_files,
)


WEBPACK = """(() => {
  var __webpack_modules__ = {0: function(module) { module.exports = 1; }};
  function __webpack_require__(moduleId) {
    var module = {exports: {}};
    __webpack_modules__[moduleId](module, module.exports, __webpack_require__);
    return module.exports;
  }
  __webpack_require__(0);
})();
"""
BROWSERIFY = """(function(){
  function r(e,n,t) {
    function o(i,f) {
      if (!n[i]) { n[i] = {exports:{}}; e[i](n[i], n[i].exports); }
      return n[i].exports;
    }
    for (var x=0;x<t.length;x++) o(t[x]);
    return o;
  }
  return r({0:function(module){module.exports=1;}},{},[0]);
})();
"""
WEBPACK_PARAMETER_TABLE = """(function(modules) {
  function __webpack_require__(id) {
    var module = {exports: {}};
    modules[id].call(module.exports, module, module.exports, __webpack_require__);
    return module.exports;
  }
  __webpack_require__(0);
})([function(module) { module.exports = 1; }]);
"""
BROWSERIFY_RETURNED_FACTORY = """(function(){
  function r(e,n,t) {
    function o(i,f) {
      if (!n[i]) { n[i] = {exports:{}}; e[i][0].call(n[i].exports,n[i],n[i].exports); }
      return n[i].exports;
    }
    for (var x=0;x<t.length;x++) o(t[x]);
    return o;
  }
  return r;
})()({0:[function(module){module.exports=1;},{}]},{},[0]);
"""


@pytest.mark.parametrize(
    "source",
    [WEBPACK, BROWSERIFY, WEBPACK_PARAMETER_TABLE, BROWSERIFY_RETURNED_FACTORY],
)
def test_structural_bundle_is_excluded(tmp_path, source):
    path = tmp_path / "bundle.js"
    path.write_text(source)
    kept, scope = partition_generated_files([path], tmp_path)
    assert kept == []
    assert scope.excluded[path] == "bundled_output"


@pytest.mark.parametrize(
    "source",
    [
        "// Explain webpackBootstrap integration.\nexport function unused(){return 1;}\n",
        "const docs = '__webpack_require__';\nexport const value = 1;\n",
        "function __webpack_require__(id) { return registry[id]; }\n",
        "const example = `" + WEBPACK + "`;\nexport const value = 1;\n",
        "export function __webpack_require__(id) { return id; }\n"
        "export function dispatch(modules, id) { return modules[id](); }\n"
        "export function unwrap(value) { return value.exports; }\n"
        "(() => { console.log('ready'); })();\n"
        "export function unused_business_logic() { return 123; }\n",
        WEBPACK.replace("__webpack_require__(0);", "console.log('no startup');"),
        WEBPACK.replace(
            "__webpack_require__(0);",
            "__webpack_modules__ = get_modules(); __webpack_require__(0);",
        ),
        WEBPACK.replace(
            "var __webpack_modules__ = {0: function(module) { module.exports = 1; }};",
            "var __webpack_modules__ = get_modules();",
        ),
        BROWSERIFY.replace("for (var x=0;x<t.length;x++) o(t[x]);", "").replace(
            "return o;", "return 42;"
        ),
    ],
)
def test_mentions_and_loader_lookalikes_remain_analyzed(tmp_path, source):
    path = tmp_path / "app.js"
    path.write_text(source)
    kept, scope = partition_generated_files([path], tmp_path)
    assert kept == [path] and not scope.excluded


@pytest.mark.parametrize("attribute", ["linguist-vendored", "linguist-generated"])
def test_unspecified_attribute_restores_first_party_file(tmp_path, attribute):
    path = tmp_path / "app.py"
    path.write_text("def unused():\n    return 1\n")
    (tmp_path / ".gitattributes").write_text(f"*.py {attribute}\napp.py !{attribute}\n")
    assert classify_generated_file(path, tmp_path) is None


def test_declared_vendoring_still_applies_and_comment_does_not(tmp_path):
    first = tmp_path / "first.py"
    vendor = tmp_path / "copied.py"
    for path in (first, vendor):
        path.write_text("value = 1\n")
    (tmp_path / ".gitattributes").write_text(
        "# first.py linguist-vendored\ncopied.py linguist-vendored\n"
    )
    assert classify_generated_file(first, tmp_path) is None
    assert classify_generated_file(vendor, tmp_path) == "linguist_vendored"


@pytest.mark.parametrize(
    ("pattern", "relative", "vendored"),
    [
        ("src/**.py", "src/app.py", True),
        ("src/**.py", "src/app/live.py", False),
        ("src/**/live.py", "src/live.py", True),
        ("src/**/live.py", "src/app/live.py", True),
        ("src/**", "src/app/live.py", True),
        ("src/foo**bar.py", "src/foox/bar.py", False),
        ("src/[ab].py", "src/[ab].py", False),
        ('"app.py"', '"app.py"', False),
        (r"src/\*.py", r"src/\app.py", False),
    ],
)
def test_globstar_only_crosses_slashes_at_component_boundaries(
    tmp_path, pattern, relative, vendored
):
    path = tmp_path / relative
    path.resolve().relative_to(tmp_path.resolve())
    make_fixture_directory(tmp_path, path.parent.relative_to(tmp_path))
    if not write_text_no_symlink(path, "def unused():\n    return 1\n"):
        raise OSError("cannot safely create generated-pattern fixture")
    (tmp_path / ".gitattributes").write_text(f"{pattern} linguist-vendored\n")
    assert classify_generated_file(path, tmp_path) == (
        "linguist_vendored" if vendored else None
    )
