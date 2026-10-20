"""JS/TS function metrics measure the code as written; vendored output is skipped.

Covers: `else if` chains are one nesting level; cognitive complexity for
JS/TS; code-line length; names of functions bound to variables, properties
and fields; test files; .gitattributes linguist markers; bundler output.
"""

from pathlib import Path

import pytest

from test.fixture_paths import write_fixture

from skylos.core.generated_files import (
    REASON_BUNDLE,
    REASON_LINGUIST_GENERATED,
    REASON_LINGUIST_VENDORED,
    classify_generated_file,
)
from skylos.visitors.languages.typescript import scan_typescript_file


def _metrics(tmp_path, relative, source):
    path = write_fixture(tmp_path, relative, source, overwrite=True)
    rows = scan_typescript_file(str(path))[6]
    return {
        (row["rule_id"], row["name"]): row["value"]
        for row in rows
        if row["rule_id"] in {"SKY-Q301", "SKY-Q302", "SKY-Q306", "SKY-C304"}
    }


CHAIN = "export const parse = (value: string): number => {\n" + "".join(
    f"  {'if' if i == 0 else '} else if'} (value === '{i}') {{\n    return {i};\n"
    for i in range(12)
) + "  } else {\n    return -1;\n  }\n};\n"

DEEP = """function deep(items: number[][], flag: boolean) {
  for (const row of items) {
    if (row.length) {
      for (const cell of row) {
        if (cell > 0 && flag || cell < -10) {
          while (cell > 100) {
            if (flag) {
              return cell;
            }
          }
        }
      }
    }
  }
  return 0;
}
"""


def test_else_if_chain_is_one_nesting_level_and_named_after_its_binding(tmp_path):
    metrics = _metrics(tmp_path, "src/chain.ts", CHAIN)
    assert ("SKY-Q302", "parse") not in metrics
    # 12 branches: cyclomatic complexity is over the limit, cognitive is not.
    assert metrics.get(("SKY-Q301", "parse")) == 13
    assert ("SKY-Q306", "parse") not in metrics


def test_nested_logic_reports_cognitive_complexity_and_real_depth(tmp_path):
    metrics = _metrics(tmp_path, "src/deep.ts", DEEP)
    assert metrics[("SKY-Q302", "deep")] == 6
    # for 1, if 2, for 3, if 4 + logical runs 2, while 5, if 6.
    assert metrics[("SKY-Q306", "deep")] == 23


def test_length_counts_code_lines_not_blank_or_comment_lines(tmp_path):
    body = "".join(f"  // note {i}\n\n  total += {i};\n" for i in range(40))
    source = f"function sum() {{\n  let total = 0;\n{body}  return total;\n}}\n"
    metrics = _metrics(tmp_path, "src/sum.js", source)
    assert ("SKY-C304", "sum") not in metrics  # 43 code lines of 123 physical
    longer = "".join(f"  total += {i};\n" for i in range(60))
    metrics = _metrics(tmp_path, "src/long.js", f"function sum() {{\n{longer}}}\n")
    assert metrics[("SKY-C304", "sum")] == 62


@pytest.mark.parametrize(
    "relative",
    ["src/app/chain.spec.ts", "src/app/chain.test.js", "src/__tests__/chain.ts", "e2e/chain.cy.ts"],
)
def test_test_files_keep_raw_function_metrics(tmp_path, relative):
    metrics = _metrics(tmp_path, relative, DEEP)
    assert metrics[("SKY-Q302", "deep")] == 6
    assert metrics[("SKY-Q306", "deep")] == 23


def test_gitattributes_linguist_markers_mark_vendored_and_generated(tmp_path):
    (tmp_path / ".gitattributes").write_text(
        "lib/search/** linguist-vendored\n"
        "lib/search/own.js linguist-vendored=false\n"
        "*.pb.ts linguist-generated\n"
    )
    for relative in ("lib/search/lunr.fi.js", "lib/search/own.js", "src/api.pb.ts", "src/app.ts"):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("export const value = 1;\n")
    root = Path(tmp_path)
    assert classify_generated_file(root / "lib/search/lunr.fi.js", root) == REASON_LINGUIST_VENDORED
    assert classify_generated_file(root / "lib/search/own.js", root) is None
    assert classify_generated_file(root / "src/api.pb.ts", root) == REASON_LINGUIST_GENERATED
    assert classify_generated_file(root / "src/app.ts", root) is None


@pytest.mark.parametrize(
    "head",
    [
        "(function(){function r(e,n,t){function o(i,f){if(!n[i]){n[i]={exports:{}};e[i](n[i],n[i].exports);}return n[i].exports;}for(var x=0;x<t.length;x++)o(t[x]);return o;} return r({0:function(module){module.exports=1;}}, {}, [0]);})();",
        "(() => {var __webpack_modules__={0:function(module){module.exports=1;}}; function __webpack_require__(id){var module={exports:{}};__webpack_modules__[id](module,module.exports);return module.exports;} __webpack_require__(0);})();",
    ],
)
def test_bundler_output_is_recognised(tmp_path, head):
    path = tmp_path / "static" / "worker" / "bundle.js"
    path.parent.mkdir(parents=True)
    path.write_text(head + "\n" + "var x = 1;\n" * 20)
    assert classify_generated_file(path, tmp_path) == REASON_BUNDLE
    plain = tmp_path / "src" / "app.js"
    plain.parent.mkdir()
    plain.write_text("function r(a) { return a; }\n")
    assert classify_generated_file(plain, tmp_path) is None
