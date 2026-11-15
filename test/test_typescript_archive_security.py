from __future__ import annotations

from pathlib import Path
from time import perf_counter

import pytest

from skylos.visitors.languages.typescript import scan_typescript_file


def _scan_ts_file(tmp_path: Path, filename: str, code: str) -> list[dict]:
    file_path = tmp_path / filename
    file_path.write_text(code, encoding="utf-8")
    return scan_typescript_file(str(file_path))[7]


def _rule_ids(findings: list[dict]) -> set[str]:
    return {finding["rule_id"] for finding in findings}


def test_unzip_entry_path_to_write_stream_flags(tmp_path):
    findings = _scan_ts_file(
        tmp_path,
        "archive.js",
        """const fs = require("fs");
const path = require("path");
const unzipper = require("unzipper");

fs.createReadStream("archive.zip")
  .pipe(unzipper.Parse())
  .on("entry", entry => {
    const fileName = entry.path;
    entry.pipe(fs.createWriteStream(path.join("/tmp/out", fileName)));
  });
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_unzip_entry_path_with_dotdot_guard_is_safe(tmp_path):
    findings = _scan_ts_file(
        tmp_path,
        "archive.js",
        """const fs = require("fs");
const path = require("path");
const unzipper = require("unzipper");

fs.createReadStream("archive.zip")
  .pipe(unzipper.Parse())
  .on("entry", entry => {
    const fileName = entry.path;
    if (fileName.includes("..")) {
      entry.autodrain();
      return;
    }
    entry.pipe(fs.createWriteStream(path.join("/tmp/out", fileName)));
  });
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)


def test_noop_dotdot_check_still_flags_archive_write(tmp_path):
    findings = _scan_ts_file(
        tmp_path,
        "archive.js",
        """const fs = require("fs");
const path = require("path");
const unzipper = require("unzipper");

fs.createReadStream("archive.zip")
  .pipe(unzipper.Parse())
  .on("entry", entry => {
    const fileName = entry.path;
    const bad = fileName.includes("..");
    entry.pipe(fs.createWriteStream(path.join("/tmp/out", fileName)));
  });
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_autodrain_without_return_still_flags_archive_write(tmp_path):
    findings = _scan_ts_file(
        tmp_path,
        "archive.js",
        """const fs = require("fs");
const path = require("path");
const unzipper = require("unzipper");

fs.createReadStream("archive.zip")
  .pipe(unzipper.Parse())
  .on("entry", entry => {
    const fileName = entry.path;
    if (fileName.includes("..")) {
      entry.autodrain();
    }
    entry.pipe(fs.createWriteStream(path.join("/tmp/out", fileName)));
  });
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_yauzl_entry_filename_to_write_file_flags(tmp_path):
    findings = _scan_ts_file(
        tmp_path,
        "archive.ts",
        """import fs from "fs";
import path from "path";
import yauzl from "yauzl";

yauzl.open("archive.zip", { lazyEntries: true, decodeStrings: false }, (err, zipfile) => {
  zipfile.on("entry", entry => {
    const outputPath = path.join("/tmp/out", entry.fileName);
    fs.writeFileSync(outputPath, "data");
  });
});
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_multiline_archive_write_sink_flags(tmp_path):
    findings = _scan_ts_file(
        tmp_path,
        "archive.js",
        """const fs = require("fs");
const path = require("path");
const unzipper = require("unzipper");

fs.createReadStream("archive.zip")
  .pipe(unzipper.Parse())
  .on("entry", entry => {
    const fileName = entry.path;
    entry.pipe(
      fs.createWriteStream(
        path.join("/tmp/out", fileName)
      )
    );
  });
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_imported_writefilesync_archive_sink_flags(tmp_path):
    findings = _scan_ts_file(
        tmp_path,
        "archive.ts",
        """import { writeFileSync } from "fs";
import path from "path";
import yauzl from "yauzl";

yauzl.open("archive.zip", { lazyEntries: true, decodeStrings: false }, (err, zipfile) => {
  zipfile.on("entry", entry => {
    const outputPath = path.join("/tmp/out", entry.fileName);
    writeFileSync(outputPath, "data");
  });
});
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_fixed_path_with_archive_name_as_content_is_not_flagged(tmp_path):
    findings = _scan_ts_file(
        tmp_path,
        "archive.js",
        """const fs = require("fs");
const unzipper = require("unzipper");

fs.createReadStream("archive.zip")
  .pipe(unzipper.Parse())
  .on("entry", entry => {
    const fileName = entry.path;
    fs.writeFileSync("/tmp/log.txt", fileName);
  });
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)


def test_unrelated_name_property_is_not_treated_as_archive_entry(tmp_path):
    findings = _scan_ts_file(
        tmp_path,
        "archive.js",
        """const fs = require("fs");
const unzipper = require("unzipper");

function writeUser(user) {
  const fileName = user.name;
  fs.writeFileSync(fileName, "x");
}
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)


def test_unrelated_path_property_is_not_treated_as_archive_entry(tmp_path):
    findings = _scan_ts_file(
        tmp_path,
        "archive.js",
        """const fs = require("fs");
const unzipper = require("unzipper");

function writeReq(req) {
  fs.writeFileSync(req.path, "x");
}
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)


def test_mixed_safe_and_unsafe_archive_handlers_still_flags_unsafe(tmp_path):
    findings = _scan_ts_file(
        tmp_path,
        "archive.js",
        """const fs = require("fs");
const path = require("path");
const unzipper = require("unzipper");

function extractUnsafe() {
  fs.createReadStream("archive.zip")
    .pipe(unzipper.Parse())
    .on("entry", entry => {
      const fileName = entry.path;
      entry.pipe(fs.createWriteStream(path.join("/tmp/out", fileName)));
    });
}

function extractSafe() {
  fs.createReadStream("archive.zip")
    .pipe(unzipper.Parse())
    .on("entry", entry => {
      const fileName = entry.path;
      if (fileName.includes("..")) {
        entry.autodrain();
        return;
      }
      entry.pipe(fs.createWriteStream(path.join("/tmp/out", fileName)));
    });
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_safe_archive_handler_before_unsafe_still_flags_unsafe(tmp_path):
    findings = _scan_ts_file(
        tmp_path,
        "archive.js",
        """const fs = require("fs");
const path = require("path");
const unzipper = require("unzipper");

function extractSafe() {
  fs.createReadStream("archive.zip")
    .pipe(unzipper.Parse())
    .on("entry", entry => {
      const fileName = entry.path;
      if (fileName.includes("..")) {
        entry.autodrain();
        return;
      }
      entry.pipe(fs.createWriteStream(path.join("/tmp/out", fileName)));
    });
}

function extractUnsafe() {
  fs.createReadStream("archive.zip")
    .pipe(unzipper.Parse())
    .on("entry", entry => {
      const fileName = entry.path;
      entry.pipe(fs.createWriteStream(path.join("/tmp/out", fileName)));
    });
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_unrelated_helper_parameter_is_not_treated_as_archive_taint(tmp_path):
    findings = _scan_ts_file(
        tmp_path,
        "archive.js",
        """const fs = require("fs");
const unzipper = require("unzipper");

function extract(entry) {
  const fileName = entry.path;
  return fileName;
}

function writeLog(fileName) {
  fs.writeFileSync(fileName, "x");
}

fs.createReadStream("archive.zip")
  .pipe(unzipper.Parse())
  .on("entry", entry => {
    extract(entry);
  });
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)


def test_outer_scope_archive_flow_not_skipped_by_nested_helper(tmp_path):
    findings = _scan_ts_file(
        tmp_path,
        "archive.js",
        """const fs = require("fs");
const path = require("path");
const unzipper = require("unzipper");

function extract(entry) {
  function helper(name) {
    return name.trim();
  }

  const fileName = entry.path;
  helper(fileName);
  fs.writeFileSync(path.join("/tmp/out", fileName), "data");
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_reassigned_guarded_output_path_still_flags(tmp_path):
    findings = _scan_ts_file(
        tmp_path,
        "archive.js",
        """const fs = require("fs");
const path = require("path");
const unzipper = require("unzipper");

function extract(entry) {
  let outputPath = path.normalize(path.join("/tmp/out", "safe.txt"));
  if (!outputPath.startsWith("/tmp/out")) {
    throw new Error("bad path");
  }

  outputPath = path.join("/tmp/out", entry.path);
  fs.writeFileSync(outputPath, "data");
}
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


def test_typed_archive_alias_flags(tmp_path):
    findings = _scan_ts_file(
        tmp_path,
        "archive.ts",
        """import fs from "fs";
import path from "path";
import yauzl from "yauzl";

yauzl.open("archive.zip", { lazyEntries: true, decodeStrings: false }, (err, zipfile) => {
  zipfile.on("entry", entry => {
    const fileName: string = entry.fileName;
    const outputPath = path.join("/tmp/out", fileName);
    fs.writeFileSync(outputPath, "data");
  });
});
""",
    )
    assert "SKY-D215" in _rule_ids(findings)


POSITIVE_BRANCH_GUARD = """import fs from "fs";
import path from "path";
import unzipper from "unzipper";

function extract(entry: { path: string }) {
  const base = "/tmp/out";
  const outputPath = path.normalize(path.join(base, entry.path));
  if (outputPath.startsWith(PREFIX)) {
    fs.writeFileSync(outputPath, "data");
    return;
  }
  throw new Error("bad path");
}
"""

BRACELESS_GUARD = """import fs from "fs";
import path from "path";
import unzipper from "unzipper";

function extract(entry: { path: string }) {
  const base = "/tmp/out";
  const outputPath = path.normalize(path.join(base, entry.path));
  if (outputPath.startsWith(PREFIX))
    fs.writeFileSync(outputPath, "data");
  else
    throw new Error("bad path");
}
"""


@pytest.mark.parametrize(
    ("source", "prefix"),
    [
        (POSITIVE_BRANCH_GUARD, "base + path.sep"),
        (POSITIVE_BRANCH_GUARD, "base + '/'"),
        (POSITIVE_BRANCH_GUARD, "`${base}/`"),
        (POSITIVE_BRANCH_GUARD, "'/tmp/out/'"),
        (BRACELESS_GUARD, "base + path.sep"),
        (BRACELESS_GUARD, "base + '/'"),
        (BRACELESS_GUARD, "'/tmp/out/'"),
    ],
)
def test_positive_startswith_guard_ending_at_a_separator_is_safe(
    tmp_path, source, prefix
):
    findings = _scan_ts_file(tmp_path, "archive.ts", source.replace("PREFIX", prefix))
    assert "SKY-D215" not in _rule_ids(findings)


@pytest.mark.parametrize("source", [POSITIVE_BRANCH_GUARD, BRACELESS_GUARD])
@pytest.mark.parametrize("prefix", ["base", "'/tmp/out'", "'/'", "path.sep"])
def test_startswith_guard_admitting_a_sibling_folder_is_reported(
    tmp_path, source, prefix
):
    findings = _scan_ts_file(tmp_path, "archive.ts", source.replace("PREFIX", prefix))
    assert "SKY-D215" in _rule_ids(findings)


MULTILINE_GUARD = """import fs from "fs";
import path from "path";
import unzipper from "unzipper";

function extract(entry: { path: string }) {
  const base = "/tmp/out";
  const outputPath = path.normalize(path.join(base, entry.path));
  if (outputPath.startsWith(
    PREFIX
  )) {
    fs.writeFileSync(outputPath, "data");
    return;
  }
  throw new Error("bad path");
}
"""


@pytest.mark.parametrize("prefix", ["base + path.sep", "base + '/'", "'/tmp/out/'"])
def test_multiline_startswith_guard_ending_at_a_separator_is_safe(tmp_path, prefix):
    source = MULTILINE_GUARD.replace("PREFIX", prefix)
    findings = _scan_ts_file(tmp_path, "archive.ts", source)
    assert "SKY-D215" not in _rule_ids(findings)


@pytest.mark.parametrize("prefix", ["base", "'/tmp/out'", "'/'", "path.sep"])
def test_multiline_startswith_guard_admitting_a_sibling_is_reported(tmp_path, prefix):
    source = MULTILINE_GUARD.replace("PREFIX", prefix)
    findings = _scan_ts_file(tmp_path, "archive.ts", source)
    assert "SKY-D215" in _rule_ids(findings)


_HEADER = (
    'import fs from "fs";\nimport path from "path";\nimport unzipper from "unzipper";\n'
)
_GUARDED_BODY = """  const out = path.normalize(path.join("/tmp/out", entry.path));
  if (!out.startsWith(ROOT)) { throw new Error("bad"); }
  fs.writeFileSync(out, "d");
"""

SAFE_RESOLVED_PREFIXES = {
    "module_const": 'const ROOT = "/tmp/out/";\n'
    "function extract(entry: { path: string }) {\n" + _GUARDED_BODY + "}\n",
    "local_const": "function extract(entry: { path: string }) {\n"
    '  const ROOT = "/tmp/out/";\n' + _GUARDED_BODY + "}\n",
    "module_const_beside_other_local": 'function other() { const ROOT = "/a/"; return ROOT; }\n'
    'const ROOT = "/tmp/out/";\n'
    "function extract(entry: { path: string }) {\n" + _GUARDED_BODY + "}\n",
    "module_concat_with_sep": 'const ROOT = "/tmp/out" + path.sep;\n'
    "function extract(entry: { path: string }) {\n" + _GUARDED_BODY + "}\n",
    "outer_function_const": "function extractAll(zip: any) {\n"
    '  const ROOT = "/tmp/out/";\n'
    '  zip.on("entry", (entry: { path: string }) => {\n'
    + _GUARDED_BODY.replace('throw new Error("bad")', "return")
    + "  });\n}\n",
}


@pytest.mark.parametrize("case", sorted(SAFE_RESOLVED_PREFIXES))
def test_guard_prefix_resolved_through_its_binding_is_safe(tmp_path, case):
    source = _HEADER + SAFE_RESOLVED_PREFIXES[case]
    findings = _scan_ts_file(tmp_path, "archive.ts", source)
    assert "SKY-D215" not in _rule_ids(findings)


def test_guard_prefix_module_const_in_commonjs_is_safe(tmp_path):
    source = (
        'const fs = require("fs");\nconst path = require("path");\n'
        'const yauzl = require("yauzl");\nconst { sep } = require("path");\n'
        'const ROOT = "/tmp/out" + sep;\n'
        "function extract(entry) {\n" + _GUARDED_BODY + "}\n"
    )
    findings = _scan_ts_file(tmp_path, "archive.js", source)
    assert "SKY-D215" not in _rule_ids(findings)


# Each prefix name below is bound to something other than the module-level
# `ROOT = "/tmp/out/"` the text would suggest, so the guard proves nothing.
SHADOWED_PREFIXES = {
    "parameter": "function extract(entry: { path: string }, ROOT: string) {\n"
    + _GUARDED_BODY
    + "}\n",
    "destructured_parameter": "function extract(entry: { path: string }, "
    "{ ROOT }: { ROOT: string }) {\n" + _GUARDED_BODY + "}\n",
    "default_parameter": 'function extract(entry: { path: string }, ROOT = "") {\n'
    + _GUARDED_BODY
    + "}\n",
    "outer_closure_parameter": "function extractAll(zip: any, ROOT: string) {\n"
    '  zip.on("entry", (entry: { path: string }) => {\n'
    + _GUARDED_BODY.replace('throw new Error("bad")', "return")
    + "  });\n}\n",
    "for_of_variable": "function extract(entry: { path: string }, roots: string[]) {\n"
    "  for (const ROOT of roots) {\n"
    + _GUARDED_BODY.replace('throw new Error("bad")', "continue")
    + "  }\n}\n",
    "catch_parameter": "function extract(entry: { path: string }) {\n"
    "  try { load(); } catch (ROOT) {\n" + _GUARDED_BODY + "  }\n}\n",
    "hoisted_var": "function extract(entry: { path: string }, r: string) {\n"
    "  if (r) { var ROOT = r; }\n" + _GUARDED_BODY + "}\n",
}


@pytest.mark.parametrize("case", sorted(SHADOWED_PREFIXES))
def test_guard_prefix_shadowing_the_module_const_is_reported(tmp_path, case):
    source = _HEADER + 'const ROOT = "/tmp/out/";\n' + SHADOWED_PREFIXES[case]
    findings = _scan_ts_file(tmp_path, "archive.ts", source)
    assert "SKY-D215" in _rule_ids(findings)


def test_guard_prefix_from_an_import_is_reported(tmp_path):
    source = (
        _HEADER
        + 'import { ROOT } from "./config";\n'
        + 'function other() { const ROOT = "/tmp/a/"; return ROOT; }\n'
        + "function extract(entry: { path: string }) {\n"
        + _GUARDED_BODY
        + "}\n"
    )
    findings = _scan_ts_file(tmp_path, "archive.ts", source)
    assert "SKY-D215" in _rule_ids(findings)


@pytest.mark.parametrize(
    "reassign",
    [
        "export function configure(o: { root: string }) { ({ root: ROOT } = o); }",
        "export function configure(r: string) { ROOT = r; }",
        "export function configure(r: string) { ROOT += r; }",
    ],
)
def test_guard_prefix_let_written_elsewhere_is_reported(tmp_path, reassign):
    source = (
        _HEADER
        + 'let ROOT = "/tmp/out/";\n'
        + reassign
        + "\nfunction extract(entry: { path: string }) {\n"
        + _GUARDED_BODY
        + "}\n"
    )
    findings = _scan_ts_file(tmp_path, "archive.ts", source)
    assert "SKY-D215" in _rule_ids(findings)


@pytest.mark.parametrize("value", ['"/"', "path.sep", '"" + "/"'])
def test_guard_prefix_resolving_to_only_a_separator_is_reported(tmp_path, value):
    source = (
        _HEADER
        + f"const ROOT = {value};\n"
        + "function extract(entry: { path: string }) {\n"
        + _GUARDED_BODY
        + "}\n"
    )
    findings = _scan_ts_file(tmp_path, "archive.ts", source)
    assert "SKY-D215" in _rule_ids(findings)


@pytest.mark.parametrize(
    "condition",
    [
        # The write runs when the path is outside the prefix.
        'out.startsWith("/tmp/out/") || entry.path !== "x"',
        'out.startsWith(\n    "/tmp/out/"\n  ) || entry.path !== "x"',
        'out.startsWith("/tmp/out/") === true',
        '!out.startsWith("/tmp/out/") && entry.path !== "x"',
    ],
)
def test_condition_that_does_not_exit_on_escape_is_reported(tmp_path, condition):
    source = (
        _HEADER
        + "function extract(entry: { path: string }) {\n"
        + '  const out = path.normalize(path.join("/tmp/out", entry.path));\n'
        + f"  if ({condition}) {{\n    return;\n  }}\n"
        + '  fs.writeFileSync(out, "d");\n}\n'
    )
    findings = _scan_ts_file(tmp_path, "archive.ts", source)
    assert "SKY-D215" in _rule_ids(findings)


@pytest.mark.parametrize(
    "condition",
    [
        '!out.startsWith("/tmp/out/") || entry.path === ""',
        'out.startsWith("/tmp/out/") === false',
        'false == out.startsWith(\n    "/tmp/out/"\n  )',
        '!(out.startsWith("/tmp/out/"))',
    ],
)
def test_condition_that_exits_on_escape_is_safe(tmp_path, condition):
    source = (
        _HEADER
        + "function extract(entry: { path: string }) {\n"
        + '  const out = path.normalize(path.join("/tmp/out", entry.path));\n'
        + f"  if ({condition}) {{\n    return;\n  }}\n"
        + '  fs.writeFileSync(out, "d");\n}\n'
    )
    findings = _scan_ts_file(tmp_path, "archive.ts", source)
    assert "SKY-D215" not in _rule_ids(findings)


def test_semicolonless_archive_alias_storm_does_not_dos_scan(tmp_path):
    aliases = "\n".join(f"    const alias{index} = entry.path" for index in range(1500))
    started = perf_counter()

    findings = _scan_ts_file(
        tmp_path,
        "archive.js",
        f"""const unzipper = require("unzipper");

function extract(entry) {{
{aliases}
}}
""",
    )
    elapsed = perf_counter() - started

    assert "SKY-D215" not in _rule_ids(findings)
    assert elapsed < 2.0


_UNZIPPER_HEADER = (
    'import fs from "fs";\nimport path from "path";\nimport unzipper from "unzipper";\n'
)


def _unzipper_extract(body: str) -> str:
    return (
        _UNZIPPER_HEADER
        + "function extract(entry: { path: string }, root: string) {\n"
        + body
        + '  fs.writeFileSync(out, "d");\n}\n'
    )


def test_unzipper_es_module_import_is_scanned(tmp_path):
    source = _unzipper_extract("  const out = path.join(root, entry.path);\n")
    findings = _scan_ts_file(tmp_path, "archive.ts", source)
    assert "SKY-D215" in _rule_ids(findings)


YAUZL_UNGUARDED = """import fs from "fs";
import path from "path";
import yauzl from "yauzl";

yauzl.open("archive.zip", { lazyEntries: true }, (err, zipfile) => {
  zipfile.on("entry", entry => {
    fs.writeFileSync(path.join("/tmp/out", entry.fileName), "data");
  });
});
"""


@pytest.mark.parametrize(
    "importer",
    [
        'import yauzl from "yauzl";',
        'const yauzl = require("yauzl");',
        'const { default: yauzl } = await import("yauzl");',
    ],
)
def test_yauzl_file_names_are_validated_by_yauzl(tmp_path, importer):
    # yauzl rejects absolute names, backslashes and `..` parts itself.
    source = YAUZL_UNGUARDED.replace('import yauzl from "yauzl";', importer)
    findings = _scan_ts_file(tmp_path, "archive.ts", source)
    assert "SKY-D215" not in _rule_ids(findings)


def test_yauzl_raw_file_names_are_reported(tmp_path):
    source = YAUZL_UNGUARDED.replace(
        "{ lazyEntries: true }", "{ lazyEntries: true, decodeStrings: false }"
    )
    findings = _scan_ts_file(tmp_path, "archive.ts", source)
    assert "SKY-D215" in _rule_ids(findings)


@pytest.mark.parametrize(
    "expression",
    ["path.basename(entry.path)", "basename(entry.path)"],
)
def test_basename_of_the_entry_name_is_safe(tmp_path, expression):
    source = _unzipper_extract(f"  const out = path.join(root, {expression});\n")
    findings = _scan_ts_file(tmp_path, "archive.ts", source)
    assert "SKY-D215" not in _rule_ids(findings)


@pytest.mark.parametrize(
    "guard",
    [
        "  if (!out.startsWith(root + path.sep)) throw new Error('bad');\n",
        (
            "  if (out !== root && !out.startsWith(root + path.sep)) {\n"
            "    throw new Error('bad');\n  }\n"
        ),
        "  if (out == null || !out.startsWith(`${root}${path.sep}`)) return;\n",
    ],
)
def test_resolved_path_checked_against_root_and_separator_is_safe(tmp_path, guard):
    source = _unzipper_extract(
        "  const out = path.resolve(root, entry.path);\n" + guard
    )
    findings = _scan_ts_file(tmp_path, "archive.ts", source)
    assert "SKY-D215" not in _rule_ids(findings)


def test_resolve_imported_from_path_normalizes(tmp_path):
    source = _unzipper_extract(
        "  const out = resolve(root, entry.path);\n"
        "  if (!out.startsWith(root + sep)) throw new Error('bad');\n"
    ).replace('import path from "path";', 'import path, { resolve, sep } from "path";')
    findings = _scan_ts_file(tmp_path, "archive.ts", source)
    assert "SKY-D215" not in _rule_ids(findings)


@pytest.mark.parametrize(
    "guard",
    [
        # No separator: `/root2/x` starts with `/root`.
        "  if (!out.startsWith(root)) throw new Error('bad');\n",
        # Lets `elsewhere` through, which is not the root.
        "  if (out !== elsewhere && !out.startsWith(root + path.sep)) return;\n",
        # Compares a different value with the root.
        "  if (entry.path !== root && !out.startsWith(root + path.sep)) return;\n",
    ],
)
def test_resolved_path_with_a_weak_check_is_reported(tmp_path, guard):
    source = _unzipper_extract(
        "  const out = path.resolve(root, entry.path);\n" + guard
    )
    findings = _scan_ts_file(tmp_path, "archive.ts", source)
    assert "SKY-D215" in _rule_ids(findings)


@pytest.mark.parametrize(
    "check",
    [
        (
            '  const parts = entry.path.split("/");\n'
            '  if (parts.some((part) => part === ".." || part === "")) {\n'
            "    throw new Error('bad');\n  }\n"
            "  const out = path.join(root, ...parts);\n"
        ),
        (
            "  const out = path.resolve(root, entry.path);\n"
            "  const rel = path.relative(root, out);\n"
            "  if (\n    !rel ||\n    rel.split(/[/\\\\]/).includes('..') ||\n"
            "    path.isAbsolute(rel)\n  ) {\n    throw new Error('bad');\n  }\n"
        ),
        (
            "  const out = path.resolve(root, entry.path);\n"
            "  const rel = path.relative(root, out);\n"
            "  if (rel.startsWith('..') || path.isAbsolute(rel)) throw new Error('bad');\n"
        ),
        (
            "  const name = entry.path;\n"
            "  if (name.split('/').indexOf('..') !== -1) return;\n"
            "  const out = path.join(root, name);\n"
        ),
    ],
)
def test_rejecting_parent_segments_is_safe(tmp_path, check):
    findings = _scan_ts_file(tmp_path, "archive.ts", _unzipper_extract(check))
    assert "SKY-D215" not in _rule_ids(findings)


@pytest.mark.parametrize(
    "check",
    [
        # Inverted: exits only for names *without* a parent part.
        (
            "  const name = entry.path;\n"
            "  if (!name.includes('..')) return;\n"
            "  const out = path.join(root, name);\n"
        ),
        # Exits only when a second condition also holds.
        (
            "  const name = entry.path;\n"
            "  if (name.includes('..') && strict) return;\n"
            "  const out = path.join(root, name);\n"
        ),
        # Checks a value the write never uses.
        (
            "  if (root.includes('..')) return;\n"
            "  const out = path.join(root, entry.path);\n"
        ),
        # Does not exit.
        (
            "  const name = entry.path;\n"
            "  if (name.includes('..')) console.warn(name);\n"
            "  const out = path.join(root, name);\n"
        ),
    ],
)
def test_parent_segment_check_that_does_not_block_is_reported(tmp_path, check):
    findings = _scan_ts_file(tmp_path, "archive.ts", _unzipper_extract(check))
    assert "SKY-D215" in _rule_ids(findings)


@pytest.mark.parametrize(
    "check",
    [
        # A raw name under `assets/` can still hold `assets/../../x`.
        (
            "  if (!entry.path.startsWith('assets/')) return;\n"
            "  const out = path.join(root, entry.path);\n"
        ),
        (
            "  const name = entry.path;\n"
            "  if (!name.startsWith('assets/')) return;\n"
            "  const out = path.join(root, name);\n"
        ),
    ],
)
def test_prefix_check_on_the_raw_entry_name_is_reported(tmp_path, check):
    findings = _scan_ts_file(tmp_path, "archive.ts", _unzipper_extract(check))
    assert "SKY-D215" in _rule_ids(findings)


@pytest.mark.parametrize(
    "check",
    [
        (
            "  if (entry.path.includes('..')) throw new Error('bad');\n"
            "  const out = path.join(root, entry.path);\n"
        ),
        (
            "  const rel = entry.path.replace(/\\\\/g, '/');\n"
            "  const segs = rel.split('/');\n"
            "  if (rel.startsWith('/') || segs.includes('..')) throw new Error('bad');\n"
            "  const out = path.join(root, rel);\n"
        ),
        (
            "  const out = path.join(root, entry.path);\n"
            "  if (!out.startsWith(root + path.sep) && out !== root) throw new Error('bad');\n"
        ),
    ],
)
def test_checks_on_the_entry_or_its_parts_are_safe(tmp_path, check):
    findings = _scan_ts_file(tmp_path, "archive.ts", _unzipper_extract(check))
    assert "SKY-D215" not in _rule_ids(findings)


def test_semicolonless_assignment_stops_at_the_end_of_its_statement(tmp_path):
    # `tmp` must not swallow the following block that reads `entry.name`.
    source = (
        "import fs from 'fs'\nimport path from 'path'\nimport unzipper from 'unzipper'\n"
        "async function pack(entries: { name: string }[]) {\n"
        "  const tmp = await fs.promises.mkdtemp(path.join('/tmp', 'zip-'))\n"
        "  try {\n"
        "    for (const entry of entries) console.log(entry.name)\n"
        "  } finally {}\n"
        "  fs.writeFileSync(path.join(tmp, 'archive.zip'), '')\n"
        "}\n"
    )
    findings = _scan_ts_file(tmp_path, "archive.ts", source)
    assert "SKY-D215" not in _rule_ids(findings)


def test_root_idiom_with_the_prefix_in_a_variable_is_safe(tmp_path):
    source = _unzipper_extract(
        "  const rootPrefix = `${root}${path.sep}`;\n"
        "  const out = path.resolve(root, entry.path);\n"
        "  if (out !== root && !out.startsWith(rootPrefix)) throw new Error('bad');\n"
    )
    findings = _scan_ts_file(tmp_path, "archive.ts", source)
    assert "SKY-D215" not in _rule_ids(findings)


def test_checking_the_canonical_parent_folder_is_safe(tmp_path):
    source = _unzipper_extract(
        "  const out = path.join(root, entry.path);\n"
        "  const dir = path.dirname(out);\n"
        "  const canonical = fs.realpathSync(dir);\n"
        "  const rel = path.relative(root, canonical);\n"
        "  if (rel.split(path.sep).includes('..')) {\n"
        "    throw new Error('bad');\n  }\n"
    )
    findings = _scan_ts_file(tmp_path, "archive.ts", source)
    assert "SKY-D215" not in _rule_ids(findings)


def test_assignment_with_an_inline_callback_keeps_its_taint(tmp_path):
    # The `(s) => s` callback must not hide the line that reads `entry.path`.
    source = _unzipper_extract(
        "  const segments = entry.path.split('/').filter((s) => s.length > 0);\n"
        "  const out = path.join(root, ...segments);\n"
    )
    findings = _scan_ts_file(tmp_path, "archive.ts", source)
    assert "SKY-D215" in _rule_ids(findings)


_VALIDATOR_FILE = (
    _UNZIPPER_HEADER
    + "HELPER\n"
    + "function extract(entry: { path: string }, root: string) {\n"
    + "BODY"
    + '  fs.writeFileSync(out, "d");\n}\n'
)


@pytest.mark.parametrize(
    ("helper", "body"),
    [
        (
            (
                "function safeTarget(root: string, name: string): string {\n"
                "  const target = path.resolve(root, name);\n"
                "  if (!target.startsWith(root + path.sep)) throw new Error('bad');\n"
                "  return target;\n}"
            ),
            "  const out = safeTarget(root, entry.path);\n",
        ),
        (
            (
                "const safeName = (name: string): string | null =>\n"
                "  { return name.split('/').every((p) => p !== '..') ? name : null; };"
            ),
            (
                "  const name = safeName(entry.path);\n"
                "  if (name === null) return;\n"
                "  const out = path.join(root, name);\n"
            ),
        ),
        (
            (
                "const assertChild = (root: string, p: string): void => {\n"
                "  if (p !== root && !p.startsWith(`${root}${path.sep}`)) throw new Error('bad');\n};"
            ),
            (
                "  const out = path.resolve(root, entry.path);\n"
                "  assertChild(root, out);\n"
            ),
        ),
    ],
)
def test_path_checked_by_a_helper_in_the_same_file_is_safe(tmp_path, helper, body):
    source = _VALIDATOR_FILE.replace("HELPER", helper).replace("BODY", body)
    findings = _scan_ts_file(tmp_path, "archive.ts", source)
    assert "SKY-D215" not in _rule_ids(findings)


@pytest.mark.parametrize(
    ("helper", "body"),
    [
        # Imported: its body cannot be read here.
        (
            'import { safeTarget } from "./paths";',
            "  const out = safeTarget(root, entry.path);\n",
        ),
        # Compares prefixes, but the caller never normalized the path.
        (
            (
                "const assertChild = (root: string, p: string): void => {\n"
                "  if (p !== root && !p.startsWith(`${root}${path.sep}`)) throw new Error('bad');\n};"
            ),
            "  const out = root + '/' + entry.path;\n  assertChild(root, out);\n",
        ),
        # Named like a check but checks nothing.
        (
            (
                "function safeTarget(root: string, name: string): string {\n"
                "  return path.join(root, name);\n}"
            ),
            "  const out = safeTarget(root, entry.path);\n",
        ),
    ],
)
def test_path_through_an_unverifiable_helper_is_reported(tmp_path, helper, body):
    source = _VALIDATOR_FILE.replace("HELPER", helper).replace("BODY", body)
    findings = _scan_ts_file(tmp_path, "archive.ts", source)
    assert "SKY-D215" in _rule_ids(findings)


def test_name_inside_a_string_literal_is_not_a_value(tmp_path):
    # `report` is tainted, but "report.json" only spells the word.
    source = (
        _UNZIPPER_HEADER
        + "function extract(entry: { path: string }, work: string) {\n"
        + "  const report = { name: entry.path };\n"
        + '  fs.writeFileSync(path.join(work, "report.json"), JSON.stringify(report));\n'
        + "}\n"
    )
    findings = _scan_ts_file(tmp_path, "archive.ts", source)
    assert "SKY-D215" not in _rule_ids(findings)


def test_template_substitution_is_still_a_value(tmp_path):
    source = _unzipper_extract("  const out = `${root}/${entry.path}`;\n")
    findings = _scan_ts_file(tmp_path, "archive.ts", source)
    assert "SKY-D215" in _rule_ids(findings)
