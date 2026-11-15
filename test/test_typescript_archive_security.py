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

yauzl.open("archive.zip", { lazyEntries: true }, (err, zipfile) => {
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

yauzl.open("archive.zip", { lazyEntries: true }, (err, zipfile) => {
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

yauzl.open("archive.zip", { lazyEntries: true }, (err, zipfile) => {
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
import yauzl from "yauzl";

function extract(entry: { fileName: string }) {
  const base = "/tmp/out";
  const outputPath = path.normalize(path.join(base, entry.fileName));
  if (outputPath.startsWith(PREFIX)) {
    fs.writeFileSync(outputPath, "data");
    return;
  }
  throw new Error("bad path");
}
"""

BRACELESS_GUARD = """import fs from "fs";
import path from "path";
import yauzl from "yauzl";

function extract(entry: { fileName: string }) {
  const base = "/tmp/out";
  const outputPath = path.normalize(path.join(base, entry.fileName));
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
import yauzl from "yauzl";

function extract(entry: { fileName: string }) {
  const base = "/tmp/out";
  const outputPath = path.normalize(path.join(base, entry.fileName));
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


_HEADER = 'import fs from "fs";\nimport path from "path";\nimport yauzl from "yauzl";\n'
_GUARDED_BODY = """  const out = path.normalize(path.join("/tmp/out", entry.fileName));
  if (!out.startsWith(ROOT)) { throw new Error("bad"); }
  fs.writeFileSync(out, "d");
"""

SAFE_RESOLVED_PREFIXES = {
    "module_const": 'const ROOT = "/tmp/out/";\n'
    "function extract(entry: { fileName: string }) {\n" + _GUARDED_BODY + "}\n",
    "local_const": "function extract(entry: { fileName: string }) {\n"
    '  const ROOT = "/tmp/out/";\n' + _GUARDED_BODY + "}\n",
    "module_const_beside_other_local": 'function other() { const ROOT = "/a/"; return ROOT; }\n'
    'const ROOT = "/tmp/out/";\n'
    "function extract(entry: { fileName: string }) {\n" + _GUARDED_BODY + "}\n",
    "module_concat_with_sep": 'const ROOT = "/tmp/out" + path.sep;\n'
    "function extract(entry: { fileName: string }) {\n" + _GUARDED_BODY + "}\n",
    "outer_function_const": "function extractAll(zip: any) {\n"
    '  const ROOT = "/tmp/out/";\n'
    '  zip.on("entry", (entry: { fileName: string }) => {\n'
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
    "parameter": "function extract(entry: { fileName: string }, ROOT: string) {\n"
    + _GUARDED_BODY
    + "}\n",
    "destructured_parameter": "function extract(entry: { fileName: string }, "
    "{ ROOT }: { ROOT: string }) {\n" + _GUARDED_BODY + "}\n",
    "default_parameter": 'function extract(entry: { fileName: string }, ROOT = "") {\n'
    + _GUARDED_BODY
    + "}\n",
    "outer_closure_parameter": "function extractAll(zip: any, ROOT: string) {\n"
    '  zip.on("entry", (entry: { fileName: string }) => {\n'
    + _GUARDED_BODY.replace('throw new Error("bad")', "return")
    + "  });\n}\n",
    "for_of_variable": "function extract(entry: { fileName: string }, roots: string[]) {\n"
    "  for (const ROOT of roots) {\n"
    + _GUARDED_BODY.replace('throw new Error("bad")', "continue")
    + "  }\n}\n",
    "catch_parameter": "function extract(entry: { fileName: string }) {\n"
    "  try { load(); } catch (ROOT) {\n" + _GUARDED_BODY + "  }\n}\n",
    "hoisted_var": "function extract(entry: { fileName: string }, r: string) {\n"
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
        + "function extract(entry: { fileName: string }) {\n"
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
        + "\nfunction extract(entry: { fileName: string }) {\n"
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
        + "function extract(entry: { fileName: string }) {\n"
        + _GUARDED_BODY
        + "}\n"
    )
    findings = _scan_ts_file(tmp_path, "archive.ts", source)
    assert "SKY-D215" in _rule_ids(findings)


@pytest.mark.parametrize(
    "condition",
    [
        # The write runs when the path is outside the prefix.
        'out.startsWith("/tmp/out/") || entry.fileName !== "x"',
        'out.startsWith(\n    "/tmp/out/"\n  ) || entry.fileName !== "x"',
        'out.startsWith("/tmp/out/") === true',
        '!out.startsWith("/tmp/out/") && entry.fileName !== "x"',
    ],
)
def test_condition_that_does_not_exit_on_escape_is_reported(tmp_path, condition):
    source = (
        _HEADER
        + "function extract(entry: { fileName: string }) {\n"
        + '  const out = path.normalize(path.join("/tmp/out", entry.fileName));\n'
        + f"  if ({condition}) {{\n    return;\n  }}\n"
        + '  fs.writeFileSync(out, "d");\n}\n'
    )
    findings = _scan_ts_file(tmp_path, "archive.ts", source)
    assert "SKY-D215" in _rule_ids(findings)


@pytest.mark.parametrize(
    "condition",
    [
        '!out.startsWith("/tmp/out/") || entry.fileName === ""',
        'out.startsWith("/tmp/out/") === false',
        'false == out.startsWith(\n    "/tmp/out/"\n  )',
        '!(out.startsWith("/tmp/out/"))',
    ],
)
def test_condition_that_exits_on_escape_is_safe(tmp_path, condition):
    source = (
        _HEADER
        + "function extract(entry: { fileName: string }) {\n"
        + '  const out = path.normalize(path.join("/tmp/out", entry.fileName));\n'
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
