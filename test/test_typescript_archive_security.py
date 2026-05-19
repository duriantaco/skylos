from __future__ import annotations

from pathlib import Path
from time import perf_counter

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


def test_positive_startswith_guard_inside_branch_is_safe(tmp_path):
    findings = _scan_ts_file(
        tmp_path,
        "archive.ts",
        """import fs from "fs";
import path from "path";
import yauzl from "yauzl";

function extract(entry: { fileName: string }) {
  const base = "/tmp/out";
  const outputPath = path.normalize(path.join(base, entry.fileName));
  if (outputPath.startsWith(base)) {
    fs.writeFileSync(outputPath, "data");
    return;
  }
  throw new Error("bad path");
}
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)


def test_braceless_positive_startswith_guard_is_safe(tmp_path):
    findings = _scan_ts_file(
        tmp_path,
        "archive.ts",
        """import fs from "fs";
import path from "path";
import yauzl from "yauzl";

function extract(entry: { fileName: string }) {
  const base = "/tmp/out";
  const outputPath = path.normalize(path.join(base, entry.fileName));
  if (outputPath.startsWith(base))
    fs.writeFileSync(outputPath, "data");
  else
    throw new Error("bad path");
}
""",
    )
    assert "SKY-D215" not in _rule_ids(findings)


def test_semicolonless_archive_alias_storm_does_not_dos_scan(tmp_path):
    aliases = "\n".join(
        f"    const alias{index} = entry.path" for index in range(1500)
    )
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
