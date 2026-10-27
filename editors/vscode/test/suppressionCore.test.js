const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const {
  fileIgnoreEdit,
  hasLineIgnore,
  lineIgnoreEdit,
  whitelistName,
} = require("../out/suppressionCore");

test("Python line ignores use markers the CLI honours", () => {
  assert.deepEqual(lineIgnoreEdit("python", "SKY-D211", 4, "cur.execute(sql)"), {
    line: 4,
    column: 16,
    text: "  # skylos: ignore[SKY-D211]",
  });
  assert.equal(lineIgnoreEdit("python", "SKY-SCA-LIC001", 0, "x").text, "  # skylos: ignore[SKY-SCA-LIC001]");
  assert.equal(lineIgnoreEdit("python", "SKY-U001", 0, "def old():").text, "  # skylos: ignore");
  assert.equal(lineIgnoreEdit("python", "DEAD-FUNC", 0, "def old():").text, "  # skylos: ignore");
  assert.equal(lineIgnoreEdit("python", "SKY-E002", 0, "").text, "  # skylos: ignore");
  assert.equal(lineIgnoreEdit("python", "custom rule", 0, "x").text, "  # skylos: ignore");
  assert.equal(lineIgnoreEdit("python", "SKY-D211", 0, "x = a + \\"), undefined);
});

test("TS/JS line ignores start their own comment", () => {
  assert.deepEqual(lineIgnoreEdit("typescript", "SKY-D211", 2, "  db.query(sql);"), {
    line: 2,
    column: 16,
    text: "  // skylos: ignore[SKY-D211]",
  });
  assert.deepEqual(lineIgnoreEdit("javascriptreact", "SKY-D211", 2, "  db.query(sql); // run it"), {
    line: 2,
    column: 2,
    text: "/* skylos: ignore[SKY-D211] */ ",
  });
  assert.equal(lineIgnoreEdit("typescriptreact", "SKY-U001", 0, "function old() {").text, "  // skylos: ignore");
});

test("Go gets a line ignore only for secrets", () => {
  assert.equal(lineIgnoreEdit("go", "SKY-S101", 0, "key := \"x\"").text, "  // skylos: ignore[SKY-S101]");
  assert.equal(lineIgnoreEdit("go", "SKY-D211", 0, "db.Query(q)"), undefined);
  assert.equal(lineIgnoreEdit("go", "SKY-U001", 0, "func old() {"), undefined);
  assert.equal(fileIgnoreEdit("go", ["package main"]), undefined);
});

test("whole-file ignore is ignore-start after shebang and encoding lines", () => {
  assert.deepEqual(fileIgnoreEdit("python", ["import os", ""]), { line: 0, column: 0, text: "# skylos: ignore-start\n" });
  assert.deepEqual(fileIgnoreEdit("python", ["#!/usr/bin/env python3", "# -*- coding: utf-8 -*-"]), {
    line: 2,
    column: 0,
    text: "# skylos: ignore-start\n",
  });
  assert.equal(fileIgnoreEdit("python", ["# coding: latin-1", "x = 1"]).line, 1);
  assert.deepEqual(fileIgnoreEdit("javascript", ["#!/usr/bin/env node", "run();"]), {
    line: 1,
    column: 0,
    text: "// skylos: ignore-start\n",
  });
  assert.equal(fileIgnoreEdit("typescript", ["// skylos: ignore-start", "x"]), undefined);
});

test("no edit writes a marker the CLI does not read", () => {
  const edits = [
    lineIgnoreEdit("python", "SKY-D211", 0, "x"),
    lineIgnoreEdit("python", "SKY-U001", 0, "x"),
    lineIgnoreEdit("typescript", "SKY-D211", 0, "x"),
    lineIgnoreEdit("typescript", "SKY-D211", 0, "x // y"),
    lineIgnoreEdit("go", "SKY-S101", 0, "x"),
    fileIgnoreEdit("python", ["x"]),
    fileIgnoreEdit("typescript", ["x"]),
  ];
  for (const edit of edits) {
    assert.doesNotMatch(edit.text, /skylos-ignore|pragma: no skylos/);
  }
  const root = path.join(__dirname, "..", "src");
  for (const file of ["quickfix.ts", "extension.ts", "codelens.ts"]) {
    const source = fs.readFileSync(path.join(root, file), "utf8");
    assert.doesNotMatch(source, /skylos-ignore|\.skylosignore/);
  }
});

test("existing Skylos markers suppress a second line ignore", () => {
  assert.equal(hasLineIgnore("x = 1  # skylos: ignore[SKY-D211]"), true);
  assert.equal(hasLineIgnore("x = 1  # pragma: no skylos"), true);
  assert.equal(hasLineIgnore("x = 1  # noqa: skylos"), true);
  assert.equal(hasLineIgnore("# skylos: ignore-start"), false);
  assert.equal(hasLineIgnore("x = 1  # noqa"), false);
});

test("whitelist names are plain identifiers", () => {
  assert.equal(whitelistName("Unused function: pkg.mod.helper"), "helper");
  assert.equal(whitelistName("Unused import: os.path"), "path");
  assert.equal(whitelistName("Unused variable: $state"), "$state");
  assert.equal(whitelistName("Unused function: a\"b"), undefined);
  assert.equal(whitelistName("Unused function: a b"), undefined);
  assert.equal(whitelistName("Unused function: --show"), undefined);
  assert.equal(whitelistName("Possible SQL injection"), undefined);
});
