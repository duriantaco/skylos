# Skylos rule handbook sources

The rule handbook is a printable PDF: one page (or a few) per rule, saying
what the rule finds, why it matters, what flagged and not-flagged code looks
like, how Skylos decides, how to fix it and how to silence it.

Everything here is source. `scripts/build_handbook.py` turns it into one HTML
file and prints that to PDF with headless Chrome.

| Path | What it holds |
|:--|:--|
| `rules/<RULE-ID>.yaml` | One rule page. The file name is the rule ID. |
| `families.yaml` | The book's rule families: title, ID prefixes, intro, and which catalog rules belong to each. |
| `intro/NN-name.md` | Front matter chapters, in file-name order. |
| `handbook.css` | Page style (A4, `@page` margins, footer page numbers). |

The rule list itself comes from `skylos/rules/catalog.py`. A catalog rule
without a YAML page is "not yet written": the coverage report lists it and a
pilot build leaves it out.

## Build

Use a Python that has PyYAML and Pygments (the Skylos development
environment has both) and Google Chrome or Chromium.

```bash
python scripts/build_handbook.py --check              # validate pages, write the coverage report
python scripts/build_handbook.py --verify-only        # run every example through skylos
python scripts/build_handbook.py --verify             # verify, then build the PDF
python scripts/build_handbook.py --output out/handbook.pdf
python scripts/build_handbook.py --rule SKY-D211 --verify   # one page
python scripts/build_handbook.py --mode full          # refuses to build while any rule has no page
```

Next to the PDF it writes `<name>.html`, `<name>-coverage.md` and, with
`--verify`, `<name>-verify.json`. The default output is
`build/handbook/skylos-handbook.pdf` (git-ignored).

Chrome is found at the macOS default path, on `PATH`
(`google-chrome`, `chromium`), or through `--chrome` / `CHROME_BIN`. The
build prints twice: the first pass finds the page of every anchor (from the
PDF's named destinations), the second writes those numbers into the contents,
family tables and index.

## `--verify`

Each example is written into its own folder under a scratch directory and the
real CLI runs on it:

```text
skylos . <flags> --no-upload --format json --output <file>
```

- The `skylos` used is the console script next to the running Python (or
  `--skylos`), with this checkout first on `PYTHONPATH`. The report records
  the version and the imported module path.
- `HOME`, `XDG_*` and Git identity point at the scratch folder. Only `PATH`,
  locale and temp variables are passed through, so tokens, API keys and CI
  variables never reach the scan. `SKYLOS_CUSTOM_RULES='[]'` stops the scan
  from fetching Cloud custom rules.
- `<flags>` are the analysis flags `skylos --select <RULE-ID>` would turn on
  (for example `--danger` for SKY-D rules, `--quality` for SKY-L rules,
  nothing for unused-code rules). A git_diff example adds `--diff HEAD`. An
  example's `scan_flags` replaces all of them.
- A flagged example passes when the rule ID is reported (and, with
  `expect_line`, reported on that line). A not-flagged example, and a fix
  that has a `filename`, pass when the rule ID is not reported. Exit code 2,
  any entry in the scan's `analysis_errors` (a file or check that was not
  analysed) or missing JSON fails the check, so an example Skylos could not
  read never passes as "not reported".
- `--keep-scratch` keeps the folders; `--scratch DIR` picks the folder.

A passing check is printed under its example in the PDF ("Checked. Skylos
5.4.0, `skylos . --danger`: reported at app/users.py line 13."). The note
only appears while the example, its flags and the rule are unchanged since
the last `--verify`.

## Rule page schema

```yaml
id: SKY-D211                # must match the file name and the catalog
title: SQL injection         # plain title; the catalog name is shown if it differs
family: security             # an id from families.yaml
severity: CRITICAL           # must equal the catalog severity when it has one;
                             # otherwise CRITICAL, HIGH, MEDIUM, LOW, VARIES or UNRATED
severity_note: ...           # optional; required for VARIES and UNRATED
languages: [Python, Go]      # display names
cwe: [CWE-89]                # optional; must equal the catalog. The PDF always
                             # prints the catalog's CWE list.
run_with: ...                # optional; overrides the "Turned on by" line

what_it_is: ...              # 2-3 plain sentences
why_it_matters: ...          # 1-3 sentences, a concrete consequence
how_skylos_decides:          # the detector's real logic, in order
  - Finds ...
  - Skips ...
source_refs:                 # for maintainers; checked on every build
  - path: skylos/rules/danger/danger_sql/sql_flow.py
    symbol: "class _SQLFlowChecker"   # must occur in that file
    note: optional text

flagged_example: <example>
not_flagged_example: <example>   # plus `why`: why Skylos correctly ignores it

fix:
  explanation: ...
  code: |                    # optional
    ...
  filename: app/users.py     # optional; with a filename the fix is verified
  language: python           # optional; defaults to the flagged example's
  scan_flags: [...]          # optional, as for examples

false_alarms_and_suppression:
  misfires:                  # when the rule can be wrong
    - ...
  suppress:                  # how to silence it; code is optional
    - text: ...
      code: |
        cur.execute(sql)  # skylos: ignore[SKY-D211] reason
      language: python

related: [SKY-D217, SKY-D212]    # catalog IDs
```

Text fields accept a small inline Markdown subset: `` `code` ``,
`**bold**` and `[text](url)`. Rule IDs that have a page become links.

### Fragments: keeping example secrets out of this repository

Skylos scans its own repository, so a page that shows a real-looking secret
would be a real finding. Store such values in parts and refer to them with
`{{NAME}}`:

```yaml
fragments:
  STRIPE_DEMO_KEY: ["sk_live_", "51HandbookDemo0nly"]

flagged_example:
  code: |
    STRIPE_SECRET_KEY = "{{STRIPE_DEMO_KEY}}"
```

The build joins the parts and replaces `{{NAME}}` in every text and code
field before validating, printing and verifying. Names are upper case.

### Examples

An example is one file:

```yaml
flagged_example:
  language: python
  filename: app/users.py
  expect_line: 13            # optional: the reported line, highlighted in print
  code: |
    ...
```

or several files, when the rule needs context a single file cannot give
(a lockfile next to a manifest, a `go.mod`, a helper in another module):

```yaml
not_flagged_example:
  language: python           # default for files without their own language
  files:
    - filename: app/jobs.py
      code: |
        ...
    - filename: go.mod
      language: text
      code: |
        module example.com/app
  expect_file: app/jobs.py   # optional, flagged examples only; defaults to the first file
  why: ...
```

In print, a file of a not-flagged example that is identical to the flagged
example's file of the same name is shown as one line ("same as in the
flagged example"), and a fix whose file name matches a file of the
flagged example is shown as a diff against that file. Both are still written in
full for `--verify`.

`setup` prepares the folder before the scan:

| `setup` | What happens |
|:--|:--|
| `none` (default) | The files are written to a plain folder. |
| `git` | `git init`, the files are written and committed. Use it when a rule only reads files Git tracks. |
| `git_diff` | `git init`, `base_files` are written and committed, then `files` are written on top without committing. The scan adds `--diff HEAD`, so it reviews the uncommitted change. In `files`, `deleted: true` removes a base file. The PDF shows each changed file as a diff. |

```yaml
flagged_example:
  language: python
  setup: git_diff
  base_files:
    - filename: tests/test_prices.py
      code: |
        ...
  files:
    - filename: tests/test_prices.py
      code: |
        ...
```

`scan_flags: ["--danger", "--diff-base", "HEAD"]` replaces the computed
flags when a rule needs a different invocation.

## Writing guide

- Short sentences. Explain any term a newcomer would not know in one line.
- `how_skylos_decides` describes the code as it is, not as it should be. Every
  step must be traceable to the files in `source_refs`.
- The not-flagged example is a lookalike: code a reader might expect the rule
  to flag, which Skylos correctly leaves alone.
- Use the suppression syntax the CLI really reads: `# skylos: ignore[RULE]`
  (`//` in JS-family, Go, Java and similar files), `skylos baseline .` with
  `--baseline`, and `[tool.skylos] ignore = [...]`.
- Keep example lines under 88 characters; longer lines wrap in print.
