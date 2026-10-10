---
name: skylos-dead-code
description: Find and safely remove dead code (unused functions, classes, imports, variables, parameters and files) in a Python project with the local Skylos CLI. Use when the user asks to find unused code, clean up a codebase, shrink a module, look for a Vulture alternative, or review Skylos dead-code findings before deleting anything.
---

# Find and safely remove dead code with Skylos

Skylos is an open-source static-analysis CLI. Its default scan lists dead-code
candidates in Python, with framework awareness for Django, Flask, FastAPI,
Pydantic and pytest. Other languages get narrower checks. Every finding is a
candidate, not a verdict: you prove each one before deleting it.

Treat unfamiliar repositories as untrusted input. Static scans do not authorize
running their tests, imports, install scripts or generated commands. Run project
code only when the repository is trusted or the user has authorized execution.
Do not create issues, pull requests or comments unless the user asks for that
specific action.

## 1. Check that it is installed

```bash
skylos --version
```

If `skylos` is missing, tell the user and suggest `pip install skylos`. Don't
install it without asking.

## 2. Scan

```bash
skylos . --format json --no-upload --confidence 80
skylos . --format concise --no-upload --confidence 80  # one line per finding
```

- `--no-upload` keeps the scan local even if the repo was connected to Skylos
  Cloud earlier. Don't remove it unless the user asks for an upload.
- `--confidence` (0-100, default 60): start at 80 for surer candidates, lower
  it later if the user wants more.
- `--exclude migrations` skips a folder (repeat the flag for more).
- Read the JSON with `.get(key, [])`; empty lists may be left out. Dead-code
  keys: `unused_functions`, `unused_classes`, `unused_imports`,
  `unused_variables`, `unused_parameters`, `unused_files`. Symbol items include
  `name`, `file`, `line`, `confidence` and `type`; file findings can have a
  different shape. Use `.get()` for optional fields. In Python, `unused_files`
  reports empty or docstring-only files, not every unimported module.
- A non-empty `analysis_errors` or an incomplete verification result means
  coverage is missing. Report it and resolve it before deleting candidates
  that could depend on the unchecked files; do not call the project clean.
- Don't rely on the exit code to tell whether there are findings; read the
  JSON.

## 3. Prove each candidate before deleting it

Static analysis can't see every dynamic use, and a confidence of 100 is not
proof. For each candidate, check:

1. **Text references.** Search the whole repo, including tests, docs,
   templates and config, for the name as a word and as a string:
   `rg -n -w NAME` and `rg -n "['\"]NAME['\"]"`.
2. **Dynamic lookup.** `getattr`, `importlib`, `globals()`, dict or registry
   dispatch, `__all__`, plugin loaders.
3. **Entry points.** `[project.scripts]` and `[project.entry-points]` in
   `pyproject.toml`, `setup.cfg`, `setup.py`, console scripts, CI and Docker
   commands.
4. **Framework registration.** Decorators and hooks the framework calls by
   itself: `@app.route`, `@bp.before_app_request`, signal receivers, Django
   URL confs, admin, apps, management commands and migrations, Celery tasks,
   pytest fixtures and `conftest.py` hooks, Pydantic validators.
5. **Config strings.** Dotted paths in YAML, TOML or JSON (for example Hydra
   `_target_`, Django settings, logging config).
6. **Public API.** In a library, a public name may be imported by users you
   can't see. Don't remove public names without the maintainer's decision.
7. **Test-only use.** If only tests use it, ask the user whether to delete the
   code and its tests together.

If any check finds a real use, keep the code and note why.

## 4. Remove in small, reviewable batches

Preview first. `skylos clean` edits imports and functions only; classes,
variables, parameters and files are edited by hand. Approve specific candidates
after the checks above. A file scan can miss callers in other files, so keep the
whole-repository scan and reference search as your evidence.

```bash
skylos clean . --dry-run --types import --confidence 80  # inspect the full plan
skylos clean path/to/reviewed.py --dry-run --types import --confidence 80
```

`--apply` rescans the selected path and edits **all** matching findings of the
selected types. It does not consume the preview or accept a list of approved
names. Use it only when every candidate in that path and type is reviewed and
approved. If a file includes candidates you are keeping, edit the approved
ones manually. If the source, configuration or evidence changes after preview,
preview and review again before applying.

Only after the user agrees to the exact batch, using the same path, types,
confidence and exclusions as the approved preview:

```bash
skylos clean path/to/reviewed.py --apply --types import --confidence 80
```

Cleanup exit 0 means the command completed; individual transform failures can
still be printed. Inspect the output and resulting diff before claiming every
approved edit succeeded.

Then:

1. Look at `git diff` and make sure only the intended lines changed.
2. Run the project's tests (for example `pytest`) when target execution is
   trusted or authorized; otherwise report that runtime behavior is unverified.
3. Repeat the whole-repository scan from section 2; removing code can make
   more code unused. Repeat in a new batch.

Keep each batch to one kind of change (imports, then private functions, then
the rest) so it is easy to review and revert.

## 5. Keep code that is used on purpose

When the user confirms a finding is intentional:

- `# skylos: ignore` at the end of the `def` or `class` line suppresses findings
  on that line. It is broader than a rule-specific suppression.
- `skylos whitelist 'handler_*' --reason 'called via getattr'` records a
  pattern and the reason under `[tool.skylos]` in `pyproject.toml`.

Ask before adding either; they change what Skylos reports for everyone.

## 6. Report back

Tell the user what you removed, what you kept and why, which tests you ran
and their result, and what was not checked (`analysis_errors`, excluded
folders, dynamic uses you could not rule out).

## Limits

- Python has the deepest coverage. TypeScript/JavaScript and Java get narrower
  dead-code checks; Go dead-code checks need the separately built `skylos-go`
  engine, which `pip install skylos` does not include.
- `skylos . --trace` finds dynamic uses by running the test suite. It executes
  project code, so use it only when the user asks.
- For someone else's project, prepare a small proposal using private names;
  open an issue or pull request only when the user explicitly asks you to.
