# Requests

Want to help but don't know where to start? Pick a request below. Each one
says what we need, which files to read first, which tests cover them, and how
to check your change.

Setup and the pull request checklist are in [CONTRIBUTING.md](./CONTRIBUTING.md).
For a big change, open an issue first.

| Request | Start in |
|:---|:---|
| [Fewer false positives: Python security](#fewer-false-positives-python-security) | `skylos/rules/danger/` |
| [Fewer false positives: Python dead code](#fewer-false-positives-python-dead-code) | `skylos/deadcode/`, `skylos/visitors/` |
| [Fewer false positives: TypeScript and JavaScript](#fewer-false-positives-typescript-and-javascript) | `skylos/visitors/languages/typescript/` |
| [Less noise from missing-package checks](#less-noise-from-missing-package-checks) | `skylos/rules/ai_defect/` |
| [Fewer warnings on shell scripts](#fewer-warnings-on-shell-scripts) | `skylos/visitors/languages/shell/` |
| [Catch more real issues](#catch-more-real-issues) | `skylos/rules/danger/danger_cors/` |
| [Good first issue: add a missing test case](#good-first-issue-add-a-missing-test-case) | `benchmarks/security/` |
| [Support more package managers and languages](#support-more-package-managers-and-languages) | `skylos/rules/sca/`, `benchmarks/holdouts/` |
| [Make Skylos faster](#make-skylos-faster) | `scripts/analyzer_speed_check.py` |

## How to work on any request

1. Install from source: `pip install -e ".[test]"`.
2. Reproduce the problem on a small example:

   ```bash
   skylos path/to/example -a --format json --no-upload
   ```

   Each finding has a `rule_id`, `file`, `line`, `message`, and the evidence
   behind it in `metadata`.
3. Write two tests first: the safe code must stay quiet, and the unsafe
   version of the same code must still be found.
4. Fix it in general. Never special-case one repository, file name or
   variable name.
5. Run your tests, the benchmark for your area, and
   `python -m ruff check skylos test`.
6. In the pull request, show the benchmark before and after.

A change that cuts noise by hiding a real issue will not be merged.

## Fewer false positives: Python security

Focus on:

- `skylos/rules/danger/untrusted_sources.py`: decides what counts as attacker
  input (request data, `input()`, `sys.argv` and so on). Most false positives
  start here.
- `skylos/rules/danger/danger_fs/path_flow.py`: path traversal (`SKY-D215`)
  and symlink checks (`SKY-D324`, `SKY-D325`).
- `skylos/rules/danger/danger_fs/path_provenance.py`: follows a path
  parameter back to every caller to see where the value came from.
- `skylos/rules/danger/danger_fs/filename_match.py`, `prefix_separator.py`,
  `weak_path_defence.py`: which path checks make a value safe, and which only
  look safe.
- `skylos/rules/danger/danger_net/ssrf_flow.py`: SSRF (`SKY-D216`).
- `skylos/rules/danger/danger_cmd/cmd_flow.py`: command injection (`SKY-D212`).

Open now:

- **SSRF on a command-line tool's own arguments.** `ssrf_flow.py` treats
  `sys.argv` and `os.environ` as the operator's input (`_OPERATOR_MAPPINGS`),
  but not values parsed by `argparse`. A URL typed by the person running the
  tool is not SSRF. `untrusted_sources.py` can already tell which names are
  `argparse` parsers.

Tests: `test/test_path_*.py`, `test/test_path_symlink_review.py`,
`test/test_ssrf.py`, `test/test_untrusted_source_flows.py`

Check: `python scripts/security_benchmark.py` (add `--scanner bandit` to
compare with Bandit).

## Fewer false positives: Python dead code

Focus on:

- `skylos/visitors/framework_aware.py`: marks routes, handlers and other
  framework entry points as used.
- `skylos/visitors/test_aware.py`: test code and fixtures.
- `skylos/deadcode/`: one file per kind of proof that code is used, such as
  `web_framework_liveness.py` (Flask, Django), `fastapi_liveness.py`,
  `registration_liveness.py` (decorators and registries), `reachability.py`
  and `confidence.py`.

Tests: `test/test_dead_code*.py`, `test/test_framework_aware.py`,
`test/test_corpus_ci*.py`

Check: `python scripts/corpus_ci.py` and `python scripts/dead_code_benchmark.py`
(add `--scanner vulture` to compare with Vulture).

To add a case, put a small project in `corpus/fixtures/` and add an entry to
`corpus/manifest.json` that says what must be `present` and what must be
`absent`.

## Fewer false positives: TypeScript and JavaScript

Focus on `skylos/visitors/languages/typescript/`:

- Dead code: `core.py` (parsing), `framework.py`, `nextjs.py`,
  `package_exports.py`, `reexport_demand.py`, `workspace.py` (monorepos).
- Security: `security_flow.py`, `express_taint.py` (request data in server
  handlers), `security_proofs.py`.
- `skylos/core/js_api_surface*.py`: what a package exports to other code.

Tests: `test/test_typescript*.py`, `test/test_ts_*.py`

Check: `python scripts/corpus_ci.py`, `python scripts/dead_code_benchmark.py`,
`python scripts/security_benchmark.py`

## Less noise from missing-package checks

`SKY-D222` reports a package that does not exist. `SKY-D223` reports code
that imports a package the project does not declare.

Focus on:

- `skylos/rules/ai_defect/dependency_hallucination.py`: both rules, and the
  map from import names to package names (`cv2` to `opencv-python`).
- `skylos/rules/ai_defect/pipreqs_import_mapping.txt`: more import-to-package
  names.
- `skylos/rules/ai_defect/environment_dependencies.py`: packages the
  project's own environment files install.
- `skylos/rules/ai_defect/manifest_dependency_hallucination.py`: made-up
  packages in manifests.

What is noise: an import of a local module, a package from the operating
system (apt, ROS), or one the project's own install files add. A real missing
package must still be reported, once per package.

Tests: `test/test_hallucination_dependency.py`, `test/test_dependency_*.py`,
`test/test_manifest_dependency_hallucination.py`

Check: `python scripts/ai_code_defect_benchmark.py`

## Fewer warnings on shell scripts

Focus on `skylos/visitors/languages/shell/danger.py`: command injection
(`SKY-D212`), paths (`SKY-D215`) and persistence (`SKY-D338`, `SKY-D339`).

Open now:

- **Root-only admin and install scripts.** A script that exits unless it runs
  as root already lowers its findings one level (see
  `test_root_only_script_arguments_lower_one_level`). Its arguments come from
  someone who already has root, so many of these findings are noise, such as
  an installer enabling the service it installs. We need clear rules for when
  such a script should not be reported at all.

Tests: `test/test_shell_security.py`, `test/test_shell_privilege_context.py`

## Catch more real issues

Open now. Both are product decisions, so open an issue before writing code:

- **Wildcard CORS on a read-only service.**
  `skylos/rules/danger/danger_cors/cors_flow.py` reports wildcard CORS
  (`SKY-D231`) only when the app also has routes that change state. Semgrep
  reports every wildcard. Tests: `test/test_cors_flow.py`,
  `test/test_cors_open_routes.py`.
- **A development server open to the network.** Other rules use
  `app.run(host="0.0.0.0")` as evidence
  (`skylos/rules/quality/_route_exposure.py`), but it is not a finding on its
  own. Semgrep reports it.

## Good first issue: add a missing test case

Each security rule should have a vulnerable example that must be found and a
safe example that must stay quiet. These are missing from
`benchmarks/security/manifest.json`:

| Rule | Language | Missing |
|:---|:---|:---|
| `SKY-D212` command injection | Shell | safe example |
| `SKY-D211` SQL injection | TypeScript | vulnerable example |
| `SKY-D206` unsafe YAML load | Python | vulnerable example |
| `SKY-D231` CORS misconfiguration | Python | safe example |
| `SKY-D232` JWT verification | Python | safe example |

Read `benchmarks/security/README.md`, add a small folder under
`benchmarks/security/fixtures/`, add a case to the manifest with `present`
or `absent`, then run:

```bash
python scripts/security_benchmark.py --case <your-case-id>
```

## Support more package managers and languages

- **SwiftPM, CocoaPods and Hex lockfiles** are not read yet.
  `skylos/rules/sca/` has one reader per lockfile (`cargo_lockfile.py`,
  `composer_lockfile.py`, `pubspec_lockfile.py` and others); add one the same
  way. Tests: `test/test_*_lockfile.py`.
- **Real-repository dead-code labels** for C#, Kotlin, Rust, Dart, PHP and
  C++: pinned public repositories with hand-checked used and unused symbols.
  See `benchmarks/holdouts/README.md`.

The full list of known gaps is in `benchmarks/GAPS.md`.

## Make Skylos faster

`python scripts/analyzer_speed_check.py` times the analyzer on each language.
Run it before and after your change and put both results in the pull
request. Test: `test/test_analyzer_speed_check.py`.
