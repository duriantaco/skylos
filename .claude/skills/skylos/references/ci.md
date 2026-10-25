# Skylos CI And Docs Reference

Use this reference for GitHub Actions, SARIF, gates, docs deploy, repo map, and
automation output.

## CI Output

```bash
skylos . -a --format github
skylos . -a --format json
skylos . -a --sarif skylos.sarif
skylos . --gate
```

Use `--format github` for annotations and `--sarif` for code scanning upload.
Use `--format json` when another script or agent will parse the result.

## Workflow Areas

Review these files for CI changes:

- `action.yml`
- `.github/workflows/`
- `skylos/cicd/`
- `skylos/gatekeeper.py`
- `scripts/skylos_gate.py`
- `test/test_cicd_*.py`
- `test/test_gatekeeper.py`
- `skylos/core/ci_env.py`
- `test/test_ci_platforms.py`
- `test/test_ci_bitbucket_azure.py`
- `docs/ci-platforms.md`

Generated workflows should be deterministic, least-privilege, and explicit
about which events receive secrets.

## Other CI Platforms

`skylos cicd init` picks the CI from the repository (`skylos/cicd/platforms.py`):

- `.github/workflows/` keeps the GitHub workflow; other CI files found get a
  `--ci` hint.
- Otherwise one of `.gitlab-ci.yml`, `Jenkinsfile`, `bitbucket-pipelines.yml`,
  `azure-pipelines.yml` or `.circleci/config.yml` gets that CI's template; two
  or more write nothing until `--ci` is given.
- `--ci other` and Buildkite/Travis/Drone/Woodpecker/TeamCity print commands.
- An existing CI file is never edited; the block to add is printed.

`--diff` with no value reads the pull request target branch per CI in
`skylos/core/ci_env.py`. Each variable counts only inside its own CI and only on
a pull request build; the table is in `docs/ci-platforms.md`.

When changing templates:

- Keep the GitHub workflow byte-identical unless the task changes it; compare
  `cicd init` output with HEAD across its flags.
- Jenkins and "other" install plain `skylos`: `skylos[dart]` builds from
  source and stock Jenkins agents have no C compiler. The `python:3.12`
  templates keep `[dart]`.
- Jenkins with no configured URL sets no `JENKINS_URL`; detection also uses
  `JENKINS_HOME` or a `jenkins-` `BUILD_TAG`.
- Test template changes in a CI container with a wheel of the working tree,
  not the PyPI version the template pins.

## Repo Map And Pages

Repo map generation lives in:

- `scripts/build_repo_map.py`
- `scripts/repo_map_renderer.py`
- `.github/workflows/repo-map-pages.yml`
- `docs/repo-map.html`

Validate with:

```bash
python scripts/build_repo_map.py --check
```

Pages deployment requires repository Pages settings to be configured for GitHub
Actions. Workflow code should not assume the token can create the Pages site
unless that permission is available.

## Rule Docs Parity

When rule IDs or catalog entries change, validate docs parity:

```bash
python skylos/scripts/check_rule_docs_parity.py --docs dictionary.md --catalog skylos/rules/catalog.json
```

Update `dictionary.md` and docs in the same change as rule catalog updates.

## Gate And Exit Behavior

- `skylos . --gate`: applies configured thresholds. Critical security issues,
  secrets, and critical AI-code issues (`ai_defects`, for example SKY-D222 or
  SKY-L012) fail it regardless of counts; `block_ai_defect_severities` under
  `[tool.skylos.gate]` sets the AI-code severities (`[]` turns that off), and
  `max_ai_defects` remains a separate count limit.
- `--strict`: fails on any issue.
- `--force`: exits zero even when the gate would fail.
- `--format concise`: exits non-zero when findings exist.

Preserve exit-code semantics unless the task explicitly asks for a breaking
change. Add CLI or gatekeeper tests when changing gate behavior.

## Security Notes

Do not design CI that executes untrusted PR code with secrets available. Be
careful with cloud policy sync: operator-controlled policy should not be
weakened by PR-controlled repository configuration.
