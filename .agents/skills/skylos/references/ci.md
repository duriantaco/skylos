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

Generated workflows should be deterministic, least-privilege, and explicit
about which events receive secrets.

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

- `skylos . --gate`: applies configured thresholds.
- `--strict`: fails on any issue.
- `--force`: exits zero even when the gate would fail.
- `--format concise`: exits non-zero when findings exist.

Preserve exit-code semantics unless the task explicitly asks for a breaking
change. Add CLI or gatekeeper tests when changing gate behavior.

## Security Notes

Do not design CI that executes untrusted PR code with secrets available. Be
careful with cloud policy sync: operator-controlled policy should not be
weakened by PR-controlled repository configuration.
