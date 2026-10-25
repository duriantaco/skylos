# What leaves your machine

Skylos scans run on your machine. This page lists every network request the
CLI and the MCP server can make, what triggers each one, what it sends, and how
to turn it off. Skylos has no update check, analytics, usage tracking or
heartbeat.

## The rule

**Skylos sends nothing to Skylos Cloud unless the command or flag you ran says
it talks to Skylos Cloud.** Those are `skylos cloud`, `--upload`, `skylos login`,
`skylos whoami`, `skylos project`, `skylos sync`, `skylos credits`,
`skylos upload`, `skylos ingest claude-security`, `skylos verify-verdict`,
`skylos feedback` (a form it opens in your browser), and the `--verify` scan
option.

A token on its own is not consent. `SKYLOS_TOKEN`, a saved `skylos login` or a
CI OIDC token never makes a command upload a scan, findings or a run summary.

Three things contact Skylos Cloud without one of those commands or flags. None
of them sends source code, file paths or findings:

| What | Request | Sends | Turn it off |
|:---|:---|:---|:---|
| A scan (`skylos .`, `skylos agent scan --changed`, `skylos agent audit`) while a token can be found | `GET /api/sync/rules`: downloads your project's Cloud custom rules | your token | set `SKYLOS_CUSTOM_RULES='[]'` (or to your rules as JSON), or remove the token (see below). `--no-upload` does not stop it |
| `skylos doctor` in text mode while a token can be found | `GET /api/credits/balance` | your token | `skylos doctor --format json` |
| The MCP server started with `SKYLOS_API_KEY` | `GET /api/sync/whoami` at start and every 15 minutes; `POST /api/credits/deduct` with the tool's credit key for each paid tool call | your API key, the credit key | start the server without `SKYLOS_API_KEY` (local-only mode). It uses `SKYLOS_CLOUD_URL`, not `SKYLOS_API_URL` |

"A token can be found" means `SKYLOS_TOKEN`, a saved login in
`~/.skylos/credentials.json`, or, in a CI job that grants an OIDC token (for
example GitHub Actions with `id-token: write`), an OIDC token Skylos first
requests from the CI provider. The workflow `skylos cicd init` writes grants
`id-token: write` only to its upload job.

## Agent-run summaries

`skylos agent scan`, `skylos agent verify`, `skylos agent remediate` and
`skylos agent remediate --standards` (cleanup) send a run summary to Skylos
Cloud **only when you add `--upload`** to that command. Without `--upload`
they make no request to Skylos Cloud, even when a token is present.

With `--upload`, Skylos sends one `POST /api/agent-runs` request with your
token in the `Authorization` header and this JSON body. Nothing else: no
source code, file paths, finding text, prompts or model output.

| Field | Value |
|:---|:---|
| `command` | `scan`, `verify`, `remediate` or `cleanup` |
| `summary` | counts for that command (below) |
| `model` | the model name you chose, e.g. `openai/gpt-4.1` |
| `provider` | the model provider, e.g. `openai` |
| `duration_seconds` | how long the run took |
| `commit_hash` | `SKYLOS_COMMIT`, else the checked-out commit, else the CI commit, else `unknown` |
| `branch` | `SKYLOS_BRANCH`, else the CI branch, else the checked-out branch, else `unknown` |
| `actor` | `SKYLOS_ACTOR`, else the user your CI system reports (e.g. `GITHUB_ACTOR`), else the author name on the `HEAD` commit, else `null`. Never your operating-system user name |
| `status` | `completed` |

`summary` holds only these counts:

| Command | `summary` keys |
|:---|:---|
| `agent scan` | `total`, `reviewed`, `static_only`, `llm_only`, `both` |
| `agent verify` | `total_findings`, `verified_true_positive`, `verified_false_positive`, `entry_points_discovered`, `llm_calls`, `elapsed_seconds` |
| `agent remediate` | `total_findings`, `fixed`, `failed`, `skipped`, `pr_url` (the pull request URL when `--auto-pr` opened one, else `null`) |
| `agent remediate --standards` | `total_items`, `applied`, `reverted`, `skipped`, `total_analyzed_files` |

`skylos agent scan --upload` also uploads the scan report when it has
findings, the same way `skylos . --upload` does.

## Skylos Cloud commands and flags

`SKYLOS_API_URL` changes the Skylos Cloud address for all of these (the MCP
server uses `SKYLOS_CLOUD_URL`).

| Command or flag | Requests | Sends |
|:---|:---|:---|
| `skylos login` | opens skylos.dev in your browser, receives the token on a `127.0.0.1` callback, then `GET /api/sync/whoami` | your token |
| `skylos feedback` | none from the CLI. It opens `https://skylos.dev/feedback` in your browser (with `--github`, GitHub's new-issue form); `--print` only prints the address | the page address carries the Skylos version, OS, Python version and, if a command failed in the last 24 hours, that command with paths and secrets masked and its exit code, so loading the page sends them to skylos.dev (or GitHub). Your message is sent only when you press Send. `SKYLOS_FEEDBACK_CONTEXT=0` stops recording failed commands |
| `skylos whoami`, `skylos project use`, `skylos project status` | `GET /api/sync/whoami` | your token |
| `skylos sync connect`, `status`, `pull`, `setup`, `upgrade` | `GET /api/sync/whoami`, `/api/sync/config`, `/api/sync/suppressions` | your token |
| `skylos credits` | `GET /api/credits/balance` | your token |
| `skylos . --upload`, `skylos upload --retry`, `skylos debt --upload`, `skylos suite --upload`, `skylos defend --upload` | `GET /api/sync/whoami`; `GET /api/report/contract` (no token; `SKYLOS_UPLOAD_CONTRACT_CHECK=0` skips it); `POST /api/report`, or `/api/report/init`, an upload to the signed storage URL Cloud returns, and `/api/report/complete` | the scan report. `--no-upload` overrides `--upload` |
| `skylos . --upload` with no token in an interactive terminal | starts `skylos login` first | as `skylos login` |
| `skylos cloud` | as `skylos . -a --upload`. With no token it starts `skylos login` before the scan in an interactive terminal, and outside CI without a terminal it stops before the scan | the scan report; `-a` also makes the OSV dependency lookups below |
| `skylos compare --upload` | `POST /api/shadow/reports` | the comparison report |
| `skylos agent scan --upload` | the report upload above (when there are findings), then `POST /api/agent-runs` | the scan report; the run summary above |
| `skylos agent verify --upload`, `skylos agent remediate --upload`, `skylos agent remediate --standards --upload` | `POST /api/agent-runs` | the run summary above |
| `skylos . --verify` | `GET /api/sync/whoami`, `POST /api/verify` | the scan findings to verify |
| `skylos ingest claude-security` | `POST /api/report` **by default** | the normalized Claude Code Security findings. `--no-upload` keeps them local |
| `skylos verify-verdict` without `--keys` | `GET https://skylos.dev/.well-known/skylos-verdict-keys.json` | nothing (public keys, no token). `--keys <file>` works offline |
| The workflow from `skylos cicd init` | its upload job runs `skylos sync pull` and `skylos cloud` (`skylos . --upload` when only dead code is checked) on pushes to the default branch | the scan report. `skylos cicd init --no-upload` leaves the job out |

## Other hosts

| Host | When | Sends | Turn it off |
|:---|:---|:---|:---|
| OSV (`api.osv.dev`) | dependency checks: `--sca`, `-a`, `--select SKY-SCA-*`, `--scan-publisher-changes`, config `sca_enabled` or required `sca` coverage, `skylos suite`, `skylos baseline --sca`, `skylos compare --sca` | package names and versions from your lockfiles and manifests | don't enable dependency checks |
| GitHub API (`api.github.com`), through the `ca9` reachability library | during dependency checks, when a Python vulnerability names a GitHub fix commit | the commit URL, and your `GITHUB_TOKEN` if that variable is set. Responses are cached in `~/.cache/ca9` | don't enable dependency checks, or unset `GITHUB_TOKEN` for the scan |
| npm registry | `--scan-publisher-changes`, `--select SKY-SCA-NPM-PUB001` | package names | don't use those options |
| deps.dev | `skylos sbom --license-lookup` | package names and versions | leave out `--license-lookup` |
| PyPI (`pypi.org`, `files.pythonhosted.org`), npm registry, Go module proxy, JSR | checks for packages that don't exist and made-up package APIs: `--ai-defects`, `-a`, config `ai_defects_enabled`; always in `skylos agent scan`, `skylos agent pre-commit`, `skylos baseline`, `skylos suite`, `skylos review` and `skylos verify` on a path; `skylos done` (the `unknown_imports` check, on by default as advice); the agent hook on package-install commands; MCP `validate_code_change` | package names (and ranged reads of public wheel files) | `skylos verify --no-dependency-hallucinations`; `unknown_imports = "off"` under `[tool.skylos.done.checks]`; MCP `check_dependencies=false`; remove the hook |
| The model provider you configure (default OpenAI) | `skylos agent ...` commands, `skylos . --verify-security`, `skylos debt --with-agent`, MCP remediation and verification tools | code excerpts and prompts | don't run LLM commands; `--base-url` on `skylos agent` commands points them at a local model |
| `api.typesafe.ai` | `skylos agent verify --jev-precheck`, `--jev-judge`, `--jev-only`, `skylos agent scan --dead-code-review jev-llm`, with `TYPESAFE_API_KEY` set | the dead-code candidates to judge | unset `TYPESAFE_API_KEY` |
| Your agent endpoint | `skylos agent test` | test scenarios. Only loopback addresses unless `--allow-remote` | — |
| `raw.githubusercontent.com` or the URL you give | `skylos rules install <pack or URL>` | nothing | — |
| Your container registry and the Trivy database | `skylos image scan` | registry credentials Trivy already has | — |
| GitHub, through `gh` and `git` | `skylos cicd review` (lists, creates and edits PR comments; reads `/user`); `skylos cicd risk-review` in a GitHub pull request job (reads PR reviews); `skylos agent remediate --auto-pr` (`git push`, `gh pr create`); the gate's push prompt after two confirmations | PR comments with findings; your branch | don't run those commands |
