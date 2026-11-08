# What Skylos is

Skylos is an open-source command-line tool that reads a project's code and
reports problems before they ship. It runs on your machine or in CI and needs
no account. Its rule catalog lists {{rule_count}} IDs. {{alias_count}} of them
are Go engine IDs that Skylos reports under a shared rule, so the complete
handbook has {{page_count}} rule pages; this edition has {{written_count}}.

`skylos .` on its own looks for dead code: unused functions, classes,
imports, variables and parameters, empty and unused files, and circular
imports. Other checks are added with flags:

| Flag | Adds |
|:--|:--|
| `--danger` (or `--security`) | Security problems in code, CI workflows, agent settings and deployment files |
| `--secrets` | Passwords, keys and tokens written into files |
| `--quality` | Logic bugs, complexity, structure and performance |
| `--ai-defects` | Mistakes coding agents often make, such as invented packages or weakened tests |
| `--sca` | Dependencies with known vulnerabilities and supply-chain risks |
| `-a` (or `--all`) | All of the above |

Skylos reads Python, TypeScript and JavaScript, Java, Go, PHP, Rust, Ruby,
Dart, C#, C++, Kotlin and Shell, plus configuration such as GitHub Actions
workflows, GitLab CI files, Dockerfiles, Kubernetes manifests, Terraform and
lockfiles. Coverage is deepest in Python, TypeScript/JavaScript and Java; a
rule page lists the languages that rule covers.

## What leaves your machine

A scan uploads nothing to Skylos Cloud unless you ask it to, for example
with `skylos cloud` or `--upload`. There is no update check and no
analytics. Dead-code, `--danger`, `--secrets` and `--quality` checks work
offline. Two checks look things up on public services. They send package
names and versions, never your source code:

- `--sca` asks OSV.dev about dependency versions. It also asks the GitHub
  API about advisory fix commits (with `GITHUB_TOKEN`, if set), downloads
  the `ca9` suspicious-package feed, and asks npm and PyPI for release dates
  when a release-age policy is set.
- `--ai-defects` asks PyPI, npm, the Go proxy and JSR whether imported
  packages and pinned versions exist, and reads parts of public wheel files
  from PyPI.

When a Skylos Cloud token is present, every scan also downloads your Cloud
custom rules, sending the token (`SKYLOS_CUSTOM_RULES='[]'` turns that off).
The optional AI review (chapter 9) sends code to the model provider you
configure, and to Jev when `TYPESAFE_API_KEY` is set.

## Where findings go

The terminal report shows each finding with a rule ID such as SKY-D211, a
file and line, a message, a severity and a one-line fix. `--format json` is
for scripts and agents (unused-code entries there carry no `rule_id` or
`severity`; the array they sit in says what they are), `--sarif FILE` writes
SARIF for code-scanning dashboards, and `skylos . --help` lists the other
formats.
