# Skylos Cloud

To use Skylos Cloud, you need one command:

```bash
skylos cloud
```

It runs every check, shows the findings, uploads them to Skylos Cloud, then
prints this branch's quality gate and one link to it.

## The whole path

```bash
pip install skylos
skylos .            # find problems; your code and findings stay on your machine
skylos cloud        # optional: track results per branch on Skylos Cloud
skylos cicd init    # add a Skylos check to every pull request
```

`skylos .` finds dead code. `skylos . -a` runs every check (security, secrets,
quality, AI-code defects, dependencies) and still sends no findings; the
dependency check asks OSV.dev about package names and versions.

## What `skylos cloud` does

1. The first time, it opens your browser to log in and pick the project for
   this repo.
2. It scans with every check (`-a`) and shows the findings, like `skylos . -a`.
   Name checks to run only those: `skylos cloud --danger --secrets`.
3. It uploads the findings and prints the gate for this branch.

What it sends: findings with file paths and code snippets of up to 7 lines
(none for secrets), the branch, the commit, the git author email of each
flagged line, and a map of your functions and classes (names, files, lines,
sizes, which calls which). Not your repository.

It takes the same scan flags as `skylos .`:

```bash
skylos cloud src --exclude build
```

## What you see

Failed gate on a branch:

```text
✗ Quality gate on feat/login: FAILED (was PASSED on 24 Oct 15:38 UTC, 1ba9895) · 1 critical security issue
  Open: https://skylos.dev/dashboard/projects/<project>?branch=feat%2Flogin
  Next: fix the issues behind the failed gate, then run skylos cloud again.
```

The issues are in the findings tables printed above these lines.

Passed gate on `main`, no CI yet:

```text
✓ Quality gate on main: PASSED (was FAILED on 24 Oct 15:38 UTC, 1ba9895)
  Open: https://skylos.dev/dashboard/projects/<project>
  Next: skylos cicd init — adds a Skylos check to every pull request.
```

When you upload `main` from your laptop with your `skylos login` token, one
more line says the upload is unverified: it is shown in Skylos Cloud but does
not set the project verdict or mark issues fixed. Uploads from CI do.

The link opens the project Overview for that branch: the gate, why it failed,
and how it changed since the last run.

## Which gate, and the exit code

`skylos cloud` shows the **Skylos Cloud** quality gate: the project's policy in
Skylos Cloud. It exits `0` even when that gate fails. Add `--gate` to exit `1`
when it fails:

```bash
skylos cloud --gate
```

`skylos . --gate` is a different, local gate: it uses the limits in your
`[tool.skylos.gate]` config and uploads nothing.

## Without a terminal

With no terminal and no login, `skylos cloud` stops before scanning and exits
`1`:

```text
Not connected to Skylos Cloud. Run skylos login in a terminal, or set SKYLOS_TOKEN to a project token (create one in your project's Settings on skylos.dev).
```

In GitHub Actions and GitLab CI it uses the CI identity (OIDC) or
`SKYLOS_TOKEN`. `skylos cicd init` writes a CI setup that does this for you;
see [Your first gated PR](./first-gated-pr.md).

## Do I need a key to pass the gate?

No. A token only lets you upload. The gate passes when the issues that fail it
are fixed. On the paid plans (Pro, Enterprise), a workspace admin or owner can
override a failed gate in Skylos Cloud; they must give a reason, and it is
recorded with the scan.

## The other Cloud commands

You only need `skylos cloud`. The rest are for control:

| Command | Use it to |
|:---|:---|
| `skylos cloud` | scan, upload, see the gate (the one to remember) |
| `skylos login` | switch to another project |
| `skylos whoami` | see which account and project you are connected to |
| `skylos project <command>` | manage the project linked to this repo |
| `skylos upload --retry` | resend uploads that did not finish |
| `skylos sync` | pull the project's Cloud policy into the repo |
| `skylos credits` | check your credit balance |
| `--upload` on a scan | the manual form of `skylos cloud`: uploads exactly the checks you picked |

Scans never upload findings unless you run `skylos cloud` or add `--upload`.
Every network request Skylos can make, and how to turn it off, is in
[Privacy and network](./privacy-and-network.md).
