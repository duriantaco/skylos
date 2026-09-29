# Verify a Signed Verdict

Skylos Cloud signs the check result it decides for a commit: after an upload,
and again when an override, review, approval, or refresh changes that result.
The signed record is a **verdict**. `skylos verify-verdict` checks one
offline, so a deploy job can refuse to ship a commit that Skylos did not pass.

```bash
pip install "skylos[verdict]"   # adds the cryptography package for Ed25519
```

## What a verdict proves

A verified verdict proves that **this Skylos check ran under this policy and
produced this result for the results uploaded for this commit**, and that
nobody changed the result, the policy hash, or the findings summary after
Skylos signed it.

It does **not** prove:

- **That the code is safe.** It records what the policy decided about the
  findings that were uploaded. A scan that missed something still passes.
- **That Skylos checked out and scanned this commit's code.** Skylos judges
  the results a CI job uploaded for the commit. Only when `repository_verified`
  is true (a GitHub OIDC upload bound to the repository id, for a project bound
  to that repository by its GitHub repository id) can it tie those results to
  this repository's CI. For a project API key, GitLab OIDC, or any other
  upload, anyone holding that credential could have uploaded results that
  claim this commit. The command says so in one line, for example:

  ```
  The results were uploaded with a project API key "ci-deploy", so Skylos can't prove they came from this commit's code.
  ```

## Recommended deploy gate

Fetch the newest verdict for the commit **fresh from the API** at deploy time,
not from an old build artifact: a later verdict (a failed re-check, a revoked
approval) replaces an earlier PASSED one, and a stored file can be replayed.

```bash
curl -fsS "https://skylos.dev/api/v1/verdicts?commit=$SHA&project_id=$PROJECT_ID" \
  -H "Authorization: Bearer $SKYLOS_TOKEN" \
  | jq '[.data[] | select(.current)][0].bundle' > verdict.json

skylos verify-verdict verdict.json --commit "$SHA" \
  --repository github.com/org/repo --require-repository-verified \
  --max-age 7d --require-passed
```

The API needs an organization API token with `read:findings` and a
`project_id` (one commit can have a different decision in each project; pass
the same id with `--project`). The verdict marked `current: true` is the
project's decision for that commit as it stands now: the server re-signs it
when the decision changed or the stored one is over a day old, so
`--max-age 7d` always has a fresh verdict to check. The gate fails closed: if
there is no current verdict (never scanned, scan pruned by retention, or
signing not set up), `verdict.json` holds `null` and the command exits 2.

You can also download a verdict from the scan page in the dashboard
(**Download** next to its signed verdict).

## Options

| Option | Fails unless |
|:---|:---|
| `--commit SHA` | the verdict is for this full 40-character SHA (case-insensitive). |
| `--repository HOST/OWNER/REPO` | the verdict's repository is this one, e.g. `github.com/acme/api` (case-insensitive). |
| `--project PROJECT_ID` | the verdict is for this Skylos project id (exact). |
| `--workspace ORG_ID` | the verdict belongs to this Skylos workspace id (exact). Verdicts signed before workspaces were recorded never match. |
| `--require-repository-verified` | the upload was GitHub OIDC bound to the repository **and** the project is bound to that repository by its GitHub repository id (`repository_binding: verified`; missing counts as unverified). |
| `--max-age DURATION` | the verdict was signed within this time (`90m`, `24h`, `7d`, `2w`; units `s m h d w`). A signing time more than five minutes in the future is rejected. |
| `--require-passed` | the result is PASSED at level `SKYLOS_POLICY_PASSED`. |
| `--allow-override` | with `--require-passed`, also accept `SKYLOS_GATE_OVERRIDDEN`. |
| `--keys PATH_OR_URL` | (trusted keys; see below) |
| `--json` | (prints one JSON object) |

### Verified levels

A PASSED verdict carries exactly one level:

| Level | Meaning | `--require-passed` |
|:---|:---|:---|
| `SKYLOS_POLICY_PASSED` | The policy passed. | Passes. |
| `SKYLOS_GATE_OVERRIDDEN` | An admin chose "merge anyway". | Exit 1, unless `--allow-override`. |
| `SKYLOS_GATE_DISABLED` | The workspace gate is off, so nothing was enforced. | Always exit 1. |
| `SKYLOS_GATE_UNKNOWN` | An older scan recorded no gate settings, so the pass isn't a policy decision. | Always exit 1. |

A FAILED verdict has the level `FAILED`. The command prints the level it found.

## Output and exit codes

```
Verified: PASSED for github.com/org/repo@3f2a9c1e… (level SKYLOS_POLICY_PASSED, scan 2222…, policy bbbbbbbbbbbb, key skylos-verdict-a0065c999b24100a, verified 2026-09-29T00:00:01.000Z)
```

When it can't verify, it prints `Not verified: <reason>` to stderr, for
example `Not verified: No valid signature from a trusted Skylos key.` or
`Not verified: The verdict is older than the allowed age.`

| Exit | Meaning |
|:---|:---|
| `0` | Verified, and every option you passed holds. |
| `1` | Only with `--require-passed`: verified, but not passing (FAILED, an overridden gate without `--allow-override`, or a disabled gate). |
| `2` | Not verified: bad signature or content, a `--commit`, `--repository`, `--project`, `--workspace`, `--require-repository-verified`, or `--max-age` mismatch, invalid input, keys unavailable, or `cryptography` not installed. |

`--json` prints one object instead: `verified`, `verdict`, `verified_level`,
`commit`, `repository`, `repository_binding`, `project_id`, `workspace_id`,
`scan_id`, `policy_hash`, `key_id`, `time_verified`, `repository_verified`
(the `--require-repository-verified` condition), and `reason` (why the command
did not exit 0; `null` when it did). When `verified` is false, every other
field except `reason` is `null`.

## What the command checks

In this order, matching Skylos Cloud's own verifier:

1. The bundle schema and a DSSE envelope with payload type
   `application/vnd.in-toto+json`.
2. An Ed25519 signature over the DSSE pre-authentication encoding from a key
   in the trusted key set.
3. The signed payload is an in-toto Statement v1 with a SLSA Verification
   Summary predicate (`https://slsa.dev/verification_summary/v1`) from the
   Skylos verifier, for one full commit SHA, with result PASSED or FAILED.
4. The SHA-256 of the bundled summary equals the digest the statement signs.
5. The summary names the same commit, result, and repository or project as
   the statement.
6. The commit, project, workspace, repository, repository verification, and
   signing age you asked for.
7. With `--require-passed`, the verified level.

## Keys and rotation

By default the command fetches the published key set from
`https://skylos.dev/.well-known/skylos-verdict-keys.json` (https only, 10 s
timeout, 1 MB cap; redirects must stay on https). For offline or pinned
verification, save that file and pass it with `--keys`:

```bash
curl -fsS https://skylos.dev/.well-known/skylos-verdict-keys.json -o skylos-verdict-keys.json
skylos verify-verdict verdict.json --keys skylos-verdict-keys.json --require-passed
```

The key set is your trust root, so only pass `--keys` a source you trust.

- **Key ids are bound to keys.** A key id is `skylos-verdict-` plus the first
  16 hex characters of the SHA-256 of the key's SubjectPublicKeyInfo DER. A
  published entry whose id does not match its own key is ignored.
- **Rotation keeps old verdicts valid.** New verdicts are signed with the
  `active` key. Keys that were rotated out stay in the set as `retired`, so
  verdicts signed before a rotation keep verifying. Use `--max-age` to stop
  accepting old verdicts.
- **Removal revokes.** A key taken out of the published set no longer verifies
  anything it signed.
- **Pinned copies go stale.** After a rotation, a pinned key file does not
  know the new active key, and new verdicts fail with `No valid signature from
  a trusted Skylos key.` Refresh the file. The published set may be cached for
  up to five minutes.
