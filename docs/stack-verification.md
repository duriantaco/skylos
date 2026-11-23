# Check an existing PR stack in CI

`skylos stack` checks stacks created by GitHub, an agent, or plain Git. It uses
ordered Git commits, not vendor metadata, and does not split, rewrite, or
publish anything. Skylos Done runs in your CI against each layer's exact
checkout, with your normal dependencies and test runner.

1. In an operator-controlled job with complete Git history, pin the approved
   base and the layer tips from lowest to highest:

   ```bash
   skylos stack plan --base origin/main --layer feature/layer-1 \
     --layer feature/layer-2 --original agent/unsplit --format json > stack.json
   ```

   The base must be an ancestor of the first layer, and each layer must
   descend from the previous one. A layer can contain more than one commit.
   `--original` is optional. With it, the last layer must have the exact same
   Git tree as that original commit, including tracked file contents and modes.
   Without it, no claim is made about preserving the original change.
2. Schedule a fresh job for **each** `layers[].sha` in `stack.json`. Check out
   that exact commit, install the normal test dependencies, and run:

   ```bash
   skylos done --base "$BASE_SHA" --format json > "$RECEIPTS_DIR/$LAYER_SHA.json"
   ```

   Use `base.sha` from the manifest for `BASE_SHA` on every layer. Keep the
   checkout clean and write the JSON outside it. Treat a nonzero Done exit
   as a failed job. The base's committed Done policy must make tests blocking
   and must not allow pre-existing failures. For a non-pytest command,
   configure `test_command` and fresh `junit_xml` in the base as described in
   [Done gate](done-gate.md). Done records its checkout state at the start;
   install dependencies outside the checkout or in an ignored directory and
   don't use setup steps that rewrite tracked files.
3. In a separate operator-controlled job, require all layer jobs to have
   succeeded. Collect their receipts from that run and verify with the same
   Skylos version:

   ```bash
   skylos stack verify --manifest stack.json --receipts-dir "$RECEIPTS_DIR" --format json
   ```

   Exit `0` means every layer has a clean, passing receipt for its exact SHA
   and the approved base policy. Exit `1` means a receipt is missing,
   mismatched or not passing (including flaky or zero passing tests). Exit
   `2` means the pinned inputs could not be verified.

## GitHub Actions

Use the [manual workflow example](../.github/workflows/examples/skylos-stack-verification.yml)
as a starting point. Install it on the protected default branch, set
`SKYLOS_STACK_VERIFY_VERSION` to a pinned release containing the verifier,
and add your project's dependency setup to the layer job. For an unpublished
pilot, replace the Skylos install steps with a pinned wheel built from a clean
Skylos tree containing only the stack verifier changes. Don't install Skylos
from the stack being checked. Keep the supplied commits reachable through
branches or tags in the checkout repository
throughout the run. The example uses the dispatched default-branch commit as
the approved base unless the operator supplies an approved older commit from
that branch's history. Inputs are full commit SHAs. The example uses fresh
GitHub-hosted runners without persisted checkout credentials, deployment
secrets, or OIDC.
Rerun **all** jobs after a failed attempt so every receipt belongs to the
same attempt. Replan after a rebase or a change to the approved base.

The verifier checks Git objects and binds **supplied** receipts; it does not
authenticate the runner or prove that tests honestly exercised the code.
Use your CI system to bind manifests, job results, and artifacts to a trusted
workflow and the same run. The layer jobs run repository code, which can
influence evidence produced in those jobs. Use this as an ordinary CI signal,
not as tamper-proof evidence or authorization to merge untrusted code. Don't
accept uploaded receipt files from a PR as proof. The manual example reports
on the workflow run; it does not install a required GitHub check on the stack
tip. It applies Done cumulatively from the pinned base, not as a separate
comparison against each predecessor.
