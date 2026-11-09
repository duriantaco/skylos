# Optional agent review after the GitHub gate

The static gate can link to **Request Review** in Skylos Cloud. That link opens
an authenticated confirmation page: it does not start a review or spend credits.
Cloud shows the repository, PR commit, source limits and credit charge before
an authorised workspace member confirms. The static gate keeps its original verdict.

After confirmation Cloud deducts the displayed credit price and dispatches
`.github/workflows/skylos-agent-review.yml` from the repository's default branch.
Its only input is `review_id`; Cloud binds that ID to the approved repository,
base/head commits, source files, model and budget. A newer PR commit requires
another confirmation. Replayed dispatches must not start a second review.

Generate the workflow with an **exact published release that contains the new
runner command**, then commit it to the default branch:

```python
from skylos.cicd.agent_review_workflow import generate_agent_review_workflow

workflow = generate_agent_review_workflow(skylos_version="X.Y.Z")
```

Replace `X.Y.Z` with that release; existing releases without
`skylos cicd agent-review` cannot run this workflow. This workflow does not check
out PR source, install its dependencies, run its tests or expose model-provider
keys. It authenticates to Cloud with GitHub OIDC using the `skylos` audience.
Cloud must validate the repository installation, workflow path, default-branch
ref, run identity and paid approval before returning a review-specific runner token.

The runner receives at most 30 source files, 64 KiB each and 512 KiB combined.
Files remain in memory and are passed as data to the existing Skylos review
prompt, schema parser and source validator. It does not load repository config or
custom prompt templates. The model sees whole changed source files, not the full
repository; cross-file findings require further verification. Deleted files,
unsupported source types are outside this review; larger reviews cannot start.
Cloud discloses these limits before consent.

One non-streaming model request per file goes through the review-bound Cloud
proxy. Cloud enforces the approved model and budget; the runner does not retry
paid model requests automatically. Malformed, truncated or failed model replies
fail the review instead of becoming a clean result. Cloud posts the final review
status and result link in the original PR comment. Failed or expired reviews
receive one refund of their charge.

The runner endpoint is:

```text
skylos cicd agent-review --review-id UUID --cloud-url https://skylos.dev
```

It is intended for the trusted dispatched workflow, not a regular PR job.
`skylos agent scan --changed` remains a separate, provider-key CLI operation;
it does not by itself implement Cloud credit consent or deduction.
