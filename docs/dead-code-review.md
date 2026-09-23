# Dead-code review with Skylos, Jev, and an LLM

Skylos does not contact a model during a normal scan. Start with `skylos .`
for local static findings. When you want model-assisted dead-code review, use
`skylos agent verify .` and choose one review mode:

| Command | What reviews static dead-code candidates | Credentials |
|:---|:---|:---|
| `skylos agent verify .` | LLM (the default for this command) | A configured LLM provider |
| `skylos agent verify . --dead-code-review jev` | Jev only | `TYPESAFE_API_KEY` |
| `skylos agent verify . --dead-code-review jev-llm` | Jev first; LLM checks cases Jev cannot decide confidently | `TYPESAFE_API_KEY` and a configured LLM provider |

Add `--format json` for machine-readable results. The explicit
`--dead-code-review llm` is equivalent to the default `agent verify` mode.
Setting an API key alone never turns Jev on. The older `--jev-judge` and
`--jev-precheck` flags still work for existing scripts; the latter is the
original router, not the Jev-first judge shown above. Do not combine old
Jev flags with `--dead-code-review`.

## Get a TypeSafe key

Sign in through the official [TypeSafe console](https://console.typesafe.ai/)
and create an API key for its hosted Jev service. If your account does not yet
have access, request access through [TypeSafe](https://typesafe.ai/). Set the
key in your shell before running either Jev mode:

```bash
# Bash or Zsh: paste the key (input is hidden), then press Enter.
read -rs TYPESAFE_API_KEY
export TYPESAFE_API_KEY
skylos agent verify . --dead-code-review jev --format json
```

Do not put the key in source files, version control, or CLI arguments. If a
Jev mode is selected and `TYPESAFE_API_KEY` is missing, Skylos reports the
missing key and the console URL, then stops before making model calls; it does
not silently switch to another mode. LLM-only review does not need a TypeSafe
key. Jev-plus-LLM also needs your ordinary LLM provider setup (for example,
`OPENAI_API_KEY` for hosted OpenAI, or a configured local endpoint). Jev is a
hosted API; there is no Jev package to install for this integration.

## What each decision means

Jev judges only the dead-code candidates Skylos already identified. It may
retain a candidate as unused or suppress it as used when both its confidence
and chosen-answer probability are at least 0.9. In `jev` mode, uncertainty,
an invalid response, a service outage, or a snapshot that cannot safely be
sent leaves the original finding visible and marked **unverified**. No LLM is
called. In `jev-llm` mode, those cases go to the broad LLM candidate verifier.
This fallback is not identical to the full LLM-only pipeline: separate LLM
entry discovery, Haiku prefilter, and survivor challenge are skipped in
Jev-first judge mode. Jev alone never authorizes automatic deletion via
`--fix`; inspect the evidence before removing code.

Jev receives a complete project source snapshot only when it fits the current
64 KB state limit. The local file guard is **not** a secret scanner. Inspect
source for embedded credentials and proprietary material, and use a Jev mode
only if sharing that source with TypeSafe is permitted. Larger or unsafe
snapshots leave Jev unable to judge. For sensitive source, keep the scan local
unless your LLM provider is separately authorized to receive it. Jev requests
are paid API calls and may consume TypeSafe credits.

`skylos agent scan . --verify-dead-code` can use the default LLM verifier or
`--dead-code-review jev-llm`. Jev-only is intentionally limited to
`agent verify`: other `agent scan` phases still use an LLM.

For measured accuracy, costs, and synthetic-suite caveats, see
[the Jev benchmark](../benchmark_jev.md) and the
[dead-code benchmark guide](../benchmarks/dead_code/README.md).
