# Type-check and profiling results in Skylos Cloud

A scan uploaded with `--upload` or `skylos cloud` can carry the type-check
and profiling results along with the findings, when the scan produced them
(`--type-check`, `--profile`) or a `skylos done` receipt supplies the type
check. A plain `skylos .` uploads nothing at all.

## What is sent

For the type check and profiling, only a fixed list of fields:

- **Type check:** the status, the checker's name, a summary and reason,
  the time taken, error, warning, project and out-of-scope counts, how many
  errors were introduced, pre-existing or unclassified, the comparison with
  the base, the suppression guard's result, whether the list was cut, and
  up to 500 diagnostics, each with file, line, column, code, message (as
  the checker wrote it), severity, origin, scope and source.
- **Profiling:** total wall time, up to 100 phases, up to 100 functions by
  total and by own time, and up to 20 notes.

Never sent: the checker's command line or path, the project's absolute
path, the checker's setup output, or fingerprints of its configuration and
program. Text fields are cut at 4,000 characters.

## Results from `skylos done`

When the scan itself did not run the type check, a `skylos done` receipt for
the same commit can supply it. With `skylos . --upload`, pass it with
`--done-receipt .skylos/receipts/latest.json`. `skylos cloud`, outside CI,
attaches the receipt by itself when the project has a committed
`[tool.skylos.done]` table, and runs `skylos done` first when there is no
valid receipt and the checkout is clean. The receipt must come from a clean
checkout of the same commit. An attached receipt is uploaded whole: its
verdict, checks and findings, and the agent model and session it records.

`skylos verify` has no upload; its type-check and profiling output stays
local.
