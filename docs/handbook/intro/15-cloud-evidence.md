# Type-check and profiling results in Skylos Cloud

A scan uploaded with `--upload` or `skylos cloud` can carry the type-check
and profiling results along with the findings. Nothing extra is uploaded
unless the scan produced them (`--type-check`, `--profile`), and a plain
`skylos .` uploads nothing at all.

## What is sent

Only a fixed list of fields:

- **Type check:** the status, the checker's name, a summary, error and
  warning counts, how many errors were introduced, pre-existing or
  unclassified, the comparison with the base, the suppression guard's
  result, and up to 500 diagnostics, each with file, line, column, code,
  message, severity and origin.
- **Profiling:** total wall time, up to 100 phases, up to 100 functions by
  total and by own time, and up to 20 notes.

Never sent: the checker's command line or path, the project's absolute
path, the checker's setup output, or fingerprints of its configuration and
program. Text fields are cut at 4,000 characters.

## Results from `skylos done`

When the scan itself did not run the type check, a `skylos done` receipt for
the same commit can supply it: pass the receipt with
`--done-receipt .skylos/receipts/latest.json` on the upload.

`skylos verify` has no upload; its type-check and profiling output stays
local.
