## What does this PR do?

<!-- Brief description of the change -->

## Why?

<!-- What problem does this solve? Link to issue if applicable -->

## How to test

<!-- Steps to verify the change works -->

## Precision Impact

<!-- If this changes static analysis behavior, note the affected pattern or corpus case -->

## Checklist

- [ ] Tests pass (`python3 -m pytest test/`)
- [ ] No new false positives introduced (if modifying analysis logic)
- [ ] Added or updated a corpus case for any confirmed precision regression or false positive fix
- [ ] Ran the corpus guard (`python3 scripts/corpus_ci.py --manifest corpus/manifest.json`) if analysis logic changed
- [ ] CHANGELOG updated (if user-facing change)
