## Benchmark: Skylos vs Vulture (Dead-Code Detection)

This benchmark compares **Skylos** against **Vulture** on a small but *realistic* FastAPI-style Python repo. The repo is intentionally seeded with a known set of unused code so we can measure detection quality against a “ground truth”.

## What are we measuring?

We’re measuring **dead-code detection quality** at different **confidence thresholds** (operating points).

- Lower threshold (e.g. 20) = **aggressive mode**
  - reports more “unused” findings
  - tends to maximize **recall**
- Higher threshold (e.g. 60/80) = **conservative mode**
  - reports fewer findings (filters out lower-confidence ones)
  - tends to reduce noise, but can lower **recall**

If confidence=60 and confidence=80 produce the same results, that means there are **no findings with confidence scores in the 60–79 range**, so raising the cutoff doesn’t filter anything additional.


### True Positives (TP)
Items in `EXPECTED_UNUSED` that the tool flags as unused.

> “Correctly found dead code.”

### False Negatives (FN)
Items in `EXPECTED_UNUSED` that the tool **misses**.

> “Dead code that the tool failed to detect.”

### False Positives (FP)
Items in `ACTUALLY_USED` that the tool flags as unused.

> “Noise: things that are actually used but the tool says are dead.”

### Precision
How often a tool’s reported dead-code findings are correct.

- `precision = TP / (TP + FP)`

High precision = fewer false alarms.

### Recall
How much of the known dead code the tool successfully finds.

- `recall = TP / (TP + FN)`

High recall = misses less dead code.

---

## Benchmark tables (Skylos vs Vulture)

### Confidence = 20

| Metric | Skylos | Vulture |
|--------|--------|---------|
| True Positives (correctly found) | 29 | 24 |
| False Positives (flagged but used) | 1 | 2 |
| False Negatives (missed) | 0 | 5 |
| Precision | 76.3% | 55.8% |
| Recall | 100.0% | 82.8% |

### Confidence = 60

| Metric | Skylos | Vulture |
|--------|--------|---------|
| True Positives (correctly found) | 23 | 24 |
| False Positives (flagged but used) | 1 | 2 |
| False Negatives (missed) | 6 | 5 |
| Precision | 71.9% | 55.8% |
| Recall | 79.3% | 82.8% |

### Confidence = 80

> Observed behavior: **Skylos at 80 == Skylos at 60** for this repo, because no findings fall in the 60–79 confidence band.

| Metric | Skylos | Vulture |
|--------|--------|---------|
| True Positives (correctly found) | 23 | 5 |
| False Positives (flagged but used) | 1 | 0 |
| False Negatives (missed) | 6 | 24 |
| Precision | 71.9% | 62.5% |
| Recall | 79.3% | 17.2% |

---

## What we are doing

1. **Define ground truth**
   - `EXPECTED_UNUSED`: a curated list of symbols that are *truly unused* in the repo.
     - Includes unused imports, helper functions, constants, and unused classes/schemas/models.
   - `ACTUALLY_USED`: a curated list of symbols that are *definitely used* (should not be flagged).

2. **Run both tools**
   - Run Skylos with JSON output (and a confidence threshold).
   - Run Vulture with a min-confidence threshold.

3. **Normalize outputs**
   - Convert paths to consistent relative paths (e.g. `app/...`).
   - Normalize symbol names where tools disagree on representation (e.g. alias imports).
     - Example: `from x import format_money as fmt_money` may be reported as either `fmt_money` or `format_money` depending on tool. We canonicalize them so comparison is fair.

4. **Compute correctness**
   - Convert each tool’s output into a set of `(file, symbol)` pairs.
   - Compare those sets to ground truth sets.

5. **Print summary + detailed tables**
   - A summary table of TP/FP/FN + precision/recall.
   - A per-ground-truth checklist of what each tool found/missed.
   - Any false positives (things marked used but flagged).
   - Any “other” findings not in either list.

---

## What is being tested (and why we think it's realistic)

This repo is structured like a real service:

- FastAPI app entrypoint + router registration
- Layered architecture: routers → services → db/crud/models → schemas
- Typical “real repo” habits:
  - helper functions that are left around but never called
  - unused imports after refactors
  - unused schemas/models from feature churn
  - integration code (webhooks, slack/github clients) with a mix of used + unused helpers

We are explicitly testing:

### 1) Basic dead-code detection
- Unused imports
- Unused private helpers (`_normalize_query`, `_row_to_dict`, etc.)
- Unused constants (`DEFAULT_PAGE_SIZE`, etc.)

Why it matters: this is the bread-and-butter of dead-code tools.

### 2) Cross-file dependency usage
Symbols that are defined in one layer but used in another:
- routers call service functions
- services call CRUD functions
- CRUD uses models / sessions

Why it matters: real dead-code analysis is mostly about cross-file reference tracking.

### 3) Framework “implicit usage” (FastAPI wiring)
FastAPI endpoints can be “used” even if nothing directly calls them:
- `@router.get(...)` handlers are invoked by the framework at runtime
- router objects become active when included via `include_router(...)`

Why it matters: many dead-code tools struggle here and produce false positives (noise).

### 4) Name-collision / heuristic traps
A deliberate example where method names collide (e.g. `process` exists on multiple classes):
- One class method is used
- Another class method with the same name is not used

Why it matters: naive approaches may overgeneralize “method name is used somewhere ⇒ all methods with that name are used”.

### 5) Alias-import reporting differences
Imports like `import x as y` can be represented differently by different tools.
We normalize this so we are measuring detection quality, not string formatting.

---

## Why we think this is a good test

This benchmark is “good” because it is:

### Ground-truthed
We don’t just eyeball outputs; we compare against a known list of unused and used items.

### Mixed difficulty
It contains:
- easy cases (unused import)
- medium cases (unused helper in a services layer)
- hard/realistic cases (framework wiring, alias imports, name collisions)

### Fair comparison
We normalize tool outputs to avoid penalizing one tool for naming conventions (e.g. alias reporting).

### Actionable
The outputs directly map to:
- what the tool should catch
- what it missed
- what it incorrectly flagged

---

## When this benchmark would NOT be “good” (and what we’d change)

To keep this benchmark credible, we must ensure:

### A) Ground truth stays correct
If `EXPECTED_UNUSED` contains items that are actually used internally (e.g. dataclasses instantiated within their own module), then we inflate false negatives and distort recall.
**Fix:** only include truly unused items.

### B) ACTUALLY_USED is truly used
If `ACTUALLY_USED` includes things that are not actually referenced anywhere (e.g. a helper that isn’t imported/called), then we inflate false positives and distort precision.
**Fix:** only list items with a real call-site/import path.

### C) We don’t count non-app files unintentionally
If the tool scans `benchmark.py` itself, “Other Findings” will include benchmark helpers and dilute the demo.
**Fix:** run tools on `app/` only.

### D) We should evolve the test as Skylos improves
Once Skylos handles these patterns well, we can add additional realistic scenarios:
- dynamically imported plugins (entrypoints / registries)
- pydantic validators and model config usage
- FastAPI dependencies (`Depends(...)`) used via injection
- conditional imports / typing-only imports

---

## Summary

This benchmark compares Skylos vs Vulture by:
- running both tools
- normalizing their outputs
- measuring TP/FP/FN against curated ground truth
- reporting precision/recall plus detailed per-item results


## Expected Skylos Findings (Demo)

This repo intentionally contains unused imports / functions / variables / classes so Skylos has something to detect.

### Unused Imports
- `app/logging.py`: `import math`
- `app/api/routers/notes.py`: `from datetime import datetime`
- `app/api/deps.py`: `from app.config import get_settings`
- `app/api/routers/reports.py`: `from app.utils.formatters import format_money as fmt_money`
- `app/integrations/bootstrap.py", "flask"`
- `app/integrations/bootstrap.py", "sys"`
- `app/integrations/slack.py", "Tuple"`

### Unused Functions
- `app/config.py`: `_is_prod()`
- `app/api/deps.py`: `get_actor_from_headers()`
- `app/api/routers/notes.py`: `_normalize_query()`
- `app/db/session.py`: `_drop_all()`
- `app/db/crud.py`: `_row_to_dict()`
- `app/services/notes_services.py`: `_validate_title()`
- `app/utils/ids.py`: `slugify()`
- `app/utils/formatters.py`: `format_money()`

# Method-name collision / trap case (intentionally dead)
- `app/services/payment_services.py`: `process`

# Integrations (wired in; these remain unused)
- `app/integrations/http_client.py`: `request_text()`
- `app/integrations/webhook_signing.py`: `verify_hmac_sha256_prefixed()`
- `app/integrations/slack.py`: `build_finding_blocks()`
- `app/integrations/github.py`: `find_issue_by_title()`
- `app/integrations/metrics.py`: `timed_request()`

### Unused Variables / Constants
- `app/main.py`: `APP_DISPLAY_NAME`
- `app/db/crud.py`: `DEFAULT_PAGE_SIZE`
- `app/utils/ids.py`: `DEFAULT_REQUEST_ID`

# Integrations (wired in; these remain unused)
- `app/integrations/http_client.py`: `DEFAULT_HEADERS`
- `app/integrations/metrics.py`: `_queue_depth`

### Unused Classes / Models / Schemas
- `app/core/errors.py`: `class DemoError(Exception)`
- `app/db/models.py`: `class Tag(Base)`
- `app/schemas/notes.py`: `class NoteInternal(BaseModel)`

The entire codebase can be found in: https://github.com/duriantaco/skylos-demo