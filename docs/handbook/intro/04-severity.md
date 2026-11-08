# Severity, finding type and confidence

Every finding carries up to three labels. They answer different questions,
so read them separately.

## Severity: how bad is it if it is real?

| Severity | What it usually means |
|:--|:--|
| **CRITICAL** | Direct, serious harm is likely: injection into SQL or a shell, a leaked secret, remote code from a dependency upgrade. |
| **HIGH** | A real weakness that an attacker or a bad input can usually reach. |
| **MEDIUM** | A weakness that needs more conditions to matter, or a risky practice. |
| **LOW** | Worth knowing; rarely urgent on its own. |

Each rule page shows the severity the catalog gives the rule. Some rules
raise or lower it for a particular finding: SKY-D211, for example, reports a
query passed in a variable that Skylos cannot trace to outside data as HIGH
instead of CRITICAL. The page says so under the severity.

CRITICAL is kept for shipped code. A CRITICAL finding in a test file
(`tests/`, `test_*.py`, `*.test.ts`, `conftest.py` and similar) is reported
as HIGH, with the original severity kept in the JSON. This cap does not
apply to secrets.

Rules marked **No severity** (most dead-code and quality rules) have no
fixed level in the catalog; the detector sets one per finding, or none. A
finding without a severity is shown and filtered (`--severity`) at LOW for
unused code, HIGH for security, secret and dependency findings and analysis
errors, and MEDIUM for everything else.

## Finding type: what kind of finding is it?

| Type | Meaning | Examples |
|:--|:--|:--|
| Defect | A concrete correctness pattern. Still check it in context. | Mutable default arguments, blocking calls in async code |
| Review | A possible risk that needs context to judge. | Possible SQL injection, dead code, unsafe type assertions |
| Advice | Maintainability or tooling conventions. | Function length, complexity, missing annotations |

Type is independent of severity: a Review finding can still be CRITICAL. The
terminal report groups findings as **Bugs** (Defect), **Needs review**
(Review) and **Maintainability advice** (Advice).

Advice is summarised by rule in the terminal report, and some advice is only
listed with `--all-advice`; `--expand-advice` shows each location. JSON,
SARIF and uploads keep unlisted advice too, unless you filter them with
`--severity`, `--category` or `--file-filter`.

## Confidence: how sure is Skylos that code is unused?

Unused-code findings (SKY-U001 to SKY-U004 and SKY-U006) carry a confidence
from 0 to 100. Skylos lowers it for things that are often used in ways a
static reader cannot see, such as public names, framework hooks and dynamic
access. Only findings at or above the threshold are reported: 60 by default,
changed with `--confidence`. A lower threshold lists more candidates and more
false alarms.
