# Change map (`skylos done map`)

A coding agent can write a pull request faster than a person can read it. The
change map shows what the change touches, so you know where to look first.

For every changed Python or TypeScript/JavaScript function, method and class it
lists:

- the old and new code
- the calls it added and removed, and calls that only moved into a helper
- who calls it, with the line, and whether that caller was updated in the same change
- removed security checks: auth calls, auth decorators, and inline 401/403 responses
- signature changes, marked breaking or compatible, checked against each
  untouched caller's actual arguments
- changed class settings and module values, and the code that reads them
- functions moved to another file or class, so a move doesn't look like new code

It ends with what to read first.

The map is computed from the code, not written by a model: the same commit
always gives the same map. It reads Git objects locally, runs none of the
project's code and makes no network requests.

```bash
skylos done map                          # uncommitted changes, compared with HEAD
skylos done map --base origin/main       # a pull request, compared with its merge base
skylos done map --format markdown        # for a PR comment or job summary
skylos done map --format json            # for a review agent or script
skylos done --base origin/main --map     # the done verdict, then the map
```

Exit codes: `0` the map was shown, `2` it could not be built (for example,
the base ref does not exist or the path is not a Git repository). A map never
fails a build: it has no verdict.

## Example

A change drops the login check from `charge` and adds a required `currency`
parameter, while `checkout` in another file still calls `charge(user, 10)`:

```text
$ skylos done map
Skylos change map
base 0980af2b → working tree · 1 production symbol(s) changed · 0 test symbol(s) · 1 flagged
Coverage: Python only; callers up to 3 levels; dynamic calls not modeled; tests not run.

READ FIRST
  1. charge  modified  FLAGGED  app/billing.py:4
     Why: stopped calling app.auth.require_login; breaking signature change, 1 caller(s) not in this change; reached by 1 caller(s)
     Removed security checks: app.auth.require_login
     Signature: (user, amount) → (user, amount, currency)
     Stopped calling: app.auth.require_login
     Called by: checkout app/api.py:5
```

`--format markdown` prints the same map with the before and after code of each
"read first" symbol in a collapsed block, sized for a pull-request comment
(at most 60,000 characters).

## Sections

| Section | What is in it |
|:--|:--|
| Read first | The three highest-risk production changes, plus every flagged change. Risk counts removed security checks, risky new calls, callers not updated, breaking signatures and how many callers reach the symbol. |
| Flagged | A mark on a "read first" entry. See [What gets flagged](#what-gets-flagged). |
| Module values changed | Changed module-level constants and the functions that use them. |
| Same change in many places | Three or more symbols changed the same way (same calls added and removed), listed once. |
| Safe to skim | Everything else, one line each: calls added and removed and the caller count. |
| Tests | Changed test functions, by name. |

## What gets flagged

A flag means a person should read the change before it merges. A production
symbol is flagged when the change:

- removes a security check (a call or decorator named for auth, permission,
  login, CSRF and the like, or an inline 401/403 response), or replaces an
  inline access check with a different one
- adds a risky call: shell commands (`subprocess`, `os.system`,
  `child_process`), code evaluation (`eval`, `exec`, `new Function`, `vm`),
  file deletion, unsafe deserialization (`pickle`, `yaml.load`), network
  requests, environment reads, or `dangerouslySetInnerHTML`
- deletes a function that other code still calls
- leaves a function's text unchanged while its calls now resolve to different
  functions (for example, an imported auth check replaced by a local function
  with the same name)
- changes a signature so a caller outside the change breaks, or adds an
  optional parameter that callers outside the change now silently default
- changes a security setting on a class (`permission_classes`,
  `authentication_classes` and similar)
- removes a validation rejection (`raise ValueError(...)`,
  `throw new ValidationError(...)` and similar)

Moved code and test code are never flagged.

## JSON

`--format json` and the MCP tool return the same object (`schema_version` 1):

| Key | Meaning |
|:--|:--|
| `base_commit` | The commit compared against. The other side is the working tree, including uncommitted and untracked files. |
| `symbols` | One entry per changed function, method or class, riskiest first. |
| `read_first` | Symbol ids to read first, in order. |
| `flagged` | Symbol ids that are flagged. |
| `groups` | Same-shape changes: `status`, `calls_added`, `calls_removed`, `members`. |
| `module_changes` | Changed module values with `file`, `line` and `used_by`. |
| `coverage` | `languages`, `not_mapped` (changed files in other languages), `unparsed`, `caller_depth`, `reach_is_lower_bound` and `notes`. |

Each symbol has:

- identity and status: `id` (`file::name`), `file`, `name`, `full_name`,
  `kind`, `status` (`added`, `modified` or `deleted`), `is_test`
- code: `before` and `after`, each with `start`, `end`, `signature`, `code`
  (up to 400 lines) and `truncated`
- moves: `moved_from`, `moved_to`
- calls: `calls_added`, `calls_removed`, `calls_moved`, `calls_retargeted`,
  `security_removed`, `guards_replaced_by`, `risky_calls_added`, `rejections_removed`
- signatures: `signature_changed`, `signature_change` (`breaking` or
  `compatible`), `new_optional_params`
- callers: `callers` (each with `name`, `file`, `line`, `in_change`, `is_test`),
  `possible_callers`, `callers_not_updated`, `test_callers_not_updated`,
  `breaking_callers`, `still_referenced_by`
- values: `values_changed`
- risk: `binding_changed`, `reach`, `lines_changed`, `risk`, `reasons`

`possible_callers` are calls to a method with the same name on an object
whose type Skylos could not prove. They are a guess: they never count toward
a flag.

## In the agent loop

The MCP server exposes the map as the `change_map` tool (`path`, `base`). A
review agent can read it before it reads the diff. Like the other MCP tools
except `analyze`, it requires a free Skylos API key (`SKYLOS_API_KEY`); the
key check contacts Skylos Cloud, and the map itself is built locally. It costs
no credits. `skylos done map` needs no key.

`skylos done --map` prints the map after the done verdict in text and
markdown output. It never changes the verdict, the receipt or the exit code.
For JSON, run `skylos done map --format json` separately.

## Not yet

- Languages: Python and TypeScript/JavaScript (`.ts`, `.tsx`, `.js`, `.jsx`,
  `.mjs`, `.cjs`, `.mts`, `.cts`). Other changed files are listed under
  `coverage.not_mapped`.
- Callers are searched in files that mention a changed name, up to 3 levels.
  Dynamic calls, callbacks, registries and injected dependencies are not
  followed.
- Tests are not run or matched to the changed code. To check that tests
  cover the changed lines, use `skylos done` (SKY-A120).
- React props: a renamed or removed destructured prop is not compared with
  the JSX that passes it.
- A deleted filter or check whose names say nothing about security (for
  example, a `where` clause that hid other users' rows) is listed but not
  flagged.
- A breaking change to a public function is not flagged when every caller
  inside the repository was updated in the same change.
- Logic errors inside a function are not detected: the map shows the change,
  it does not judge it.
- The pull-request comment from `skylos cicd review` does not include the
  map yet.
