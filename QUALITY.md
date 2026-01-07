| Rule | ID | What It Catches |
|------|-----|-----------------|
| **Complexity** | | |
| Cyclomatic complexity | SKY-Q301 | Too many branches/loops (default: >10) |
| Deep nesting | SKY-Q302 | Too many nested levels (default: >3) |
| **Structure** | | |
| Too many arguments | SKY-C303 | Functions with >5 args |
| Function too long | SKY-C304 | Functions >50 lines |
| **Logic** | | |
| Mutable default | SKY-L001 | `def foo(x=[])` - causes state leaks |
| Bare except | SKY-L002 | `except:` swallows SystemExit |
| Dangerous comparison | SKY-L003 | `x == None` instead of `x is None` |
| Anti-pattern try block | SKY-L004 | Nested try, or try wrapping too much logic |
| **Performance** | | |
| Memory load | SKY-P401 | `.read()` / `.readlines()` loads entire file |
| Pandas no chunk | SKY-P402 | `read_csv()` without `chunksize` |
| Nested loop | SKY-P403 | O(N²) complexity |
| **Unreachable** | | |
| Unreachable Code | SKY-UC001 | `if False:` or `else` after always-true |
| **Empty** | | |
| Empty File | SKY-E002 | Empty File |