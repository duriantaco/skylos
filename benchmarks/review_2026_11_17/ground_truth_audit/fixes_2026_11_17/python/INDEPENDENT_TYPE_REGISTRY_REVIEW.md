# Independent review of closed type-registry negative evidence

Author: `/root/python_truth`. Independent reviewer: `/root/ts_truth`.

The review accepts the final implementation within its explicit supported
domain. It parses source into bounded abstract data; it never imports or
executes a target module. Unsupported behavior preserves existing conservative
liveness instead of producing negative evidence.

The domain is deliberately narrow: at most32 Python source files, a bounded
Python-only project tree, no packaging/explicit external entry contracts,
plain synchronous functions, literal defaults, no annotations or deferred
bodies, ordinary source-owned classes and trivial source-owned inheritance.
Unknown inputs, escapes, provider replacement, unsupported expressions, custom
class protocols and magic class-state mutation abort the negative proof.
Observed trace/coverage and package/test evidence revoke cached conclusions.

Review used source-visible semantic counterexamples rather than assertions on
rule names. They exposed and drove guards for:

- `bool` dispatch through its `int` base;
- custom hash, repr, operator, subclass and destructor side effects;
- class decorators/keyword-bearing class bodies and function annotations;
- discarded comprehensions and unsupported expressions;
- runtime class rebasing and captured base identity after name rebinding;
- compiler constant-pooling differences in primitive identity comparisons;
- late authoritative liveness evidence after an earlier cached negative proof.

Resource review also required caps on native operations, not just AST steps.
Repeated integer squaring, repeated repr, large scalars, table growth and
shared tuple-key graphs now abort within bounded work. Scalars are limited to
8192 bits/characters/bytes as applicable, tables to256 items, and compound keys
to bounded flat tuples. The evaluator retains its shared step/depth bounds.
Integer multiplication is checked before execution; unsupported power, shift
and sequence repetition are not evaluated. Exact primitive string operations
check bounded inputs/outputs. Custom object conversion is not performed.

Final independent tests: **20 passed**, with Ruff and whitespace checks clean.
See [the final test receipt](independent_proof_review_final.log),
[test source](/Users/oha/skylos/test/test_closed_type_registry_independent_review.py)
and [resource controls](/Users/oha/skylos/test/test_closed_type_registry_proof_limits.py).
Earlier failing receipts remain alongside the final result.

These controls validate the identified boundaries and the seven authored
registry contracts. They do not establish unrestricted whole-program analysis,
real-world population recall or authorization to remove reported code. Projects
outside the proof domain retain the analyzer's existing behavior.
