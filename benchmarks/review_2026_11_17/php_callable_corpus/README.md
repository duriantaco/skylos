# PHP private callable helper regression

This development fixture was derived after the reviewed Slim `CallableResolver` callbacks were found falsely reported. It is **not blind evaluation data** and does not claim whole-repository precision or recall. Main manifests and upstream target checkouts are unchanged.

The core change proves only a narrow reference chain: a direct `$this` call to a same-class private, nonstatic helper; an ordinary explicitly `callable` parameter; that parameter used only as direct invocation(s); and a literal unkeyed `[$this, 'method']` argument selecting an exact local **private** method. The analyzer adds an edge from the actual caller, not a global liveness root. Signatures are indexed before bodies, so declaration order does not matter.

The proof abstains on overridable helper or callback targets, trait dispatch, other receivers, array data, wrong parameter positions, named/unpacked arguments, interpolated/dynamic method names, nullable/by-reference/variadic parameters, ignored or rebound callable parameters, nested callable scopes, first-class callable construction, and dynamic local-scope mutation. `extract` aliases, inclusion, variable variables and unknown dynamic function calls also invalidate this narrow proof. Some excluded shapes are valid live PHP callbacks; these tests constrain the implementation's scope and do not label all excluded shapes dead.

The [manifest](manifest.json) contains one original synthetic case with ten source-reviewed labels: four used methods and six unused items. The six unused items comprise a dead caller, its private callback, a private sibling, another owner's same-named private method, and two unused import aliases. All ten labels were unchanged between runs.

| Static run | TP | FP | FN | TN | Analysis |
| --- | ---:| ---:| ---:| ---:| --- |
| Archived `analyzer_after`, before PHP fix | 6 | 2 | 0 | 2 | Complete |
| Current PHP fix | 6 | 0 | 0 | 4 | Complete |

[Before](before.json) and [after](after.json) retain raw reports, exact loaded core path/hash, manifest/fixture hashes and scored labels. Both false positives were `Review.Resolver.isRoute` and `Review.Resolver.isMiddleware`. All six true positives remained, including both unused imports. These are fixture results; the parent study runs the separately reviewed real repositories against a third saved analyzer snapshot.

Validation: 126 tests passed across the new callback controls, three independently authored audit controls, and existing PHP parser/identity/benchmark tests. The independent reviewer exposed three initial scope errors—overridable callback target, first-class callable placeholder and dynamic local rebinding—and the final code closes each. No target PHP code, dependencies, tests or package scripts were executed. `git diff --check` passed for the detector change. [Validation receipt](VALIDATION.json).

The static fixture runner accepts an explicit analyzer checkout:

```sh
/tmp/skylos-new001-validation/bin/python \
  benchmarks/review_2026_11_17/php_callable_corpus/run_corpus.py \
  --engine-root /path/to/analyzer-checkout \
  --output /tmp/php-callback-check.json
```
