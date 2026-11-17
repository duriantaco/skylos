# Gorilla Mux source review before scanning

Reviewed at **2026-11-17T00:03:04.154723+00:00** by a second agent. The reviewer read source and metadata only, did not run Skylos against Mux, and did not inspect Mux scan results. No target program, test, build script or package installation was executed.

The three frozen known-used claims are **supported**. Mux has no labelled security controls and earns no security TN credit from silence. These labels measure selected false alerts, not unused-code recall or whole-repository accuracy.

| Identity | Verified value |
| --- | --- |
| Repository | `https://github.com/gorilla/mux` |
| HEAD | `db9d1d0073d27a0a2d9a8c1bc52aa0af4374d265` |
| Frozen manifest timestamp | `2026-11-17T00:02:00.903840+00:00` |
| Frozen manifest SHA-256 | `f40ff39bdec8f5cd6c03fa6a9a16b83a33f53479f619a3538a60f7da26bb1b26` |
| Checkout | `/tmp/skylos-review-20261117-repos/gorilla--mux` |
| Working tree at review | Clean (`git status --short` empty) |
| Declared source hashes | All three match |

| Label | Source proof | Review |
| --- | --- | --- |
| `mux.go:524 cleanPath` | Exact function declaration at 524; `Router.ServeHTTP` calls it at 195 before request dispatch. Router HTTP serving is a public interface and exercised by test calls. | Used |
| `mux.go:113 copyRouteConf` | Exact function declaration at 113; `Router.NewRoute` calls it at 316 and `Route.Subrouter` calls it at `route.go:559`. Both construct the router's published route graph. | Used |
| `middleware.go:74 getAllMethodsForRoute` | Exact function declaration at 74; the HTTP handler returned by exported `CORSMethodMiddleware` calls it at 58. `middleware_test.go:563` registers that middleware and the surrounding test sends a request through the router. | Used |

The calls resolve to package-owned functions, rather than merely sharing text with an unrelated declaration. Source-backed use is sufficient for these protected negative controls; target execution is not needed or claimed.

## Freshness audit

The available repository-owned `corpus/` and `benchmarks/` trees were searched with ripgrep, excluding `benchmarks/review_2026_11_17/**`. Both searches returned exit 1 with zero matches and no error:

```text
rg -n -i 'gorilla[/_-]+mux|github.com/gorilla/mux|\bgorilla\b' corpus benchmarks -g '!benchmarks/review_2026_11_17/**'
rg -n -i '\bmux\b' corpus benchmarks -g '!benchmarks/review_2026_11_17/**'
```

No recovered Desktop target directory was named `mux` or contained `gorilla`. This audit establishes absence of references in those available sources; it cannot establish absence from unavailable historical checkouts, model training data or every prior human experiment. Selection is nonrandom and model-authored, with a second-agent source review; it is not independently adjudicated human ground truth.

Chi was previously referenced by the development corpus and remains a supplementary target only. The original `holdout_manifest.json` stays unchanged. Mux is frozen in `blind_manifest.json`; the Hono, Slim, Spring Petclinic and tiny-http label objects are unchanged from the original pre-scan manifest.

## Source evidence hashes

| Source | SHA-256 |
| --- | --- |
| `mux.go` | `c707fbb675cd43278c1c315e4075f0b4f0e9b34479cecb099c12ad09a1e75e76` |
| `middleware.go` | `70ba00e0414acaf92b47fff2550a2ebcdbbe6832306b570220691c461b098d5f` |
| `route.go` | `c38f996705a96623f9fd50b3e8d584786c3d591ffe1b304730f08f2bd8cc00db` |
| `middleware_test.go` | `d5c004efaaefb626922e9f2324c21cb690f4d1039627651b960d2cc21b93da09` |
| `mux_test.go` | `2a78bbea1d3037b19e2576fdf19410e8f862bd6026e1db6cdf006aa1e9bdf814` |
| `LICENSE` | `0b77fdea862f869ef4f201ac5649bdbd38ccb055c7f6454dffae9e2adb4941c1` |

## Scoring conditions

- Award retained-control credit only if each exact labelled declaration is extracted and required analysis succeeds. Missing definitions, parser failures and unsupported outcomes remain incomplete and unscored.
- A warning against a labelled declaration, its source file or its owning class must not silently earn quiet credit through grouping. Mux's selected helpers are package-level functions.
- Unreviewed findings remain unlabelled. No unsafe/unused positive denominator exists for Mux, so recall is N/A.
- The previously observed missing extraction of Spring Petclinic `initCreationForm` remains incomplete and earns no credit; it is not repaired or relabelled based on holdout output.
- This review changed no manifest, label or detector. Scanner outcomes belong in the subsequent execution report.
