# Independent Mux/Tiny source review

All33 draft semantic labels agree after checking pinned source, source ranges, exact file hashes, declaration identities, direct call sites, public boundaries and selected trust paths. No target execution or scanner output was used. See the per-ID JSON for evidence and eligibility.

Two distinctions must survive freezing:

- `tiny-fused-into-inner`: source-unused inside a private module, but explicitly `#[allow(dead_code)]`. Intentional retention is not evidence the method is used; equally, failing to suggest its removal should not be treated as loss of actionable-removal accuracy. Keep it in a separate semantic-deadness/intentional-keep bucket if evaluated.
- `tiny-example-file-read`: source proves request-derived path → unbounded file open → returned contents. This is conditional unsafe filesystem exposure in an intentionally broad example. Require example inclusion/parse coverage, and label it example source-risk detection, never a core-library or deployed-service vulnerability count.

Test/benchmark-only negative labels require corresponding file coverage before any absence credit. Unknown redirect/public-API/cleanup facts stay unscored. Safe php-cgi means only no shell-code injection via the Rust construction under trusted startup argv/PATH; downstream interpreter behavior is outside the fact.

Freeze may proceed only with these explicit scope/eligibility qualifications. The review does not supply whole-repository recall or externally validated ground truth.
