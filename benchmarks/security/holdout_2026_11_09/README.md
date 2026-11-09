# Security gap replay and new repository holdouts

This change tightens source provenance and adds the Python checks exercised by
`security-gaps.md`. It does not solve general SAST precision.

The repository replay counts, labels and runtime fingerprint below describe the
frozen security implementation at `2621062e`, before integration with newer main
changes. They are historical measurements, not fresh accuracy measurements of the
merged implementation.

The frozen implementation completed the original **26 pinned repository scans**
with valid JSON and no timeout. All **12 original REAL cases remain detected**.
Of the original **101 WRONG historical labels, 37 still appear as security
claims**. The other 64 no longer do; some moved into explicit UNKNOWN diagnostics.
That is a classification/provenance improvement, not proof that 64 operations
are safe. These are matches against historical labels, not a fresh 275-row
measurement. New unreviewed detections are excluded from those counts.

The fresh PyPI 5.4.0 comparison produced usable code-security output for 24 of the
original 26 repos; Google API client and HanLP baseline full attempts timed out.
They were never counted as clean scans. The final implementation completed all 26.
Labml and HanLP retained 13 and 6 unverified dead-code candidates respectively.
Dependency/SCA coverage was incomplete; no dependency-vulnerability or full-profile
clean-bill claim is made here.

## New holdouts

The repositories below were selected/pinned before findings, with source checks
for related behaviors recorded before scanning. They had no overlap with the
prior benchmark/scored inventories. The two engines used the same pins and
`skylos REPO -a --json --no-upload --no-provenance`. Target code, tests and package
scripts were never executed; target dependencies were not installed.

| Engine | Listed rows | REAL | NOISE | WRONG | UNRESOLVED |
| --- | ---: | ---: | ---: | ---: | ---: |
| Official PyPI 5.4.0 | 208 | 1 | 37 | 133 | 37 |
| Frozen change | 160 | 1 | 26 | 97 | 36 |

All 217 union rows have per-row labels, trust-boundary reasoning, confidence,
limits and pinned source URLs/hashes in [labels.json](./labels.json). Related
rules are separate rows. The same HTTPie TLS issue is retained; its visible
impact is update-metadata integrity, not automatic installation or RCE.
Unresolved cases are excluded from any resolved precision denominator. These
small holdouts do not establish repository-wide recall.

The reductions include diagnostic reclassification: 31 removed WRONG rows remain
UNKNOWN diagnostics; 10 other WRONG rows are absent from native output. Five
additional WRONG redirect rows appear versus PyPI, but all five also appear in
the task-start checkout and were not introduced by this change. ArchiveBox still
has substantial escaping, SQL and path-context noise. Its unrelated directory
symlink prevents a complete project-source snapshot, so source-required policy
conservatively retains incomplete candidates. Source review also found an
undetected helper-forwarded cleartext metadata request; a meaningful security
impact remains unresolved. No product change was tuned to these holdout findings.

| Repository | Pinned commit |
| --- | --- |
| [httpie/cli](https://github.com/httpie/cli) | `5b604c37c6c67e18e7c3e9aee6c88a8c22b98345` |
| [simonw/datasette](https://github.com/simonw/datasette) | `4e70219b7b817b9bf9dd200bdc14bc1a53a4515d` |
| [ArchiveBox/ArchiveBox](https://github.com/ArchiveBox/ArchiveBox) | `2afd1f662aa9f701c1bb57a3e66b08cb25e6d11c` |

## Concrete coverage and remaining boundaries

- The exact Maigret operator-input paths, Khoj server UUID filenames and internal
  PDF translation request cases no longer produce the reported path claims.
- SQLAlchemy builders, fixed SQL text/digests and native Cosmos query sinks are
  recognized. Unresolved SQL/redirect inputs stay diagnostics after a complete
  project analysis. An incomplete index retains candidates conservatively.
- Python credential logging and urllib scheme audits are restored. Proven HTTP
  response/public verified-payload fields do not inherit request/signing secrets.
  URL-scheme audits remain UNKNOWN diagnostics; source-backed SSRF remains.
- Native browser TLS disabling is restored. The reported HTTP request, Gradio
  normal launch, remote-config import and registered search callback argv flow
  are detected on their original source lines or documented sink mappings.
- Jinja environment autoescape configuration, cached request-host URLs,
  security-context weak randomness and fixed shared temporary directories have
  source-backed checks. Jinja render 94 is represented by its environment
  configuration warning, not a separately proven render-source flow.
- The two GraphRAG Cosmos compiler/sink candidates remain UNKNOWN at the
  application trust boundary. Unsafe SQL construction is visible, but a concrete
  pinned remote/LLM filter caller was not proven; they are not counted as two
  listed, remotely confirmed vulnerabilities.
- RFC OAuth public identifiers/examples and legitimate source Unicode/log
  templates have negative controls. Path check grouping affects terminal display;
  JSON, SARIF and gates preserve the underlying distinct findings.

## Validation

The isolated publication checkout passed **2,753 tests across 64 files** with
runtime source hashes unchanged. A test-fixture portability spelling correction
then passed the same 62 focused path cases; assertions and runtime bytes did not
change. All 57 changed Python files parse under Python 3.10 and 3.11. The suite was
not an every-rule or whole-project test certification. Historical local contract
checks with unrelated drift were not reported as passes.

All scanned target source hashes and both frozen engine inventories remained
unchanged. Each label binds to the pinned full file SHA256; no label is inferred
from a rule ID alone. Runtime source fingerprint: `f70f090a629831d7da5bffa363dd049e4972ab87753abf4988f77918b3d7d055`.

## Main integration validation

Integration with main `a10d85d3` preserves its newer logging, native-provider,
mutation and source-snapshot checks. A combined run across 101 test files
completed with 3,868 passes and two expected failures. Its single failing core
benchmark reproduced the same 13 Go case failures on exact main: the tracked Go
binary predates source fixes. An offline build of main's Go source passes those
13 cases and the merged core benchmark without changing expectations.

Final urllib/source-prefilter checks pass 417 cases. A duplicated urllib audit
hook was removed, and concatenated shared temporary paths now reach the new
scanner. The frozen private contract registry remains blocked by reviewed
version drift; that registry is not reported as passed. The replay counts and
labels above remain bound to the earlier frozen implementation.

Final SQL/Cosmos checks pass 178 cases. Selected pinned source replays retain
the earlier path classifications and security detections. Both GraphRAG Cosmos
query candidates remain present as UNKNOWN diagnostics with `safety_proven:
false`; they are not silently lost or counted as confirmed vulnerabilities.
These bounded static checks did not execute target code or repeat the full
29-repository accuracy study.

## Original repository pins

| Repository | Commit | Final scope |
| --- | --- | --- |
| [annotated_deep_learning_paper_implementations](https://github.com/labmlai/annotated_deep_learning_paper_implementations) | `2be1800d141eb2716d6079405bbe47ce1040ef85` | code-security output complete; dead-code verification incomplete |
| [asgiref](https://github.com/django/asgiref) | `03dcd190a363be6e501b2819803e70495200551c` | code-security output complete |
| [asn1crypto](https://github.com/wbond/asn1crypto) | `a767d2daa8ef4549d497b67a0304561c2eb4b858` | code-security output complete |
| [asyncpg](https://github.com/MagicStack/asyncpg) | `13b01910da3fe01b8241c31cc86eccb1301a2d39` | code-security output complete |
| [authlib](https://github.com/authlib/authlib) | `df5fb3eab96423f2a0b0ecf1cbf918ad4e5133d5` | code-security output complete |
| [ChatDev](https://github.com/OpenBMB/ChatDev) | `464a681ba7bda869db97a50c5fa707c9a0fb57a0` | code-security output complete |
| [CloakBrowser](https://github.com/CloakHQ/CloakBrowser) | `b860957b1299967e1f0226b629b1da2d36e53c82` | code-security output complete |
| [docker-py](https://github.com/docker/docker-py) | `e734fd5a5508bc1062a28a51dc2f31ae47af7a2f` | code-security output complete |
| [fish-speech](https://github.com/fishaudio/fish-speech) | `0f8a12e8a651062fdee9c33a894bdccd3a8513f1` | code-security output complete |
| [google-api-python-client](https://github.com/googleapis/google-api-python-client) | `c1bdb24533614d6fcffeb7b9a93b2fc836c4e4e0` | code-security output complete |
| [gpt-pilot](https://github.com/Pythagora-io/gpt-pilot) | `9b763fdaf0020c7d8abacc7b58b2b09e57494623` | code-security output complete |
| [graphrag](https://github.com/microsoft/graphrag) | `c600ff80b77b9b62c47d539a3ac9569e95d8949b` | code-security output complete |
| [HanLP](https://github.com/hankcs/HanLP) | `281e8ef1821bd49d0c4bd38a2111729863e924d0` | code-security output complete; dead-code verification incomplete |
| [heretic](https://github.com/p-e-w/heretic) | `ecde93f1e012bb344ac45de5cbd1027275f8b136` | code-security output complete |
| [httplib2](https://github.com/httplib2/httplib2) | `dbbba89e394c98813884d06061d661e033acc023` | code-security output complete |
| [khoj](https://github.com/khoj-ai/khoj) | `ae229ca894c0b80ad84664afcfdde523b5e87057` | code-security output complete |
| [langextract](https://github.com/google/langextract) | `3493510c234c82e217f683071b13562529b2bbdd` | code-security output complete |
| [maigret](https://github.com/soxoj/maigret) | `b8747b98820f4df9d1baf23235db7b2cb55d0198` | code-security output complete |
| [OCRmyPDF](https://github.com/ocrmypdf/OCRmyPDF) | `b457e9efa68c3a46be2470ffb222ed1bccc4dcbc` | code-security output complete |
| [PDFMathTranslate](https://github.com/PDFMathTranslate/PDFMathTranslate) | `3bdb146c0453239fd2c863f848580f0b97fe349e` | code-security output complete |
| [pre-commit](https://github.com/pre-commit/pre-commit) | `8cb5845c835b1ff72240eb2484239411ec481d92` | code-security output complete |
| [rapidfuzz](https://github.com/rapidfuzz/RapidFuzz) | `09328422916b13181238660cd3b23a71905d1ec9` | code-security output complete |
| [Scrapegraph-ai](https://github.com/ScrapeGraphAI/Scrapegraph-ai) | `194055e203afce41ed4e70365dbc416bad756115` | code-security output complete |
| [searxng](https://github.com/searxng/searxng) | `ffa88e3ba3ade64185d5754c839cdf5a80708c4a` | code-security output complete |
| [timesfm](https://github.com/google-research/timesfm) | `e51928e27119cb17bebc005be2696b75e0a9e688` | code-security output complete |
| [traitlets](https://github.com/ipython/traitlets) | `a576f243ec6c7be0ac3d00b3ba294408a84b068e` | code-security output complete |
