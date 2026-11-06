# Pinned upstream checks

These are targeted labels from independently maintained upstream repositories.
Expected facts and source hashes were recorded before the first Skylos scan.
The manifest labels an **open set**: unreviewed findings are not automatically
false positives, and an unreported item does not automatically count as safe.
There is no whole-repository accuracy percentage.

| Target | Upstream class | Labels |
| --- | --- | --- |
| `ruby/rake` at `3f29d39daa688eb51cd975c06b1501320f10b911` | Maintained MIT Ruby library | Five known-used private helpers in `lib/rake/task.rb`, supported by direct calls from public API paths |
| `bridgecrewio/terragoat` at `729f8da62c6a85ce4af5ad3d123de97776d954c4` | Apache-2.0, deliberately vulnerable training repository | Two unsafe AWS declarations, two not-applicable ingress checks and one unresolved check |

Rake's selected helper references are visible in the same class: prerequisite
lookup, comment addition/transformation, first-sentence extraction and trace
formatting. This checks whether those particular used methods are incorrectly
reported. It does not measure Ruby dead-code recall or establish that every
unreported method is live.

TerraGoat explicitly documents its training purpose and independently lists its
worldwide SSH and unencrypted RDS examples. Its declarations are read as data;
Terraform, providers, shell scripts, application code and cloud APIs are never
run. These facts do not prove applied state or live Internet reachability.
Numeric-string port fields and resource-derived CIDRs remain an explicit
unresolved control. Unknown and not-applicable results earn no safe/TN credit.
The initial cloud engine covers only two policies; other resource families
remain outside those policies.

Use complete pinned checkouts and the declared `scan_root`, not extracted
snippets. Check the commit, repository cleanliness and every `source_files`
SHA-256 before and after analysis. Missing, modified or unsupported inputs must
be incomplete, not a passing absence. Ruby labels require the exact parsed
symbol and source file as well as absence from unused findings. Terraform
labels require actual parsed-file/resource coverage and the exact per-resource
policy status.

No upstream source is vendored here. The manifest records the upstream license
file; the checkouts remain separate static inputs. Default offline CI must not
fetch repositories or treat a missing checkout as a passed holdout.

With both pinned checkouts already present under one directory, run:

```bash
python scripts/security_holdouts.py --checkout-root /path/to/checkouts
python scripts/security_holdouts.py --checkout-root /path/to/checkouts --json
```

The directory must contain `rake/` and `terragoat/` at the exact manifest commits.
The runner never fetches or installs them. It rejects changed, untracked or
ignored files, symlinks, special files and mismatched pins/origins/hashes. It
repeats checkout checks after scanning. A missing checkout fails rather than
silently skipping its labels. Use `--target` with a manifest target ID to select
one check. JSON output includes the native reports, source hashes, selected
outcomes, unreviewed finding counts and partial Terraform coverage.

Sources: [Rake source](https://github.com/ruby/rake/blob/3f29d39daa688eb51cd975c06b1501320f10b911/lib/rake/task.rb),
[Rake license](https://github.com/ruby/rake/blob/3f29d39daa688eb51cd975c06b1501320f10b911/MIT-LICENSE),
[TerraGoat training documentation](https://github.com/bridgecrewio/terragoat/blob/729f8da62c6a85ce4af5ad3d123de97776d954c4/README.md),
[AWS declarations](https://github.com/bridgecrewio/terragoat/tree/729f8da62c6a85ce4af5ad3d123de97776d954c4/terraform/aws),
[TerraGoat license](https://github.com/bridgecrewio/terragoat/blob/729f8da62c6a85ce4af5ad3d123de97776d954c4/LICENSE).
