# Terraform/AWS configuration corpus

Run `python scripts/cloud_benchmark.py` (add `--json` for the full receipts).
The runner checks the normal Skylos analyzer on isolated fixture snapshots.
It requires Terraform file and resource coverage; no application source file is
added to make a configuration scan look complete.

This manifest runs the original `SKY-D400`/`SKY-D401` policy profile explicitly.
Other registered Terraform policies are excluded from this legacy corpus run;
the default CLI continues to run them. The unchanged expected rows below prove
only these two policies, rather than accuracy of the additional infrastructure
checks. Those checks require their own CLI and real-repository verification.

The first 16 cases cover two declaration policies:

- `SKY-D400`: an AWS security-group ingress declaration allows worldwide TCP
  administrative access on port 22 or 3389. Includes inline, standalone and
  modern ingress resources, IPv4/IPv6, and a union of literal CIDRs.
- `SKY-D401`: a directly created `aws_db_instance` explicitly sets
  `storage_encrypted = false`.

Six more cases bring the corpus to 22. They cover RDS encryption locals in a
sibling file and modern ingress resources in `.tf.json`, with unsafe, safe and
unknown controls for each. A variable's safe default does not establish its
deployed value. Numeric-string ports remain an unsupported model value, not a
safe result. These additions close evidence gaps without changing a detector.

Each resource check reports `unsafe`, `safe`, `unknown` or `not_applicable`.
The runner compares that exact outcome and the corresponding finding. Unknown
variables, providers and inherited snapshot/replica encryption never count as
safe. Malformed input must produce an incomplete parse receipt and a diagnostic.
A correctly reported unknown passes its communication contract; it contributes
no safe count. This corpus does not calculate a compliance or deployment score.

The parser reads `.tf` and `.tf.json`, combines sibling files within a module,
and resolves bounded literal locals. Input variables (including defaults),
external modules, data sources, functions and dynamic expressions stay unknown.
It neither runs Terraform nor downloads providers, executes target code, or
contacts a cloud account. Coverage is in
`analysis_summary.configuration_coverage.terraform`; application source counts
remain separate. Explicitly required unresolved policies report an analysis
error. Other unresolved policies are visible in the coverage and assessment.

These are source declaration observations. They do not prove that a resource was
applied, attached, reachable from the Internet, or free of other cloud issues.
No general IAM, S3, Kubernetes RBAC, CloudFormation, Helm, Azure or GCP policy
coverage is claimed. Limits and parse failures remain visible.

The cases are original synthetic fixtures. They are useful regression controls,
not an independent real-world holdout or a claim of broad Terraform accuracy.

References: [Terraform modules](https://developer.hashicorp.com/terraform/language/files),
[AWS security-group rules](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html),
[AWS provider ingress rules](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule),
[AWS provider DB instance](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance),
[RDS encryption inheritance](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html).
