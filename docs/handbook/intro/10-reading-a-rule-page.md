# How to read a rule page

Every rule page has the same parts, in the same order.

| Part | What it tells you |
|:--|:--|
| Header | The rule ID, a plain title and the severity. Below them: the languages the rule covers, its CWE weakness ID when the catalog has one, the command that turns the rule on, and the finding type (defect, review or advice). When the catalog uses a different name, it is shown as **Catalog name**. |
| What it is | The problem in two or three sentences. |
| Why it matters | What can go wrong in a real project. |
| Flagged | Code Skylos reports. The line Skylos reports is shaded. |
| Not flagged | Code that looks similar but is safe, and why Skylos leaves it alone. |
| How Skylos decides | The steps the detector really follows: what it looks for, what makes it skip, and what proof it needs. |
| Fix | What to change. When the fix edits a file of the flagged example, it is shown as a change against that file. |
| False alarms and suppression | When the rule can be wrong, and how to silence one finding or all of them. |
| Related and source | Neighbouring rules, then the files a maintainer reads to check the logic. |

## The "Checked" line

Under most examples there is a line such as:

```text
Checked. Skylos {{skylos_version}}, skylos . --danger: reported at app/users.py line 13.
```

It means the handbook build wrote that example to an empty folder, ran the
real `skylos` command shown (with JSON output added), and got the expected
result: the rule reported on the flagged example, and not reported on the
lookalike or on a fix given as a whole file. The line only appears when the
example has not changed since that run.

## Examples that need a change

Some rules look at what a change does, not at one version of a file. Their
examples are printed as a diff. Lines starting with `-` were in the last
commit; lines starting with `+` are the uncommitted edit. The build commits
the old files, writes the new ones and runs Skylos with `--diff HEAD`, unless
the page asks for other flags.

## Code shown in examples

The examples are short on purpose. They keep only what the rule needs to see.
File names such as `app/users.py` are part of the example: some rules only
read certain files, such as `.github/workflows/*.yml` or
`.claude/settings.json`.
