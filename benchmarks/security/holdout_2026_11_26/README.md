# Python source evidence and security holdouts

`source_provenance_cases.json` contains 14 files across two projects. The expected results were sealed before the final implementation was selected. Seven files should warn and seven should stay quiet. The rules under test are `SKY-D357` for dynamic imports and `SKY-D212` for command arguments. The CLI reads the fixture source as text.

```sh
python benchmarks/security/holdout_2026_11_26/replay.py skylos \
  --cases benchmarks/security/holdout_2026_11_26/source_provenance_cases.json \
  --no-grep-verify
```

The `--no-grep-verify` option disables the unrelated dead-code verification step. The scorer checks that Skylos inspected all labeled files and reported no analysis errors. It scores each file once against its expected rule.

`nested_argv_controls.json` contains a separate safe and unsafe command pair with seven possible data paths. The experimental command change reported both. The retained detector stays quiet on both, so the safe case passes and the unsafe case remains a known miss. To reproduce, pass this file with the same command.

`cases.json` and `followup_cases.json` contain four earlier published suites and two webhook suites respectively. They provide 112 additional labeled files for regression comparisons. Replays of published fixtures measure preservation on known cases.

Against upstream commit `7b579b13`, the release branch matched all 128 per-file decisions. Both versions scored 14/14 on the source-evidence holdout. Both flagged 30 of 51 positives and 28 of 61 safe files on the 112 earlier cases. The nested pair scored one true negative and one false negative. In separate targeted import tests, the repair detected all 10 positive projects and cleared all seven safe projects. Upstream detected eight positives and flagged one safe project.
