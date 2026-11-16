"""Discarded promises require local callable identity, not name/type guesses."""

import pytest

from skylos.visitors.languages.typescript import scan_typescript_file


def _scan(tmp_path, source, *, config=None, enabled=True):
    path = tmp_path / "app.ts"
    path.write_text(source, encoding="utf-8")  # skylos: ignore[SKY-D324] fixed filename in each caller's fresh pytest tmp_path
    findings = scan_typescript_file(
        str(path), config=config, enable_quality_rules=enabled,
        enable_danger_rules=False, _include_analysis_metadata=True,
    )[6]
    return [row for row in findings if row["rule_id"] == "SKY-Q410"]


@pytest.mark.parametrize("source", [
    'async function save() { throw new Error("failed"); } save();',
    'save(); async function save() { return 1; }',
    'const save = async () => 1; save();',
    'const save = async function() { return 1; }; save();',
    'let save = async () => 1; save();',
    'var save = async () => 1; save();',
    'async function save() { return 1; } const alias = save; alias();',
    'async function save() { return 1; } const alias = save; save = () => 0; alias();',
    'const save = async () => 1; const first = save; const second = first; second();',
    'async function save() { return 1; } function run() { save(); }',
    'async function save() { return 1; } (save() as unknown);',
])
def test_discarded_proven_local_async_results_are_reported(tmp_path, source):
    findings = _scan(tmp_path, source)
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["line"] == 1


@pytest.mark.parametrize("source", [
    'async function save() { return 1; } await save();',
    'async function save() { return 1; } function run() { return save(); }',
    'async function save() { return 1; } const pending = save();',
    'async function save() { return 1; } save().catch(console.error);',
    'async function save() { return 1; } void save();',
    'async function save() { return 1; } void (save() as unknown);',
    'async function save() { return 1; } function run(save) { save(); }',
    'async function save() { return 1; } function run() { save(); const save = sync; }',
    'async function save() { return 1; } function run() { function save() { return 0; } save(); }',
    'async function save() { return 1; } save = () => 0; save();',
    'async function save() { return 1; } function replace() { save = sync; } replace(); save();',
    'let save = async () => 1; if (flag) { save = sync; } save();',
    'async function* save() { yield 1; } save();',
    'import { save } from "sdk"; save();',
    'declare function save(): Promise<void>; save();',
    'async function save() { return 1; } const alias = await save; alias();',
    'const service = { async save() { return 1; } }; service.save();',
    'function save() { return 1; } save();',
    'async function save() { return 1; } const text = "save();";',
    'async function save() { return 1; } save(); const broken = ;',
])
def test_handled_or_unproven_results_stay_quiet(tmp_path, source):
    assert _scan(tmp_path, source) == []


def test_local_async_rule_respects_configuration_and_inline_scope(tmp_path):
    source = 'async function save() { return 1; }\nsave();\n'
    assert _scan(tmp_path, source, config={"ignore": ["SKY-Q410"]}) == []
    assert _scan(tmp_path, source, enabled=False) == []
    assert _scan(tmp_path, source.replace('save();\n', 'save(); // skylos: ignore[SKY-Q410]\n')) == []
