"""End-to-end contracts for source usage, scoped findings and honest coverage."""
import json
import shutil
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink

ROOT = Path(__file__).resolve().parents[1]


def _fixture(tmp_path, name):
    target = tmp_path / 'project'
    shutil.copytree(ROOT / 'corpus' / 'fixtures' / name, target)
    return target


def _scan(path, **kwargs):
    return json.loads(analyze(str(path), grep_verify=False, grep_cache=False, **kwargs))


def test_npm_usage_reports_findings_and_rule_coverage(tmp_path):
    project = _fixture(tmp_path, 'npm_dependency_usage')
    result = _scan(project, enable_quality=True)
    findings = result.get('quality', [])
    assert {'SKY-U005', 'SKY-Q408', 'SKY-Q409'} <= {row['rule_id'] for row in findings}
    assert result['analysis_summary']['npm_dependency_analysis']['complete'] is True
    assert not result.get('analysis_errors')


def test_enum_findings_obey_inline_and_project_rule_suppression(tmp_path):
    project = _fixture(tmp_path, 'enum_member_usage')
    initial = _scan(project)
    assert any(row.get('rule_id') == 'SKY-U007' for row in initial['unused_variables'])
    path = project / 'app.ts'
    lines = path.read_text().splitlines(keepends=True)
    lines[4] = lines[4].rstrip('\n') + ' // skylos: ignore[SKY-U007] reserved protocol value\n'
    assert write_text_no_symlink(path, ''.join(lines))
    ignored = _scan(project)
    assert not any(row.get('rule_id') == 'SKY-U007' for row in ignored['unused_variables'])
    assert any(row.get('rule_id') == 'SKY-U007' for row in ignored['suppressed'])
    assert write_text_no_symlink(path, ''.join(line.split(' // skylos: ignore')[0] + '\n' if ' // skylos: ignore' in line else line for line in lines))
    assert write_text_no_symlink(project / 'pyproject.toml', '[tool.skylos]\nignore = ["SKY-U007"]\n')
    configured = _scan(project)
    assert not any(row.get('rule_id') == 'SKY-U007' for row in configured['unused_variables'])


def test_file_scope_does_not_claim_unused_npm_dependencies(tmp_path):
    project = _fixture(tmp_path, 'npm_dependency_usage')
    result = _scan(project / 'app.ts', enable_quality=True)
    assert not any(row.get('rule_id') == 'SKY-U005' for row in result.get('quality', []))
    assert result['analysis_summary']['npm_dependency_analysis']['complete'] is False


def test_component_parse_failure_cannot_earn_complete_analysis(tmp_path):
    assert write_text_no_symlink(tmp_path / 'main.ts', 'import Panel from "./Panel.vue"; console.log(Panel);\n')
    assert write_text_no_symlink(tmp_path / 'Panel.vue', '<script setup>import { helper from "./helpers";</script>')
    assert write_text_no_symlink(tmp_path / 'helpers.ts', 'export function helper() { return 1; }\n')
    result = _scan(tmp_path)
    assert result['analysis_summary']['component_import_graph']['complete'] is False
    assert any(row['kind'] == 'component_import_graph_incomplete' for row in result['analysis_errors'])


@pytest.mark.parametrize("absolute", [False, True])
def test_private_enum_diff_reports_only_requested_provider(tmp_path, absolute):
    project = _fixture(tmp_path, 'private_exported_enum_members')
    assert write_text_no_symlink(project / 'other.ts', 'export enum Other {Ready, Spare};\n')
    app = project / 'app.ts'
    assert write_text_no_symlink(app, app.read_text() + '\nimport {Other} from "./other"; console.log(Other.Ready);\n')
    # Only dead-code checks are requested: the test needs no Git comparison
    # history for unrelated security-control regression checks.
    options = dict(enable_quality=False, enable_danger=False, enable_ai_defects=False,
                   enable_dependency_hallucinations=False, enable_sca=False)
    initial = _scan(project, **options)
    assert not initial.get('analysis_errors'), initial.get('analysis_errors')
    assert {row['full_name'] for row in initial['unused_variables'] if row.get('rule_id') == 'SKY-U007'} == {'Status.Spare', 'Other.Spare'}
    changed = str(project / 'status.ts') if absolute else 'status.ts'
    scoped = _scan(project, changed_files=[changed], **options)
    assert not scoped.get('analysis_errors'), scoped.get('analysis_errors')
    findings = [row for row in scoped['unused_variables'] if row.get('rule_id') == 'SKY-U007']
    assert [row['full_name'] for row in findings] == ['Status.Spare']
    assert Path(findings[0]['file']) == project / 'status.ts'
    coverage = scoped['analysis_summary']['enum_member_analysis']
    assert coverage['complete'] is True
    assert coverage['report_scope'] == 'changed_files'
    assert coverage['outside_changed_files_count'] == 1
    assert coverage['reported_count'] == 1
    assert sum(row.get('rules', {}).get('SKY-U007', 0) for row in scoped['analysis_summary']['by_directory']) == 1


@pytest.mark.parametrize("config, reason", [
    ('[tool.skylos]\nwhitelist = ["Status.*"]\n', "matches"),
    ('[tool.skylos.overrides."status.ts"]\nwhitelist = ["Status.*"]\n', "per-file: status.ts"),
])
def test_private_enum_obeys_symbol_and_file_whitelists(tmp_path, config, reason):
    project = _fixture(tmp_path, 'private_exported_enum_members')
    assert write_text_no_symlink(project / 'pyproject.toml', config)
    result = _scan(project, enable_quality=False, enable_danger=False,
                   enable_ai_defects=False, enable_dependency_hallucinations=False,
                   enable_sca=False)
    assert not result.get('analysis_errors'), result.get('analysis_errors')
    assert not any(row.get('rule_id') == 'SKY-U007' for row in result['unused_variables'])
    suppressed = [row for row in result['suppressed'] if row.get('rule_id') == 'SKY-U007']
    assert len(suppressed) == 1
    assert suppressed[0]['full_name'] == 'Status.Spare'
    assert reason in suppressed[0]['reason']
    coverage = result['analysis_summary']['enum_member_analysis']
    assert coverage['suppressed_count'] == 1 and coverage['reported_count'] == 0
    assert not any(row.get('rules', {}).get('SKY-U007', 0) for row in result['analysis_summary'].get('by_directory', []))
