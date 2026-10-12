#!/usr/bin/env python3
"""Reproduce deterministic Skylos capabilities and boundaries, without network/LLM.

Run from the Skylos checkout:
  .venv/bin/python scripts/product_ai_evidence.py

Targets are parsed, never imported or executed. Package metadata and registry
responses in the two focused probes are explicit synthetic inputs, not claims
about live registry contents. Most full verifier probes disable those lookups. The unavailable-metadata
full-verifier probe stubs registries and explicitly supplies missing metadata.
The results are small synthetic fixtures, not deployment or accuracy evidence.
"""
from __future__ import annotations

import argparse
import contextlib
import difflib
import hashlib
import io
import json
import os
import socket
import sys
import time
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
OUT: Path
FIXTURES: Path

from skylos.verify_change import verify_change_path
from skylos.commands.verify_cmd import _exit_code
from skylos.rules.ai_defect.api_signature_hallucination import scan_python_api_signature_hallucinations
from skylos.rules.ai_defect.manifest_dependency_hallucination import scan_manifest_dependency_hallucinations
from skylos.rules.ai_defect.assertion_weakening import detect_assertion_weakening
from skylos.rules.ai_defect.ci_permission_expansion import detect_ci_permission_expansion
from skylos.rules.ai_defect.api_surface_drift import detect_cli_surface_drift
from skylos.verification.comparison import SourceSnapshot, compare_source_changes

def deny_network(*args, **kwargs):
    raise RuntimeError('Audit forbids network access')
socket.create_connection = deny_network
socket.socket.connect = deny_network

def fixture(name, files):
    root = FIXTURES / name
    root.mkdir(exist_ok=True)
    for relative, content in files.items():
        dest = root / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding='utf-8')
    return root

results = []
def record(name, expected, actual, evidence):
    results.append({'name': name, 'expected': expected, 'actual': actual,
                    'matched_expectation': expected == actual, 'evidence': evidence})

def verify_case(name, files, expected, **overrides):
    root = fixture(name, files)
    options = {'include_dependency_hallucinations': False,
               'include_security_findings': False, 'behavior_comparison': False}
    options.update(overrides)
    started = time.perf_counter()
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        result = verify_change_path(root, **options)
    result['audit_elapsed_ms'] = round((time.perf_counter() - started) * 1000, 3)
    (OUT / (name + '.json')).write_text(json.dumps(result, indent=2) + '\n')
    record(name, expected, result['status'], {
        'fixture': str(root), 'elapsed_ms': result['audit_elapsed_ms'],
        'exit_code': _exit_code(result, no_fail=False),
        'rule_ids': [f['rule_id'] for f in result['findings']],
        'coverage': result.get('coverage'), 'summary': result['summary'],
        'security_enabled': result['security_checks_enabled'],
        'contract_checks': result.get('contract_checks'),
    })
    return result

def main():
    global OUT, FIXTURES
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--output', type=Path,
        default=Path('/private/tmp/skylos-product-audit/fixed/ai'),
        help='Directory for fixtures and JSON evidence (default: %(default)s)',
    )
    args = parser.parse_args()
    OUT = args.output.expanduser().resolve()
    OUT.mkdir(parents=True, exist_ok=True)
    FIXTURES = OUT / 'fixtures'
    FIXTURES.mkdir(exist_ok=True)
    for key in list(os.environ):
        if key.startswith(('SKYLOS_', 'ANTHROPIC_', 'OPENAI_', 'TYPESAFE_')):
            os.environ.pop(key, None)
    os.environ['SKYLOS_JOBS'] = '1'
    results.clear()
    verify_case('python_phantom', {'app.py': 'def handler(token):\n    return validate_token(token)\n'}, 'fail')
    verify_case('python_local_missing', {'security.py': 'def verify_token(value):\n    return bool(value)\n',
        'app.py': 'import security\nsecurity.verify_session("ok")\n'}, 'fail')
    verify_case('python_local_valid', {'security.py': 'def verify_token(value):\n    return bool(value)\n',
        'app.py': 'import security\nsecurity.verify_token("ok")\n'}, 'pass')
    verify_case('python_dynamic_surface', {'plugins.py': 'def __getattr__(name):\n    return lambda: name\n',
        'app.py': 'import plugins\nplugins.generated_helper()\n'}, 'incomplete')
    verify_case('typescript_local_missing', {'security.ts': 'export function verifyToken() { return true; }\n',
        'app.ts': 'import { verifyTenant } from "./security";\nverifyTenant();\n'}, 'fail')
    verify_case('typescript_local_valid', {'security.ts': 'export function verifyToken() { return true; }\n',
        'app.ts': 'import { verifyToken } from "./security";\nverifyToken();\n'}, 'pass')
    verify_case('typescript_unresolved_external', {'app.ts': 'import { inventedApi } from "audit-external";\ninventedApi();\n'}, 'incomplete')
    external_result = verify_case('typescript_declared_external_missing_api', {
        'package.json': json.dumps({'dependencies': {'audit-external': '1.0.0'}}),
        'app.ts': 'import { inventedApi } from "audit-external";\ninventedApi();\n'}, 'pass')
    record('typescript_external_api_not_claimed_verified', ['not_verified'],
        [item['external_api_verification'] for item in external_result['coverage']['limitations']],
        external_result['coverage'])
    for language, source in {'php': '<?php function identity($value) { return $value; }\n',
                             'rust': 'fn identity(value: i32) -> i32 { value }\n',
                             'dart': 'int identity(int value) => value;\n'}.items():
        verify_case(language + '_api_unsupported', {'app.' + {'rust': 'rs'}.get(language, language): source}, 'incomplete')

    contract = 'version: 1\nsecurity:\n  routes:\n    paths: [app.py]\n    require_any_decorator: [tenant_admin_required]\n'
    route = 'class Router:\n    def route(self, path):\n        return lambda fn: fn\napp = Router()\n\n'
    verify_case('contract_missing_guard', {'.skylos/ai-contract.yml': contract,
        'app.py': route + '@app.route("/admin")\ndef admin():\n    records = [1, 2, 3]\n    return records\n'}, 'fail')
    contract_result = verify_case('contract_noop_guard_accepted', {'.skylos/ai-contract.yml': contract,
        'app.py': route + 'def tenant_admin_required(fn):\n    return fn\n\n@app.route("/admin")\n@tenant_admin_required\ndef admin():\n    records = [1, 2, 3]\n    return records\n'}, 'pass')
    record('contract_guard_proof_is_structural', 'structural_decorator_presence',
        contract_result['contract_checks'][0]['scope'], contract_result['contract_checks'])
    record('contract_authentication_behavior_not_verified', 'not_verified',
        contract_result['contract_checks'][0]['authentication_behavior'], contract_result['contract_checks'])
    verify_case('security_default', {'app.py': 'import os\ndef handler(command):\n    return os.system(command)\n'}, 'fail', include_security_findings=True)

    # Full analyzer path; registries explicitly stubbed, installed metadata absent.
    with patch('skylos.rules.ai_defect.dependency_hallucination.scan_python_dependency_hallucinations', return_value=[]), \
         patch('skylos.rules.ai_defect.manifest_dependency_hallucination.scan_manifest_dependency_hallucinations', return_value=[]), \
         patch('skylos.core.python_api_surface.PythonApiSurfaceCacheSession.load_surface', return_value=None):
        metadata_result = verify_case('python_installed_metadata_unavailable_full_verifier', {
            'app.py': 'import requests\nrequests.not_an_api()\n'}, 'incomplete',
            include_dependency_hallucinations=True)
    record('python_missing_metadata_verifier_exit', 2,
        _exit_code(metadata_result, no_fail=False), metadata_result['coverage'])

    # Surface provided directly: tests signature logic without importing packages.
    api = fixture('python_signature_surface', {'app.py': 'import requests\nrequests.missing()\nrequests.get("https://example.test", imaginary=True)\n'})
    surface = {'members': {'get': {'kind': 'function', 'parameters': [
        {'name': 'url', 'kind': 'POSITIONAL_OR_KEYWORD'}]}}, 'members_truncated': False}
    bad = scan_python_api_signature_hallucinations(api, [api / 'app.py'], surface_loader=lambda *_: surface)
    unavailable = scan_python_api_signature_hallucinations(api, [api / 'app.py'], surface_loader=lambda *_: None)
    record('python_signature_metadata_available', ['SKY-D224', 'SKY-D224'], [f['rule_id'] for f in bad], bad)
    record('python_signature_metadata_unavailable', [], [f['rule_id'] for f in unavailable], {
        'findings': unavailable, 'coverage': unavailable.check,
        'boundary': 'Unavailable metadata is incomplete coverage; it cannot prove a missing API.'})
    record('python_signature_unavailable_coverage', 'incomplete', unavailable.check['outcome'], unavailable.check)

    # Exact package and version checks with explicit mocked registry truth.
    manifest = fixture('registry_mock', {'package.json': json.dumps({'dependencies': {
        'audit-missing': '1.0.0', 'audit-version-missing': '99.0.0', 'audit-unavailable': '1.0.0'}})})
    states = {'audit-missing': 'missing_package', 'audit-version-missing': 'missing_version', 'audit-unavailable': 'unknown'}
    manifest_findings = scan_manifest_dependency_hallucinations(manifest, status_checker=lambda _eco, name, _version, _cache: states[name])
    record('registry_explicit_truth', ['SKY-D222', 'SKY-D225'], [f['rule_id'] for f in manifest_findings], manifest_findings)

    def diff(before, after):
        return ''.join(difflib.unified_diff(before.splitlines(True), after.splitlines(True), fromfile='a/file', tofile='b/file'))
    weak = detect_assertion_weakening(diff('def test_answer():\n    assert answer == 42\n', 'def test_answer():\n    assert answer\n'), 'test/test_answer.py')
    record('test_assertion_weakened', ['SKY-A101'], [f['rule_id'] for f in weak], weak)
    ci = detect_ci_permission_expansion(diff('permissions:\n  contents: read\n', 'permissions:\n  contents: write\n'), '.github/workflows/build.yml')
    record('ci_permission_expanded', ['SKY-A103'], [f['rule_id'] for f in ci], ci)
    cli = detect_cli_surface_drift(diff('parser.add_argument("--legacy")\n', 'parser.add_argument("--replacement")\n'), 'cli.py')
    record('public_cli_flag_removed', ['SKY-A104'], [f['rule_id'] for f in cli], cli)

    def snapshot(code):
        return SourceSnapshot({'app.py': code}, {'app.py': hashlib.sha256(code.encode()).hexdigest()})
    before = 'def run(value):\n    return value\n'
    for name, after, expected in [
        ('behavior_helper_extraction', 'def identity(value):\n    return value\n\ndef run(value):\n    return identity(value)\n', 'equivalent'),
        ('behavior_changed_return', 'def run(value):\n    return "changed"\n', 'different'),
        ('behavior_loop_outside_model', 'def run(value):\n    for item in value:\n        print(item)\n    return value\n', 'unknown'),
    ]:
        result = compare_source_changes(snapshot(before), snapshot(after))
        record(name, expected, result['status'], result)

    payload = {'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
               'python': sys.version, 'executable': sys.executable,
               'network': 'blocked', 'llm': 'not called', 'target_execution': 'none',
               'probe_scope': {
                   'fixture_kind': 'small synthetic examples, not deployment accuracy evidence',
                   'full_verifier_defaults': 'registry/signature lookups, security and behavior disabled unless explicitly enabled',
                   'python_installed_metadata_unavailable_full_verifier': 'registry scanners stubbed to []; API surface loader returns None',
                   'python_signature_metadata_available': 'explicit synthetic member/signature dictionary; no package import',
                   'python_signature_metadata_unavailable': 'API surface loader returns None',
                   'registry_explicit_truth': 'synthetic missing_package/missing_version/unknown status responses',
               },
               'passed_expectations': sum(r['matched_expectation'] for r in results),
               'total_cases': len(results), 'results': results}
    (OUT / 'results.json').write_text(json.dumps(payload, indent=2) + '\n')
    for item in results:
        print(f"{item['name']}: {item['actual']} (expected {item['expected']})")
    print(f"{payload['passed_expectations']}/{payload['total_cases']} expectations matched; full evidence: {OUT / 'results.json'}")
    sys.exit(0 if all(r['matched_expectation'] for r in results) else 1)

if __name__ == '__main__':
    main()
