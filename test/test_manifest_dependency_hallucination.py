from __future__ import annotations

import json

from skylos.rules.ai_defect.manifest_dependency_hallucination import (
    RULE_ID_DEPENDENCY_HALLUCINATION,
    RULE_ID_VERSION_HALLUCINATION,
    INSTALL_SURFACE_SOURCE,
    STATUS_EXISTS,
    STATUS_MISSING_PACKAGE,
    STATUS_MISSING_VERSION,
    STATUS_PRESENT,
    STATUS_PRIVATE_OR_UNVERIFIED,
    STATUS_UNKNOWN,
    VERSION_CACHE_PATH,
    VERSION_CACHE_SCHEMA_VERSION,
    scan_manifest_dependency_hallucinations,
)
from skylos.rules.ai_defect.dependency_truth import (
    DependencyTruthState,
    normalize_dependency_truth_state,
)
from skylos.rules.sca.vulnerability_scanner import (
    ECOSYSTEM_GO,
    ECOSYSTEM_NPM,
    ECOSYSTEM_PYPI,
)


def _status_checker(statuses, calls):
    def checker(ecosystem, name, version, _cache):
        calls.append((ecosystem, name, version))
        key = (ecosystem, name, version)
        if key in statuses:
            return statuses[key]
        return STATUS_EXISTS

    return checker


def _messages(findings):
    messages = []
    for finding in findings:
        messages.append(finding["message"])
    return messages


def test_dependency_truth_state_normalizes_legacy_and_unknown_values():
    assert normalize_dependency_truth_state(STATUS_EXISTS) == DependencyTruthState.PRESENT
    assert normalize_dependency_truth_state(STATUS_PRESENT) == DependencyTruthState.PRESENT
    assert (
        normalize_dependency_truth_state(STATUS_MISSING_PACKAGE)
        == DependencyTruthState.MISSING_PACKAGE
    )
    assert (
        normalize_dependency_truth_state(STATUS_PRIVATE_OR_UNVERIFIED)
        == DependencyTruthState.PRIVATE_OR_UNVERIFIED
    )
    assert normalize_dependency_truth_state("not-a-status") == DependencyTruthState.UNKNOWN


def test_scan_package_json_flags_missing_npm_package_and_version(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    manifest = {
        "dependencies": {
            "leftpadz": "9.9.9",
            "stale-version": "^99.0.0",
            "realpkg": "1.2.3",
        },
        "devDependencies": {
            "devghost": "2.0.0",
        },
    }
    (repo / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
    calls = []
    statuses = {
        (ECOSYSTEM_NPM, "leftpadz", "9.9.9"): STATUS_MISSING_PACKAGE,
        (ECOSYSTEM_NPM, "stale-version", "99.0.0"): STATUS_MISSING_VERSION,
        (ECOSYSTEM_NPM, "devghost", "2.0.0"): STATUS_MISSING_VERSION,
    }

    findings = scan_manifest_dependency_hallucinations(
        repo,
        status_checker=_status_checker(statuses, calls),
    )
    rule_ids = []
    for finding in findings:
        rule_ids.append(finding["rule_id"])

    assert len(findings) == 3
    assert RULE_ID_DEPENDENCY_HALLUCINATION in rule_ids
    assert rule_ids.count(RULE_ID_VERSION_HALLUCINATION) == 2
    assert findings[0]["metadata"]["dependency_truth_state"] in {
        STATUS_MISSING_PACKAGE,
        STATUS_MISSING_VERSION,
    }
    assert findings[0]["metadata"]["dependency_truth_source"] == "registry"
    assert any("leftpadz" in message for message in _messages(findings))
    assert any("stale-version@99.0.0" in message for message in _messages(findings))
    assert (ECOSYSTEM_NPM, "realpkg", "1.2.3") in calls


def test_scan_go_mod_flags_missing_go_module_and_version(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "go.mod").write_text(
        "\n".join(
            [
                "module example.com/demo",
                "",
                "go 1.22",
                "",
                "require (",
                "    github.com/real/pkg v1.2.3",
                "    github.com/no/module v0.0.1",
                "    github.com/real/pkg v9.9.9",
                ")",
                "",
            ]
        ),
        encoding="utf-8",
    )
    calls = []
    statuses = {
        (ECOSYSTEM_GO, "github.com/no/module", "0.0.1"): STATUS_MISSING_PACKAGE,
        (ECOSYSTEM_GO, "github.com/real/pkg", "9.9.9"): STATUS_MISSING_VERSION,
    }

    findings = scan_manifest_dependency_hallucinations(
        repo,
        status_checker=_status_checker(statuses, calls),
    )
    messages = _messages(findings)

    assert len(findings) == 2
    assert any("github.com/no/module" in message for message in messages)
    assert any("github.com/real/pkg@9.9.9" in message for message in messages)
    assert (ECOSYSTEM_GO, "github.com/real/pkg", "1.2.3") in calls


def test_scan_install_surfaces_flags_pinned_dependency_commands(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "RUN python -m pip install dockergone==9.9.9 && npm install leftpadz@1.0.0\n"
        "RUN pip install --index-url https://pypi.org/simple publicgone==5.0.0\n"
        "RUN npm install --registry=https://registry.npmjs.org public-npm@6.0.0\n"
        "RUN pip install semighost==1.0.0; npm install semighost-npm@2.0.0\n"
        "RUN pip install nospaceghost==1.0.0;npm install nospace-npm@2.0.0\n",
        encoding="utf-8",
    )
    workflow = repo / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - run: |\n"
        "          go get github.com/no/module@v0.0.1\n",
        encoding="utf-8",
    )
    scripts = repo / "scripts"
    scripts.mkdir()
    (scripts / "bootstrap.sh").write_text(
        "poetry add shellgone==2.0.0\n",
        encoding="utf-8",
    )
    (repo / "README.md").write_text(
        "```bash\n"
        "pip install docs-real\n"
        "pnpm add @scope/docgone@3.4.5\n"
        "```\n",
        encoding="utf-8",
    )
    calls = []
    statuses = {
        (ECOSYSTEM_PYPI, "dockergone", "9.9.9"): STATUS_MISSING_PACKAGE,
        (ECOSYSTEM_NPM, "leftpadz", "1.0.0"): STATUS_MISSING_VERSION,
        (ECOSYSTEM_GO, "github.com/no/module", "0.0.1"): STATUS_MISSING_PACKAGE,
        (ECOSYSTEM_PYPI, "shellgone", "2.0.0"): STATUS_MISSING_VERSION,
        (ECOSYSTEM_NPM, "@scope/docgone", "3.4.5"): STATUS_MISSING_PACKAGE,
        (ECOSYSTEM_PYPI, "publicgone", "5.0.0"): STATUS_MISSING_PACKAGE,
        (ECOSYSTEM_NPM, "public-npm", "6.0.0"): STATUS_MISSING_PACKAGE,
        (ECOSYSTEM_PYPI, "semighost", "1.0.0"): STATUS_MISSING_PACKAGE,
        (ECOSYSTEM_NPM, "semighost-npm", "2.0.0"): STATUS_MISSING_PACKAGE,
        (ECOSYSTEM_PYPI, "nospaceghost", "1.0.0"): STATUS_MISSING_PACKAGE,
        (ECOSYSTEM_NPM, "nospace-npm", "2.0.0"): STATUS_MISSING_PACKAGE,
    }

    findings = scan_manifest_dependency_hallucinations(
        repo,
        status_checker=_status_checker(statuses, calls),
    )
    names = {
        finding["metadata"]["package_name"]: finding["metadata"]
        for finding in findings
    }

    assert set(names) == {
        "dockergone",
        "leftpadz",
        "github.com/no/module",
        "shellgone",
        "@scope/docgone",
        "publicgone",
        "public-npm",
        "semighost",
        "semighost-npm",
        "nospaceghost",
        "nospace-npm",
    }
    assert all(
        metadata["dependency_source"] == INSTALL_SURFACE_SOURCE
        for metadata in names.values()
    )
    assert (ECOSYSTEM_PYPI, "docs-real", "") not in calls


def test_scan_install_surfaces_skip_private_registry_commands(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "RUN pip install --index-url https://packages.internal/simple internalpkg==1.2.3\n"
        "RUN PIP_INDEX_URL=https://packages.internal/simple pip install envpkg==2.3.4\n"
        "RUN pip install -ihttps://packages.internal/simple attachedpkg==3.4.5\n"
        "RUN npm install --registry=https://npm.internal internal-npm@4.5.6\n",
        encoding="utf-8",
    )
    scripts = repo / "scripts"
    scripts.mkdir()
    (scripts / "bootstrap.sh").write_text(
        "NPM_CONFIG_REGISTRY=https://npm.internal npm install env-npm@6.7.8\n",
        encoding="utf-8",
    )

    def fail_checker(_ecosystem, _name, _version, _cache):
        raise AssertionError("private registry install snippets should not be checked")

    findings = scan_manifest_dependency_hallucinations(
        repo,
        status_checker=fail_checker,
    )

    assert findings == []
    assert not (repo / VERSION_CACHE_PATH).exists()


def test_scan_manifest_private_registry_contexts_are_unverified_not_missing(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text(
        "--index-url https://packages.internal/simple\n"
        "internalpkg==1.2.3\n",
        encoding="utf-8",
    )
    (repo / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {
                    "@internal/widget": "2.0.0",
                    "left-pad": "1.3.0",
                }
            }
        ),
        encoding="utf-8",
    )
    (repo / ".npmrc").write_text(
        "@internal:registry=https://npm.internal\n",
        encoding="utf-8",
    )
    calls = []

    findings = scan_manifest_dependency_hallucinations(
        repo,
        status_checker=_status_checker({}, calls),
    )

    assert findings == []
    assert (ECOSYSTEM_PYPI, "internalpkg", "1.2.3") not in calls
    assert (ECOSYSTEM_NPM, "@internal/widget", "2.0.0") not in calls
    assert calls == [(ECOSYSTEM_NPM, "left-pad", "1.3.0")]


def test_scan_private_context_does_not_suppress_public_duplicate(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text(
        "--index-url https://packages.internal/simple\n"
        "ghostpkg==1.0.0\n",
        encoding="utf-8",
    )
    (repo / "pyproject.toml").write_text(
        '[project]\ndependencies = ["ghostpkg==1.0.0"]\n',
        encoding="utf-8",
    )
    calls = []
    statuses = {
        (ECOSYSTEM_PYPI, "ghostpkg", "1.0.0"): STATUS_MISSING_PACKAGE,
    }

    findings = scan_manifest_dependency_hallucinations(
        repo,
        status_checker=_status_checker(statuses, calls),
    )

    assert len(findings) == 1
    assert findings[0]["metadata"]["package_name"] == "ghostpkg"
    assert calls == [(ECOSYSTEM_PYPI, "ghostpkg", "1.0.0")]


def test_scan_install_surfaces_require_command_context_and_exact_pins(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "README.md").write_text(
        "Do not run `pip install fakepkg==1.0.0` from random docs prose.\n"
        "> Do not run pip install quotegone==1.0.0 from a blockquote.\n"
        "$ pip install promptgone==2.0.0\n",
        encoding="utf-8",
    )
    workflow = repo / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "name: pip install not-a-command==1.0.0\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - run: pip install ranged>=2.0.0\n"
        "      - run: pip install wildcard==1.*\n"
        "      - run: pip install exactgone==3.0.0\n",
        encoding="utf-8",
    )
    calls = []
    statuses = {
        (ECOSYSTEM_PYPI, "promptgone", "2.0.0"): STATUS_MISSING_PACKAGE,
        (ECOSYSTEM_PYPI, "exactgone", "3.0.0"): STATUS_MISSING_PACKAGE,
    }

    findings = scan_manifest_dependency_hallucinations(
        repo,
        status_checker=_status_checker(statuses, calls),
    )
    names = {finding["metadata"]["package_name"] for finding in findings}

    assert names == {"promptgone", "exactgone"}
    assert (ECOSYSTEM_PYPI, "fakepkg", "1.0.0") not in calls
    assert (ECOSYSTEM_PYPI, "quotegone", "1.0.0") not in calls
    assert (ECOSYSTEM_PYPI, "not-a-command", "1.0.0") not in calls
    assert (ECOSYSTEM_PYPI, "ranged", "2.0.0") not in calls
    assert all(call[1] != "wildcard" for call in calls)


def test_scan_flags_suspicious_existing_popular_package_lookalike(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text(
        "reqeusts==1.0.0\nrequests==2.31.0\n",
        encoding="utf-8",
    )
    calls = []

    findings = scan_manifest_dependency_hallucinations(
        repo,
        status_checker=_status_checker({}, calls),
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding["rule_id"] == RULE_ID_DEPENDENCY_HALLUCINATION
    assert finding["severity"] == "HIGH"
    assert finding["metadata"]["package_name"] == "reqeusts"
    assert finding["metadata"]["dependency_truth_state"] == "suspicious_existing"
    assert finding["metadata"]["dependency_truth_source"] == "registry+lookalike"
    assert "requests" in finding["metadata"]["dependency_truth_reason"]


def test_scan_suspicious_existing_precision_guards(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    manifest = {
        "dependencies": {
            "express": "4.18.0",
            "express-session": "1.17.0",
            "internal-client": "1.0.0",
            "internal-clients": "1.0.0",
            "@scope/recat": "1.0.0",
        }
    }
    (repo / "package.json").write_text(json.dumps(manifest), encoding="utf-8")

    findings = scan_manifest_dependency_hallucinations(
        repo,
        status_checker=_status_checker({}, []),
    )

    assert findings == []


def test_scan_static_ecosystem_adapters_collect_without_default_findings(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Cargo.toml").write_text(
        "[dependencies]\n"
        'serde_alias = { package = "serde", version = "1.0.0" }\n'
        'local_crate = { path = "../local", version = "0.1.0" }\n'
        'git_crate = { git = "https://example.com/repo", version = "0.1.0" }\n'
        'internal_crate = { registry = "internal", version = "0.1.0" }\n',
        encoding="utf-8",
    )
    (repo / "composer.json").write_text(
        json.dumps(
            {
                "require": {
                    "monolog/monolog": "3.0.0",
                    "range/range": ">=1.0 <2.0",
                }
            }
        ),
        encoding="utf-8",
    )
    (repo / "Gemfile").write_text(
        "gem 'rails', '~> 7.1'\n",
        encoding="utf-8",
    )
    (repo / "pubspec.yaml").write_text(
        "dependencies:\n"
        "  http: ^1.2.0\n"
        "  nested_pkg:\n"
        "    version: ^1.2.3\n",
        encoding="utf-8",
    )
    (repo / "build.gradle").write_text(
        "dependencies {\n"
        "  implementation 'org.example:demo:1.0.0'\n"
        "  println(\"implementation 'org.example:logged:9.9.9'\")\n"
        "  /*\n"
        "  implementation 'org.example:blockcomment:9.9.9'\n"
        "  */\n"
        "  implementation 'org.example:ranged:[1.0,2.0)'\n"
        "}\n"
        "// dependencies { implementation 'org.example:commented:9.9.9' }\n",
        encoding="utf-8",
    )
    (repo / "pom.xml").write_text(
        "<project><dependencies><dependency><groupId>org.acme</groupId>"
        "<artifactId>toolkit</artifactId><version>2.0.0</version>"
        "</dependency><dependency><groupId>org.acme</groupId>"
        "<artifactId>ranged</artifactId><version>[1.0,2.0)</version>"
        "</dependency></dependencies></project>",
        encoding="utf-8",
    )
    (repo / "app.csproj").write_text(
        '<Project><ItemGroup><PackageReference Include="Newtonsoft.Json">'
        "<Version>13.0.1</Version></PackageReference>"
        '<PackageReference Include="RangeLib" Version="[1.0,2.0)" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )
    (repo / "packages.config").write_text(
        '<packages><package id="NUnit" version="3.14.0" />'
        '<package id="RangePkg" version="[1.0,2.0)" /></packages>',
        encoding="utf-8",
    )
    calls = []

    findings = scan_manifest_dependency_hallucinations(
        repo,
        status_checker=_status_checker({}, calls),
    )

    assert findings == []
    assert ("crates.io", "serde", "1.0.0") in calls
    assert ("crates.io", "local_crate", "0.1.0") not in calls
    assert ("crates.io", "git_crate", "0.1.0") not in calls
    assert ("crates.io", "internal_crate", "0.1.0") not in calls
    assert ("Packagist", "monolog/monolog", "3.0.0") in calls
    assert ("Packagist", "range/range", "1.0") not in calls
    assert ("RubyGems", "rails", "7.1") in calls
    assert ("Pub", "http", "1.2.0") in calls
    assert ("Pub", "nested_pkg", "1.2.3") not in calls
    assert ("Pub", "version", "1.2.3") not in calls
    assert ("Maven", "org.example:demo", "1.0.0") in calls
    assert ("Maven", "org.example:logged", "9.9.9") not in calls
    assert ("Maven", "org.example:blockcomment", "9.9.9") not in calls
    assert ("Maven", "org.example:ranged", "[1.0,2.0)") not in calls
    assert ("Maven", "org.example:commented", "9.9.9") not in calls
    assert ("Maven", "org.acme:toolkit", "2.0.0") in calls
    assert ("Maven", "org.acme:ranged", "[1.0,2.0)") not in calls
    assert ("NuGet", "Newtonsoft.Json", "13.0.1") in calls
    assert ("NuGet", "RangeLib", "[1.0,2.0)") not in calls
    assert ("NuGet", "NUnit", "3.14.0") in calls
    assert ("NuGet", "RangePkg", "[1.0,2.0)") not in calls


def test_scan_static_ecosystem_adapters_can_surface_checker_findings(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Cargo.toml").write_text(
        "[dependencies]\nserdeghost = \"9.9.9\"\n",
        encoding="utf-8",
    )
    calls = []
    statuses = {
        ("crates.io", "serdeghost", "9.9.9"): STATUS_MISSING_PACKAGE,
    }

    findings = scan_manifest_dependency_hallucinations(
        repo,
        status_checker=_status_checker(statuses, calls),
    )

    assert len(findings) == 1
    assert findings[0]["metadata"]["ecosystem"] == "crates.io"
    assert findings[0]["metadata"]["package_name"] == "serdeghost"
    assert findings[0]["rule_id"] == RULE_ID_DEPENDENCY_HALLUCINATION


def test_scan_requirements_txt_flags_missing_pypi_version(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text(
        "\n".join(
            [
                "requests==999.0.0",
                "click==8.1.7",
            ]
        ),
        encoding="utf-8",
    )
    calls = []
    statuses = {
        (ECOSYSTEM_PYPI, "requests", "999.0.0"): STATUS_MISSING_VERSION,
    }

    findings = scan_manifest_dependency_hallucinations(
        repo,
        status_checker=_status_checker(statuses, calls),
    )

    assert len(findings) == 1
    assert findings[0]["rule_id"] == RULE_ID_VERSION_HALLUCINATION
    assert "requests@999.0.0" in findings[0]["message"]
    assert (ECOSYSTEM_PYPI, "click", "8.1.7") in calls


def test_scan_requirements_txt_ignores_wildcard_pins(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text(
        "wildcard==1.*\n"
        "normal-pkg==6.0.0\n",
        encoding="utf-8",
    )
    calls = []

    findings = scan_manifest_dependency_hallucinations(
        repo,
        status_checker=_status_checker({}, calls),
    )

    assert findings == []
    assert (ECOSYSTEM_PYPI, "normal-pkg", "6.0.0") in calls
    assert all(call[1] != "wildcard" for call in calls)


def test_scan_pyproject_skips_uv_non_pypi_sources(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text(
        "\n".join(
            [
                "[project]",
                'name = "uv-source-demo"',
                "dependencies = [",
                '  "git-pkg>=1.0.0",',
                '  "url-pkg==2.0.0",',
                '  "path-pkg>=3.0.0",',
                '  "workspace-pkg>=4.0.0",',
                '  "index-pkg>=5.0.0",',
                '  "normal-pkg>=6.0.0",',
                "]",
                "",
                "[tool.uv.sources]",
                'git-pkg = { git = "https://github.com/example/git-pkg" }',
                'url-pkg = { url = "https://example.com/url-pkg.whl" }',
                'path-pkg = { path = "../path-pkg" }',
                "workspace-pkg = { workspace = true }",
                'index-pkg = { index = "internal" }',
                "",
            ]
        ),
        encoding="utf-8",
    )
    calls = []

    findings = scan_manifest_dependency_hallucinations(
        repo,
        status_checker=_status_checker({}, calls),
    )

    assert findings == []
    assert calls == [(ECOSYSTEM_PYPI, "normal-pkg", "6.0.0")]


def test_scan_pyproject_skips_pep508_direct_references(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text(
        "\n".join(
            [
                "[project]",
                'name = "direct-ref-demo"',
                "dependencies = [",
                '  "direct-git @ git+https://github.com/example/direct-git@v1.0.0",',
                '  "direct-url @ https://example.com/direct-url-1.0.0.whl",',
                '  "direct-path @ ../direct-path",',
                '  "normal-pkg==2.0.0",',
                "]",
                "",
            ]
        ),
        encoding="utf-8",
    )
    calls = []

    findings = scan_manifest_dependency_hallucinations(
        repo,
        status_checker=_status_checker({}, calls),
    )

    assert findings == []
    assert calls == [(ECOSYSTEM_PYPI, "normal-pkg", "2.0.0")]


def test_scan_pyproject_skips_poetry_non_pypi_sources(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text(
        "\n".join(
            [
                "[tool.poetry.dependencies]",
                'python = "^3.11"',
                'git-pkg = { git = "https://github.com/example/git-pkg", rev = "1.0.0" }',
                'path-pkg = { path = "../path-pkg" }',
                'url-pkg = { url = "https://example.com/url-pkg-1.0.0.whl" }',
                'source-pkg = { version = "1.2.3", source = "internal" }',
                'normal-pkg = "^6.0.0"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    calls = []

    findings = scan_manifest_dependency_hallucinations(
        repo,
        status_checker=_status_checker({}, calls),
    )

    assert findings == []
    assert calls == [(ECOSYSTEM_PYPI, "normal-pkg", "6.0.0")]


def test_scan_manifest_dependency_statuses_are_cached(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    manifest = {"dependencies": {"stale-version": "99.0.0"}}
    (repo / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
    calls = []
    statuses = {
        (ECOSYSTEM_NPM, "stale-version", "99.0.0"): STATUS_MISSING_VERSION,
    }

    first = scan_manifest_dependency_hallucinations(
        repo,
        status_checker=_status_checker(statuses, calls),
    )

    def fail_checker(_ecosystem, _name, _version, _cache):
        raise AssertionError("cached dependency status should be reused")

    second = scan_manifest_dependency_hallucinations(
        repo,
        status_checker=fail_checker,
    )

    assert len(first) == 1
    assert len(second) == 1
    assert calls == [(ECOSYSTEM_NPM, "stale-version", "99.0.0")]


def test_scan_manifest_dependency_cache_key_normalizes_pypi_identity(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text(
        "Requests_HTML==1.2.3\n",
        encoding="utf-8",
    )
    cache_path = repo / VERSION_CACHE_PATH
    cache_path.parent.mkdir(parents=True)
    cache_path.write_text(
        json.dumps(
            {
                "schema_version": VERSION_CACHE_SCHEMA_VERSION,
                "statuses": {"PyPI:requests-html:1.2.3": STATUS_EXISTS},
            }
        ),
        encoding="utf-8",
    )

    def fail_checker(_ecosystem, _name, _version, _cache):
        raise AssertionError("normalized dependency cache key should be reused")

    findings = scan_manifest_dependency_hallucinations(
        repo,
        status_checker=fail_checker,
    )

    assert findings == []


def test_scan_manifest_dependency_unknown_offline_status_is_not_cached(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    manifest = {"dependencies": {"offline-only": "1.2.3"}}
    (repo / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
    calls = []

    def offline_checker(ecosystem, name, version, _cache):
        calls.append((ecosystem, name, version))
        return STATUS_UNKNOWN

    first = scan_manifest_dependency_hallucinations(
        repo,
        status_checker=offline_checker,
    )

    second = scan_manifest_dependency_hallucinations(
        repo,
        status_checker=offline_checker,
    )

    assert first == []
    assert second == []
    assert calls == [
        (ECOSYSTEM_NPM, "offline-only", "1.2.3"),
        (ECOSYSTEM_NPM, "offline-only", "1.2.3"),
    ]
    assert not (repo / VERSION_CACHE_PATH).exists()


def test_scan_manifest_dependency_legacy_exists_cache_is_present_state(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    manifest = {"dependencies": {"realpkg": "1.2.3"}}
    (repo / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
    cache_path = repo / VERSION_CACHE_PATH
    cache_path.parent.mkdir(parents=True)
    cache_path.write_text(
        json.dumps(
            {
                "schema_version": VERSION_CACHE_SCHEMA_VERSION,
                "statuses": {"npm:realpkg:1.2.3": STATUS_EXISTS},
            }
        ),
        encoding="utf-8",
    )

    def fail_checker(_ecosystem, _name, _version, _cache):
        raise AssertionError("legacy present cache status should be reused")

    findings = scan_manifest_dependency_hallucinations(
        repo,
        status_checker=fail_checker,
    )

    assert findings == []
