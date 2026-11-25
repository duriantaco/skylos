import json
from pathlib import Path

import pytest

from skylos.deadcode.sveltekit_aliases import sveltekit_resolver
from skylos.visitors.languages.typescript.framework_aliases import (
    resolve_sveltekit_alias,
)
from skylos.visitors.languages.typescript.resolve import MonorepoResolver


def _write(root: Path, name: str, content: str = "") -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


@pytest.fixture
def app(tmp_path):
    root = tmp_path.resolve()
    _write(root, "package.json", "{}")
    return root


def _resolver(root):
    return sveltekit_resolver(
        MonorepoResolver(str(root)), {str(root): str(root / "src/lib")}
    )


def test_stock_sveltekit_aliases_resolve_source_and_components(app):
    generated = {"extends": "./.svelte-kit/tsconfig.json"}
    _write(app, "jsconfig.json", json.dumps(generated))
    importer = _write(app, "src/routes/+page.ts")
    library = _write(app, "src/lib/index.js")
    helper = _write(app, "src/lib/helper.ts")
    component = _write(app, "src/lib/Button.svelte")

    resolver = _resolver(app)
    assert resolver.resolve("$lib", str(importer)) == str(library)
    assert resolver.resolve("$lib/helper.js", str(importer)) == str(helper)
    assert resolver.resolve("$lib/Button.svelte", str(importer)) == str(component)

    generated_paths = {"$lib": ["../src/lib"], "$lib/*": ["../src/lib/*"]}
    _write(
        app,
        ".svelte-kit/tsconfig.json",
        json.dumps({"compilerOptions": {"paths": generated_paths}}),
    )
    assert _resolver(app).resolve("$lib/helper", str(importer)) == str(helper)


def test_explicit_tsconfig_resolution_and_unresolved_claim_win(app):
    importer = _write(app, "src/routes/+page.ts")
    _write(app, "src/lib/helper.ts")
    target = _write(app, "custom/helper.ts")
    config = _write(
        app,
        "tsconfig.json",
        json.dumps({"compilerOptions": {"paths": {"$lib/*": ["custom/*"]}}}),
    )
    assert _resolver(app).resolve("$lib/helper", str(importer)) == str(target)

    config.write_text(
        json.dumps({"compilerOptions": {"paths": {"$lib/*": ["missing/*"]}}}),
        encoding="utf-8",
    )
    assert _resolver(app).resolve("$lib/helper", str(importer)) is None


@pytest.mark.parametrize(
    "settings",
    [
        '{"compilerOptions": {"paths": {"$lib/helper": ["missing"]}}}',
        '{"compilerOptions": {"paths": {"$lib/*": ["missing/*"]}}}',
        '{"compilerOptions": {"paths": {"*": ["missing/*"]}}}',
        '{"extends": "./custom.json"}',
        '{"extends": ["./custom.json"]}',
        '{"compilerOptions": {"baseUrl": "./custom"}}',
    ],
)
def test_local_jsconfig_can_block_implicit_lib(app, settings):
    importer = _write(app, "src/routes/+page.js")
    _write(app, "src/lib/helper.js")
    _write(app, "src/routes/jsconfig.json", settings)
    assert _resolver(app).resolve("$lib/helper", str(importer)) is None


def test_unrelated_jsconfig_paths_leave_implicit_lib_available(app):
    importer = _write(app, "src/routes/+page.js")
    target = _write(app, "src/lib/helper.js")
    _write(app, "jsconfig.json", '{"compilerOptions": {"paths": {"@/*": ["app/*"]}}}')
    assert _resolver(app).resolve("$lib/helper", str(importer)) == str(target)


def test_implicit_lib_follows_nearest_package_boundary(app):
    importer = _write(app, "packages/plain/src/+page.js")
    _write(app, "packages/plain/package.json", "{}")
    _write(app, "src/lib/helper.js")
    assert _resolver(app).resolve("$lib/helper", str(importer)) is None


def test_implicit_lib_keeps_resolution_inside_the_library(app):
    importer = _write(app, "src/routes/+page.js")
    outside = _write(app, "src/other.js")
    _write(app, "src/lib/index.js")
    _write(app, "src/lib.js")
    (app / "src/lib/link.js").symlink_to(outside)

    resolver = _resolver(app)
    assert resolver.resolve("$lib", str(importer)) is None
    assert resolver.resolve("$lib/../other.js", str(importer)) is None
    assert resolver.resolve("$lib/link.js", str(importer)) is None


def test_projects_without_library_proof_keep_the_original_resolver(app):
    original = MonorepoResolver(str(app))
    assert sveltekit_resolver(original, {}) is original


def test_general_resolver_does_not_guess_lib_with_literal_override(app):
    _write(app, "package.json", '{"devDependencies": {"@sveltejs/kit": "2.55.0"}}')
    importer = _write(app, "src/routes/+page.js")
    default = _write(app, "src/lib/helper.js")
    declared = _write(app, "site/lib/helper.js")
    resolver = MonorepoResolver(str(app))
    assert resolver.resolve("$lib/helper", str(importer)) == str(default)

    _write(
        app, "svelte.config.js",
        "export default { kit: { files: { lib: 'site/lib' } } };",
    )
    assert resolver.resolve("$lib/helper", str(importer)) is None
    assert resolve_sveltekit_alias("$lib/helper", str(importer)) is None
    proven = sveltekit_resolver(resolver, {str(app): str(app / "site/lib")})
    assert proven.resolve("$lib/helper", str(importer)) == str(declared)


def test_unproved_config_keeps_existing_default_alias(app):
    _write(app, "package.json", '{"devDependencies": {"@sveltejs/kit": "2"}}')
    importer = _write(app, "src/routes/+page.js")
    target = _write(app, "src/lib/helper.js")
    _write(app, "svelte.config.js", "export default computeConfig();")
    assert MonorepoResolver(str(app)).resolve("$lib/helper", str(importer)) == str(target)


def test_general_resolver_prefers_explicit_typescript_alias_to_default_lib(app):
    _write(app, "package.json", '{"devDependencies": {"@sveltejs/kit": "2"}}')
    importer = _write(app, "src/routes/+page.js")
    _write(app, "src/lib/helper.js")
    _write(app, "src/lib/missing.js")
    explicit = _write(app, "site/helper.ts")
    _write(
        app,
        "tsconfig.json",
        '{"compilerOptions": {"paths": {"$lib/*": ["site/*"]}}}',
    )
    resolver = MonorepoResolver(str(app))
    assert resolver.resolve("$lib/helper", str(importer)) == str(explicit)
    assert resolver.resolve("$lib/missing", str(importer)) is None


@pytest.mark.parametrize("version", ["^3.0.0", "2 || 3"])
def test_kit_versions_without_proved_lib_semantics_do_not_guess(app, version):
    _write(
        app, "package.json", json.dumps({"devDependencies": {"@sveltejs/kit": version}})
    )
    importer = _write(app, "src/routes/+page.js")
    _write(app, "src/lib/helper.js")
    assert MonorepoResolver(str(app)).resolve("$lib/helper", str(importer)) is None


def test_general_resolver_respects_unresolved_javascript_alias(app):
    _write(app, "package.json", '{"devDependencies": {"@sveltejs/kit": "2"}}')
    importer = _write(app, "src/routes/+page.js")
    _write(app, "src/lib/helper.js")
    _write(app, "jsconfig.json", '{"compilerOptions":{"paths":{"$lib/*":["other/*"]}}}')
    assert MonorepoResolver(str(app)).resolve("$lib/helper", str(importer)) is None


def test_general_resolver_respects_a_config_selected_by_vite_script(app):
    _write(
        app,
        "package.json",
        json.dumps(
            {
                "devDependencies": {"@sveltejs/kit": "2"},
                "scripts": {"dev": "vite --config tool/project.js"},
            }
        ),
    )
    importer = _write(app, "src/routes/+page.js")
    _write(app, "src/lib/helper.js")
    assert MonorepoResolver(str(app)).resolve("$lib/helper", str(importer)) is None
