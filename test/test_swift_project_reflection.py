"""Cross-file Swift reflection is source-bound positive property evidence."""

import pytest

from skylos.visitors.languages.swift import scan_swift_file
from skylos.visitors.languages.swift.project_reflection import apply_project_reflection


MODEL = (
    "public struct Payload { private var detail = 1; private var computed: Int { 2 }; "
    "private static var global = 3; private func spare() {}; public init() {} }\n"
)
REFLECTION = (
    "public func inspect<T>(_ value: T) -> Mirror { Mirror(reflecting: value) }\n"
    "public func entry(_ value: Payload) -> Mirror { inspect(value) }\n"
)


def _project(root, reflection=REFLECTION, *, newline="\n", extra=None):
    sources = {"Model.swift": MODEL, "Reflection.swift": reflection, **(extra or {})}
    definitions, facts = {}, {}
    for filename, text in sources.items():
        path = root / filename
        path.write_bytes(text.replace("\n", newline).encode("utf-8"))
        result = scan_swift_file(str(path), _include_analysis_metadata=True)
        assert result[25] is None, result[25]
        for definition in result[0]:
            definitions[(str(path), definition.name, definition.line)] = definition
        facts[str(path)] = result[4].swift_reflection_facts
    return definitions, facts


def _definition(definitions, name):
    return next(d for d in definitions.values() if d.name == name)


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_generic_reflection_in_another_file_preserves_only_instance_storage(
    tmp_path, newline
):
    definitions, facts = _project(tmp_path, newline=newline)
    detail = _definition(definitions, "Payload.detail")
    assert detail.references == 0
    assert apply_project_reflection(definitions, facts, scan_root=tmp_path) == []
    assert detail.references > 0
    for name in ("Payload.spare", "Payload.computed", "Payload.global"):
        assert _definition(definitions, name).references == 0


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
@pytest.mark.parametrize(
    "reflection",
    [
        "private func inspect<T>(_ value: T) -> Mirror { Mirror(reflecting: value) }\npublic func entry() {}\n",
        "public func entry() -> Mirror { Mirror(reflecting: 1) }\n",
    ],
)
def test_unreachable_or_literal_reflection_does_not_credit_other_file_fields(
    tmp_path, newline, reflection
):
    definitions, facts = _project(tmp_path, reflection, newline=newline)
    assert apply_project_reflection(definitions, facts, scan_root=tmp_path) == []
    assert _definition(definitions, "Payload.detail").references == 0
    assert _definition(definitions, "Payload.spare").references == 0


def test_standard_provider_type_shadowed_in_another_file_is_not_reflection(tmp_path):
    definitions, facts = _project(
        tmp_path,
        extra={
            "Mirror.swift": "public struct Mirror { public init<T>(reflecting value: T) {} }\n"
        },
    )
    assert apply_project_reflection(definitions, facts, scan_root=tmp_path) == []
    assert _definition(definitions, "Payload.detail").references == 0
    assert _definition(definitions, "Payload.spare").references == 0


def test_changed_source_invalidates_all_project_positive_evidence(tmp_path):
    definitions, facts = _project(tmp_path)
    path = tmp_path / "Model.swift"
    path.write_bytes(path.read_bytes() + b"// changed after parse\n")
    errors = apply_project_reflection(definitions, facts, scan_root=tmp_path)
    assert errors and errors[0]["kind"] == "swift_reflection_context_error"
    assert _definition(definitions, "Payload.detail").references == 0


def test_project_context_cannot_read_outside_scan_root(tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    definitions, facts = _project(tmp_path)
    errors = apply_project_reflection(definitions, facts, scan_root=allowed)
    assert errors and errors[0]["kind"] == "swift_reflection_context_error"
    assert _definition(definitions, "Payload.detail").references == 0


def test_project_reflection_file_and_byte_limits_are_explicit(tmp_path, monkeypatch):
    import skylos.visitors.languages.swift.project_reflection as module

    definitions, facts = _project(tmp_path)
    monkeypatch.setattr(module, "MAX_PROJECT_REFLECTION_FILES", 1)
    assert apply_project_reflection(definitions, facts, scan_root=tmp_path)
    assert _definition(definitions, "Payload.detail").references == 0
    monkeypatch.setattr(module, "MAX_PROJECT_REFLECTION_FILES", 512)
    monkeypatch.setattr(module, "MAX_PROJECT_REFLECTION_BYTES", 1)
    assert apply_project_reflection(definitions, facts, scan_root=tmp_path)
    assert _definition(definitions, "Payload.detail").references == 0


def test_swapped_symlink_cannot_supply_project_reflection_evidence(tmp_path):
    definitions, facts = _project(tmp_path)
    path = tmp_path / "Model.swift"
    original = tmp_path / "Original.swift"
    path.rename(original)
    path.symlink_to(original)
    errors = apply_project_reflection(definitions, facts, scan_root=tmp_path)
    assert errors
    assert _definition(definitions, "Payload.detail").references == 0


def test_project_fact_limit_is_explicit_and_never_partially_credits_fields(
    tmp_path, monkeypatch
):
    import skylos.visitors.languages.swift.project_reflection as module

    definitions, facts = _project(tmp_path)
    monkeypatch.setattr(module, "MAX_PROJECT_REFLECTION_FACTS", 1)
    errors = apply_project_reflection(definitions, facts, scan_root=tmp_path)
    assert errors and errors[0]["kind"] == "swift_reflection_context_error"
    assert _definition(definitions, "Payload.detail").references == 0


@pytest.mark.parametrize(
    "case", ["shadow", "ordinary-read", "qualified-stdlib", "dead-reader"]
)
def test_cross_file_provider_validation_preserves_ordinary_and_qualified_reads(
    tmp_path, case
):
    import json

    from skylos.analyzer import analyze

    # Native Swift/Periphery reviewed this exact three-program boundary before
    # the scanner was changed. The custom module Mirror never reads detail.
    model = (
        "public struct Payload {\n"
        "    private var detail = 1\n"
        "    public init() {}\n"
        + (
            "    public func read() -> Int { detail }\n"
            if case == "ordinary-read"
            else "    private func ignored() -> Int { detail }\n"
            if case == "dead-reader"
            else ""
        )
        + "}\n"
    )
    qualified = "Swift." if case == "qualified-stdlib" else ""
    model += f"public func entry(_ p: Payload) -> {qualified}Mirror {{ {qualified}Mirror(reflecting: p) }}\n"
    other = "public struct Mirror {\n    public init(reflecting value: Payload) {}\n}\n"
    (tmp_path / "A.swift").write_text(model, encoding="utf-8")
    (tmp_path / "B.swift").write_text(other, encoding="utf-8")
    result = json.loads(
        analyze(
            str(tmp_path),
            conf=60,
            grep_verify=True,
            grep_cache=False,
            enable_danger=False,
            enable_quality=False,
            enable_secrets=False,
            enable_dependency_hallucinations=False,
        )
    )
    assert not result.get("analysis_errors")
    detail = [
        row
        for row in result.get("unused_variables", ())
        if row["simple_name"] == "detail"
    ]
    assert bool(detail) == (case in {"shadow", "dead-reader"})
    if case == "dead-reader":
        assert any(
            row["simple_name"] == "ignored"
            for row in result.get("unused_functions", ())
        )


def test_stale_reflection_provenance_never_resets_ordinary_reads(tmp_path):
    model = MODEL + "extension Payload { public func read() -> Int { detail } }\n"
    definitions, facts = _project(tmp_path, extra={"Model.swift": model})
    detail = _definition(definitions, "Payload.detail")
    assert detail.references > 0
    facts[str(tmp_path / "Model.swift")]["proof_version"] = 1
    errors = apply_project_reflection(definitions, facts, scan_root=tmp_path)
    assert errors and errors[0]["kind"] == "swift_reflection_context_error"
    assert detail.references > 0


def test_unrelated_swiftpm_target_does_not_shadow_standard_reflection(tmp_path):
    import json

    from skylos.analyzer import analyze

    sources = {
        "Package.swift": '// swift-tools-version: 5.9\nimport PackageDescription\nlet package = Package(name: "ProviderScopes", targets: [.target(name: "One"), .target(name: "Two")])\n',
        "Sources/One/A.swift": "public struct Payload { private var detail = 1; public init() {} }\npublic func entry(_ p: Payload) -> Mirror { Mirror(reflecting: p) }\n",
        "Sources/Two/B.swift": "public struct Mirror { public init(reflecting value: Int) {} }\n",
    }
    for filename, source in sources.items():
        path = tmp_path / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    result = json.loads(
        analyze(
            str(tmp_path),
            conf=60,
            grep_verify=False,
            enable_danger=False,
            enable_quality=False,
            enable_secrets=False,
            enable_dependency_hallucinations=False,
        )
    )
    assert not result.get("analysis_errors")
    assert not any(
        row["simple_name"] == "detail" for row in result.get("unused_variables", ())
    )
