import io

from rich.console import Console

from skylos.upload_manifest import (
    build_code_scan_manifest,
    build_debt_manifest,
    print_upload_manifest,
)


def _render_manifest(*families, auto_upload=False, bundle_id=None):
    output = io.StringIO()
    console = Console(
        file=output,
        force_terminal=False,
        color_system=None,
        width=160,
    )
    print_upload_manifest(
        console,
        list(families),
        auto_upload=auto_upload,
        bundle_id=bundle_id,
    )
    return output.getvalue()


def test_code_scan_manifest_lists_selected_categories_and_provenance():
    manifest = build_code_scan_manifest(
        ["dead_code", "danger", "quality"],
        provenance_attached=True,
    )

    rendered = _render_manifest(manifest)

    assert "Code Scan" in rendered
    assert "security (danger)" in rendered
    assert "quality" in rendered
    assert "dead code" in rendered
    assert "AI provenance attached to the code scan." in rendered
    assert "technical debt" in rendered


def test_manifest_renders_suite_bundle_note_when_bundle_id_present():
    rendered = _render_manifest(
        build_code_scan_manifest(["dead_code"], provenance_attached=False),
        build_debt_manifest(),
        bundle_id="bundle-123",
    )

    assert "Uploading 2 cloud scans." in rendered
    assert "suite bundle" in rendered
    assert "Bundle id: bundle-123" in rendered


def test_manifest_marks_auto_upload_explicitly():
    rendered = _render_manifest(
        build_code_scan_manifest(["dead_code"], provenance_attached=False),
        auto_upload=True,
    )

    assert "Auto-uploading 1 cloud scan." in rendered
