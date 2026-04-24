from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class UploadFamilyManifest:
    label: str
    tool: str
    includes: list[str] = field(default_factory=list)
    excludes: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


_CODE_CATEGORY_LABELS = {
    "danger": "security (danger)",
    "quality": "quality",
    "secrets": "secrets",
    "dead_code": "dead code",
    "dependency": "dependency",
}


def build_code_scan_manifest(
    static_categories: list[str] | tuple[str, ...] | set[str],
    *,
    provenance_attached: bool,
) -> UploadFamilyManifest:
    ordered = [
        _CODE_CATEGORY_LABELS[key]
        for key in ("dead_code", "danger", "quality", "secrets", "dependency")
        if key in set(static_categories)
    ]
    notes = [
        "AI provenance attached to the code scan."
        if provenance_attached
        else "AI provenance not attached."
    ]
    return UploadFamilyManifest(
        label="Code Scan",
        tool="skylos",
        includes=ordered,
        excludes=["AI defense", "technical debt"],
        notes=notes,
    )


def build_defense_manifest() -> UploadFamilyManifest:
    return UploadFamilyManifest(
        label="AI Defense",
        tool="skylos-defend",
        includes=[
            "defense score",
            "ops score",
            "OWASP coverage",
            "defense findings",
            "integration inventory",
        ],
        excludes=["code scan findings", "technical debt"],
    )


def build_debt_manifest() -> UploadFamilyManifest:
    return UploadFamilyManifest(
        label="Technical Debt",
        tool="skylos-debt",
        includes=[
            "debt score",
            "hotspots",
            "baseline status",
            "signal evidence",
        ],
        excludes=["code scan findings", "AI defense"],
    )


def print_upload_manifest(
    console,
    families: list[UploadFamilyManifest],
    *,
    auto_upload: bool = False,
    bundle_id: str | None = None,
) -> None:
    if not families:
        return

    from rich.panel import Panel

    count = len(families)
    lines = [
        "[bold]Upload manifest[/bold]",
        (
            f"  {'Auto-uploading' if auto_upload else 'Uploading'} "
            f"{count} cloud scan{'s' if count != 1 else ''}."
        ),
    ]

    if count > 1:
        lines.append(
            (
                "  [dim]Each selected family uploads as a separate cloud scan inside one suite bundle.[/dim]"
                if bundle_id
                else "  [dim]Each selected family uploads as a separate cloud scan.[/dim]"
            )
        )
    if bundle_id:
        lines.append(f"  [dim]Bundle id:[/dim] {bundle_id}")

    for family in families:
        lines.extend(
            [
                "",
                f"  [bold]{family.label}[/bold] [dim]({family.tool})[/dim]",
                "  includes: " + ", ".join(family.includes),
            ]
        )
        if family.excludes:
            lines.append("  excludes: " + ", ".join(family.excludes))
        for note in family.notes:
            lines.append("  note: " + note)

    console.print(
        Panel(
            "\n".join(lines),
            border_style="blue",
            padding=(1, 2),
        )
    )
